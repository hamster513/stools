import hashlib
import json
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path

from .classify import classify_publication
from .contracts import Publication, Source, utcnow
from .monitoring_contracts import CveEnrichment, PocCandidate
from .storage_migrations import migrate


PUBLISH_BATCH_SIZE = 1000

def encode(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sources(id TEXT PRIMARY KEY, config TEXT NOT NULL,
                    checkpoint TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL DEFAULT '{}');
                CREATE TABLE IF NOT EXISTS publications(id TEXT PRIMARY KEY, source_id TEXT NOT NULL,
                    revision INTEGER NOT NULL, fingerprint TEXT NOT NULL, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS changes(seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL, operation TEXT NOT NULL, entity_id TEXT NOT NULL,
                    revision INTEGER NOT NULL, observed_at TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY, name TEXT NOT NULL, scopes TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, source_id TEXT NOT NULL,
                    state TEXT NOT NULL, created_at TEXT NOT NULL, finished_at TEXT, error TEXT);
            """)
            for key, value in (("collector_id", str(uuid.uuid4())), ("epoch", str(uuid.uuid4())), ("schema", "1")):
                db.execute("INSERT OR IGNORE INTO meta VALUES (?, ?)", (key, value))
            migrate(db)
        self.path.chmod(0o600)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def info(self):
        with self.connection() as db:
            meta = dict(db.execute("SELECT key,value FROM meta LIMIT 10").fetchall())
            last = db.execute("SELECT COALESCE(MAX(seq),0) FROM changes").fetchone()[0]
        return {"protocol_version": int(meta.get("protocol_version", "1")), "supported_protocol_versions": [1, 2], "collector_id": meta["collector_id"],
                "epoch": meta["epoch"], "last_seq": last}

    def source(self, source_id):
        with self.connection() as db:
            row = db.execute("SELECT * FROM sources WHERE id=? LIMIT 1", (source_id,)).fetchone()
        if row is None:
            raise KeyError(source_id)
        return {"id": row["id"], **json.loads(row["config"]), "checkpoint": json.loads(row["checkpoint"]),
                "status": json.loads(row["status"])}

    def sources(self):
        with self.connection() as db:
            ids = [row[0] for row in db.execute("SELECT id FROM sources ORDER BY id LIMIT 5000")]
        return [self.source(id_) for id_ in ids]

    @staticmethod
    def public_source(source):
        return {key: value for key, value in source.items() if key != "checkpoint"}

    @staticmethod
    def event(db, kind, operation, entity_id, revision, payload):
        db.execute("INSERT INTO changes(entity_type,operation,entity_id,revision,observed_at,payload) VALUES(?,?,?,?,?,?)",
                   (kind, operation, entity_id, revision, utcnow(), encode(payload)))

    def save_source(self, values, source_id=None):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            source_id = self._save_source(db, values, source_id)
        return self.source(source_id)

    def _save_source(self, db, values, source_id=None):
        source_id = source_id or str(uuid.uuid4())
        config = Source.model_validate(values).model_dump(mode="json")
        if config["adapter"] == "telegram" and config["llm_allowed"]:
            raise ValueError("Telegram sources use rule-based processing")
        old = db.execute("SELECT config FROM sources WHERE id=? LIMIT 1", (source_id,)).fetchone()
        if old:
            previous = json.loads(old[0])
            if config["version"] != previous["version"]:
                raise ValueError("source version conflict")
            previous_normalized = Source.model_validate({**previous, "telegram_mode": previous.get("telegram_mode", "mtproto" if previous["adapter"] == "telegram" else "web")}).model_dump(mode="json")
            if (config["url"], config["adapter"], config["telegram_mode"]) != (previous_normalized["url"], previous_normalized["adapter"], previous_normalized["telegram_mode"]):
                db.execute("UPDATE sources SET checkpoint='{}',status='{}' WHERE id=?", (source_id,))
            config["version"] += 1
            db.execute("UPDATE sources SET config=? WHERE id=?", (encode(config), source_id))
        else:
            if db.execute("SELECT COUNT(*) FROM sources").fetchone()[0] >= 5000:
                raise ValueError("source limit reached")
            config["version"] = 1
            db.execute("INSERT INTO sources(id,config) VALUES(?,?)", (source_id, encode(config)))
        self.event(db, "source", "upsert", source_id, config["version"], {"id": source_id, **config})
        return source_id

    def ingest(self, source_id, documents, checkpoint, expected_version=None, job_id=None):
        count = 0
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if job_id:
                job_row = db.execute("SELECT data FROM source_runs WHERE id=? LIMIT 1",(job_id,)).fetchone()
                if job_row and json.loads(job_row[0]).get("state")=="cancelled":
                    return 0
            source_row = db.execute("SELECT config FROM sources WHERE id=? LIMIT 1", (source_id,)).fetchone()
            if not source_row:
                raise KeyError(source_id)
            source = json.loads(source_row[0])
            if expected_version is not None and source["version"] != expected_version:
                raise ValueError("source changed during collection")
            for document in documents:
                value = Publication.model_validate(document).model_dump()
                value["classification"] = classify_publication(value, source).model_dump()
                value["source_published_at"] = value["published_at"]
                value["source_updated_at"] = value["updated_at"]
                value["date_basis"] = "published" if value["published_at"] else "unknown"
                value["content_hash"] = hashlib.sha256(value["text"].encode()).hexdigest()
                identity = str(uuid.uuid5(uuid.NAMESPACE_URL, source_id + "/" + value["external_id"]))
                data = {**value, "title": value["title"] or value["url"] or value["external_id"], "id": identity, "source_id": source_id, "publisher_id": source["publisher_id"],
                        "origin_adapter": source["adapter"], "language": value["language"] or source["language"], "llm_allowed": source["llm_allowed"]}
                fingerprint = hashlib.sha256(encode(data).encode()).hexdigest()
                old = db.execute("SELECT revision,fingerprint FROM publications WHERE id=? LIMIT 1", (identity,)).fetchone()
                if old and old["fingerprint"] == fingerprint:
                    continue
                revision = old["revision"] + 1 if old else 1
                db.execute("INSERT INTO publications VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                           "revision=excluded.revision,fingerprint=excluded.fingerprint,data=excluded.data",
                           (identity, source_id, revision, fingerprint, encode(data)))
                for identifier in value["identifiers"]:
                    if __import__("re").fullmatch(r"CVE-\d{4}-\d{4,}", identifier):
                        db.execute("INSERT OR IGNORE INTO pending_work(id,kind,data,next_attempt) VALUES(?,?,?,?)",
                            ("enrich:"+identifier, "enrichment", encode({"cve_id":identifier}), utcnow()))
                self.event(db, "publication", "retract" if value["retracted"] else "upsert", identity, revision, data)
                count += 1
            if checkpoint is not None:
                db.execute("UPDATE sources SET checkpoint=? WHERE id=?", (encode(checkpoint), source_id))
        return count

    def changes(self, after, until=None, limit=100, byte_limit=8 * 1024 * 1024):
        info = self.info()
        until = info["last_seq"] if until is None else until
        if after < 0 or until < after or until > info["last_seq"]:
            raise ValueError("cursor out of range; full sync required")
        if not 1 <= limit <= 500:
            raise ValueError("invalid page limit")
        with self.connection() as db:
            rows = db.execute("SELECT * FROM changes WHERE seq>? AND seq<=? ORDER BY seq LIMIT ?",
                              (after, until, limit)).fetchall()
        events, used = [], 1024
        for row in rows:
            event = {**dict(row), "payload": json.loads(row["payload"])}
            size = len(encode(event).encode())
            if used + size > byte_limit:
                if not events:
                    raise ValueError("event exceeds page limit")
                break
            events.append(event)
            used += size
        cursor = events[-1]["seq"] if events else after
        return {**info, "until_seq": until, "next_cursor": cursor, "has_more": cursor < until, "events": events}

    def create_token(self, name, scopes):
        if not set(scopes) <= {"data:read", "sources:write"}:
            raise ValueError("invalid token scopes")
        token = secrets.token_urlsafe(40)
        with self.connection() as db:
            db.execute("INSERT INTO tokens VALUES(?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), name, encode(scopes)))
        return token

    def scopes(self, token):
        with self.connection() as db:
            row = db.execute("SELECT scopes FROM tokens WHERE hash=? LIMIT 1", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        return json.loads(row[0]) if row else []

    def revoke_token(self, name):
        with self.connection() as db:
            db.execute("DELETE FROM tokens WHERE name=?", (name,))

    def set_status(self, source_id, values):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM sources WHERE id=? LIMIT 1", (source_id,)).fetchone()
            state = {**json.loads(row[0]), **values}
            db.execute("UPDATE sources SET status=? WHERE id=?", (encode(state), source_id))

    def backup(self, destination):
        with self.connection() as db, sqlite3.connect(destination) as target:
            db.backup(target)
        Path(destination).chmod(0o600)

    def restore(self, backup):
        with sqlite3.connect(backup) as source, self.connection() as target:
            if source.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("invalid backup")
            source.backup(target)
            target.execute("UPDATE meta SET value=? WHERE key='epoch'", (str(uuid.uuid4()),))

    def create_job(self, source_id):
        self.source(source_id)
        id_ = str(uuid.uuid4())
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT id FROM jobs WHERE source_id=? AND state='running' LIMIT 1", (source_id,)).fetchone():
                raise ValueError("collection already running")
            db.execute("INSERT INTO jobs(id,source_id,state,created_at) VALUES(?,?,'running',?)", (id_, source_id, utcnow()))
        return id_

    def finish_job(self, job_id, error=None):
        with self.connection() as db:
            db.execute("UPDATE jobs SET state=?,finished_at=?,error=? WHERE id=?",
                       ("failed" if error else "done", utcnow(), error, job_id))

    def job(self, job_id):
        with self.connection() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=? LIMIT 1", (job_id,)).fetchone()
        if not row:
            raise KeyError(job_id)
        return dict(row)

    def recover_jobs(self):
        with self.connection() as db:
            db.execute("UPDATE jobs SET state='failed',finished_at=?,error='Collector restarted' WHERE state='running'", (utcnow(),))

    def save_monitoring(self, kind, entity_id, data):
        model, table = {"cve_enrichment": (CveEnrichment, "cve_enrichments"), "poc_candidate": (PocCandidate, "poc_candidates")}[kind]
        value = model.model_validate(data).model_dump(mode="json")
        expected_id = "cve:" + value["cve_id"] if kind == "cve_enrichment" else f"poc:{value['cve_id']}:{value['repository_id']}"
        if entity_id != expected_id:
            raise ValueError("entity identity mismatch")
        fingerprint = hashlib.sha256(encode(value).encode()).hexdigest()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute(f"SELECT revision,fingerprint FROM {table} WHERE id=? LIMIT 1", (entity_id,)).fetchone()
            if old and old['fingerprint'] == fingerprint:
                return old['revision']
            revision = old['revision'] + 1 if old else 1
            db.execute(f"INSERT INTO {table} VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,fingerprint=excluded.fingerprint,data=excluded.data", (entity_id, revision, fingerprint, encode(value)))
            version = db.execute("SELECT value FROM meta WHERE key='protocol_version' LIMIT 1").fetchone()[0]
            if version == '2':
                self.event(db, kind, "upsert", entity_id, revision, value)
            else:
                db.execute("INSERT INTO pending_work(id,kind,data) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", ('publish:' + entity_id, kind, encode({'id': entity_id, 'revision': revision, 'payload': value})))
        return revision

    def enable_protocol_v2(self):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE meta SET value='2' WHERE key='protocol_version'")
            while True:
                rows = db.execute("SELECT id,kind,data FROM pending_work WHERE id LIKE 'publish:%' ORDER BY id LIMIT ?", (PUBLISH_BATCH_SIZE,)).fetchall()
                if not rows:
                    break
                for row in rows:
                    value = json.loads(row['data'])
                    self.event(db, row['kind'], 'upsert', value['id'], value['revision'], value['payload'])
                    db.execute('DELETE FROM pending_work WHERE id=?', (row['id'],))
        return self.info()

    def monitoring_record(self, kind, entity_id):
        table = {"cve_enrichment":"cve_enrichments", "poc_candidate":"poc_candidates"}[kind]
        with self.connection() as db:
            row = db.execute(f"SELECT data FROM {table} WHERE id=? LIMIT 1", (entity_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def due_work(self, kind, limit=20):
        with self.connection() as db:
            return [dict(row) for row in db.execute("SELECT id,data,next_attempt FROM pending_work WHERE kind=? AND (next_attempt IS NULL OR next_attempt<=?) ORDER BY next_attempt,id LIMIT ?",(kind,utcnow(),min(limit,20))).fetchall()]

    def defer_work(self, work_id, next_attempt, data=None):
        with self.connection() as db:
            if data is None:
                db.execute("UPDATE pending_work SET next_attempt=? WHERE id=?",(next_attempt,work_id))
            else:
                db.execute("UPDATE pending_work SET next_attempt=?,data=? WHERE id=?",(next_attempt,encode(data),work_id))

    def enqueue_work(self, work_id, kind, data):
        with self.connection() as db:
            db.execute("INSERT OR IGNORE INTO pending_work VALUES(?,?,?,?)",(work_id,kind,encode(data),utcnow()))
