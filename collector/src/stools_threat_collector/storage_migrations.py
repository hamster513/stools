"""Additive SQLite migrations; keep identities, history and checkpoints intact."""
import json


def migrate(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS cve_enrichments(id TEXT PRIMARY KEY, revision INTEGER NOT NULL, fingerprint TEXT NOT NULL, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS poc_candidates(id TEXT PRIMARY KEY, revision INTEGER NOT NULL, fingerprint TEXT NOT NULL, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS source_runs(id TEXT PRIMARY KEY, source_id TEXT NOT NULL, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS pending_work(id TEXT PRIMARY KEY, kind TEXT NOT NULL, data TEXT NOT NULL, next_attempt TEXT);
        CREATE TABLE IF NOT EXISTS catalog_revisions(id TEXT PRIMARY KEY, applied_at TEXT NOT NULL, result TEXT NOT NULL);
    ''')
    db.execute("INSERT OR IGNORE INTO meta VALUES ('protocol_version', '1')")
    if not db.execute("SELECT value FROM meta WHERE key='monitoring_schema' LIMIT 1").fetchone():
        for row in db.execute('SELECT id, config FROM sources LIMIT 5000').fetchall():
            config = json.loads(row['config'])
            if config.get('adapter') == 'telegram' and 'telegram_mode' not in config:
                config['telegram_mode'] = 'mtproto'
                db.execute('UPDATE sources SET config=? WHERE id=?', (json.dumps(config), row['id']))
        db.execute("INSERT INTO meta VALUES ('monitoring_schema', '1')")
