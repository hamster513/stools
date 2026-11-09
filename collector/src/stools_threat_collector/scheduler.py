import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from .collection import ADAPTERS, collect_batch
from .contracts import utcnow
from .enrichment import enrich_cve
from .poc_search import search_poc_candidates
from .poc_validation import validate_poc
from .fetcher import FetchError
from .outbound_profiles import make_fetcher
from . import monitoring
from .classify import classify_publication
from .monitoring_contracts import CollectionWindow




class Runner:
    def __init__(self, store):
        self.store = store
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="source")
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.domains = {}
        self.active = set()
        self.metadata_thread = threading.Thread(target=self.metadata_loop, name="collector-metadata", daemon=True)
        self.thread = threading.Thread(target=self.loop, name="collector-scheduler", daemon=True)

    def start(self):
        self.store.recover_jobs()
        for row in monitoring.runs(self.store, limit=200):
            if row.get("state") in ("running", "queued"):
                monitoring.update_run(self.store,row["id"],state="failed",error="collector restarted",finished_at=utcnow())
        self.thread.start()
        self.metadata_thread.start()

    def close(self):
        self.stop.set()
        if self.thread.is_alive():
            self.thread.join(timeout=5)
        if self.metadata_thread.is_alive():
            self.metadata_thread.join(timeout=5)
        self.pool.shutdown(wait=True, cancel_futures=False)

    def submit(self, source_id, window=None, preview=False, resume=None):
        with self.lock:
            if source_id in self.active or len(self.active) >= 4:
                raise ValueError("collection capacity busy")
            source = self.store.source(source_id)
            if source.get("retired"):
                raise ValueError("source retired; select replacement")
            previous = monitoring.run(self.store,resume) if resume else None
            if previous and (previous["source_id"]!=source_id or previous["state"] not in ("partial","failed","cancelled")):
                raise ValueError("job cannot be resumed")
            if previous and previous.get("source_version",source["version"]) != source["version"]:
                raise ValueError("source changed since previous run; start a new check")
            window = CollectionWindow.model_validate(previous["window"]) if previous else (window or CollectionWindow())
            isolated = bool(previous or window.date_from or window.date_to or window.force)
            job = self.store.create_job(source_id)
            checkpoint = previous.get("checkpoint",{}) if previous else {} if isolated else source["checkpoint"]
            monitoring.update_run(self.store,job,id=job,source_id=source_id,state="queued",stage="fetch",created_at=utcnow(),
                window=window.model_dump(mode="json"),source_version=source["version"],checkpoint=checkpoint,preview=preview,isolated=isolated,counters={},coverage={},resumed_from=resume)
            self.active.add(source_id)
            guard = self.domains.setdefault(urlsplit(source["url"]).hostname, threading.Lock())
            self.pool.submit(self.work, source, job, guard)
        return job

    def work(self, source, job, guard):
        error = None
        try:
            with guard:
                state = monitoring.update_run(self.store,job,state="running",stage="fetch")
                if state["state"]=="cancelled": return
                batch = collect_batch(source,state["checkpoint"],make_fetcher(source),CollectionWindow.model_validate(state["window"]))
                if monitoring.run(self.store,job)["state"]=="cancelled": return
                counts = dict(batch.counters)
                for document in batch.documents:
                    category=classify_publication(document,source).category
                    counts[category]=counts.get(category,0)+1
                count = 0 if state["preview"] else self.store.ingest(source["id"],batch.documents,
                    None if state["isolated"] else batch.checkpoint,source["version"],job_id=job)
                counts["new_versions"] = count
                sample = [{**d,"text":d.get("text","")[:2000],"classification":classify_publication(d,source).model_dump()} for d in batch.documents[:10]] if state["preview"] else []
                monitoring.update_run(self.store,job,state="partial" if batch.continuation else "succeeded",stage="complete",finished_at=utcnow(),
                    counters=counts,coverage=batch.coverage,continuation=batch.continuation,checkpoint=batch.checkpoint,sample=sample,error=None)
            if not state["preview"] and not state["isolated"]:
                self.store.set_status(source["id"], {"last_success": utcnow(), "error": None, "failures": 0,"system_paused":False,
                    "new_versions": count,"coverage":batch.coverage,"continuation":batch.continuation,
                    "next_attempt": (datetime.now(timezone.utc)+timedelta(minutes=1 if batch.continuation else source["interval_minutes"])).isoformat()})
        except Exception as exc:
            error = monitoring.source_error(exc)
            status=monitoring.failure_status(source,exc)
            self.store.set_status(source["id"],status)
            monitoring.update_run(self.store,job,state="failed",finished_at=utcnow(),error=error,
                stage="parse" if isinstance(exc,ValueError) and not isinstance(exc,FetchError) else "fetch",next_attempt=status["next_attempt"])
        finally:
            self.store.finish_job(job,error)
            with self.lock:
                self.active.discard(source["id"])

    def loop(self):
        while not self.stop.is_set():
            for source in sorted(self.store.sources(),key=lambda s:-s.get("importance",3)) if monitoring.settings(self.store)["collection_enabled"] else []:
                due = source["status"].get("next_attempt")
                if source["enabled"] and (not due or datetime.fromisoformat(due) <= datetime.now(timezone.utc)):
                    try:
                        self.submit(source["id"])
                    except ValueError:
                        pass
            self.stop.wait(10)

    def metadata_loop(self):
        while not self.stop.is_set():
            for work in self.store.due_work("enrichment", limit=1) if monitoring.settings(self.store)["enrichment_enabled"] else []:
                if self.stop.is_set():
                    break
                cve_id = json.loads(work["data"])["cve_id"]
                try:
                    previous = self.store.monitoring_record("cve_enrichment", "cve:"+cve_id)
                    fetcher = make_fetcher()
                    result = enrich_cve(cve_id, fetcher, previous=previous).model_dump(mode="json")
                    self.store.save_monitoring("cve_enrichment", "cve:"+cve_id, result)
                    self.store.defer_work(work["id"], result["expires_at"])
                    self.store.enqueue_work("poc:"+cve_id, "poc_search", {"cve_id":cve_id})
                except Exception:
                    self.store.defer_work(work["id"], (datetime.now(timezone.utc)+timedelta(minutes=15)).isoformat())
                # Shared public API budget: no key required, bounded retry pressure.
                if self.stop.wait(6):
                    break
            if not self.stop.is_set() and monitoring.settings(self.store)["poc_enabled"]:
                self.poc_step()
            self.stop.wait(10)

    def poc_step(self):
        for kind in ("poc_search", "poc_validate"):
            for work in self.store.due_work(kind, limit=1):
                data = json.loads(work["data"])
                delay = 21600
                try:
                    fetcher = make_fetcher()
                    if kind == "poc_search":
                        result = search_poc_candidates(data["cve_id"], fetcher, page=(data.get("continuation") or {}).get("page",1))
                        if result.get("continuation"):
                            delay = 60
                        data.update({k:v for k,v in result.items() if k != "candidates"}, checked_at=utcnow(), error="")
                        for candidate in result["candidates"]:
                            identity = "poc:"+candidate["cve_id"]+":"+str(candidate["repository_id"])
                            if not self.store.monitoring_record("poc_candidate", identity):
                                self.store.save_monitoring("poc_candidate", identity, candidate)
                            self.store.enqueue_work("validate:"+identity, "poc_validate", candidate)
                    else:
                        identity = "poc:"+data["cve_id"]+":"+str(data["repository_id"])
                        previous = self.store.monitoring_record("poc_candidate", identity)
                        result = validate_poc(data, fetcher, previous=previous)
                        self.store.save_monitoring("poc_candidate", identity, result.model_dump(mode="json"))
                        if result.error:
                            delay = 3600
                except Exception as exc:
                    data.update(error=type(exc).__name__, checked_at=utcnow())
                    delay = max(900, getattr(exc,"retry_after",0))
                self.store.defer_work(work["id"], (datetime.now(timezone.utc)+timedelta(seconds=delay)).isoformat(), data)
