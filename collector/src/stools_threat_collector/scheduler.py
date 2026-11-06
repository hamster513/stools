import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from .adapters import github, html, kev, msrc, rss, telegram
from .contracts import utcnow
from .fetcher import Fetcher, FetchError

ADAPTERS = {"rss": rss.collect, "kev": kev.collect, "msrc": msrc.collect,
            "cncert": html.collect, "telegram": telegram.collect, "github": github.collect}


class Runner:
    def __init__(self, store):
        self.store = store
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="source")
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.domains = {}
        self.active = set()
        self.thread = threading.Thread(target=self.loop, name="collector-scheduler", daemon=True)

    def start(self):
        self.store.recover_jobs()
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread.is_alive():
            self.thread.join(timeout=5)
        self.pool.shutdown(wait=True, cancel_futures=False)

    def submit(self, source_id):
        with self.lock:
            if source_id in self.active or len(self.active) >= 4:
                raise ValueError("collection capacity busy")
            source = self.store.source(source_id)
            job = self.store.create_job(source_id)
            self.active.add(source_id)
            domain = urlsplit(source["url"]).hostname
            guard = self.domains.setdefault(domain, threading.Lock())
            self.pool.submit(self.work, source, job, guard)
        return job

    def work(self, source, job, guard):
        error = None
        try:
            with guard:
                fetcher = Fetcher(proxy=os.environ.get("COLLECTOR_HTTP_PROXY"), ca=os.environ.get("COLLECTOR_CA_FILE"))
                documents, checkpoint = ADAPTERS[source["adapter"]](source, source["checkpoint"], fetcher)
                count = self.store.ingest(source["id"], documents, checkpoint, source["version"])
            self.store.set_status(source["id"], {"last_success": utcnow(), "error": None, "failures": 0,
                "new_versions": count, "next_attempt": (datetime.now(timezone.utc) + timedelta(minutes=source["interval_minutes"])).isoformat()})
        except Exception as exc:  # noqa: BLE001 — isolate provider/adapter failure from durable delivery
            error = str(exc)[:200] if isinstance(exc, FetchError) else type(exc).__name__
            failures = source["status"].get("failures", 0) + 1
            delay = [300, 900, 3600][min(failures - 1, 2)]
            delay = max(delay, getattr(exc, "retry_after", 0), getattr(exc, "seconds", 0))
            self.store.set_status(source["id"], {"last_error": utcnow(), "error": error, "failures": failures,
                "next_attempt": (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat()})
        finally:
            self.store.finish_job(job, error)
            with self.lock:
                self.active.discard(source["id"])

    def loop(self):
        while not self.stop.is_set():
            for source in self.store.sources():
                due = source["status"].get("next_attempt")
                if source["enabled"] and (not due or datetime.fromisoformat(due) <= datetime.now(timezone.utc)):
                    try:
                        self.submit(source["id"])
                    except ValueError:
                        pass
            self.stop.wait(10)
