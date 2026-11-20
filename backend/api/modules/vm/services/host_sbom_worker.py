"""One bounded scanning worker per API instance, with cross-process claims in PostgreSQL."""

import logging
import threading
import time

from api.modules.vm.services.host_sbom import process_next, refresh_queue

log = logging.getLogger(__name__)


def start(session_factory, data_dir):
    stop = threading.Event()

    def loop():
        next_sweep = 0.0
        while not stop.is_set():
            try:
                with session_factory() as db:
                    if time.monotonic() >= next_sweep:
                        refresh_queue(db, data_dir)
                        next_sweep = time.monotonic() + 60
                    if process_next(db, data_dir):
                        continue
            except Exception:
                log.exception("Ошибка фоновой проверки SBOM")
            stop.wait(5)

    thread = threading.Thread(target=loop, name="stools-host-sbom", daemon=True)
    thread.start()
    return stop.set
