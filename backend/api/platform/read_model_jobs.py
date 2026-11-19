"""Assets read-model maintenance uses the existing serialized, cancellable queue."""
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.jobs import JobCancelled, JobHandle
from api.modules.assets.services.read_model import ready_generation, refresh
from api.platform.sync_queue.models import SyncStep
from api.settings import get_settings
from api.timeutil import utcnow

KEY = "platform/assets_read_refresh/0"


def run(db: Session, handle: JobHandle) -> dict[str, int | bool]:
    def check() -> None:
        if handle.cancelled():
            raise JobCancelled()
    return refresh(db, check=check)


def ensure_queued(db: Session) -> int | None:
    if not get_settings().assets_sql_list_enabled:
        return None
    from api.platform.sync_queue.service import enqueue, lock
    lock(db)
    if ready_generation(db, utcnow()) or db.scalar(select(SyncStep.id).where(
        SyncStep.key == KEY, SyncStep.status.in_(("queued", "waiting", "starting", "running"))).limit(1)):
        db.rollback()
        return None
    run = enqueue(db, [{"key": KEY}], actor="system", origin="maintenance")
    db.commit()
    return run.id
