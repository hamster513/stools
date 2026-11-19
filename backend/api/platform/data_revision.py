"""Monotonic revisions committed with source data, never independently."""
from sqlalchemy import BigInteger, String, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Mapped, Session, mapped_column

from api.db.models import Base


class DataRevision(Base):
    __tablename__ = "platform_data_revision"
    module: Mapped[str] = mapped_column(String(32), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    writer_xid: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


def read_revision(db: Session, module: str) -> int:
    return db.scalar(select(DataRevision.revision).where(DataRevision.module == module)) or 0


def bump_revision(db: Session, module: str) -> int:
    stmt = insert(DataRevision).values(module=module, revision=1)
    return db.execute(stmt.on_conflict_do_update(index_elements=[DataRevision.module],
        set_={"revision": DataRevision.revision + 1}).returning(DataRevision.revision)).scalar_one()


def ensure_revision(db: Session, module: str) -> None:
    db.execute(insert(DataRevision).values(module=module, revision=0)
               .on_conflict_do_nothing(index_elements=[DataRevision.module]))
