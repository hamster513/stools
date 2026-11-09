"""Explicit deletion of nightly findings and their dependent data."""
from collections import Counter

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, PositiveInt, model_validator
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from api.modules.siem.hunting.findings_adapter import (
    BulkFilter,
    base_query,
    conditions,
    parse_filter,
)
from api.modules.siem.hunting.models import ThFinding, ThRun, ThRunQuery
from api.modules.siem.hunting.nightly import TH_MODULE, TH_SCOPE, finding_key
from api.platform.findings.models import FindingState
from api.platform.findings.service import lock_scope

MAX_DELETE = 10000


class DeleteFilter(BulkFilter):
    model_config = ConfigDict(extra="forbid")


class DeleteFindingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ids: list[PositiveInt] | None = Field(default=None, min_length=1, max_length=MAX_DELETE)
    filter: DeleteFilter | None = None
    expected_count: int = Field(ge=1, le=MAX_DELETE)

    @model_validator(mode="after")
    def selection(self):
        if (self.ids is None) == (self.filter is None):
            raise ValueError("Укажите либо IDs находок, либо фильтр")
        return self


def delete_findings(db: Session, body: DeleteFindingsIn) -> int:
    # Serialize with status/comment updates to avoid orphaned platform states.
    lock_scope(db, TH_MODULE, TH_SCOPE)
    query = base_query(ThFinding.id).where(ThFinding.kind == "nightly")
    if body.ids is not None:
        query = query.where(ThFinding.id.in_(body.ids))
    else:
        try:
            parsed = parse_filter(body.filter.model_dump(exclude_none=True))
        except ValueError as exc:
            raise HTTPException(422, "Некорректный фильтр находок") from exc
        query = query.where(*conditions(parsed))
    ids = list(db.scalars(query.order_by(ThFinding.id).limit(MAX_DELETE + 1)))
    if (len(ids) != body.expected_count
            or (body.ids is not None and set(ids) != set(body.ids))):
        raise HTTPException(409, "Состав или количество находок изменились. Обновите список и подтвердите удаление заново.")
    rows = list(db.scalars(select(ThFinding).where(ThFinding.id.in_(ids))
                          .order_by(ThFinding.id).limit(MAX_DELETE).with_for_update()))
    if len(rows) != len(ids):
        raise HTTPException(409, "Находки изменились. Обновите список.")
    by_run = Counter(row.run_id for row in rows if row.run_id is not None)
    if by_run:
        runs = list(db.scalars(select(ThRun).where(ThRun.id.in_(by_run))
                              .order_by(ThRun.id).limit(MAX_DELETE).with_for_update()))
        if any(run.status in ("queued", "running") for run in runs):
            raise HTTPException(409, "Дождитесь завершения прогона перед удалением его находок.")
    db.execute(update(ThRunQuery).where(ThRunQuery.finding_id.in_(ids)).values(finding_id=None))
    # Events and state history use FK ON DELETE CASCADE.
    db.execute(delete(FindingState).where(FindingState.module == TH_MODULE, FindingState.scope_id == TH_SCOPE,
                                          FindingState.key.in_([finding_key(fid) for fid in ids])))
    db.execute(delete(ThFinding).where(ThFinding.id.in_(ids)))
    for run_id, count in by_run.items():
        db.execute(update(ThRun).where(ThRun.id == run_id).values(findings=func.greatest(0, ThRun.findings - count)))
    db.commit()
    return len(ids)
