"""Свежесть импорта и справочников для сводки настроек."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.vm.models import VmImport
from api.modules.vm.services.refs_view import RefView, ref_views
from api.platform.data_status import DataItem, State, register_data_status, stale_after

IMPORT_DAYS = 7


def _import_row(db: Session) -> DataItem:
    title = "Импорт уязвимостей"
    last = db.execute(select(VmImport).order_by(VmImport.finished_at.desc(), VmImport.id.desc()).limit(1)).scalar_one_or_none()
    if last is None:
        return DataItem("vm", "import", title, "snapshot", None, "missing", None, "импортов ещё не было", "upload")
    return DataItem(
        "vm", "import", title, "snapshot", last.finished_at, stale_after(last.finished_at, IMPORT_DAYS),
        last.source, last.filename or f"{last.hosts} хостов", "upload",
    )


def _ref_row(ref: RefView) -> DataItem:
    # Порог в 30 дней уже посчитан обзором (`RefView.stale`): второй раз его не считаем.
    state: State = "running" if ref.active_job_id else "missing" if ref.loaded_at is None else "stale" if ref.stale else "fresh"
    detail = f"{ref.records} записей" if ref.loaded_at else "не загружено"
    return DataItem("vm", f"ref:{ref.name}", ref.title, "reference", ref.loaded_at, state, ref.source, detail, "references")


def provide(db: Session) -> list[DataItem]:
    return [_import_row(db), *(_ref_row(ref) for ref in ref_views(db))]


register_data_status("vm", provide)
