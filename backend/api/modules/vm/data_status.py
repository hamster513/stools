"""Свежесть импорта, синхронизации образов из Harbor и справочников для сводки настроек."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.vm.models import VmImport
from api.modules.vm.services.harbor_settings import load_harbor
from api.modules.vm.services.harbor_sync import SYNC_KIND, last_sync, public_netloc
from api.modules.vm.services.jobs import active_job
from api.modules.vm.services.refs_view import RefView, ref_views
from api.platform.data_status import DataItem, State, count_ru, register_data_status, stale_after

IMPORT_DAYS = 7
HARBOR_DAYS = 7

#: Внутренние коды происхождения импорта в словах для экрана; незнакомый код показывается как есть.
IMPORT_SOURCES = {"vm": "MaxPatrol VM", "file": "файл"}


def _import_row(db: Session) -> DataItem:
    title = "Импорт уязвимостей"
    last = db.execute(select(VmImport).order_by(VmImport.finished_at.desc(), VmImport.id.desc()).limit(1)).scalar_one_or_none()
    if last is None:
        return DataItem("vm", "import", title, "snapshot", None, "missing", None, "импортов ещё не было", "upload")
    return DataItem(
        "vm", "import", title, "snapshot", last.finished_at, stale_after(last.finished_at, IMPORT_DAYS),
        IMPORT_SOURCES.get(last.source, last.source),
        last.filename or count_ru(last.hosts, ("хост", "хоста", "хостов")), "upload",
    )


def _harbor_row(db: Session) -> DataItem:
    conn = load_harbor(db)
    last = last_sync(db)
    updated_at = last.finished_at if last is not None else None
    running = active_job(db, (SYNC_KIND,)) is not None
    if last is not None:
        detail = f"{count_ru(last.images, ('образ', 'образа', 'образов'))}, {count_ru(last.cves, ('пара', 'пары', 'пар'))}"
    elif not conn.configured:
        detail = "подключение не настроено"
    else:
        detail = "синхронизаций ещё не было"
    return DataItem(
        "vm", "harbor", "Образы контейнеров (Harbor)", "source", updated_at,
        stale_after(updated_at, HARBOR_DAYS, running=running), public_netloc(conn.url), detail, "harbor",
    )


def _ref_row(ref: RefView) -> DataItem:
    # Порог в 30 дней уже посчитан обзором (`RefView.stale`): второй раз его не считаем.
    state: State = "running" if ref.active_job_id else "missing" if ref.loaded_at is None else "stale" if ref.stale else "fresh"
    detail = count_ru(ref.records, ("запись", "записи", "записей")) if ref.loaded_at else "не загружено"
    return DataItem("vm", f"ref:{ref.name}", ref.title, "reference", ref.loaded_at, state, ref.source, detail, "references")


def provide(db: Session) -> list[DataItem]:
    return [_import_row(db), _harbor_row(db), *(_ref_row(ref) for ref in ref_views(db))]


register_data_status("vm", provide)
