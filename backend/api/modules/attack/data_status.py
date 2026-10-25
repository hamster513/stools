"""Свежесть баз ATT&CK для сводки настроек."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.models import RuTtpImport
from api.modules.attack.services.attack_bundle import ensure_bundle
from api.platform.data_status import DataItem, count_ru, register_data_status, stale_after

#: Матрица выходит раз в полгода: квартал без обновления — повод заглянуть.
REFERENCE_DAYS = 90

#: Внутренние коды происхождения базы ATT&CK в словах для экрана; незнакомый код показывается как есть.
BUNDLE_SOURCES = {"builtin": "встроенный", "uploaded": "файл", "online": "MITRE"}


def _ru_ttp(db: Session) -> DataItem:
    last = db.execute(
        select(RuTtpImport).order_by(RuTtpImport.imported_at.desc(), RuTtpImport.id.desc()).limit(1)
    ).scalar_one_or_none()
    title = "Применяемость техник в России"
    if last is None:
        return DataItem("attack", "ru-ttp", title, "reference", None, "missing", None, "не загружено", "ru-ttp")
    detail = count_ru(last.row_count, ("строка", "строки", "строк")) + (f", ATT&CK {last.attack_version}" if last.attack_version else "")
    return DataItem(
        "attack", "ru-ttp", title, "reference", last.imported_at,
        stale_after(last.imported_at, REFERENCE_DAYS), last.source or None, detail, "ru-ttp",
    )


def provide(db: Session) -> list[DataItem]:
    bundle = ensure_bundle(db)
    return [
        DataItem(
            "attack", "bundle", "База MITRE ATT&CK", "reference", bundle.loaded_at,
            stale_after(bundle.loaded_at, REFERENCE_DAYS), BUNDLE_SOURCES.get(bundle.source, bundle.source),
            f"версия {bundle.version}" if bundle.version else "", "bundle",
        ),
        _ru_ttp(db),
    ]


register_data_status("attack", provide)
