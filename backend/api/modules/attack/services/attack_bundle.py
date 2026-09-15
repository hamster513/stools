"""Действующий бандл ATT&CK и его перевод.

Матрица живёт в базе, а не только в образе: заказчик обновляет её сам,
не дожидаясь поставки. Вложенный бандл при этом остаётся — он и база,
и то, что перекрывает загруженное при обновлении софта.

Перекрытие срабатывает на смену вложенного бандла, а не на каждый
перезапуск: иначе сервис затирал бы загруженную матрицу при первом же
`docker compose up`.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.db.models import AttackBundleRow, AttackTranslation
from kbaudit.attack.bundle import (
    COMPACT_BUNDLE,
    TRANSLATIONS,
    AttackBundle,
    Tactic,
    Technique,
    load_bundle,
    load_compact,
)

SOURCE_BUILTIN = "builtin"
SOURCE_UPLOADED = "uploaded"

ORIGIN_BUILTIN = "builtin"
ORIGIN_LLM = "llm"
ORIGIN_MANUAL = "manual"


def source_hash(technique: Technique) -> str:
    """Отпечаток английского исходника техники.

    Считается по названию и описанию — по тому, с чего переводят. Меняется
    описание — меняется отпечаток, и перевод виден как устаревший.
    """
    payload = f"{technique.name}\n{technique.description}".encode()
    return hashlib.sha256(payload).hexdigest()


def version_key(version: str | None) -> tuple[int, ...]:
    """Версия ATT&CK как кортеж чисел для сравнения.

    Нечисловые части отбрасываются: нумерация MITRE всегда вида «19.2»,
    но полагаться на это без запаса не стоит — нераспознанная версия
    считается нулевой и попадает в «старее любой», что и требуется:
    сомнение трактуется в пользу предупреждения.
    """
    parts: list[int] = []
    for chunk in (version or "").split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) or (0,)


def builtin_fingerprint() -> str:
    """Отпечаток вложенного бандла. По его смене видно, что обновился софт."""
    return hashlib.sha256(COMPACT_BUNDLE.read_bytes()).hexdigest()


# --------------------------------------------------------------------------
# Чтение и запись действующего бандла
# --------------------------------------------------------------------------


def _row_to_bundle(row: AttackBundleRow) -> AttackBundle:
    return AttackBundle(
        version=row.version,
        techniques=[Technique.model_validate(t) for t in json.loads(row.techniques_json)],
        tactics=[Tactic.model_validate(t) for t in json.loads(row.tactics_json)],
    )


def _store(
    db: Session,
    bundle: AttackBundle,
    source: str,
    login: str | None,
    fingerprint: str | None,
) -> AttackBundleRow:
    row = db.get(AttackBundleRow, 1) or AttackBundleRow(id=1)
    row.version = bundle.version
    row.techniques_json = json.dumps(
        [t.model_dump(exclude={"name_ru", "description_ru"}) for t in bundle.techniques],
        ensure_ascii=False,
    )
    row.tactics_json = json.dumps([t.model_dump() for t in bundle.tactics], ensure_ascii=False)
    row.source = source
    row.builtin_fingerprint = fingerprint
    row.loaded_at = dt.datetime.now(dt.UTC)
    row.loaded_by = login
    db.add(row)
    db.commit()
    return row


def seed_builtin_translations(db: Session, bundle: AttackBundle) -> int:
    """Перенести перевод из поставки в базу.

    Переводы из поставки не затирают правки человека: у них разное
    происхождение, и `manual` выигрывает — иначе обновление образа
    молча отменяло бы чужую работу.
    """
    if not TRANSLATIONS.is_file():
        return 0
    raw = json.loads(TRANSLATIONS.read_text(encoding="utf-8"))
    by_id = {t.technique_id: t for t in bundle.techniques}
    existing = {r.technique_id: r for r in db.query(AttackTranslation)}

    written = 0
    for item in raw:
        technique_id = item.get("id")
        technique = by_id.get(technique_id)
        if technique is None:
            continue
        row = existing.get(technique_id)
        if row is not None and row.origin == ORIGIN_MANUAL:
            continue
        if row is None:
            row = AttackTranslation(technique_id=technique_id)
            db.add(row)
        row.name_ru = item.get("name_ru") or ""
        row.description_ru = item.get("description_ru") or ""
        row.source_hash = source_hash(technique)
        row.origin = ORIGIN_BUILTIN
        row.model = None
        row.updated_at = dt.datetime.now(dt.UTC)
        written += 1
    db.commit()
    return written


def ensure_bundle(db: Session) -> AttackBundleRow:
    """Действующий бандл, при необходимости — заполненный вложенным.

    Вложенный перекрывает загруженный, когда сам изменился: это признак
    того, что обновили софт. Простой перезапуск отпечаток не меняет и
    загруженную матрицу не трогает.

    Замена загруженной матрицы запоминается и показывается человеку.
    Он загружал её руками, и подмена молча — худший из вариантов:
    поставка бывает старее, и тогда он увидел бы у себя откат назад
    без объяснения, откуда тот взялся.
    """
    row = db.get(AttackBundleRow, 1)
    fingerprint = builtin_fingerprint()
    if row is not None and row.builtin_fingerprint == fingerprint:
        return row

    # Любая матрица, выбранная человеком, — файлом или скачиванием: подмена
    # обеих одинаково требует объяснения. Сравнение с «не поставка», а не
    # перечисление источников: следующий источник иначе молча выпал бы.
    replaced = row.version if row is not None and row.source != SOURCE_BUILTIN else None
    bundle = load_compact()
    row = _store(db, bundle, SOURCE_BUILTIN, None, fingerprint)
    if replaced is not None:
        row.replaced_version = replaced
        row.replaced_at = dt.datetime.now(dt.UTC)
        row.notice_dismissed = False
        db.add(row)
        db.commit()
    seed_builtin_translations(db, bundle)
    return row


#: Кэш разобранного бандла. Ключ — время загрузки: оно меняется и при
#: приёме нового бандла, и при перекрытии вложенным. Разбор мегабайтного
#: JSON на каждый запрос списка правил — это лишние десятки миллисекунд
#: на строку, а бандл меняется дважды в год.
_cache: tuple[dt.datetime, AttackBundle] | None = None


def invalidate_cache() -> None:
    """Сбросить кэш. Нужен после записи перевода: бандл тот же,
    а русский текст в нём изменился."""
    global _cache
    _cache = None


def current(db: Session) -> AttackBundle:
    """Действующий бандл с наложенным переводом."""
    global _cache
    row = ensure_bundle(db)
    if _cache is not None and _cache[0] == row.loaded_at:
        return _cache[1]
    bundle = _row_to_bundle(row)
    translations = {r.technique_id: r for r in db.query(AttackTranslation)}
    for technique in bundle.techniques:
        translation = translations.get(technique.technique_id)
        if translation is None:
            continue
        technique.name_ru = translation.name_ru or None
        technique.description_ru = translation.description_ru or None
    _cache = (row.loaded_at, bundle)
    return bundle


# --------------------------------------------------------------------------
# Загрузка нового бандла и разница с действующим
# --------------------------------------------------------------------------


class BundleDiff(BaseModel):
    """Что изменится, если принять загруженный бандл."""

    version: str | None = None
    current_version: str | None = None
    added: list[str] = Field(default_factory=list)
    changed: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    #: Тактики: их состав меняется редко, но когда меняется — это ломает
    #: и матрицу, и словарь названий (в 19.2 «обход защиты» разделили надвое).
    tactics_added: list[str] = Field(default_factory=list)
    tactics_removed: list[str] = Field(default_factory=list)
    #: Разметка, привязанная к исчезнувшим техникам, требует пересмотра.
    untranslated: int = 0
    stale_translations: int = 0


def parse_uploaded(data: bytes) -> AttackBundle:
    """Разбор загруженного STIX-бандла во внутреннюю выжимку."""
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".json", delete=True) as tmp:
        tmp.write(data)
        tmp.flush()
        return load_bundle(Path(tmp.name))


def diff(db: Session, incoming: AttackBundle) -> BundleDiff:
    """Разница между загруженным и действующим бандлом."""
    live = current(db)
    live_by_id = live.by_id()
    incoming_by_id = incoming.by_id()
    translations = {r.technique_id: r for r in db.query(AttackTranslation)}

    added = sorted(set(incoming_by_id) - set(live_by_id))
    removed = sorted(set(live_by_id) - set(incoming_by_id))
    changed = sorted(
        tid
        for tid in set(incoming_by_id) & set(live_by_id)
        if source_hash(incoming_by_id[tid]) != source_hash(live_by_id[tid])
    )

    untranslated = 0
    stale = 0
    for technique in incoming.techniques:
        translation = translations.get(technique.technique_id)
        if translation is None or not translation.name_ru:
            untranslated += 1
        elif translation.source_hash != source_hash(technique):
            stale += 1

    live_tactics = {t.shortname for t in live.tactics}
    incoming_tactics = {t.shortname for t in incoming.tactics}
    return BundleDiff(
        version=incoming.version,
        current_version=live.version,
        added=added,
        changed=changed,
        removed=removed,
        tactics_added=sorted(incoming_tactics - live_tactics),
        tactics_removed=sorted(live_tactics - incoming_tactics),
        untranslated=untranslated,
        stale_translations=stale,
    )


def accept(
    db: Session, incoming: AttackBundle, login: str | None, source: str = SOURCE_UPLOADED
) -> AttackBundleRow:
    """Принять загруженный бандл как действующий.

    Снимает сообщение о прошлой замене: человек только что сам выбрал
    версию, и напоминать ему о предыдущей подмене больше незачем.

    `source` запоминает, откуда бандл взялся: файлом его принесли или
    скачали с сайта MITRE — это видно в состоянии матрицы.
    """
    row = _store(db, incoming, source, login, builtin_fingerprint())
    row.replaced_version = None
    row.replaced_at = None
    row.notice_dismissed = True
    db.add(row)
    db.commit()
    return row


def replacement_notice(row: AttackBundleRow) -> dict[str, object] | None:
    """Сообщение о том, что поставка перекрыла загруженную матрицу."""
    if row.replaced_version is None or row.notice_dismissed:
        return None
    return {
        "replaced_version": row.replaced_version,
        "current_version": row.version,
        # Понижение выделяется отдельно: это не просто смена версии,
        # а откат назад, и разметка, сделанная на новой матрице,
        # окажется помеченной как сделанная на другой версии.
        "downgraded": version_key(row.version) < version_key(row.replaced_version),
        "replaced_at": row.replaced_at.isoformat() if row.replaced_at else None,
    }


def dismiss_notice(db: Session) -> None:
    row = db.get(AttackBundleRow, 1)
    if row is not None:
        row.notice_dismissed = True
        db.add(row)
        db.commit()


# --------------------------------------------------------------------------
# Состояние перевода
# --------------------------------------------------------------------------


class TranslationGap(BaseModel):
    technique_id: str
    name: str
    #: missing — перевода нет вовсе, stale — исходник изменился после перевода.
    reason: str


def gaps(db: Session, bundle: AttackBundle | None = None) -> list[TranslationGap]:
    """Техники без перевода и с устаревшим переводом.

    Устаревший перевод опаснее отсутствующего: отсутствие видно сразу,
    а устаревший выглядит как нормальный русский текст, просто описывает
    не ту технику.
    """
    book = bundle or current(db)
    translations = {r.technique_id: r for r in db.query(AttackTranslation)}
    out: list[TranslationGap] = []
    for technique in book.techniques:
        translation = translations.get(technique.technique_id)
        if translation is None or not translation.name_ru:
            out.append(
                TranslationGap(
                    technique_id=technique.technique_id, name=technique.name, reason="missing"
                )
            )
        elif translation.source_hash != source_hash(technique):
            out.append(
                TranslationGap(
                    technique_id=technique.technique_id, name=technique.name, reason="stale"
                )
            )
    return out
