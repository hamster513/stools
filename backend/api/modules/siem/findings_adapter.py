"""Находки гигиены SIEM на общих статусах платформы (спека статусов §3).

Область одна (`scope_id = 0`), свежие данные — находки активного снапшота
базы: последнего, чей разбор завершился. Снапшот, который ещё загружается,
находок не имеет, и сверка по нему закрыла бы всё разом.

Ключ находки — `object_uuid|kind|<подпись>`, где подпись — HMAC-SHA256 с
солью установки от `(object_uuid, kind, field, value_hash)`, первые 32
шестнадцатеричных знака. Так ключ воспроизводит прежнее сопоставление
вердикта с находкой по (object_uuid, kind, field, value_hash), но не несёт
sha256 значения: ключ уходит в ответы API и в «Мои находки», а несолёный
хеш адреса или имени узла восстанавливается словарём — значения же в списках
не отдаются никогда (контракт, «Общие правила»). Поле в ключ открытым
текстом не входит ещё и потому, что колонка ключа — 128 знаков, а поле —
до 255. Соль хранится в `app_setting` (`SALT_SETTING`), заводится миграцией
`c6d7e8f9a0b1`, а если её нет (чистая база тестов) — при первом обращении.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import logging
import secrets
from collections.abc import Iterable
from itertools import batched
from urllib.parse import urlencode

from sqlalchemy import exists, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import Exists

from api.db.models import AppSetting, Finding, Job, Snapshot
from api.platform.findings.adapters import CurrentFinding, safe_reconcile

log = logging.getLogger(__name__)

MODULE = "siem"
SCOPE = 0
SALT_SETTING = "siem_finding_key"
#: Подписи классов — как в интерфейсе модуля (FINDING_KIND_LABELS).
KIND_TITLES = {1: "дублирует список", 2: "IP / CIDR / FQDN", 3: "not in_list из 3+", 4: "доменный SID", 5: "одиночный литерал"}
_CHUNK = 5000


def finding_key(salt: bytes, object_uuid: str, kind: int, field: str, value_hash: str) -> str:
    sign = hmac.new(salt, f"{object_uuid}|{kind}|{field}|{value_hash}".encode(), hashlib.sha256).hexdigest()
    return f"{object_uuid}|{kind}|{sign[:32]}"


def key_of(salt: bytes, f: Finding) -> str:
    return finding_key(salt, f.object_uuid, f.kind, f.field, f.value_hash)


def key_salt(db: Session) -> bytes:
    """Соль ключей. Заводится отдельной транзакцией: откат запроса, в котором
    её впервые спросили, не должен оставить в базе ключи от исчезнувшей соли."""
    row = db.get(AppSetting, SALT_SETTING)
    if row is None:
        with db.get_bind().engine.connect() as conn:
            conn.execute(pg_insert(AppSetting).values(
                key=SALT_SETTING, value_json=json.dumps({"salt": secrets.token_hex(32)}),
                updated_at=dt.datetime.now(dt.UTC), updated_by="system",
            ).on_conflict_do_nothing(index_elements=["key"]))
            conn.commit()
        row = db.get(AppSetting, SALT_SETTING)
        assert row is not None
    return bytes.fromhex(json.loads(row.value_json)["salt"])


def _parsed() -> Exists:
    """Снапшот разобран: у него есть завершённое задание."""
    return exists().where(Job.snapshot_id == Snapshot.id, Job.status == "done")


def active_snapshot_id(db: Session) -> int | None:
    value: int | None = db.scalar(select(func.max(Snapshot.id)).where(_parsed()))
    return value


def _previous_snapshot_id(db: Session, snapshot_id: int) -> int | None:
    value: int | None = db.scalar(select(func.max(Snapshot.id)).where(_parsed(), Snapshot.id < snapshot_id))
    return value


def title_of(object_name: str, kind: int, field: str) -> str:
    return f"{object_name}: {KIND_TITLES.get(kind, f'класс {kind}')}, поле {field}"


def findings_of(db: Session, snapshot_id: int, salt: bytes) -> list[CurrentFinding]:
    """Находки снапшота — только нужные колонки, без значений."""
    rows = db.execute(select(Finding.object_uuid, Finding.object_name, Finding.kind, Finding.field,
                             Finding.value_hash, Finding.severity).where(Finding.snapshot_id == snapshot_id))
    return [CurrentFinding(key=finding_key(salt, uuid, kind, field, vh), title=title_of(name, kind, field), severity=sev)
            for uuid, name, kind, field, vh, sev in rows]


class SiemFindingAdapter:
    module = MODULE

    def scopes(self, db: Session) -> Iterable[int]:
        return [SCOPE]

    def has_scope(self, db: Session, scope_id: int) -> bool:
        return scope_id == SCOPE

    def current(self, db: Session, scope_id: int) -> Iterable[CurrentFinding] | None:
        """Находки активного снапшота; без разобранных снапшотов данных нет — None."""
        active = active_snapshot_id(db) if scope_id == SCOPE else None
        return findings_of(db, active, key_salt(db)) if active is not None else None

    def first_seen_many(self, db: Session, scope_id: int, keys: Iterable[str]) -> dict[str, dt.datetime]:
        """Время загрузки самого раннего снапшота с находкой. Ключ подписан, поэтому
        отбор идёт по uuid объекта из ключа, а совпадение проверяется подписью."""
        wanted = set(keys)
        uuids = {k.split("|", 1)[0] for k in wanted}
        if scope_id != SCOPE or not uuids:
            return {}
        salt = key_salt(db)
        found: dict[str, dt.datetime] = {}
        for chunk in batched(uuids, _CHUNK):
            for uuid, kind, field, vh, at in db.execute(
                select(Finding.object_uuid, Finding.kind, Finding.field, Finding.value_hash, func.min(Snapshot.created_at))
                .join(Snapshot, Finding.snapshot_id == Snapshot.id).where(Finding.object_uuid.in_(chunk))
                .group_by(Finding.object_uuid, Finding.kind, Finding.field, Finding.value_hash)
            ):
                key = finding_key(salt, uuid, kind, field, vh)
                if key in wanted and (key not in found or at < found[key]):
                    found[key] = at
        return found

    def first_seen(self, db: Session, scope_id: int, key: str) -> dt.datetime | None:
        return self.first_seen_many(db, scope_id, [key]).get(key)

    def link(self, scope_id: int, key: str) -> str:
        return f"/siem/hygiene?{urlencode({'key': key})}"


ADAPTER = SiemFindingAdapter()


def reconcile(db: Session) -> None:
    """Сверка статусов с активным снапшотом — в конце загрузки, переразбора и
    пересчёта по профилю, после commit данных модуля. Пропавшие с предыдущего
    разобранного снапшота находки получают строки состояния, чтобы закрыться
    системой, а не исчезнуть молча."""
    try:
        # Точка сохранения: сбой чтения откатывает только её, не работу вызывающего.
        with db.begin_nested():
            active = active_snapshot_id(db)
            if active is None:
                return
            salt = key_salt(db)
            prev = _previous_snapshot_id(db, active)
            disappeared: list[CurrentFinding] = []
            if prev is not None:
                now = {f.key for f in findings_of(db, active, salt)}
                disappeared = [f for f in findings_of(db, prev, salt) if f.key not in now]
    # Данные модуля уже записаны: сбой здесь, как и в самой сверке, их не роняет.
    except Exception:
        log.exception("сверка статусов находок siem не начата")
        return
    safe_reconcile(db, MODULE, SCOPE, f"снапшот #{active}", disappeared=disappeared)
