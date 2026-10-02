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
`c6d7e8f9a0b1`, а если её нет и решений SIEM ещё нет (чистая база) — при
первом обращении. Пропавшая соль при живых решениях заново не заводится:
новая соль молча сделала бы все решения ничьими (`SaltMissing`).

Автоматика («устранена», «переоткрыта», шаг «пропали с прошлого снапшота»)
срабатывает только на новой выгрузке и только если она и предыдущий
разобранный снапшот посчитаны одинаково: той же версией разбора и с тем же
отпечатком профиля (`profile_hash`). Переразбор, смена профиля, другая
версия или профиль меняют находки без изменений в самой базе знаний — тогда
у строк обновляется только наличие, подпись и тяжесть.
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
from typing import NamedTuple
from urllib.parse import urlencode

from sqlalchemy import exists, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import Exists

from api.db.models import AppSetting, Finding, Job, Snapshot
from api.platform.findings.adapters import CurrentFinding, safe_reconcile
from api.platform.findings.models import FindingState
from kbaudit import __version__ as PARSER_VERSION
from kbaudit.profile import Profile

log = logging.getLogger(__name__)

MODULE = "siem"
SCOPE = 0
SALT_SETTING = "siem_finding_key"
#: Подписи классов — как в интерфейсе модуля (FINDING_KIND_LABELS).
KIND_TITLES = {1: "дублирует список", 2: "IP / CIDR / FQDN", 3: "not in_list из 3+", 4: "доменный SID", 5: "одиночный литерал"}
_CHUNK = 5000


class SaltMissing(RuntimeError):
    """Соли ключей нет, а решения SIEM есть: ключи не воспроизвести."""


# ---- Чем посчитаны находки снапшота ------------------------------------------------


def profile_hash(profile: Profile) -> str:
    """Отпечаток той части профиля, от которой зависят находки: роли полей и
    служебные учётные записи (kbaudit.report.build_report). Схема имён в него
    не входит: она своя у каждой выгрузки (в ней счётчики правил), а находок
    не меняет; не входят и роли списков, и кто подтвердил профиль."""
    part = {
        "environmental": sorted(set(profile.field_roles.environmental)),
        "technical": sorted(set(profile.field_roles.technical)),
        "builtin_accounts": sorted(set(profile.builtin_accounts)),
    }
    return hashlib.sha256(json.dumps(part, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def stamp(snapshot: Snapshot, profile: Profile) -> None:
    """Запомнить у снапшота, чем посчитаны его находки, — в той же транзакции, что и они."""
    snapshot.parser_version = PARSER_VERSION
    snapshot.profile_hash = profile_hash(profile)


def finding_key(salt: bytes, object_uuid: str, kind: int, field: str, value_hash: str) -> str:
    sign = hmac.new(salt, f"{object_uuid}|{kind}|{field}|{value_hash}".encode(), hashlib.sha256).hexdigest()
    return f"{object_uuid}|{kind}|{sign[:32]}"


def key_of(salt: bytes, f: Finding) -> str:
    return finding_key(salt, f.object_uuid, f.kind, f.field, f.value_hash)


def key_salt(db: Session) -> bytes:
    """Соль ключей. Заводится отдельной транзакцией: откат запроса, в котором
    её впервые спросили, не должен оставить в базе ключи от исчезнувшей соли.
    Заводится, только пока решений SIEM нет; иначе — `SaltMissing`: соль
    потеряна (восстановление без `app_setting`?), и новая отвязала бы решения."""
    row = db.get(AppSetting, SALT_SETTING)
    if row is None:
        if db.scalar(select(exists().where(FindingState.module == MODULE))):
            log.error("соли ключей находок SIEM (app_setting.%s) нет, а статусы находок SIEM есть: "
                      "ключи не воспроизвести, сверка статусов пропускается, статусы показываются как «Новая». "
                      "Восстановите app_setting.%s из резервной копии", SALT_SETTING, SALT_SETTING)
            raise SaltMissing(f"нет соли ключей находок SIEM (app_setting.{SALT_SETTING})")
        with db.get_bind().engine.connect() as conn:
            conn.execute(pg_insert(AppSetting).values(
                key=SALT_SETTING, value_json=json.dumps({"salt": secrets.token_hex(32)}),
                updated_at=dt.datetime.now(dt.UTC), updated_by="system",
            ).on_conflict_do_nothing(index_elements=["key"]))
            conn.commit()
        row = db.get(AppSetting, SALT_SETTING)
        assert row is not None
    return bytes.fromhex(json.loads(row.value_json)["salt"])


def display_salt(db: Session) -> tuple[bytes, bool]:
    """Соль для показа: без соли — случайная, ключи которой не совпадут ни с
    одним решением (все находки — «Новая»), и признак `True` «ключи сломаны»."""
    try:
        return key_salt(db), False
    except SaltMissing:
        return secrets.token_bytes(32), True


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


class FindingView(NamedTuple):
    """Находка для списков: без значения и фрагмента тела — их отдаёт только /detail."""

    id: int
    snapshot_id: int
    object_type: str
    object_uuid: str
    object_name: str
    kind: int
    severity: str
    field: str
    value_hash: str
    polarity: str
    in_table: bool
    shape: str | None
    table_name: str | None
    has_value: bool


_VIEW = (Finding.id, Finding.snapshot_id, Finding.object_type, Finding.object_uuid, Finding.object_name, Finding.kind,
         Finding.severity, Finding.field, Finding.value_hash, Finding.polarity, Finding.in_table, Finding.shape,
         Finding.table_name, (Finding.value != "").label("has_value"))


def view_key(salt: bytes, f: FindingView) -> str:
    return finding_key(salt, f.object_uuid, f.kind, f.field, f.value_hash)


def findings_view(db: Session, snapshot_id: int) -> list[FindingView]:
    return [FindingView(*row) for row in db.execute(select(*_VIEW).where(Finding.snapshot_id == snapshot_id))]


def last_known(db: Session, salt: bytes, keys: set[str]) -> dict[str, FindingView]:
    """Находки по ключам, каждая — из самого позднего снапшота, где была: один
    запрос на пачку uuid (`DISTINCT ON` по составу ключа), без значений.
    Отбор по uuid объекта из ключа, совпадение — по подписи."""
    found: dict[str, FindingView] = {}
    identity = (Finding.object_uuid, Finding.kind, Finding.field, Finding.value_hash)
    for chunk in batched({k.split("|", 1)[0] for k in keys}, _CHUNK):
        for row in db.execute(select(*_VIEW).where(Finding.object_uuid.in_(chunk)).distinct(*identity)
                              .order_by(*identity, Finding.snapshot_id.desc(), Finding.id)):
            view = FindingView(*row)
            key = view_key(salt, view)
            if key in keys:
                found[key] = view
    return found


def titles_for(db: Session, salt: bytes, keys: set[str]) -> dict[str, CurrentFinding]:
    """Подпись и тяжесть по последнему снапшоту, где находка была."""
    return {key: CurrentFinding(key=key, title=title_of(f.object_name, f.kind, f.field), severity=f.severity)
            for key, f in last_known(db, salt, keys).items()}


class SiemFindingAdapter:
    module = MODULE

    def scopes(self, db: Session) -> Iterable[int]:
        return [SCOPE]

    def has_scope(self, db: Session, scope_id: int) -> bool:
        return scope_id == SCOPE

    def current(self, db: Session, scope_id: int) -> Iterable[CurrentFinding] | None:
        """Находки активного снапшота; без разобранных снапшотов данных нет — None."""
        active = active_snapshot_id(db) if scope_id == SCOPE else None
        if active is None:
            return None
        try:
            salt = key_salt(db)
        except SaltMissing:
            return None
        return findings_of(db, active, salt)

    def first_seen_many(self, db: Session, scope_id: int, keys: Iterable[str]) -> dict[str, dt.datetime]:
        """Время загрузки самого раннего снапшота с находкой. Ключ подписан, поэтому
        отбор идёт по uuid объекта из ключа, а совпадение проверяется подписью."""
        wanted = set(keys)
        uuids = {k.split("|", 1)[0] for k in wanted}
        if scope_id != SCOPE or not uuids:
            return {}
        try:
            salt = key_salt(db)
        except SaltMissing:
            return {}
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


def _incomparable(active: Snapshot, prev: Snapshot | None, upload: bool) -> str | None:
    """Почему находки активного снапшота нельзя сравнивать с прошлыми; None — можно."""
    if not upload:
        return "пересчитан (переразбор или смена профиля)"
    if prev is None:
        return None
    if active.parser_version != prev.parser_version:
        return f"разобран версией {active.parser_version!r}, предыдущий #{prev.id} — {prev.parser_version!r}"
    if active.profile_hash != prev.profile_hash:
        return f"посчитан с другим профилем, чем предыдущий #{prev.id}"
    return None


def reconcile(db: Session, snapshot_id: int, *, upload: bool) -> None:
    """Сверка статусов с активным снапшотом — в конце загрузки, переразбора и
    пересчёта по профилю, после commit данных модуля. `snapshot_id` — снапшот,
    который только что записан; не активный (старый пересчитан, старая загрузка
    разобралась после новой) — статусы по активному, а он не менялся.

    Новая выгрузка (`upload`), посчитанная как предыдущая, — полная сверка:
    пропавшие с предыдущего разобранного снапшота находки получают строки
    состояния, чтобы закрыться системой, а не исчезнуть молча. Иначе — только
    наличие, подпись и тяжесть строк, без смен статусов и событий."""
    why: str | None = None
    try:
        # Точка сохранения: сбой чтения откатывает только её, не работу вызывающего.
        with db.begin_nested():
            active_id = active_snapshot_id(db)
            if active_id is None or active_id != snapshot_id:
                return
            salt = key_salt(db)
            active = db.get(Snapshot, active_id)
            assert active is not None
            prev_id = _previous_snapshot_id(db, active_id)
            prev = db.get(Snapshot, prev_id) if prev_id is not None else None
            why = _incomparable(active, prev, upload)
            disappeared: list[CurrentFinding] = []
            if why is None and prev is not None:
                now = {f.key for f in findings_of(db, active_id, salt)}
                disappeared = [f for f in findings_of(db, prev.id, salt) if f.key not in now]
    except SaltMissing:
        return  # key_salt уже сказал в журнал
    # Данные модуля уже записаны: сбой здесь, как и в самой сверке, их не роняет.
    except Exception:
        log.exception("сверка статусов находок siem не начата")
        return
    if why is not None:
        log.warning("siem: снапшот #%s %s — статусы находок не меняются, обновляется только наличие; "
                    "автоматика вернётся со следующей выгрузкой, посчитанной так же", active_id, why)
        _refresh_rows(db, salt, active_id)
        return
    safe_reconcile(db, MODULE, SCOPE, f"снапшот #{active_id}", disappeared=disappeared)
    _refresh_rows(db, salt, None)


def _refresh_rows(db: Session, salt: bytes, snapshot_id: int | None) -> None:
    """Без автоматики: статусы и история не меняются. С `snapshot_id` у всех строк
    обновляются наличие, подпись и тяжесть по этому снапшоту. Строкам без подписи
    (заведены массовой сменой, перенесены из вердиктов) она берётся из последнего
    снапшота, где находка была, — иначе «Мои находки» показали бы пустую строку."""
    from api.platform.findings import service

    try:
        with db.begin_nested():
            service.lock_scope(db, MODULE, SCOPE)
            if snapshot_id is None:
                rows = list(db.scalars(select(FindingState).where(
                    FindingState.module == MODULE, FindingState.scope_id == SCOPE, FindingState.title == "",
                ).execution_options(populate_existing=True)))
            else:
                rows = list(service.state_map(db, MODULE, SCOPE, fresh=True).values())
                current = {f.key: f for f in findings_of(db, snapshot_id, salt)}
                for row in rows:
                    found = current.get(row.key)
                    if row.present != (found is not None):
                        row.present = found is not None
                    if found is not None:
                        if found.title and row.title != found.title[:512]:
                            row.title = found.title[:512]
                        if found.severity and row.severity != found.severity[:16]:
                            row.severity = found.severity[:16]
            untitled = {r.key: r for r in rows if not r.title}
            for key, found in (titles_for(db, salt, set(untitled)) if untitled else {}).items():
                untitled[key].title = found.title[:512]
                if not untitled[key].severity:
                    untitled[key].severity = found.severity[:16]
        db.commit()
    except Exception:
        log.exception("обновление строк статусов находок siem не удалось")
        db.rollback()
