"""Инвентарь хостов снапшота с фасетами; карточка хоста с его находками; профили, активные на хосте."""
from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ksc.core.checks import CHECK_BY_CODE
from api.modules.ksc.core.checks.hosts import COMPONENT_OFF_STATES
from api.modules.ksc.core.dictionary.components import component_title
from api.modules.ksc.core.export import status_reasons
from api.modules.ksc.core.profile_activation import (
    REASON_DISABLED,
    Activation,
    evaluate,
    parse_condition,
)
from api.modules.ksc.models import (
    KscExclusion,
    KscFinding,
    KscHost,
    KscNetRule,
    KscPolicy,
    KscPolicyScope,
    KscProfile,
    KscSnapshot,
)
from api.modules.ksc.services.policy_store import ensure_policy_tables
from api.modules.ksc.services.settings import load_config
from api.platform.export import Column, export_response
from api.platform.filters import QueryList, QueryStatus, matches, multi
from api.platform.findings import service as finding_svc
from api.platform.findings.core import STATUS_TITLES
from api.settings import Settings, get_settings

router = APIRouter(tags=["ksc"])

MAX_LIMIT = 1000
AGENT = ("none", "silent", "alive")
PROTECTION = ("none", "off", "on")
BASES = ("fresh", "old", "unknown")
COMPONENT_STATES = ("on", "off", "other", "none")
#: Худшее состояние побеждает, если хост перечисляет компонент дважды (две версии продукта): выключен > прочее > работает.
_COMPONENT_RANK = {"on": 0, "other": 1, "off": 2}
NO_TAGS = "-"
#: Сеансы хоста для фасета: идёт сеанс; заходили раньше; никто (в том числе только группы); пользователи не собраны.
SESSIONS = ("active", "past", "none", "not_collected")
#: Ключи пользователей и владельца в `extra_json`: в `extra` ответа не повторяются, отдаются полями `users`, `owner`, `users_collected`.
USER_KEYS = ("users", "owner", "users_collected")


def _agent(h: KscHost, now: dt.datetime, silent_days: int) -> str:
    if not h.agent_installed:
        return "none"
    if h.last_seen_at is None or (now - h.last_seen_at).days > silent_days:
        return "silent"
    return "alive"


def _bases(h: KscHost, now: dt.datetime, old_days: int) -> str:
    if h.bases_at is None:
        return "unknown"
    return "old" if (now - h.bases_at).days > old_days else "fresh"


def _component_state(code: Any) -> str:
    if code == 4:
        return "on"
    return "off" if code in COMPONENT_OFF_STATES else "other"


def _components(h: KscHost) -> dict[str, str]:
    """Состояние каждого компонента защиты хоста: on | off | other; ключ — единое (русское) название, английское сведено к нему."""
    return {name: _component_state(code) for name, code in _component_rows(h)}


def _component_rows(h: KscHost) -> list[tuple[str, int]]:
    """Компоненты хоста под единым названием, одна строка на компонент; при повторе остаётся строка с худшим состоянием."""
    worst: dict[str, tuple[str, int]] = {}
    for name, code in json.loads(h.components_json or "[]"):
        title = component_title(name)
        if title not in worst or _COMPONENT_RANK[_component_state(code)] > _COMPONENT_RANK[_component_state(worst[title][1])]:
            worst[title] = (title, code)
    return list(worst.values())


def _tags(h: KscHost, collected: bool) -> list[str] | None:
    """Теги хоста; None — сборщик секцию тегов не присылал (не собрано, а не «без тегов»)."""
    if not collected:
        return None
    return list(json.loads(h.extra_json or "{}").get("tags", []))


def _tags_collected(rows: list[KscHost]) -> bool:
    """Секция тегов в выгрузке была, если ключ `tags` есть хотя бы у одного хоста снапшота."""
    return any("tags" in json.loads(h.extra_json or "{}") for h in rows)


@dataclass(frozen=True)
class HostUsers:
    """Пользователи хоста из `extra_json` (сборщик 1.4)."""

    #: Секция `host_users` была в выгрузке; иначе (сборщик до 1.4) пользователей и владельца нет — «не собрано».
    collected: bool
    #: None — не собрано: секции нет или запрос по этому хосту отказал; `[]` — никто не заходил.
    users: list[dict[str, Any]] | None
    #: `{sid, sam, display_name}`; `{owner_id}` — владелец задан, но не в списке пользователей хоста; None — не задан или не собран.
    owner: dict[str, Any] | None

    def session(self) -> str:
        """Группы в сеансах не считаются (KSC отдаёт их в том же списке)."""
        if self.users is None:
            return "not_collected"
        people = [u for u in self.users if not u.get("group")]
        if any(u.get("active") for u in people):
            return "active"
        return "past" if people else "none"

    def needles(self) -> list[str]:
        """Что ищется в пользователях хоста: учётная запись, UPN, отображаемое имя (в нижнем регистре); группы не в счёт."""
        return [str(u.get(k) or "").lower() for u in self.users or [] if not u.get("group") for k in ("sam", "upn", "display_name")]


def _host_users(h: KscHost) -> HostUsers:
    extra = json.loads(h.extra_json or "{}")
    if not extra.get("users_collected"):
        return HostUsers(False, None, None)
    return HostUsers(True, extra.get("users"), extra.get("owner"))


def _status_reasons(h: KscHost) -> list[str] | None:
    """Причины статуса по KSC из `extra_json`; None — строка записана до разбора причин (ключа `status_mask` нет):
    причины не разобраны, пересчёт снапшота их заполнит."""
    extra = json.loads(h.extra_json or "{}")
    if "status_mask" not in extra:
        return None
    return status_reasons(h.status, int(extra.get("status_mask") or 0), str(extra.get("status_text") or ""))


def _item(h: KscHost, agent: str, bases: str, findings: int, tags: list[str] | None) -> dict[str, Any]:
    extra = {k: v for k, v in json.loads(h.extra_json or "{}").items() if k not in USER_KEYS}
    people = _host_users(h)
    return {
        "id": h.id, "host_id": h.host_id, "name": h.name, "fqdn": h.fqdn, "domain": h.domain, "group": h.group_path, "os": h.os, "ip": h.ip,
        "agent": agent, "agent_version": h.agent_version, "last_seen_at": h.last_seen_at.isoformat() if h.last_seen_at else None,
        "product": h.product, "product_version": h.product_version, "protection": h.protection, "rtp_state": h.rtp_state,
        "bases_at": h.bases_at.isoformat() if h.bases_at else None, "bases": bases,
        "last_fullscan_at": h.last_fullscan_at.isoformat() if h.last_fullscan_at else None,
        "status": h.status, "status_reasons": _status_reasons(h), "threats": h.threats, "unassigned": h.unassigned, "in_ad": h.in_ad,
        "components": _component_rows(h), "extra": extra, "tags": tags, "findings": findings,
        "users": people.users, "users_collected": people.collected, "owner": people.owner,
    }


def _snapshot(db: Session, snapshot_id: int, settings: Settings) -> KscSnapshot:
    """Снапшот с заполненными таблицами политик и группами хостов (старый дозаполняется из файла при первом чтении)."""
    snap = db.get(KscSnapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    ensure_policy_tables(db, snap, settings.data_dir)
    return snap


def _host_key(h: KscHost) -> str:
    """Тот же ключ, что у находки: имя (KLHST_WKS_DN) не уникально."""
    return h.fqdn or h.name.lower()


def _findings_per_host(db: Session, snap: KscSnapshot) -> dict[str, int]:
    """Сколько у хоста находок, которые учитываются (настройка платформы `counted`)."""
    counted = finding_svc.counted_statuses(db)
    states = finding_svc.state_map(db, "ksc", snap.server_id)
    rows = db.execute(select(KscFinding.host_key, KscFinding.key).where(KscFinding.snapshot_id == snap.id, KscFinding.host_key != "")).all()
    per_host: dict[str, int] = {}
    for host, key in rows:
        if finding_svc.is_counted(states.get(key), counted):
            per_host[host] = per_host.get(host, 0) + 1
    return per_host


def _scope_policies(db: Session, snapshot_id: int, h: KscHost) -> list[tuple[KscPolicy, bool]]:
    """Политики, действующие на группу хоста, по имени; bool — политика создана в этой группе, а не унаследована."""
    if h.group_id is None:
        return []
    rows = db.execute(
        select(KscPolicy, KscPolicyScope.own)
        .join(KscPolicyScope, (KscPolicyScope.snapshot_id == KscPolicy.snapshot_id) & (KscPolicyScope.policy_id == KscPolicy.policy_id))
        .where(KscPolicy.snapshot_id == snapshot_id, KscPolicyScope.group_id == h.group_id)
    ).all()
    return sorted(((p, own) for p, own in rows), key=lambda r: (r[0].name.lower(), r[0].policy_id))


def _host_policies(db: Session, snapshot_id: int, h: KscHost) -> list[dict[str, Any]]:
    """Политики, действующие на группу хоста; `own` — политика создана в этой группе, а не унаследована."""
    return [{"id": p.policy_id, "name": p.name, "product": p.product, "active": p.active, "own": own} for p, own in _scope_policies(db, snapshot_id, h)]


def _host(db: Session, snapshot_id: int, host_id: str) -> KscHost:
    h = db.execute(select(KscHost).where(KscHost.snapshot_id == snapshot_id, KscHost.host_id == host_id)).scalars().first()
    if h is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="хост не найден")
    return h


def _tags_collected_db(db: Session, snapshot_id: int) -> bool:
    """Секция тегов была в выгрузке, если ключ `tags` есть хотя бы у одного хоста снапшота (поиск по тексту, без разбора JSON всех хостов)."""
    has_tags = select(KscHost.id).where(KscHost.snapshot_id == snapshot_id, KscHost.extra_json.like('%"tags"%')).limit(1)
    return db.scalar(has_tags) is not None


@dataclass(frozen=True)
class HostScope:
    """Что действует на хост: политики его группы и активация каждого их профиля по тегам хоста."""

    host: KscHost
    #: None — теги не собраны.
    tags: list[str] | None
    policies: list[tuple[KscPolicy, bool]]
    #: По политикам в порядке `policies`, внутри — по приоритету; выключенный профиль — не активен, «профиль выключен».
    profiles: list[tuple[KscProfile, Activation]]


def host_scope(db: Session, snapshot_id: int, host_id: str) -> HostScope:
    """404 — хоста нет в снапшоте. Таблицы политик снапшота должны быть заполнены (`_snapshot`)."""
    h = _host(db, snapshot_id, host_id)
    tags = _tags(h, _tags_collected_db(db, snapshot_id))
    policies = _scope_policies(db, snapshot_id, h)
    order = {p.policy_id: n for n, (p, _) in enumerate(policies)}
    rows: list[KscProfile] = []
    if order:
        rows = list(db.execute(select(KscProfile).where(KscProfile.snapshot_id == snapshot_id, KscProfile.policy_id.in_(list(order)))).scalars())
    profiles: list[tuple[KscProfile, Activation]] = []
    for r in sorted(rows, key=lambda r: (order[r.policy_id], r.priority, r.id)):
        groups = parse_condition(json.loads(r.condition_json or "{}"))
        a = evaluate(groups, tags) if r.enabled else Activation(False, (), groups, REASON_DISABLED)
        profiles.append((r, a))
    return HostScope(h, tags, policies, profiles)


def _object_counts(db: Session, model: type[KscExclusion | KscNetRule], snapshot_id: int, policy_ids: list[int]) -> dict[tuple[int, str], int]:
    """(политика, профиль) → записей извлекателя в снапшоте."""
    if not policy_ids:
        return {}
    stmt = (
        select(model.policy_id, model.profile, func.count())
        .where(model.snapshot_id == snapshot_id, model.policy_id.in_(policy_ids))
        .group_by(model.policy_id, model.profile)
    )
    return {(pid, profile): n for pid, profile, n in db.execute(stmt).all()}


@router.get("/snapshots/{snapshot_id}/hosts")
def list_hosts(
    snapshot_id: int,
    group: QueryList = None,
    product: QueryList = None,
    agent: QueryList = None,
    protection: QueryList = None,
    bases: QueryList = None,
    in_ad: QueryList = None,
    status_: QueryStatus = None,
    status_reason: QueryList = None,
    component: QueryList = None,
    component_state: str | None = None,
    tag: QueryList = None,
    session: QueryList = None,
    user: str | None = None,
    policy: int | None = None,
    q: str | None = None,
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Фасеты `protection, agent, bases, in_ad, status, status_reason, component, tag, session, group, product` — повтором
    ключа, внутри фасета «или» (`status` — ещё и через запятую); `component_state` — одно, к любому из выбранных
    компонентов. `status_reason` — текст причины как в `status_reasons`; неизвестный текст ничего не находит.
    `session` — сеансы по данным KSC: `active` (в системе на момент сбора), `past` (заходили раньше), `none` (никто),
    `not_collected` (пользователи не собраны). `user` — подстрока без учёта регистра в учётной записи, UPN или имени
    любого пользователя хоста (в том числе заходившего раньше; группы не в счёт); `q` ищет и по ним."""
    snap = _snapshot(db, snapshot_id, settings)
    groups, products, agents, protections, bases_, in_ads, reasons_, components, tags_, sessions = (
        multi(v) for v in (group, product, agent, protection, bases, in_ad, status_reason, component, tag, session))
    # Статус, как и статусы находок, понимает и старую строку через запятую (`status=ok,warning`).
    statuses = multi(status_, commas=True)
    checked = (
        (agents, AGENT), (protections, PROTECTION), (bases_, BASES), (in_ads, ("both", "ksc_only")),
        (statuses, ("ok", "warning", "critical")), (sessions, SESSIONS), ({component_state} if component_state is not None else None, COMPONENT_STATES),
    )
    for values, allowed in checked:
        for value in sorted(values or ()):
            if value not in allowed:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"неизвестное значение фильтра «{value}»")
    if component_state and not components:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="состояние компонента задаётся вместе с названием компонента")
    cfg = load_config(db)
    per_host = _findings_per_host(db, snap)
    rows = list(db.execute(select(KscHost).where(KscHost.snapshot_id == snapshot_id)).scalars())
    tags_collected = _tags_collected(rows)
    tags = {h.id: _tags(h, tags_collected) for h in rows}
    comps = {h.id: _components(h) for h in rows}
    reasons = {h.id: _status_reasons(h) or [] for h in rows}
    people = {h.id: _host_users(h) for h in rows}
    sessions_of = {h.id: people[h.id].session() for h in rows}
    users_collected = any(p.collected for p in people.values())
    policy_groups: set[int] = set()
    if policy is not None:
        scope = select(KscPolicyScope.group_id).where(KscPolicyScope.snapshot_id == snapshot_id, KscPolicyScope.policy_id == policy)
        policy_groups = set(db.scalars(scope))
    # Хостов у сервера тысячи: фасеты и фильтры считаются в памяти, как находки в AD.
    derived = {h.id: (_agent(h, snap.collected_at, cfg.agent_silent_days), _bases(h, snap.collected_at, cfg.bases_old_days)) for h in rows}

    def has_component(h: KscHost, name: str) -> bool:
        state = comps[h.id].get(component_title(name), "none")
        # без состояния — хосты, у которых компонент есть
        return state == component_state if component_state else state != "none"

    def has_tag(own: list[str], t: str) -> bool:
        # `multi` превращает `-` («без тегов») в '' — прежний смысл тот же.
        return not own if t in (NO_TAGS, "") else t in own

    def keep(h: KscHost) -> bool:
        a, b = derived[h.id]
        if not (matches(h.group_path, groups) and matches(h.product, products) and matches(a, agents)
                and matches(h.protection, protections) and matches(b, bases_) and matches(h.in_ad, in_ads)
                and matches(h.status, statuses)):
            return False
        if components and not any(has_component(h, c) for c in components):
            return False
        if reasons_ and not any(r in reasons[h.id] for r in reasons_):
            return False
        if tags_:
            own = tags[h.id]
            if own is None or not any(has_tag(own, t) for t in tags_):
                return False
        if sessions and sessions_of[h.id] not in sessions:
            return False
        if user and not any(user.lower() in n for n in people[h.id].needles()):
            return False
        if policy is not None and (h.group_id is None or h.group_id not in policy_groups):
            return False
        if q:
            needle = q.lower()
            if (needle not in h.name.lower() and needle not in h.fqdn and needle not in h.ip and needle not in h.os.lower()
                    and not any(needle in t.lower() for t in tags[h.id] or [])
                    and not any(needle in n for n in people[h.id].needles())):
                return False
        return True

    filtered = sorted((h for h in rows if keep(h)), key=lambda h: (h.group_path.lower(), h.name.lower()))
    facets: dict[str, dict[str, Any]] = {
        "group": {}, "product": {}, "agent": dict.fromkeys(AGENT, 0), "protection": dict.fromkeys(PROTECTION, 0), "bases": dict.fromkeys(BASES, 0),
        "in_ad": {}, "status": {"ok": 0, "warning": 0, "critical": 0}, "status_reason": {}, "component": {},
        "session": dict.fromkeys(SESSIONS, 0),
    }
    if tags_collected:
        facets["tag"] = {}
    for h in filtered:
        a, b = derived[h.id]
        facets["group"][h.group_path] = facets["group"].get(h.group_path, 0) + 1
        if h.product:
            facets["product"][h.product] = facets["product"].get(h.product, 0) + 1
        facets["agent"][a] += 1
        facets["protection"][h.protection] += 1
        facets["bases"][b] += 1
        facets["session"][sessions_of[h.id]] += 1
        if h.in_ad:
            facets["in_ad"][h.in_ad] = facets["in_ad"].get(h.in_ad, 0) + 1
        facets["status"][h.status] = facets["status"].get(h.status, 0) + 1
        for r in reasons[h.id]:
            facets["status_reason"][r] = facets["status_reason"].get(r, 0) + 1
        for name, state in comps[h.id].items():
            facets["component"].setdefault(name, {"on": 0, "off": 0, "other": 0})[state] += 1
        for t in tags[h.id] or []:
            facets["tag"][t] = facets["tag"].get(t, 0) + 1
    page = filtered[offset : offset + limit]
    return {"total": len(filtered), "items": [_item(h, *derived[h.id], per_host.get(_host_key(h), 0), tags[h.id]) for h in page],
            "facets": facets if offset == 0 else None, "tags_collected": tags_collected, "users_collected": users_collected}


#: Подписи значений — как на экране (AGENT_LABELS, PROTECTION_LABELS, BASES_LABELS, IN_AD_LABELS, RTP_STATE_LABELS фронтенда).
AGENT_TITLES = {"none": "нет агента", "silent": "молчит", "alive": "на связи"}
PROTECTION_TITLES = {"none": "нет защиты", "off": "выключена", "on": "работает"}
BASES_TITLES = {"fresh": "свежие", "old": "устарели", "unknown": "неизвестно"}
IN_AD_TITLES = {"both": "в AD и KSC", "ksc_only": "только KSC"}
RTP_STATE_TITLES = {0: "неизвестно", 1: "остановлена", 2: "приостановлена", 3: "запускается", 9: "сбой", 10: "не установлена",
                    11: "не поддерживается лицензией"}

EXPORT_COLUMNS = [
    Column("name", "Хост"), Column("group", "Группа"), Column("tags", "Теги"), Column("os", "ОС"), Column("agent", "Агент"),
    Column("protection", "Защита"), Column("bases", "Базы"), Column("full_scan", "Полный поиск"), Column("threats", "Угрозы"),
    Column("in_ad", "AD"), Column("findings", "Находок"),
]
#: Выгрузке нужен весь отбор: страница списка ограничена `MAX_LIMIT`, здесь — нет.
EXPORT_ALL = 10**9


def _export_row(h: dict[str, Any]) -> dict[str, Any]:
    """Ячейки — как на экране: агент с версией, защита с состоянием при «выключена», базы — дата и свежесть."""
    agent = AGENT_TITLES.get(h["agent"], h["agent"]) + (f" · {h['agent_version']}" if h["agent_version"] else "")
    protection = PROTECTION_TITLES.get(h["protection"], h["protection"])
    if h["protection"] == "off":
        protection += f" · {RTP_STATE_TITLES.get(h['rtp_state'], h['rtp_state'])}"
    bases_at = dt.datetime.fromisoformat(h["bases_at"]).strftime("%d.%m.%Y") if h["bases_at"] else "—"
    return {
        "name": h["name"], "group": h["group"], "tags": ", ".join(h["tags"] or []), "os": h["os"], "agent": agent,
        "protection": protection, "bases": f"{bases_at} · {BASES_TITLES.get(h['bases'], h['bases'])}",
        "full_scan": dt.datetime.fromisoformat(h["last_fullscan_at"]) if h["last_fullscan_at"] else None,
        "threats": h["threats"], "in_ad": IN_AD_TITLES.get(h["in_ad"], h["in_ad"]) if h["in_ad"] else None, "findings": h["findings"],
    }


@router.get("/snapshots/{snapshot_id}/hosts/export")
def export_hosts(
    snapshot_id: int,
    group: QueryList = None,
    product: QueryList = None,
    agent: QueryList = None,
    protection: QueryList = None,
    bases: QueryList = None,
    in_ad: QueryList = None,
    status_: QueryStatus = None,
    status_reason: QueryList = None,
    component: QueryList = None,
    component_state: str | None = None,
    tag: QueryList = None,
    session: QueryList = None,
    user: str | None = None,
    policy: int | None = None,
    q: str | None = None,
    fmt: str = Query(default="csv", alias="format"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    current: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """Хосты под фильтрами списка, в его порядке — тот же отбор (`list_hosts`) без страницы."""
    page = list_hosts(snapshot_id, group, product, agent, protection, bases, in_ad, status_, status_reason, component, component_state, tag,
                      session, user, policy, q, limit=EXPORT_ALL, offset=0, db=db, settings=settings, _user=current)
    return export_response(fmt, EXPORT_COLUMNS, [_export_row(h) for h in page["items"]], module="ksc", name="hosts")


@router.get("/snapshots/{snapshot_id}/hosts/{host_id}")
def host_detail(
    snapshot_id: int,
    host_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    snap = _snapshot(db, snapshot_id, settings)
    h = _host(db, snapshot_id, host_id)
    cfg = load_config(db)
    findings = list(db.execute(select(KscFinding).where(KscFinding.snapshot_id == snapshot_id, KscFinding.host_key == _host_key(h))).scalars())
    states = finding_svc.state_map(db, "ksc", snap.server_id, [f.key for f in findings])
    counted = finding_svc.counted_statuses(db)
    items = []
    for f in findings:
        status_ = finding_svc.effective_status(states.get(f.key))
        items.append({"key": f.key, "check": f.check, "check_title": CHECK_BY_CODE[f.check].title if f.check in CHECK_BY_CODE else f.check,
                      "severity": f.severity, "status": status_, "status_title": STATUS_TITLES[status_], "details": json.loads(f.details_json or "{}")})
    # `findings` — все находки хоста со статусами; `findings_counted` — по тому же правилу, что счётчик в списке хостов.
    n_counted = sum(1 for i in items if i["status"] in counted)
    agent, bases = _agent(h, snap.collected_at, cfg.agent_silent_days), _bases(h, snap.collected_at, cfg.bases_old_days)
    return {**_item(h, agent, bases, n_counted, _tags(h, _tags_collected_db(db, snapshot_id))),
            "findings": items, "findings_counted": n_counted, "policies": _host_policies(db, snapshot_id, h)}


@router.get("/snapshots/{snapshot_id}/hosts/{host_id}/profiles")
def host_profiles(
    snapshot_id: int,
    host_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Политики группы хоста с профилями и их активацией на хосте по тегам (трактовка условия — `core/profile_activation`);
    `by_tag` — какие профили (включая выключенные) упоминают каждый тег хоста в условии."""
    _snapshot(db, snapshot_id, settings)
    scope = host_scope(db, snapshot_id, host_id)
    policy_ids = [p.policy_id for p, _ in scope.policies]
    exclusions, net_rules = _object_counts(db, KscExclusion, snapshot_id, policy_ids), _object_counts(db, KscNetRule, snapshot_id, policy_ids)
    names = {p.policy_id: p.name for p, _ in scope.policies}
    policies: list[dict[str, Any]] = []
    for p, own in scope.policies:
        policies.append({
            "id": p.policy_id, "name": p.name, "product": p.product, "active": p.active, "own": own, "profiles_collected": p.profiles is not None,
            "profiles": [
                {
                    "name": r.name, "enabled": r.enabled, "priority": r.priority, "active": a.active, "reason": a.reason, "matched_tags": list(a.matched_tags),
                    "condition": [[{"field": c.field, "text": c.text} for c in g] for g in a.groups], "settings": r.settings,
                    # У политики с неописанным продуктом записей нет потому, что продукт не описан, а не потому, что их нет.
                    "exclusions": exclusions.get((p.policy_id, r.name), 0) if p.described else None,
                    "net_rules": net_rules.get((p.policy_id, r.name), 0) if p.described else None,
                }
                for r, a in scope.profiles if r.policy_id == p.policy_id
            ],
        })
    by_tag = [
        {"tag": tag, "profiles": [
            {"policy_id": r.policy_id, "policy_name": names.get(r.policy_id, ""), "profile": r.name, "enabled": r.enabled}
            for r, a in scope.profiles if any(c.field == "tag" and str(c.value).lower() == tag.lower() for g in a.groups for c in g)
        ]}
        for tag in scope.tags or []
    ]
    collected = db.scalar(select(KscPolicy.id).where(KscPolicy.snapshot_id == snapshot_id, KscPolicy.profiles.is_not(None)).limit(1)) is not None
    return {"profiles_collected": collected, "tags": scope.tags, "policies": policies, "by_tag": by_tag}
