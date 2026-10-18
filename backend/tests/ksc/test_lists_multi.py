"""Многозначные фасеты списков KSC (хосты, исключения, сетевые правила, изменения, политики, задачи):
внутри фасета — «ИЛИ». Выбор двух значений даёт объединение выбранного по каждому порознь, а у фасетов
с одним значением на строку — ещё и сумму итогов."""
from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update
from sqlalchemy.orm import Session

from api.modules.ksc.core.policy_model import EXTRACTORS
from api.modules.ksc.models import KscHost
from tests.ksc.synthetic import build_export
from tests.ksc.test_api import upload
from tests.ksc.test_changes_api import _setup as changes_setup
from tests.ksc.test_policy_objects_api import _fake


def _items(client: TestClient, url: str, **params: Any) -> dict[Any, dict[str, Any]]:
    r = client.get(url, params={"limit": "1000", **params} if "policy-list" not in url and "tasks" not in url else params)
    assert r.status_code == 200, r.text
    body = r.json()
    if "total" in body:
        assert body["total"] == len(body["items"])
    return {i["id"]: i for i in body["items"]}


def _check(client: TestClient, url: str, param: str, a: str, b: str, *, disjoint: bool = True) -> None:
    one, two = _items(client, url, **{param: a}), _items(client, url, **{param: b})
    both = _items(client, url, **{param: [a, b]})
    assert one and (two or b == ABSENT), (param, a, b)
    assert set(both) == set(one) | set(two)
    if disjoint:
        assert len(both) == len(one) + len(two)


#: Значение, которого нет в синтетике: у фасета с единственным значением (продукт хостов — только KES,
#: действие изменений — только changed) второе значение ничего не добавляет, но и не сужает.
ABSENT = "нет-такого"


def _top_two(client: TestClient, url: str, facet: str) -> tuple[str, str]:
    r = client.get(url)
    counts = r.json()["facets"][facet]
    picked = sorted((k for k, n in counts.items() if (n if isinstance(n, int) else sum(n.values()))), key=lambda k: str(k))[:2]
    assert picked, (facet, counts)
    return str(picked[0]), str(picked[1]) if len(picked) > 1 else ABSENT


@pytest.fixture
def snap(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setitem(EXTRACTORS, "KES", _fake)
    assert upload(auth_client, build_export())["status"] == "done"
    return int(auth_client.get("/api/ksc/snapshots").json()[0]["id"])


@pytest.mark.parametrize(("facet", "disjoint"), [
    ("protection", True), ("agent", True), ("bases", True), ("status", True), ("group", True), ("product", True),
    ("component", False), ("tag", True),
])
def test_hosts(auth_client: TestClient, snap: int, facet: str, disjoint: bool) -> None:
    url = f"/api/ksc/snapshots/{snap}/hosts"
    a, b = _top_two(auth_client, url, facet)
    _check(auth_client, url, facet, a, b, disjoint=disjoint)


def test_hosts_all_and_bad_values(auth_client: TestClient, snap: int) -> None:
    url = f"/api/ksc/snapshots/{snap}/hosts"
    full = _items(auth_client, url)
    assert _items(auth_client, url, protection="all", agent="all", group="all", tag="all") == full
    _check(auth_client, url, "tag", "-", "VIP")  # «без тегов» и тег — вместе
    assert len(_items(auth_client, url, tag="-")) == 12  # `-` по-прежнему «без тегов»
    assert auth_client.get(url, params={"protection": ["on", "bogus"]}).status_code == 422
    # Статус хоста, как и статусы находок, понимает старую строку через запятую.
    a, b = _top_two(auth_client, url, "status")
    assert _items(auth_client, url, status=f"{a},{b}") == _items(auth_client, url, status=[a, b])
    # Состояние — одно, к любому из выбранных компонентов.
    a, b = _top_two(auth_client, url, "component")
    off = _items(auth_client, url, component=[a, b], component_state="off")
    assert set(off) == set(_items(auth_client, url, component=a, component_state="off")) | set(
        _items(auth_client, url, component=b, component_state="off"))


@pytest.mark.parametrize(("facet", "a", "b", "disjoint"), [
    ("policy_id", "1", "3", True), ("kind", "path", "hash", True), ("dup", "multi", "single", True),
])
def test_exclusions(auth_client: TestClient, snap: int, facet: str, a: str, b: str, disjoint: bool) -> None:
    _check(auth_client, f"/api/ksc/snapshots/{snap}/exclusions", facet, a, b, disjoint=disjoint)


@pytest.mark.parametrize(("facet", "a", "b"), [("policy_id", "1", "3"), ("action", "allow", "block"), ("direction", "in", "out")])
def test_net_rules(auth_client: TestClient, snap: int, facet: str, a: str, b: str) -> None:
    _check(auth_client, f"/api/ksc/snapshots/{snap}/net-rules", facet, a, b)


@pytest.mark.parametrize("facet", ["product", "grade"])
def test_policies(auth_client: TestClient, snap: int, facet: str) -> None:
    url = f"/api/ksc/snapshots/{snap}/policy-list"
    if facet == "grade":  # оценок у синтетики нет: «нет оценки» + «плохая» — те же, что «нет оценки»
        full = _items(auth_client, url)
        assert _items(auth_client, url, grade=["none", "bad"]) == _items(auth_client, url, grade="none") == full
        assert auth_client.get(url, params={"grade": ["none", "bogus"]}).status_code == 422
        return
    a, b = _top_two(auth_client, url, facet)
    _check(auth_client, url, facet, a, b)


def test_tasks(auth_client: TestClient, snap: int) -> None:
    url = f"/api/ksc/snapshots/{snap}/tasks"
    a, b = _top_two(auth_client, url, "type")
    _check(auth_client, url, "type", a, b)
    assert _items(auth_client, url, type="all") == _items(auth_client, url)


def test_changes(auth_client: TestClient) -> None:
    server, ids = changes_setup(auth_client)
    url = f"/api/ksc/servers/{server}/changes"
    full = _items(auth_client, url)
    for facet in ("kind", "action"):
        a, b = _top_two(auth_client, url, facet)
        _check(auth_client, url, facet, a, b)
    policies = sorted({str(i["policy_id"]) for i in full.values() if i["policy_id"] is not None})
    _check(auth_client, url, "policy_id", policies[0], policies[1])
    _check(auth_client, url, "snapshot_id", str(ids["2026-09-15"]), str(ids["2026-09-16"]))
    assert _items(auth_client, url, kind="all", action="all") == full
    assert auth_client.get(url, params={"snapshot_id": ["1", "x"]}).status_code == 422


def test_group_with_comma_is_one_value(auth_client: TestClient, db_session: Session, snap: int) -> None:
    """Свободное значение с запятой (группа «Серверы, Москва») не рвётся на части."""
    group = "Managed devices/Серверы, Москва"
    db_session.execute(update(KscHost).where(KscHost.snapshot_id == snap, KscHost.name == "SRV01").values(group_path=group))
    db_session.commit()
    url = f"/api/ksc/snapshots/{snap}/hosts"
    assert [h["name"] for h in _items(auth_client, url, group=group).values()] == ["SRV01"]
    assert [h["name"] for h in _items(auth_client, url, group=[group, "Managed devices/Серверы"]).values()] == ["SRV01"]
