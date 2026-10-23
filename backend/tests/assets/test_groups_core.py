"""Группы как активы: личность группы, встроенные субъекты, полный состав и предки (спека §3, §6) — без базы."""
from __future__ import annotations

from collections.abc import Callable

import pytest

from api.modules.assets.core.groups import (
    Edge,
    ancestors,
    expand,
    group_key,
    is_well_known,
    normalize_sid,
    well_known_text,
)

SID = "S-1-5-21-1111111111-2222222222-3333333333-{}"
G, H, K, L = 1, 2, 3, 4


def user(user_id: int | None, name: str, sid: str = "") -> Edge:
    return Edge("user", user_id, None, None, sid, name, False)


def group(group_id: int | None, name: str, sid: str = "") -> Edge:
    return Edge("group", None, group_id, None, sid, name, False)


def graph(edges: dict[int, list[Edge]]) -> Callable[[int], list[Edge]]:
    return lambda gid: edges.get(gid, [])


# --- личность и встроенные субъекты -----------------------------------------

def test_normalize_sid_upper_and_strip() -> None:
    assert normalize_sid("s-1-5-32-544") == "S-1-5-32-544"
    assert normalize_sid("  s-1-5-11 ") == "S-1-5-11"


def test_group_key_four_kinds() -> None:
    assert group_key(local=False, domain="corp.local", host_asset_id=None, sid=SID.format(512).lower(),
                     name="Domain Admins") == f"d:corp.local:{SID.format(512)}"
    assert group_key(local=True, domain="", host_asset_id=7, sid="s-1-5-32-544",
                     name="administrators") == "l:7:S-1-5-32-544"
    assert group_key(local=True, domain="", host_asset_id=7, sid="", name="Wheel") == "l:7:n:wheel"
    assert group_key(local=False, domain="CORP.local", host_asset_id=None, sid="",
                     name="Helpdesk") == "d:corp.local:n:helpdesk"


def test_group_key_local_needs_host() -> None:
    with pytest.raises(ValueError):
        group_key(local=True, domain="", host_asset_id=None, sid="S-1-5-32-544", name="administrators")


@pytest.mark.parametrize("sid", ["S-1-1-0", "S-1-5-11", "S-1-5-18", "S-1-5-80-1-2-3-4-5", "s-1-5-4"])
def test_well_known(sid: str) -> None:
    assert is_well_known(sid)


@pytest.mark.parametrize("sid", ["S-1-5-32-544", SID.format(513), "", "S-1-5"])
def test_not_well_known(sid: str) -> None:
    assert not is_well_known(sid)


def test_well_known_text() -> None:
    assert well_known_text("S-1-5-11") == "все прошедшие проверку пользователи и компьютеры"
    assert well_known_text("s-1-5-80-1-2-3-4-5") == "служебная учётка службы"
    assert well_known_text("S-1-5-1") == "встроенный субъект Windows"


# --- полный состав -----------------------------------------------------------

def test_chain() -> None:
    res = expand(G, graph({G: [group(H, "helpdesk")], H: [user(10, "user01")]}))
    assert [(x.kind, x.user_id, x.via, x.paths) for x in res.leaves] == [("user", 10, [H], 1)]
    assert res.groups_seen == {G, H}
    assert res.well_known == [] and res.dead_ends == []


def test_diamond_user_once_two_paths_shortest_via() -> None:
    # G→H→u, G→K→L→u: пользователь один раз, путей 2, «через» — кратчайший [H].
    res = expand(G, graph({
        G: [group(K, "k"), group(H, "h")],
        K: [group(L, "l")],
        L: [user(10, "user01")],
        H: [user(10, "user01")],
    }))
    assert [(x.user_id, x.via, x.paths) for x in res.leaves] == [(10, [H], 2)]


def test_paths_count_through_shared_subgroup() -> None:
    # G→H→L→u и G→K→L→u: L раскрывается один раз, но путей до u — 2.
    res = expand(G, graph({
        G: [group(H, "h"), group(K, "k")],
        H: [group(L, "l")],
        K: [group(L, "l")],
        L: [user(10, "user01")],
    }))
    assert [(x.via, x.paths) for x in res.leaves] == [([H, L], 2)]


def test_cycle_is_finite() -> None:
    res = expand(G, graph({
        G: [group(H, "h")],
        H: [group(K, "k"), user(10, "user01")],
        K: [group(H, "h"), group(G, "g"), user(11, "user02")],
    }))
    assert res.groups_seen == {G, H, K}
    assert [(x.user_id, x.via, x.paths) for x in res.leaves] == [(10, [H], 1), (11, [H, K], 1)]
    assert res.dead_ends == []


def test_leaves_order_by_path_length_then_name() -> None:
    res = expand(G, graph({
        G: [group(H, "h"), user(12, "zeta"), user(None, "Beta", SID.format(1201))],
        H: [user(10, "alpha")],
    }))
    assert [x.name for x in res.leaves] == ["Beta", "zeta", "alpha"]


def test_unlinked_users_keyed_by_sid_and_name() -> None:
    res = expand(G, graph({
        G: [group(H, "h"), user(None, "user05", SID.format(1205))],
        H: [user(None, "user05", SID.format(1205)), user(None, "user06", SID.format(1206))],
    }))
    assert [(x.name, x.paths) for x in res.leaves] == [("user05", 2), ("user06", 1)]


def test_computer_leaf() -> None:
    res = expand(G, graph({G: [Edge("computer", None, None, 30, SID.format(1300), "srv01$", False)]}))
    assert [(x.kind, x.asset_id) for x in res.leaves] == [("computer", 30)]


def test_well_known_separate_not_expanded() -> None:
    res = expand(G, graph({
        G: [Edge("well_known", None, None, None, "S-1-5-11", "authenticated users", False), group(H, "h")],
        H: [Edge("well_known", None, None, None, "S-1-5-11", "authenticated users", False)],
    }))
    assert res.leaves == []
    assert [(x.sid, x.via, x.paths) for x in res.well_known] == [("S-1-5-11", [], 2)]


def test_dead_ends_unknown_and_group_without_id() -> None:
    res = expand(G, graph({
        G: [Edge("unknown", None, None, None, "S-1-5-21-9-9-9-1000", "", False),
            group(None, "foreign admins", "S-1-5-21-9-9-9-1001")],
    }))
    assert sorted((x.kind, x.sid) for x in res.dead_ends) == [
        ("group", "S-1-5-21-9-9-9-1001"), ("unknown", "S-1-5-21-9-9-9-1000")]
    assert res.leaves == [] and res.groups_seen == {G}


def test_dead_end_group_with_id_but_no_members() -> None:
    # Ruling R1: группа с id без рёбер (нет в AD или пустая) — тупик; пометку ставит API по in_ad.
    res = expand(G, graph({G: [group(H, "desktop admins", SID.format(1100)), group(K, "k")],
                           K: [group(H, "desktop admins", SID.format(1100))]}))
    assert [(x.kind, x.group_id, x.via, x.paths) for x in res.dead_ends] == [("group", H, [], 2)]
    assert res.groups_seen == {G, H, K}


def test_root_without_members_is_not_dead_end() -> None:
    res = expand(G, graph({}))
    assert res.leaves == res.well_known == res.dead_ends == []
    assert res.groups_seen == {G}


# --- предки ------------------------------------------------------------------

def test_ancestors_with_cycle() -> None:
    # G в H, H в K, K в H, H в G (цикл через старт): старт в ответ не входит.
    parents = {G: [H], H: [K, G], K: [H, L], L: []}
    res = ancestors({G}, lambda gid: parents.get(gid, []))
    assert res == {H: [G], K: [G, H], L: [G, H, K]}


def test_ancestors_shortest_from_any_start() -> None:
    parents = {G: [H], H: [K], L: [K]}
    res = ancestors({G, L}, lambda gid: parents.get(gid, []))
    assert res == {H: [G], K: [L]}
