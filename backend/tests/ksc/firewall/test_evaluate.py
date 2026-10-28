"""Вычисление вердикта по сетевым правилам хоста (спека §4.2, §4.4, §4.5): первое совпавшее решает, ответный пакет,
слой правил программ, состояние экрана, ветвление на неопределённостях."""
from __future__ import annotations

import ipaddress
from dataclasses import replace
from typing import Any

import pytest

from api.modules.ksc.core.firewall.evaluate import (
    ASSUME_MERGE,
    ASSUME_REPLACE,
    NOTE_COMPONENT_STOPPED,
    NOTE_FIREWALL_OFF,
    NOTE_FIREWALL_UNKNOWN,
    NOTE_HIPS_NOTIFY,
    NOTE_HIPS_OFF,
    NOTE_NOTIFY_ONLY,
    NOTE_REPLY_APP,
    NOTE_TOO_MANY,
    POINT_MODEL,
    effective_rules,
    evaluate_side,
    point_profile,
)
from api.modules.ksc.core.firewall.model import (
    HostFirewall,
    Packet,
    Protocol,
    RuleView,
    SourceSet,
    Verdict,
    ZoneView,
)
from api.modules.ksc.core.firewall.view import Source, host_firewall
from api.modules.ksc.core.policy_model import (
    AccessRule,
    Address,
    AppGroupDefault,
    FirewallSettings,
    Locks,
    Scope,
)

ALLOW, DENY, BY_APP = "разрешить", "запретить", "по правилам программ"
ZONES = (
    ZoneView("Тестовая локальная", 1, ipaddress.ip_network("198.51.100.0/24")),
    ZoneView("Тестовая публичная", 2, ipaddress.ip_network("203.0.113.0/24")),
)
#: Имя узла без адресов: при пустом имени назначения критерий «возможно».
UNKNOWN_HOST = (Address(host="srv.example.test"),)


def rule(position: int, action: str = ALLOW, *, enabled: bool = True, profile: str = "", layer: str = "packet",
         **scope: Any) -> RuleView:
    return RuleView(row_id=position + (1000 if profile else 0) + (500 if layer == "app" else 0), policy_id=1, profile=profile,
                    layer=layer, position=position, name=f"Тестовое правило {position}", action=action, enabled=enabled,
                    scope=Scope(**scope), direction_text="", protocol_text="", local_ports_text="", remote_ports_text="",
                    addresses_text="")


def src(rules: tuple[RuleView, ...], profile: str = "", priority: int | None = None) -> SourceSet:
    return SourceSet(policy_id=1, profile=profile, priority=priority, locked=True if profile else None, rules=rules)


def host(packet_rules: tuple[RuleView, ...] = (), **over: Any) -> HostFirewall:
    base: dict[str, Any] = {
        "host_id": "h-1", "host_name": "ws01.example.test", "host_ip": "192.0.2.10", "policy_id": 1,
        "policy_name": "Тестовая политика", "packet": src(packet_rules), "packet_profiles": (), "packet_undetermined": (),
        "app": src(()), "app_profiles": (), "app_undetermined": (), "zones": ZONES, "firewall_enabled": True,
        "notify_only": False, "hips_enabled": True, "hips_notify_only": False, "component_running": True,
        "trust_groups": (), "notes": (),
    }
    return HostFirewall(**{**base, **over})


def packet(**over: Any) -> Packet:
    base: dict[str, Any] = {"outbound": True, "protocol": Protocol.TCP, "local_port": 50000, "remote_port": 3389,
                            "remote_ip": "198.51.100.7", "remote_host": ""}
    return Packet(**{**base, **over})


def statuses(steps: Any) -> list[str]:
    return [s.status for s in steps]


# --- пакетные правила ---------------------------------------------------------------------------------------------------

def test_first_match_wins() -> None:
    rules = (rule(1, ALLOW, remote_ports=((80, 80),)), rule(2, DENY, remote_ports=((3389, 3389),)), rule(3, ALLOW))
    res = evaluate_side(host(rules), packet())
    assert res.verdict is Verdict.DENY and res.depends_on == ()
    (b,) = res.branches
    assert b.decided_by == rules[1] and b.layer == "packet" and b.assumptions == ()
    assert statuses(b.steps) == ["no", "hit", "not_checked"] and b.reply_steps == ()
    assert res.effective_sources == ("политика „Тестовая политика“",)


def test_disabled_rule_is_skipped_with_mark() -> None:
    rules = (rule(1, DENY, enabled=False), rule(2, ALLOW, direction=2))
    (b,) = evaluate_side(host(rules), packet()).branches
    assert b.verdict is Verdict.ALLOW and statuses(b.steps) == ["disabled", "hit"]


def test_deny_reply_packet() -> None:
    """Первый пакет разрешён правилом «исходящий (пакет)», ответный (входящий) режет правило «входящий (пакет)»."""
    rules = (rule(1, ALLOW, direction=1), rule(2, DENY, direction=0))
    res = evaluate_side(host(rules), packet())
    (b,) = res.branches
    assert res.verdict is Verdict.DENY and b.decided_by == rules[1] and b.layer == "reply"
    assert statuses(b.steps) == ["hit", "not_checked"] and statuses(b.reply_steps) == ["no", "hit"]


def test_reply_allowed_keeps_first_rule_as_decider() -> None:
    rules = (rule(1, ALLOW, direction=1), rule(2, ALLOW, direction=0))
    (b,) = evaluate_side(host(rules), packet()).branches
    assert b.verdict is Verdict.ALLOW and b.decided_by == rules[0] and b.layer == "packet"
    assert statuses(b.reply_steps) == ["no", "hit"]


def test_stream_rule_skipped_on_reply() -> None:
    """Правило потока разрешает соединение и в ответном прогоне не участвует; ответ разрешает правило пакета."""
    rules = (rule(1, ALLOW, direction=4), rule(2, ALLOW, direction=0))
    (b,) = evaluate_side(host(rules), packet()).branches
    assert b.verdict is Verdict.ALLOW and statuses(b.reply_steps) == ["skipped", "hit"]


def test_reply_without_packet_rule_goes_to_app_rules() -> None:
    rules = (rule(1, ALLOW, direction=1),)
    (b,) = evaluate_side(host(rules), packet()).branches
    assert b.verdict is Verdict.APP and b.layer == "reply" and b.decided_by is None and NOTE_REPLY_APP in b.note


def test_icmp_has_no_reply_pass() -> None:
    rules = (rule(1, ALLOW, direction=1), rule(2, DENY, direction=0))
    (b,) = evaluate_side(host(rules), packet(protocol=Protocol.ICMP, local_port=None, remote_port=None)).branches
    assert b.verdict is Verdict.ALLOW and b.reply_steps == ()


# --- слой правил программ -----------------------------------------------------------------------------------------------

def _groups() -> tuple[AppGroupDefault, ...]:
    return (
        AppGroupDefault("Тестовая доверенная", None, 0, (AccessRule(-1, True, False),)),
        AppGroupDefault("Тестовая ограниченная", None, 0, (AccessRule(-1, True, False), AccessRule(1, False, False))),
        AppGroupDefault("Тестовая без правил", None, 0, ()),
    )


def test_by_app_rules_goes_to_layer3() -> None:
    rules = (rule(1, BY_APP, remote_ports=((3389, 3389),)), rule(2, DENY))
    app = (rule(1, ALLOW, layer="app", remote_ports=((3389, 3389),)), rule(2, ALLOW, layer="app", remote_ports=((80, 80),)),
           rule(3, DENY, layer="app", remote=UNKNOWN_HOST))
    res = evaluate_side(host(rules, app=src(app), trust_groups=_groups()), packet())
    (b,) = res.branches
    assert res.verdict is Verdict.APP and b.decided_by == rules[0] and b.layer == "app"
    assert statuses(b.steps) == ["hit", "not_checked"]
    assert b.app_candidates == (app[0], app[2])
    # Адрес в зоне «локальные сети» (код 1): правило зоны, иначе правило «любая сеть» (-1), иначе неизвестно.
    assert b.trust_groups == (("Тестовая доверенная", True), ("Тестовая ограниченная", False), ("Тестовая без правил", None))


def test_trust_groups_unknown_zone_uses_any_network_rule() -> None:
    res = evaluate_side(host(trust_groups=_groups()), packet(remote_ip="192.0.2.99"))
    (b,) = res.branches
    assert b.trust_groups == (("Тестовая доверенная", True), ("Тестовая ограниченная", True), ("Тестовая без правил", None))


def test_no_match_goes_to_layer3() -> None:
    rules = (rule(1, DENY, remote_ports=((80, 80),)),)
    (b,) = evaluate_side(host(rules), packet()).branches
    assert b.verdict is Verdict.APP and b.decided_by is None and b.layer == "app" and statuses(b.steps) == ["no"]


def test_hips_disabled_undetermined() -> None:
    res = evaluate_side(host(hips_enabled=False), packet())
    (b,) = res.branches
    assert res.verdict is Verdict.UNDETERMINED and b.layer == "app" and NOTE_HIPS_OFF in b.note
    assert NOTE_HIPS_OFF in res.notes and b.app_candidates == ()


def test_hips_notify_only_still_app_with_note() -> None:
    res = evaluate_side(host(hips_notify_only=True), packet())
    assert res.verdict is Verdict.APP and NOTE_HIPS_NOTIFY in res.notes


# --- наложение профиля --------------------------------------------------------------------------------------------------

def test_effective_rules_merge_and_replace() -> None:
    policy = (rule(2, DENY), rule(1, ALLOW))
    p_low, p_high = (rule(1, ALLOW, profile="Тестовый низкий"),), (rule(1, DENY, profile="Тестовый высокий"),)
    fw = host(policy, packet_profiles=(src(p_high, "Тестовый высокий", 1), src(p_low, "Тестовый низкий", 5)))
    assert effective_rules(fw, "merge") == (policy[1], policy[0], *p_high, *p_low)
    assert effective_rules(fw, "replace") == p_high
    maybe = (rule(1, ALLOW, profile="Тестовый неясный"),)
    fw2 = replace(fw, packet_undetermined=(src(maybe, "Тестовый неясный", 0),))
    assert effective_rules(fw2, "replace") == p_high
    assert effective_rules(fw2, "replace", with_undetermined=("Тестовый неясный",)) == maybe
    assert effective_rules(fw2, "merge", with_undetermined=("Тестовый неясный",)) == (policy[1], policy[0], *maybe, *p_high, *p_low)
    # Профиль без правил в модели «заменяет» не выбирается: действует следующий или политика.
    fw3 = host(policy, packet_profiles=(src((), "Тестовый пустой", 1),))
    assert effective_rules(fw3, "replace") == (policy[1], policy[0])


def test_merge_vs_replace_agree_single_verdict() -> None:
    fw = host((rule(1, DENY),), packet_profiles=(src((rule(1, DENY, profile="Тестовый профиль"),), "Тестовый профиль", 1),))
    res = evaluate_side(fw, packet())
    assert res.verdict is Verdict.DENY and res.depends_on == ()
    assert [b.assumptions for b in res.branches] == [(ASSUME_MERGE,), (ASSUME_REPLACE,)]
    assert res.effective_sources == ("политика „Тестовая политика“", "профиль „Тестовый профиль“")


def test_merge_vs_replace_differ_depends() -> None:
    fw = host((rule(1, DENY),), packet_profiles=(src((rule(1, ALLOW, profile="Тестовый профиль", direction=2),), "Тестовый профиль", 1),))
    res = evaluate_side(fw, packet())
    assert res.verdict is Verdict.DEPENDS and res.depends_on == (POINT_MODEL,)
    assert [(b.assumptions, b.verdict) for b in res.branches] == [((ASSUME_MERGE,), Verdict.DENY), ((ASSUME_REPLACE,), Verdict.ALLOW)]
    merge = evaluate_side(fw, packet(), profile_mode="merge")
    assert merge.verdict is Verdict.DENY and [b.assumptions for b in merge.branches] == [()]
    assert evaluate_side(fw, packet(), profile_mode="replace").verdict is Verdict.ALLOW


def test_no_overlay_profiles_single_model() -> None:
    res = evaluate_side(host((rule(1, DENY),)), packet())
    assert len(res.branches) == 1 and res.branches[0].assumptions == ()


def test_undetermined_profile_branches() -> None:
    name = "Тестовый профиль"
    fw = host((rule(1, ALLOW, direction=2),), packet_undetermined=(src((rule(1, DENY, profile=name),), name, 1),))
    res = evaluate_side(fw, packet(), profile_mode="replace")
    assert res.verdict is Verdict.DEPENDS and res.depends_on == (point_profile(name),)
    assert [(b.assumptions, b.verdict) for b in res.branches] == [
        ((f"профиль „{name}“ активен",), Verdict.DENY), ((f"профиль „{name}“ не активен",), Verdict.ALLOW)]
    assert res.effective_sources == (f"профиль „{name}“", "политика „Тестовая политика“")


# --- состояние экрана ---------------------------------------------------------------------------------------------------

def _settings(enabled: bool | None, packet_lock: bool | None) -> FirewallSettings:
    return FirewallSettings(enabled=enabled, notify_only=False, hips_enabled=True, hips_notify_only=False, zones=(), app_groups=(),
                            locks=Locks(packet=packet_lock, networks=None, app=None))


def test_profile_disables_firewall() -> None:
    policy = Source("", None, True, _settings(True, None), (rule(1, DENY),), ())
    profile = Source("Тестовый профиль", 1, True, _settings(False, True), (), ())
    fw = host_firewall("h-1", "ws01.example.test", "192.0.2.10", 1, "Тестовая политика", policy, [profile], [], [])
    res = evaluate_side(fw, packet())
    (b,) = res.branches
    assert res.verdict is Verdict.NOT_APPLIED and b.layer == "state" and b.steps == () and NOTE_FIREWALL_OFF in res.notes


def test_component_not_running() -> None:
    res = evaluate_side(host((rule(1, DENY),), component_running=False), packet())
    (b,) = res.branches
    assert res.verdict is Verdict.NOT_APPLIED and b.layer == "state" and b.steps == ()
    assert NOTE_COMPONENT_STOPPED in res.notes


def test_no_policy_not_applied() -> None:
    fw = host(policy_id=None, packet=None, app=None, notes=("политики KES у хоста нет",))
    res = evaluate_side(fw, packet())
    assert res.verdict is Verdict.NOT_APPLIED and res.notes == ("политики KES у хоста нет",)


def test_firewall_state_unknown_is_noted() -> None:
    res = evaluate_side(host((rule(1, DENY),), firewall_enabled=None, notes=("оговорка представления",)), packet())
    assert res.verdict is Verdict.DENY and res.notes[0] == "оговорка представления" and NOTE_FIREWALL_UNKNOWN in res.notes


def test_notify_only_mode() -> None:
    res = evaluate_side(host((rule(1, DENY),), notify_only=True), packet())
    assert res.verdict is Verdict.DENY and res.mode == "notify_only" and NOTE_NOTIFY_ONLY in res.notes
    assert evaluate_side(host((rule(1, DENY),)), packet()).mode == ""


# --- ветвление на «возможно» --------------------------------------------------------------------------------------------

def test_maybe_rule_branches() -> None:
    rules = (rule(1, DENY, remote=UNKNOWN_HOST), rule(2, ALLOW, direction=2))
    res = evaluate_side(host(rules), packet())
    assumption = "имя узла srv.example.test не проверено"
    assert res.verdict is Verdict.DEPENDS and res.depends_on == (assumption,)
    hit, miss = res.branches
    assert hit.verdict is Verdict.DENY and hit.decided_by == rules[0] and statuses(hit.steps) == ["hit", "not_checked"]
    assert hit.assumptions == (f"{assumption}: правило №1 подошло",)
    assert miss.verdict is Verdict.ALLOW and statuses(miss.steps) == ["maybe", "hit"]
    assert miss.assumptions == (f"{assumption}: правило №1 не подошло",)
    # В ответном пакете то же допущение о том же правиле не ветвится заново.
    assert statuses(miss.reply_steps) == ["maybe", "hit"]


def test_maybe_rule_on_reply_branches() -> None:
    rules = (rule(1, ALLOW, direction=1), rule(2, DENY, direction=0, remote=UNKNOWN_HOST))
    res = evaluate_side(host(rules), packet())
    assert [(b.verdict, b.layer, b.decided_by) for b in res.branches] == [
        (Verdict.DENY, "reply", rules[1]), (Verdict.APP, "reply", None)]
    assert res.verdict is Verdict.DEPENDS and res.depends_on == ("имя узла srv.example.test не проверено",)


def test_maybe_rule_after_decision_is_not_branched() -> None:
    rules = (rule(1, DENY), rule(2, ALLOW, remote=UNKNOWN_HOST))
    res = evaluate_side(host(rules), packet())
    assert len(res.branches) == 1 and res.verdict is Verdict.DENY


def test_too_many_maybes() -> None:
    rules = tuple(rule(i, DENY, remote=UNKNOWN_HOST) for i in range(1, 7))
    res = evaluate_side(host(rules), packet())
    assert res.verdict is Verdict.DEPENDS and len(res.branches) == 5
    last = res.branches[-1]
    assert last.verdict is Verdict.UNDETERMINED and last.note == NOTE_TOO_MANY and NOTE_TOO_MANY in res.notes
    assert statuses(last.steps) == ["maybe"] * 5 + ["not_checked"] and len(last.assumptions) == 4


def test_max_branches_caps_total() -> None:
    rules = tuple(rule(i, DENY, remote=UNKNOWN_HOST) for i in range(1, 7))
    res = evaluate_side(host(rules), packet(), max_branches=3)
    assert len(res.branches) == 3 and res.branches[-1].verdict is Verdict.UNDETERMINED and res.branches[-1].note == NOTE_TOO_MANY


@pytest.mark.parametrize("mode", ["auto", "merge", "replace"])
def test_profile_mode_values(mode: str) -> None:
    assert evaluate_side(host((rule(1, DENY),)), packet(), profile_mode=mode).verdict is Verdict.DENY


def test_unknown_profile_mode_rejected() -> None:
    with pytest.raises(ValueError):
        evaluate_side(host(), packet(), profile_mode="other")


# --- «почти подошло» ----------------------------------------------------------------------------------------------------

def test_almost_matched_marked() -> None:
    rules = (rule(1, DENY, remote_ports=((3390, 3390),)), rule(2, DENY, remote_ports=((3389, 3389),)),
             rule(3, ALLOW, remote_ports=((3390, 3390),)))
    (b,) = evaluate_side(host(rules), packet()).branches
    first, hit, after = b.steps
    assert first.status == "no" and first.match.almost is not None and first.match.almost.name == "remote_ports"
    assert hit.status == "hit" and after.status == "not_checked" and after.match.almost is None
