"""Сопоставление наблюдений с активами (спека §2): правила 1–5 и каноническая карточка."""
from __future__ import annotations

import datetime as dt

import pytest

from api.modules.assets.core.matching import Candidate, Observed, canonical, match, normalize_name

NOW = dt.datetime(2026, 10, 1, 12, 0, tzinfo=dt.UTC)


def days_ago(n: float) -> dt.datetime:
    return NOW - dt.timedelta(days=n)


def cand(asset_id: int, *observations: Observed, name: str = "", fqdn: str = "", domain: str = "", ip: str = "") -> Candidate:
    return Candidate(asset_id=asset_id, name=name, fqdn=fqdn, domain=domain, ip=ip, observations=list(observations))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("WS01$", ("ws01", "")),
        ("ws01.corp.local", ("ws01", "corp.local")),
        ("WS01.Corp.Local.", ("ws01", "corp.local")),
        ("CORP\\ws01", ("ws01", "corp")),
        ("CORP\\WS01$", ("ws01", "corp")),
        ("ws01", ("ws01", "")),
        ("  SRV01 ", ("srv01", "")),
        ("10.10.0.5", ("", "")),
        ("fe80::1", ("", "")),
        ("", ("", "")),
    ],
)
def test_normalize_name(raw: str, expected: tuple[str, str]) -> None:
    assert normalize_name(raw) == expected


def test_rule1_same_source_key_wins_even_with_other_name() -> None:
    old = Observed(source="ksc", source_key="h-1", name="WS01", fqdn="ws01.corp.local")
    renamed = Observed(source="ksc", source_key="h-1", name="WS99", fqdn="ws99.corp.local")
    other = cand(2, Observed(source="ad", source_key="S-1", name="WS99", fqdn="ws99.corp.local"), name="WS99", fqdn="ws99.corp.local")
    assert match(renamed, [other, cand(1, old, name="WS01", fqdn="ws01.corp.local")]) == (1, 1)


def test_rule2_fqdn_ignores_case() -> None:
    obs = Observed(source="ad", source_key="S-1", name="SRV01", fqdn="SRV01.CORP.LOCAL")
    assert match(obs, [cand(7, name="srv01", fqdn="srv01.corp.local", domain="corp.local")]) == (7, 2)


def test_rule2_fqdn_of_any_observation() -> None:
    ksc = Observed(source="ksc", source_key="h-1", name="SRV01", fqdn="srv01.corp.local", domain="corp.local")
    obs = Observed(source="dns", source_key="srv01.corp.local", fqdn="srv01.corp.local", ip="10.10.0.50")
    # Каноническое FQDN пустое (например, закреплено чужое имя), но наблюдение KSC его знает.
    assert match(obs, [cand(3, ksc, name="core")]) == (3, 2)


def test_rule2_ip_move_keeps_the_same_asset() -> None:
    ksc = Observed(source="ksc", source_key="h-1", name="SRV01", fqdn="srv01.corp.local", ip="10.10.0.11")
    moved = Observed(source="dns", source_key="srv01.corp.local", fqdn="srv01.corp.local", ip="10.20.0.11")
    assert match(moved, [cand(4, ksc, name="SRV01", fqdn="srv01.corp.local", ip="10.10.0.11")]) == (4, 2)


def test_rule3_short_name_and_domain() -> None:
    obs = Observed(source="ksc", source_key="h-1", name="WS01", domain="corp.local")
    assert match(obs, [cand(5, name="ws01", domain="corp.local")]) == (5, 3)


def test_rule3_netbios_domain_against_dns_suffix() -> None:
    obs = Observed(source="vm", source_key="CORP\\ws01|", name="CORP\\ws01")
    assert match(obs, [cand(5, name="WS01", fqdn="ws01.corp.local", domain="corp.local")]) == (5, 3)


def test_rule4_vm_short_name_against_ksc_fqdn() -> None:
    ksc = Observed(source="ksc", source_key="h-1", name="WS01", fqdn="ws01.corp.local", domain="corp.local")
    vm = Observed(source="vm", source_key="ws01|10.10.0.5", name="ws01", ip="10.10.0.5")
    assert match(vm, [cand(6, ksc, name="WS01", fqdn="ws01.corp.local", domain="corp.local")]) == (6, 4)


def test_rule4_known_domain_on_obs_and_unknown_on_asset() -> None:
    vm = Observed(source="vm", source_key="ws01|", name="ws01")
    obs = Observed(source="ad", source_key="S-1", name="WS01", fqdn="ws01.corp.local", domain="corp.local")
    assert match(obs, [cand(6, vm, name="ws01")]) == (6, 4)


def test_different_domains_do_not_merge() -> None:
    obs = Observed(source="ad", source_key="S-2", name="WS01", fqdn="ws01.other.local", domain="other.local")
    assert match(obs, [cand(1, name="WS01", fqdn="ws01.corp.local", domain="corp.local")]) == (None, 0)


def test_rule4_does_not_apply_when_asset_knows_a_domain_through_any_observation() -> None:
    """VM без домена и KSC с доменом в одном активе: домен актива известен, правило 4 не склеивает."""
    vm = Observed(source="vm", source_key="ws01|", name="ws01")
    ksc = Observed(source="ksc", source_key="h-1", name="WS01", fqdn="ws01.corp.local", domain="corp.local")
    obs = Observed(source="ad", source_key="S-2", name="WS01", fqdn="ws01.other.local", domain="other.local")
    assert match(obs, [cand(1, vm, ksc, name="WS01", fqdn="ws01.corp.local", domain="corp.local")]) == (None, 0)


def test_rule5_ip_when_scan_has_no_name() -> None:
    obs = Observed(source="scan", source_key="10.10.0.5", ip="10.10.0.5")
    assert match(obs, [cand(8, name="ws01", fqdn="ws01.corp.local", ip="10.10.0.5")]) == (8, 5)


def test_rule5_vm_host_named_by_ip() -> None:
    obs = Observed(source="vm", source_key="10.10.0.9|10.10.0.9", name="10.10.0.9", ip="10.10.0.9")
    scan = Observed(source="scan", source_key="10.10.0.9", ip="10.10.0.9")
    assert match(obs, [cand(9, scan, ip="10.10.0.9")]) == (9, 5)


def test_same_ip_with_different_names_is_not_merged() -> None:
    """DHCP переиспользует адреса: при известных и разных именах IP не склеивает."""
    obs = Observed(source="ksc", source_key="h-2", name="WS02", fqdn="ws02.corp.local", ip="10.10.0.5")
    assert match(obs, [cand(1, name="WS01", fqdn="ws01.corp.local", ip="10.10.0.5")]) == (None, 0)


def test_rules_are_checked_in_order_across_candidates() -> None:
    by_ip = cand(1, Observed(source="scan", source_key="10.10.0.5", ip="10.10.0.5"), ip="10.10.0.5")
    by_fqdn = cand(2, name="ws01", fqdn="ws01.corp.local")
    obs = Observed(source="ksc", source_key="h-1", name="WS01", fqdn="ws01.corp.local", ip="10.10.0.5")
    assert match(obs, [by_ip, by_fqdn]) == (2, 2)


def test_no_candidates() -> None:
    assert match(Observed(source="scan", source_key="10.10.0.5", ip="10.10.0.5"), []) == (None, 0)


# ---- Каноническая карточка -------------------------------------------------


def test_canonical_fresh_wins_and_empty_fields_fall_back() -> None:
    vm = Observed(source="vm", source_key="msk1|192.168.6.53", name="msk1", ip="192.168.6.53", os="Windows 10", seen_at=days_ago(20))
    ksc = Observed(source="ksc", source_key="h-1", name="MSK1", fqdn="msk1.corp.local", domain="corp.local", ip="192.168.2.23", seen_at=days_ago(0))
    card = canonical([vm, ksc], {}, {})
    assert card["ip"] == "192.168.2.23" and card["name"] == "MSK1" and card["fqdn"] == "msk1.corp.local"
    assert card["os"] == "Windows 10"  # у свежего KSC поля нет — берётся из VM
    assert card["first_seen"] == days_ago(20) and card["last_seen"] == days_ago(0)


def test_canonical_pinned_field_keeps_current_value() -> None:
    ksc = Observed(source="ksc", source_key="h-1", name="MSK1", ip="192.168.2.23", seen_at=days_ago(0))
    card = canonical([ksc], {"ip": True, "name": False}, {"ip": "192.168.6.53", "name": "old"})
    assert card["ip"] == "192.168.6.53" and card["name"] == "MSK1"


def test_canonical_gone_is_excluded_but_counts_for_first_seen() -> None:
    gone = Observed(source="vm", source_key="srv01|10.10.0.99", name="srv01", ip="10.10.0.99", seen_at=days_ago(1), gone_at=days_ago(0))
    first = Observed(source="ad", source_key="S-1", name="SRV01", fqdn="srv01.corp.local", seen_at=days_ago(50))
    live = Observed(source="ksc", source_key="h-1", name="SRV01", ip="10.10.0.11", seen_at=days_ago(3))
    card = canonical([gone, first, live], {}, {})
    assert card["ip"] == "10.10.0.11"
    assert card["first_seen"] == days_ago(50) and card["last_seen"] == days_ago(3)


def test_canonical_all_gone_keeps_last_known_values() -> None:
    gone = Observed(source="vm", source_key="old|10.10.0.7", name="old", ip="10.10.0.7", seen_at=days_ago(9), gone_at=days_ago(1))
    card = canonical([gone], {}, {})
    assert card["name"] == "old" and card["ip"] == "10.10.0.7" and card["last_seen"] == days_ago(9)
