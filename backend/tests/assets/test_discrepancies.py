"""Коды расхождений (спека §2): у каждого — положительный и отрицательный случай."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from typing import Any

from api.modules.assets.core.discrepancies import Discrepancy, discrepancies
from api.modules.assets.core.matching import Observed, canonical

NOW = dt.datetime(2026, 10, 1, 12, 0, tzinfo=dt.UTC)


def days_ago(n: float) -> dt.datetime:
    return NOW - dt.timedelta(days=n)


def never_scanned(_ip: str) -> bool:
    return False


def unknown(_ip: str) -> bool | None:
    return None


def run(
    observations: list[Observed], *, stale_days: int = 30, inactive_days: int = 30,
    scanned: Callable[[str], bool] = never_scanned, alive: Callable[[str], bool | None] = unknown,
    pinned: dict[str, bool] | None = None, current: dict[str, str] | None = None,
) -> list[Discrepancy]:
    asset: dict[str, Any] = canonical(observations, pinned or {}, current or {})
    return discrepancies(asset, observations, stale_days=stale_days, inactive_days=inactive_days,
                         scanned_networks=scanned, scan_alive=alive, now=NOW)


def codes(found: list[Discrepancy]) -> set[str]:
    return {d.code for d in found}


def vm(ip: str, seen: float, name: str = "msk1") -> Observed:
    return Observed(source="vm", source_key=f"{name}|{ip}", name=name, ip=ip, seen_at=days_ago(seen))


def ksc(ip: str, seen: float, name: str = "MSK1") -> Observed:
    return Observed(source="ksc", source_key=f"h-{name.lower()}", name=name, fqdn=f"{name.lower()}.corp.local",
                    domain="corp.local", ip=ip, seen_at=days_ago(seen))


def ad(seen: float, last_logon_days: float | None, name: str = "MSK1") -> Observed:
    extra: dict[str, Any] = {"enabled": True}
    if last_logon_days is not None:
        extra["last_logon"] = days_ago(last_logon_days).isoformat()
    return Observed(source="ad", source_key=f"S-{name}", name=name, fqdn=f"{name.lower()}.corp.local", domain="corp.local",
                    seen_at=days_ago(seen), extra=extra)


def test_stale_old_source_with_other_ip() -> None:
    found = run([vm("192.168.6.53", 40), ksc("192.168.2.23", 0)])
    stale = [d for d in found if d.code == "stale"]
    assert len(stale) == 1
    d = stale[0]
    assert (d.source, d.field, d.value, d.current) == ("vm", "ip", "192.168.6.53", "192.168.2.23")
    assert "192.168.6.53" in d.text and "192.168.2.23" in d.text and "устарели" in d.text
    assert "conflict" not in codes(found)


def test_conflict_when_freshness_is_comparable() -> None:
    found = run([vm("192.168.6.53", 5), ksc("192.168.2.23", 0)])
    assert [(d.code, d.source, d.field) for d in found if d.code in ("stale", "conflict")] == [("conflict", "vm", "ip")]
    assert "расходятся" in found[0].text or any("расходятся" in d.text for d in found)


def test_stale_threshold_is_inclusive() -> None:
    found = run([vm("192.168.6.53", 0.5), ksc("192.168.2.23", 0)], stale_days=0)
    assert "stale" in codes(found) and "conflict" not in codes(found)


def test_same_values_are_not_a_discrepancy() -> None:
    found = run([vm("10.10.0.11", 40, name="srv01"), ksc("10.10.0.11", 0, name="SRV01")])
    assert not codes(found) & {"stale", "conflict"}


def test_gone_observation_is_not_compared() -> None:
    old = vm("192.168.6.53", 40)
    old.gone_at = days_ago(1)
    assert not codes(run([old, ksc("192.168.2.23", 0)])) & {"stale", "conflict"}


def test_pinned_value_is_the_reference() -> None:
    found = run([ksc("192.168.2.23", 0)], pinned={"ip": True}, current={"ip": "10.10.0.1"})
    assert [(d.code, d.source, d.value, d.current) for d in found if d.field == "ip"] == [("conflict", "ksc", "192.168.2.23", "10.10.0.1")]


def test_no_av_without_live_ksc() -> None:
    assert "no_av" in codes(run([ad(0, 3)]))
    assert "no_av" in codes(run([Observed(source="scan", source_key="10.10.0.5", ip="10.10.0.5", seen_at=days_ago(0))]))


def test_no_av_negative_with_live_ksc() -> None:
    assert "no_av" not in codes(run([ad(0, 3), ksc("10.10.0.5", 0)]))


def test_no_av_when_ksc_is_gone() -> None:
    gone = ksc("10.10.0.5", 2)
    gone.gone_at = days_ago(0)
    assert "no_av" in codes(run([ad(0, 3), gone]))


def test_ad_inactive() -> None:
    assert "ad_inactive" in codes(run([ad(0, 120, name="OLD01")]))
    assert "ad_inactive" in codes(run([ad(0, None, name="OLD01")]))
    # Другой источник видел давно — компьютер всё равно неактивен.
    assert "ad_inactive" in codes(run([ad(0, 120), vm("10.10.0.7", 90)]))


def test_ad_inactive_negative() -> None:
    assert "ad_inactive" not in codes(run([ad(0, 3)]))
    # Вход давно, но антивирус видел хост вчера.
    assert "ad_inactive" not in codes(run([ad(0, 120), ksc("10.10.0.7", 1)]))
    assert "ad_inactive" not in codes(run([ksc("10.10.0.7", 100)]))


def test_unreachable_known_ip_in_scanned_network_not_found() -> None:
    found = run([ksc("10.10.0.7", 0)], scanned=lambda ip: ip.startswith("10.10.0."), alive=lambda ip: False)
    assert [(d.code, d.value) for d in found if d.code == "unreachable"] == [("unreachable", "10.10.0.7")]


def test_unreachable_negative() -> None:
    assert "unreachable" not in codes(run([ksc("10.10.0.7", 0)], scanned=lambda ip: True, alive=lambda ip: True))
    assert "unreachable" not in codes(run([ksc("10.20.0.7", 0)], scanned=lambda ip: False, alive=lambda ip: False))
    assert "unreachable" not in codes(run([ad(0, 3)], scanned=lambda ip: True, alive=lambda ip: False))


def test_unknown_host_only_scan_and_ptr() -> None:
    scan = Observed(source="scan", source_key="10.10.0.5", ip="10.10.0.5", seen_at=days_ago(0))
    ptr = Observed(source="dns", source_key="10.10.0.5", fqdn="x.corp.local", ip="10.10.0.5", seen_at=days_ago(0), extra={"record_type": "PTR"})
    assert "unknown_host" in codes(run([scan]))
    assert "unknown_host" in codes(run([scan, ptr]))


def test_unknown_host_negative() -> None:
    scan = Observed(source="scan", source_key="10.10.0.5", ip="10.10.0.5", seen_at=days_ago(0))
    a = Observed(source="dns", source_key="x.corp.local", fqdn="x.corp.local", ip="10.10.0.5", seen_at=days_ago(0), extra={"record_type": "A"})
    assert "unknown_host" not in codes(run([scan, ksc("10.10.0.5", 0, name="X")]))
    assert "unknown_host" not in codes(run([scan, a]))
    assert "unknown_host" not in codes(run([ksc("10.10.0.5", 0)]))


def test_dns_orphan() -> None:
    rec = Observed(source="dns", source_key="gone.corp.local", fqdn="gone.corp.local", ip="10.10.0.8", seen_at=days_ago(0), extra={"record_type": "A"})
    found = run([rec], scanned=lambda ip: True, alive=lambda ip: False)
    assert "dns_orphan" in codes(found)


def test_dns_orphan_negative() -> None:
    rec = Observed(source="dns", source_key="gone.corp.local", fqdn="gone.corp.local", ip="10.10.0.8", seen_at=days_ago(0), extra={"record_type": "A"})
    assert "dns_orphan" not in codes(run([rec], scanned=lambda ip: False, alive=lambda ip: None))
    assert "dns_orphan" not in codes(run([rec], scanned=lambda ip: True, alive=lambda ip: True))
    assert "dns_orphan" not in codes(run([rec, ad(0, 3, name="GONE")], scanned=lambda ip: True, alive=lambda ip: False))
