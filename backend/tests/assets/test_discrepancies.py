"""Коды расхождений (спека §2): у каждого — положительный и отрицательный случай."""
from __future__ import annotations

import datetime as dt
from typing import Any

from api.modules.assets.core.discrepancies import CODES, Discrepancy, discrepancies
from api.modules.assets.core.matching import Observed, canonical

NOW = dt.datetime(2026, 10, 1, 12, 0, tzinfo=dt.UTC)


def days_ago(n: float) -> dt.datetime:
    return NOW - dt.timedelta(days=n)


def run(
    observations: list[Observed], *, stale_days: int = 30, inactive_days: int = 30,
    pinned: dict[str, bool] | None = None, current: dict[str, str] | None = None,
) -> list[Discrepancy]:
    asset: dict[str, Any] = canonical(observations, pinned or {}, current or {})
    return discrepancies(asset, observations, stale_days=stale_days, inactive_days=inactive_days, now=NOW)


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


def test_ip_text_forms_are_not_a_discrepancy() -> None:
    v6 = Observed(source="vm", source_key="x", name="srv", ip="2001:DB8:0:0::5", seen_at=days_ago(1))
    assert not codes(run([v6, Observed(source="ksc", source_key="1:h", name="SRV", ip="2001:db8::5", seen_at=days_ago(0))])) & {"stale", "conflict"}


def test_gone_observation_is_not_compared() -> None:
    old = vm("192.168.6.53", 40)
    old.gone_at = days_ago(1)
    assert not codes(run([old, ksc("192.168.2.23", 0)])) & {"stale", "conflict"}


def test_pinned_value_is_the_reference() -> None:
    found = run([ksc("192.168.2.23", 0)], pinned={"ip": True}, current={"ip": "10.10.0.1"})
    assert [(d.code, d.source, d.value, d.current) for d in found if d.field == "ip"] == [("conflict", "ksc", "192.168.2.23", "10.10.0.1")]


def test_no_av_without_live_ksc() -> None:
    assert "no_av" in codes(run([ad(0, 3)]))
    a = Observed(source="dns", source_key="x.corp.local", fqdn="x.corp.local", ip="10.10.0.5", seen_at=days_ago(0), extra={"record_type": "A"})
    assert "no_av" in codes(run([a]))


def test_no_scan_codes() -> None:
    """Сканирования нет (спека §7): кодов, опиравшихся на скан, нет, а оставшееся наблюдение `scan` само по себе
    не даёт «нет агента»."""
    assert not {"unreachable", "unknown_host", "dns_orphan"} & set(CODES)
    lone = Observed(source="scan", source_key="10.10.0.5", ip="10.10.0.5", seen_at=days_ago(0))
    assert codes(run([lone])) == set()
    rec = Observed(source="dns", source_key="gone.corp.local", fqdn="gone.corp.local", ip="10.10.0.8", seen_at=days_ago(0), extra={"record_type": "A"})
    assert not codes(run([rec, ksc("10.10.0.7", 0)])) & {"unreachable", "unknown_host", "dns_orphan"}


def test_no_av_only_for_hosts_that_live() -> None:
    """Выключенный или давно не входивший компьютер AD без других источников — не «нет агента»."""
    disabled = ad(0, 3)
    disabled.extra["enabled"] = False
    assert not codes(run([disabled])) & {"no_av", "ad_inactive"}
    old = codes(run([ad(0, 120)]))
    assert "no_av" not in old and "ad_inactive" in old
    assert "no_av" in codes(run([ad(0, 3)]))
    assert "no_av" in codes(run([vm("10.10.0.5", 0)]))
    # Хост жив по VM — агента нет, даже если компьютер AD давно не входил.
    assert "no_av" in codes(run([ad(0, 120), vm("10.10.0.5", 0)]))


def test_ad_inactive_needs_enabled_live_computer() -> None:
    disabled = ad(0, 120, name="OLD01")
    disabled.extra["enabled"] = False
    assert "ad_inactive" not in codes(run([disabled]))
    gone = ad(0, 120, name="OLD01")
    gone.gone_at = days_ago(0)
    assert "ad_inactive" not in codes(run([gone, vm("10.10.0.7", 90)]))


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


def test_public_and_private_ip_are_not_a_conflict() -> None:
    """Внешний адрес из RackTables при внутреннем в KSC — NAT, не расхождение; два внутренних — расхождение."""
    rt_public = Observed(source="rt", source_key="8.8.4.10", name="srv01", ip="8.8.4.10", seen_at=days_ago(0))
    ksc = Observed(source="ksc", source_key="1:h-srv01", name="SRV01", ip="10.10.0.11", seen_at=days_ago(0))
    assert not codes(run([ksc, rt_public])) & {"conflict", "stale"}
    rt_private = Observed(source="rt", source_key="10.10.0.99", name="srv01", ip="10.10.0.99", seen_at=days_ago(0))
    assert "conflict" in codes(run([ksc, rt_private]))


def test_cluster_virtual_names_are_not_hosts() -> None:
    """Учётка кластера и роль (виртуальные имена) не дают no_av и ad_inactive; узел — обычный хост."""
    def ad_obj(kind: str, name: str, last_logon: float | None) -> Observed:
        return Observed(source="ad", source_key=f"S-{name}", name=name, fqdn=f"{name.lower()}.corp.local", domain="corp.local",
                        seen_at=days_ago(0), extra={"enabled": True, "last_logon": days_ago(last_logon).isoformat() if last_logon is not None else None, "cluster": kind})
    dns = Observed(source="dns", source_key="clu1.corp.local", fqdn="clu1.corp.local", ip="10.10.0.50", seen_at=days_ago(0), extra={"record_type": "A"})
    dead = run([ad_obj("cluster", "CLU1", None), dns])
    assert not codes(dead) & {"no_av", "ad_inactive"}
    assert not codes(run([ad_obj("role", "FS1", 200)])) & {"no_av", "ad_inactive"}
    node = run([ad_obj("node", "N1", 1)])
    assert "no_av" in codes(node)
    assert "ad_inactive" in codes(run([ad_obj("node", "N2", 200)]))
