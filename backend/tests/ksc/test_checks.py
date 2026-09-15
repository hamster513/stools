"""Каждая проверка: срабатывает на своём хосте синтетики и молчит на эталонном WS01."""
from __future__ import annotations

import datetime as dt

from api.modules.ksc.core.checks import CHECK_BY_CODE, CHECKS, run_all
from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import ExportIndex, load_export
from api.modules.ksc.core.findings import Finding
from tests.ksc.synthetic import NOW, build_export, export_bytes


def _findings(raw: dict | None = None, cfg: KscConfig | None = None) -> list[Finding]:
    import json
    data = export_bytes() if raw is None else json.dumps(raw).encode()
    return run_all(ExportIndex(load_export(data)), cfg or KscConfig())


def _hosts(findings: list[Finding], code: str) -> set[str]:
    return {f.host for f in findings if f.check == code}


def test_registry_has_unique_codes_and_titles() -> None:
    codes = [c.code for c in CHECKS]
    assert len(codes) == len(set(codes)) and all(c.title and c.description for c in CHECKS)
    assert CHECK_BY_CODE["RTP_OFF"].func is not None


def test_host_checks_fire_on_expected_hosts() -> None:
    f = _findings()
    assert _hosts(f, "RTP_OFF") == {"WS02"}
    assert _hosts(f, "BASES_OLD") == {"WS03"}
    assert _hosts(f, "NO_FULLSCAN") == {"WS04"}
    assert _hosts(f, "AGENT_SILENT") == {"WS05"}
    assert _hosts(f, "NO_AGENT") == {"WS06", "WS08"}
    assert _hosts(f, "NO_PROTECTION") == {"WS07"}
    assert _hosts(f, "UNASSIGNED") == {"WS08"}
    assert _hosts(f, "THREATS_ACTIVE") == {"WS09"}
    assert _hosts(f, "HOST_CRITICAL") == {"WS09"}
    assert _hosts(f, "PRODUCT_OUTDATED") == {"WS10"}
    assert len([x for x in f if x.check == "PRODUCT_OUTDATED"]) == 2  # продукт и агент
    assert _hosts(f, "COMPONENT_OFF") == {"WS11"}
    assert not [x for x in f if x.host == "WS01"]


def test_severities_and_details() -> None:
    f = {x.check: x for x in _findings() if x.host in ("WS02", "WS09", "WS11", "WS10", "WS03")}
    assert f["RTP_OFF"].severity == "Critical" and f["RTP_OFF"].details["rtp_state"] == "остановлена"
    assert f["HOST_CRITICAL"].severity == "Medium" and "невылеченных" in f["HOST_CRITICAL"].details["reasons"][0]
    assert f["COMPONENT_OFF"].details["component"] == "Firewall" and f["COMPONENT_OFF"].details["status"] == "остановлен" and f["COMPONENT_OFF"].details["code"] == "firewall"
    assert f["BASES_OLD"].details["age_days"] == 10 and f["BASES_OLD"].severity == "High"
    assert f["PRODUCT_OUTDATED"].details["newest"] in ("12.0.0.0", "15.1.0.0")


def test_thresholds_from_config() -> None:
    relaxed = KscConfig(bases_old_days=30, fullscan_days=90, agent_silent_days=60)
    f = _findings(cfg=relaxed)
    assert not _hosts(f, "BASES_OLD") and not _hosts(f, "NO_FULLSCAN") and not _hosts(f, "AGENT_SILENT")


def test_allowlist_lowers_to_info_and_marks() -> None:
    cfg = KscConfig(allowlist_hosts=["ws0*", "*.lab.local"])
    f = [x for x in _findings(cfg=cfg) if x.check == "RTP_OFF"]
    assert len(f) == 1 and f[0].allowlisted and f[0].severity == "Info" and f[0].severity_original == "Critical"


def test_key_is_stable_and_independent_of_severity() -> None:
    a = {x.check + x.host + x.key_extra: x.key for x in _findings()}
    b = {x.check + x.host + x.key_extra: x.key for x in _findings(cfg=KscConfig(allowlist_hosts=["*"]))}
    assert a == b and len(set(a.values())) == len(a)


def test_host_finding_key_survives_group_move() -> None:
    before = next(x.key for x in _findings() if x.check == "RTP_OFF" and x.host == "WS02")
    raw = build_export()
    for h in raw["hosts"]:
        if h["KLHST_WKS_DN"] == "WS02":
            h["KLHST_WKS_GROUPID"] = 3
    after = next(x.key for x in _findings(raw) if x.check == "RTP_OFF" and x.host == "WS02")
    assert before == after


def test_missing_dates_do_not_fire() -> None:
    raw = build_export()
    for h in raw["hosts"]:
        h.pop("KLHST_WKS_RTP_AV_BASES_TIME", None)
    f = _findings(raw)
    assert not _hosts(f, "BASES_OLD")
    # а без даты полного поиска у защищённого хоста — находка «никогда»
    raw = build_export()
    for h in raw["hosts"]:
        if h["KLHST_WKS_DN"] == "WS01":
            h.pop("KLHST_WKS_LAST_FULLSCAN")
    f = _findings(raw)
    assert "WS01" in _hosts(f, "NO_FULLSCAN") and next(x for x in f if x.host == "WS01").details["last_fullscan"] == "никогда"


def test_analysis_date_is_collected_at_not_wall_clock() -> None:
    old = build_export(now=NOW - dt.timedelta(days=400))
    assert not _hosts(_findings(old), "BASES_OLD") - {"WS03"}
