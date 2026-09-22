"""Каждая проверка: срабатывает на своём хосте синтетики и молчит на эталонном WS01."""
from __future__ import annotations

import base64
import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from api.modules.ksc.core.certs import parse_cert
from api.modules.ksc.core.checks import CHECK_BY_CODE, CHECKS, run_all
from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import ExportIndex, load_export
from api.modules.ksc.core.findings import Finding
from tests.ksc.synthetic import NOW, add_ws02_twin, build_export, export_bytes


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


def test_same_named_hosts_get_different_keys() -> None:
    f = [x for x in _findings(add_ws02_twin(build_export())) if x.check == "RTP_OFF"]
    assert [x.host for x in f] == ["WS02", "WS02"]
    assert {x.host_key for x in f} == {"ws02.corp.local", "ws02.lab.local"}
    assert len({x.key for x in f}) == 2


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


def _targets(findings: list[Finding], code: str) -> set[str]:
    return {f.target for f in findings if f.check == code}


def test_policy_checks() -> None:
    f = _findings()
    assert _targets(f, "POLICY_NONE") == {"Managed devices/Servers"}
    none = next(x for x in f if x.check == "POLICY_NONE")
    assert none.severity == "High" and none.details["product"] == "KES" and none.details["hosts"] == 1
    assert _targets(f, "POLICY_INHERIT_BROKEN") == {"Managed devices/Workstations/Lab"}
    assert next(x for x in f if x.check == "POLICY_INHERIT_BROKEN").details["policy"] == "KES lab"


def test_policy_none_silent_when_group_has_no_hosts_with_product() -> None:
    raw = build_export()
    raw["hosts"] = [h for h in raw["hosts"] if h["KLHST_WKS_DN"] != "SRV01"]
    assert not _targets(_findings(raw), "POLICY_NONE")


def test_task_checks() -> None:
    f = _findings()
    assert _targets(f, "TASK_NO_SCAN") == {"Managed devices/Servers"}
    assert not _targets(f, "TASK_NO_UPDATE")  # задача обновления на корне покрывает всех
    raw = build_export()
    raw["tasks"] = [t for t in raw["tasks"] if t["TASK_NAME"] != "Update"]
    f = _findings(raw)
    assert _targets(f, "TASK_NO_UPDATE") == {"Managed devices/Workstations", "Managed devices/Servers", "Managed devices/Workstations/Lab"}


def test_license_checks() -> None:
    f = [x for x in _findings() if x.check == "LICENSE"]
    assert len(f) == 1 and f[0].severity == "High" and f[0].target == "AAAA-BBBB"
    assert f[0].details["days_left"] == 15 and f[0].details["over_limit"] == 2
    raw = build_export()
    raw["licenses"][0]["KLLIC_LIMIT_DATE"] = {"type": "datetime", "value": "2026-01-01T00:00:00Z"}
    f = [x for x in _findings(raw) if x.check == "LICENSE"]
    assert f[0].severity == "Critical" and f[0].details["expired"] is True
    raw["licenses"][0]["KLLIC_LIMIT_DATE"] = {"type": "datetime", "value": "2027-09-15T00:00:00Z"}
    raw["licenses"][0]["KLLIC_NHOSTS_ASCURRENT"] = 5
    assert not [x for x in _findings(raw) if x.check == "LICENSE"]


def test_full_registry_count() -> None:
    assert len(CHECKS) == 29  # 18 (блок 0) + 8 (блок 1) + 3 (блок 2, этап A: замки содержимого политик)


def test_group_and_task_ids_tolerate_garbage_values() -> None:
    raw = build_export()
    raw["policies"][2]["KLPOL_GROUP_ID"] = "garbage"
    raw["tasks"][0]["TASK_INFO_PARAMS"]["PRTS_TASK_GROUPID"] = "x"
    f = _findings(raw)  # не должно упасть
    assert _targets(f, "TASK_NO_UPDATE") == {"Managed devices/Workstations", "Managed devices/Servers", "Managed devices/Workstations/Lab"}


def test_kes_ods_task_counts_as_scan() -> None:
    raw = build_export()
    for t in raw["tasks"]:
        if t["TASK_NAME"] == "Scan":
            t["TASK_NAME"] = "ods"  # имя задачи поиска у KES на живом сервере
    assert _targets(_findings(raw), "TASK_NO_SCAN") == {"Managed devices/Servers"}


# --- Блок 1: провалы и застой задач, зависшая перезагрузка, 2FA, роли, сертификат, иерархия ---


def test_task_failed_high_on_share_over_threshold() -> None:
    f = _findings()
    failed = next(x for x in f if x.check == "TASK_FAILED")
    assert failed.target == "Обновление (Managed devices)" and failed.severity == "High" and failed.key_extra == "t-upd"
    assert failed.details["failed"] == 3 and failed.details["total"] == 10 and failed.details["share"] == 0.3
    assert not _targets(f, "TASK_STALE")  # t-upd запускался вчера, t-scan — не задача обновления


def test_task_failed_medium_below_threshold_and_silent_without_failures() -> None:
    f = _findings(cfg=KscConfig(task_failed_share=0.5))
    assert next(x for x in f if x.check == "TASK_FAILED").severity == "Medium"
    raw = build_export()
    raw["tasks"][0]["statistics"] = {"4": 6, "8": 1, "16": 0}
    assert not [x for x in _findings(raw) if x.check == "TASK_FAILED"]  # без провалов не срабатывает вовсе


def test_task_failed_survives_non_numeric_statistics() -> None:
    """Счётчики statistics — значения KSC: строка или контейнер вместо числа не роняют проверку."""
    raw = build_export()
    raw["tasks"][0]["statistics"] = {"16": "abc", "4": {"x": 1}}
    f = _findings(raw)
    assert not [x for x in f if x.check == "TASK_FAILED"]
    assert f  # run_all дошёл до конца, остальные проверки на месте


def test_task_stale_fires_on_old_or_never_run_update_task() -> None:
    raw = build_export()
    raw["tasks"][0]["TASK_LAST_EXEC_TIME"] = {"type": "datetime", "value": (NOW - dt.timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    stale = next(x for x in _findings(raw) if x.check == "TASK_STALE")
    assert stale.target == "Обновление (Managed devices)" and stale.severity == "Medium" and stale.details["age_days"] == 10
    raw = build_export()
    del raw["tasks"][0]["TASK_LAST_EXEC_TIME"]
    never = next(x for x in _findings(raw) if x.check == "TASK_STALE")
    assert never.details["last_exec"] == "никогда" and never.details["age_days"] is None


def test_reboot_pending_fires_past_threshold_and_respects_config() -> None:
    f = _findings()
    assert _hosts(f, "REBOOT_PENDING") == {"WS04"}
    pending = next(x for x in f if x.check == "REBOOT_PENDING")
    assert pending.severity == "Low" and pending.details["age_days"] == 15 and pending.details["reason"] == 4
    raw = build_export()
    for h in raw["hosts"]:
        if h["KLHST_WKS_DN"] == "WS04":
            h["KLHST_WKS_RBT_REQUEST_TIME"] = {"type": "datetime", "value": (NOW - dt.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    assert not _hosts(_findings(raw), "REBOOT_PENDING")  # перезагрузка запрошена вчера
    assert not _hosts(_findings(cfg=KscConfig(reboot_pending_days=20)), "REBOOT_PENDING")  # порог поднят выше 15 дней


def test_ksc_2fa_off_and_respects_enabled() -> None:
    f = _findings()
    off = next(x for x in f if x.check == "KSC_2FA_OFF")
    assert off.severity == "High" and off.target == "Двухэтапная проверка"
    raw = build_export()
    raw["security"]["two_factor_required_for_all"] = True
    assert not [x for x in _findings(raw) if x.check == "KSC_2FA_OFF"]


def test_ksc_2fa_off_silent_on_non_boolean_value() -> None:
    """Не-логическое значение — это «нет данных» (ручка /server показывает null), а не выключенная 2FA."""
    for value in (0, ""):
        raw = build_export()
        raw["security"]["two_factor_required_for_all"] = value
        assert not [x for x in _findings(raw) if x.check == "KSC_2FA_OFF"]


def test_ksc_internal_admin_only_for_internal_account_holding_admin_role() -> None:
    f = _findings()
    assert _targets(f, "KSC_INTERNAL_ADMIN") == {"kladmin"}  # доменная учётка ivanov с ролью Administrator не внутренняя
    internal = next(x for x in f if x.check == "KSC_INTERNAL_ADMIN")
    assert internal.severity == "Medium" and internal.details["role"] == "Main Administrator"
    assert internal.details["display_name"] == "kladmin"  # UPN у внутренней учётки пуст — цель по имени


def test_ksc_admins_lists_all_admin_role_holders_but_not_auditor() -> None:
    f = _findings()
    # цель — UPN, если он есть: устойчивее и менее личный, чем отображаемое имя
    assert _targets(f, "KSC_ADMINS") == {"kladmin", "ivanov@corp.local"}
    assert all(x.severity == "Info" for x in f if x.check == "KSC_ADMINS")
    ivanov = next(x for x in f if x.check == "KSC_ADMINS" and x.target == "ivanov@corp.local")
    assert ivanov.details["display_name"] == "CORP\\ivanov" and ivanov.key_extra == "2|0"


def test_role_findings_keys_are_unique_per_role_and_group() -> None:
    """Одно и то же отображаемое имя в двух группах и две роли у одной учётки — разные находки."""
    raw = build_export()
    admin = raw["role_assignments"][0]
    raw["role_assignments"] = [
        admin,
        dict(admin, nGroupId=2, wstrGroupName="Workstations"),          # та же роль, другая группа
        dict(admin, nRoleId=7, wstrRoleName="Administrator", wstrRoleDisplayName="Administrator"),  # другая роль
    ]
    f = [x for x in _findings(raw) if x.check == "KSC_INTERNAL_ADMIN"]
    assert len(f) == 3 and len({x.key for x in f}) == 3
    assert {x.key_extra for x in f} == {"1|0", "1|2", "7|0"}


def test_server_cert_high_when_expiring_within_threshold() -> None:
    f = _findings()
    cert = next(x for x in f if x.check == "SERVER_CERT")
    assert cert.severity == "High" and cert.target == "сертификат 1: CN=ksc01" and cert.details["days_left"] == 30


def test_server_cert_silent_when_valid_for_a_year_and_critical_when_expired() -> None:
    raw = build_export()
    raw["server_certs"]["1"]["CPublic"]["value"] = base64.b64encode(_gen_cert_der("ksc01", not_before_days=-30, not_after_days=365)).decode("ascii")
    assert not [x for x in _findings(raw) if x.check == "SERVER_CERT"]
    raw["server_certs"]["1"]["CPublic"]["value"] = base64.b64encode(_gen_cert_der("ksc01", not_before_days=-300, not_after_days=-5)).decode("ascii")
    expired = next(x for x in _findings(raw) if x.check == "SERVER_CERT")
    assert expired.severity == "Critical" and expired.details["days_left"] == -5


def test_secondary_server_stale_uses_agent_silent_days() -> None:
    f = _findings()
    stale = next(x for x in f if x.check == "SECONDARY_SERVER_STALE")
    assert stale.severity == "Medium" and stale.target == "ksc02" and stale.details["age_days"] == 20
    raw = build_export()
    raw["secondary_servers"][0]["KLSRVH_SRV_LAST_CONNECTED"] = {"type": "datetime", "value": (NOW - dt.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    assert not [x for x in _findings(raw) if x.check == "SECONDARY_SERVER_STALE"]
    raw = build_export()
    del raw["secondary_servers"][0]["KLSRVH_SRV_LAST_CONNECTED"]
    never = next(x for x in _findings(raw) if x.check == "SECONDARY_SERVER_STALE")
    assert never.details["age_days"] is None


def test_block1_checks_silent_when_sections_absent() -> None:
    """Секции role_assignments/security/server_certs/secondary_servers и статистика задач — все необязательны."""
    raw = build_export()
    for key in ("role_assignments", "internal_users", "security", "server_certs", "secondary_servers"):
        raw.pop(key, None)
    for t in raw["tasks"]:
        t["statistics"] = {}
    f = _findings(raw)
    silent_codes = {"TASK_FAILED", "KSC_2FA_OFF", "KSC_INTERNAL_ADMIN", "KSC_ADMINS", "SERVER_CERT", "SECONDARY_SERVER_STALE"}
    assert not {x.check for x in f} & silent_codes


def _gen_cert_der(cn: str, *, not_before_days: int, not_after_days: int, now: dt.datetime = NOW) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + dt.timedelta(days=not_before_days))
        .not_valid_after(now + dt.timedelta(days=not_after_days))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_parse_cert_accepts_der_pem_wrapper_and_bare_base64() -> None:
    der = _gen_cert_der("test", not_before_days=-1, not_after_days=30)
    b64 = base64.b64encode(der).decode("ascii")
    from_wrapper = parse_cert({"type": "binary", "value": b64})
    from_bare_b64 = parse_cert(b64)
    from_der_bytes = parse_cert(der)
    pem = x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM).decode("ascii")
    from_pem = parse_cert(pem)
    for info in (from_wrapper, from_bare_b64, from_der_bytes, from_pem):
        assert info is not None and info.subject == "CN=test"
    assert from_wrapper.not_after.tzinfo is not None


def test_parse_cert_accepts_base64_wrapped_in_lines() -> None:
    """KSC переносит base64 по строкам — переводы строк и пробелы не должны ломать разбор."""
    der = _gen_cert_der("test", not_before_days=-1, not_after_days=30)
    b64 = base64.b64encode(der).decode("ascii")
    wrapped = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64)) + "\n"
    info = parse_cert({"type": "binary", "value": wrapped})
    assert info is not None and info.subject == "CN=test"


def test_parse_cert_returns_none_on_garbage() -> None:
    assert parse_cert(None) is None
    assert parse_cert("not a certificate") is None
    assert parse_cert({"type": "binary", "value": "not base64!!!"}) is None
    assert parse_cert(12345) is None
    assert parse_cert({}) is None
