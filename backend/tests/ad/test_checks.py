"""Двадцать одна проверка на синтетическом домене CORP: известные ответы."""
from __future__ import annotations

import json
from typing import Any

import pytest

from api.modules.ad.core.checks import CHECKS, run_all
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex, load_export
from api.modules.ad.core.findings import Finding
from tests.ad.synthetic import build_export, export_bytes


@pytest.fixture(scope="module")
def findings() -> list[Finding]:
    return run_all(ExportIndex(load_export(export_bytes())), AdConfig())


def by(findings: list[Finding], check: str) -> list[Finding]:
    return [f for f in findings if f.check == check]


def idents(fs: list[Finding]) -> set[str]:
    return {f.identity for f in fs}


def test_registry_has_twenty_nine_checks() -> None:
    assert len(CHECKS) == 35 and len({c.code for c in CHECKS}) == 35


def test_dcsync(findings: list[Finding]) -> None:
    fs = by(findings, "DCSync")
    da = [f for f in fs if f.identity == "CORP\\Domain Admins"]
    svc = [f for f in fs if f.identity == "CORP\\svc_backup"]
    assert len(da) == 2 and all(f.allowlisted and f.severity == "Low" for f in da)
    assert {f.right: f.severity for f in svc} == {"DS-Replication-Get-Changes-All": "Critical", "DS-Replication-Get-Changes": "High"}
    assert all(f.severity_original in ("Critical", "High") for f in da)


def test_shadow_admins_and_keycred(findings: list[Finding]) -> None:
    shadow = by(findings, "ShadowAdmins")
    assert idents(shadow) == {"CORP\\Domain Admins", "CORP\\shadow.admin"}
    assert next(f for f in shadow if f.identity == "CORP\\shadow.admin").severity == "High"
    kc = by(findings, "KeyCredentialLinkACL")
    # GenericAll на AdminSDHolder — тоже запись в msDS-KeyCredentialLink.
    assert {(f.identity, f.right) for f in kc} == {("CORP\\helpdesk", "WriteProperty"), ("CORP\\shadow.admin", "GenericAll")}


def test_sensitive_acl_and_gpo(findings: list[Finding]) -> None:
    sens = by(findings, "SensitiveAcl")
    assert {(f.identity, f.target.split(",")[0]) for f in sens} == {("CORP\\helpdesk", "OU=Servers"), ("CORP\\Domain Users", "CN=SRV01")}
    gpo = by(findings, "GpoPermissions")
    assert idents(gpo) == {"CORP\\Domain Admins", "CORP\\gpo.editor"}
    assert next(f for f in gpo if f.identity == "CORP\\gpo.editor").severity == "High"
    assert all(f.target == "Default Domain Policy" for f in gpo)


def test_accounts(findings: list[Finding]) -> None:
    assert idents(by(findings, "ASREP")) == {"CORP\\svc_old"}
    kerb = by(findings, "Kerberoast")
    assert idents(kerb) == {"CORP\\svc_sql"} and kerb[0].details["spn"] == ["MSSQLSvc/srv01.corp.local:1433"]
    assert {f.identity: f.severity for f in by(findings, "PasswordNeverExpires")} == {"CORP\\user.noexpire": "Low"}
    inactive = by(findings, "InactiveUsers")
    assert idents(inactive) == {"CORP\\user.inactive"} and inactive[0].details["idle_days"] == 200
    weak = {f.identity: f.severity for f in by(findings, "WeakEncryption")}
    assert weak == {"CORP\\user.rc4": "High", "CORP\\user.rc4aes": "Medium"}
    # admin1, admin2, Domain Admins, Enterprise Admins — в защищённых группах: adminCount у них штатный.
    assert idents(by(findings, "AdminCount")) == {"CORP\\svc_old"}
    deleg = {f.identity: (f.severity, f.details["delegation_type"]) for f in by(findings, "Delegation")}
    assert deleg == {"CORP\\delegate.user": ("High", "Unconstrained"), "CORP\\SRV01$": ("Medium", "Constrained (S4U); Constrained (Services)")}
    rbcd = by(findings, "RBCD")
    assert len(rbcd) == 1 and rbcd[0].identity == "CORP\\helpdesk" and rbcd[0].target == "WS01$"


def test_groups(findings: list[Finding]) -> None:
    priv = by(findings, "PrivilegedGroups")
    assert {(f.target, f.identity) for f in priv} == {
        ("Domain Admins", "CORP\\admin1"),
        ("Domain Admins", "CORP\\admin2"),
        ("Domain Admins", "CORP\\WS01$"),
        ("Enterprise Admins", "CORP\\admin1"),
    }
    cover = by(findings, "ProtectedUsersCoverage")
    assert {(f.target, f.identity) for f in cover} == {("Domain Admins", "CORP\\admin2")}


def test_domain_checks(findings: list[Finding]) -> None:
    maq = by(findings, "MachineAccountQuota")
    assert len(maq) == 1 and maq[0].severity == "Medium" and maq[0].details["quota"] == 10
    krb = by(findings, "KrbtgtPasswordAge")
    assert len(krb) == 1 and krb[0].severity == "High" and krb[0].details["age_days"] == 400


def test_user_rights_and_adcs(findings: list[Finding]) -> None:
    ura = {(f.right, f.identity): f.severity for f in by(findings, "UserRightsAssignment")}
    assert ura == {
        ("SeDebugPrivilege", "BUILTIN\\Administrators"): "Low",
        ("SeDebugPrivilege", "CORP\\helpdesk"): "High",
        ("SeBackupPrivilege", "BUILTIN\\Backup Operators"): "Medium",
    }
    esc = {(f.target, f.details["esc"]): (f.severity, f.details.get("requesters") or [p["name"] for p in f.details["principals"]]) for f in by(findings, "ADCS_ESC")}
    assert esc == {
        ("VulnTemplate", "ESC1"): ("High", ["CORP\\Domain Users"]),
        ("AgentTemplate", "ESC3"): ("High", ["NT AUTHORITY\\Authenticated Users"]),
        ("AgentTemplate", "ESC4"): ("High", ["NT AUTHORITY\\Authenticated Users"]),
    }
    assert by(findings, "ADCS_CA") == [] and by(findings, "ADCS_MAPPING") == []


def test_keys_stable_and_unique(findings: list[Finding]) -> None:
    again = run_all(ExportIndex(load_export(export_bytes())), AdConfig())
    assert [f.key for f in findings] == [f.key for f in again]
    keys = [f.key for f in findings]
    assert len(keys) == len(set(keys)), "ключи находок должны быть уникальны в снапшоте"


def test_allowlist_from_config_changes_severity() -> None:
    cfg = AdConfig()
    cfg.allowlist_short.append("SVC_BACKUP")
    fs = run_all(ExportIndex(load_export(export_bytes())), cfg)
    svc = [f for f in fs if f.check == "DCSync" and f.identity == "CORP\\svc_backup"]
    assert svc and all(f.allowlisted and f.severity == "Low" for f in svc)


def test_modified_export_removes_finding() -> None:
    raw: dict[str, Any] = build_export()
    for o in raw["objects"]:
        if o.get("sam") == "svc_sql":
            o["spn"] = []
    fs = run_all(ExportIndex(load_export(json.dumps(raw).encode())), AdConfig())
    assert not by(fs, "Kerberoast")
