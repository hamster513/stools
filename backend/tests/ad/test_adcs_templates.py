"""ADCS_ESC: правило заявителя и ESC1–4, 9, 13, 15 по шаблонам."""
from __future__ import annotations

import base64
import json
import uuid
from typing import Any

from api.modules.ad.core import sd
from api.modules.ad.core.checks.adcs import check_adcs_templates
from api.modules.ad.core.checks.adcs_rules import requester_kind, severity_for, step_down
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex, load_export
from api.modules.ad.core.findings import Finding
from tests.ad.synthetic import GUID_ENROLL, OTHER_SID, PKI, b64sd, build_export, rid, user_dn

CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
ANY_PURPOSE = "2.5.29.37.0"
REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
POLICY_OID = "1.3.6.1.4.1.311.21.8.1.1"
HELPDESK = rid(1108)


def enroll(sid: str) -> bytes:
    return sd.build_ace(sid, sd.EXTENDED_RIGHT, object_type=uuid.UUID(GUID_ENROLL))


def template(cn: str = "TestTemplate", aces: list[bytes] | None = None, **fields: Any) -> dict[str, Any]:
    t: dict[str, Any] = {
        "dn": f"CN={cn},CN=Certificate Templates,{PKI}",
        "class": "pKICertificateTemplate",
        "cn": cn,
        "displayName": cn,
        "pKIExtendedKeyUsage": [CLIENT_AUTH],
        "msPKI-Certificate-Name-Flag": 1,
        "msPKI-Enrollment-Flag": 0,
        "msPKI-RA-Signature": 0,
        "msPKI-Template-Schema-Version": 2,
        "sd": b64sd(aces if aces is not None else [enroll(HELPDESK), sd.build_ace(rid(512), sd.GENERIC_ALL)]),
    }
    t.update(fields)
    return t


def _raw(*templates: dict[str, Any], publish: bool = True) -> dict[str, Any]:
    raw = build_export()
    raw["objects"].extend(templates)
    if publish:
        ca = next(o for o in raw["objects"] if o["class"] == "pKIEnrollmentService")
        ca["certificateTemplates"] = ca["certificateTemplates"] + [t["cn"] for t in templates]
    return raw


def _idx(raw: dict[str, Any] | None = None) -> ExportIndex:
    return ExportIndex(load_export(json.dumps(raw or build_export()).encode()))


def run(*templates: dict[str, Any], publish: bool = True, raw: dict[str, Any] | None = None, cfg: AdConfig | None = None) -> list[Finding]:
    return check_adcs_templates(_idx(raw or _raw(*templates, publish=publish)), cfg or AdConfig())


def esc(fs: list[Finding], code: str, target: str = "TestTemplate") -> list[Finding]:
    return [f for f in fs if f.key_extra == code and f.target == target]


def on(fs: list[Finding], target: str = "TestTemplate") -> list[Finding]:
    return [f for f in fs if f.target == target]


# ---- правило заявителя ------------------------------------------------------


def test_requester_kind() -> None:
    idx, cfg = _idx(), AdConfig()
    assert requester_kind(idx, cfg, "S-1-5-11") == "broad"
    assert requester_kind(idx, cfg, rid(513)) == "broad"
    assert requester_kind(idx, cfg, f"{OTHER_SID}-513") == "broad"
    assert requester_kind(idx, cfg, rid(512)) == "safe"
    assert requester_kind(idx, cfg, f"{OTHER_SID}-519") == "safe"
    assert requester_kind(idx, cfg, "S-1-5-18") == "safe"
    assert requester_kind(idx, cfg, HELPDESK) == "other"


def test_safe_principal_by_name() -> None:
    idx = _idx()
    assert requester_kind(idx, AdConfig(adcs_safe_principals=["CORP\\helpdesk"]), HELPDESK) == "safe"
    assert requester_kind(idx, AdConfig(adcs_safe_principals=["helpdesk"]), HELPDESK) == "safe"


def test_severity_steps() -> None:
    assert severity_for("High", ["other"]) == "Medium"
    assert severity_for("High", ["other", "broad"]) == "High"
    assert [step_down(s) for s in ("Critical", "High", "Medium", "Low")] == ["High", "Medium", "Low", "Low"]


# ---- ESC1 -------------------------------------------------------------------


def test_esc1_other_requester_is_one_step_down() -> None:
    fs = esc(run(template()), "ESC1")
    assert len(fs) == 1
    f = fs[0]
    assert f.check == "ADCS_ESC" and f.severity == "Medium" and f.identity == ""
    assert f.details["requesters"] == ["CORP\\helpdesk"] and f.details["requesters_broad"] is False
    assert f.details["published"] == ["CORP-CA"] and f.details["template_dn"].startswith("CN=TestTemplate,")
    assert "проверьте состав группы" in f.details["details"]


def test_esc1_foreign_domain_users_is_high() -> None:
    f = esc(run(template(aces=[enroll(f"{OTHER_SID}-513")])), "ESC1")[0]
    assert f.severity == "High" and f.details["requesters"] == ["OTHER\\Domain Users"] and f.details["requesters_broad"] is True


def test_esc1_blocked_by_manager_approval() -> None:
    assert esc(run(template(**{"msPKI-Enrollment-Flag": 0x2})), "ESC1") == []


def test_esc1_blocked_by_agent_signature() -> None:
    assert esc(run(template(**{"msPKI-RA-Signature": 1})), "ESC1") == []


def test_esc1_not_for_server_auth_only() -> None:
    assert esc(run(template(pKIExtendedKeyUsage=[SERVER_AUTH])), "ESC1") == []


def test_esc1_not_when_only_admins_enroll() -> None:
    assert on(run(template(aces=[enroll(rid(512)), enroll("S-1-5-18"), sd.build_ace(rid(519), sd.GENERIC_ALL)]))) == []


def test_esc1_by_application_policies() -> None:
    t = template(pKIExtendedKeyUsage=[SERVER_AUTH], **{"msPKI-Certificate-Application-Policy": [CLIENT_AUTH]})
    fs = esc(run(t), "ESC1")
    assert len(fs) == 1 and fs[0].details["eku"] == [CLIENT_AUTH]


def test_application_policies_override_eku() -> None:
    t = template(pKIExtendedKeyUsage=[CLIENT_AUTH], **{"msPKI-Certificate-Application-Policy": [SERVER_AUTH]})
    assert esc(run(t), "ESC1") == []


def test_esc1_via_all_extended_rights() -> None:
    t = template(aces=[sd.build_ace(HELPDESK, sd.EXTENDED_RIGHT)])
    assert len(esc(run(t), "ESC1")) == 1


def test_esc1_via_generic_all() -> None:
    t = template(aces=[sd.build_ace(HELPDESK, sd.GENERIC_ALL)])
    assert len(esc(run(t), "ESC1")) == 1


def test_inherit_only_ace_is_not_a_requester() -> None:
    t = template(aces=[sd.build_ace(HELPDESK, sd.GENERIC_ALL, flags=sd.ACE_FLAG_INHERIT_ONLY)])
    assert on(run(t)) == []


def test_unpublished_template_is_low() -> None:
    f = esc(run(template(aces=[enroll("S-1-5-11")]), publish=False), "ESC1")[0]
    assert f.severity == "Low" and f.details["published"] == [] and "не опубликован" in f.details["details"]


def test_publication_unknown_without_ca_objects() -> None:
    raw = _raw(template(), publish=False)
    raw["objects"] = [o for o in raw["objects"] if o["class"] != "pKIEnrollmentService"]
    f = esc(run(raw=raw), "ESC1")[0]
    assert f.details["published"] == "неизвестно" and f.severity == "Medium"


def test_two_templates_with_same_display_name_are_two_findings() -> None:
    fs = [f for f in run(template("TplA", displayName="Dup"), template("TplB", displayName="Dup")) if f.key_extra == "ESC1"]
    fs = [f for f in fs if f.details["template_dn"].startswith(("CN=TplA,", "CN=TplB,"))]
    assert len(fs) == 2 and len({f.key for f in fs}) == 2 and len({f.target for f in fs}) == 2


def test_target_is_display_name_or_cn() -> None:
    t = template("NoDisplay")
    del t["displayName"]
    assert len(esc(run(t), "ESC1", target="NoDisplay")) == 1


# ---- ESC2, ESC3, ESC4 ---------------------------------------------------------


def test_esc2_empty_eku() -> None:
    fs = run(template(pKIExtendedKeyUsage=[], **{"msPKI-Certificate-Name-Flag": 0}))
    assert len(esc(fs, "ESC2")) == 1 and esc(fs, "ESC1") == []


def test_esc2_any_purpose() -> None:
    fs = run(template(pKIExtendedKeyUsage=[ANY_PURPOSE], **{"msPKI-Certificate-Name-Flag": 0}))
    assert len(esc(fs, "ESC2")) == 1


def test_esc2_not_for_client_auth() -> None:
    assert esc(run(template(**{"msPKI-Certificate-Name-Flag": 0})), "ESC2") == []


def test_esc3_counts_on_behalf_templates() -> None:
    agent = template("Agent3", pKIExtendedKeyUsage=[REQUEST_AGENT], **{"msPKI-Certificate-Name-Flag": 0})
    v1 = template("UserV1", aces=[enroll(rid(512))], **{"msPKI-Template-Schema-Version": 1, "msPKI-Certificate-Name-Flag": 0})
    ra = template("UserRa", aces=[enroll(rid(512))], pKIExtendedKeyUsage=[SERVER_AUTH], **{"msPKI-RA-Application-Policies": [REQUEST_AGENT], "msPKI-Certificate-Name-Flag": 0})
    fs = esc(run(agent, v1, ra), "ESC3", target="Agent3")
    assert len(fs) == 1 and fs[0].details["on_behalf_templates"] == 2 and fs[0].severity == "Medium"


def test_esc3_on_behalf_count_skips_unpublished() -> None:
    agent = template("Agent3", pKIExtendedKeyUsage=[REQUEST_AGENT], **{"msPKI-Certificate-Name-Flag": 0})
    raw = _raw(agent)
    raw["objects"].append(template("UserV1", aces=[enroll(rid(512))], **{"msPKI-Template-Schema-Version": 1}))
    assert esc(run(raw=raw), "ESC3", target="Agent3")[0].details["on_behalf_templates"] == 0


def test_esc3_blocked_by_manager_approval() -> None:
    t = template(pKIExtendedKeyUsage=[REQUEST_AGENT], **{"msPKI-Enrollment-Flag": 0x2})
    assert esc(run(t), "ESC3") == []


def _writer(sid: str, right: int) -> dict[str, Any]:
    return template(aces=[sd.build_ace(sid, right), sd.build_ace(rid(512), sd.GENERIC_ALL)], pKIExtendedKeyUsage=[SERVER_AUTH], **{"msPKI-Certificate-Name-Flag": 0})


def test_esc4_other_writer_is_medium() -> None:
    fs = run(_writer(HELPDESK, sd.WRITE_DACL))
    assert [(f.key_extra, f.severity) for f in on(fs)] == [("ESC4", "Medium")]
    d = esc(fs, "ESC4")[0].details
    assert d["principals"] == [{"name": "CORP\\helpdesk", "sid": HELPDESK, "kind": "other", "rights": ["WriteDacl"]}]
    assert d["principals_broad"] is False and "requesters" not in d


def test_esc4_broad_writer_is_high() -> None:
    assert esc(run(_writer("S-1-5-11", sd.WRITE_PROPERTY)), "ESC4")[0].severity == "High"


def test_esc4_not_for_admins() -> None:
    assert on(run(_writer(rid(512), sd.WRITE_OWNER))) == []


def test_esc4_owner_is_writer() -> None:
    t = template(aces=[sd.build_ace(rid(512), sd.GENERIC_ALL)], pKIExtendedKeyUsage=[SERVER_AUTH], **{"msPKI-Certificate-Name-Flag": 0})
    t["sd"] = base64.b64encode(sd.build_sd([sd.build_ace(rid(512), sd.GENERIC_ALL)], owner=HELPDESK)).decode()
    fs = esc(run(t), "ESC4")
    assert len(fs) == 1 and fs[0].severity == "Medium" and fs[0].details["principals"][0]["rights"] == ["owner"]


def test_esc4_not_for_create_child() -> None:
    assert on(run(_writer("S-1-5-11", sd.CREATE_CHILD))) == []


# ---- ESC9, ESC13, ESC15 -------------------------------------------------------


def test_esc9_no_security_extension() -> None:
    t = template(aces=[enroll(rid(513))], **{"msPKI-Enrollment-Flag": 0x80000, "msPKI-Certificate-Name-Flag": 0})
    fs = esc(run(t), "ESC9")
    assert len(fs) == 1 and fs[0].severity == "Medium"


def test_esc9_needs_login_eku() -> None:
    t = template(aces=[enroll(rid(513))], pKIExtendedKeyUsage=[SERVER_AUTH], **{"msPKI-Enrollment-Flag": 0x80000})
    assert esc(run(t), "ESC9") == []


def test_esc9_needs_flag() -> None:
    assert esc(run(template(aces=[enroll(rid(513))])), "ESC9") == []


def test_esc9_not_with_manager_approval() -> None:
    t = template(aces=[enroll(rid(513))], **{"msPKI-Enrollment-Flag": 0x80000 | 0x2, "msPKI-Certificate-Name-Flag": 0})
    assert esc(run(t), "ESC9") == []


def _linked(raw: dict[str, Any], link: str) -> dict[str, Any]:
    oid = next(o for o in raw["objects"] if o["class"] == "msPKI-Enterprise-Oid")
    oid["msDS-OIDToGroupLink"] = link
    return raw


def test_esc13_policy_linked_to_group() -> None:
    t = template(**{"msPKI-Certificate-Policy": [POLICY_OID], "msPKI-Certificate-Name-Flag": 0})
    fs = esc(run(raw=_linked(_raw(t), user_dn("Tier0"))), "ESC13")
    assert len(fs) == 1 and fs[0].details["group"] == user_dn("Tier0") and fs[0].severity == "Medium"


def test_esc13_not_without_group_link() -> None:
    t = template(**{"msPKI-Certificate-Policy": [POLICY_OID], "msPKI-Certificate-Name-Flag": 0})
    assert esc(run(t), "ESC13") == []


def test_esc13_not_with_manager_approval() -> None:
    t = template(**{"msPKI-Certificate-Policy": [POLICY_OID], "msPKI-Certificate-Name-Flag": 0, "msPKI-Enrollment-Flag": 0x2})
    assert esc(run(raw=_linked(_raw(t), user_dn("Tier0"))), "ESC13") == []


def test_esc15_schema_v1_with_supplied_subject() -> None:
    t = template(pKIExtendedKeyUsage=[SERVER_AUTH], **{"msPKI-Template-Schema-Version": 1})
    fs = esc(run(t), "ESC15")
    assert len(fs) == 1 and "ноября 2024" in fs[0].details["details"]


def test_esc15_not_for_schema_v2() -> None:
    assert esc(run(template(pKIExtendedKeyUsage=[SERVER_AUTH])), "ESC15") == []


def test_esc15_not_with_manager_approval() -> None:
    t = template(pKIExtendedKeyUsage=[SERVER_AUTH], **{"msPKI-Template-Schema-Version": 1, "msPKI-Enrollment-Flag": 0x2})
    assert esc(run(t), "ESC15") == []


def test_esc9_13_15_not_with_agent_signature() -> None:
    t = template(**{
        "msPKI-Enrollment-Flag": 0x80000,
        "msPKI-Template-Schema-Version": 1,
        "msPKI-Certificate-Policy": [POLICY_OID],
        "msPKI-RA-Signature": 1,
    })
    fs = run(raw=_linked(_raw(t), user_dn("Tier0")))
    assert esc(fs, "ESC9") == esc(fs, "ESC13") == esc(fs, "ESC15") == []
