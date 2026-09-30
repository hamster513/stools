from __future__ import annotations

import json
from typing import Any

from api.modules.ad.core.export import ExportIndex, load_export
from tests.ad.synthetic import DOMAIN_SID, EXT_SID, OTHER_SID, build_export


def _idx(raw: dict[str, Any] | None = None) -> ExportIndex:
    return ExportIndex(load_export(json.dumps(raw or build_export()).encode()))


def test_new_pki_fields_are_read() -> None:
    idx = _idx()
    ca = idx.objects("pKIEnrollmentService")[0]
    assert ca.cn == "CORP-CA" and ca.dNSHostName == "ca01.corp.local" and ca.certificateTemplates == ["VulnTemplate", "AgentTemplate"]
    oid = idx.objects("msPKI-Enterprise-Oid")[0]
    assert oid.template_oid == "1.3.6.1.4.1.311.21.8.1.1" and oid.oid_group_link == ""
    assert len(idx.objects("pkiContainer")) == 2


def test_template_publication_is_read_from_ca_objects() -> None:
    idx = _idx()
    by_cn = {t.cn: t for t in idx.objects("pKICertificateTemplate")}
    assert idx.published_on(by_cn["VulnTemplate"]) == ["CORP-CA"]
    assert idx.published_on(by_cn["SafeTemplate"]) == []


def test_publication_ignores_case() -> None:
    raw = build_export()
    ca = next(o for o in raw["objects"] if o["class"] == "pKIEnrollmentService")
    ca["certificateTemplates"] = ["vulntemplate"]
    idx = _idx(raw)
    by_cn = {t.cn: t for t in idx.objects("pKICertificateTemplate")}
    assert idx.published_on(by_cn["VulnTemplate"]) == ["CORP-CA"]
    assert idx.published_on(by_cn["AgentTemplate"]) == []


def test_publication_unknown_without_ca_objects() -> None:
    raw = build_export()
    raw["objects"] = [o for o in raw["objects"] if o["class"] != "pKIEnrollmentService"]
    idx = _idx(raw)
    assert idx.published_on(idx.objects("pKICertificateTemplate")[0]) is None


def test_template_without_cn_uses_first_rdn() -> None:
    raw = build_export()
    for o in raw["objects"]:
        if o["class"] == "pKICertificateTemplate":
            o.pop("cn", None)
    idx = _idx(raw)
    vuln = next(t for t in idx.objects("pKICertificateTemplate") if t.dn.startswith("CN=VulnTemplate,"))
    assert idx.published_on(vuln) == ["CORP-CA"]


def test_foreign_domain_sids_get_domain_and_rid_names() -> None:
    idx = _idx()
    assert idx.trusted_domains == {OTHER_SID: "OTHER", EXT_SID: "EXT"}
    assert idx.principal_name(f"{OTHER_SID}-513") == "OTHER\\Domain Users"
    assert idx.principal_name(f"{OTHER_SID}-4711") == "OTHER\\RID-4711"
    assert idx.principal_name("S-1-5-21-9-9-9-513") == "S-1-5-21-9-9-9-513"


def test_principals_name_wins_over_foreign_domain_rid() -> None:
    raw = build_export()
    raw["principals"][f"{OTHER_SID}-4711"] = {"name": "OTHER\\pki.admins", "class": "group"}
    assert _idx(raw).principal_name(f"{OTHER_SID}-4711") == "OTHER\\pki.admins"


def test_trusted_domain_sid_is_not_an_account() -> None:
    """SID домена у объекта доверия не должен выдавать объект за учётную запись этого домена."""
    idx = _idx()
    assert OTHER_SID not in idx.by_sid
    assert idx.principal_name(OTHER_SID) == OTHER_SID


def test_old_export_without_new_fields_still_loads() -> None:
    raw = build_export()
    raw["objects"] = [o for o in raw["objects"] if o["class"] not in ("pKIEnrollmentService", "pkiContainer", "msPKI-Enterprise-Oid", "trustedDomain")]
    assert _idx(raw).trusted_domains == {}


def test_forest_domain_sids_from_trust_attributes() -> None:
    """Свой домен и доверия с TRUST_ATTRIBUTE_WITHIN_FOREST (0x20); внешнее доверие — не лес."""
    assert _idx().forest_domain_sids == {DOMAIN_SID, OTHER_SID}


def test_forest_unknown_without_trusts_or_trust_attributes() -> None:
    """Старая выгрузка: доверий нет или у них нет trustAttributes — состав леса неизвестен."""
    raw = build_export()
    raw["objects"] = [o for o in raw["objects"] if o["class"] != "trustedDomain"]
    assert _idx(raw).forest_domain_sids is None
    raw = build_export()
    for o in raw["objects"]:
        o.pop("trustAttributes", None)
    assert _idx(raw).forest_domain_sids is None
