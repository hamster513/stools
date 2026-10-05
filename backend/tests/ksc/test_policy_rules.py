"""Правила оценки политики KES: каждое срабатывает на замене в синтетике `kes11` и молчит на исходной политике."""
from __future__ import annotations

import json
from typing import Any

import pytest

from api.modules.ksc.core.checks import CHECK_BY_CODE, run_all
from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import ExportIndex, load_export
from api.modules.ksc.core.findings import Finding, finding_key
from tests.ksc.kes11 import kes11_export
from tests.ksc.synthetic import build_export

RULES = ("POLICY_COMPONENT_OFF", "POLICY_NOTIFY_ONLY", "POLICY_SELFDEFENSE_OFF", "POLICY_PASSWORD_OFF", "POLICY_THREAT_TYPES_OFF",
         "POLICY_LOCAL_EXCLUSIONS", "POLICY_KEY_UNLOCKED")
CONTAINERS = ("leaf", "top", "section", "mixed")


def _findings(raw: dict[str, Any], cfg: KscConfig | None = None) -> list[Finding]:
    """Через `load_export`, как при импорте: секреты скрываются (пароль — «<скрыто>»)."""
    return run_all(ExportIndex(load_export(json.dumps(raw).encode())), cfg or KscConfig())


def _of(findings: list[Finding], code: str) -> list[Finding]:
    return [f for f in findings if f.check == code]


def _sections(raw: dict[str, Any]) -> dict[str, Any]:
    return dict(raw["policy_contents"]["1"]["sections"])


def test_rules_registered() -> None:
    for code in RULES:
        assert code in CHECK_BY_CODE and CHECK_BY_CODE[code].title and CHECK_BY_CODE[code].description


@pytest.mark.parametrize("container", CONTAINERS)
def test_clean_policy_is_silent(container: str) -> None:
    found = _findings(kes11_export(container))
    assert not [f for f in found if f.check in RULES]


COMPONENTS = [
    ("file_threat", "4b741d57/enabled", "High"),
    ("behavior", "a9084f82/enabled", "High"),
    ("exploit", "49c71a58/enabled", "High"),
    ("network_threat", "55b2467a/enabled", "High"),
    ("remediation", "e9221213/enabled", "High"),
    ("web_threat", "da3d6211/enabled", "Medium"),
    ("mail_threat", "265f2c1d/enabled", "Medium"),
    ("amsi", "339e619d/enabled", "Medium"),
    ("firewall", "cf9370d5/firewall.enabled", "Medium"),
    ("hips", "cf9370d5/hips.enabled", "Medium"),
]


@pytest.mark.parametrize("container", CONTAINERS)
@pytest.mark.parametrize(("component", "path", "severity"), COMPONENTS)
def test_component_off(component: str, path: str, severity: str, container: str) -> None:
    found = _of(_findings(kes11_export(container, **{path: False})), "POLICY_COMPONENT_OFF")
    assert [(f.target, f.severity, f.details["component"]) for f in found] == [("KES workstations", severity, component)]
    f = found[0]
    assert f.details["policy_id"] == 1 and f.key_extra == f"1|{component}" and f.details["title"]


def test_component_off_one_finding_per_component_and_config() -> None:
    raw = kes11_export(**{"4b741d57/enabled": False, "da3d6211/enabled": False})
    found = _of(_findings(raw), "POLICY_COMPONENT_OFF")
    assert sorted(f.details["component"] for f in found) == ["file_threat", "web_threat"]
    assert len({f.key for f in found}) == 2
    only = _of(_findings(raw, KscConfig(policy_key_components=["file_threat"])), "POLICY_COMPONENT_OFF")
    assert [f.details["component"] for f in only] == ["file_threat"]


def test_component_without_flag_is_unknown_not_off() -> None:
    raw = kes11_export()
    del raw["policy_contents"]["1"]["sections"]["4b741d57"]  # секции нет — неизвестно, а не «выключен»
    assert not _of(_findings(raw), "POLICY_COMPONENT_OFF")


@pytest.mark.parametrize("container", ("leaf", "top"))
@pytest.mark.parametrize(("component", "path"), [
    ("firewall", "cf9370d5/firewall.notifyOnly"), ("hips", "cf9370d5/hips.notifyOnly"), ("network_threat", "55b2467a/notifyOnly"),
])
def test_notify_only(component: str, path: str, container: str) -> None:
    found = _of(_findings(kes11_export(container, **{path: True})), "POLICY_NOTIFY_ONLY")
    assert [(f.severity, f.details["component"], f.key_extra) for f in found] == [("High", component, f"1|{component}")]
    assert found[0].details["policy_id"] == 1


def test_notify_only_silent_when_component_off() -> None:
    found = _findings(kes11_export(**{"cf9370d5/firewall.notifyOnly": True, "cf9370d5/firewall.enabled": False}))
    assert not _of(found, "POLICY_NOTIFY_ONLY")
    assert [f.details["component"] for f in _of(found, "POLICY_COMPONENT_OFF")] == ["firewall"]


@pytest.mark.parametrize("container", CONTAINERS)
def test_selfdefense_off(container: str) -> None:
    found = _of(_findings(kes11_export(container, **{"1d3e35bd/selfDefense.enableSelfDefence": False})), "POLICY_SELFDEFENSE_OFF")
    assert [(f.severity, f.target, f.key_extra, f.details["policy_id"]) for f in found] == [("High", "KES workstations", "1", 1)]


def test_password_off_on_empty_login_and_hash() -> None:
    found = _of(_findings(kes11_export(**{"1d3e35bd/passwordProtection.login": "", "1d3e35bd/passwordProtection.passwordHash": ""})),
                "POLICY_PASSWORD_OFF")
    assert [(f.severity, f.key_extra, f.details["policy_id"]) for f in found] == [("Medium", "1", 1)]


@pytest.mark.parametrize("over", [
    {},  # оба заданы — после загрузки «<скрыто>»
    {"1d3e35bd/passwordProtection.login": ""},  # пароль задан, имени нет
    {"1d3e35bd/passwordProtection.passwordHash": ""},
    {"1d3e35bd/passwordProtection.login": "<скрыто>", "1d3e35bd/passwordProtection.passwordHash": "<скрыто>"},  # старый сборщик: неизвестно
])
def test_password_unknown_or_set_is_silent(over: dict[str, Any]) -> None:
    assert not _of(_findings(kes11_export(**over)), "POLICY_PASSWORD_OFF")


def test_password_without_keys_is_silent() -> None:
    raw = kes11_export(**{"1d3e35bd/passwordProtection.login": "", "1d3e35bd/passwordProtection.passwordHash": ""})
    del raw["policy_contents"]["1"]["sections"]["1d3e35bd"]["passwordProtection"]["passwordHash"]
    assert not _of(_findings(raw), "POLICY_PASSWORD_OFF")


@pytest.mark.parametrize(("over", "severity", "types"), [
    ({"852d0287/threats.virusesAndWorms": False}, "High", ["virusesAndWorms"]),
    ({"852d0287/threats.adware": False}, "Medium", ["adware"]),
    ({"852d0287/threats.adware": False, "852d0287/threats.trojans": False}, "High", ["trojans", "adware"]),
])
def test_threat_types_off(over: dict[str, Any], severity: str, types: list[str]) -> None:
    found = _of(_findings(kes11_export(**over)), "POLICY_THREAT_TYPES_OFF")
    assert [(f.severity, f.key_extra) for f in found] == [(severity, "1")]
    assert found[0].details["types"] == types and len(found[0].details["titles"]) == len(types)


def test_threat_types_off_on_top_container() -> None:
    found = _of(_findings(kes11_export("top", **{"852d0287/threats.maliciousTools": False})), "POLICY_THREAT_TYPES_OFF")
    assert [(f.severity, f.details["types"]) for f in found] == [("High", ["maliciousTools"])]


@pytest.mark.parametrize(("path", "flag"), [
    ("852d0287/scanExclusionsAndTrustedZone.allowUseLocalScanExclusions", "allowUseLocalScanExclusions"),
    ("852d0287/scanExclusionsAndTrustedZone.allowUseLocalTrustedApps", "allowUseLocalTrustedApps"),
])
def test_local_exclusions(path: str, flag: str) -> None:
    found = _of(_findings(kes11_export(**{path: True})), "POLICY_LOCAL_EXCLUSIONS")
    assert [(f.severity, f.key_extra, f.details["allowed"]) for f in found] == [("Medium", "1", [flag])]


def _set_lock(node: dict[str, Any], locked: bool | None) -> None:
    if locked is None:
        node.pop("KLPRSS_Mnd")
    else:
        node["KLPRSS_Mnd"] = locked


def test_key_unlocked_leaf() -> None:
    raw = kes11_export()
    sections = _sections(raw)
    _set_lock(sections["4b741d57"]["enabled"], False)
    _set_lock(sections["1d3e35bd"]["selfDefense"]["enableSelfDefence"], False)
    found = _of(_findings(raw), "POLICY_KEY_UNLOCKED")
    assert [(f.severity, f.key_extra) for f in found] == [("Medium", "1")]
    assert found[0].details["unlocked"] == ["file_threat", "self_defense"] and found[0].details["policy_id"] == 1


def test_key_unlocked_top() -> None:
    raw = kes11_export("top")
    _set_lock(_sections(raw)["cf9370d5"]["hips"], False)  # замок контейнера `hips` — у `hips.enabled`
    found = _of(_findings(raw), "POLICY_KEY_UNLOCKED")
    assert [f.details["unlocked"] for f in found] == [["hips"]]


def test_key_unlocked_silent_without_lock_flag() -> None:
    raw = kes11_export()
    sections = _sections(raw)
    _set_lock(sections["4b741d57"]["enabled"], None)
    _set_lock(sections["1d3e35bd"]["selfDefense"]["enableSelfDefence"], None)
    assert not _of(_findings(raw), "POLICY_KEY_UNLOCKED")


ALL_BAD = {
    "4b741d57/enabled": False, "cf9370d5/hips.notifyOnly": True, "1d3e35bd/selfDefense.enableSelfDefence": False,
    "1d3e35bd/passwordProtection.login": "", "1d3e35bd/passwordProtection.passwordHash": "", "852d0287/threats.trojans": False,
    "852d0287/scanExclusionsAndTrustedZone.allowUseLocalScanExclusions": True,
}


def _all_bad(**policy: Any) -> dict[str, Any]:
    raw = kes11_export(**ALL_BAD)
    _set_lock(_sections(raw)["a9084f82"]["enabled"], False)
    raw["policies"][0].update(policy)
    return raw


def test_all_rules_fire_together() -> None:
    assert {f.check for f in _findings(_all_bad())} >= set(RULES)


def test_inactive_policy_is_silent() -> None:
    assert not [f for f in _findings(_all_bad(KLPOL_ACTIVE=False)) if f.check in RULES]


def test_product_without_dictionary_is_silent() -> None:
    assert not [f for f in _findings(_all_bad(KLPOL_PRODUCT="KESL")) if f.check in RULES]


def test_policy_without_contents_is_silent() -> None:
    raw = _all_bad()
    del raw["policy_contents"]["1"]
    assert not [f for f in _findings(raw) if f.check in RULES]


def test_lock_checks_carry_policy_id_with_same_keys() -> None:
    """`POLICY_NO_LOCKS`, `POLICY_WEAK_LOCKS`, `POLICY_CONTENT_MISSING` получили `policy_id`, ключи прежние (`key_extra` — id политики)."""
    raw = build_export()
    raw["policy_contents"]["1"]["sections"] = {}  # пустое содержимое — POLICY_CONTENT_MISSING
    found = _findings(raw, KscConfig(policy_lock_share=0.9))
    no_locks = _of(found, "POLICY_NO_LOCKS")
    missing = _of(found, "POLICY_CONTENT_MISSING")
    assert [(f.details["policy_id"], f.key_extra) for f in no_locks] == [(3, "3")]
    assert [(f.details["policy_id"], f.key_extra) for f in missing] == [(1, "1")]
    for f in no_locks + missing:
        assert f.key == finding_key(Finding(check=f.check, severity="Info", target=f.target, key_extra=f.key_extra))
    weak = _of(_findings(build_export(), KscConfig(policy_lock_share=0.9)), "POLICY_WEAK_LOCKS")
    assert [(f.details["policy_id"], f.key_extra) for f in weak] == [(1, "1")]
