"""Опасные исключения: правила по кодам, списки из настроек, находка POLICY_EXCLUSION_RISKY, хранение и API."""
from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.ksc.core.checks import CHECK_BY_CODE, run_all
from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.exclusion_risks import RISKS, exclusion_risks
from api.modules.ksc.core.export import ExportIndex, load_export
from api.modules.ksc.core.extractors.kes_windows import (
    BEHAVIOR,
    CHILDREN,
    CHILDREN_RECURSIVE,
    NET,
    NET_ENCRYPTED,
    OBJECT,
    OPEN_FILES,
)
from api.modules.ksc.core.findings import SEVERITIES, Finding
from api.modules.ksc.core.policy_model import Exclusion, exclusion_key
from api.modules.ksc.models import KscExclusion, KscFinding
from tests.ksc.kes11 import exclusion, kes11_export, kes11_sections, trusted_app
from tests.ksc.test_api import upload

EXCLUSIONS = "852d0287/scanExclusionsAndTrustedZone.scanExclusions"
TRUSTED = "852d0287/scanExclusionsAndTrustedZone.trustedApplications"
CHECK = "POLICY_EXCLUSION_RISKY"


def _path(value: str) -> Exclusion:
    return Exclusion("mask" if "*" in value or "?" in value else "path", value)


def _app(value: str, *components: str) -> Exclusion:
    return Exclusion("trusted_app", value, components)


# --- правила ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(("e", "expected"), [
    # весь диск
    (_path("C:\\"), ["whole_drive"]),
    (_path("c:/"), ["whole_drive"]),
    (_path("C:\\*"), ["whole_drive"]),
    (_path("*"), ["whole_drive"]),
    (_path("\\\\*"), ["whole_drive"]),
    (_path("%SystemDrive%\\"), ["whole_drive"]),
    (_path("?:\\*"), ["whole_drive"]),
    (_path("\\\\?\\C:\\"), ["whole_drive"]),
    (_path("C:\\Tools\\a.exe"), []),
    (_path("C:\\Tools\\*"), []),
    # каталоги с правом записи пользователя
    (_path("C:\\Users\\Public\\Tools"), ["user_writable"]),
    (_path("%TEMP%\\build"), ["user_writable"]),
    (_path("C:/Windows/Temp/x.dat"), ["user_writable"]),
    (_path("C:\\Users\\u\\AppData\\Local\\App\\a.exe"), ["user_writable"]),
    (_path("%TEMP%"), ["user_writable"]),
    (_path("%ProgramFiles%"), []),
    (_path("C:\\ProgramData\\Vendor\\a.exe"), []),
    (_path("C:\\Tempest\\a.exe"), []),
    # маска расширения исполняемого без каталога
    (_path("*.exe"), ["ext_mask"]),
    (_path("*.PS1"), ["ext_mask"]),
    (_path("*\\*.dll"), ["ext_mask"]),
    (_path("C:\\*.exe"), ["ext_mask"]),
    (_path("C:\\**\\*.exe"), ["ext_mask"]),
    (_path("*.*"), ["ext_mask"]),
    (_path("C:\\Program Files\\App\\*.dll"), []),
    # имя файла без пути
    (_path("tool.exe"), ["name_only"]),
    (_path("*\\tool.exe"), ["name_only"]),
    (_path("**\\tool.exe"), ["name_only"]),
    (_path("C:\\tool.exe"), []),
    # маска расширения не из списка исполняемых и маска имени — без риска
    (_path("*.log"), []),
    (_path("*\\*.mdf"), []),
    (_path("tool*.exe"), []),
    # интерпретаторы
    (_path("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"), ["interpreter"]),
    (_app("C:\\Python\\python.exe"), ["interpreter"]),
    (_path("*\\cmd.exe"), ["name_only", "interpreter"]),
    (_path("C:\\Tools\\powershell_helper.exe"), []),
    (_path("%TEMP%\\wscript.exe"), ["user_writable", "interpreter"]),
    # широкое доверие
    (_app("C:\\Tools\\b.exe", OPEN_FILES, BEHAVIOR, NET), ["broad_trust"]),
    (_app("C:\\Tools\\b.exe", OPEN_FILES, BEHAVIOR, NET_ENCRYPTED), ["broad_trust"]),
    (_app("C:\\Tools\\b.exe", OPEN_FILES, CHILDREN, BEHAVIOR), ["broad_trust"]),
    (_app("C:\\Tools\\b.exe", OPEN_FILES, CHILDREN, CHILDREN_RECURSIVE), []),
    (_app("C:\\Tools\\b.exe", OPEN_FILES, BEHAVIOR), []),
    # объект «*»
    (Exclusion("threat", "*"), ["threat_any"]),
    (Exclusion("threat", "not-a-virus:*"), []),
    (Exclusion("hash", "0123456789abcdef"), []),
])
def test_rules(e: Exclusion, expected: list[str]) -> None:
    assert exclusion_risks(e, KscConfig()) == expected


@pytest.mark.parametrize(("e", "expected"), [
    # имя объекта сужает исключение до одной угрозы в этом пути: правила ширины не действуют, интерпретатор — да
    (Exclusion("path", "C:\\", (f"{OBJECT}not-a-virus:RemoteAdmin*",)), []),
    (Exclusion("path", "%TEMP%\\x", (f"{OBJECT}not-a-virus:Test*", "рекурсивно")), []),
    (Exclusion("mask", "*.exe", (f"{OBJECT}not-a-virus:Test*",)), []),
    (Exclusion("path", "tool.exe", (f"{OBJECT}not-a-virus:Test*",)), []),
    (Exclusion("mask", "*\\cmd.exe", (f"{OBJECT}not-a-virus:Test*",)), ["interpreter"]),
    # «объект: *» сужением не считается
    (Exclusion("path", "C:\\", (f"{OBJECT}*",)), ["whole_drive"]),
    (Exclusion("mask", "*\\cmd.exe", (f"{OBJECT}*",)), ["name_only", "interpreter"]),
])
def test_object_name_restricts_breadth(e: Exclusion, expected: list[str]) -> None:
    assert exclusion_risks(e, KscConfig()) == expected


def test_disabled_has_no_risks() -> None:
    assert exclusion_risks(Exclusion("path", "C:\\", enabled=False), KscConfig()) == []
    assert exclusion_risks(Exclusion("threat", "*", enabled=False), KscConfig()) == []


def test_risks_table() -> None:
    assert list(RISKS) == ["whole_drive", "user_writable", "ext_mask", "name_only", "interpreter", "broad_trust", "threat_any"]
    assert {code for code, risk in RISKS.items() if risk.severity == "Medium"} == {"name_only", "broad_trust"}
    for risk in RISKS.values():
        assert risk.severity in {"High", "Medium"} and risk.severity in SEVERITIES
        assert risk.title and risk.detail and len(risk.detail) > len(risk.title)
        assert len(risk.recommendations) >= 2 and all(r for r in risk.recommendations)


def test_config_lists_change_result() -> None:
    cfg = KscConfig(exclusion_user_writable=["\\build\\"], exclusion_exec_extensions=["*.log"], exclusion_interpreters=["tool.exe"])
    assert exclusion_risks(_path("C:\\Build\\x"), cfg) == ["user_writable"]
    assert exclusion_risks(_path("%TEMP%\\x"), cfg) == []
    assert exclusion_risks(_path("*.log"), cfg) == ["ext_mask"]
    assert exclusion_risks(_path("*.exe"), cfg) == []
    assert exclusion_risks(_path("C:\\Tools\\tool.exe"), cfg) == ["interpreter"]
    assert exclusion_risks(_path("C:\\Windows\\System32\\cmd.exe"), cfg) == []


def test_config_lists_drop_blanks() -> None:
    cfg = KscConfig(exclusion_user_writable=["  ", " \\build\\ "], exclusion_exec_extensions=[""], exclusion_interpreters=[" ", " cmd.exe "])
    assert (cfg.exclusion_user_writable, cfg.exclusion_exec_extensions, cfg.exclusion_interpreters) == (["\\build\\"], [], ["cmd.exe"])
    assert exclusion_risks(_path("C:\\Tools\\"), cfg) == []
    assert exclusion_risks(_path("C:\\Build\\cmd.exe"), cfg) == ["user_writable", "interpreter"]


def test_defaults_without_programdata() -> None:
    assert not {"\\programdata\\", "%programdata%"} & set(KscConfig().exclusion_user_writable)


# --- проверка по выгрузке ----------------------------------------------------------------------------


def _risky_export(**over: Any) -> dict[str, Any]:
    return kes11_export(**{
        EXCLUSIONS: [
            exclusion("C:\\", comment="весь диск"),
            exclusion("C:\\Tools\\a.exe"),
            exclusion("*\\cmd.exe"),
            exclusion(name="*"),
            exclusion("%TEMP%\\x", enabled=False),
        ],
        TRUSTED: [trusted_app("C:\\Tools\\b.exe", excludeOpenFiles=True, excludeBehavior=True, excludeNet=True)],
        **over,
    })


def _run(raw: dict[str, Any], cfg: KscConfig | None = None) -> list[Finding]:
    return [f for f in run_all(ExportIndex(load_export(json.dumps(raw).encode())), cfg or KscConfig()) if f.check == CHECK]


def test_registered() -> None:
    assert CHECK_BY_CODE[CHECK].title == "Опасное исключение в политике"


def test_findings_one_per_risky_exclusion() -> None:
    found = {f.details["value"]: f for f in _run(_risky_export())}
    assert set(found) == {"C:\\", "*\\cmd.exe", "*", "C:\\Tools\\b.exe"}
    drive = found["C:\\"]
    assert (drive.severity, drive.target) == ("High", "KES workstations")
    assert drive.details == {"policy_id": 1, "profile": "", "kind": "path", "value": "C:\\", "risks": ["whole_drive"],
                             "why": [RISKS["whole_drive"].title], "comment": "весь диск"}
    assert drive.key_extra == f"1||{exclusion_key(Exclusion('path', 'C:\\'))}"
    assert (found["*\\cmd.exe"].severity, found["*\\cmd.exe"].details["risks"]) == ("High", ["name_only", "interpreter"])
    assert (found["C:\\Tools\\b.exe"].severity, found["C:\\Tools\\b.exe"].details["risks"]) == ("Medium", ["broad_trust"])
    assert found["*"].details["kind"] == "threat" and found["*"].details["risks"] == ["threat_any"]


def test_clean_policy_and_inactive_policy_are_silent() -> None:
    assert _run(kes11_export()) == []
    raw = _risky_export()
    raw["policies"][0]["KLPOL_ACTIVE"] = False
    assert _run(raw) == []


def _with_profiles(raw: dict[str, Any], notebooks: list[dict[str, Any]], disabled: list[dict[str, Any]]) -> dict[str, Any]:
    """Профили политики 1: «Ноутбуки» (включён) и «Выключенный» с исключениями KES; элементы синтетики — общие словари,
    поэтому заменяются копиями, а не правятся."""
    profiles = raw["policy_profiles"]["1"]["profiles"]
    profiles[0] = {**profiles[0], "sections": kes11_sections(**{EXCLUSIONS: notebooks, TRUSTED: []})}
    profiles[1] = {**profiles[1], "sections": kes11_sections(**{EXCLUSIONS: disabled, TRUSTED: []})}
    return raw


def test_key_stable_and_profile_has_own_key() -> None:
    first = _run(_risky_export())
    raw = _with_profiles(_risky_export(**{EXCLUSIONS: [exclusion("C:\\", comment="поправлено")]}),
                         [exclusion("C:\\"), exclusion("D:\\")], [])
    second = _run(raw)
    drive = next(f for f in first if f.details["value"] == "C:\\")
    by_value = {(f.details["profile"], f.details["value"]): f for f in second if f.details["kind"] == "path"}
    # копия исключения самой политики в профиле своей находки не даёт
    assert set(by_value) == {("", "C:\\"), ("Ноутбуки", "D:\\")}
    assert by_value[("", "C:\\")].key == drive.key
    profile_only = by_value[("Ноутбуки", "D:\\")]
    assert profile_only.key_extra == f"1|Ноутбуки|{exclusion_key(Exclusion('path', 'D:\\'))}" and profile_only.key != drive.key


def test_disabled_profile_has_no_findings() -> None:
    raw = _with_profiles(kes11_export(), [], [exclusion("E:\\")])
    assert _run(raw) == []
    # Признак включённости в контейнере KLPRSS_Val (как в настоящей выгрузке): выключенный профиль по-прежнему без находок.
    profiles = raw["policy_profiles"]["1"]["profiles"]
    profiles[1] = {**profiles[1], "attrs": {**profiles[1]["attrs"], "KLSSPOL_PRF_ENABLED": {"KLPRSS_Mnd": False, "KLPRSS_Val": False}}}
    assert _run(raw) == []


def test_duplicate_key_is_one_finding_with_union() -> None:
    raw = kes11_export(**{EXCLUSIONS: [], TRUSTED: [
        trusted_app("C:\\Tools\\b.exe", excludeOpenFiles=True, excludeBehavior=True, excludeNet=True),
        trusted_app("C:\\Tools\\b.exe", comment="второй"),
        trusted_app("C:\\TOOLS\\b.exe", excludeOpenFiles=True, excludeBehavior=True, excludeChildsBehavior=True),
    ]})
    assert [(f.severity, f.details["risks"]) for f in _run(raw)] == [("Medium", ["broad_trust"])]
    raw = kes11_export(**{EXCLUSIONS: [], TRUSTED: [
        trusted_app("C:\\Python\\python.exe", excludeOpenFiles=True, excludeBehavior=True, excludeNet=True),
        trusted_app("C:\\Python\\python.exe"),
    ]})
    [f] = _run(raw)
    assert (f.severity, f.details["risks"], f.details["why"]) == ("High", ["interpreter", "broad_trust"],
                                                                 [RISKS["interpreter"].title, RISKS["broad_trust"].title])


# --- импорт и API ----------------------------------------------------------------------------------


def _sid(client: TestClient) -> int:
    return int(client.get("/api/ksc/snapshots").json()[0]["id"])


def test_import_stores_risks_findings_and_api_filter(auth_client: TestClient, db_session: Session) -> None:
    assert upload(auth_client, _with_profiles(_risky_export(), [], [exclusion("E:\\")]))["status"] == "done"
    sid = _sid(auth_client)
    db_session.expire_all()
    rows = {r.value: json.loads(r.risks_json) for r in db_session.execute(select(KscExclusion).where(KscExclusion.snapshot_id == sid)).scalars()}
    assert rows["C:\\"] == ["whole_drive"] and rows["C:\\Tools\\a.exe"] == [] and rows["%TEMP%\\x"] == []
    # строка выключенного профиля хранит коды, но находки не даёт
    assert rows["E:\\"] == ["whole_drive"]
    findings = db_session.execute(select(KscFinding).where(KscFinding.snapshot_id == sid, KscFinding.check == CHECK)).scalars().all()
    assert len(findings) == 4

    risky = auth_client.get(f"/api/ksc/snapshots/{sid}/exclusions?policy_id=1&profile=&risky=true").json()
    assert risky["total"] == 4 and risky["facets"]["risky"] == {"true": 4, "false": 0}
    item = next(i for i in risky["items"] if i["value"] == "*\\cmd.exe")
    assert item["risks"] == ["name_only", "interpreter"] and item["risk_titles"] == [RISKS["name_only"].title, RISKS["interpreter"].title]
    clean = auth_client.get(f"/api/ksc/snapshots/{sid}/exclusions?policy_id=1&profile=&risky=false").json()
    assert clean["total"] == 2 and all(i["risks"] == [] and i["risk_titles"] == [] for i in clean["items"])
    every = auth_client.get(f"/api/ksc/snapshots/{sid}/exclusions?policy_id=1").json()
    assert every["facets"]["risky"] == {"true": 5, "false": 2}  # с исключением выключенного профиля


def test_two_imports_same_finding_keys(auth_client: TestClient, db_session: Session) -> None:
    second = _risky_export()
    second["server"]["collected_at"] = "2026-09-16T12:00:00Z"
    assert upload(auth_client, _risky_export())["status"] == "done"
    assert upload(auth_client, second)["status"] == "done"
    db_session.expire_all()
    keys: dict[int, set[str]] = {}
    for f in db_session.execute(select(KscFinding).where(KscFinding.check == CHECK)).scalars():
        keys.setdefault(f.snapshot_id, set()).add(f.key)
    assert len(keys) == 2 and len(set(map(frozenset, keys.values()))) == 1


def test_settings_lists_change_stored_risks(auth_client: TestClient, db_session: Session) -> None:
    cfg = auth_client.get("/api/ksc/settings").json()["config"]
    assert cfg["exclusion_interpreters"][:2] == ["powershell.exe", "pwsh.exe"]
    cfg["exclusion_interpreters"] = []
    assert auth_client.put("/api/ksc/settings", json=cfg).status_code == 200
    assert upload(auth_client, _risky_export())["status"] == "done"
    sid = _sid(auth_client)
    item = next(i for i in auth_client.get(f"/api/ksc/snapshots/{sid}/exclusions?policy_id=1&risky=true").json()["items"]
                if i["value"] == "*\\cmd.exe")
    assert item["risks"] == ["name_only"]
