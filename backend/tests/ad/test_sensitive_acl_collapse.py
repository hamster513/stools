"""Сворачивание находок SensitiveAcl: унаследованные ACE — к источнику, массовые явные — в одну."""
from __future__ import annotations

import json
import uuid
import zlib
from typing import Any

import pytest
from pydantic import ValidationError

from api.modules.ad.core import sd
from api.modules.ad.core.checks.acl import (
    check_dcsync,
    check_gpo_permissions,
    check_key_credential_link_acl,
    check_sensitive_acl,
    check_shadow_admins,
)
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex, load_export
from api.modules.ad.core.findings import Finding, finding_key, is_allowlisted
from tests.ad.synthetic import (
    DN,
    GUID_GET_CHANGES,
    GUID_GET_CHANGES_ALL,
    GUID_KEYCRED,
    b64sd,
    build_export,
    rid,
)

CI = 0x02  # CONTAINER_INHERIT_ACE
INH = sd.ACE_FLAG_INHERITED

OU = f"OU=Workstations,{DN}"
SUB = f"OU=Floor2,{OU}"
EDITOR = rid(1113)  # gpo.editor: явное право на OU, наследуется компьютерами
ROOTER = rid(1110)  # user.rc4: явное право на корне домена
GHOST = rid(1111)  # user.rc4aes: унаследовано от объекта вне выгрузки
MASS = rid(1107)  # user.noexpire: явное право на множестве компьютеров


def comp(dn: str, aces: list[bytes]) -> dict[str, Any]:
    name = dn.split(",")[0][3:]
    return {"dn": dn, "class": "computer", "sid": rid(5000 + zlib.crc32(dn.encode()) % 100000), "sam": name + "$", "name": name, "uac": 4096, "sd": b64sd(aces)}


def tree_export(*, mass: int = 0) -> ExportIndex:
    exp = build_export()
    objs: list[dict[str, Any]] = exp["objects"]
    root = next(o for o in objs if o["dn"] == DN)
    # Корень (вне области проверки) отдаёт WriteProperty пользователю user.rc4 всем потомкам.
    root["sd"] = b64sd(
        [
            sd.build_ace(rid(512), sd.EXTENDED_RIGHT, object_type=uuid.UUID(GUID_GET_CHANGES_ALL)),
            sd.build_ace(rid(512), sd.EXTENDED_RIGHT, object_type=uuid.UUID(GUID_GET_CHANGES)),
            sd.build_ace(rid(1104), sd.EXTENDED_RIGHT, object_type=uuid.UUID(GUID_GET_CHANGES_ALL)),
            sd.build_ace(rid(1104), sd.EXTENDED_RIGHT, object_type=uuid.UUID(GUID_GET_CHANGES)),
            sd.build_ace(rid(1108), sd.WRITE_PROPERTY, object_type=uuid.UUID(GUID_KEYCRED)),
            sd.build_ace(ROOTER, sd.WRITE_PROPERTY, flags=CI),
        ]
    )
    from_root = sd.build_ace(ROOTER, sd.WRITE_PROPERTY, flags=CI | INH)
    objs.append({"dn": OU, "class": "organizationalUnit", "sd": b64sd([sd.build_ace(EDITOR, sd.GENERIC_WRITE, flags=CI), from_root])})
    # Вложенная OU получает оба права по наследству.
    objs.append({"dn": SUB, "class": "organizationalUnit", "sd": b64sd([sd.build_ace(EDITOR, sd.GENERIC_WRITE, flags=CI | INH), from_root])})
    for i in range(3):
        objs.append(comp(f"CN=WS1{i},{SUB}", [sd.build_ace(EDITOR, sd.GENERIC_WRITE, flags=CI | INH), from_root]))
    # CN=Computers в выгрузке нет: право GHOST унаследовано от него, источник неизвестен.
    for i in range(2):
        objs.append(comp(f"CN=PC{i},CN=Computers,{DN}", [sd.build_ace(GHOST, sd.WRITE_DACL, flags=INH), from_root]))
    for i in range(mass):
        objs.append(comp(f"CN=M{i:03d},OU=Mass,{DN}", [sd.build_ace(MASS, sd.WRITE_OWNER)]))
    return ExportIndex(load_export(json.dumps(exp).encode()))


def of(fs: list[Finding], sid: str) -> list[Finding]:
    return [f for f in fs if f.identity_sid == sid]


def test_inherited_from_ou_collapses_to_ou() -> None:
    fs = check_sensitive_acl(tree_export(), AdConfig())
    ed = of(fs, EDITOR)
    assert len(ed) == 1
    f = ed[0]
    assert f.target == OU and f.key_extra == "" and f.severity == "High"
    assert f.details["inherited_to"] == {"organizationalUnit": 1, "computer": 3}
    assert f.details["source_in_scope"] is True and f.details["is_inherited"] is False
    assert f.details["object_type"] == "organizationalUnit"
    assert sorted(f.details["samples"]) == sorted([SUB] + [f"CN=WS1{i},{SUB}" for i in range(3)])
    assert f.right == "GenericWrite"


def test_inherited_from_root_out_of_scope() -> None:
    fs = of(check_sensitive_acl(tree_export(), AdConfig()), ROOTER)
    assert len(fs) == 1
    f = fs[0]
    assert f.target == DN and f.details["source_in_scope"] is False and f.details["object_type"] == "domainDNS"
    assert f.details["inherited_to"] == {"organizationalUnit": 2, "computer": 5}
    assert "source" not in f.details


def test_unknown_source_grouped() -> None:
    fs = of(check_sensitive_acl(tree_export(), AdConfig()), GHOST)
    assert len(fs) == 1
    f = fs[0]
    # CN=Computers в выгрузке нет — ближайший известный общий предок это корень.
    assert f.target == DN and f.details["source"] == "unknown" and f.details["inherited_to"] == {"computer": 2}
    assert f.details["source_in_scope"] is False and f.key_extra == "unknown"


def test_no_findings_on_children_for_inherited() -> None:
    fs = check_sensitive_acl(tree_export(), AdConfig())
    assert not [f for f in fs if f.target.startswith("CN=WS1") or f.target.startswith("CN=PC") or f.target == SUB]


def test_mass_explicit_collapses_over_threshold() -> None:
    idx = tree_export(mass=60)
    fs = of(check_sensitive_acl(idx, AdConfig()), MASS)
    assert len(fs) == 1
    f = fs[0]
    assert f.key_extra == "mass" and f.target == f"OU=Mass,{DN}"
    assert f.details["explicit_on"] == {"computer": 60} and len(f.details["samples"]) == 20
    per_obj = of(check_sensitive_acl(idx, AdConfig(sensitive_acl_collapse_threshold=100)), MASS)
    assert len(per_obj) == 60 and {x.key_extra for x in per_obj} == {""}


def _legacy(idx: ExportIndex, cfg: AdConfig) -> list[tuple[str, str]]:
    """Эталон прежнего поведения: находка на каждую пару (объект, ACE)."""
    from api.modules.ad.core.checks.acl import WRITE_LIKE, _sensitive_targets

    out = []
    for obj in _sensitive_targets(idx, cfg):
        desc = idx.sd_of(obj)
        for ace in desc.dacl if desc else []:
            if ace.allow and ace.mask & WRITE_LIKE and not is_allowlisted(idx.principal_name(ace.sid), cfg):
                f = Finding(check="SensitiveAcl", severity="High", identity=idx.principal_name(ace.sid), identity_sid=ace.sid, target=obj.dn, right=", ".join(ace.rights))
                out.append((finding_key(f), obj.dn))
    return out


def test_collapse_off_keeps_old_findings_and_keys() -> None:
    idx = tree_export(mass=60)
    cfg = AdConfig(sensitive_acl_collapse=False)
    fs = check_sensitive_acl(idx, cfg)
    assert [(f.key, f.target) for f in fs] == _legacy(idx, cfg)
    assert all(set(f.details) == {"object_type", "is_inherited"} for f in fs)
    assert len(fs) > 60


def test_explicit_findings_keep_keys_when_collapsed() -> None:
    """Явная ACE на объекте в области — прежний ключ и при сворачивании."""
    idx = tree_export()
    old = {k for k, _ in _legacy(idx, AdConfig())}
    new = check_sensitive_acl(idx, AdConfig())
    ou = next(f for f in new if f.identity_sid == EDITOR)
    assert ou.key in old


def test_keys_stable_and_unique() -> None:
    a = check_sensitive_acl(tree_export(mass=60), AdConfig())
    b = check_sensitive_acl(tree_export(mass=60), AdConfig())
    assert [f.key for f in a] == [f.key for f in b]
    assert len({f.key for f in a}) == len(a)


def test_other_acl_checks_unaffected() -> None:
    idx = tree_export(mass=60)
    for check in (check_dcsync, check_shadow_admins, check_key_credential_link_acl, check_gpo_permissions):
        on = [(f.key, f.details) for f in check(idx, AdConfig())]
        off = [(f.key, f.details) for f in check(idx, AdConfig(sensitive_acl_collapse=False))]
        assert on == off and on


@pytest.mark.parametrize("value", [0, 100001])
def test_threshold_bounds(value: int) -> None:
    with pytest.raises(ValidationError):
        AdConfig(sensitive_acl_collapse_threshold=value)


def test_computers_only_scope_counts_computers() -> None:
    """Дерево OU → 3 компьютера: одна находка на OU, даже если OU вне области."""
    fs = of(check_sensitive_acl(tree_export(), AdConfig(sensitive_acl_scope="Computers")), EDITOR)
    assert len(fs) == 1 and fs[0].target == OU
    assert fs[0].details["inherited_to"] == {"computer": 3} and fs[0].details["source_in_scope"] is False


def test_generic_rights_match_mapped_child_and_escaped_dn() -> None:
    """На OU стоит GenericAll, у потомка — те же права битами; запятая в имени экранирована."""
    exp = build_export()
    ou = f"OU=Sales\\, East,{DN}"
    exp["objects"].append({"dn": ou, "class": "organizationalUnit", "sd": b64sd([sd.build_ace(EDITOR, sd.GENERIC_ALL, flags=CI)])})
    exp["objects"].append(comp(f"CN=S1,{ou}", [sd.build_ace(EDITOR, 0xF01FF, flags=CI | INH)]))
    fs = of(check_sensitive_acl(ExportIndex(load_export(json.dumps(exp).encode())), AdConfig()), EDITOR)
    assert [(f.target, f.details["inherited_to"]) for f in fs] == [(ou, {"computer": 1})]


IO = sd.ACE_FLAG_INHERIT_ONLY
NP = 0x04  # NO_PROPAGATE_INHERIT_ACE


def run(extra: list[dict[str, Any]], *, root_aces: list[bytes] | None = None, cfg: AdConfig | None = None) -> list[Finding]:
    exp = build_export()
    if root_aces is not None:
        next(o for o in exp["objects"] if o["dn"] == DN)["sd"] = b64sd(root_aces)
    exp["objects"].extend(extra)
    return check_sensitive_acl(ExportIndex(load_export(json.dumps(exp).encode())), cfg or AdConfig())


def ou_obj(dn: str, aces: list[bytes]) -> dict[str, Any]:
    return {"dn": dn, "class": "organizationalUnit", "sd": b64sd(aces)}


def test_split_generic_ace_counts_child_once() -> None:
    """Inherit-only GenericAll даёт потомку две ACE с одним ключом — объект считается один раз."""
    fs = of(
        run([
            ou_obj(OU, [sd.build_ace(EDITOR, sd.GENERIC_ALL, flags=CI | IO)]),
            comp(f"CN=C1,{OU}", [sd.build_ace(EDITOR, 0xF01FF, flags=INH), sd.build_ace(EDITOR, sd.GENERIC_ALL, flags=CI | IO | INH)]),
        ]),
        EDITOR,
    )
    assert [(f.target, f.details["inherited_to"], f.details["samples"]) for f in fs] == [(OU, {"computer": 1}, [f"CN=C1,{OU}"])]


def test_same_ace_inherited_twice_counts_once() -> None:
    fs = of(
        run([
            ou_obj(OU, [sd.build_ace(EDITOR, sd.WRITE_DACL, flags=CI)]),
            comp(f"CN=C1,{OU}", [sd.build_ace(EDITOR, sd.WRITE_DACL, flags=CI | INH), sd.build_ace(EDITOR, sd.WRITE_DACL, flags=INH)]),
        ]),
        EDITOR,
    )
    assert [f.details["inherited_to"] for f in fs] == [{"computer": 1}]


def test_non_inheritable_explicit_ace_is_not_a_source() -> None:
    """Явная ACE без CONTAINER_INHERIT на OU потомкам не достаётся — источник выше, на корне."""
    fs = of(
        run(
            [
                ou_obj(OU, [sd.build_ace(ROOTER, sd.WRITE_DACL), sd.build_ace(ROOTER, sd.WRITE_DACL, flags=CI | INH)]),
                comp(f"CN=C1,{OU}", [sd.build_ace(ROOTER, sd.WRITE_DACL, flags=CI | INH)]),
            ],
            root_aces=[sd.build_ace(ROOTER, sd.WRITE_DACL, flags=CI)],
        ),
        ROOTER,
    )
    got = {f.target: f.details.get("inherited_to") for f in fs}
    assert got == {OU: None, DN: {"organizationalUnit": 1, "computer": 1}}


def _np_tree() -> list[dict[str, Any]]:
    np_ace = sd.build_ace(EDITOR, sd.WRITE_DACL, flags=CI | NP)
    return [
        ou_obj(OU, [np_ace]),
        ou_obj(SUB, [sd.build_ace(EDITOR, sd.WRITE_DACL, flags=INH)]),
        comp(f"CN=C1,{OU}", [sd.build_ace(EDITOR, sd.WRITE_DACL, flags=INH)]),
        comp(f"CN=G1,{SUB}", [sd.build_ace(EDITOR, sd.WRITE_DACL, flags=INH)]),
    ]


def test_no_propagate_source_counts_only_children() -> None:
    fs = {f.target: f for f in of(run(_np_tree()), EDITOR)}
    assert fs[OU].details["inherited_to"] == {"organizationalUnit": 1, "computer": 1}
    # Внук от NP-источника прийти не мог; выше источника нет — unknown.
    unk = [f for f in fs.values() if f.key_extra == "unknown"]
    assert len(unk) == 1 and unk[0].details["samples"] == [f"CN=G1,{SUB}"]


def test_no_propagate_grandchild_goes_higher() -> None:
    fs = {f.target: f for f in of(run(_np_tree(), root_aces=[sd.build_ace(EDITOR, sd.WRITE_DACL, flags=CI)]), EDITOR)}
    assert fs[OU].details["inherited_to"] == {"organizationalUnit": 1, "computer": 1}
    assert fs[DN].details["inherited_to"] == {"computer": 1} and fs[DN].details["samples"] == [f"CN=G1,{SUB}"]
    assert not [f for f in fs.values() if f.key_extra == "unknown"]


@pytest.mark.parametrize(("n", "expected"), [(50, 50), (51, 1)])
def test_threshold_boundary(n: int, expected: int) -> None:
    fs = of(run([comp(f"CN=M{i},OU=Mass,{DN}", [sd.build_ace(MASS, sd.WRITE_OWNER)]) for i in range(n)]), MASS)
    assert len(fs) == expected


def test_mass_group_absorbs_inherited_children() -> None:
    extra: list[dict[str, Any]] = []
    for i in range(60):
        ou = f"OU=B{i:02d},{DN}"
        extra.append(ou_obj(ou, [sd.build_ace(MASS, sd.WRITE_DACL, flags=CI)]))
        extra.append(comp(f"CN=K{i:02d},{ou}", [sd.build_ace(MASS, sd.WRITE_DACL, flags=CI | INH)]))
    fs = of(run(extra), MASS)
    assert len(fs) == 1
    f = fs[0]
    assert f.key_extra == "mass" and f.target == DN
    assert f.details["explicit_on"] == {"organizationalUnit": 60} and f.details["inherited_to"] == {"computer": 60}
    assert len(f.details["samples"]) == 20 and all(s.startswith("OU=B") for s in f.details["samples"])
