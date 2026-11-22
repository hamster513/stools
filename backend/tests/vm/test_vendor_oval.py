from io import BytesIO

import pytest

from api.modules.vm.core import vendor_oval as oval

DEF = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
CVE = "CVE-2020-24027"


def criterion(test, negate=False):
    return f'<criterion test_ref="oval:test:tst:{test}" negate="{str(negate).lower()}" />'


def pkg(test, name, limit=None, *, op="less than", arch="", check="all", unknown=""):
    state = f'<evr datatype="DATATYPE" operation="{op}">{limit}</evr>' if limit else ""
    if arch:
        state += f'<arch operation="equals">{arch}</arch>'
    obj = f'<PKG_object id="o{test}"><name>{name}</name></PKG_object>'
    ste = f'<PKG_state id="s{test}">{state}{unknown}</PKG_state>' if state or unknown else ""
    test_xml = (f'<PKG_test id="oval:test:tst:{test}" check="{check}" check_existence="at_least_one_exists">'
                f'<object object_ref="o{test}" />' + (f'<state state_ref="s{test}" />' if ste else "") + '</PKG_test>')
    return test_xml, obj, ste


def document(profile, criteria, packages, *, ids=(CVE,), product="demo", bulletin=True, platform=None):
    redos = profile.startswith("redos")
    platform = platform or {"redos-7.3": "RED OS 7.3", "redos-8": "RED OS 8.0"}.get(
        profile, "Astra Linux " + profile.split("-")[1])
    vendor = ('<reference source="ROS" ref_id="ROS-20211223-07" '
              'ref_url="https://redos.red-soft.ru/support/secure/uyazvimosti/busybox/" />') if redos else (
        '<reference source="VENDOR" ref_id="№ 2024-0905SE18MD" '
        'ref_url="https://wiki.astralinux.ru/astra-linux-se18-bulletin-2024-0905SE18MD" />')
    refs = "".join(f'<reference source="CVE" ref_id="{c}" />' for c in ids)
    def section(name, values):
        namespaced = "".join(values).replace(' id=', f' xmlns="{DEF}#linux" id=')
        return f'<{name}>{namespaced}</{name}>'

    sections = "".join(section(name, values) for name, values in zip(("tests", "objects", "states"),
                                                                      zip(*packages), strict=True))
    xml = f'''<oval_definitions xmlns="{DEF}"><definitions>
      <definition id="oval:vendor:def:1" class="vulnerability"><metadata>
      <affected family="unix"><platform>{platform}</platform><product>{product}</product></affected>
      {vendor if bulletin else ""}{refs}</metadata>{criteria}</definition>
      </definitions>{sections}</oval_definitions>'''
    xml = xml.replace("PKG_", "rpminfo_" if redos else "dpkginfo_")
    return xml.replace("DATATYPE", "evr_string" if redos else "debian_evr_string").encode()


def compile_xml(profile, criteria, packages, **kwargs):
    return oval.compile_oval(BytesIO(document(profile, criteria, packages, **kwargs)), profile)


def target(name, version, arch=""):
    return {"name": name, "version": version, "arch": arch}


def test_redos_release_and_full_binary_evr_boundaries():
    tree = '<criteria operator="OR">' + criterion(1) + "</criteria>"
    index = compile_xml("redos-7.3", tree, [pkg(1, "busybox", "1:1.34.1-1.el7.3")], product="busybox")
    vulnerable = target("busybox", "1.34.1-0.el7.3") | {"epoch": 1}
    matched = index.match(CVE, vulnerable, os_version="7.3.7")
    assert matched == {"definition_id": "oval:vendor:def:1", "bulletin": "ROS-20211223-07",
                       "bulletin_url": "https://redos.red-soft.ru/support/secure/uyazvimosti/busybox/",
                       "package": "busybox", "installed_version": "1:1.34.1-0.el7.3",
                       "fixed_version": "1:1.34.1-1.el7.3"}
    for row in [target("busybox", "1:1.34.1-1.el7.3"), target("busybox", "2:1.1-1"),
                target("busybox", "1:1.34.1"), target("unrelated", "1.0-0"),
                vulnerable | {"version": "2:1.2-1"}]:
        assert index.match(CVE, row, os_version="7.3") is None
    assert index.match(CVE, vulnerable, os_version="8.0") is None
    assert index.match("CVE-2040-12345", vulnerable, os_version="7.3") is None


def test_redos_disjoint_branches_require_both_range_tests_on_exact_binary():
    tree = ('<criteria operator="OR"><criteria operator="AND">' + criterion(1) + criterion(2)
            + "</criteria>" + criterion(3) + "</criteria>")
    packages = [pkg(1, "php", "0:8.1.34-1.red80"), pkg(2, "php", "0:8.1.24-1.red80",
                                                        op="greater than or equal"),
                pkg(3, "php-cli", "0:8.1.34-1.red80")]
    index = compile_xml("redos-8", tree, packages, product="php")
    cli = target("php-cli", "8.1.20-1.red80")
    for version, expected in [("8.1.23-9.red80", False), ("8.1.24-1.red80", True),
                              ("8.1.30-1.red80", True), ("8.1.34-1.red80", False)]:
        row = target("php", version)
        proof = index.match(CVE, row, oval.package_inventory([cli, row]), os_version="8")
        assert bool(proof) == expected
        if proof:
            assert proof["fixed_version"] == "0:8.1.34-1.red80"
    assert not index.match(CVE, cli, os_version="8.1.2")


def test_branch_encoded_ros_bulletin_ids_and_vendor_url_identifiers():
    tree = "<criteria>" + criterion(1) + "</criteria>"
    packages = [pkg(1, "demo", "1:2-5")]
    redos = document("redos-8", tree, packages)
    code = b"ROS-20251216-80-0006"
    redos = redos.replace(b"ROS-20211223-07", code)
    row = target("demo", "1:2-4", "amd64")
    assert oval.compile_oval(BytesIO(redos), "redos-8").match(CVE, row, os_version="8")["bulletin"] == code.decode()
    wrong_branch = redos.replace(code, b"ROS-20251216-73-0006")
    assert not oval.compile_oval(BytesIO(wrong_branch), "redos-8").has_bulletins
    astra = document("astra-1.8", tree, packages).replace("№ 2024-0905SE18MD".encode(), b"1.8.3")
    proof = oval.compile_oval(BytesIO(astra), "astra-1.8").match(CVE, row, os_version="1.8")
    assert proof["bulletin"] == "2024-0905SE18MD"


def test_only_strict_vendor_upper_bounds_supply_a_fix():
    row = target("demo", "1-1")
    for op in ("less than or equal", "equals", "greater than or equal"):
        index = compile_xml("redos-8", "<criteria>" + criterion(1) + "</criteria>", [pkg(1, "demo", "1-1", op=op)])
        assert index.match(CVE, row, os_version="8")["fixed_version"] == ""
    tree = '<criteria operator="OR">' + criterion(1) + criterion(2) + "</criteria>"
    index = compile_xml("redos-8", tree, [pkg(1, "demo", "2-0"), pkg(2, "demo", "3-0", op="less than or equal")])
    assert index.match(CVE, row, os_version="8")["fixed_version"] == ""
    tree = ('<criteria operator="OR">' + criterion(1) + '<criteria operator="AND">'
            + criterion(2) + criterion(3) + "</criteria></criteria>")
    index = compile_xml("redos-8", tree, [pkg(1, "demo", "2-0"), pkg(2, "demo", "2-0", op="greater than or equal"),
                                         pkg(3, "demo", "3-0")])
    assert index.match(CVE, row, os_version="8")["fixed_version"] == ""


def test_astra_formal_reference_binary_name_architecture_and_roundtrip():
    tree = '<criteria operator="OR">' + criterion(1) + criterion(2) + "</criteria>"
    packages = [pkg(1, "libgroupsock", "0:2024.06.26-1"), pkg(2, "liblivemedia77", "0:2024.06.26-1")]
    index = compile_xml("astra-1.8", tree, packages, product="liblivemedia")
    data = BytesIO()
    oval.dump_index(index, data)
    data.seek(0)
    restored = oval.read_index(data, "astra-1.8")
    installed = target("liblivemedia77", "2024.06.26-1~astra1", "amd64")
    for idx in (index, restored):
        proof = idx.match(CVE, installed, os_version="1.8.4")
        assert idx.has_bulletins and proof["bulletin"] == "№ 2024-0905SE18MD"
        assert proof["fixed_version"] == "0:2024.06.26-1"
        assert not idx.match(CVE, installed, os_version="1.7.8")
        assert not idx.match(CVE, installed, os_version="1.8", host_arch="s390x")
        assert not idx.match(CVE, installed | {"arch": "arm64"}, os_version="1.8", host_arch="x86_64")
        assert not idx.match(CVE, installed | {"arch": "all"}, os_version="1.8")
        assert idx.match(CVE, installed | {"arch": "all"}, os_version="1.8", host_arch="x86_64")
        assert not idx.match(CVE, target("liblivemedia", "1.1", "amd64"), os_version="1.8")
        assert not idx.match(CVE, installed | {"version": "2024.06.26-1+astra1"}, os_version="1.8")
    data.seek(0)
    with pytest.raises(ValueError):
        oval.read_index(data, "astra-4.8")


def test_no_formal_vendor_bulletin_no_id_or_ambiguous_aggregate():
    tree = "<criteria>" + criterion(1) + "</criteria>"
    pkgs = [pkg(1, "busybox", "1:2-5")]
    row = target("busybox", "1:2-4")
    for options in [{"bulletin": False}, {"ids": ()}, {"ids": (CVE, "CVE-2022-1111")}]:
        index = compile_xml("redos-7.3", tree, pkgs, **options)
        assert not index.has_bulletins
        assert index.match(CVE, row, os_version="7.3") is None
    with pytest.raises(ValueError, match="mismatched platform"):
        compile_xml("redos-8", tree, pkgs, platform="RED OS 7.3")


def test_partial_sibling_inventory_unknown_tests_negation_and_arch():
    row = target("demo", "1.2-3", "x86_64")
    installed = target("gate", "1-1")
    has = criterion(2)
    conditions = [pkg(1, "demo", "2-1", arch="x86_64"), pkg(2, "gate"), pkg(3, "other", "9-1")]
    inv = oval.package_inventory([row, installed, installed])
    assert len(inv["gate"]) == 1
    def match(other, inventory=inv, candidate=row):
        tree = '<criteria operator="AND">' + criterion(1) + other + "</criteria>"
        return compile_xml("redos-8", tree, conditions).match(CVE, candidate, inventory, os_version="8.0.3")
    assert match(has)["fixed_version"] == "2-1"
    assert not match(has, oval.package_inventory([row]))
    assert not match(criterion(2, negate=True), oval.package_inventory([row]))
    assert not match(criterion(2, negate=True))
    assert not match(criterion(999))
    assert not match(criterion(999, negate=True))
    assert not match(has, inv, row | {"arch": ""})
    assert not match(has, inv, row | {"arch": "aarch64"})
    assert not match(has + criterion(3), oval.package_inventory([row, installed, target("other", "4-1")]),
                     target("other", "4-1"))
    tree = "<criteria>" + criterion(1, negate=True) + "</criteria>"
    index = compile_xml("redos-8", tree, [pkg(1, "demo", "2-1", op="greater than or equal")])
    assert index.match(CVE, row, os_version="8")["fixed_version"] == "2-1"


def test_same_name_siblings_cannot_supply_other_versions_condition():
    rows = [target("demo", "1-0", "amd64"), target("demo", "4-0", "arm64")]
    inv = oval.package_inventory(rows)
    tree = "<criteria>" + criterion(1) + criterion(2) + "</criteria>"
    tests = [pkg(1, "demo", "2-0", op="greater than or equal", check="at least one"),
             pkg(2, "demo", "3-0", check="at least one")]
    index = compile_xml("redos-8", tree, tests)
    assert all(not index.match(CVE, row, inv, os_version="8") for row in rows)
    only = compile_xml("redos-8", "<criteria>" + criterion(2) + "</criteria>", [pkg(2, "demo", "3-0")])
    assert not only.match(CVE, rows[0], inv, os_version="8")  # check=all includes the fixed sibling


def test_unsupported_fields_and_branch_scoping_fail_closed():
    tree = "<criteria>" + criterion(1) + "</criteria>"
    pkgs = [pkg(1, "demo", "2-1", unknown='<signature_keyid>missing</signature_keyid>')]
    index = compile_xml("redos-8", tree, pkgs)
    row = target("demo", "1.5-1")
    assert not index.match(CVE, row, os_version="8")
    partial = compile_xml("redos-8", tree, [pkg(1, "demo", "2-1")], platform="RED OS 8.0.4")
    assert not partial.match(CVE, row, os_version="8.0.3")
    assert not partial.match(CVE, row, os_version="8")
    assert partial.match(CVE, row, os_version="8.0.4")


@pytest.mark.parametrize(("kind", "lower", "higher"), [
    ("deb", "1:2.0-19+deb10u9", "1:2.0-19+deb10u10"),
    ("deb", "2.0-1~rc1", "2.0-1"), ("deb", "1.9+1~astra1", "1.9+a"),
    ("deb", "0:9.9-100", "1:0.1"), ("deb", "1.0a", "1.0+"),
    ("deb", "1.0-1-astra1", "1.0-2-astra1"),
    ("rpm", "2.1~rc2-1", "2.1-1"), ("rpm", "2.1-1", "2.1^git4-1"),
    ("rpm", "2.1^git4-1", "2.1.1-1"), ("rpm", "1.0-2.el7", "1.0-10.el7"),
    ("rpm", "0:999-1", "1:1-1"), ("rpm", "1.0a-1", "1.0.1-1"),
])
def test_native_comparison_order(kind, lower, higher):
    assert oval._compare_evr(kind, lower, higher) == -1
    assert oval._compare_evr(kind, higher, lower) == 1
    assert oval._compare_evr(kind, lower, lower) == 0


def test_zero_epoch_native_revision_and_separator_equivalence():
    assert oval._compare_evr("deb", "0:1.01", "1.1-0") == 0
    assert oval._compare_evr("rpm", "01:1.002-2+el7", "1:1.2-2.el07") == 0
    assert oval._compare_evr("rpm", "1.2", "1.2-7.el7") is None
    assert oval._compare_evr("rpm", "1.2", "2.0-7.el7") < 0
    assert oval._compare_evr("rpm", "1:???", "1.0-1") is None


def test_bounded_xml_rejects_doctypes_and_corrupt_index(monkeypatch):
    tree = "<criteria>" + criterion(1) + "</criteria>"
    xml = document("redos-8", tree, [pkg(1, "demo", "2-1")])
    with pytest.raises(ValueError, match="Invalid OVAL"):
        oval.compile_oval(BytesIO(b'<!DOCTYPE oval_definitions [<!ENTITY one "A">]>' + xml), "redos-8")
    with pytest.raises(ValueError, match="Malformed OVAL XML"):
        oval.compile_oval(BytesIO(xml[:-10]), "redos-8")
    monkeypatch.setattr(oval, "_XML_LIMIT", 100)
    with pytest.raises(ValueError, match="size limit"):
        oval.compile_oval(BytesIO(xml), "redos-8")
    malformed = b'{"format":1,"profile":"redos-8","tests":[],"rules":[-1],"definitions":{}}'
    with pytest.raises(ValueError, match="Invalid OVAL rule"):
        oval.read_index(BytesIO(malformed), "redos-8")
