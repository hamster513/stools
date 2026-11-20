import datetime as dt
import json

import pytest

from api.modules.vm.core.host_sbom import make_bom
from api.modules.vm.core.software_match import evaluate

WINDOWS = "Windows 10 Enterprise LTSC"
GIT = {"name": "Git", "publisher": "The Git Development Community", "version": "2.40.1",
       "source": "ksc", "type": "generic"}


def test_windows_desktop_product_stays_separate_from_same_named_npm_library():
    library = dict(GIT, source="maxpatrol", type="npm", publisher="")
    docs = make_bom("1", "test", WINDOWS, [GIT, library])["components"]
    assert len(docs) == 2
    native = next(c for c in docs if c["type"] == "application")
    assert native["cpe"].startswith("cpe:2.3:a:git_for_windows_project:git_for_windows:")
    assert {"name": "stools:winget-id", "value": "Git.Git"} in native["properties"]
    assert "purl" not in native
    assert next(c for c in docs if c["type"] == "library")["purl"] == "pkg:npm/git@2.40.1"


@pytest.mark.parametrize("os_name,publisher", [("Ubuntu 22.04", GIT["publisher"]), (WINDOWS, "Another Vendor"),
                                                ("", GIT["publisher"])])
def test_identity_requires_matching_platform_and_publisher(os_name, publisher):
    row = make_bom("1", "test", os_name, [dict(GIT, publisher=publisher)])["components"][0]
    assert "cpe" not in row and "purl" not in row


@pytest.mark.parametrize("platform,expected", [("windows", "affected"), ("linux", "not_affected"),
                                               ("android", "not_affected"), ("node.js", "unknown")])
def test_nvd_checks_windows_identity_platform_and_installed_version(platform, expected):
    match = {"criteria": f"cpe:2.3:a:gitforwindows:git:*:*:*:*:*:{platform}:*:*",
             "vulnerable": True, "versionEndExcluding": "2.41.0"}
    config = [{"nodes": [{"cpeMatch": [match]}]}]
    assert evaluate(GIT, config, [GIT], WINDOWS)["state"] == expected
    assert evaluate(dict(GIT, version="2.41.0"), config, [], WINDOWS)["state"] == "not_affected"


def test_generic_native_identity_needs_distro_publisher_and_local_advisory_name():
    row = dict(GIT, name="git", publisher="Ubuntu Developers", version="1:2.43.0-1ubuntu7.3")
    def package(os_name, item, names=("git",)):
        return make_bom("1", "host", os_name, [item], native_names=set(names))["components"][0]
    assert package("Ubuntu 24.04.1 LTS", row)["purl"].startswith("pkg:deb/ubuntu/git@")
    assert "purl" not in package(WINDOWS, row)
    assert "purl" not in package("Ubuntu 24.04", dict(row, publisher="Private Vendor"))
    assert "purl" not in package("Ubuntu 24.04", row, ())


def test_generic_windows_product_requires_unique_local_index_match():
    row = dict(GIT, name="Acme Widget", publisher="Acme Corp.")
    def component(keys):
        return make_bom("1", "host", WINDOWS, [row], known_products=keys)["components"][0]
    assert component({("acme", "widget")})["cpe"] == "cpe:2.3:a:acme:widget:2.40.1:*:*:*:*:*:*:*"
    assert "cpe" not in component({("acme", "widget"), ("acme", "acme_widget")})
    assert "cpe" not in component({("another", "widget")})


def test_windows_product_corroborates_observed_ids_and_preserves_installer_variants():
    def build(*rows):
        return make_bom("1", "test", WINDOWS, rows)["components"]
    accepted = build(dict(GIT, purl="pkg:winget/Git.Git@2.40.1"))[0]
    assert accepted["cpe"] and accepted["name"] == "Git" and "purl" not in accepted
    for identifier in ("pkg:winget/Git.Git@9.9", "pkg:winget/Unrelated.Product@2.40.1", "winget:Google.Chrome"):
        assert "cpe" not in build(dict(GIT, product_id=identifier))[0]
    assert len(build(dict(GIT, arch="x86"), dict(GIT, arch="x64"))) == 2
    assert len(build(GIT, dict(GIT, source="maxpatrol"))) == 1


def test_installed_windows_release_confirms_or_excludes_an_os_prerequisite():
    def check(required):
        rows = [{"criteria": "cpe:2.3:a:gitforwindows:git:*:*:*:*:*:windows:*:*", "vulnerable": True},
                {"criteria": f"cpe:2.3:o:microsoft:{required}:*:*:*:*:*:*:*:*", "vulnerable": False}]
        return evaluate(GIT, [{"operator": "AND", "cpeMatch": rows}], [], WINDOWS)["state"]
    assert check("windows_10") == "affected"
    assert check("windows_11") == "not_affected"


def test_specific_known_host_os_refines_generic_observations():
    from api.modules.vm.core.software_identity import observed_os
    assert observed_os(["unknown", "Windows", WINDOWS]) == WINDOWS
    assert observed_os(["Linux", WINDOWS, "Debian 12"]) == "Debian 12"
    assert observed_os(["Windows 11", "Debian 12", WINDOWS]) == "Windows 11"


def test_ksc_reuses_identical_checks_without_mixing_host_prerequisites(monkeypatch):
    from api.modules.vm.services import software
    calls = 0
    def count(*args, **kwargs):
        nonlocal calls
        calls += 1
        return evaluate(*args, **kwargs)
    monkeypatch.setattr(software, "evaluate", count)
    target, runtime = ("example", "widget"), ("example", "runtime")
    rows = [{"criteria": "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*", "vulnerable": True},
            {"criteria": "cpe:2.3:a:example:runtime:*:*:*:*:*:*:*:*", "vulnerable": False,
             "versionStartIncluding": "2.0"}]
    assess = software._host_assessor({target: [("CVE-2025-1234", [{"operator": "AND", "cpeMatch": rows}])]}, True)
    fact = {"name": "Widget", "version": "1.0"}
    for host in range(100):
        versions = {("unrelated", "agent"): (("Agent", str(host)),), runtime: (("Runtime", "2.1"),)}
        assert assess((target,), fact, WINDOWS, versions)[0] == "matched"
    assert assess((target,), fact, WINDOWS, {})[0] == "unknown"
    assert assess((target,), fact, WINDOWS, {runtime: (("Runtime", "1.9"),)})[0] == "no_match"
    assert calls == 3


def test_conflicting_observed_identity_cannot_confirm_another_products_prerequisite():
    other = dict(GIT, name="Azure Data Studio", publisher="Microsoft Corporation", version="1.47.1")
    components = make_bom("1", "box", WINDOWS, [other, dict(GIT, product_id="winget:Google.Chrome")])["components"]
    program = next(c for c in components if c["name"] == other["name"])
    rows = [{"criteria": "cpe:2.3:a:microsoft:azure_data_studio:*:*:*:*:*:*:*:*", "vulnerable": True},
            {"criteria": "cpe:2.3:a:gitforwindows:git:*:*:*:*:*:*:*:*", "vulnerable": False}]
    assert evaluate(program, [{"operator": "AND", "cpeMatch": rows}], components, WINDOWS)["state"] == "unknown"


def test_nvd_component_on_existing_asset_uses_same_identity_as_ksc_and_requires_vm_access(db_session, client_as):
    from sqlalchemy import select

    from api.modules.assets.models import Asset, AssetObservation
    from api.modules.ksc.models import KscServer, KscSnapshot
    from api.modules.ksc.software_models import KscSoftware, KscSoftwareInventory
    from api.modules.vm.core.software_match import iter_products
    from api.modules.vm.models import VmRefNvd
    from api.modules.vm.sbom_models import VmPackageHost
    from api.modules.vm.services.software import rebuild_ksc
    from api.modules.vm.software_models import VmKscCve, VmNvdProduct

    db = db_session
    asset = Asset(name="observed", os=WINDOWS)
    server = KscServer(name="sbom")
    now = dt.datetime.now(dt.UTC)
    db.add_all([asset, server])
    db.flush()
    snapshot = KscSnapshot(server_id=server.id, collected_at=now, source="file")
    db.add(snapshot)
    db.flush()
    inventory = KscSoftwareInventory(snapshot_id=snapshot.id, host_id="1", host_name="observed", status="complete", os="")
    db.add(inventory)
    db.flush()
    db.add_all([
        AssetObservation(asset_id=asset.id, source="ksc", source_key=f"{server.id}:1", seen_at=now),
        AssetObservation(asset_id=asset.id, source="vm", source_key="observed|", seen_at=now),
        KscSoftware(inventory_id=inventory.id, name="Git", publisher=GIT["publisher"], version="2.40.1",
                    product_id="Git.Git", raw_json="{}"),
        VmPackageHost(kind="software", source_key="observed|", hostname="observed", ip="", os_name="",
                      packages=[dict(GIT), dict(GIT, name="Unidentified", publisher="")], changed_at=now),
    ])
    def rule(vendor, product, bound, platform, edition="*"):
        return {"vulnerable": True, "criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:{edition}:*:*:{platform}:*:*",
                "versionEndExcluding": bound}
    for number, rows in enumerate([
        [rule("git", "git", "2.41", "windows"), rule("gitforwindows", "git", "2.41", "windows")],
        [rule("git", "git", "2.40.1", "windows")],
        [rule("git", "git", "99", "linux")],
        [rule("git", "git", "2.41", "windows", "enterprise")],
    ], start=1000):
        cve = f"CVE-2025-{number}"
        cfg = [{"nodes": [{"operator": "OR", "cpeMatch": rows}]}]
        db.add(VmRefNvd(cve_id=cve, year=2025, applicability_loaded=True, configurations_json=json.dumps(cfg)))
        db.flush()
        db.add_all(VmNvdProduct(cve_id=cve, vendor=v, product=p) for v, p in iter_products(cfg))
    db.commit()

    url = f"/api/assets/assets/{asset.id}/sbom"
    viewer = client_as({"assets": "read", "vm": "read"})
    components = viewer.get(url + "/components").json()
    assert (components["total"], components["identified"], components["nvd_identified"]) == (2, 0, 1)
    git, other = components["items"]
    assert git["winget_id"] == "Git.Git" and git["sources"] == ["ksc", "maxpatrol"]
    assert git["cpe"] == viewer.get(url).json()["components"][0]["cpe"]
    assert other["cpe"] is None
    path = f"{url}/components/{git['ref']}/nvd"
    assert client_as({"assets": "read"}).get(path).status_code == 403
    assert client_as({"vm": "read"}).get(path).status_code == 403
    assert viewer.get(url + "/components/missing/nvd").status_code == 404
    page = viewer.get(path, params={"limit": 1, "offset": 1}).json()
    assert (page["ready"], page["examined"], page["affected"], page["unknown"]) == (True, 4, 1, 1)
    assert [(r["cve_id"], r["state"]) for r in page["items"]] == [("CVE-2025-1000", "affected")]
    rebuild_ksc(db, snapshot.id)
    assert set(db.execute(select(VmKscCve.cve_id, VmKscCve.state)).all()) == {
        ("CVE-2025-1000", "affected"), ("CVE-2025-1003", "unknown")}
