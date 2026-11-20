import json
import os
import sys
from pathlib import Path

import pytest

from api.modules.vm.core.host_sbom import make_bom
from api.modules.vm.services.trivy_scan import ScanError, database_revision, scan_bom


def observed(name, version="", kind="generic", source="maxpatrol", **kwargs):
    return dict(name=name, version=version, type=kind, source=source, **kwargs)


def props(component, name):
    return [p["value"] for p in component["properties"] if p["name"] == name]


def test_bom_is_stable_and_uses_only_inventory_fields():
    native = observed("libssl3", "3.0.11-1~deb12u1", "os", arch="amd64",
                      source_name="openssl", source_version="3.0.11-1~deb12u1")
    records = [native, observed("libssl3", native["version"], source="ksc"),
               observed("Private Agent", source="ksc", publisher="Internal",
                        cve="private-vm-payload", raw="private-source-payload")]
    a = make_bom("asset-42", "lab", "Debian GNU/Linux 12 (bookworm)", records)
    assert a == make_bom("asset-42", "lab", "Debian GNU/Linux 12 (bookworm)", reversed(records))
    assert (a["bomFormat"], a["specVersion"], a["version"]) == ("CycloneDX", "1.6", 1)
    assert "private-source-payload" not in str(a) and "private-vm-payload" not in str(a)
    os_component = a["metadata"]["component"]
    assert (os_component["type"], os_component["name"], os_component["version"]) == (
        "operating-system", "debian", "12")
    assert len(a["components"]) == 2
    by_name = {pkg["name"]: pkg for pkg in a["components"]}
    lib = by_name["libssl3"]
    assert lib["purl"] == "pkg:deb/debian/libssl3@3.0.11-1~deb12u1?arch=amd64&distro=debian-12"
    assert sorted(props(lib, "stools:source")) == ["ksc", "maxpatrol"]
    assert props(lib, "aquasecurity:trivy:SrcName") == ["openssl"]
    assert props(lib, "aquasecurity:trivy:SrcVersion") == ["3.0.11"]
    assert props(lib, "aquasecurity:trivy:SrcRelease") == ["1~deb12u1"]
    generic = by_name["Private Agent"]
    assert generic["publisher"] == "Internal"
    assert "version" not in generic and props(generic, "stools:unassessed-reason")


def test_dedup_respects_ecosystem_version_architecture_and_publisher():
    records = [observed("foo", "1", "pypi"), observed("foo", "1", "npm"),
               observed("foo", "1", source="ksc"), observed("foo", "2", "npm"),
               observed("bar", "1", "os", arch="amd64"), observed("bar", "1", "os", arch="i386"),
               observed("bar", "1", source="ksc"), observed("App", "1", publisher="X"),
               observed("App", "1", source="ksc", publisher="Y")]
    bom = make_bom("key", "lab", "Ubuntu 22.04 LTS", records)
    assert len({c["bom-ref"] for c in bom["components"]}) == len(records)
    assert len(bom["components"]) == len(records)


@pytest.mark.parametrize(("os_name", "kind", "expected"), [
    ("Red Hat Enterprise Linux Server release 8.10", "os", "pkg:rpm/redhat/"),
    ("Alpine Linux v3.20.2", "os", "pkg:apk/alpine/"),
    ("Microsoft Windows Server 2019", "generic", None),
    ("Debian GNU/Linux 12", "generic", None),
    ("Astra Linux 1.7 (Debian 10)", "os", None),
    ("Debian", "os", None),
])
def test_native_identity_requires_observed_supported_distribution(os_name, kind, expected):
    pkg = make_bom("key", "lab", os_name, [observed("example", "1.2", kind)])["components"][0]
    if expected:
        assert pkg["purl"].startswith(expected) and not props(pkg, "stools:unassessed-reason")
    else:
        assert props(pkg, "stools:unassessed-reason")


def test_supplied_package_and_embedded_epoch_survive_round_trip():
    records = [observed("flask", "", purl="pkg:pypi/flask@1.0"),
               observed("example", "2:1.3-4.el9", "rpm", source_name="example-src",
                        source_version="1:1.2-3.el9", os_name="Rocky Linux 9")]
    bom = make_bom("key", "lab", "", records)
    assert bom["metadata"]["component"]["name"] == "rocky"
    pkgs = {c["name"]: c for c in bom["components"]}
    assert pkgs["flask"]["version"] == "1.0"
    rpm = pkgs["example"]
    assert "epoch=2" in rpm["purl"] and rpm["version"] == "2:1.3-4.el9"
    assert props(rpm, "aquasecurity:trivy:SrcEpoch") == ["1"]
    assert props(rpm, "aquasecurity:trivy:SrcRelease") == ["3.el9"]


def test_incompatible_purl_is_exported_as_evidence_and_scan_input_is_the_download(tmp_path, monkeypatch):
    from api.modules.vm.services import trivy_scan

    foreign = "pkg:rpm/redhat/curl@7.1?distro=redhat-9"
    bom = make_bom("id", "host", "Debian 12", [
        observed("curl", "7.1", purl=foreign), observed("lodash", "4.17.20", "npm"),
    ])
    rpm = next(c for c in bom["components"] if c["name"] == "curl")
    assert "purl" not in rpm and props(rpm, "stools:observed-purl") == [foreign]
    scanned = []

    def observe(args, directory, timeout, limit):
        scanned.append(json.loads(Path(args[-1]).read_text()))
        return {"SchemaVersion": 2, "ArtifactType": "cyclonedx", "Results": []}

    monkeypatch.setattr(trivy_scan, "_context", lambda _: ("trivy", tmp_path, "0.76.2", "db"))
    monkeypatch.setattr(trivy_scan, "_run_json", observe)
    scan_bom(bom, tmp_path)
    assert scanned == [bom]


def test_can_use_distribution_attested_by_purl_without_guessing_kernel_or_derivatives():
    explicit = "pkg:deb/debian/curl@7.1?distro=debian-12"
    for host_os in ("Linux", "Debian GNU/Linux"):
        bom = make_bom("id", "test", host_os, [observed("curl", "7.1", purl=explicit)])
        assert bom["metadata"]["component"].get("version") == "12"
        assert bom["components"][0]["purl"] == explicit
    bom = make_bom("id", "test", "Debian 12", [
        observed("curl", "7.1", "os", os_name="Astra Linux Special Edition 1.7"),
    ])
    native = bom["components"][0]
    assert props(native, "stools:unassessed-reason")
    assert props(native, "stools:package-type") == ["os"] and not props(native, "stools:observed-purl")


def test_native_without_publisher_cannot_disambiguate_two_conflicting_display_vendors():
    pkgs = [observed("curl", "1", "os"), observed("curl", "1", source="ksc", publisher="A"),
            observed("curl", "1", source="ksc", publisher="B")]
    bom = make_bom("id", "test", "Debian 12", pkgs)
    assert len(bom["components"]) == 3
    typed = next(c for c in bom["components"] if c.get("purl"))
    assert props(typed, "stools:source") == ["maxpatrol"]


def test_purl_and_observed_identifiers_must_agree_and_never_duplicate_an_epoch():
    records = [
        observed("rpm-app", "2:1.0-3", purl="pkg:rpm/rocky/rpm-app@1.0-3?epoch=3"),
        observed("other", "1", arch="i386", purl="pkg:rpm/rocky/other@1?arch=x86_64"),
        observed("third", "", purl="pkg:rpm/rocky/third@2%3A1.0-3"),
    ]
    components = {c["name"]: c for c in make_bom("key", "lab", "Rocky Linux 9", records)["components"]}
    for name in ("rpm-app", "other"):
        assert "purl" not in components[name] and props(components[name], "stools:unassessed-reason")
    assert components["third"]["version"] == "2:1.0-3"
    assert components["third"]["purl"] == "pkg:rpm/rocky/third@1.0-3?distro=rocky-9&epoch=2"


def test_unavailable_database_is_an_error_and_does_not_disclose_inventory(tmp_path, monkeypatch):
    from api.modules.vm.services import trivy_scan

    monkeypatch.setattr(trivy_scan, "_BUNDLED_CACHE", tmp_path / "bundled")
    bom = make_bom("internal-host", "private-display", "", [observed("private-app")])
    assert database_revision(tmp_path) == ""
    with pytest.raises(ScanError) as error:
        scan_bom(bom, tmp_path)
    assert all(name not in str(error.value) for name in ("internal-host", "private-display", "private-app"))


@pytest.mark.parametrize("program", [
    "print('{}')",
    "print('{\"SchemaVersion\":2,\"ArtifactType\":\"cyclonedx\"}')",
    "print('x' * 20000)",
    "sys.stderr.write('private-app'); sys.exit(3)",
    "import time; time.sleep(3)",
])
def test_failed_incomplete_oversized_and_timed_out_reports_are_errors(tmp_path, monkeypatch, program):
    from api.modules.vm.services import trivy_scan

    db = tmp_path / "trivy" / "db"
    db.mkdir(parents=True)
    (db / "metadata.json").write_text('{"Version":2,"UpdatedAt":"2025-04-01T00:00:00Z"}')
    (db / "trivy.db").write_bytes(b"x")
    executable = tmp_path / "trivy-test"
    executable.write_text(f"#!{sys.executable}\nimport sys\n"
                          "if 'version' in sys.argv:\n"
                          "    print('{\"Version\":\"0.76.2\"}')\n"
                          f"else:\n    {program}\n")
    executable.chmod(0o700)
    monkeypatch.setattr(trivy_scan.shutil, "which", lambda name: str(executable))
    monkeypatch.setattr(trivy_scan, "_MAX_REPORT_BYTES", 4096)
    monkeypatch.setattr(trivy_scan, "_SCAN_TIMEOUT", 0.3)
    bom = make_bom("id", "test-host", "", [observed("private-app", "1", "npm")])
    with pytest.raises(ScanError) as error:
        scan_bom(bom, tmp_path)
    assert "private-app" not in str(error.value)


@pytest.mark.skipif(not os.environ.get("STOOLS_TEST_TRIVY_DATA"),
                    reason="requires a provisioned official Trivy cache and binary")
def test_offline_real_trivy_detects_known_advisory_and_counts_covered_packages():
    data_dir = Path(os.environ["STOOLS_TEST_TRIVY_DATA"])
    bom = make_bom("lab-id", "synthetic-host", "Debian GNU/Linux 12 (bookworm)", [
        observed("lodash", "4.17.20", "npm"),
        observed("libssl3", "3.0.11-1~deb12u1", "os",
                 source_name="openssl", source_version="3.0.11-1~deb12u1"),
        observed("Private Windows Agent", "9", source="ksc"),
        observed("foreign", "1", purl="pkg:rpm/redhat/foreign@1?distro=redhat-9"),
    ])
    result = scan_bom(bom, data_dir)
    assert result["checked"] == 2
    findings = result["findings"]
    assert any(f["vuln_id"] == "CVE-2021-23337" and f["package"] == "lodash"
               and f["installed_version"] == "4.17.20" and f["fixed_version"]
               and f["severity"] and f["purl"] == "pkg:npm/lodash@4.17.20" for f in findings)
    assert any(f["package"] == "libssl3" and f["vuln_id"].startswith("CVE-") for f in findings)
    assert result["db_version"] == database_revision(data_dir) and result["scanner_version"]
    empty = make_bom("lab-id", "synthetic-host", "Windows 11", [observed("Private Agent", "1")])
    assert scan_bom(empty, data_dir)["checked"] == 0


@pytest.mark.skipif(not os.environ.get("STOOLS_TEST_TRIVY_DATA"),
                    reason="requires a provisioned official Trivy cache and binary")
@pytest.mark.parametrize(("os_name", "name", "version", "arch"), [
    ("Rocky Linux 9.0", "openssl-libs", "1:3.0.7-1.el9", "x86_64"),
    ("Alpine Linux 3.20.0", "libcrypto3", "3.3.0-r0", "x86_64"),
])
def test_offline_real_rpm_and_apk_scan(os_name, name, version, arch):
    bom = make_bom("synthetic", "lab", os_name, [
        observed(name, version, "os", arch=arch, source_name="openssl", source_version=version)
    ])
    result = scan_bom(bom, Path(os.environ["STOOLS_TEST_TRIVY_DATA"]))
    assert result["checked"] == 1
    assert any(f["vuln_id"] == "CVE-2024-12797" and f["package"] == name
               and f["installed_version"] == version for f in result["findings"])
