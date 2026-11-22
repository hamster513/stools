from copy import deepcopy

import pytest

from api.modules.vm.core.host_sbom import make_bom
from api.modules.vm.core.vendor_profiles import observed_arch, scan_document, upstream_profile
from api.modules.vm.services import trivy_scan


@pytest.mark.parametrize(("family", "release", "expected"), [
    ("redos", "7.3.7", ("RHEL 7", "redos-7.3")), ("redos", "8.0.2", ("RHEL 8", "redos-8")),
    ("astra", "1.6", ("Debian 9", "astra-1.6")), ("astra", "1.7.6", ("Debian 10", "astra-1.7")),
    ("astra", "1.8.4", ("Debian 12", "astra-1.8")), ("astra", "4.8", ("Debian 12", "astra-4.8")),
    ("astra", "2.12", ("Debian 9", "astra-2.12")), ("astra", "1.9", None),
    ("redos", "9", None), ("linux", "7", None), ("astra", "", None),
])
def test_candidate_profile_requires_known_os_and_release(family, release, expected):
    profile = upstream_profile(family, release)
    assert ((profile.label, profile.feed) if profile else None) == expected


def test_astra_uses_observed_release_and_preserves_identity_in_the_download():
    rows = [{"name": "libssl3", "version": "3.0.1-1+astra1", "type": "os", "source": "maxpatrol",
                 "os_name": "Astra Linux", "source_name": "openssl", "source_version": "3.0.1-1+astra1"}]
    doc = make_bom("1", "lab", "Astra Linux", rows, os_hints=["Astra Linux SE 1.8.4_x86-64"])
    original = deepcopy(doc)
    profile = upstream_profile("astra", "1.8.4")
    projected, native = scan_document(doc, profile)
    ref = doc["components"][0]["bom-ref"]
    assert doc == original and doc["metadata"]["component"]["version"] == "1.8.4"
    assert native[ref]["purl"] == doc["components"][0]["purl"] and "/astra/" in native[ref]["purl"]
    assert native[ref]["source_name"] == "openssl" and observed_arch(doc) == "x86_64"
    assert projected["components"][0]["bom-ref"] == ref and "distro=debian-12" in projected["components"][0]["purl"]
    assert projected["metadata"]["component"]["version"] == "12"
    ambiguous = make_bom("1", "lab", "Astra Linux", rows, os_hints=["Astra Linux 1.8", "Astra Linux 1.7"])
    assert ambiguous["metadata"]["component"]["type"] == "platform" and "purl" not in ambiguous["components"][0]


@pytest.mark.parametrize("available", [True, False])
def test_only_exact_vendor_proof_can_supply_the_hosts_fixed_version(tmp_path, monkeypatch, available):
    doc = make_bom("1", "lab", "RED OS 7.3.7", [
        {"name": name, "version": "0:2.3-1.el7", "source": "maxpatrol", "type": "os"} for name in ("alpha", "beta")])
    cve = "CVE-2024-12880"
    def scan(projected, cache, *, retain_refs):
        assert retain_refs and projected["metadata"]["component"]["name"] == "redhat"
        return {"db_version": "Trivy DB", "checked": 2, "findings": [
            {"vuln_id": cve, "package": c["name"], "bom_ref": c["bom-ref"], "purl": c["purl"],
             "fixed_version": "2.8-4.rhel", "severity": "high"} for c in projected["components"]]}

    class Index:
        has_bulletins = True

        def match(self, vid, pkg, inventory, *, os_version, host_arch):
            assert set(inventory) == {"alpha", "beta"} and vid == cve and os_version == "7.3.7"
            if pkg["name"] == "alpha":
                return {"definition_id": "oval:example:def:1", "bulletin": "ROS-2024-1",
                            "bulletin_url": "https://redos.red-soft.ru/support/", "fixed_version": "2.3-2.redos"}

    monkeypatch.setattr(trivy_scan, "scan_cached", scan)
    monkeypatch.setattr(trivy_scan.vendor_bulletins, "load_index", lambda path, profile: Index() if available else None)
    monkeypatch.setattr(trivy_scan.vendor_bulletins, "vendor_revision", lambda path: "feed42" if available else "")
    scan = trivy_scan.scan_bom(doc, tmp_path)
    assert scan["db_version"] == trivy_scan.expected_revision(doc, "Trivy DB", tmp_path)
    assert scan["vendor_summary"]["confirmed"] == int(available) and scan["vendor_summary"]["candidates"] == 1
    alpha, beta = scan["findings"]
    assert all("/redos/" in r["purl"] and r["installed_version"] == "0:2.3-1.el7" for r in (alpha, beta))
    assert beta["assessment"] == "candidate" and not beta["fixed_version"] and beta["upstream_fixed_version"] == "2.8-4.rhel"
    assert alpha["assessment"] == ("vendor_confirmed" if available else "candidate")
    assert alpha["fixed_version"] == ("2.3-2.redos" if available else "")
