"""Host package snapshots and independent comparison with MaxPatrol findings."""

import datetime as dt

from sqlalchemy import select

from api.modules.assets.models import Asset, AssetObservation
from api.modules.vm.models import VmCve, VmHost, VmHostCve, VmImport
from api.modules.vm.services.settings import Connection


class PackageExport:
    fail_software = False

    def export_csv(self, query, path):
        assert "Vulners" not in query and "limit(0)" in query
        if "UnixHost.Packages.Name" in query:
            path.write_text(
                "@UnixHost;UnixHost.OsName;UnixHost.Packages.Name;UnixHost.Packages.Version\n"
                "box (10.0.0.2);Debian GNU/Linux 12;openssl;3.0.11-1~deb12u1\n"
                "box (10.0.0.2);Debian GNU/Linux 12;openssl;3.0.11-1~deb12u1\n"
                "other (10.0.0.3);Debian GNU/Linux 12;curl;7.1\n",
                encoding="utf-8",
            )
        else:
            assert "Host.Softs.Name" in query
            path.write_text(
                "truncated"
                if self.fail_software
                else "@Host;Host.OsName;Host.Softs.Name;Host.Softs.Version;Host.Softs.Vendor\n"
                "win (10.0.0.4);Windows Server 2019;Example App;3.1;Example Vendor\n",
                encoding="utf-8",
            )


def test_packages_collected_without_cve_and_incomplete_family_keeps_previous(db_session, tmp_path):
    from api.modules.assets.services.sync import observations_from_vm
    from api.modules.vm.sbom_models import VmPackageFeed, VmPackageHost
    from api.modules.vm.services.host_packages import collect_packages

    client = PackageExport()
    conn = Connection(host="unit.test", api_token="test", limit=0)
    assert collect_packages(db_session, client, conn, tmp_path)
    box = db_session.get(VmPackageHost, ("unix", "box|10.0.0.2"))
    assert len(box.packages) == 1 and box.packages[0]["version"] == "3.0.11-1~deb12u1"
    assert {row.source_key for row in observations_from_vm(db_session)} == {
        "box|10.0.0.2",
        "other|10.0.0.3",
        "win|10.0.0.4",
    }
    changed = box.changed_at
    client.fail_software = True
    assert collect_packages(db_session, client, conn, tmp_path)
    assert db_session.get(VmPackageHost, ("unix", box.source_key)).changed_at == changed
    assert db_session.get(VmPackageHost, ("software", "win|10.0.0.4"))
    assert db_session.get(VmPackageFeed, "software").error
    assert not collect_packages(db_session, client, conn.model_copy(update={"limit": 1}), tmp_path)
    assert db_session.get(VmPackageHost, ("unix", box.source_key))


def test_host_download_and_three_way_comparison(db_session, client_as, tmp_path, monkeypatch):
    from api.modules.vm.ghsa_models import VmRefGhsa, VmRefGhsaAlias
    from api.modules.vm.services import host_sbom as service
    from api.modules.vm.services.host_packages import collect_packages

    db = db_session
    assert collect_packages(
        db, PackageExport(), Connection(host="unit.test", api_token="test", limit=0), tmp_path
    )
    asset = Asset(name="box", os="Debian GNU/Linux 12")
    db.add(asset)
    db.flush()
    now = dt.datetime.now(dt.UTC)
    db.add(
        AssetObservation(
            asset_id=asset.id, source="vm", source_key="box|10.0.0.2", name="box", seen_at=now
        )
    )
    vm = VmHost(hostname="box", ip="10.0.0.2")
    db.add_all(
        [
            vm,
            VmCve(cve_id="CVE-2024-1111"),
            VmCve(cve_id="CVE-2024-2222"),
            VmRefGhsa(ghsa_id="GHSA-2345-2345-2345"),
            VmImport(finished_at=now, source="vm", hosts=1, pairs=2, cves=2),
        ]
    )
    db.flush()
    db.add(VmRefGhsaAlias(ghsa_id="GHSA-2345-2345-2345", alias="CVE-2024-1111"))
    db.add_all(
        [
            VmHostCve(host_id=vm.id, cve_id="CVE-2024-1111"),
            VmHostCve(host_id=vm.id, cve_id="CVE-2024-2222"),
        ]
    )
    db.commit()
    url = f"/api/assets/assets/{asset.id}/sbom"
    viewer = client_as({"assets": "read", "vm": "read"})
    response = viewer.get(url)
    assert response.status_code == 200 and "attachment" in response.headers["Content-Disposition"]
    bom = response.json()
    assert bom["bomFormat"] == "CycloneDX"
    assert [c["name"] for c in bom["components"]] == ["openssl"]
    assert "CVE-2024" not in response.text
    assert client_as({"assets": "read"}).get(url + "/comparison").status_code == 403
    assert viewer.post(url + "/scan").status_code == 403
    calls = []

    def scan(document, directory):
        calls.append(document)
        return {
            "checked": 1,
            "findings": [
                {
                    "vuln_id": identifier,
                    "package": "openssl",
                    "installed_version": "3.0.11",
                    "fixed_version": "3.0.16",
                    "severity": "HIGH",
                    "purl": "",
                }
                for identifier in ["GHSA-2345-2345-2345", "CVE-2024-1111", "CVE-2024-3333"]
            ],
            "db_version": "test-v1",
            "scanner_version": "unit",
        }

    monkeypatch.setattr(service.trivy_scan, "scan_bom", scan)
    monkeypatch.setattr(service.trivy_scan, "database_revision", lambda _: "test-v1")
    service.refresh_queue(db, tmp_path)
    assert service.process_next(db, tmp_path)
    assert calls == [bom]
    result = viewer.get(url + "/comparison").json()
    assert result["counts"] == {"both": 1, "trivy_only": 1, "vm_only": 1}
    assert result["checked"] == 1 and result["status"] == "ready"
    assert (
        viewer.get(url + "/comparison", params={"group": "vm_only"}).json()["items"][0]["id"]
        == "CVE-2024-2222"
    )
    assert not service.process_next(db, tmp_path)
    writer = client_as({"assets": "write", "vm": "read"})
    assert writer.post(url + "/scan").status_code == 202

    def fail(doc, directory):
        raise ValueError("Сканер недоступен")

    monkeypatch.setattr(service.trivy_scan, "scan_bom", fail)
    assert service.process_next(db, tmp_path)
    result = viewer.get(url + "/comparison").json()
    assert result["status"] == "error" and result["scan_at"] and result["counts"] is None
    assert any(row["group"] == "trivy_uncompared" for row in result["items"])


def test_scoped_inventory_uses_a_host_group_before_joining_packages():
    from api.modules.vm.services.host_packages import package_pdql

    conn = Connection(
        host="unit.test", api_token="test", pdql_extra="Host.UF_Zone = 'DMZ'", limit=0
    )
    query = package_pdql(conn, "unix")
    assert "join(" in query and "group(@Host" in query and "Scope." in query
    assert "Host.UF_Zone = 'DMZ'" in query
    assert "Vulners" not in query


def test_explicit_empty_vm_coverage_is_distinct_from_unassessed(db_session, tmp_path):
    from api.modules.vm.sbom_models import VmHostCoverage
    from api.modules.vm.services.importer import _parse_into_stage, _replace_current
    from tests.vm.test_ref_update_import import Handle

    path = tmp_path / "hosts.csv"
    path.write_text(
        "@Host;Host.@Vulners.CVEs\nbox (10.0.0.2);\nother (10.0.0.3);CVE-2024-1111\n"
        "unparsed (10.0.0.4);invalid-cve-value\n"
    )
    hosts, count, clean = _parse_into_stage(db_session, Handle(db_session), path)
    _replace_current(db_session, hosts, count, Handle(db_session), clean)
    assert db_session.get(VmHostCoverage, "box|10.0.0.2")
    assert not db_session.get(VmHostCoverage, "unparsed|10.0.0.4")
    assert len(db_session.scalars(select(VmHost)).all()) == 1
