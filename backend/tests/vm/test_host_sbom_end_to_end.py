"""Run both import APIs and the host worker against a provisioned official Trivy database."""

import datetime as dt
import hashlib
import json
import os
import threading
import time
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from api.modules.assets.models import AssetObservation
from api.modules.ksc.core.export import FORMAT
from api.modules.vm.sbom_models import HostSbomScan
from api.modules.vm.services import importer, trivy_scan

HOST = "sbom-lab.example.test"
IP = "192.0.2.25"
DISTRO = "Debian GNU/Linux 12 (bookworm)"
VERSION = "3.0.11-1~deb12u1"
DISPLAY_APP = "Инвентарный агент"
OVERLAP = "CVE-2024-6119"  # OpenSSL
VM_ONLY = "CVE-2021-44228"  # Log4j
TRIVY_ONLY = "CVE-2024-0727"  # OpenSSL


def maxpatrol_transport():
    """Serve actual-style semicolon exports through the production HTTP client's three requests."""
    exports = {}
    native = (
        "@UnixHost;UnixHost.OsName;UnixHost.Packages.Name;UnixHost.Packages.Version;"
        "UnixHost.Packages.Architecture;UnixHost.Packages.Release;UnixHost.Packages.Epoch;"
        "UnixHost.Packages.SourceName;UnixHost.Packages.SourceVersion\n"
        f'"{HOST} ({IP})";"{DISTRO}";libssl3;{VERSION};amd64;;;openssl;{VERSION}\n'
    )
    findings = (
        "@Host;Host.OsName;Host.@Groups;Host.@Vulners.CVEs;Host.UF_Criticality;Host.UF_Zone\n"
        f'"{HOST} ({IP})";"{DISTRO}";Servers;"{OVERLAP}, {VM_ONLY}";High;Test\n'
    )

    def serve(request):
        if request.url.path.endswith("/assets_grid"):
            query = json.loads(request.content)["pdql"]
            columns = query.removeprefix("select(").split(")", 1)[0].split(", ")
            if "UnixHost.Packages.Name" in columns:
                assert "UnixHost.Packages.SourceName" in columns and "Vulners" not in query
                body = native
            elif "Host.@Vulners.CVEs" in columns:
                body = findings
            else:
                body = ";".join(columns) + "\n"
            token = str(len(exports) + 1)
            exports[token] = body
            return httpx.Response(200, json={"token": token})
        body = exports[request.url.params["pdqlToken"]]
        if request.url.path.endswith("/row_count"):
            return httpx.Response(200, json={"rowCount": len(body.splitlines()) - 1})
        assert request.url.path.endswith("/export")
        return httpx.Response(200, content=body.encode("utf-8-sig"))

    return httpx.MockTransport(serve)


def import_inventories(client, monkeypatch):
    transport = maxpatrol_transport()
    monkeypatch.setattr(importer, "make_client", lambda conn: httpx.Client(transport=transport))
    settings = {
        "connection": {"host": "maxpatrol.example.test", "api_token": "fixture", "limit": 0}
    }
    assert client.put("/api/vm/settings", json=settings).status_code == 200
    submitted = client.post("/api/vm/import/vm")
    assert submitted.status_code == 202
    job = client.get(f"/api/vm/jobs/{submitted.json()['job_id']}").json()
    assert job["status"] == "done", job.get("error")

    ksc = {
        "format": FORMAT,
        "server": {"name": "ksc-lab", "collected_at": dt.datetime.now(dt.UTC).isoformat()},
        "hosts": [
            {
                "KLHST_WKS_HOSTNAME": "guid-lab",
                "KLHST_WKS_DN": "sbom-lab",
                "KLHST_WKS_FQDN": HOST,
                "KLHST_WKS_OS_NAME": DISTRO,
            }
        ],
        "host_inventory": {
            "guid-lab": {
                "status": "complete",
                "items": [
                    {
                        "DisplayName": DISPLAY_APP,
                        "DisplayVersion": "9.2",
                        "Publisher": "Example",
                        "InstallLocation": "/private/internal-install-path",
                    }
                ],
            }
        },
    }
    submitted = client.post(
        "/api/ksc/snapshots/file",
        files={"file": ("lab.json", json.dumps(ksc).encode(), "application/json")},
    )
    assert submitted.status_code == 202
    job = client.get(f"/api/ksc/jobs/{submitted.json()['job_id']}").json()
    assert job["status"] == "done", job.get("error")


@pytest.mark.skipif(
    not os.environ.get("STOOLS_TEST_TRIVY_DATA"), reason="requires official Trivy and its database"
)
def test_worker_scans_the_exact_download_and_compares_current_feeds(
    db_session,
    client_as,
    app_settings,
    monkeypatch,
    record_property,
):
    cache = Path(os.environ["STOOLS_TEST_TRIVY_DATA"]) / "trivy"
    app_settings.data_dir.mkdir(parents=True, exist_ok=True)
    (app_settings.data_dir / "trivy").symlink_to(cache, target_is_directory=True)
    client = client_as("admin")
    import_inventories(client, monkeypatch)
    asset_id = db_session.scalars(
        select(AssetObservation.asset_id)
        .where(AssetObservation.source == "vm", AssetObservation.source_key == f"{HOST}|{IP}")
        .limit(1)
    ).one()
    url = f"/api/assets/assets/{asset_id}/sbom"
    downloaded = client.get(url)
    assert (
        downloaded.status_code == 200 and "attachment" in downloaded.headers["content-disposition"]
    )
    components = {row["name"]: row for row in downloaded.json()["components"]}
    assert set(components) == {"libssl3", DISPLAY_APP}
    assert {"name": "aquasecurity:trivy:SrcName", "value": "openssl"} in components["libssl3"][
        "properties"
    ]
    assert (
        components["libssl3"]["version"] == VERSION
        and "distro=debian-12" in components["libssl3"]["purl"]
    )
    assert {"name": "stools:source", "value": "ksc"} in components[DISPLAY_APP]["properties"]
    assert "CVE-" not in downloaded.text and "/private/internal-install-path" not in downloaded.text

    launch, resume = threading.Event(), threading.Event()
    input_bytes = []
    elapsed = []
    run_json = trivy_scan._run_json

    def observe(args, directory, timeout, limit):
        if args[1] != "sbom":
            return run_json(args, directory, timeout, limit)
        input_bytes.append(Path(args[-1]).read_bytes())
        launch.set()
        assert resume.wait(30)
        started = time.monotonic()
        report = run_json(args, directory, timeout, limit)
        elapsed.append(time.monotonic() - started)
        return report

    monkeypatch.setattr(trivy_scan, "_run_json", observe)
    assert client.post(url + "/scan").status_code == 202
    with client:  # The normal application lifespan starts and stops the real background worker.
        try:
            assert launch.wait(30), "worker did not start Trivy"
            while_scanning = client.get(url + "/comparison").json()["status"]
            concurrent_download = client.get(url).content
        finally:
            resume.set()
        deadline = time.monotonic() + 135
        while True:
            result = client.get(url + "/comparison").json()
            if result["status"] != "running" or time.monotonic() >= deadline:
                break
            time.sleep(0.2)
        assert while_scanning == "running"
        assert concurrent_download == downloaded.content == input_bytes[0]
        assert result["status"] == "partial", result.get("error")
        assert result["inventory"] == {"maxpatrol": "available", "ksc": "available"}
        assert (result["components"], result["scanned_components"], result["checked"]) == (2, 2, 1)
        counts = result["counts"]
        assert counts["both"] == counts["vm_only"] == 1 and counts["trivy_only"] >= 1
        assert result["total"] == sum(counts.values())
        for offset, size in ((counts["trivy_only"] - 1, 1), (counts["trivy_only"], 0)):
            page = client.get(
                url + "/comparison", params={"group": "trivy_only", "limit": 1, "offset": offset}
            ).json()
            assert page["total"] == counts["trivy_only"] and len(page["items"]) == size
        for group, expected in (
            ("both", OVERLAP),
            ("vm_only", VM_ONLY),
            ("trivy_only", TRIVY_ONLY),
        ):
            rows = client.get(url + "/comparison", params={"group": group, "limit": 200}).json()[
                "items"
            ]
            found = next(row for row in rows if row["id"] == expected)
            assert found["group"] == group
            if group == "vm_only":
                assert found["packages"] == []
            else:
                package = found["packages"][0]
                assert (package["package"], package["installed_version"]) == ("libssl3", VERSION)
                assert package["fixed_version"] and package["purl"] == components["libssl3"]["purl"]

    digest = hashlib.sha256(downloaded.content).hexdigest()
    assert db_session.get(HostSbomScan, asset_id).digest == digest
    record_property(
        "scan",
        json.dumps(
            {
                "counts": counts,
                "seconds": elapsed[0],
                "sha256": digest,
                "bytes": len(downloaded.content),
                "revision": result["db_version"],
            }
        ),
    )
