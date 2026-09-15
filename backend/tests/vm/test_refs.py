"""Справочники: парсеры на фикстурах и загрузка через API с обогащением."""
from __future__ import annotations

import gzip
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select

from api.modules.vm.core.refs import (
    open_maybe_gzip,
    parse_epss,
    parse_exploitdb,
    parse_msf,
    parse_nvd,
)
from api.modules.vm.models import VmCve, VmRefNvd

FIXTURES = Path(__file__).parent / "fixtures"


def test_parsers() -> None:
    with (FIXTURES / "epss.csv").open("rb") as fh:
        epss = list(parse_epss(fh))
    assert [e.cve_id for e in epss] == ["CVE-2021-44228", "CVE-2019-0708", "CVE-2023-1234"]
    assert epss[0].epss == 0.97565

    with (FIXTURES / "nvd-2021.json").open("rb") as fh:
        nvd = list(parse_nvd(fh))
    assert nvd[0].cve_id == "CVE-2021-44228" and nvd[0].year == 2021
    assert (nvd[0].cvss_v3, nvd[0].v3_av, nvd[0].cvss_v2, nvd[0].v2_ac) == (10.0, "NETWORK", 9.3, "MEDIUM")
    assert nvd[0].description.startswith("Apache") and str(nvd[0].published) == "2021-12-10"
    assert nvd[1].cvss_v3 is None and nvd[1].v2_av == "LOCAL"

    with (FIXTURES / "exploits.csv").open("rb") as fh:
        exdb = list(parse_exploitdb(fh))
    assert (exdb[0].exploit_id, exdb[0].type, exdb[0].verified, exdb[0].cve_ids) == (50592, "remote", True, ["CVE-2021-44228"])
    assert len(exdb) == 4  # парсер отдаёт и дубль id; его убирает загрузчик

    with (FIXTURES / "msf.json").open("rb") as fh:
        msf = list(parse_msf(fh))
    assert msf[0].fullname == "exploit/multi/http/log4shell_header_injection" and msf[0].rank == 600
    assert msf[0].cve_ids == ["CVE-2021-44228"]


def test_open_maybe_gzip(tmp_path: Path) -> None:
    gz = tmp_path / "epss.csv.gz"
    gz.write_bytes(gzip.compress((FIXTURES / "epss.csv").read_bytes()))
    with open_maybe_gzip(gz) as fh:
        assert len(list(parse_epss(fh))) == 3


def _upload_ref(client: TestClient, name: str, *files: str) -> dict[str, Any]:
    payload = [("files", (f, (FIXTURES / f).read_bytes(), "application/octet-stream")) for f in files]
    r = client.post(f"/api/vm/refs/{name}/upload", files=payload)
    assert r.status_code == 202, r.text
    return client.get(f"/api/vm/jobs/{r.json()['job_id']}").json()


def test_refs_enrich_imported_cves(auth_client: TestClient, db_session: Any) -> None:
    r = auth_client.post("/api/vm/import/file", files={"file": ("hosts.csv", (FIXTURES / "hosts.csv").read_bytes(), "text/csv")})
    assert r.status_code == 202
    for name, files in (("epss", ("epss.csv",)), ("nvd", ("nvd-2021.json", "nvd-2019.json")), ("exploitdb", ("exploits.csv",)), ("msf", ("msf.json",))):
        job = _upload_ref(auth_client, name, *files)
        assert job["status"] == "done", job

    states = {s["name"]: s for s in auth_client.get("/api/vm/refs").json()}
    assert states["epss"]["records"] == 3 and states["epss"]["source"] == "file" and not states["epss"]["stale"]
    assert states["nvd"]["records"] == 3 and "2019" in states["nvd"]["detail"] and "2021" in states["nvd"]["detail"]
    assert states["exploitdb"]["records"] == 3 and states["msf"]["records"] == 3

    db_session.expire_all()
    log4j = db_session.get(VmCve, "CVE-2021-44228")
    assert (log4j.cvss, log4j.cvss_source, log4j.epss) == (10.0, "nvd_v3", 0.97565)
    assert log4j.exploitdb_type == "remote" and log4j.exploits_count == 2
    assert log4j.msf_rank == "excellent" and log4j.msf_modules == 2
    assert log4j.cve_factor > 1.0
    bluekeep = db_session.get(VmCve, "CVE-2019-0708")
    assert bluekeep.cvss == 9.8 and bluekeep.msf_rank == "normal"

    # Повторная загрузка NVD только за 2019 не трогает 2021.
    job = _upload_ref(auth_client, "nvd", "nvd-2019.json")
    assert job["status"] == "done"
    years = sorted(db_session.execute(select(VmRefNvd.year).distinct()).scalars())
    assert years == [2019, 2021]


def test_unknown_ref_and_year_validation(auth_client: TestClient) -> None:
    assert auth_client.post("/api/vm/refs/foo/download").status_code == 404
    r = auth_client.post("/api/vm/refs/nvd/download", json={"years": [1990]})
    assert r.status_code == 422
