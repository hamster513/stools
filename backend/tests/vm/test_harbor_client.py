from __future__ import annotations

import base64
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from api.hosts import LOGIN_REJECTED, NO_LINK, NO_RIGHTS, TLS_FAILED, server_error
from api.modules.vm.core.harbor import (
    BAD_FORMAT,
    MAX_PAGES,
    REPORT_MIME,
    REPORT_MIME_OLD,
    HarborArtifact,
    HarborClient,
    HarborError,
    HarborInfo,
    HarborRepo,
    HarborVuln,
    is_cve,
    make_harbor_client,
)

FIXTURES = Path(__file__).parent / "harbor_fixtures"
Handler = Callable[[httpx.Request], httpx.Response]


class Conn:
    url = "https://harbor.corp/"
    robot_name = "robot$stools"
    robot_secret = "s3cret"
    verify_tls = True


def fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


def client_for(handler: Handler, calls: list[httpx.Request] | None = None) -> HarborClient:
    def wrapped(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        return handler(request)

    http = httpx.Client(transport=httpx.MockTransport(wrapped), auth=(Conn.robot_name, Conn.robot_secret))
    return HarborClient(Conn(), http)


def test_make_client_uses_basic_auth_and_no_redirects() -> None:
    http = make_harbor_client(Conn())
    assert http.follow_redirects is False
    assert isinstance(http.auth, httpx.BasicAuth)
    request = http.build_request("GET", "https://harbor.corp/api/v2.0/systeminfo")
    sent = next(http.auth.auth_flow(request))
    assert sent.headers["Authorization"] == "Basic " + base64.b64encode(b"robot$stools:s3cret").decode()


def test_make_client_propagates_verify_tls() -> None:
    class Insecure(Conn):
        verify_tls = False

    called: dict[str, Any] = {}
    real = httpx.Client

    def spy(**kwargs: Any) -> httpx.Client:
        called.update(kwargs)
        return real(**kwargs)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(httpx, "Client", spy)
        make_harbor_client(Insecure())
    assert called["verify"] is False
    assert called["auth"] == ("robot$stools", "s3cret")


def test_invalid_url_is_no_link() -> None:
    class Bad(Conn):
        url = "http://[not-an-ip"

    with pytest.raises(HarborError) as exc:
        HarborClient(Bad(), httpx.Client()).projects()
    assert exc.value.kind == NO_LINK


def test_pagination_stops_when_server_ignores_page() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"name": f"p{i}"} for i in range(100)])

    names = client_for(handler, calls).projects()
    assert len(calls) == 2
    assert names == [f"p{i}" for i in range(100)]


def test_pagination_beyond_max_pages_is_error() -> None:
    """Список длиннее предохранителя — ошибка, а не усечённый список: по нему удаляют пропавшее."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        return httpx.Response(200, json=[{"name": f"p{page}-{i}"} for i in range(100)], headers={"X-Total-Count": "1000000"})

    with pytest.raises(HarborError) as err:
        client_for(handler, calls).projects()
    assert err.value.kind == BAD_FORMAT and len(calls) == MAX_PAGES


def test_pagination_ignores_non_ascii_total_count() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"name": "a"}], headers={"X-Total-Count": "١٢٣".encode()})

    assert client_for(handler).projects() == ["a"]


def test_severity_vocabulary_is_closed() -> None:
    def item(sev: object) -> dict[str, Any]:
        return {"id": "CVE-2024-0001", "package": "p", "version": "1", "severity": sev, "links": []}

    report = {REPORT_MIME: {"vulnerabilities": [item(s) for s in ("Critical", "HIGH", "Negligible", "None", "", None, 5)]}}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=report)

    got = [v.severity for v in client_for(handler).vulnerabilities("p", "r", "sha256:1")]
    assert got == ["critical", "high", "unknown", "unknown", "unknown", "unknown", "unknown"]


def test_scan_status_whitelist_and_null_tags() -> None:
    def art(status: str | None) -> dict[str, Any]:
        raw = fixture("artifacts_stools_web.json")[0]
        raw["tags"] = None
        if status is None:
            raw["scan_overview"][REPORT_MIME].pop("scan_status")
        else:
            raw["scan_overview"][REPORT_MIME]["scan_status"] = status
        return raw

    cases = [("Success", "success"), ("Scheduled", "pending"), ("Stopped", "error"), ("Running", "running"), ("Weird", "none"), (None, "none")]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[art(s) for s, _ in cases], headers={"X-Total-Count": str(len(cases))})

    got = client_for(handler).artifacts("p", "r")
    assert [a.scan_status for a in got] == [want for _, want in cases]
    assert all(a.tags == () for a in got)


def test_probe_reads_version() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.0/systeminfo":
            return httpx.Response(200, json=fixture("systeminfo.json"))
        if request.url.path == "/api/v2.0/projects":
            return httpx.Response(200, json=fixture("projects.json"), headers={"X-Total-Count": "2"})
        return httpx.Response(404)

    info = client_for(handler, calls).probe()
    assert info == HarborInfo(version="v2.15.4")
    assert {c.url.path for c in calls} == {"/api/v2.0/systeminfo", "/api/v2.0/projects"}
    assert all(c.headers["Authorization"].startswith("Basic ") for c in calls)


def test_projects_paginates() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        assert request.url.params["page_size"] == "100"
        items = [{"name": f"p{page}-{i}"} for i in range(100 if page == 1 else 50)]
        return httpx.Response(200, json=items, headers={"X-Total-Count": "150"})

    names = client_for(handler, calls).projects()
    assert len(names) == 150 and names[0] == "p1-0" and names[-1] == "p2-49"
    assert len(calls) == 2


def test_projects_without_total_header_stops_on_short_page() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"name": "a"}, {"name": "b"}])

    assert client_for(handler).projects() == ["a", "b"]


def test_repositories_strips_project_prefix() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v2.0/projects/library/repositories"
        return httpx.Response(200, json=fixture("repositories_library.json"), headers={"X-Total-Count": "5"})

    repos = client_for(handler).repositories("library")
    assert len(repos) == 5
    first = repos[0]
    assert (first.project, first.name, first.artifact_count) == ("library", "alpine", 1)
    assert isinstance(first, HarborRepo)
    assert first.update_time is not None and first.update_time.isoformat().startswith("2026-10-28T10:38:03")
    assert [r.name for r in repos][:2] == ["alpine", "debian"]


def artifacts_of(name: str) -> list[HarborArtifact]:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=fixture(name), headers={"X-Total-Count": str(len(fixture(name)))})

    return client_for(handler).artifacts("p", "x")


def test_artifacts_parse_overview_and_index() -> None:
    (alpine,) = artifacts_of("artifacts_library_alpine.json")
    assert alpine.is_index is True
    assert "linux/amd64" in alpine.platforms and "linux/arm64" in alpine.platforms
    assert not any("unknown" in p for p in alpine.platforms)
    assert alpine.scan_status == "success"
    assert alpine.tags == ("3.18",)
    assert alpine.digest.startswith("sha256:de0eb0b3")
    assert alpine.trivy_counts == {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "total": 0}

    (web,) = artifacts_of("artifacts_stools_web.json")
    assert web.is_index is False
    assert web.platforms == ()
    assert web.trivy_counts == {"critical": 0, "high": 2, "medium": 1, "low": 0, "unknown": 3, "total": 6}
    assert web.scanner == "Trivy v0.75.0"
    assert web.scan_status == "success"
    assert web.scanned_at is not None and web.scanned_at.isoformat().startswith("2026-10-28T10:36:41")
    assert web.size == 24160194
    assert web.push_time is not None
    assert web.media_type == "application/vnd.docker.distribution.manifest.v2+json"
    assert web.tags == ("2615570",)

    (debian,) = artifacts_of("artifacts_library_debian.json")
    assert debian.trivy_counts == {"critical": 1, "high": 56, "medium": 87, "low": 83, "unknown": 1, "total": 228}


def test_artifact_without_scan_overview_is_none() -> None:
    raw = fixture("artifacts_stools_web.json")
    raw[0].pop("scan_overview")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=raw, headers={"X-Total-Count": "1"})

    (art,) = client_for(handler).artifacts("stools", "stools-web")
    assert art.scan_status == "none"
    assert art.scanned_at is None and art.scanner is None
    assert art.trivy_counts == {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "total": 0}


def test_repo_name_double_encoded() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[], headers={"X-Total-Count": "0"})

    client = client_for(handler, calls)
    client.artifacts("team", "team/app")
    assert "team%252Fapp" in calls[0].url.raw_path.decode()
    assert calls[0].url.raw_path.decode().startswith("/api/v2.0/projects/team/repositories/team%252Fapp/artifacts?")


def test_vulnerabilities_request_path() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=fixture("vulns_library_alpine_index.json"))

    client_for(handler, calls).vulnerabilities("team", "team/app", "sha256:abc")
    path = calls[0].url.raw_path.decode()
    assert path == "/api/v2.0/projects/team/repositories/team%252Fapp/artifacts/sha256:abc/additions/vulnerabilities"
    assert REPORT_MIME in calls[0].headers["X-Accept-Vulnerabilities"]


def vulns_of(name: str) -> list[HarborVuln]:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/additions/vulnerabilities")
        return httpx.Response(200, json=fixture(name))

    return client_for(handler).vulnerabilities("stools", "stools-web", "sha256:5b8f")


def test_vulnerabilities_parse() -> None:
    vulns = vulns_of("vulns_stools_web.json")
    assert len(vulns) == 6
    chi, jose3, jose4, gorel, _, _ = vulns
    assert chi.vuln_id == "CVE-2026-114437"
    assert chi.package == "github.com/go-chi/chi/v5" and chi.installed_version == "v5.3.2"
    assert chi.fixed_version == "5.4.0"
    assert chi.cvss == 4.8
    assert chi.severity == "medium"
    assert chi.link == "https://avd.aquasec.com/nvd/cve-2026-114437"
    assert chi.description is not None and chi.description.startswith("In the Golang Chi")
    assert jose3.fixed_version is None and jose4.fixed_version == "4.1.6"
    assert jose3.vuln_id == jose4.vuln_id and jose3.package != jose4.package
    assert gorel.vuln_id == "GO-2026-5932" and gorel.cvss is None
    assert gorel.link == "https://go.dev/issue/44226"
    assert sum(v.fixed_version is not None for v in vulns) == 4
    assert vulns_of("vulns_library_alpine_index.json") == []


def test_report_non_cve_and_duplicates() -> None:
    vulns = vulns_of("vulns_library_debian.json")
    assert len(vulns) == 25
    temp = next(v for v in vulns if v.vuln_id == "TEMP-0841856-B18BAF")
    assert is_cve(temp.vuln_id) is False
    assert all(v.fixed_version is None for v in vulns)
    assert len([v for v in vulns if is_cve(v.vuln_id)]) == 24


def test_description_is_cut() -> None:
    item = {"id": "CVE-2024-0001", "package": "p", "version": "1", "fix_version": "", "severity": "High", "description": "x" * 5000, "links": []}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={REPORT_MIME: {"vulnerabilities": [item]}})

    (v,) = client_for(handler).vulnerabilities("p", "r", "sha256:1")
    assert v.description is not None and len(v.description) == 2000
    assert v.link is None and v.cvss is None


def test_report_old_mime_fallback() -> None:
    item = {"id": "CVE-2024-0001", "package": "p", "version": "1", "fix_version": "2", "severity": "Low", "links": []}

    def old(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={REPORT_MIME_OLD: {"vulnerabilities": [item]}})

    assert [v.vuln_id for v in client_for(old).vulnerabilities("p", "r", "sha256:1")] == ["CVE-2024-0001"]

    def none(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"something/else": {"vulnerabilities": [item]}})

    with pytest.raises(HarborError) as exc:
        client_for(none).vulnerabilities("p", "r", "sha256:1")
    assert exc.value.kind == "BAD_FORMAT"


def test_garbage_body_is_bad_format() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>not json</html>")

    with pytest.raises(HarborError) as exc:
        client_for(handler).projects()
    assert exc.value.kind == "BAD_FORMAT"


@pytest.mark.parametrize(
    ("status", "kind"),
    [(401, LOGIN_REJECTED), (403, NO_RIGHTS), (502, server_error(502)), (500, server_error(500))],
)
def test_errors_map_to_classes(status: int, kind: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text="no")

    with pytest.raises(HarborError) as exc:
        client_for(handler).projects()
    assert exc.value.kind == kind


def test_connect_error_is_no_link() -> None:
    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(HarborError) as exc:
        client_for(refused).projects()
    assert exc.value.kind == NO_LINK

    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    with pytest.raises(HarborError) as exc2:
        client_for(slow).projects()
    assert exc2.value.kind == NO_LINK


def test_tls_error_is_tls_failed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")

    with pytest.raises(HarborError) as exc:
        client_for(handler).projects()
    assert exc.value.kind == TLS_FAILED


def test_is_cve() -> None:
    assert is_cve("CVE-2024-1234") is True
    assert is_cve("cve-2023-99999") is True
    assert is_cve("GHSA-abcd-efgh-ijkl") is False
    assert is_cve("TEMP-0841856-B18BAF") is False
    assert is_cve("CVE-2024-123") is False
