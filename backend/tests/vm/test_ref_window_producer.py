"""Bounded offline periods use local transports and Git fixtures only."""
from __future__ import annotations

import hashlib
import importlib
import json
import subprocess
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from api.modules.vm.core import ref_updates as updates


def window_module():
    try:
        return importlib.import_module("api.modules.vm.core.ref_window")
    except ModuleNotFoundError:
        pytest.fail("bounded period producer is not implemented")


def response(data, status=200, **headers):
    return updates.HttpResponse(status, headers, data if isinstance(data, bytes) else json.dumps(data).encode())


@pytest.mark.parametrize(("end", "expected"), [
    ("2024-05-31T12:00:00+00:00", "2024-02-29T12:00:00+00:00"),
    ("2025-05-31T12:00:00+00:00", "2025-02-28T12:00:00+00:00"),
    ("2026-01-31T12:00:00+00:00", "2025-10-31T12:00:00+00:00"),
])
def test_calendar_three_months_clamps_days(end, expected):
    now = datetime.fromisoformat(end)
    assert window_module().period_bounds("3m", now) == (datetime.fromisoformat(expected), now)


def test_day_periods_are_utc_and_invalid_period_fails():
    module = window_module()
    now = datetime.fromisoformat("2026-11-15T12:00:00+03:00")
    for period, days in (("1d", 1), ("7d", 7)):
        since, until = module.period_bounds(period, now)
        assert until == now and until.tzinfo is UTC
        assert until - since == timedelta(days=days)
    with pytest.raises(ValueError, match="period"):
        module.period_bounds("90d", now)


def test_nvd_exact_window_all_cve_years_and_no_export(tmp_path):
    module = window_module()
    calls = []
    now = datetime(2026, 11, 15, tzinfo=UTC)
    def http(url, headers):
        query = parse_qs(urlsplit(url).query)
        calls.append(query)
        items = [("CVE-1999-1234", "2026-11-14T00:00:01Z"),
                 ("CVE-2026-9999", "2026-11-15T00:00:00Z"),
                 ("CVE-2001-1234", "2026-11-14T00:00:00Z")]
        return response({"startIndex": 0, "totalResults": 3, "vulnerabilities": [
            {"cve": {"id": identifier, "lastModified": modified, "vulnStatus": "Rejected"}}
            for identifier, modified in items]})
    output = tmp_path / "window.zip"
    manifest = module.build_window_bundle(output, ["nvd"], tmp_path / "cache", now=now, http=http)
    assert calls[0]["lastModStartDate"] == ["2026-11-14T00:00:00Z"]
    assert calls[0]["lastModEndDate"] == ["2026-11-15T00:00:00Z"]
    assert "noRejected" not in calls[0]
    assert manifest["version"] == 2 and manifest["scope"] == "window"
    assert manifest["window"] == {"since": "2026-11-14T00:00:00Z", "until": "2026-11-15T00:00:00Z"}
    entry = manifest["sources"][0]
    assert entry["mode"] == "delta" and "base" not in entry and "target" not in entry
    with zipfile.ZipFile(output) as archive:
        assert json.loads(archive.read(updates.MANIFEST_NAME)) == manifest
        payload = entry["files"][0]
        body = archive.read(payload["path"])
        assert hashlib.sha256(body).hexdigest() == payload["sha256"]
        assert [row["cve"]["id"] for row in json.loads(body)["vulnerabilities"]] == ["CVE-1999-1234", "CVE-2026-9999"]


def test_nvd_three_months_pages_seven_days_without_truncation(tmp_path):
    module = window_module()
    calls = []
    def http(url, headers):
        query = parse_qs(urlsplit(url).query)
        calls.append(query)
        offset = int(query["startIndex"][0])
        end = query["lastModEndDate"][0]
        return response({"startIndex": offset, "totalResults": 2, "vulnerabilities": [
            {"cve": {"id": f"CVE-1999-{1000 + len(calls)}", "lastModified": end}}]})
    module.build_window_bundle(tmp_path / "w.zip", ["nvd"], tmp_path / "cache", period="3m",
                               now=datetime(2026, 11, 15, tzinfo=UTC), http=http)
    assert len(calls) == 28
    assert calls[0]["lastModStartDate"] == ["2026-08-15T00:00:00Z"]
    assert calls[-1]["lastModEndDate"] == ["2026-11-15T00:00:00Z"]
    assert all(datetime.fromisoformat(q["lastModEndDate"][0]) - datetime.fromisoformat(q["lastModStartDate"][0]) <= timedelta(days=7) for q in calls)


def test_snapshot_local_validators_only_advance_after_published_bundle(tmp_path):
    module = window_module()
    cache = tmp_path / "cache"
    payload = {"vulnerabilities": [{"cveID": "CVE-2026-1234"}]}
    first = module.build_window_bundle(tmp_path / "first.zip", ["kev"], cache,
        http=lambda url, headers: response(payload, ETag='"one"'))
    assert first["sources"][0]["mode"] == "snapshot"
    seen = []
    def cached(url, headers):
        seen.append(headers)
        return response(b"", 304)
    second = module.build_window_bundle(tmp_path / "second.zip", ["kev"], cache, http=cached)
    assert seen == [{"If-None-Match": '"one"'}]
    assert second["sources"][0]["mode"] == "unchanged"
    def failing(url, headers):
        if url.startswith(updates.NVD_API):
            raise RuntimeError("source unavailable")
        return response({"vulnerabilities": [{"cveID": "CVE-2026-2345"}]}, ETag='"two"')
    with pytest.raises(RuntimeError, match="source unavailable"):
        module.build_window_bundle(tmp_path / "failed.zip", ["kev", "nvd"], cache, http=failing)
    assert not (tmp_path / "failed.zip").exists()
    seen.clear()
    module.build_window_bundle(tmp_path / "retry.zip", ["kev"], cache, http=cached)
    assert seen == [{"If-None-Match": '"one"'}]


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def test_git_window_exact_diff_move_delete_and_withdrawn_raw(tmp_path):
    module = window_module()
    repo = tmp_path / "remote"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "fixture@example.invalid")
    git(repo, "config", "user.name", "fixture")
    git(repo, "config", "uploadpack.allowFilter", "true")
    ids = ["GHSA-2345-2345-2345", "GHSA-3456-3456-3456", "GHSA-4567-4567-4567"]
    def put(identifier, reviewed="github-reviewed", withdrawn=False):
        path = Path("advisories") / reviewed / "2026" / "11" / identifier / (identifier + ".json")
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        body = {"id": identifier, "affected": [], "modified": "2026-11-15T00:00:00Z", "database_specific": {"raw": True}}
        if withdrawn:
            body["withdrawn"] = "2026-11-15T00:00:00Z"
        (repo / path).write_text(json.dumps(body))
        return path
    old = [put(identifier) for identifier in ids]
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "cutoff")
    base = git(repo, "rev-parse", "HEAD")
    put(ids[0], withdrawn=True)
    (repo / old[1]).unlink()
    (repo / old[2]).unlink()
    put(ids[2], "unreviewed")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "end")
    target = git(repo, "rev-parse", "HEAD")
    now = datetime(2026, 11, 15, tzinfo=UTC)
    def resolve(at, http, ref):
        return target if at == now else base
    provider = module.GitWindowSource(tmp_path / "cache", remote=repo.as_uri(), revision_resolver=resolve)
    requested = []
    def http(url, headers):
        requested.append(url)
        assert f"/{target}/advisories/" in url
        return response((repo / ("advisories/" + url.split("/advisories/", 1)[1])).read_bytes())
    output = tmp_path / "w.zip"
    manifest = module.build_window_bundle(output, ["ghsa"], tmp_path / "cache", now=now, http=http, github=provider)
    entry = manifest["sources"][0]
    assert entry["deleted_ids"] == [ids[1]]
    assert len(requested) == 2
    assert entry["provenance"]["base_revision"] == base
    assert entry["provenance"]["target_revision"] == target
    with zipfile.ZipFile(output) as archive:
        raw = json.loads(archive.read(old[0].as_posix()))
        assert raw["withdrawn"] and raw["database_specific"]["raw"]
    rule_source = module.GitWindowSource(tmp_path / "rules-cache", remote=repo.as_uri(),
        prefixes=("advisories",), path_filter=lambda path: "unreviewed" in path, revision_resolver=resolve)
    changes = rule_source.changes(now - timedelta(days=1), now, http)
    assert len(changes.changed) == 1 and changes.deleted == []


def test_github_metadata_pins_target_then_cutoff_on_same_history(tmp_path):
    module = window_module()
    provider = module.GitWindowSource(tmp_path)
    now = datetime(2026, 11, 15, tzinfo=UTC)
    queries = []
    def http(url, headers):
        query = parse_qs(urlsplit(url).query)
        queries.append(query)
        return response([{"sha": "a" * 40, "commit": {"committer": {"date": query["until"][0]}}}])
    changes = provider.changes(now - timedelta(days=1), now, http)
    assert changes.changed == changes.deleted == []
    assert queries == [{"sha": ["main"], "until": ["2026-11-15T00:00:00Z"], "per_page": ["1"]},
                       {"sha": ["a" * 40], "until": ["2026-11-14T00:00:00Z"], "per_page": ["1"]}]


@pytest.mark.parametrize("status", [403, 429, 500])
def test_metadata_failure_has_no_full_fallback_and_no_output(tmp_path, status):
    module = window_module()
    calls = []
    def http(url, headers):
        calls.append(url)
        return response({}, status)
    with pytest.raises(ValueError, match="revision|metadata"):
        module.build_window_bundle(tmp_path / "failed.zip", ["ghsa"], tmp_path / "cache", http=http)
    assert len(calls) == 1 and calls[0].startswith("https://api.github.com/")
    assert not (tmp_path / "failed.zip").exists()


def test_nvd_outside_window_and_oversize_never_publish(tmp_path):
    module = window_module()
    def http(url, headers):
        return response({"startIndex": 0, "totalResults": 1, "vulnerabilities": [
            {"cve": {"id": "CVE-2026-1234", "lastModified": "2020-01-01T00:00:00Z"}}]})
    with pytest.raises(ValueError, match="outside"):
        module.build_window_bundle(tmp_path / "outside.zip", ["nvd"], tmp_path / "cache", http=http)
    with pytest.raises(ValueError, match="limit"):
        module.build_window_bundle(tmp_path / "size.zip", ["kev"], tmp_path / "cache", max_bytes=1,
            http=lambda url, headers: response({"vulnerabilities": [{"cveID": "CVE-2026-1234"}]}))
    assert not (tmp_path / "outside.zip").exists() and not (tmp_path / "size.zip").exists()


@pytest.mark.parametrize(("since", "until"), [
    ("2020-11-15T00:00:00+00:00", "2026-11-15T00:00:00+00:00"),
    ("2024-02-29T11:59:59+00:00", "2024-05-31T12:00:00+00:00"),
    ("2025-02-28T11:59:59+00:00", "2025-05-31T12:00:00+00:00"),
    ("2025-10-31T11:59:59+00:00", "2026-01-31T12:00:00+00:00"),
])
def test_git_window_rejects_over_three_months_before_resolving(tmp_path, since, until):
    module = window_module()
    calls = []
    def resolve(at, http, ref):
        calls.append(at)
        return "a" * 40
    provider = module.GitWindowSource(tmp_path, revision_resolver=resolve)
    with pytest.raises(ValueError, match="three calendar months"):
        provider.changes(datetime.fromisoformat(since), datetime.fromisoformat(until),
                         lambda url, headers: pytest.fail("unexpected HTTP request"))
    assert calls == []
    assert not provider.transport.path.exists()


@pytest.mark.parametrize(("since", "until"), [
    ("2024-02-29T12:00:00+00:00", "2024-05-31T12:00:00+00:00"),
    ("2025-02-28T12:00:00+00:00", "2025-05-31T12:00:00+00:00"),
    ("2025-10-31T12:00:00+00:00", "2026-01-31T12:00:00+00:00"),
])
def test_git_window_accepts_exact_calendar_three_months(tmp_path, since, until):
    module = window_module()
    calls = []
    def resolve(at, http, ref):
        calls.append(at)
        return "a" * 40
    provider = module.GitWindowSource(tmp_path, revision_resolver=resolve)
    start, end = datetime.fromisoformat(since), datetime.fromisoformat(until)
    changes = provider.changes(start, end, lambda url, headers: pytest.fail("unexpected HTTP request"))
    assert calls == [end, start]
    assert changes.changed == changes.deleted == []
