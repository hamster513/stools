"""Portable update producer: bounded local transports, no live feed downloads."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from api.modules.vm.core import ref_updates as updates


def state(**sources):
    return {"format": "stools-reference-state", "version": 1, "sources": sources}


def response(data, status=200, **headers):
    body = data if isinstance(data, bytes) else json.dumps(data).encode()
    return updates.HttpResponse(status, headers, body)


def nvd_page(start, items, total, modified="2026-11-01T00:00:00.000"):
    return {"startIndex": start, "resultsPerPage": len(items), "totalResults": total,
            "vulnerabilities": [{"cve": {"id": item, "lastModified": modified,
                "vulnStatus": "Rejected"}} for item in items]}


def test_nvd_pages_fixed_windows_rejected_and_state_untouched(tmp_path):
    initial = state(nvd={"cursor": "2026-10-20T00:00:00Z", "years": [2025, 2026]})
    original = copy.deepcopy(initial)
    calls = []
    def http(url, headers):
        query = parse_qs(urlsplit(url).query)
        calls.append(query)
        start = int(query["startIndex"][0])
        return response(nvd_page(start, [f"CVE-2026-{1000 + start + 10 * ((len(calls) - 1) // 2)}"], 2, query["lastModStartDate"][0]))
    manifest, target = updates.build_update_bundle(tmp_path / "delta.zip", initial, ["nvd"],
        tmp_path / "cache", http=http, now=datetime(2026, 11, 1, tzinfo=UTC))
    assert initial == original
    assert len(calls) == 4
    for query in calls:
        begin = datetime.fromisoformat(query["lastModStartDate"][0])
        end = datetime.fromisoformat(query["lastModEndDate"][0])
        assert end - begin <= updates.timedelta(days=7)
        assert "noRejected" not in query
    assert calls[0]["lastModEndDate"] == calls[1]["lastModEndDate"]
    assert calls[2]["lastModStartDate"] == calls[0]["lastModEndDate"]
    assert [call["startIndex"][0] for call in calls] == ["0", "1", "0", "1"]
    assert target["sources"]["nvd"]["cursor"] == "2026-11-01T00:00:00Z"
    assert manifest["sources"][0]["mode"] == "delta"
    with zipfile.ZipFile(tmp_path / "delta.zip") as archive:
        assert updates.MANIFEST_NAME in archive.namelist()
        assert all(json.loads(archive.read(f["path"]))["vulnerabilities"][0]["cve"]["vulnStatus"] == "Rejected"
                   for f in manifest["sources"][0]["files"])


def test_failed_page_or_cancellation_never_publishes_archive(tmp_path):
    initial = state(nvd={"cursor": "2026-10-31T00:00:00Z", "years": [2026]})
    original = copy.deepcopy(initial)
    def http(url, headers):
        if "startIndex=0" in url:
            return response(nvd_page(0, ["CVE-2026-1000"], 2, parse_qs(urlsplit(url).query)["lastModStartDate"][0]))
        raise RuntimeError("page failed")
    with pytest.raises(RuntimeError, match="page failed"):
        updates.build_update_bundle(tmp_path / "delta.zip", initial, ["nvd"], tmp_path / "cache", http=http)
    assert not (tmp_path / "delta.zip").exists()
    assert initial == original
    def cancelled(message):
        raise RuntimeError("cancelled")
    with pytest.raises(RuntimeError, match="cancelled"):
        updates.build_update_bundle(tmp_path / "delta.zip", initial, ["nvd"], tmp_path / "cache", progress=cancelled, http=http)
    assert not (tmp_path / "delta.zip").exists()


def test_conditional_304_has_no_payload_and_preserves_validators(tmp_path):
    url = updates.SNAPSHOTS["kev"][0][1]
    initial = state(kev={"validators": {url: {"etag": '"v1"', "sha256": "a" * 64}}})
    seen = []
    def http(actual, headers):
        seen.append((actual, headers))
        return response(b"", 304)
    manifest, target = updates.build_update_bundle(tmp_path / "delta.zip", initial, ["kev"], tmp_path / "cache", http=http)
    assert seen == [(url, {"If-None-Match": '"v1"'})]
    assert target == initial
    assert manifest["sources"][0]["mode"] == "unchanged"
    assert manifest["sources"][0]["files"] == []


def test_changed_snapshot_is_labelled_and_hashed(tmp_path):
    payload = b'{"vulnerabilities": [{"cveID": "CVE-2026-1234"}]}'
    manifest, target = updates.build_update_bundle(tmp_path / "delta.zip", state(), ["kev"], tmp_path / "cache",
        http=lambda url, headers: response(payload, ETag='"v2"'))
    entry = manifest["sources"][0]
    assert entry["mode"] == "snapshot" and entry["base"] is None
    assert entry["files"] == [{"path": "known_exploited_vulnerabilities.json", "sha256": hashlib.sha256(payload).hexdigest()}]
    assert next(iter(target["sources"]["kev"]["validators"].values()))["etag"] == '"v2"'


def test_nvd_missing_checkpoint_fails_before_transport(tmp_path):
    with pytest.raises(ValueError, match="checkpoint"):
        updates.build_update_bundle(tmp_path / "delta.zip", state(), ["nvd"], tmp_path / "cache",
            http=lambda *args: pytest.fail("must not download full feed"))


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def test_native_git_exact_edit_add_delete_move_and_withdrawn(tmp_path):
    repo = tmp_path / "remote"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "test")
    git(repo, "config", "uploadpack.allowFilter", "true")
    ids = ["GHSA-2345-2345-2345", "GHSA-3456-3456-3456", "GHSA-4567-4567-4567", "GHSA-5678-5678-5678"]
    def put(advisory, reviewed="github-reviewed", withdrawn=False):
        path = Path("advisories") / reviewed / "2026" / "11" / advisory / (advisory + ".json")
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        doc = {"id": advisory, "modified": "2026-11-01T00:00:00Z", "affected": [], "database_specific": {"keep_raw": True}}
        if withdrawn:
            doc["withdrawn"] = "2026-11-01T00:00:00Z"
        (repo / path).write_text(json.dumps(doc))
        return path.as_posix()
    old = [put(advisory) for advisory in ids[:3]]
    git(repo, "add", "advisories")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    put(ids[0], withdrawn=True)
    (repo / old[1]).unlink()
    (repo / old[2]).unlink()
    put(ids[2], reviewed="unreviewed")
    put(ids[3])
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "target")
    target = git(repo, "rev-parse", "HEAD")
    provider = updates.GitAdvisorySource(tmp_path / "cache", remote=repo.as_uri())
    requested = []
    def http(url, headers):
        requested.append(url)
        assert f"/{target}/advisories/" in url
        path = "advisories/" + url.split("/advisories/", 1)[1]
        return response((repo / path).read_bytes())
    manifest, next_state = updates.build_update_bundle(tmp_path / "delta.zip", state(ghsa={"revision": base}),
        ["ghsa"], tmp_path / "cache", http=http, github=provider)
    entry = manifest["sources"][0]
    assert entry["deleted_ids"] == [ids[1]]
    assert len(requested) == 3
    assert next_state["sources"]["ghsa"]["revision"] == target
    assert git(tmp_path / "cache" / "ghsa.git", "rev-parse", "--is-bare-repository") == "true"
    with zipfile.ZipFile(tmp_path / "delta.zip") as archive:
        raw = json.loads(archive.read(old[0]))
        assert raw["withdrawn"] and raw["database_specific"]["keep_raw"]
        for payload in entry["files"]:
            assert hashlib.sha256(archive.read(payload["path"])).hexdigest() == payload["sha256"]


def test_git_missing_base_is_explicit_and_no_full_fallback(tmp_path):
    repo = tmp_path / "remote"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "uploadpack.allowFilter", "true")
    git(repo, "-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "--allow-empty", "-qm", "head")
    with pytest.raises(ValueError, match="base|checkpoint"):
        updates.GitAdvisorySource(tmp_path / "cache", remote=repo.as_uri()).changes("a" * 40)


def test_cli_preserves_state_and_existing_immutable_output(tmp_path):
    exported = tmp_path / "state.json"
    exported.write_text(json.dumps(state()))
    output = tmp_path / "out.zip"
    output.write_bytes(b"original")
    with pytest.raises((ValueError, FileExistsError)):
        updates.run_cli(["--state", str(exported), "--out", str(output), "--sources", "kev"])
    assert output.read_bytes() == b"original"
    assert json.loads(exported.read_text()) == state()


def test_http_retry_after_rate_limit_and_retry_budget():
    from io import BytesIO
    from urllib.error import HTTPError
    attempts = []
    sleeps = []
    class Reply(BytesIO):
        status = 200
        @property
        def headers(self):
            return {"ETag": "ok"}
    def opener(request, timeout):
        attempts.append(request)
        if len(attempts) == 1:
            raise HTTPError(request.full_url, 429, "limited", {"Retry-After": "1"}, None)
        return Reply(b"{}")
    result = updates.HttpClient(opener=opener, sleep=sleeps.append)("https://example.invalid/", {})
    assert result.status == 200 and sleeps == [1.0] and len(attempts) == 2


def test_distributed_helper_is_same_source_and_kit_contains_scripts():
    root = Path(__file__).resolve().parents[3]
    assert (root / "frontend/public/vm/ref_updates.py").read_bytes() == Path(updates.__file__).read_bytes()
    subprocess.run(["node", str(root / "frontend/scripts/build-reference-kit.mjs")], check=True, capture_output=True)
    with zipfile.ZipFile(root / "frontend/public/vm/reference-update-scripts.zip") as kit:
        assert set(kit.namelist()) == {"download-references.sh", "download-references.ps1", "ref_updates.py"}
        assert kit.read("ref_updates.py") == Path(updates.__file__).read_bytes()


def test_sh_updates_forwards_checkpoint_skip_and_hard_limit(tmp_path):
    import os
    root = Path(__file__).resolve().parents[3]
    binary = tmp_path / "python3"
    captured = tmp_path / "args"
    binary.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURED"\nexit 17\n')
    binary.chmod(0o755)
    curl = tmp_path / "curl"
    curl.write_text("#!/bin/sh\nexit 91\n")  # Fail closed even before wrapper update branch exists.
    curl.chmod(0o755)
    result = subprocess.run(["/bin/sh", str(root / "frontend/public/vm/download-references.sh")],
        cwd=tmp_path, capture_output=True, text=True, check=False,
        env={**os.environ, "PATH": str(tmp_path) + ":/usr/bin:/bin", "MODE": "updates", "STATE": "state.json",
             "SKIP": "nvd epss kev exploitdb msf attack", "OUT": "update.zip", "CAPTURED": str(captured)})
    assert result.returncode == 17, result.stderr
    arguments = captured.read_text().splitlines()
    assert arguments[0].endswith("/ref_updates.py")
    assert arguments[arguments.index("--sources") + 1:] == ["ghsa"]
    assert arguments[arguments.index("--state") + 1] == "state.json"
    assert arguments[arguments.index("--max-bytes") + 1] == "524288000"


def test_cli_durable_archive_precedes_state_and_failed_save_keeps_previous(tmp_path, monkeypatch):
    exported = tmp_path / "state.json"
    original = json.dumps(state(ghsa={"revision": "a" * 40}))
    exported.write_text(original)
    output = tmp_path / "out.zip"
    def build(path, initial, sources, cache, progress, **kwargs):
        path.write_bytes(b"durable archive")
        return {"sources": [{"name": "ghsa", "mode": "delta"}]}, state(ghsa={"revision": "b" * 40})
    def failed_save(path, body):
        assert output.read_bytes() == b"durable archive"
        raise OSError("state disk failed")
    monkeypatch.setattr(updates, "build_update_bundle", build)
    monkeypatch.setattr(updates, "_atomic_write", failed_save)
    with pytest.raises(OSError, match="state disk failed"):
        updates.run_cli(["--state", str(exported), "--out", str(output), "--sources", "ghsa"])
    assert exported.read_text() == original
    assert not exported.with_name("state.json.lock").exists()


def test_nvd_rollover_adds_new_year_but_not_excluded_historical_year(tmp_path):
    initial = state(nvd={"cursor": "2026-12-31T00:00:00Z", "years": [2026]})
    manifest, target = updates.build_update_bundle(tmp_path / "new-year.zip", initial, ["nvd"], tmp_path / "cache",
        now=datetime(2027, 1, 2, tzinfo=UTC), http=lambda *args: response(nvd_page(0,
            ["CVE-2025-1000", "CVE-2026-1000", "CVE-2027-1000"], 3, "2027-01-01T00:00:00Z")))
    assert target["sources"]["nvd"]["years"] == [2026, 2027]
    with zipfile.ZipFile(tmp_path / "new-year.zip") as archive:
        rows = json.loads(archive.read(manifest["sources"][0]["files"][0]["path"]))["vulnerabilities"]
        assert [row["cve"]["id"] for row in rows] == ["CVE-2026-1000", "CVE-2027-1000"]


@pytest.mark.parametrize("case", ["duplicate", "outside_window"])
def test_nvd_inconsistent_page_refuses_cursor_advance(tmp_path, case):
    initial = state(nvd={"cursor": "2026-11-01T00:00:00Z", "years": [2026]})
    def http(url, headers):
        offset = int(parse_qs(urlsplit(url).query)["startIndex"][0])
        return response(nvd_page(offset, ["CVE-2026-1000"], 2,
            "2026-11-01T00:00:00Z" if case == "duplicate" else "2025-01-01T00:00:00Z"))
    with pytest.raises(ValueError, match="duplicate|window"):
        updates.build_update_bundle(tmp_path / "invalid.zip", initial, ["nvd"], tmp_path / "cache", http=http,
            now=datetime(2026, 11, 2, tzinfo=UTC))
    assert not (tmp_path / "invalid.zip").exists()


def test_nvd_inclusive_boundary_is_emitted_once(tmp_path):
    cursor = datetime(2026, 10, 20, tzinfo=UTC)
    boundary = cursor - updates.timedelta(minutes=2) + updates.timedelta(days=7)
    calls = []
    def http(url, headers):
        calls.append(url)
        return response(nvd_page(0, ["CVE-2026-1000"], 1, updates._iso(boundary)))
    manifest, _ = updates.build_update_bundle(tmp_path / "delta.zip", state(nvd={"cursor": updates._iso(cursor), "years": [2026]}),
        ["nvd"], tmp_path / "cache", now=datetime(2026, 11, 1, tzinfo=UTC),
        http=http)
    assert len(calls) == 2
    assert len(manifest["sources"][0]["files"]) == 1


def test_source_identity_and_limits_rejected_before_http(tmp_path):
    with pytest.raises(ValueError, match="identity"):
        updates.build_update_bundle(tmp_path / "invalid.zip", state(kev={"validators": {"https://evil.invalid": {"etag": "bad"}}}),
            ["kev"], tmp_path / "cache", http=lambda *args: pytest.fail("unexpected HTTP"))
    with pytest.raises(ValueError, match="500 MiB"):
        updates.build_update_bundle(tmp_path / "invalid.zip", state(), ["kev"], tmp_path / "cache", max_bytes=updates.MAX_BUNDLE_BYTES+1)


def test_changed_attack_snapshot_includes_304_companion_with_digest_verification(tmp_path):
    sources = updates.SNAPSHOTS["attack"]
    json_body = b'{"mapping_objects": []}'
    csv_body = b'CVE ID,Primary Impact,Secondary Impact,Exploitation Technique\nCVE-2026-1000,,,T1190\n'
    old_csv = {"etag": "csv-v1", "sha256": hashlib.sha256(csv_body).hexdigest()}
    initial = state(attack={"validators": {sources[1][1]: old_csv}})
    requested = []
    def http(url, headers):
        requested.append((url, headers))
        if url == sources[0][1]:
            return response(json_body, ETag="json-v2")
        return response(b"", 304) if headers else response(csv_body)
    manifest, _ = updates.build_update_bundle(tmp_path / "attack.zip", initial, ["attack"], tmp_path / "cache", http=http)
    assert len(manifest["sources"][0]["files"]) == 2
    assert len(requested) == 3


def test_powershell_updates_forwards_checkpoint_in_network_isolated_container(tmp_path):
    import shutil
    image = "mcr.microsoft.com/powershell:lts-alpine-3.20"
    if not shutil.which("docker") or subprocess.run(["docker", "image", "inspect", image], capture_output=True, check=False).returncode:
        pytest.skip("PowerShell test image unavailable")
    root = Path(__file__).resolve().parents[3]
    binary = tmp_path / "python3"
    binary.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > /out/args\nexit 17\n')
    binary.chmod(0o755)
    result = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v",
        str(root / "frontend/public/vm") + ":/s:ro", "-v", str(tmp_path) + ":/out",
        "-e", "PATH=/out:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", image,
        "pwsh", "-NoProfile", "-File", "/s/download-references.ps1", "-Mode", "Updates",
        "-State", "/out/state.json", "-Out", "/out/delta.zip", "-Skip", "nvd,epss,kev,exploitdb,msf,attack",
        "-NoProxy"], capture_output=True, text=True, check=False, timeout=30)
    assert result.returncode == 17, result.stdout + result.stderr
    arguments = (tmp_path / "args").read_text().splitlines()
    assert arguments[0] == "/s/ref_updates.py"
    assert arguments[arguments.index("--sources") + 1:] == ["ghsa", "--no-proxy"]
    assert arguments[arguments.index("--state") + 1] == "/out/state.json"


def test_ghsa_numeric_revision_is_rejected_before_git(tmp_path):
    revision = 1111111111111111111111111111111111111111
    with pytest.raises(ValueError, match="revision"):
        updates.validate_checkpoint("ghsa", {"revision": revision})
    with pytest.raises(ValueError, match="checkpoint"):
        updates.GitAdvisorySource(tmp_path).changes(revision)
    assert not (tmp_path / "ghsa.git").exists()


@pytest.mark.parametrize("proxies", [{}, {"https": "http://user:secret@proxy.invalid:3128"}])
def test_explicit_proxy_policy_applies_to_http_and_git_without_argv_secrets(tmp_path, monkeypatch, proxies):
    import os
    from types import SimpleNamespace
    monkeypatch.setenv("HTTPS_PROXY", "http://old-proxy.invalid:3128")
    monkeypatch.setenv("all_proxy", "http://old-proxy.invalid:3129")
    observed = {}
    def opener(handler):
        observed["http_proxies"] = handler.proxies
        return SimpleNamespace(open=lambda *args, **kwargs: None)
    def process(args, **kwargs):
        observed["args"] = args
        observed["env"] = kwargs["env"]
        return SimpleNamespace(poll=lambda: 0, returncode=0)
    monkeypatch.setattr(updates, "build_opener", opener)
    monkeypatch.setattr(updates.subprocess, "Popen", process)
    updates.HttpClient(proxies=proxies)
    updates.GitAdvisorySource(tmp_path, proxies=proxies)._git("version")
    assert observed["http_proxies"] == proxies
    assert "HTTPS_PROXY" not in observed["env"] and "all_proxy" not in observed["env"]
    assert observed["env"].get("https_proxy") == proxies.get("https")
    config = {observed["env"][f"GIT_CONFIG_KEY_{i}"]: observed["env"][f"GIT_CONFIG_VALUE_{i}"]
              for i in range(int(observed["env"]["GIT_CONFIG_COUNT"]))}
    assert config["http.proxy"] == proxies.get("https", "")
    assert config["remote.origin.proxy"] == proxies.get("https", "")
    assert all("secret" not in arg for arg in observed["args"])
    assert os.environ["HTTPS_PROXY"] == "http://old-proxy.invalid:3128"


def test_cli_no_proxy_reaches_shared_builder(tmp_path, monkeypatch):
    exported = tmp_path / "state.json"
    exported.write_text(json.dumps(state(ghsa={"revision": "a" * 40})))
    observed = {}
    def build(path, initial, sources, cache, progress, **kwargs):
        observed.update(kwargs)
        path.write_bytes(b"archive")
        return {"sources": [{"name": "ghsa", "mode": "unchanged"}]}, initial
    monkeypatch.setattr(updates, "build_update_bundle", build)
    updates.run_cli(["--state", str(exported), "--out", str(tmp_path / "out.zip"), "--sources", "ghsa", "--no-proxy"])
    assert observed["proxies"] == {}


def test_nvd_checkpoint_supports_pre_2002_cve_years_from_oldest_feed(tmp_path):
    # nvdcve-2002 contains CVEs whose identifiers start in 1999, 2000 and 2001.
    years = [1999, 2000, 2001, 2002]
    identifiers = [f"CVE-{year}-1000" for year in years]
    initial = state(nvd={"cursor": "2026-11-01T00:00:00Z", "years": years})
    manifest, target = updates.build_update_bundle(tmp_path / "early-cves.zip", initial, ["nvd"], tmp_path / "cache",
        now=datetime(2026, 11, 2, tzinfo=UTC), http=lambda *args: response(nvd_page(0,
            [*identifiers, "CVE-2026-1000"], 5, "2026-11-01T12:00:00Z")))
    assert target["sources"]["nvd"]["years"] == years
    assert manifest["sources"][0]["mode"] == "delta"
    with zipfile.ZipFile(tmp_path / "early-cves.zip") as archive:
        rows = json.loads(archive.read(manifest["sources"][0]["files"][0]["path"]))["vulnerabilities"]
    assert [row["cve"]["id"] for row in rows] == identifiers
    with pytest.raises(ValueError, match="checkpoint years"):
        updates.validate_checkpoint("nvd", {"cursor": "2026-11-01T00:00:00Z", "years": [1998]})


@pytest.mark.parametrize("invalid_json,invalid_csv", [
    (b'{"objects": []}', None),
    (b'{"mappings": []}', None),
    (b'{"mapping_objects": [{"capability_id": 123, "attack_object_id": "T1190", "mapping_type": "exploitation_technique"}]}', None),
    (b'{"mapping_objects": [{"capability_id": "CVE-2026-1000", "attack_object_id": "T1190"}]}', None),
    (None, b'CVE,Technique\nCVE-2026-1000,T1190\n'),
    (None, b'cve id,primary impact,secondary impact,exploitation technique\n'),
])
def test_attack_invalid_native_schema_preserves_offline_state(tmp_path, monkeypatch, invalid_json, invalid_csv):
    fixtures = Path(__file__).parent / "fixtures"
    sources = updates.SNAPSHOTS["attack"]
    payloads = {sources[0][1]: invalid_json if invalid_json is not None else (fixtures / "ctid-kev.json").read_bytes(),
                sources[1][1]: invalid_csv if invalid_csv is not None else (fixtures / "attack_to_cve.csv").read_bytes()}
    monkeypatch.setattr(updates, "HttpClient", lambda **kwargs: lambda url, headers: response(payloads[url]))
    exported = tmp_path / "state.json"
    original = json.dumps(state())
    exported.write_text(original)
    output = tmp_path / "invalid.zip"
    with pytest.raises(ValueError, match="ATTACK"):
        updates.run_cli(["--state", str(exported), "--out", str(output), "--sources", "attack"])
    assert exported.read_text() == original
    assert not output.exists()


def test_attack_native_ctid_fixture_snapshot_remains_supported(tmp_path):
    fixtures = Path(__file__).parent / "fixtures"
    sources = updates.SNAPSHOTS["attack"]
    payloads = {sources[0][1]: (fixtures / "ctid-kev.json").read_bytes(),
                sources[1][1]: (fixtures / "attack_to_cve.csv").read_bytes()}
    manifest, target = updates.build_update_bundle(tmp_path / "native.zip", state(), ["attack"], tmp_path / "cache",
        http=lambda url, headers: response(payloads[url]))
    assert manifest["sources"][0]["mode"] == "snapshot"
    assert len(manifest["sources"][0]["files"]) == 2
    assert set(target["sources"]["attack"]["validators"]) == set(payloads)


@pytest.mark.parametrize("mapping,csv_row", [
    (None, ""),
    ({"capability_id": "CVE-2026-1000", "attack_object_id": "T1190", "mapping_type": "unsupported"}, ""),
    ({"capability_id": "CVE-2026-1000", "attack_object_id": "unknown", "mapping_type": "primary_impact"}, ""),
    (None, "not-a-cve,T1190,,\n"),
])
def test_attack_no_usable_mapping_keeps_archive_and_offline_state_unchanged(tmp_path, monkeypatch, mapping, csv_row):
    sources = updates.SNAPSHOTS["attack"]
    payloads = {sources[0][1]: json.dumps({"mapping_objects": [mapping] if mapping else []}).encode(),
                sources[1][1]: ("CVE ID,Primary Impact,Secondary Impact,Exploitation Technique\n" + csv_row).encode()}
    monkeypatch.setattr(updates, "HttpClient", lambda **kwargs: lambda url, headers: response(payloads[url]))
    exported = tmp_path / "state.json"
    original = json.dumps(state())
    exported.write_text(original)
    output = tmp_path / "empty.zip"
    with pytest.raises(ValueError, match="supported ATTACK"):
        updates.run_cli(["--state", str(exported), "--out", str(output), "--sources", "attack"])
    assert exported.read_text() == original
    assert not output.exists()


@pytest.mark.parametrize("empty_component", ["json", "csv"])
def test_attack_one_empty_component_is_allowed_if_other_has_mappings(tmp_path, empty_component):
    fixtures = Path(__file__).parent / "fixtures"
    sources = updates.SNAPSHOTS["attack"]
    payloads = {sources[0][1]: b'{"mapping_objects": []}' if empty_component == "json" else (fixtures / "ctid-kev.json").read_bytes(),
                sources[1][1]: b'CVE ID,Primary Impact,Secondary Impact,Exploitation Technique\n' if empty_component == "csv" else (fixtures / "attack_to_cve.csv").read_bytes()}
    manifest, _ = updates.build_update_bundle(tmp_path / "usable.zip", state(), ["attack"], tmp_path / "cache",
        http=lambda url, headers: response(payloads[url]))
    assert manifest["sources"][0]["mode"] == "snapshot"
    assert len(manifest["sources"][0]["files"]) == 2
