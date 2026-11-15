import datetime as dt
import gzip
import importlib
import importlib.util
import io
import json
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
NOW = dt.datetime(2026, 11, 15, 12, tzinfo=dt.UTC)


@pytest.fixture
def sources(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "frontend/public/offline"))
    monkeypatch.syspath_prepend(str(ROOT / "backend/api/modules/vm/core"))
    sys.modules.pop("offline_sources", None)
    return importlib.import_module("offline_sources")


@pytest.fixture
def intel():
    spec = importlib.util.spec_from_file_location(
        "test_unified_intel", ROOT / "frontend/public/siem/download-intel.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.DEFAULT_SOURCES = [
        {"id": "test-news", "name": "Fixture news", "kind": "rss", "url": "https://example.org/rss"}
    ]
    return module


def test_news_window_exact_no_undated_or_future_materials(sources, intel, tmp_path):
    def item(identifier, published):
        date = f"<pubDate>{published}</pubDate>" if published else ""
        return f"<item><guid>{identifier}</guid><title>{identifier}</title><link>https://example.org/{identifier}</link>{date}</item>"

    rss = (
        "<rss><channel>"
        + "".join(
            [
                item("at-start", "Sat, 14 Nov 2026 12:00:00 GMT"),
                item("new", "Sun, 15 Nov 2026 11:00:00 GMT"),
                item("future", "Mon, 16 Nov 2026 12:00:00 GMT"),
                item("unknown", None),
            ]
        )
        + "</channel></rss>"
    ).encode()
    target = tmp_path / "news.zip"
    result = sources.intel_archive(
        "news",
        target,
        SimpleNamespace(fetch=lambda *_: rss),
        "updates",
        "1d",
        NOW,
        tmp_path,
        lambda _: None,
        module=intel,
    )
    from api.modules.siem.hunting.intel import read_bundle

    manifest, rows = read_bundle(target.read_bytes())
    assert [r.external_id for r in rows] == ["new"] and manifest.items_count == 1
    assert result["status"] == "partial" and result["diagnostics"][0]["excluded_undated"] == 1
    assert result["diagnostics"][0]["excluded_outside_period"] == 2


def test_full_news_retains_old_and_undated_available_history(sources, intel, tmp_path):
    rss = b"<rss><channel><item><guid>old</guid><title>Old</title><link>https://example.org/old</link><pubDate>Tue, 01 Jan 2019 00:00:00 GMT</pubDate></item><item><guid>unknown</guid><link>https://example.org/unknown</link></item></channel></rss>"
    target = tmp_path / "full.zip"
    result = sources.intel_archive(
        "news",
        target,
        SimpleNamespace(fetch=lambda *_: rss),
        "full",
        None,
        NOW,
        tmp_path,
        lambda _: None,
        module=intel,
    )
    from api.modules.siem.hunting.intel import read_bundle

    _, rows = read_bundle(target.read_bytes())
    assert {r.external_id for r in rows} == {"old", "unknown"} and result["status"] == "ok"


def test_full_nvd_preserves_native_filenames_and_all_years(sources, tmp_path):
    calls = []

    def download(url, target, **kwargs):
        calls.append(url)
        target.write_bytes(gzip.compress(json.dumps({"vulnerabilities": []}).encode()))

    target = tmp_path / "nvd.zip"
    result = sources.full_reference(
        "nvd", target, SimpleNamespace(download=download), NOW.replace(year=2004), lambda _: None
    )
    with zipfile.ZipFile(target) as z:
        assert z.namelist() == [f"nvdcve-2.0-{year}.json.gz" for year in (2002, 2003, 2004)]
    assert len(calls) == 3 and result["status"] == "ok"


def test_full_ghsa_preserves_upstream_zip_revision(sources, tmp_path):
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as z:
        z.comment = b"a" * 40
        z.writestr("upstream/README", b"fixture")
    target = tmp_path / "ghsa.zip"
    sources.full_reference(
        "ghsa",
        target,
        SimpleNamespace(download=lambda url, path, **kw: path.write_bytes(raw.getvalue())),
        NOW,
        lambda _: None,
    )
    with zipfile.ZipFile(target) as z:
        assert (
            z.namelist() == ["advisory-database.zip"]
            and z.read("advisory-database.zip") == raw.getvalue()
        )


def test_failed_component_does_not_publish_partial_full_reference(sources, tmp_path):
    def download(url, path, **kw):
        if path.name.endswith(".csv"):
            raise OSError("source down")
        path.write_text('{"mapping_objects": []}')

    target = tmp_path / "attack.zip"
    with pytest.raises(OSError):
        sources.full_reference(
            "attack", target, SimpleNamespace(download=download), NOW, lambda _: None
        )
    assert not target.exists() and not list(tmp_path.glob(".full-*"))


def test_rule_updates_fetch_only_changed_raw_rule_and_license(
    sources, intel, tmp_path, monkeypatch
):
    source = {
        "id": "sigmahq",
        "name": "SigmaHQ",
        "kind": "github",
        "repository": "SigmaHQ/sigma",
        "ref": "master",
        "prefixes": ["rules/"],
        "format": "sigma",
        "license_file": "LICENSE",
    }
    intel.DEFAULT_SOURCES = [source]
    calls = []

    class Git:
        def __init__(self, *args, **kwargs):
            pass

        def changes(self, since, until, http):
            assert (until - since).days == 7
            return SimpleNamespace(
                base_revision="a" * 40,
                target_revision="b" * 40,
                changed=["rules/test.yml"],
                deleted=["rules/old.yml"],
            )

        def raw_url(self, revision, path):
            return f"https://raw.example/{revision}/{path}"

    monkeypatch.setattr(sources.ref_window, "GitWindowSource", Git)

    def fetch(url, *_):
        calls.append(url)
        return (
            b"license fixture"
            if url.endswith("/LICENSE")
            else b"title: Changed\nid: fixture\ndate: 2020/01/01\ntags: [attack.t1059]\n"
        )

    transport = SimpleNamespace(fetch=fetch, open=None, git_proxies=lambda: None)
    target = tmp_path / "rules.zip"
    result = sources.intel_archive(
        "sigma", target, transport, "updates", "7d", NOW, tmp_path, lambda _: None, module=intel
    )
    from api.modules.siem.hunting.intel import read_bundle

    _, rows = read_bundle(target.read_bytes())
    assert len(calls) == 2 and rows[0].external_id == "rules/test.yml"
    assert rows[0].published_at.year == 2020  # File changed now despite older creation date.
    assert (
        result["diagnostics"][0]["deleted_paths"] == ["rules/old.yml"]
        and result["status"] == "partial"
    )


@pytest.mark.parametrize("name", ["kev", "msf", "exploitdb", "attack"])
def test_full_reference_rejects_html_success_responses(sources, tmp_path, name):
    target = tmp_path / (name + ".zip")
    transport = SimpleNamespace(
        download=lambda url, path, **kw: path.write_bytes(b"<html>Proxy error</html>")
    )
    with pytest.raises(ValueError):
        sources.full_reference(name, target, transport, NOW, lambda _: None)
    assert not target.exists()
