"""Native STools reference and news/rule archives for the unified downloader."""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import zipfile
from pathlib import Path

import ref_updates
import ref_window
from offline_http import Transport


def intel_module():
    path = Path(__file__).with_name("intel_downloader.py")
    if not path.exists():
        raise ValueError(
            "Missing intel_downloader.py; unpack the complete download kit"
        )
    spec = importlib.util.spec_from_file_location("stools_intel", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def full_reference(
    name: str, output: Path, transport: Transport, now: dt.datetime, progress
) -> dict:
    if name == "nvd":
        files = [
            (
                f"nvdcve-2.0-{year}.json.gz",
                f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz",
            )
            for year in range(2002, now.year + 1)
        ]
    elif name == "ghsa":
        files = [
            (
                "advisory-database.zip",
                "https://codeload.github.com/github/advisory-database/zip/refs/heads/main",
            )
        ]
    else:
        files = ref_updates.SNAPSHOTS[name]
    with tempfile.TemporaryDirectory(prefix=".full-", dir=output.parent) as directory:
        temporary = Path(directory) / "archive.zip"
        with zipfile.ZipFile(
            temporary, "w", zipfile.ZIP_DEFLATED, compresslevel=6
        ) as archive:
            for filename, url in files:
                progress(filename)
                path = Path(directory) / filename
                transport.download(
                    url,
                    path,
                    limit=(
                        ref_updates.MAX_RESPONSE_BYTES
                        if name in ref_updates.SNAPSHOTS
                        else ref_updates.MAX_BUNDLE_BYTES
                    ),
                    timeout=120,
                )
                if not path.stat().st_size:
                    raise ValueError("empty_source_file: " + filename)
                with path.open("rb") as stream:
                    magic = stream.read(4)
                if filename.endswith(".gz") and not magic.startswith(b"\x1f\x8b"):
                    raise ValueError("invalid_gzip: " + filename)
                if filename.endswith(".zip") and not magic.startswith(b"PK"):
                    raise ValueError("invalid_zip: " + filename)
                if name in ref_updates.SNAPSHOTS:
                    ref_updates._validate_snapshot(name, filename, path.read_bytes())
                archive.write(path, filename)
                path.unlink()
        if temporary.stat().st_size > ref_updates.MAX_BUNDLE_BYTES:
            raise ValueError("Full reference archive exceeds the STools500MiB limit")
        os.link(temporary, output)
    return {
        "status": "ok",
        "archive": output.name,
        "files": len(files),
        "bytes": output.stat().st_size,
        "import_section": "VM / References",
    }


def _write_intel(output, results, module, now, progress):
    reports, diagnostics = [], []
    digest = hashlib.sha256()
    count = size = 0
    with tempfile.TemporaryFile() as stream:
        for report, rows, extra in results:
            report["items"] = len(rows)
            reports.append(report)
            diagnostics.append({"id": report["id"], **extra})
            progress(f"{report['name']}: {report['status']}, {len(rows)}")
            for row in rows:
                line = (json.dumps(row, ensure_ascii=False) + "\n").encode()
                size += len(line)
                count += 1
                if size > module.MAX_DATA or count > module.MAX_ITEMS:
                    raise ValueError("News/rule archive exceeds STools limits")
                stream.write(line)
                digest.update(line)
        if not count and all(source["status"] == "error" for source in reports):
            return {
                "status": "error",
                "error": "all_sources_failed",
                "sources": reports,
                "diagnostics": diagnostics,
            }
        manifest = {
            "format": "stools-th-intel",
            "version": 1,
            "generated_at": now.isoformat(),
            "items_count": count,
            "items_sha256": digest.hexdigest(),
            "sources": reports,
        }
        stream.seek(0)
        with tempfile.TemporaryDirectory(
            prefix=".intel-", dir=output.parent
        ) as directory:
            temporary = Path(directory) / "archive.zip"
            with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(
                    "manifest.json", json.dumps(manifest, ensure_ascii=False)
                )
                with archive.open("items.jsonl", "w") as target:
                    while chunk := stream.read(1024 * 1024):
                        target.write(chunk)
            if temporary.stat().st_size > 64 * 1024 * 1024:
                raise ValueError("News/rule ZIP exceeds STools64MiB limit")
            os.link(temporary, output)
    return {
        "status": "partial" if any(s["status"] != "ok" for s in reports) else "ok",
        "archive": output.name,
        "bytes": output.stat().st_size,
        "items": count,
        "sources": reports,
        "diagnostics": diagnostics,
        "import_section": "VM / News archive",
    }


def _period_news(source, module, transport, mode, since, until):
    report, rows = module.collect_source(
        source, days=0, articles=False, maximum=200, timeout=20, fetcher=transport.fetch
    )
    extra = {"excluded_undated": 0, "excluded_outside_period": 0}
    if mode == "updates":
        selected = []
        for row in rows:
            if not row["published_at"]:
                extra["excluded_undated"] += 1
                continue
            published = dt.datetime.fromisoformat(
                row["published_at"].replace("Z", "+00:00")
            )
            if since < published <= until:
                selected.append(row)
            else:
                extra["excluded_outside_period"] += 1
        rows = selected
        if extra["excluded_undated"]:
            if report["status"] == "ok":
                report["status"] = "partial"
            report["error"] = (
                report.get("error", "")
                + f"; undated items excluded: {extra['excluded_undated']}"
            ).strip("; ")[:1000]
    return report, rows, extra


def _period_rules(source, module, transport, cache, since, until, progress):
    suffixes = (".toml",) if source["format"] == "elastic" else (".yml", ".yaml")
    git = ref_window.GitWindowSource(
        cache,
        progress,
        remote=f"https://github.com/{source['repository']}.git",
        ref=source["ref"],
        prefixes=tuple(source["prefixes"]),
        path_filter=lambda path: path.endswith(suffixes),
        proxies=transport.git_proxies(),
    )
    http = ref_updates.HttpClient(opener=transport.open, progress=progress)
    changes = git.changes(since, until, http)
    report = {
        "id": source["id"],
        "name": source["name"],
        "kind": "rule",
        "url": "https://github.com/" + source["repository"],
        "status": "ok",
        "items": 0,
        "revision": changes.target_revision,
        "license_url": f"https://github.com/{source['repository']}/blob/{changes.target_revision}/{source['license_file']}",
    }
    deleted = changes.deleted
    extra = {
        "deleted_paths": deleted,
        "base_revision": changes.base_revision,
        "target_revision": changes.target_revision,
    }
    if deleted:
        report["status"] = "partial"
        report["error"] = (
            f"{len(deleted)} rules removed upstream; paths in report.json; existing reference materials are retained"
        )
    if not changes.changed:
        return report, [], extra
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        total = 0
        for path in changes.changed:
            raw = transport.fetch(
                git.raw_url(changes.target_revision, path), module.MAX_TEXT, 30
            )
            total += len(raw)
            if total > module.MAX_DATA:
                raise ValueError("Changed rules exceed STools archive limit")
            archive.writestr("repository/" + path, raw)
        license_path = source["license_file"]
        archive.writestr(
            "repository/" + license_path,
            transport.fetch(
                git.raw_url(changes.target_revision, license_path), 100_000, 30
            ),
        )
    rows, license_text = module.parse_rules(
        buffer.getvalue(), source, changes.target_revision
    )
    report["license_text"] = license_text
    return report, rows, extra


def intel_archive(
    name, output, transport, mode, period, now, cache, progress, *, module=None
):
    module = module or intel_module()
    source_id = "sigmahq" if name == "sigma" else name
    sources = [
        source
        for source in module.DEFAULT_SOURCES
        if (source["kind"] == "rss" if name == "news" else source["id"] == source_id)
    ]
    if not sources:
        raise ValueError("No sources selected")
    since, until = (
        ref_window.period_bounds(period, now) if mode == "updates" else (None, now)
    )

    def job(source):
        if source["kind"] == "rss":
            return _period_news(source, module, transport, mode, since, until)
        if mode == "updates":
            return _period_rules(
                source, module, transport, cache, since, until, progress
            )
        report, rows = module.collect_source(
            source,
            days=0,
            articles=False,
            maximum=200,
            timeout=30,
            fetcher=transport.fetch,
        )
        return report, rows, {}

    def results():
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(4, len(sources))
        ) as pool:
            remaining = iter(sources)
            pending = {
                pool.submit(job, source)
                for source in [
                    next(remaining, None) for _ in range(min(4, len(sources)))
                ]
                if source
            }
            while pending:
                ready, pending = concurrent.futures.wait(
                    pending, return_when=concurrent.futures.FIRST_COMPLETED
                )
                for future in ready:
                    yield future.result()
                    source = next(remaining, None)
                    if source:
                        pending.add(pool.submit(job, source))

    result = _write_intel(output, results(), module, now, progress)
    if since is not None:
        result["window"] = {"since": since.isoformat(), "until": until.isoformat()}
    return result


def execute_dataset(name, config, run_dir, progress):
    now = config.as_of
    cache = config.output / ".stools-cache" / name
    transport = Transport(no_proxy=config.no_proxy, progress=progress)
    output = run_dir / (name + "-" + config.mode + ".zip")
    if name in ("news", "sigma", "elastic"):
        return intel_archive(
            name, output, transport, config.mode, config.period, now, cache, progress
        )
    if config.mode == "full":
        return full_reference(name, output, transport, now, progress)
    manifest = ref_window.build_window_bundle(
        output,
        [name],
        cache,
        period=config.period,
        now=now,
        progress=progress,
        http=ref_updates.HttpClient(opener=transport.open, progress=progress),
        proxies=transport.git_proxies() if name == "ghsa" else None,
    )
    entry = manifest["sources"][0]
    return {
        "status": "ok",
        "archive": output.name,
        "bytes": output.stat().st_size,
        "window": manifest["window"],
        "source_mode": entry["mode"],
        "files": len(entry["files"]),
        "deleted_ids": len(entry["deleted_ids"]),
        "import_section": "VM / References",
    }
