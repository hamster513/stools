"""Portable offline snapshots of official distribution OVAL advisories."""

import datetime as dt
import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path
from xml.parsers import expat

MANIFEST = "vendor-oval.json"
MAX_MANIFEST = 32 * 1024
MAX_XML = 256 * 1024**2
ASTRA_BASE = "https://dl.astralinux.ru/astra/oval"
ASTRA_META = ASTRA_BASE + "/oval_meta.json"
ASTRA_TARGETS = {"1.7": "x86-64", "1.8": "x86-64", "3.8": "s390x", "4.7": "arm", "4.8": "arm"}
FEEDS = {
    "redos-7.3": "https://redos.red-soft.ru/support/secure/7.3/redos.xml",
    "redos-8": "https://redos.red-soft.ru/support/secure/8.0/redos.xml",
    **{f"astra-{v}": f"{ASTRA_BASE}/{v}_{arch}/oval-definitions-alse-{v}.xml"
       for v, arch in ASTRA_TARGETS.items()},
}
OVAL = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
GENERATOR = "http://oval.mitre.org/XMLSchema/oval-common-5"


def inspect_xml(source, profile, target=None):
    """Check the feed identity and branch and hash bounded XML without constructing a DOM."""
    vendor, version = profile.split("-")
    product = "The OVAL Astra Linux" if vendor == "astra" else "RED OS security oval"
    platform = "Astra Linux " + version if vendor == "astra" else "RED OS " + ("8.0" if version == "8" else version)
    root = OVAL + "}oval_definitions"
    path = []
    parts = []
    fields = {}
    count = matched = size = 0
    digest = hashlib.sha256()

    def invalid(*_):
        raise ValueError(f"Некорректный OVAL {profile}")

    def start(name, attrs):
        nonlocal count
        path.append(name)
        if len(path) > 64 or path[0] != root:
            invalid()
        if len(path) == 3 and name == OVAL + "}definition" and path[1] == OVAL + "}definitions":
            if not attrs.get("id", "").startswith(f"oval:{vendor}:def:"):
                invalid()
            count += 1
        parts.clear()

    def characters(value):
        if path[-1] in (GENERATOR + "}product_name", GENERATOR + "}timestamp", OVAL + "}platform"):
            if sum(map(len, parts)) + len(value) > 256:
                invalid()
            parts.append(value)

    def end(name):
        nonlocal matched
        if len(path) == 3 and path[1] == OVAL + "}generator" and name.startswith(GENERATOR + "}"):
            fields[name.rsplit("}", 1)[1]] = "".join(parts).strip()
        if name == OVAL + "}platform" and path[-2] == OVAL + "}affected":
            if "".join(parts).strip() != platform:
                invalid()
            matched += 1
        parts.clear()
        path.pop()

    parser = expat.ParserCreate(namespace_separator="}")
    parser.StartDoctypeDeclHandler = invalid
    parser.StartElementHandler = start
    parser.CharacterDataHandler = characters
    parser.EndElementHandler = end
    try:
        while block := source.read(256 * 1024):
            size += len(block)
            if size > MAX_XML:
                invalid()
            parser.Parse(block, False)
            digest.update(block)
            if target is not None:
                target.write(block)
        parser.Parse(b"", True)
        stamp = dt.datetime.fromisoformat(fields["timestamp"])
        if not count or not matched or fields["product_name"] != product or stamp.utcoffset() is None:
            invalid()
    except (KeyError, TypeError, expat.ExpatError, OverflowError) as exc:
        raise ValueError(f"Некорректный OVAL {profile}") from exc
    return {"url": FEEDS[profile], "sha256": digest.hexdigest(), "bytes": size,
            "updated_at": stamp.astimezone(dt.UTC).isoformat(), "definitions": count}


def read_manifest(archive):
    info = archive.getinfo(MANIFEST) if MANIFEST in archive.namelist() else None
    if info is None or info.file_size > MAX_MANIFEST or info.flag_bits & 1:
        raise ValueError("Повреждён каталог OVAL")
    doc = json.loads(archive.read(info))
    if (not isinstance(doc, dict) or doc.get("format") != "stools-vendor-oval" or doc.get("version") != 1
            or not isinstance(doc.get("feeds"), dict) or set(doc["feeds"]) != set(FEEDS)):
        raise ValueError("Неполный каталог OVAL")
    names = {p + ".xml" for p in FEEDS} | {MANIFEST}
    if len(archive.infolist()) != len(names) or set(archive.namelist()) != names:
        raise ValueError("Неизвестные или повторяющиеся файлы OVAL")
    for profile, item in doc["feeds"].items():
        entry = archive.getinfo(profile + ".xml")
        if (not isinstance(item, dict) or item.get("url") != FEEDS[profile] or not 0 < entry.file_size <= MAX_XML
                or entry.file_size != item.get("bytes") or entry.flag_bits & 1
                or entry.compress_type not in (zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED)):
            raise ValueError(f"Некорректный файл OVAL {profile}")
    return doc["feeds"]


def _astra_checksums(raw):
    import re

    digests = {}
    try:
        for platform in json.loads(raw)["platforms"]:
            for target in platform["targets"]:
                branch = target["target"].split("_", 1)[0]
                key = "astra-" + branch
                if key not in FEEDS:
                    continue
                if (target["target"] != f"{branch}_{ASTRA_TARGETS[branch]}" or target["url"] != FEEDS[key]
                        or not re.fullmatch("[0-9a-f]{64}", target["sha256sum"]) or key in digests):
                    raise ValueError
                digests[key] = target["sha256sum"]
        if len(digests) != len(ASTRA_TARGETS):
            raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError) as exc:
        raise ValueError("Недействительный официальный каталог OVAL Astra Linux") from exc
    return digests


def download_archive(output: Path, cache: Path, transport, progress) -> dict:
    """Astra publishes SHA-256. RED publishes XML directly over HTTPS."""
    cache.mkdir(parents=True, exist_ok=True)
    digests = _astra_checksums(transport.fetch(ASTRA_META, MAX_MANIFEST, 60))
    items = {}
    with tempfile.TemporaryDirectory(dir=output.parent) as dirname:
        work = Path(dirname)
        dest = work / "oval.zip"
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for profile, url in FEEDS.items():
                progress(f"OVAL · {profile}")
                expected = digests.get(profile)
                cached = cache / (profile + ".xml")
                valid = False
                if expected and cached.is_file() and 0 < cached.stat().st_size <= MAX_XML:
                    with cached.open("rb") as source:
                        valid = hashlib.file_digest(source, "sha256").hexdigest() == expected
                path = cached if valid else work / (profile + ".xml")
                if not valid:
                    transport.download(url, path, headers={}, limit=MAX_XML, timeout=600)
                with path.open("rb") as source, archive.open(profile + ".xml", "w") as target:
                    items[profile] = inspect_xml(source, profile, target)
                if expected and items[profile]["sha256"] != expected:
                    raise ValueError(f"SHA-256 OVAL {profile} отличается от каталога Astra Linux")
                if expected and not valid:
                    os.replace(path, cached)
                if not expected:
                    path.unlink()
            archive.writestr(MANIFEST, json.dumps({"format": "stools-vendor-oval", "version": 1, "feeds": items}))
        os.replace(dest, output)
    return {"status": "ok", "archive": output.name, "bytes": output.stat().st_size, "files": len(items),
            "source_mode": "snapshot", "import_section": "VM / References"}
