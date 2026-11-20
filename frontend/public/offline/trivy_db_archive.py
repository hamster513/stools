"""Portable ZIP envelope for the official Trivy vulnerability database OCI layer."""

import hashlib
import json
import os
import re
import tempfile
import zipfile
from pathlib import Path

MANIFEST = "trivy-manifest.json"
LAYER = "db.tar.gz"
MAX_MANIFEST = 64 * 1024
MAX_LAYER = 500 * 1024**2 - MAX_MANIFEST - 4096
LAYER_TYPE = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"


def layer_descriptor(raw: bytes) -> tuple[str, int]:
    if len(raw) > MAX_MANIFEST:
        raise ValueError("Oversized Trivy manifest")
    try:
        doc = json.loads(raw)
        if doc["schemaVersion"] != 2 or len(doc["layers"]) != 1:
            raise ValueError
        layer = doc["layers"][0]
        digest, size = layer["digest"], layer["size"]
        if (layer["mediaType"] != LAYER_TYPE or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
                or type(size) is not int or not 0 < size <= MAX_LAYER):
            raise ValueError
    except (KeyError, IndexError, TypeError, ValueError, RecursionError):
        raise ValueError("Некорректный манифест базы уязвимостей Trivy v2") from None
    return digest[7:], size


def copy_verified(source, target, digest: str, size: int) -> None:
    checksum = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = source.read(min(1024**2, remaining))
        if not chunk:
            break
        checksum.update(chunk)
        target.write(chunk)
        remaining -= len(chunk)
    if remaining or source.read(1) or checksum.hexdigest() != digest:
        raise ValueError("Размер или SHA-256 базы Trivy не совпадает с официальным манифестом")


REGISTRIES = (
    "https://mirror.gcr.io/v2/aquasec/trivy-db",
    "https://ghcr.io/v2/aquasecurity/trivy-db",
)
TOKEN_URL = "https://ghcr.io/token?service=ghcr.io&scope=repository%3Aaquasecurity%2Ftrivy-db%3Apull"


def _pack(path, raw, blob, digest, size):
    with blob.open("rb") as source, zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr(MANIFEST, raw)
        with archive.open(LAYER, "w") as target:
            copy_verified(source, target, digest, size)


def download_database(output: Path, cache: Path, transport, progress, lang: str, *, active_digest: str | None = None) -> dict:
    cache.mkdir(parents=True, exist_ok=True)
    saved = cache / LAYER
    headers = {"Accept": "application/vnd.oci.image.manifest.v1+json"}
    for base in REGISTRIES:
        with tempfile.TemporaryDirectory(dir=output.parent) as dirname:
            work = Path(dirname)
            try:
                auth = {}
                if base == REGISTRIES[1]:
                    response = json.loads(transport.fetch(TOKEN_URL, MAX_MANIFEST, 60))
                    token = response.get("token") if isinstance(response, dict) else None
                    if not isinstance(token, str) or not token or not token.isascii() or not token.isprintable():
                        raise ValueError("Invalid registry token")
                    auth["Authorization"] = "Bearer " + token
                manifest = work / MANIFEST
                transport.download(base + "/manifests/2", manifest, headers=headers | auth,
                                   limit=MAX_MANIFEST, timeout=60)
                raw = manifest.read_bytes()
                digest, size = layer_descriptor(raw)
                if active_digest == digest:
                    return {"status": "unchanged", "sha256": digest}
                cached = False
                if saved.exists() and saved.stat().st_size == size:
                    try:
                        _pack(work / "archive.zip", raw, saved, digest, size)
                        cached = True
                    except (FileNotFoundError, ValueError):
                        pass
                if not cached:
                    blob = work / LAYER
                    transport.download(base + "/blobs/sha256:" + digest, blob, headers=auth,
                                       limit=size, timeout=600)
                    _pack(work / "archive.zip", raw, blob, digest, size)
                    try:
                        os.replace(blob, saved)
                    except PermissionError:
                        # A second Windows process may still be reading the previous cached layer.
                        pass
                os.replace(work / "archive.zip", output)
                return {"status": "ok", "archive": output.name, "bytes": output.stat().st_size,
                        "source_mode": "snapshot", "sha256": digest, "cached": cached,
                        "import_section": "VM / References"}
            except (OSError, ValueError):
                if base == REGISTRIES[-1]:
                    raise
                progress("Trivy: пробуем официальный резервный реестр GHCR"
                         if lang == "ru" else "Trivy: trying the official GHCR registry")
    raise RuntimeError("Trivy registry unavailable")
