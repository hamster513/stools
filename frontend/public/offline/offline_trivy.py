"""Download the official Trivy DB layer using the kit's system proxy and transport."""

import json
import os
import tempfile
import zipfile
from pathlib import Path

from trivy_db_archive import (
    LAYER,
    MANIFEST,
    MAX_MANIFEST,
    copy_verified,
    layer_descriptor,
)

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


def download_database(output: Path, cache: Path, transport, progress, lang: str) -> dict:
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
