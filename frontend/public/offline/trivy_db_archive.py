"""Portable ZIP envelope for the official Trivy vulnerability database OCI layer."""

import hashlib
import json
import re

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
