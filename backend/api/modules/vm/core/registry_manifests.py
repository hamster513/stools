"""Resolve runnable image identities from verified Harbor registry manifests.

OCI manifest/config references: https://github.com/opencontainers/image-spec/blob/main/manifest.md
Only the configured Harbor origin is contacted, including authentication.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import quote

import httpx

from api.limits import ResponseTooLarge, read_limited
from api.modules.vm.core.harbor import BAD_FORMAT, HarborError

MAX_MANIFESTS = 128
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
ACCEPT = (
    "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"
)
CONFIG_TYPES = {"application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json"}


def image_ids(client: Any, project: str, repository: str, digest: str) -> list[str]:
    root = client.base.removesuffix("/api/v2.0")
    name = f"{project}/{repository}"
    if any(part in {"", ".", ".."} for part in name.split("/")) or "\\" in name:
        raise HarborError(BAD_FORMAT)

    def request(path: str, *, token: str = "", params: dict[str, str] | None = None,
                login: bool = False) -> tuple[int, httpx.Headers, bytes]:
        headers = {"Accept": ACCEPT if not login else "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        auth = (client.conn.robot_name, client.conn.robot_secret) if login else None
        try:
            with client.http.stream("GET", root + path, headers=headers, params=params, auth=auth, follow_redirects=False) as response:
                body = read_limited(response, MAX_MANIFEST_BYTES)
                return response.status_code, response.headers, body
        except (httpx.HTTPError, httpx.InvalidURL, ResponseTooLarge) as exc:
            raise HarborError("MANIFEST_UNAVAILABLE") from exc

    def manifest(ref: str) -> dict[str, Any]:
        if not DIGEST.fullmatch(ref):
            raise HarborError(BAD_FORMAT)
        path = f"/v2/{quote(name, safe='/')}/manifests/{ref}"
        status, headers, body = request(path, token=client._registry_tokens.get(name, ""))
        if status == 401:
            challenge = headers.get("WWW-Authenticate", "")
            service = re.search(r'\bservice="([^"\r\n]+)"', challenge, re.IGNORECASE)
            if not challenge.lower().startswith("bearer ") or not service:
                raise HarborError("MANIFEST_AUTH", 401)
            # The advertised realm is untrusted: credentials stay on configured Harbor.
            status, _, token_body = request("/service/token", login=True,
                                            params={"service": service[1], "scope": f"repository:{name}:pull"})
            if status != 200:
                raise HarborError(f"MANIFEST_AUTH_HTTP_{status}", status)
            try:
                payload = json.loads(token_body)
                token = payload.get("token") or payload.get("access_token")
                if not isinstance(token, str) or not token or len(token) > 32768:
                    raise ValueError("invalid token")
            except (ValueError, AttributeError) as exc:
                raise HarborError(BAD_FORMAT) from exc
            client._registry_tokens[name] = token
            status, _, body = request(path, token=token)
        if status != 200:
            raise HarborError(f"MANIFEST_HTTP_{status}", status)
        if "sha256:" + hashlib.sha256(body).hexdigest() != ref:
            raise HarborError("MANIFEST_DIGEST_MISMATCH")
        try:
            obj = json.loads(body)
        except ValueError as exc:
            raise HarborError(BAD_FORMAT) from exc
        if not isinstance(obj, dict) or obj.get("schemaVersion") != 2:
            raise HarborError(BAD_FORMAT)
        return obj

    seen: set[str] = set()
    pending = [digest]
    configs: set[str] = set()
    while pending:
        ref = pending.pop()
        if ref in seen:
            continue
        if len(seen) >= MAX_MANIFESTS:
            raise HarborError("MANIFEST_LIMIT")
        obj = manifest(ref)
        seen.add(ref)
        if "manifests" in obj:
            if not isinstance(obj["manifests"], list) or not obj["manifests"]:
                raise HarborError(BAD_FORMAT)
            for child in obj["manifests"]:
                if not isinstance(child, dict):
                    raise HarborError(BAD_FORMAT)
                platform = child.get("platform") or {}
                if isinstance(platform, dict) and platform.get("os") == "unknown":
                    continue  # provenance/SBOM attestations are not runnable images
                child_digest = child.get("digest")
                if not isinstance(child_digest, str) or not DIGEST.fullmatch(child_digest):
                    raise HarborError(BAD_FORMAT)
                pending.append(child_digest)
        else:
            config = obj.get("config")
            if not isinstance(config, dict) or config.get("mediaType") not in CONFIG_TYPES:
                raise HarborError(BAD_FORMAT)
            config_digest = config.get("digest")
            if not isinstance(config_digest, str) or not DIGEST.fullmatch(config_digest):
                raise HarborError(BAD_FORMAT)
            configs.add(config_digest)
    if not configs:
        raise HarborError(BAD_FORMAT)
    return sorted(seen | configs)
