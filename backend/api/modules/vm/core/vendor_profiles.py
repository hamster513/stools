"""Native SBOM identities and the upstream scan profiles used to look for leads."""

import re
from dataclasses import dataclass

from packageurl import PackageURL

from .host_sbom import UNASSESSED

# Astra's edition/release table, not the host's kernel or the suffix of a DEB.
_DEBIAN = {
    "1.3": "7", "1.4": "7", "1.5": "7", "1.6": "9", "7.6": "9", "2.12": "9",
    "1.7": "10", "4.7": "10", "7.7": "10", "1.8": "12", "3.8": "12", "4.8": "12",
}


@dataclass(frozen=True)
class VendorProfile:
    feed: str
    os: str
    version: str
    label: str


def upstream_profile(family: str, release: str) -> VendorProfile | None:
    if not re.fullmatch(r"\d+(?:\.\d+)*", release):
        return None
    series = ".".join(release.split(".")[:2])
    major = release.split(".")[0]
    if family == "redos" and major in {"7", "8"}:
        feed = "redos-8" if series in {"8", "8.0"} else f"redos-{series}"
        return VendorProfile(feed, "redhat", major, f"RHEL {major}")
    if family == "astra" and series in _DEBIAN:
        version = _DEBIAN[series]
        return VendorProfile(f"astra-{series}", "debian", version, f"Debian {version}")
    return None


def scan_document(bom: dict, profile: VendorProfile) -> tuple[dict, dict]:
    """Keep BOM references stable. Only the temporary scanner input uses upstream names."""
    root = bom["metadata"]["component"]
    family = root["name"]
    native = {}
    projected = []
    for component in bom["components"]:
        props = {p["name"]: p["value"] for p in component.get("properties", ())}
        if component.get("purl") and props.get(UNASSESSED) == "unsupported-distribution":
            url = PackageURL.from_string(component["purl"])
            if url.namespace == family and url.type == {"redos": "rpm", "astra": "deb"}[family]:
                qualifiers = {**url.qualifiers, "distro": f"{profile.os}-{profile.version}"}
                proxy = url._replace(namespace=profile.os, qualifiers=qualifiers)
                native[component["bom-ref"]] = {
                    "name": component["name"], "version": component["version"], "purl": component["purl"],
                    "arch": url.qualifiers.get("arch", ""), "source_name": props.get("aquasecurity:trivy:SrcName", ""),
                }
                component = {**component, "purl": proxy.to_string(),
                             "properties": [p for p in component["properties"] if p["name"] != UNASSESSED]}
        projected.append(component)
    metadata = {**bom["metadata"], "component": {**root, "name": profile.os, "version": profile.version}}
    return {**bom, "metadata": metadata, "components": projected}, native


def observed_arch(bom: dict) -> str:
    return next((p["value"] for p in bom["metadata"].get("properties", ()) if p["name"] == "stools:host-arch"), "")
