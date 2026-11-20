"""CycloneDX 1.6 for observed host software. No vulnerability input is required."""

import json
import re
from collections import defaultdict
from collections.abc import Iterable
from functools import lru_cache
from uuid import NAMESPACE_URL, uuid5

from packageurl import PackageURL

from .software_identity import os_family, windows_product


def bom_bytes(document: dict) -> bytes:
    """The attachment, scanner input and saved digest use the same canonical JSON bytes."""
    return json.dumps(document, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")

# A native package-manager record is identifiable only with an observed distribution.
_DISTROS = (
    ("debian", "deb", r"debian(?: gnu/linux)?"),
    ("ubuntu", "deb", r"ubuntu(?: linux)?"),
    ("alpine", "apk", r"alpine(?: linux)?"),
    ("redhat", "rpm", r"(?:red hat enterprise linux(?: server| workstation)?|rhel|redhat)"),
    ("rocky", "rpm", r"rocky(?: linux)?"),
    ("alma", "rpm", r"alma(?:linux| linux)?"),
    ("oracle", "rpm", r"oracle linux(?: server)?"),
    ("centos", "rpm", r"centos(?: linux)?"),
    ("amazon", "rpm", r"amazon linux"),
    ("sles", "rpm", r"(?:suse linux enterprise server|sles)"),
    ("opensuse-leap", "rpm", r"opensuse[ -]leap"),
    ("photon", "rpm", r"(?:vmware )?photon(?: os)?"),
    ("azurelinux", "rpm", r"(?:microsoft )?azure linux"),
    ("cbl-mariner", "rpm", r"cbl-mariner"),
)
_NATIVE = {"apk", "deb", "rpm"}
_LANG = {"pypi", "npm", "maven", "gem", "cargo", "golang", "nuget", "composer",
         "hex", "pub", "swift", "cocoapods", "conda", "conan"}
_UNKNOWN = {"", "-", "unknown", "n/a", "неизвестно"}
_VAGUE_OS = _UNKNOWN | {"linux", "gnu/linux", "unix"}
_PURL_QUALIFIERS = {"arch", "distro", "epoch", "modularitylabel", "type", "classifier"}
UNASSESSED = "stools:unassessed-reason"

# Only a distribution's own publisher is evidence for an otherwise generic
# package. A matching npm/PyPI name in Trivy never identifies a desktop app.
_DISTRIBUTORS = {
    "debian": {"debian", "debian project", "the debian project"},
    "ubuntu": {"ubuntu", "ubuntu developers", "canonical", "canonical ltd."},
    "alpine": {"alpine linux", "alpine linux development team"},
    "oracle": {"oracle", "oracle corporation"},
    "sles": {"suse", "suse llc"},
}


def lookup_source(distro):
    if not distro or distro[0] not in _DISTRIBUTORS:
        return None
    family, _, version = distro
    label = {"oracle": "Oracle Linux", "sles": "SUSE Linux Enterprise"}.get(family, family)
    width = 1 if family in {"debian", "oracle"} else 2
    release = ".".join(version.split(".")[:width])
    return f"{label} {release}"


def native_candidate(row, distro):
    if not distro or row.get("type", "generic") != "generic" or row.get("purl"):
        return False
    name, version = _text(row.get("name")), _text(row.get("version"))
    return bool(version.casefold() not in _UNKNOWN and re.fullmatch(r"[a-z0-9][a-z0-9+._-]*", name)
                and _text(row.get("publisher")).casefold() in _DISTRIBUTORS.get(distro[0], ())
                and _row_os_matches(_text(row.get("os_name")), distro))


def _text(value):
    return value.strip() if isinstance(value, str) else ""


@lru_cache(maxsize=256)
def _distribution(name):
    for family, kind, pattern in _DISTROS:
        match = re.match(rf"(?:linux )?{pattern}(?: release)?[ -]+v?(\d+(?:\.\d+)*)\b",
                         name, re.IGNORECASE)
        if match:
            return family, kind, match[1]
    return None


def _purl_distribution(purl):
    if not purl or purl.type not in _NATIVE:
        return None
    release = purl.qualifiers.get("distro", "")
    if re.fullmatch(r"\d+(?:\.\d+)*", release) and purl.namespace:
        release = f"{purl.namespace}-{release}"
    return _distribution(release)


def _host_distribution(os_name, rows):
    if distro := _distribution(os_name):
        return distro
    vague = os_name.casefold() in _VAGUE_OS
    family = next((f for f, _, pattern in _DISTROS if re.fullmatch(pattern, os_name, re.IGNORECASE)), "")
    if not vague and not family:
        return None
    observed = set()
    for row in rows:
        if row.get("source") not in {"ksc", "maxpatrol"}:
            continue
        if distro := _distribution(_text(row.get("os_name"))):
            observed.add(distro)
        if raw := _text(row.get("purl")):
            try:
                from_url = _purl_distribution(PackageURL.from_string(raw))
            except ValueError:
                continue
            if from_url:
                observed.add(from_url)
    if len(observed) == 1:
        distro = observed.pop()
        if vague or distro[0] == family:
            return distro
    return None


def _compatible(left, right):
    return left[:2] == right[:2] and (
        left[2] == right[2] or left[2].startswith(right[2] + ".") or right[2].startswith(left[2] + "."))


def _row_os_matches(name, distro):
    if name.casefold() in _VAGUE_OS:
        return True
    if observed := _distribution(name):
        return _compatible(observed, distro)
    return any(family == distro[0] and re.fullmatch(pattern, name, re.IGNORECASE)
               for family, _, pattern in _DISTROS)


def _ref(*values):
    return uuid5(NAMESPACE_URL, json.dumps(values, ensure_ascii=False)).urn


def _prop(name, value):
    return {"name": name, "value": value}


def _source_properties(row, kind):
    props = []
    name, version = _text(row.get("source_name")), _text(row.get("source_version"))
    if name:
        props.append(_prop("aquasecurity:trivy:SrcName", name))
    if version:
        if kind in {"deb", "rpm"}:
            epoch, sep, rest = version.partition(":")
            if sep and epoch.isdecimal():
                props.append(_prop("aquasecurity:trivy:SrcEpoch", epoch))
                version = rest
            upstream, sep, release = version.rpartition("-")
            if sep and upstream and release:
                props.append(_prop("aquasecurity:trivy:SrcRelease", release))
                version = upstream
        props.append(_prop("aquasecurity:trivy:SrcVersion", version))
    return props


def _package(row, distro, os_name, known_products, native_names):
    original = _text(row.get("name"))
    source = _text(row.get("source"))
    if source not in {"maxpatrol", "ksc"}:
        return None
    kind = _text(row.get("type")).lower() or "generic"
    version = _text(row.get("version"))
    if version.casefold() in _UNKNOWN:
        version = ""
    arch = _text(row.get("arch"))
    raw_purl = _text(row.get("purl"))
    windows = None
    if kind == "generic":
        if version:
            windows = windows_product(row, os_name, known_products)
        if native_candidate(row, distro) and (row.get("source_name") or original) in native_names:
            kind = distro[1]
    reason = ""
    purl = None
    if raw_purl:
        try:
            purl = PackageURL.from_string(raw_purl)
            # Repository URLs and arbitrary qualifiers can contain credentials.
            purl = purl._replace(qualifiers={k: v for k, v in purl.qualifiers.items()
                                             if k in _PURL_QUALIFIERS})
        except ValueError:
            reason = "invalid-purl"
    if not original and not purl:
        return None
    if purl:
        kind = purl.type
        pname = purl.name
        namespace = purl.namespace
        qualifiers = dict(purl.qualifiers)
        if not version:
            version = purl.version or ""
            if qualifiers.get("epoch") and version and not re.match(r"^\d+:", version):
                version = f"{qualifiers['epoch']}:{version}"
    else:
        pname, namespace, qualifiers = original, None, {}
        if kind == "os" and distro and _row_os_matches(_text(row.get("os_name")), distro):
            kind = distro[1]
        if kind == "maven":
            namespace, sep, pname = original.rpartition(":")
            if not sep:
                reason = "missing-namespace"
        elif kind in {"npm", "golang", "composer", "swift"} and "/" in original:
            namespace, _, pname = original.rpartition("/")
    name = pname or original
    pversion = version
    if kind in _NATIVE:
        if distro and kind == distro[1]:
            family, _, release = distro
            expected_ns = {"sles": "suse", "opensuse-leap": "opensuse"}.get(family, family)
            if namespace and namespace != expected_ns:
                reason = "distribution-mismatch"
            namespace = namespace or expected_ns
            if not _row_os_matches(_text(row.get("os_name")), distro):
                reason = "distribution-mismatch"
            distro_value = release if kind == "apk" else f"{family}-{release}"
            purl_os = _purl_distribution(purl)
            if "distro" in qualifiers and (not purl_os or not _compatible(purl_os, distro)):
                reason = "distribution-mismatch"
            qualifiers.setdefault("distro", distro_value)
        else:
            reason = "missing-or-incompatible-distribution"
        if arch:
            if qualifiers.get("arch", arch) != arch:
                reason = "conflicting-architecture"
            qualifiers.setdefault("arch", arch)
        if kind in {"deb", "rpm"} and re.match(r"^\d+:", pversion):
            epoch, pversion = pversion.split(":", 1)
            if qualifiers.get("epoch", epoch) != epoch:
                reason = "conflicting-epoch"
            qualifiers["epoch"] = epoch
    elif kind not in _LANG:
        reason = reason or "unsupported-ecosystem"
    if not version:
        reason = reason or "missing-version"
    elif purl and purl.version and purl.version not in {pversion, version}:
        reason = "conflicting-version"
    props = [_prop("stools:source", source), _prop("stools:package-type", kind)]
    component = {"type": "library" if kind in _NATIVE | _LANG else "application",
                 "name": name, "properties": props}
    if version:
        component["version"] = version
    if publisher := _text(row.get("publisher")):
        component["publisher"] = publisher
    if windows:
        component["name"] = original
        component["cpe"] = windows.cpe_for(version)
        if windows.winget:
            props.append(_prop("stools:winget-id", windows.winget))
    if arch:
        props.append(_prop("stools:arch", arch))
    if kind in _NATIVE | {"os"}:
        props.extend(_source_properties(row, kind))
    if kind in _LANG and namespace:
        component["group"] = namespace
    if original and original != name:
        props.append(_prop("stools:display-name", original))
    if purl or kind in _NATIVE | _LANG:
        try:
            component["purl"] = PackageURL(type=kind, namespace=namespace, name=pname, version=pversion,
                                           qualifiers=qualifiers, subpath=purl.subpath if purl else None
                                           ).to_string()
        except ValueError:
            reason = "invalid-purl"
    if reason:
        # Trivy otherwise applies the host distribution to incompatible OS packages.
        # Preserve an observed identifier as evidence without presenting it for matching.
        component.pop("purl", None)
        if purl:
            props.append(_prop("stools:observed-purl", purl.to_string()))
        props.append(_prop(UNASSESSED, reason))
    return component


def make_bom(host_key: str, host_name: str, os_name: str, packages: Iterable[dict], *,
             known_products=(), native_names=()) -> dict:
    rows = list(packages)
    os_name = _text(os_name)
    distro = _host_distribution(os_name, rows)
    root = {"type": "platform", "name": host_name or host_key, "bom-ref": _ref("host", host_key)}
    if distro:
        root.update(type="operating-system", name=distro[0], version=distro[2])
    metadata = {"component": root, "properties": [_prop("stools:asset-id", host_key),
                _prop("stools:host-name", host_name), _prop("stools:os-name", os_name)]}
    candidates = [component for row in rows if (component := _package(row, distro, os_name, known_products, native_names))]
    vendors = defaultdict(set)
    for c in candidates:
        if c.get("publisher"):
            vendors[(c["name"].casefold(), c.get("version", ""))].add(c["publisher"].casefold())
    # Insert precise observations first so an ancillary display name can match at most one identity.
    candidates.sort(key=lambda c: (not c.get("purl"), not c.get("purl") and not c.get("publisher"),
                                   c["properties"][0]["value"] != "maxpatrol", json.dumps(c, sort_keys=True)))
    indexed = {}
    by_name = defaultdict(list)
    for c in candidates:
        props = {p["name"]: p["value"] for p in c["properties"]}
        group = c.get("group")
        name = f"{group}/{c['name']}" if group else c["name"]
        name_version = (name.casefold(), c.get("version", ""))
        kind, source, arch = props["stools:package-type"], props["stools:source"], props.get("stools:arch", "")
        publisher = c.get("publisher", "").casefold()
        identity = c.get("purl") or props.get("stools:observed-purl")
        key = (identity, c.get("version", ""), props.get(UNASSESSED)) if identity else (
            kind, *name_version, arch, publisher, "" if name_version[1] else source)
        if c.get("cpe") and not identity:
            key = (*key, c["cpe"])
        if key not in indexed and kind == "generic" and name_version[1] and not identity and not c.get("cpe"):
            matches = [k for k, vendor, cpu in by_name[name_version]
                       if (not vendor or not publisher or vendor == publisher)
                       and (vendor == publisher or len(vendors[name_version]) <= 1)
                       and (not cpu or not arch or cpu == arch)
                       and not (os_family(os_name) == "windows" and
                                (indexed[k].get("purl") or indexed[k].get("cpe")))]
            if len(matches) == 1:
                key = matches[0]
        if key not in indexed:
            indexed[key] = c
            c["bom-ref"] = _ref("package", *key)
            by_name[name_version].append((key, publisher, arch))
        else:
            existing = indexed[key]
            if c.get("publisher"):
                existing.setdefault("publisher", c["publisher"])
            present = {p["name"] for p in existing["properties"]}
            for p in c["properties"]:
                if p not in existing["properties"] and (p["name"] == "stools:source" or (
                        p["name"] not in present and p["name"] != UNASSESSED)):
                    existing["properties"].append(p)
    components = sorted(indexed.values(), key=lambda c: (c["name"].casefold(), c["bom-ref"]))
    for c in components:
        c["properties"].sort(key=lambda p: (p["name"], p["value"]))
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": metadata, "components": components}
