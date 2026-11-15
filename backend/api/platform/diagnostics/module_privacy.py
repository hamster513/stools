"""Identity helpers shared by native AD/KSC and cached diagnostic rows.

Addresses use a keyed prefix-preserving permutation. Registered ranges reserve
their common-prefix subtree so their endpoints remain ordered. This reveals
prefix/range topology, as required for offline policy reproduction; it is not
a cryptographic promise of unlinkability.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import uuid

from api.modules.ksc.core.secrets import has_secret_marker

from .sanitize import Anonymizer
from .schema import BundleError

_RANGE = re.compile(r"^([0-9a-fA-F:.]+)\s*-\s*([0-9a-fA-F:.]+)$")
_GUID = re.compile(r"^\{?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?$")
# These public path segments affect the ordinary exclusion risk checks.
_PATH_CONSTANTS = frozenset((
    "windows", "system32", "syswow64", "program files", "program files (x86)",
    "temp", "tmp", "downloads", "appdata", "localappdata", "userprofile",
    "users", "public", "systemdrive", "systemroot", "windir", "allusersprofile",
    "exe", "dll", "ps1", "bat", "cmd", "js", "vbs", "scr", "msi", "jar",
    "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32",
    "regsvr32", "python", "java", "javaw", "msbuild", "installutil", "certutil",
    "bitsadmin", "wmic", "log", "txt",
))


class ModuleAnonymizer(Anonymizer):
    def __init__(self):
        super().__init__()
        self._ranges = set()
        self._mapped_addresses = {}
        self._group_paths = {}

    @staticmethod
    def matching_text(value):
        # AD identity labels retain legacy casefold semantics, but KSC host,
        # path and account predicates compare lower(). Refuse the exceptional
        # Unicode classes rather than merge predicates (e.g. sharp-s and ss).
        if str(value).casefold() != str(value).lower():
            raise BundleError("Unsupported KSC Unicode identity matching.")
        return value

    def tag(self, value):
        if not value or not str(value).strip():
            return ""
        digest = hmac.new(self.secret, ("tag:" + str(value).lower()).encode(), hashlib.sha256).hexdigest()[:16]
        return f"entity-{digest}"

    def directory_domain(self, value):
        if not value:
            return ""
        return self.directory_labels.get(str(value).casefold(), self.domain(value) if "." in value else self.name(value))

    def principal(self, value, *, directory=False):
        if value and "\\" in value:
            domain, name = value.rsplit("\\", 1)
            label = self.directory_labels.get(domain.casefold(), self.name(domain)) if directory else self.domain(domain)
            return label + "\\" + self.name(name)
        return super().principal(value, directory=directory)

    def register_group_path(self, source, target):
        if source:
            if source in self._group_paths and self._group_paths[source] != target:
                raise BundleError("Unsupported conflicting diagnostic KSC group paths.")
            self._group_paths[source] = target

    def group_path(self, value):
        if value in self._group_paths:
            return self._group_paths[value]
        return "/".join(self.name(part) for part in str(value).split("/")) if value else ""

    def guid(self, value):
        if not value:
            return ""
        try:
            source = str(uuid.UUID(str(value).strip("{}")))
        except ValueError:
            raise BundleError("Unsupported diagnostic GUID.") from None
        digest = hmac.new(self.secret, ("guid:" + source).encode(), hashlib.sha256).digest()[:16]
        result = str(uuid.UUID(bytes=digest, version=4))
        return "{" + result + "}" if str(value).startswith("{") else result

    def dn(self, value):
        if not value:
            return ""
        parts = []
        for part in re.split(r"(?<!\\),", str(value)):
            key, sep, item = part.strip().partition("=")
            if not sep or key.lower() not in {"dc", "cn", "ou"}:
                raise BundleError("Unsupported directory identity.")
            if _GUID.fullmatch(item):
                label = self.guid(item)
            elif item.upper().startswith("S-1-"):
                label = self.sid(item)
            else:
                label = self.token(item)
            parts.append(key.upper() + "=" + label)
        return ",".join(parts)

    def sid(self, value):
        if re.fullmatch(r"S-1-(?:5-\d+|[123]-\d+|16-(?:0|4096|8192|8448|12288|16384|20480))", str(value), re.IGNORECASE):
            return str(value).upper()
        if not value:
            return ""
        if re.fullmatch(r"S-1-5-(?:21-\d+-\d+-\d+(?:-\d+)?|32-\d+)", str(value), re.IGNORECASE):
            return super().sid(value)
        if not re.fullmatch(r"S-1-\d+(?:-\d+)+", str(value), re.IGNORECASE):
            raise BundleError("Unsupported diagnostic SID.")
        parts = str(value).upper().split("-")
        # Preserve the authority/family discriminator: turning a service SID
        # into S-1-5-21 would make ordinary Assets parsing admit a new account.
        digest = hmac.new(self.secret, ("sid:" + str(value).lower()).encode(), hashlib.sha512).digest()
        tail = [str(int.from_bytes(digest[i * 4:i * 4 + 4], "big")) for i, _ in enumerate(parts[4:])]
        return "-".join(parts[:4] + tail)

    def _register_range(self, first, last):
        try:
            start, end = ipaddress.ip_address(first), ipaddress.ip_address(last)
        except ValueError:
            raise BundleError("Unsupported diagnostic address range.") from None
        if start.version != end.version or int(start) > int(end):
            raise BundleError("Unsupported diagnostic address range.")
        width = start.max_prefixlen
        prefix = width - (int(start) ^ int(end)).bit_length()
        # An interval crossing the root cannot be reordered without losing its
        # contiguous shape. Refuse instead of exporting unchanged identities.
        if prefix == 0:
            raise BundleError("Unsupported diagnostic address range spanning address families' root.")
        network = ipaddress.ip_network((start, prefix), strict=False)
        if network not in self._ranges:
            previous = {key: self._map_address(ipaddress.ip_address(key)) for key in self._mapped_addresses}
            self._ranges.add(network)
            if any(self._map_address(ipaddress.ip_address(key)) != mapped for key, mapped in previous.items()):
                self._ranges.remove(network)
                raise BundleError("Register diagnostic address ranges before serializing addresses.")

    def prepare_addresses(self, raw):
        """Register ranges across every selected raw snapshot before building any."""
        if isinstance(raw, dict):
            for first, last in (("begin", "end"), ("start", "end"), ("from", "to"), ("ipStart", "ipEnd")):
                if isinstance(raw.get(first), str) and isinstance(raw.get(last), str):
                    try:
                        ipaddress.ip_address(raw[first])
                        ipaddress.ip_address(raw[last])
                    except ValueError:
                        continue
                    self._register_range(raw[first], raw[last])
            for field, value in raw.items():
                if not has_secret_marker(str(field)):
                    self.prepare_addresses(value)
        elif isinstance(raw, list):
            for value in raw:
                self.prepare_addresses(value)
        elif isinstance(raw, str) and (match := _RANGE.fullmatch(raw.strip())):
            try:
                ipaddress.ip_address(match[1])
                ipaddress.ip_address(match[2])
            except ValueError:
                return
            self._register_range(match[1], match[2])

    def _map_address(self, address):
        width, original, mapped = address.max_prefixlen, int(address), 0
        frozen = min((network.prefixlen for network in self._ranges
                      if network.version == address.version and address in network), default=width)
        for depth in range(width):
            bit = (original >> (width - depth - 1)) & 1
            if depth < frozen:
                prefix = original >> (width - depth) if depth else 0
                message = f"ip:{address.version}:{depth}:{prefix}".encode()
                flip = (hmac.new(self.secret, message, hashlib.sha256).digest()[0] & 1) if depth else 1
                bit ^= flip
            mapped = (mapped << 1) | bit
        return str(type(address)(mapped))

    def ip(self, value):
        if not value:
            return ""
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return ""
        key = str(address)
        if key not in self._mapped_addresses:
            self._mapped_addresses[key] = self._map_address(address)
        return self._mapped_addresses[key]

    def network(self, value):
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise BundleError("Unsupported diagnostic network.") from None
        return str(ipaddress.ip_network(f"{self.ip(str(network.network_address))}/{network.prefixlen}", strict=False))

    def ip_range(self, first, last):
        self._register_range(first, last)
        return self.ip(first), self.ip(last)

    def fingerprint(self, value):
        digest = hmac.new(self.secret, ("fingerprint:" + value.lower()).encode(), hashlib.sha512).hexdigest()
        return digest[:len(value)]

    def pattern(self, value):
        """Preserve path shape and supported whole-component wildcard masks.

        Partial literal globs, character classes and regular expressions cannot
        be tokenized while preserving their predicates and are rejected.
        """
        if not value:
            return ""
        pieces = re.split(r"([\\/:.%])", str(self.matching_text(value)))
        result = []
        for piece in pieces:
            if not piece or piece in "\\/:.%" or piece in {"*", "**"}:
                result.append(piece)
            elif len(piece) == 1 and piece.isalpha() and len(pieces) > 1 and pieces[1] == ":" and not result:
                result.append(piece.upper())
            elif any(char in piece for char in "*?[]"):
                raise BundleError("Unsupported partial wildcard in diagnostic policy.")
            elif piece.casefold() in _PATH_CONSTANTS:
                result.append(piece)
            else:
                result.append(self.token(piece))
        return "".join(result)
