"""A selected, dependency-complete KSC export for ordinary module readers."""
from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import json
import math
import re

from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.dictionary.kes_windows import KES_WINDOWS
from api.modules.ksc.core.export import (
    ExportIndex,
    KscExport,
    _int,
    _str,
    parent_id,
    strip_params,
    unwrap,
)
from api.modules.ksc.core.secrets import HIDDEN, has_secret_marker

from .module_privacy import ModuleAnonymizer
from .schema import BundleError

_TOP = {"format", "server", "groups", "hosts", "host_products", "host_components", "host_users",
        "host_tags", "policies", "effective_policies", "policy_contents", "policy_profiles"}
_VERSION = re.compile(r"\d+(?:\.\d+){0,5}")
_LABEL = re.compile(r"(?:entity|key)-[0-9a-f]{16}")
_PRODUCTS = {"KES", "1103", "1093"}
_HOST_NUMBERS = {'KLHST_WKS_STATUS', 'KLHST_WKS_RTP_STATE', 'KLHST_WKS_STATUS_ID', 'KLHST_WKS_STATUS_MASK', 'KLHST_WKS_UNCURED_COUNT', 'KLHST_WKS_FROM_UNASSIGNED', 'KLHST_WKS_OS_BUILD_NUMBER', 'KLHST_WKS_CPU_ARCH', 'HST_VM_TYPE', 'KLHST_WKS_RBT_REQUIRED', 'KLHST_WKS_RBT_REQUEST_REASON', 'KLHST_WKS_EDR_STATUS', 'KLHST_MANAGED_OTHER_SERVER', 'KLHST_WKS_CTYPE', 'KLHST_WKS_OWNER_IS_CUSTOM'}
_HOST_DATES = {'KLHST_WKS_LAST_NAGENT_CONNECTED', 'KLHST_WKS_LAST_VISIBLE', 'KLHST_WKS_RTP_AV_BASES_TIME', 'KLHST_WKS_LAST_FULLSCAN', 'KLHST_WKS_RBT_REQUEST_TIME'}
_HOST_NAMES = {"KLHST_WKS_DN", "KLHST_WKS_WINHOSTNAME"}
_HOST_DOMAINS = {"KLHST_WKS_DNSDOMAIN", "KLHST_WKS_WINDOMAIN"}
_HOST_VERSIONS = {"KLHST_WKS_NAG_VERSION", "KLHST_WKS_RTP_AV_VERSION"}
_POLICY_FLAGS = {"KLPOL_ACTIVE", "KLPOL_INHERITED", "KLPOL_ACCEPT_PARENT", "KLPOL_FORCE_DISTRIB2CHILDREN", "KLPOL_FORCED"}
_POLICY_REFS = {"KLPOL_PARENT_ID", "KLPOL_BASE_ID", "KLPOL_BASE_POLICY_ID"}
_POLICY_FIELDS = {"KLPOL_ID", "KLPOL_DN", "KLPOL_PRODUCT", "KLPOL_VERSION", "KLPOL_GROUP_ID", "KLPOL_GROUP_NAME",
                  "KLPOL_MODIFIED", "KLPOL_CREATED"} | _POLICY_FLAGS | _POLICY_REFS
_PATH_FIELDS = {"path", "objectPath", "filePath", "nativePath", "wildcard", "Exclusions", "TrustedApps"}
_TEXT_FIELDS = {"name", "Name", "comment", "description", "objectName", "userTag", "display_name", "logonText",
                "errors", "KLPRSS_ValLckPolicy", "KLPRSS_ValLckGroup", "serviceAccountName"}
_HOST_FIELDS = _HOST_NUMBERS | _HOST_DATES | _HOST_NAMES | _HOST_DOMAINS | _HOST_VERSIONS | {
    "KLHST_WKS_HOSTNAME", "KLHST_WKS_GROUPID", "KLHST_WKS_IP_LONG", "KLHST_WKS_FQDN", "KLHST_WKS_OWNER_ID",
    "KLHST_WKS_OS_NAME", "KLHST_WKS_STATUS_HSDP"}
_CONDITION_FIELDS = {"NGTPP_sHostTag", "NGTPP_sNlaLocation", "NGTPP_nCpus"}
_ADDRESS_FIELDS = {"address", "remoteAddress", "localAddress", "ip", "ipStart", "ipEnd", "begin", "end", "start", "from", "to"}
# Public schema keys come from the existing product dictionary plus the item
# schemas used by the ordinary extractors. Customer-defined keys are not labels.
_OPERATIONAL_NUMBERS = {"Attempts", "Required", "Enabled", "OP", "LOP"}
_KEYS = set(KES_WINDOWS.sections)
for _section in KES_WINDOWS.sections.values():
    for _entry in _section.entries:
        _KEYS.update(_entry.path.split("."))
        if _entry.kind in {"number", "enum", "bool"}:
            _OPERATIONAL_NUMBERS.add(_entry.path.rsplit(".", 1)[-1])
_KEYS.update(["KLPRSS_Val", "KLPRSS_Mnd", "KLPRSS_ValLck", "KLPRSS_ValLckPolicy", "KLPRSS_ValLckGroup", "KLPRSS_ValConcatItemName", "KLSSPOL_PRF_ENABLED", "EXPRESSION", "ARGS", "LOP", "OP", "name", "Name", "val", "type", "value", "octets", "mask", "hostName", "hostNameIPs", "zoneIPv6", "unique_id", "action", "enabled", "log", "networkAdapters", "packetDirection", "protocol", "scope", "userChanged", "localPorts", "remotePorts", "begin", "end", "localAddresses", "remoteAddresses", "networks", "address", "parent", "parentId", "accessRules", "inherited", "allow", "applications", "networkPacketRules", "id", "appId", "components", "objectMask", "objectPath", "objectName", "recursive", "comment", "userTag", "fileHash", "fileHashType", "filePath", "nativePath", "excludeAmsiScan", "excludeBehavior", "excludeChildsBehavior", "excludeChildsBehaviorRecursive", "excludeConsoleInputMonitoring", "excludeFileIntegrityMonitoring", "excludeHipsNoInherit", "excludeNet", "encryptedTrafficOnly", "hosts", "ports", "excludeOpenFiles", "excludeRegistryIntegrityMonitoring", "excludeSelfProt", "excludeXDRTelemetry", "path", "createdByUser", "description", "wildcard", "domain", "KLPRSS_Basic", "KLPRSS_Components", "KLPRSS_Firewall", "KLPRSS_Password", "KLPRSS_Passwords", "KLPRSS_Secret", "EnableSelfProtection", "EnablePasswordProtection", "ReportsMaxSize", "AdminPassword", "ProxyPassword", "PasswordProtection", "PasswordHash", "Login", "Enabled", "Exclusions", "TrustedApps", "PASSWORD_HASH", "Uninstall", "Exit", "Value", "Required", "Attempts", "FileThreatProtection", "Firewall", "HIPS", "rules", "errors", "attrs", "sections", "priorities", "profiles", "product", "version", "remoteAddress", "localAddress", "ip", "ipStart", "ipEnd", "start", "from", "to", "notifications", "defaultPreset", "adaptiveAnomaliesControl", "critical", "saveToLocalLog", "saveToWindowsEventLog", "sendEmail", "settingsRevision", "minimumFileSize", "serviceAccountName", "logonText", "adminMessageTemplate", "allLocalProfiles", "blockMsg", "complainBody", "complainRecipient", "complainSubject", "complaintAddress", "complaintBodyTemplate", "complaintMsg", "complaintRecipient", "complaintSubject", "denyMessageTemplate", "enableTrafficStatistics", "exclusionGroups_merging_crutch", "f8e8efda", "followSymLinks", "hash", "include", "info", "isDeny", "lastActivityDays", "messageDeny", "messageTemplates", "messageWarn", "mode", "networkAccessRules", "noEnvExpand", "optimizeTelemetry", "port", "processRules", "scanExclusions_merging_crutch", "trustedApplications_merging_crutch", "trustedDevices_merging_crutch", "warnMessageTemplate"])


def _version(value):
    value = _str(value)
    if value and not _VERSION.fullmatch(value):
        raise BundleError("Unsupported diagnostic KSC version.")
    return value


def _product(value):
    value = _str(value)
    if value not in _PRODUCTS:
        raise BundleError("Unsupported diagnostic KSC product.")
    return value


def _date(anon, value, *, typed=True):
    value = unwrap(value)
    if value is None:
        return None
    try:
        shifted = anon.date(value)
        if typed:
            instant = dt.datetime.fromisoformat(shifted)
            if instant.tzinfo is None:
                instant = instant.replace(tzinfo=dt.UTC)
            shifted = instant.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, AttributeError):
        raise BundleError("Unsupported diagnostic KSC timestamp.") from None
    return {"type": "datetime", "value": shifted} if typed else shifted


def _number(value):
    value = unwrap(value)
    if value is not None and (type(value) not in (int, float, bool) or isinstance(value, float) and not math.isfinite(value)):
        raise BundleError("Unsupported diagnostic KSC scalar.")
    return value


def _address_text(value, anon):
    if "-" in value:
        first, _, last = value.partition("-")
        try:
            ipaddress.ip_address(first.strip())
            ipaddress.ip_address(last.strip())
        except ValueError:
            pass
        else:
            return "-".join(anon.ip_range(first.strip(), last.strip()))
    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            pass
        else:
            return anon.network(value)
    if mapped := anon.ip(value):
        return mapped
    raise BundleError("Unsupported diagnostic KSC address.")


def _policy_value(value, anon, key="", *, secret=False, depth=0):
    if depth > 80:
        raise BundleError("Unsupported diagnostic KSC policy nesting.")
    secret = secret or has_secret_marker(key)
    if isinstance(value, dict):
        if set(value) == {"type", "value"}:
            kind, inner = value["type"], value["value"]
            if kind == "binary":
                if secret:
                    return HIDDEN if inner else ""
                if key.casefold() != "octets":
                    raise BundleError("Unsupported opaque binary KSC policy content.")
                try:
                    address = ipaddress.ip_address(base64.b64decode(inner, validate=True))
                except (ValueError, TypeError):
                    raise BundleError("Unsupported opaque KSC address content.") from None
                packed = ipaddress.ip_address(anon.ip(str(address))).packed
                return {"type": "binary", "value": base64.b64encode(packed).decode()}
            if kind == "datetime":
                return _date(anon, value)
            if kind not in {"params", "string", "wstring", "long", "int", "int64", "bool", "boolean", "date"}:
                raise BundleError("Unsupported opaque typed KSC policy content.")
            return {"type": kind, "value": _policy_value(inner, anon, key, secret=secret, depth=depth + 1)}
        condition = "OP" in value and "name" in value and "val" in value
        if condition and _str(value["name"]) not in _CONDITION_FIELDS:
            raise BundleError("Unsupported opaque KSC activation field.")
        result = {}
        for field, item in value.items():
            if not isinstance(field, str) or field not in _KEYS:
                raise BundleError("Unsupported opaque KSC policy field.")
            if condition and field == "name":
                result[field] = _str(item)
            elif condition and field == "val" and _str(value["name"]) != "NGTPP_nCpus":
                method = anon.tag if _str(value["name"]) == "NGTPP_sHostTag" else anon.token
                result[field] = method(str(unwrap(item)))
            else:
                child_key = key if field in {"KLPRSS_Val", "value"} else field
                result[field] = _policy_value(item, anon, child_key, secret=secret, depth=depth + 1)
        return result
    if isinstance(value, list):
        return [_policy_value(item, anon, key, secret=secret, depth=depth + 1) for item in value]
    if value is None or type(value) in (bool, int, float):
        if secret and type(value) in (int, float) and key not in _OPERATIONAL_NUMBERS:
            return HIDDEN
        return _number(value)
    if not isinstance(value, str):
        raise BundleError("Unsupported opaque KSC policy value.")
    if not value or value == HIDDEN:
        return value
    if secret:
        return HIDDEN
    if key in _TEXT_FIELDS:
        return value if key == "objectName" and value == "*" else anon.token(value)
    if key in _PATH_FIELDS:
        return anon.pattern(value)
    if key in {"hostName", "serverAddress", "primaryServer", "secondaryServer"}:
        return anon.ip(value) or anon.fqdn(anon.matching_text(value))
    if key in {"domain", "urlList"}:
        anon.matching_text(value)
        # Whole-label masks only. URL expressions require an explicit parser.
        if value.startswith("*.") and "/" not in value:
            return "*." + anon.domain(value[2:])
        if any(c in value for c in "/*?[]"):
            raise BundleError("Unsupported opaque KSC URL expression.")
        return anon.domain(value)
    if key in _ADDRESS_FIELDS:
        return _address_text(value, anon)
    if key in {"primaryPort", "secondaryPort"} and re.fullmatch(r"[0-9]{1,5}", value):
        return value
    if key == "fileHash":
        if not re.fullmatch(r"[0-9a-fA-F]{32,128}", value):
            raise BundleError("Unsupported opaque KSC file hash.")
        return anon.fingerprint(value)
    if key == "KLPRSS_ValConcatItemName":
        return anon.token(value)
    raise BundleError("Unsupported opaque string KSC policy content.")


def _component(value, anon):
    value = _str(value)
    known = ["File Threat Protection", "Behavior Detection", "Exploit Prevention", "Firewall",
             "Network Threat Protection", "Web Control", "Device Control"]
    if value in known:
        return value
    matched = [term for terms in KscConfig().key_components.values() for term in terms if term in value.casefold()]
    return " / ".join(matched) if matched else anon.token(value)


def _host(raw, anon, gid):
    result = {}
    for key, value in raw.items():
        if key not in _HOST_FIELDS:
            continue
        if key == "KLHST_WKS_HOSTNAME":
            result[key] = anon.token(_str(value))
        elif key == "KLHST_WKS_GROUPID":
            result[key] = gid(_int(value))
        elif key == "KLHST_WKS_IP_LONG":
            number = _int(value)
            result[key] = int(ipaddress.ip_address(anon.ip(str(ipaddress.IPv4Address(number & 0xFFFFFFFF))))) if number else 0
        elif key == "KLHST_WKS_OWNER_ID":
            result[key] = anon.token(_str(value))
        elif key in _HOST_NUMBERS:
            result[key] = _number(value)
        elif key in _HOST_DATES:
            result[key] = _date(anon, value)
        elif key in _HOST_VERSIONS:
            result[key] = _version(value)
        elif key in _HOST_NAMES:
            result[key] = anon.name(anon.matching_text(_str(value)))
        elif key == "KLHST_WKS_WINDOMAIN":
            text = anon.matching_text(_str(value))
            result[key] = "WORKGROUP" if text.upper() == "WORKGROUP" else anon.name(text)
        elif key in _HOST_DOMAINS:
            result[key] = anon.domain(anon.matching_text(_str(value)))
        elif key == "KLHST_WKS_FQDN":
            result[key] = anon.fqdn(anon.matching_text(_str(value)))
        else:
            result[key] = anon.token(_str(value))
    return result


def _policy(raw, anon, gid, pid):
    result = {}
    for key, value in raw.items():
        if key not in _POLICY_FIELDS:
            continue
        if key == "KLPOL_ID" or key in _POLICY_REFS:
            result[key] = pid(_int(value)) if _int(value) >= 0 else -1
        elif key == "KLPOL_GROUP_ID":
            result[key] = gid(_int(value))
        elif key == "KLPOL_PRODUCT":
            result[key] = _product(value)
        elif key == "KLPOL_VERSION":
            result[key] = _version(value)
        elif key in _POLICY_FLAGS:
            result[key] = _number(value)
        elif key in {"KLPOL_MODIFIED", "KLPOL_CREATED"}:
            result[key] = _date(anon, value)
        else:
            result[key] = anon.name(_str(value))
    return result


def _sam(value, anon):
    anon.matching_text(value)
    result = anon.principal(value, directory=True) if "\\" in value else anon.name(value)
    return result + "$" if value.endswith("$") and not result.endswith("$") else result


def _user(raw, anon):
    methods = {"sid": anon.sid, "sam": lambda value: _sam(value, anon), "upn": anon.principal, "display_name": anon.name,
               "domain": lambda value: anon.directory_domain(anon.matching_text(value)), "bin_id": anon.token}
    return {key: methods[key](_str(value)) if key in methods else _number(value)
            for key, value in raw.items() if key in methods or key in {"local", "group", "active"}}


def prepare_ksc_addresses(raw: dict, host_ids: set[str], anon) -> None:
    """Prepare only retained policy ranges before serializing any module addresses.

    Retain the selected closure in the anonymizer until build_ksc_payload consumes
    it. Other snapshots can be prepared first without remapping existing IPs.
    """
    key = (id(raw), frozenset(str(host) for host in host_ids))
    cache = getattr(anon, "_prepared_ksc", None)
    if cache is None:
        cache = anon._prepared_ksc = {}
    if key in cache:
        return
    try:
        plain = strip_params(raw)
        if plain.get("format") != "stools-ksc/1":
            raise BundleError("Unsupported diagnostic KSC format.")
        KscExport.model_validate(plain)
        selection = _select(plain, set(key[1]))
        for section in ("policy_contents", "policy_profiles"):
            for policy_id in sorted(selection[-1]):
                anon.prepare_addresses((plain.get(section) or {}).get(str(policy_id), {}))
        cache[key] = raw, plain, selection
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError) as exc:
        if isinstance(exc, BundleError):
            raise
        raise BundleError("Unsupported diagnostic KSC source structure.") from None


def build_ksc_payload(raw: dict, host_ids: set[str], anon, snapshot_id: int) -> dict:
    prepare_ksc_addresses(raw, host_ids, anon)
    key = (id(raw), frozenset(str(host) for host in host_ids))
    _, plain, selection = anon._prepared_ksc.pop(key)
    try:
        return _build(plain, set(key[1]), anon, snapshot_id, selection)
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError) as exc:
        if isinstance(exc, BundleError):
            raise
        raise BundleError("Unsupported diagnostic KSC source structure.") from None



def _select(raw, host_ids):
    selected = [host for host in raw.get("hosts", []) if _str(host.get("KLHST_WKS_HOSTNAME")) in host_ids]
    if {_str(h.get("KLHST_WKS_HOSTNAME")) for h in selected} != host_ids:
        raise BundleError("Selected diagnostic KSC host is absent from native export.")
    groups = {_int(group.get("id")): group for group in raw.get("groups", [])}
    needed_groups = {_int(host.get("KLHST_WKS_GROUPID")) for host in selected}
    policies = {_int(p.get("KLPOL_ID")): p for p in raw.get("policies", [])}
    effective = raw.get("effective_policies", {})
    needed_policies = set()
    while True:
        before = needed_groups.copy(), needed_policies.copy()
        for group_id in tuple(needed_groups):
            if group_id not in groups:
                raise BundleError("Diagnostic KSC group dependency is missing.")
            parent = parent_id(groups[group_id])
            if parent >= 0:
                needed_groups.add(parent)
            needed_policies.update(_int(p.get("KLPOL_ID")) for p in effective.get(str(group_id), []))
        needed_policies.update(key for key, policy in policies.items() if _int(policy.get("KLPOL_GROUP_ID")) in needed_groups)
        for policy_id in tuple(needed_policies):
            if policy_id not in policies:
                raise BundleError("Diagnostic KSC base policy dependency is missing.")
            policy = policies[policy_id]
            needed_groups.add(_int(policy.get("KLPOL_GROUP_ID")))
            needed_policies.update(_int(policy[key]) for key in _POLICY_REFS if key in policy and _int(policy[key]) >= 0)
        if before == (needed_groups, needed_policies):
            break
    return selected, groups, policies, effective, needed_groups, needed_policies


def _build(raw, host_ids, anon, snapshot_id, selection):
    selected, groups, policies, effective, needed_groups, needed_policies = selection
    gid = lambda value: anon.identifier(f"group_id:{snapshot_id}", value)
    pid = lambda value: anon.identifier(f"policy_id:{snapshot_id}", value)
    server = raw["server"]
    result = {"format": "stools-ksc/1",
              "server": {"name": anon.name(server["name"]), "version": _version(server.get("version", "")),
                         "collected_at": _date(anon, server["collected_at"], typed=False), "collector": "diagnostic"},
              "groups": [], "hosts": [_host(host, anon, gid) for host in selected],
              "policies": [_policy(policies[key], anon, gid, pid) for key in sorted(needed_policies)],
              "effective_policies": {}, "policy_contents": {}, "host_products": {}, "host_components": {}}
    for key in sorted(needed_groups):
        group = groups[key]
        item = {"id": gid(key), "parentId": gid(parent_id(group)) if parent_id(group) >= 0 else -1,
                "name": anon.name(_str(group.get("name")))}
        if "level" in group:
            item["level"] = _number(group["level"])
        result["groups"].append(item)
        if str(key) in effective:
            result["effective_policies"][str(gid(key))] = [_policy(p, anon, gid, pid) for p in effective[str(key)]]
    original_groups = ExportIndex(KscExport(format="stools-ksc/1", server=server,
                                            groups=[groups[key] for key in sorted(needed_groups)]))
    copied_groups = ExportIndex(KscExport(format="stools-ksc/1", server=result["server"], groups=result["groups"]))
    for key in sorted(needed_groups):
        anon.register_group_path(original_groups.group_path(key), copied_groups.group_path(gid(key)))
    for host in selected:
        source = _str(host.get("KLHST_WKS_HOSTNAME"))
        target = anon.token(source)
        if source in raw.get("host_products", {}):
            result["host_products"][target] = {
                _product(product): {_version(version): {key: _version(value) if key == "ProdVersion" else anon.name(_str(value))
                    for key, value in attrs.items() if key in {"DisplayName", "ProdVersion"}} for version, attrs in versions.items()}
                for product, versions in raw["host_products"][source].items()}
        if source in raw.get("host_components", {}):
            components = {}
            for product_version, items in raw["host_components"][source].items():
                product, _, version = product_version.partition("/")
                label = _product(product) + ("/" + _version(version) if version else "")
                components[label] = [{"KLHST_PRCST_COMPONENT_DN": _component(item.get("KLHST_PRCST_COMPONENT_DN"), anon),
                                      "KLHST_PRCST_COMPONENT_STATUS": _number(item.get("KLHST_PRCST_COMPONENT_STATUS"))} for item in items]
            result["host_components"][target] = components
    for section in ("host_tags", "host_users"):
        if raw.get(section) is not None:
            result[section] = {}
            for source in sorted(host_ids & raw[section].keys()):
                values = raw[section][source]
                result[section][anon.token(source)] = None if values is None else [
                    anon.tag(tag) if section == "host_tags" else _user(tag, anon) for tag in values]
    if raw.get("policy_profiles") is not None:
        result["policy_profiles"] = {}
    for policy_id in sorted(needed_policies):
        key = str(policy_id)
        content = raw.get("policy_contents", {}).get(key)
        if content is not None:
            result["policy_contents"][str(pid(policy_id))] = {
                "product": _product(content.get("product", policies[policy_id].get("KLPOL_PRODUCT"))),
                "version": _version(content.get("version", "")),
                "sections": _policy_value(content.get("sections", {}), anon),
                "errors": [anon.token(str(error)) for error in content.get("errors", [])]}
        entry = (raw.get("policy_profiles") or {}).get(key)
        if entry is not None:
            rank = {str(name): index for index, name in enumerate(entry.get("priorities") or [])}
            ordered = sorted(entry.get("profiles") or [], key=lambda p: (rank.get(_str(p.get("name")), len(rank)), _str(p.get("name"))))
            result["policy_profiles"][str(pid(policy_id))] = {
                "profiles": [{"name": anon.token(_str(profile.get("name"))),
                              "attrs": _policy_value(profile.get("attrs", {}), anon),
                              "sections": _policy_value(profile.get("sections", {}), anon),
                              "errors": [anon.token(str(error)) for error in profile.get("errors", [])]} for profile in ordered],
                "priorities": [anon.token(_str(profile.get("name"))) for profile in ordered],
                "errors": [anon.token(str(error)) for error in entry.get("errors", [])]}
    validate_ksc_payload(result)
    return result


def validate_ksc_payload(raw: dict) -> None:
    """Validate native shape and all local references before normal-module import."""
    try:
        if not isinstance(raw, dict) or raw.get("format") != "stools-ksc/1" or set(raw) - _TOP:
            raise ValueError
        export = KscExport.model_validate(raw)
        groups = {_int(g.get("id")) for g in export.groups}
        hosts = {_str(h.get("KLHST_WKS_HOSTNAME")) for h in export.hosts}
        policies = {_int(p.get("KLPOL_ID")) for p in export.policies}
        if len(groups) != len(export.groups) or len(hosts) != len(export.hosts) or len(policies) != len(export.policies):
            raise ValueError
        if any(g <= 0 for g in groups) or any(p <= 0 for p in policies) or any(not _LABEL.fullmatch(h) for h in hosts):
            raise ValueError
        if not _LABEL.fullmatch(export.server.name):
            raise ValueError
        for group in export.groups:
            if set(group) - {"id", "parentId", "name", "level"} or not _LABEL.fullmatch(_str(group.get("name"))):
                raise ValueError
            if parent_id(group) >= 0 and parent_id(group) not in groups:
                raise ValueError
            seen = set()
            index = {_int(g.get("id")): g for g in export.groups}
            current = _int(group.get("id"))
            while current >= 0:
                if current in seen:
                    raise ValueError
                seen.add(current)
                current = parent_id(index[current])
        for host in export.hosts:
            if set(host) - _HOST_FIELDS or _int(host.get("KLHST_WKS_GROUPID")) not in groups:
                raise ValueError
        for section in (export.host_products, export.host_components, export.host_tags or {}, export.host_users or {}):
            if set(section) - hosts:
                raise ValueError
        for policy in export.policies:
            if set(policy) - _POLICY_FIELDS or _int(policy.get("KLPOL_GROUP_ID")) not in groups:
                raise ValueError
            if not _LABEL.fullmatch(_str(policy.get("KLPOL_DN"))):
                raise ValueError
            if any(_int(policy[key]) >= 0 and _int(policy[key]) not in policies for key in _POLICY_REFS if key in policy):
                raise ValueError
            _product(policy.get("KLPOL_PRODUCT"))
            _version(policy.get("KLPOL_VERSION"))
        for group, entries in export.effective_policies.items():
            if int(group) not in groups or any(_int(p.get("KLPOL_ID")) not in policies or _int(p.get("KLPOL_GROUP_ID")) not in groups for p in entries):
                raise ValueError
        if any(int(key) not in policies for section in (export.policy_contents, export.policy_profiles or {}) for key in section):
            raise ValueError
        for content in export.policy_contents.values():
            if set(content) - {"product", "version", "sections", "errors"}:
                raise ValueError
        for entry in (export.policy_profiles or {}).values():
            if set(entry) - {"profiles", "priorities", "errors"}:
                raise ValueError
            names = [p.get("name") for p in entry.get("profiles", [])]
            if len(names) != len(set(names)) or any(not isinstance(name, str) or not _LABEL.fullmatch(name) for name in names):
                raise ValueError
            if entry.get("priorities") != names:
                raise ValueError
        # Native readers must also be able to construct host/group relationships.
        _check_native_values(raw, export)
        ExportIndex(export)
        json.dumps(raw, allow_nan=False)
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
        raise BundleError("Invalid diagnostic KSC native payload.") from None


class _PrivacyGuard(ModuleAnonymizer):
    """Check generated scalar forms without changing their package mappings."""
    def token(self, value, category="entity"):
        if value and (not isinstance(value, str) or not _LABEL.fullmatch(value)):
            raise ValueError
        return value

    def tag(self, value):
        return self.token(value)

    def domain(self, value):
        if value and not re.fullmatch(r"domain-[0-9a-f]{16}\.invalid", str(value)):
            raise ValueError
        return value

    def fqdn(self, value):
        if value and not re.fullmatch(r"entity-[0-9a-f]{16}(?:\.domain-[0-9a-f]{16}\.invalid)?", str(value)):
            raise ValueError
        return value

    def directory_domain(self, value):
        if value and _LABEL.fullmatch(str(value)):
            return self.token(value)
        return self.domain(value)

    def principal(self, value, *, directory=False):
        if not value:
            return value
        if "\\" in value:
            domain, name = value.rsplit("\\", 1)
            self.directory_domain(domain) if directory else self.domain(domain)
            self.token(name.rstrip("$"))
        elif "@" in value:
            name, domain = value.rsplit("@", 1)
            self.token(name)
            self.domain(domain)
        else:
            self.token(value)
        return value

    def sid(self, value):
        if value and not re.fullmatch(r"S-1-\d+(?:-\d+)+", str(value)):
            raise ValueError
        return value

    def ip(self, value):
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return ""

    def network(self, value):
        return str(ipaddress.ip_network(value, strict=False))

    def ip_range(self, first, last):
        start, end = ipaddress.ip_address(first), ipaddress.ip_address(last)
        if start.version != end.version or int(start) > int(end):
            raise ValueError
        return str(start), str(end)

    def date(self, value):
        return value.isoformat() if isinstance(value, dt.datetime) else value

    def fingerprint(self, value):
        if not re.fullmatch(r"[0-9a-f]{32,128}", value):
            raise ValueError
        return value


def _check_native_values(raw, export):
    guard = _PrivacyGuard()
    if set(raw["server"]) - {"name", "version", "collected_at", "collector"} or raw["server"].get("collector") != "diagnostic":
        raise ValueError
    _version(export.server.version)
    for host in export.hosts:
        if _host(host, guard, lambda value: value) != host:
            raise ValueError
    for policy in export.policies:
        if _policy(policy, guard, lambda value: value, lambda value: value) != policy:
            raise ValueError
    for entries in export.effective_policies.values():
        for policy in entries:
            if _policy(policy, guard, lambda value: value, lambda value: value) != policy:
                raise ValueError
    for products in export.host_products.values():
        for product, versions in products.items():
            _product(product)
            for version, details in versions.items():
                _version(version)
                if set(details) - {"DisplayName", "ProdVersion"}:
                    raise ValueError
                if "DisplayName" in details:
                    guard.name(details["DisplayName"])
                if "ProdVersion" in details:
                    _version(details["ProdVersion"])
    for components in export.host_components.values():
        for label, items in components.items():
            product, _, version = label.partition("/")
            _product(product)
            _version(version)
            for item in items:
                if set(item) - {"KLHST_PRCST_COMPONENT_DN", "KLHST_PRCST_COMPONENT_STATUS"}:
                    raise ValueError
                if _component(item.get("KLHST_PRCST_COMPONENT_DN"), guard) != item.get("KLHST_PRCST_COMPONENT_DN"):
                    raise ValueError
                _number(item.get("KLHST_PRCST_COMPONENT_STATUS"))
    for tags in (export.host_tags or {}).values():
        for tag in tags:
            guard.token(tag)
    for users in (export.host_users or {}).values():
        for user in users or []:
            if _user(user, guard) != user:
                raise ValueError
    for content in export.policy_contents.values():
        _product(content.get("product"))
        _version(content.get("version"))
        if _policy_value(content.get("sections", {}), guard) != content.get("sections", {}):
            raise ValueError
        for error in content.get("errors", []):
            guard.token(error)
    for entry in (export.policy_profiles or {}).values():
        for profile in entry.get("profiles", []):
            if set(profile) - {"name", "attrs", "sections", "errors"}:
                raise ValueError
            for field in ("attrs", "sections"):
                if _policy_value(profile.get(field, {}), guard) != profile.get(field, {}):
                    raise ValueError
            for error in profile.get("errors", []):
                guard.token(error)
        for error in entry.get("errors", []):
            guard.token(error)
