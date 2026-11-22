"""Offline package evidence from RED OS and Astra Linux vulnerability definitions."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from contextlib import contextmanager, nullcontext
from functools import lru_cache
from itertools import zip_longest
from typing import NamedTuple
from urllib.parse import urlsplit

from lxml import etree

_OVAL = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
_LINUX = "{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}"
# Release families and architectures published in the official feed catalogs.
_PROFILES = {
    "redos-7.3": ("7.3", ""), "redos-8": ("8.0", ""),
    "astra-1.7": ("1.7", "amd64"), "astra-1.8": ("1.8", "amd64"),
    "astra-4.7": ("4.7", "arm64"), "astra-4.8": ("4.8", "arm64"),
    "astra-3.8": ("3.8", "s390x"),
}
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._-]{0,254}")
_XML_LIMIT = 256 * 1024 * 1024
_INDEX_LIMIT = 64 * 1024 * 1024
_COMPARE = {"equals": {0}, "not equal": {-1, 1}, "less than": {-1},
            "less than or equal": {-1, 0}, "greater than": {1}, "greater than or equal": {0, 1}}
_CHECK = {"all": "AND", "at least one": "OR", "none satisfy": "NONE", "only one": "ONE"}
_EXISTS = {"at_least_one_exists", "all_exist", "any_exist", "none_exist", "only_one_exists"}


def _sign(left, right):
    return (left > right) - (left < right)


def _rpm_part(left, right):
    # '~' < end < '^' < letters < numbers; separators and leading zeroes compare equal.
    def segments(value):
        for unit in re.findall(r"[0-9]+|[A-Za-z]+|[~^]", value):
            if unit == "~":
                yield (0, "")
            elif unit == "^":
                yield (2, "")
            elif unit.isdigit():
                yield (4, int(unit))
            else:
                yield (3, unit)

    for a, b in zip_longest(segments(left), segments(right), fillvalue=(1, "")):
        if a != b:
            return _sign(a, b)
    return 0


def _deb_order(char):
    if char == "~":
        return -1
    if not char or char.isdigit():
        return 0
    return ord(char) if char.isalpha() else ord(char) + 256


def _deb_part(left, right):
    while left or right:
        while (left and not left[0].isdigit()) or (right and not right[0].isdigit()):
            order = _sign(_deb_order(left[:1]), _deb_order(right[:1]))
            if order:
                return order
            left, right = left[1:], right[1:]
        a, b = re.match(r"[0-9]*", left)[0], re.match(r"[0-9]*", right)[0]
        order = _sign(int(a or 0), int(b or 0))
        if order:
            return order
        left, right = left[len(a):], right[len(b):]
    return 0


@lru_cache(maxsize=8192)
def _evr(kind, value):
    if not isinstance(value, str) or len(value) > 512:
        return None
    pattern = (r"(?:(\d+):)?([A-Za-z0-9._+~^]+)(?:-([A-Za-z0-9._+~^]+))?"
               if kind == "rpm" else r"(?:(\d+):)?([0-9][A-Za-z0-9.+~\-]*)")
    match = re.fullmatch(pattern, value, flags=re.ASCII)
    if not match:
        return None
    epoch, version = int(match[1] or 0), match[2]
    if kind == "rpm":
        return epoch, version, match[3]
    if "-" not in version:
        return epoch, version, "0"
    upstream, revision = version.rsplit("-", 1)
    return (epoch, upstream, revision) if revision else None


@lru_cache(maxsize=16384)
def _compare_evr(kind, installed, threshold):
    left, right = _evr(kind, installed), _evr(kind, threshold)
    if left is None or right is None:
        return None
    part = _rpm_part if kind == "rpm" else _deb_part
    order = _sign(left[0], right[0]) or part(left[1], right[1])
    if order:
        return order
    # Every installed RPM has a release. A truncated inventory version cannot prove a backport.
    if left[2] is None or right[2] is None:
        return 0 if left[2] == right[2] else None
    return part(left[2], right[2])


def _arch(value):
    value = value.lower() if isinstance(value, str) else ""
    return {"x86_64": "amd64", "x86-64": "amd64", "aarch64": "arm64"}.get(value, value)


def _package(row):
    name, version = row.get("name"), row.get("version")
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        name = ""
    if not isinstance(version, str) or version.casefold() in {"unknown", "none", "null", "unspecified"}:
        version = ""
    epoch = row.get("epoch")
    if epoch is not None and epoch != "" and isinstance(version, str):
        if not re.fullmatch(r"[0-9]{1,20}", str(epoch)):
            version = ""
        elif ":" not in version:
            version = f"{epoch}:{version}"
        elif version.split(":", 1)[0].lstrip("0") != str(epoch).lstrip("0"):
            version = ""
    return name, version or "", _arch(row.get("arch"))


def package_inventory(rows):
    """Index native binary versions once, deduplicating observations from multiple sources."""
    packages = defaultdict(set)
    for row in rows:
        name, version, arch = _package(row)
        if name:
            packages[name].add((version, arch))
    return {name: tuple(sorted(items)) for name, items in packages.items()}


def _release_matches(branch, release):
    return release == branch or release.startswith(branch + ".")


def _platforms(metadata, profile):
    family, branch = profile.split("-", 1)[0], _PROFILES[profile][0]
    prefix = r"RED\s*OS" if family == "redos" else r"Astra Linux(?: Special Edition)?"
    releases = set()
    for affected in metadata.findall(_OVAL + "affected"):
        if affected.get("family") != "unix":
            continue
        for platform in affected.findall(_OVAL + "platform"):
            found = re.fullmatch(prefix + r"\s+(\d+(?:\.\d+)*)", (platform.text or "").strip(), re.IGNORECASE)
            if found:
                version = "8.0" if family == "redos" and found[1] == "8" else found[1]
                if _release_matches(branch, version):
                    releases.add(version)
    return tuple(sorted(releases))


def _bulletin(metadata, profile):
    redos = profile.startswith("redos-")
    branch = _PROFILES[profile][0].replace(".", "")
    expression = (r"ROS-[0-9]{8}-(?:" + branch + r"-)?[0-9]+" if redos
                  else r"[0-9]{4}-[0-9]{4}SE" + branch + r"[A-Z0-9]*")
    for ref in metadata.findall(_OVAL + "reference"):
        identifier, url = ref.get("ref_id", "").strip(), ref.get("ref_url", "")
        try:
            link = urlsplit(url)
            hosts = (("redos.red-soft.ru",) if redos else
                     ("wiki.astralinux.ru", "astralinux.ru", "astra.ru", "dl.astralinux.ru"))
            vendor_link = (link.scheme == "https" and link.hostname in hosts and not link.username
                           and not link.password and not link.port)
        except ValueError:
            vendor_link = False
        labelled = ref.get("source", "").upper() in ({"ROS", "REDOS"} if redos else {"VENDOR", "ASTRA"})
        ident = re.fullmatch(expression, identifier.removeprefix("№").strip(), re.IGNORECASE)
        if ident and (vendor_link or labelled):
            return identifier, url if vendor_link else ""
        if not redos and vendor_link:
            ident = re.search(r"(?:^|/)astra-linux-se\d+-bulletin-(" + expression + r")/?$", link.path, re.IGNORECASE)
            if ident:
                return ident[1], url
    return "", ""


def _criteria(elem, depth=0):
    if elem is None or depth > 32 or elem.get("applicability_check", "false") not in ("false", "0"):
        return None
    if elem.tag == _OVAL + "criterion":
        node = elem.get("test_ref")
    elif elem.tag == _OVAL + "criteria" and elem.get("operator", "AND") in ("AND", "OR") and len(elem):
        children = tuple(_criteria(child, depth + 1) for child in elem)
        node = children[0] if len(children) == 1 else (elem.get("operator", "AND"), *children)
    else:
        return None
    negate = elem.get("negate", "false")
    if negate in ("true", "1"):
        return ("NOT", node)
    return node if negate in ("false", "0") else None


def _object(elem):
    if len(elem) == 1:
        child = elem[0]
        name = (child.text or "").strip()
        if (child.tag == _LINUX + "name" and child.get("operation", "equals") == "equals"
                and set(child.attrib) <= {"operation", "datatype"} and child.get("datatype", "string") == "string"
                and _NAME.fullmatch(name)):
            return name
    return None


def _state(elem, kind):
    operator = elem.get("operator", "AND")
    if operator not in ("AND", "OR") or not len(elem):
        return None
    atoms = []
    for child in elem:
        field = child.tag.removeprefix(_LINUX) if isinstance(child.tag, str) else ""
        operation, value = child.get("operation", "equals"), (child.text or "").strip()
        datatype = child.get("datatype", "string")
        valid = (set(child.attrib) <= {"operation", "datatype"} and len(value) <= 512 and
                 ((field == "evr" and datatype == ("evr_string" if kind == "rpm" else "debian_evr_string")
                   and operation in _COMPARE and _evr(kind, value) is not None)
                  or (field in {"arch", "architecture", "name"} and datatype == "string"
                      and operation in {"equals", "not equal"} and bool(_NAME.fullmatch(value)))))
        atoms.append((field, operation, value) if valid else None)
    return (operator, *atoms)


def _test(elem):
    check = _CHECK.get(elem.get("check"))
    existence = elem.get("check_existence", "at_least_one_exists")
    operator = elem.get("state_operator", "AND")
    if not check or existence not in _EXISTS or operator not in ("AND", "OR"):
        return None
    objects = elem.findall(_LINUX + "object")
    states = elem.findall(_LINUX + "state")
    if len(objects) != 1 or len(elem) != 1 + len(states):
        return None
    return objects[0].get("object_ref"), check, existence, operator, tuple(s.get("state_ref") for s in states)


class _LimitedXML:
    def __init__(self, stream):
        self.stream = stream
        self.size = 0

    def read(self, length):
        remaining = _XML_LIMIT - self.size + 1
        data = self.stream.read(min(length, remaining) if length >= 0 else remaining)
        self.size += len(data)
        if self.size > _XML_LIMIT:
            raise ValueError("OVAL XML exceeds the size limit")
        return data


@contextmanager
def _xml_records(source):
    with (nullcontext(source) if hasattr(source, "read") else open(source, "rb")) as stream:
        try:
            yield etree.iterparse(_LimitedXML(stream), events=("end",), load_dtd=False, no_network=True,
                                  resolve_entities=False, remove_comments=True, remove_pis=True)
        except etree.XMLSyntaxError as exc:
            raise ValueError(f"Malformed OVAL XML at line {exc.position[0]}") from exc


class _Definition(NamedTuple):
    identifier: str
    bulletin: str
    url: str
    releases: tuple
    products: tuple
    rule: int


def compile_oval(source, profile):
    """Compile uncompressed official XML from a path or binary stream into a factual index."""
    if profile not in _PROFILES:
        raise ValueError(f"Unsupported OVAL profile {profile}")
    kind = "rpm" if profile.startswith("redos-") else "deb"
    prefix = _LINUX + ("rpminfo_" if kind == "rpm" else "dpkginfo_")
    objects, states, raw_tests, records = {}, {}, {}, []
    saw_platform = False
    sections = {_OVAL + name for name in ("definitions", "tests", "objects", "states", "variables")}
    with _xml_records(source) as parser:
        for _, elem in parser:
            parent = elem.getparent()
            if parent is None or parent.tag not in sections:
                continue
            tag, identifier = elem.tag, elem.get("id", "")
            if tag == _OVAL + "definition" and elem.get("class") == "vulnerability" and identifier:
                metadata = elem.find(_OVAL + "metadata")
                if metadata is not None and (releases := _platforms(metadata, profile)):
                    saw_platform = True
                    bulletin, url = _bulletin(metadata, profile)
                    cves = {ref.get("ref_id", "").upper() for ref in metadata.findall(_OVAL + "reference")
                            if ref.get("source", "").upper() == "CVE"}
                    # Multi-CVE advisories can combine independently affected packages. Require the
                    # vendor to bind the CVE at definition granularity, as both official feeds do.
                    if bulletin and len(cves) == 1 and _CVE.fullmatch(cve := cves.pop()):
                        products = tuple(sorted({p.text for p in metadata.findall(_OVAL + "affected/" +
                                                                                   _OVAL + "product") if p.text}))
                        criteria = elem.find(_OVAL + "criteria")
                        if criteria is not None and not any(
                            e.get("applicability_check", "false") not in {"false", "0"} for e in criteria.iter()
                        ):
                            records.append((cve, identifier, bulletin, url, releases, products, _criteria(criteria)))
            elif tag in (prefix + "test", prefix + "object", prefix + "state") and identifier:
                if tag == prefix + "test":
                    table, value = raw_tests, _test(elem)
                elif tag == prefix + "object":
                    table, value = objects, _object(elem)
                else:
                    table, value = states, _state(elem, kind)
                # Conflicting duplicate IDs cannot establish a unique object/state.
                table[identifier] = value if identifier not in table or table[identifier] == value else None
            elem.clear()
            while elem.getprevious() is not None:
                del parent[0]
        if (parser.root.tag != _OVAL + "oval_definitions" or parser.root.getroottree().docinfo.doctype
                or not saw_platform):
            raise ValueError(f"Invalid OVAL file or mismatched platform for {profile}")

    test_ids, unique_tests, unique_rules, definitions = {}, {}, {}, defaultdict(list)

    def bind(node):
        if isinstance(node, tuple):
            return (node[0], *(bind(child) for child in node[1:]))
        if node in test_ids:
            return test_ids[node]
        test = raw_tests.get(node)
        if test is None or not (name := objects.get(test[0])):
            return None
        _, check, existence, operator, refs = test
        bound = (name, check, existence, operator, tuple(states.get(ref) for ref in refs))
        test_ids[node] = unique_tests.setdefault(bound, len(unique_tests))
        return test_ids[node]

    for cve, identifier, bulletin, url, releases, products, node in records:
        rule = unique_rules.setdefault(bind(node), len(unique_rules))
        definitions[cve].append(_Definition(identifier, bulletin, url, releases, products, rule))
    return OvalIndex(profile, list(unique_tests), list(unique_rules), dict(definitions))


class _Proof(NamedTuple):
    truth: bool | None
    witness: bool = False
    bounds: frozenset = frozenset()


_UNKNOWN = _Proof(None)


def _negate(proof):
    return _UNKNOWN if proof.truth is None else _Proof(not proof.truth, proof.witness, proof.bounds)


def _combine(operator, proofs):
    if not proofs:
        return _UNKNOWN
    values = [proof.truth for proof in proofs]
    if operator == "ONE":
        if values.count(True) > 1:
            return _Proof(False)
        if None in values:
            return _UNKNOWN
        return next((p for p in proofs if p.truth), _Proof(False))
    if operator == "NONE":
        return _negate(_combine("OR", proofs))
    decisive = operator == "OR"
    truth = decisive if decisive in values else (None if None in values else not decisive)
    if truth is None:
        return _UNKNOWN
    relevant = [p for p in proofs if p.truth == truth and p.witness]
    bounds = frozenset().union(*(p.bounds for p in relevant))
    if operator == "OR" and bounds and any(not p.bounds for p in relevant):
        bounds |= {""}
    return _Proof(truth, bool(relevant), bounds)


def _item_proof(test, version, arch, kind, target, declared):
    name, _, _, operator, states = test
    if not states:
        return _Proof(True)

    def atom(condition):
        if condition is None:
            return _UNKNOWN
        field, operation, expected = condition
        if field == "evr":
            order = _compare_evr(kind, version, expected)
            if order is None:
                return _UNKNOWN
            truth = order in _COMPARE[operation]
            # A lower bound may be a prerequisite for another component. It can identify the
            # target on its own when the vendor explicitly names this product as affected.
            upper = ((operation == "less than" and truth) or
                     (operation == "greater than or equal" and not truth))
            vulnerable = upper or ((operation in ("equals", "less than or equal") and truth) or
                                   (operation in ("not equal", "greater than") and not truth))
            if target and vulnerable:
                return _Proof(truth, True, frozenset((expected if upper else "",)))
            return _Proof(truth, target and declared)
        actual = name if field == "name" else arch
        expected = expected if field == "name" else _arch(expected)
        return _Proof(_sign(actual, expected) in _COMPARE[operation]) if actual else _UNKNOWN

    return _combine(operator, [_UNKNOWN if s is None else _combine(s[0], [atom(c) for c in s[1:]])
                               for s in states])


class OvalIndex:
    def __init__(self, profile, tests, rules, definitions):
        self.profile, self.tests, self.rules, self.definitions = profile, tests, rules, definitions
        self._by_package = {}

    @property
    def has_bulletins(self):
        return bool(self.definitions)

    def _branches(self, rule):
        if rule not in self._by_package:
            def names(node):
                if isinstance(node, int):
                    test = self.tests[node]
                    if any(c and c[0] == "evr" for s in test[4] if s for c in s[1:]):
                        return {test[0]}
                if isinstance(node, tuple):
                    return set().union(*(names(child) for child in node[1:]))
                return set()

            node = self.rules[rule]
            choices = node[1:] if isinstance(node, tuple) and node[0] == "OR" else (node,)
            by_name = defaultdict(list)
            for branch in choices:
                affected = names(branch)
                for name in affected:
                    by_name[name].append((branch, len(affected) > 1))
            self._by_package[rule] = by_name
        return self._by_package[rule]

    def match(self, cve, package, inventory=None, *, os_version="", host_arch=""):
        """Return proof for this exact installed binary/CVE pair, or None for incomplete evidence."""
        definitions = self.definitions.get(cve)
        if not definitions:
            return None
        name, version, arch = _package(package)
        branch, required_arch = _PROFILES[self.profile]
        if self.profile == "redos-8" and os_version == "8":
            os_version = "8.0"
        if (not name or not isinstance(os_version, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", os_version)
                or not _release_matches(branch, os_version)):
            return None
        if required_arch and ((_arch(host_arch) or arch) != required_arch or
                              (arch and arch not in {required_arch, "all", "noarch"})):
            return None
        kind = "rpm" if self.profile.startswith("redos-") else "deb"
        if _evr(kind, version) is None:
            return None
        hosts = inventory or {}
        target = (version, arch)

        def evaluate(node, declared, candidate):
            if node is None:
                return _UNKNOWN
            if isinstance(node, tuple):
                if node[0] == "NOT":
                    return _negate(evaluate(node[1], declared, candidate))
                return _combine(node[0], [evaluate(n, declared, candidate) for n in node[1:]])
            test = self.tests[node]
            subject, check, existence, _, _ = test
            rows = hosts.get(subject, ())
            focused = subject == name
            if focused and target not in rows:
                rows = (*rows, target)
            if focused and candidate != target:
                rows = tuple(candidate if r == target else r for r in rows)
            if not rows:
                # Host SBOM observations are partial. An absent package is unknown even under NOT.
                return _UNKNOWN
            if existence == "none_exist" or (existence == "only_one_exists" and len(rows) != 1):
                return _Proof(False)
            proofs = [_item_proof(test, v, a, kind, focused and (v, a) == candidate, declared) for v, a in rows]
            result = _combine(check, proofs)
            if focused and len(rows) > 1:
                exact = _combine(check, [proofs[rows.index(candidate)]])
                if result.truth != exact.truth:
                    return _UNKNOWN
                return exact
            return result

        def for_version(definition, candidate):
            if not any(_release_matches(r, os_version) for r in definition.releases):
                return _UNKNOWN
            declared = name in definition.products
            return _combine("OR", [evaluate(expression, declared, candidate)
                                   for expression, multiple_names in self._branches(definition.rule).get(name, ())
                                   if not multiple_names or declared])

        for definition in definitions:
            outcome = for_version(definition, target)
            if outcome.truth and outcome.witness:
                fix = next(iter(outcome.bounds)) if len(outcome.bounds) == 1 else ""
                # Another vendor interval or bulletin may still affect this proposed boundary.
                if fix and any((p := for_version(d, (fix, arch))).truth and p.witness for d in definitions):
                    fix = ""
                return {"definition_id": definition.identifier, "bulletin": definition.bulletin,
                        "bulletin_url": definition.url, "package": name, "installed_version": version,
                        "fixed_version": fix}
        return None


def dump_index(index, stream):
    data = {"format": 1, "profile": index.profile, "tests": index.tests, "rules": index.rules,
            "definitions": index.definitions}
    stream.write(json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def read_index(stream, profile):
    """Read a bounded, data-only packaged index. References must address this profile's own tables."""
    raw = stream.read(_INDEX_LIMIT + 1)
    if len(raw) > _INDEX_LIMIT:
        raise ValueError("OVAL index exceeds the size limit")

    def tuples(value):
        return tuple(tuples(v) for v in value) if isinstance(value, list) else value

    try:
        data = json.loads(raw)
        if profile not in _PROFILES or data["profile"] != profile or data["format"] != 1:
            raise ValueError("Invalid OVAL index header or profile")
        kind = "rpm" if profile.startswith("redos-") else "deb"
        tests = [tuples(t) for t in data["tests"]]
        for name, check, existence, operator, states in tests:
            if (not _NAME.fullmatch(name) or check not in _CHECK.values() or existence not in _EXISTS
                    or operator not in {"AND", "OR"} or not isinstance(states, tuple)):
                raise ValueError("Invalid OVAL package test")
            for state in states:
                if state is not None:
                    if not isinstance(state, tuple) or len(state) < 2 or state[0] not in ("AND", "OR"):
                        raise ValueError("Invalid OVAL state")
                    for atom in state[1:]:
                        if atom is None:
                            continue
                        field, operation, value = atom
                        if not (
                            (field == "evr" and operation in _COMPARE and _evr(kind, value))
                            or (field in {"arch", "architecture", "name"} and operation in {"equals", "not equal"}
                                and _NAME.fullmatch(value))
                        ):
                            raise ValueError("Invalid OVAL package condition")

        def valid(node, depth=0):
            if node is None:
                return True
            if type(node) is int:
                return 0 <= node < len(tests)
            return (depth < 33 and isinstance(node, tuple) and len(node) >= 2 and
                    (node[0] in ("AND", "OR") or (node[0] == "NOT" and len(node) == 2)) and
                    all(valid(n, depth + 1) for n in node[1:]))

        rules = [tuples(r) for r in data["rules"]]
        if not all(valid(r) for r in rules):
            raise ValueError("Invalid OVAL rule")
        definitions = {}
        for cve, records in data["definitions"].items():
            values = [_Definition(*tuples(r)) for r in records]
            if not _CVE.fullmatch(cve) or any(not (
                isinstance(d.identifier, str) and d.identifier and isinstance(d.bulletin, str) and d.bulletin
                and isinstance(d.url, str) and isinstance(d.products, tuple)
                and all(isinstance(p, str) for p in d.products)
                and isinstance(d.releases, tuple) and d.releases
                and all(isinstance(r, str) and _release_matches(_PROFILES[profile][0], r) for r in d.releases)
                and type(d.rule) is int and 0 <= d.rule < len(rules)
            ) for d in values):
                raise ValueError("Invalid OVAL definition")
            definitions[cve] = values
        return OvalIndex(profile, tests, rules, definitions)
    except (KeyError, TypeError, AttributeError, IndexError, RecursionError) as exc:
        raise ValueError("Malformed OVAL index") from exc
