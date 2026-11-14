"""OSV version evidence: boundaries, strict package identity and unknown ordering."""
from __future__ import annotations

import pytest

from api.modules.vm.core.ghsa_versions import match_package, version_affected


def _range(kind: str = "SEMVER", **end: str) -> list[dict]:
    return [{"type": kind, "events": [{"introduced": "0"}, end]}]


@pytest.mark.parametrize(("version", "affected"), [
    ("1.9.9", True), ("2.0.0-rc.1", True), ("2.0.0", False),
    ("2.0.0+build.4", False), ("10.0.0", False),
])
def test_semver_fixed_boundary(version: str, affected: bool) -> None:
    assert version_affected(version, "npm", _range(fixed="2.0.0"), []) is affected


def test_semver_sorts_events_and_prerelease_numerically() -> None:
    ranges = [{"type": "SEMVER", "events": [
        {"fixed": "1.0.0-beta.11"}, {"introduced": "1.0.0-beta.2"},
    ]}]
    assert version_affected("1.0.0-beta.9", "npm", ranges, []) is True
    assert version_affected("1.0.0-beta.11", "npm", ranges, []) is False


def test_last_affected_inclusive_and_multiple_limits() -> None:
    assert version_affected("2.0.0", "npm", _range(last_affected="2.0.0"), []) is True
    assert version_affected("2.0.1", "npm", _range(last_affected="2.0.0"), []) is False
    ranges = [{"type": "SEMVER", "events": [
        {"introduced": "0"}, {"limit": "1.0.0"}, {"limit": "2.0.0"},
    ]}]
    assert version_affected("1.5.0", "npm", ranges, []) is True
    assert version_affected("2.0.0", "npm", ranges, []) is False


def test_pypi_orders_pep440_instead_of_lexical_versions() -> None:
    ranges = _range("ECOSYSTEM", fixed="2.0")
    assert version_affected("2.0rc1", "PyPI", ranges, []) is True
    assert version_affected("2.0.post1", "PyPI", ranges, []) is False
    assert version_affected("1!1.0", "PyPI", ranges, []) is False


def test_unknown_order_is_not_an_unaffected_verdict() -> None:
    ranges = _range("ECOSYSTEM", fixed="2.0")
    assert version_affected("1.0", "Maven", ranges, []) is None
    assert version_affected("1.0", "Maven", ranges, ["1.0"]) is True
    assert version_affected("1.1", "Maven", [], ["1.0"]) is False
    assert version_affected("invalid", "PyPI", ranges, []) is None
    assert version_affected("1.0", "npm", _range(fixed="2.0.0"), []) is None
    assert version_affected("1.0.0", "npm", [], []) is None


def test_strict_identity_prevents_cross_ecosystem_and_purl_collision() -> None:
    package = {"ecosystem": "npm", "name": "requests", "purl": "pkg:npm/requests",
               "ranges": _range(fixed="2.0.0"), "versions": []}
    assert match_package(package, ecosystem="PyPI", name="requests", version="1.0.0") is False
    assert match_package(package, ecosystem="npm", name="requests", version="1.0.0") is True
    assert match_package(package, ecosystem="npm", name="requests", version="1.0.0",
                         purl="pkg:npm/other") is False
    assert match_package(package, ecosystem=None, name="requests", version="1.0.0") is None
    assert match_package(package, ecosystem="npm", name="requests", version="1.0.0",
                         withdrawn=True) is None
