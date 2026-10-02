"""Переходы статусов находок (спека §1): чистые функции, без базы."""
from __future__ import annotations

import datetime as dt

import pytest

from api.platform.findings.core import (
    DEFAULT_COUNTED,
    MANUAL,
    OPEN,
    STATUSES,
    FindingSettings,
    RoleRequired,
    TransitionError,
    check_manual,
    is_overdue,
    on_absent,
    on_present,
)

TODAY = dt.date(2026, 10, 2)
DEFAULTS = FindingSettings()


def _check(status: str, *, reason: str = "так решили", role: str = "analyst",
           settings: FindingSettings = DEFAULTS, risk_until: dt.date | None = None) -> None:
    check_manual(status, reason=reason, role=role, settings=settings, risk_until=risk_until, today=TODAY)


def test_manual_statuses_pass() -> None:
    for status in MANUAL:
        _check(status)


@pytest.mark.parametrize("status", ["risk_accepted", "false_positive"])
def test_closing_decision_needs_reason(status: str) -> None:
    with pytest.raises(TransitionError):
        _check(status, reason="  ")


@pytest.mark.parametrize("status", ["resolved", "reopened", "nonsense"])
def test_system_statuses_are_not_manual(status: str) -> None:
    with pytest.raises(TransitionError):
        _check(status)


def test_risk_accept_role_admin_denies_analyst() -> None:
    settings = FindingSettings(risk_accept_role="admin")
    with pytest.raises(RoleRequired):
        _check("risk_accepted", settings=settings)
    _check("risk_accepted", settings=settings, role="admin")
    # Ложное срабатывание — не принятие риска: роль на него не влияет.
    _check("false_positive", settings=settings)


def test_risk_max_days() -> None:
    settings = FindingSettings(risk_max_days=90)
    with pytest.raises(TransitionError):
        _check("risk_accepted", settings=settings)
    with pytest.raises(TransitionError):
        _check("risk_accepted", settings=settings, risk_until=TODAY + dt.timedelta(days=120))
    _check("risk_accepted", settings=settings, risk_until=TODAY + dt.timedelta(days=30))


def test_risk_until_in_past_is_refused() -> None:
    with pytest.raises(TransitionError):
        _check("risk_accepted", risk_until=TODAY - dt.timedelta(days=1))


@pytest.mark.parametrize("status,expected", [
    ("new", "resolved"), ("in_work", "resolved"), ("fixed", "resolved"), ("reopened", "resolved"),
    ("risk_accepted", None), ("false_positive", None), ("resolved", None),
])
def test_on_absent(status: str, expected: str | None) -> None:
    assert on_absent(status) == expected


@pytest.mark.parametrize("status,was_present,expected", [
    ("resolved", False, "reopened"), ("resolved", True, "reopened"),
    # fixed остаётся fixed, пока ключ в данных: reopened — только после исчезновения.
    ("fixed", True, None),
    # «Исправлено» поставили, когда находки в данных уже не было, — она вернулась.
    ("fixed", False, "reopened"),
    ("new", False, None), ("in_work", False, None), ("reopened", False, None),
    ("risk_accepted", False, None), ("false_positive", False, None),
])
def test_on_present(status: str, was_present: bool, expected: str | None) -> None:
    assert on_present(status, was_present) == expected


def test_unknown_status_is_named_unknown() -> None:
    with pytest.raises(TransitionError, match="неизвестный статус «nonsense»"):
        _check("nonsense")


def test_is_overdue() -> None:
    yesterday = TODAY - dt.timedelta(days=1)
    assert is_overdue("in_work", yesterday, TODAY)
    assert is_overdue("reopened", yesterday, TODAY)
    assert not is_overdue("risk_accepted", yesterday, TODAY)
    assert not is_overdue("resolved", yesterday, TODAY)
    assert not is_overdue("in_work", TODAY, TODAY)
    assert not is_overdue("in_work", None, TODAY)


def test_constants_match_spec() -> None:
    assert set(MANUAL) | {"resolved", "reopened"} == set(STATUSES)
    assert OPEN == {"new", "in_work", "fixed", "reopened"}
    assert {s for s, on in DEFAULT_COUNTED.items() if not on} == {"risk_accepted", "false_positive", "resolved"}
    assert set(DEFAULT_COUNTED) == set(STATUSES)
