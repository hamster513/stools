"""Настройки модуля VM: подключение, веса формулы, порог."""
from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.audit import changes_summary
from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.hosts import (
    LOGIN_REJECTED,
    NO_LINK,
    NO_RIGHTS,
    TLS_FAILED,
    is_tls_error,
    server_error,
    take_slot,
)
from api.modules.vm.core.mpvm import MpVmClient, MpVmError, MpVmLoginError, make_client
from api.modules.vm.core.weights import DEFAULT_THRESHOLD, Weights
from api.modules.vm.services.settings import (
    DEFAULT_ATTACK_MIN_RISK,
    SecretsRequired,
    VmSettings,
    VmSettingsIn,
    changed_fields,
    load_settings,
    save_settings,
)

router = APIRouter(prefix="/settings", tags=["vm"])


class SettingsView(BaseModel):
    connection: dict[str, Any]
    weights: Weights
    threshold: int
    attack_min_risk: int
    defaults: dict[str, Any]


def _view(s: VmSettings) -> SettingsView:
    conn = s.connection.model_dump(exclude={"password", "client_secret"})
    conn["password_set"] = bool(s.connection.password)
    conn["client_secret_set"] = bool(s.connection.client_secret)
    conn["configured"] = s.connection.configured
    return SettingsView(
        connection=conn,
        weights=s.weights,
        threshold=s.threshold,
        attack_min_risk=s.attack_min_risk,
        # Умолчания отдаются рядом, чтобы «сбросить» на экране не требовало
        # ещё одной ручки и не расходилось с бэкендом.
        defaults={"weights": Weights().model_dump(), "threshold": DEFAULT_THRESHOLD, "attack_min_risk": DEFAULT_ATTACK_MIN_RISK},
    )


@router.get("", response_model=SettingsView)
def get_settings_(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> SettingsView:
    return _view(load_settings(db))


@router.put("", response_model=SettingsView)
def put_settings(
    payload: VmSettingsIn,
    request: Request,
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> SettingsView:
    request.state.audit_summary = changes_summary(changed_fields(load_settings(db), payload))
    try:
        return _view(save_settings(db, payload, user.login))
    except SecretsRequired as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc


class TestVmResponse(BaseModel):
    ok: bool
    message: str


def _public_error(exc: BaseException) -> str:
    """Класс причины отказа для ответа проверки: без адреса и текста VM."""
    if isinstance(exc.__cause__, httpx.HTTPError) or isinstance(exc, httpx.HTTPError):
        return TLS_FAILED if is_tls_error(exc) else NO_LINK
    code = exc.status if isinstance(exc, MpVmError) else None
    if isinstance(exc, MpVmLoginError) and code in (None, 400, 401):
        return LOGIN_REJECTED
    if code == 401:
        return LOGIN_REJECTED
    if code == 403:
        return NO_RIGHTS
    return server_error(code)


@router.post("/test-vm", response_model=TestVmResponse)
def test_vm(db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> TestVmResponse:
    """Проверка сохранённого подключения: токен и PDQL с limit(1).

    Проверяется то, что сохранено, а не то, что в форме: пароль и секрет
    форма не показывает и не присылает, проверять их «из поля» нечем.
    """
    conn = load_settings(db).connection
    if not conn.configured:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="подключение не настроено: нужны хост, логин и пароль")
    slot = take_slot("vm", user.id)
    try:
        with make_client(conn, timeout=30.0) as http:
            head = MpVmClient(conn, http).probe()
    except Exception as exc:  # noqa: BLE001 — любая причина отказа доходит до человека классом, без текста VM
        return TestVmResponse(ok=False, message=_public_error(exc))
    finally:
        slot.release()
    return TestVmResponse(ok=True, message=f"MaxPatrol VM отвечает, экспорт начинается с: {head[:60]}")
