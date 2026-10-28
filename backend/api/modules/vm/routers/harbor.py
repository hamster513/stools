"""Подключение к Harbor: просмотр, сохранение, проверка."""
from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.audit import changes_summary
from api.crypto import SecretUnreadable
from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.hosts import NO_LINK, TLS_FAILED, is_tls_error, server_error, take_slot
from api.modules.vm.core.harbor import HarborClient, HarborError, make_harbor_client
from api.modules.vm.services.harbor_settings import (
    HarborConnection,
    HarborConnectionIn,
    SecretsRequired,
    changed_fields,
    load_harbor,
    save_harbor,
)

router = APIRouter(prefix="/harbor", tags=["vm"])


class HarborView(BaseModel):
    url: str
    robot_name: str
    robot_secret_set: bool
    verify_tls: bool
    projects: list[str]
    tags_per_repo: int
    configured: bool
    #: Task 4 заменит на `LastSyncView | None` и `api.platform.schedule_views.ScheduleView | None`.
    last_sync: None = None
    schedule: None = None


def _view(conn: HarborConnection) -> HarborView:
    return HarborView(
        url=conn.url,
        robot_name=conn.robot_name,
        robot_secret_set=bool(conn.robot_secret),
        verify_tls=conn.verify_tls,
        projects=conn.projects,
        tags_per_repo=conn.tags_per_repo,
        configured=conn.configured,
    )


@router.get("", response_model=HarborView)
def get_harbor(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> HarborView:
    return _view(load_harbor(db))


@router.put("", response_model=HarborView)
def put_harbor(
    payload: HarborConnectionIn,
    request: Request,
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> HarborView:
    request.state.audit_summary = changes_summary(changed_fields(load_harbor(db), payload))
    try:
        return _view(save_harbor(db, payload, user.login))
    except SecretsRequired as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc


class TestResponse(BaseModel):
    ok: bool
    message: str


def _public_error(exc: BaseException) -> str:
    """Класс причины отказа для ответа проверки: без адреса и текста Harbor."""
    if isinstance(exc, SecretUnreadable):
        return str(exc)
    if isinstance(exc, HarborError):
        return exc.kind
    if isinstance(exc.__cause__, httpx.HTTPError) or isinstance(exc, httpx.HTTPError):
        return TLS_FAILED if is_tls_error(exc) else NO_LINK
    return server_error(None)


@router.post("/test", response_model=TestResponse)
def test_harbor(db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> TestResponse:
    """Проверка сохранённого подключения: версия Harbor и вход под роботом.

    Проверяется то, что сохранено, а не то, что в форме: секрет форма не
    показывает и не присылает, проверять его «из поля» нечем.
    """
    conn = load_harbor(db)
    if not conn.configured:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="подключение не настроено: нужны адрес, имя и секрет робота")
    slot = take_slot("vm", user.id)
    try:
        real = conn.unsealed()
        with make_harbor_client(real, timeout=30.0) as http:
            info = HarborClient(real, http).probe()
    # Любая причина отказа доходит до человека классом, без текста Harbor.
    except Exception as exc:  # noqa: BLE001
        return TestResponse(ok=False, message=_public_error(exc))
    finally:
        slot.release()
    return TestResponse(ok=True, message=f"Harbor {info.version}")
