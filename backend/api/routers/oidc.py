"""Вход через провайдера: /api/auth/oidc/status, /start, /callback.

Публичный роутер — сессии на этих ручках ещё нет и быть не может (см.
api/main.py про то, как защищены остальные). Любой отказ — редирект на
`/login?error=<код>`, а не 4xx: сюда возвращается браузер человека, и ему
нужна страница входа с внятным сообщением, а не JSON с деталью.

`state` привязан к браузеру ещё и cookie: строки в таблице мало — она
пускает любого, кому досталась ссылка возврата. Совпадение проверяется до
того, как состояние будет израсходовано.

Код и state в журнал не попадают: сводку туда пишет строка запроса, поэтому
обработчик кладёт свою `request.state.audit_summary` первым же действием —
до любого выхода, включая 404 и необработанную ошибку.
"""
from __future__ import annotations

import logging
import secrets
from typing import Any

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.oidc import login as oidc_login
from api.oidc.login import (
    STATE_TTL,
    LoginRefused,
    begin_login,
    claim_list,
    resolve_user,
    take_state,
)
from api.oidc.provider import (
    ProviderError,
    exchange_code,
    fetch_discovery,
    fetch_userinfo,
    verify_id_token,
)
from api.oidc.settings import OidcSettings, load_oidc
from api.routers.auth import open_session
from api.settings import Settings, get_settings

router = APIRouter(prefix="/api/auth/oidc", tags=["auth"])

#: Привязка начатого входа к браузеру. Путь — только ручки OIDC: на
#: остальные запросы эта cookie не нужна. samesite=lax, а не strict:
#: браузер приходит на callback переходом с чужого сайта — от провайдера.
STATE_COOKIE = "stools_oidc_state"
STATE_COOKIE_PATH = "/api/auth/oidc"


def _enabled_or_404(db: Session) -> OidcSettings:
    cfg = load_oidc(db)
    if not (cfg.enabled and cfg.configured):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="вход через OIDC выключен")
    return cfg


def _forget_state(response: Response) -> None:
    """Начатый вход кончился — привязка больше не нужна ни при каком исходе."""
    response.delete_cookie(STATE_COOKIE, path=STATE_COOKIE_PATH)


def _refused(request: Request, code: str, login: str | None) -> RedirectResponse:
    request.state.audit_login = login or ""
    request.state.audit_summary = code
    redirect = RedirectResponse(f"/login?error={code}", status_code=status.HTTP_302_FOUND)
    _forget_state(redirect)
    return redirect


@router.get("/status")
def oidc_status(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Показывать ли на странице входа кнопку провайдера и как её назвать."""
    cfg = load_oidc(db)
    return {"enabled": cfg.enabled and cfg.configured, "display_name": cfg.display_name}


@router.get("/start")
def oidc_start(
    request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings)
) -> Response:
    #: Сводка журнала — до всего остального: 404 ниже ушёл бы мимо этой
    #: строки, и в журнал попала бы строка запроса.
    request.state.audit_summary = ""
    cfg = _enabled_or_404(db)
    try:
        disco = fetch_discovery(cfg.issuer_url, oidc_login.http_factory)
    except ProviderError as exc:
        return _refused(request, exc.code, None)
    url, state = begin_login(db, cfg, disco)
    redirect = RedirectResponse(url, status_code=status.HTTP_302_FOUND)
    redirect.set_cookie(
        key=STATE_COOKIE,
        value=state,
        httponly=True,
        samesite="lax",
        secure=settings.session_cookie_secure,
        max_age=int(STATE_TTL.total_seconds()),
        path=STATE_COOKIE_PATH,
    )
    return redirect


#: Причина отказа во входе: человек видит общий текст, а оператору нужно
#: знать, какая проверка не прошла (издатель, аудитория, подпись, группы).
#: Секретов в сообщениях нет — только классы ошибок и имена групп.
logger = logging.getLogger("stools.oidc")


@router.get("/callback")
def oidc_callback(
    request: Request,
    state: str = "",
    code: str = "",
    error: str = "",
    stools_oidc_state: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    request.state.audit_summary = ""
    cfg = _enabled_or_404(db)
    #: Состояние из базы годится только тому браузеру, который вход начинал.
    #: Сравниваются байты: `state` приходит снаружи, а compare_digest на
    #: строке с не-ASCII падает — это был бы 500 по чужому запросу.
    if not state or not stools_oidc_state or not secrets.compare_digest(
        stools_oidc_state.encode(), state.encode()
    ):
        return _refused(request, "oidc_state", None)
    #: Забирается ровно один раз: повтор того же callback (кнопка «назад»,
    #: перезагрузка страницы) не должен открывать вторую сессию.
    pending = take_state(db, state)
    if pending is None:
        return _refused(request, "oidc_state", None)
    if error or not code:
        logger.warning("вход через OIDC отклонён (oidc_denied): провайдер вернул error=%r", error[:100])
        return _refused(request, "oidc_denied", None)
    groups: list[str] = []
    try:
        disco = fetch_discovery(cfg.issuer_url, oidc_login.http_factory)
        tokens = exchange_code(disco, cfg, code, pending.code_verifier, oidc_login.http_factory)
        claims = verify_id_token(
            tokens["id_token"], disco, cfg, pending.nonce, oidc_login.http_factory
        )
        groups = claim_list(claims, cfg.groups_claim)
        #: Групп в id_token может не быть вовсе — их отдают и отдельной
        #: ручкой. Пустой список — другое дело: это ответ «групп нет», и
        #: переспрашивать провайдера незачем.
        if cfg.groups_claim not in claims and tokens.get("access_token"):
            userinfo = fetch_userinfo(
                disco, tokens["access_token"], str(claims["sub"]), oidc_login.http_factory
            )
            groups = claim_list(userinfo, cfg.groups_claim)
        user = resolve_user(db, cfg, claims, groups)
    except ProviderError as exc:
        logger.warning("вход через OIDC отклонён (%s): %s", exc.code, exc)
        return _refused(request, exc.code, None)
    except LoginRefused as exc:
        logger.warning(
            "вход через OIDC отклонён (%s): логин %r, группы от провайдера %s", exc.code, exc.login, groups
        )
        return _refused(request, exc.code, exc.login)
    request.state.audit_summary = "oidc"
    redirect = RedirectResponse("/", status_code=status.HTTP_302_FOUND)
    _forget_state(redirect)
    open_session(db, request, redirect, settings, user)
    return redirect
