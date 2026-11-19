"""Клиент Open API KSC: сессия, вызов метода, постраничное чтение accessor-ов.

Фабрика httpx-клиента модульная и подменяется в тестах поддельным KSC.
"""
from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable
from typing import Any, Self

import httpx

from api.limits import MAX_API_RESPONSE, ResponseTooLarge, read_limited

from api.modules.ksc.core.totp import totp_code

MFA_MESSAGES = {
    "mfa_required": "KSC требует второй фактор: задайте секрет TOTP в настройках подключения",
    "mfa_invalid": "KSC не подтвердил второй фактор: проверьте секрет TOTP и синхронизацию времени STools и KSC",
    "mfa_challenge": "KSC запросил второй фактор, но не выдал корректную промежуточную сессию",
}

TIMEOUT = 60.0


def _default_http_factory(verify: bool) -> httpx.Client:
    return httpx.Client(verify=verify, timeout=TIMEOUT, follow_redirects=False)


http_factory: Callable[[bool], httpx.Client] = _default_http_factory


class KscError(Exception):
    """`kind` — класс причины для ответа проверки подключения: link (нет
    связи), auth (вход отклонён), forbidden (нет прав), http (код ответа не
    200), server (ошибка метода или ответа)."""

    def __init__(self, message: str, code: int | None = None, *, kind: str = "server") -> None:
        super().__init__(message)
        self.code = code
        self.kind = kind


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


class _MfaChallenge(Exception):
    def __init__(self, session: str) -> None:
        super().__init__()
        self.session = session


class KscClient:
    def __init__(self, base_url: str, username: str, password: str, *, verify_tls: bool = True, internal: bool = True, domain: str = "", totp_secret: str = "") -> None:
        self.base_url = base_url.rstrip("/") + "/api/v1.0/"
        self._auth = f'KSCBasic user="{_b64(username)}", pass="{_b64(password)}", internal="{"1" if internal else "0"}"'
        if not internal and domain:
            self._auth += f', domain="{_b64(domain)}"'
        self._http = http_factory(verify_tls)
        self._session: str | None = None
        self._totp_secret = totp_secret

    def __enter__(self) -> Self:
        try:
            self.login()
        except Exception:
            self.close()
            raise
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _post(self, method: str, body: dict[str, Any] | None, headers: dict[str, str], *, allow_mfa: bool = False) -> dict[str, Any]:
        try:
            with self._http.stream("POST", self.base_url + method, json=body or {}, headers={"Content-Type": "application/json", **headers}) as resp:
                if allow_mfa and resp.status_code == 401 and re.search(r"(?:^|[,\s])KSCMFA(?:\s|$)", resp.headers.get("WWW-Authenticate", ""), re.I):
                    pending = resp.headers.get("X-KSC-Session", "")
                    if not pending.strip() or len(pending) > 4096:
                        raise KscError(MFA_MESSAGES["mfa_challenge"], kind="mfa_challenge")
                    raise _MfaChallenge(pending)
                if resp.status_code in (401, 403):
                    if method != "Session.StartSession" and resp.status_code == 403:
                        raise KscError(f"нет прав на {method}", resp.status_code, kind="forbidden")
                    raise KscError("вход отклонён: неверные логин, пароль или тип учётной записи", resp.status_code, kind="auth")
                if resp.status_code != 200:
                    raise KscError(f"KSC ответил {resp.status_code} на {method}", resp.status_code, kind="http")
                # Ответ читается в память целиком, поэтому с потолком (аудит L6).
                content = read_limited(resp, MAX_API_RESPONSE)
        except httpx.HTTPError as exc:
            raise KscError(f"нет связи с KSC: {exc.__class__.__name__}", kind="link") from exc
        except ResponseTooLarge as exc:
            raise KscError(f"KSC на {method}: {exc}") from exc
        try:
            data = json.loads(content) if content else {}
        except ValueError as exc:
            raise KscError(f"KSC вернул не JSON на {method}") from exc
        if not isinstance(data, dict):
            raise KscError(f"неожиданный ответ на {method}")
        err = data.get("PxgError")
        if isinstance(err, dict):
            raise KscError(f"{method}: {err.get('message') or 'ошибка KSC'}", err.get("code"))
        return data

    def login(self) -> None:
        try:
            data = self._post("Session.StartSession", {}, {"Authorization": self._auth}, allow_mfa=True)
        except _MfaChallenge as challenge:
            if not self._totp_secret:
                raise KscError(MFA_MESSAGES["mfa_required"], kind="mfa_required") from None
            try:
                code = totp_code(self._totp_secret)
                data = self._post("Session.StartSession", {}, {
                    "Authorization": f'KSCMFA totp="{code}"', "X-KSC-Session": challenge.session,
                })
            except ValueError:
                raise KscError(MFA_MESSAGES["mfa_invalid"], kind="mfa_invalid") from None
            except KscError as exc:
                if exc.kind == "link":
                    raise
                # Never forward KSC error text: it can echo the code or headers.
                raise KscError(MFA_MESSAGES["mfa_invalid"], kind="mfa_invalid") from None
        token = data.get("PxgRetVal")
        if not isinstance(token, str) or not token:
            raise KscError("KSC не выдал сессию")
        self._session = token

    def logout(self) -> None:
        if self._session:
            try:
                self._post("Session.EndSession", {}, {"X-KSC-Session": self._session})
            except KscError:
                pass
            self._session = None

    def close(self) -> None:
        self.logout()
        self._http.close()

    def call(self, method: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._session is None:
            self.login()
        assert self._session is not None
        return self._post(method, body, {"X-KSC-Session": self._session})

    def read_accessor(self, accessor: str, page: int = 500) -> list[dict[str, Any]]:
        total = int(self.call("ChunkAccessor.GetItemsCount", {"strAccessor": accessor}).get("PxgRetVal") or 0)
        items: list[dict[str, Any]] = []
        start = 0
        while start < total:
            chunk = self.call("ChunkAccessor.GetItemsChunk", {"strAccessor": accessor, "nStart": start, "nCount": page})
            arr = (chunk.get("pChunk") or {}).get("KLCSP_ITERATOR_ARRAY") or []
            if not arr:
                break
            items.extend(arr)
            start += len(arr)
        self.call("ChunkAccessor.Release", {"strAccessor": accessor})
        return items
