"""Клиент Open API KSC: сессия, вызов метода, постраничное чтение accessor-ов.

Фабрика httpx-клиента модульная и подменяется в тестах поддельным KSC.
"""
from __future__ import annotations

import base64
from collections.abc import Callable
from typing import Any, Self

import httpx

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


class KscClient:
    def __init__(self, base_url: str, username: str, password: str, *, verify_tls: bool = True, internal: bool = True, domain: str = "") -> None:
        self.base_url = base_url.rstrip("/") + "/api/v1.0/"
        self._auth = f'KSCBasic user="{_b64(username)}", pass="{_b64(password)}", internal="{"1" if internal else "0"}"'
        if not internal and domain:
            self._auth += f', domain="{_b64(domain)}"'
        self._http = http_factory(verify_tls)
        self._session: str | None = None

    def __enter__(self) -> Self:
        try:
            self.login()
        except Exception:
            self.close()
            raise
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _post(self, method: str, body: dict[str, Any] | None, headers: dict[str, str]) -> dict[str, Any]:
        try:
            resp = self._http.post(self.base_url + method, json=body or {}, headers={"Content-Type": "application/json", **headers})
        except httpx.HTTPError as exc:
            raise KscError(f"нет связи с KSC: {exc.__class__.__name__}", kind="link") from exc
        if resp.status_code in (401, 403):
            if method != "Session.StartSession" and resp.status_code == 403:
                raise KscError(f"нет прав на {method}", resp.status_code, kind="forbidden")
            raise KscError("вход отклонён: неверные логин, пароль или тип учётной записи", resp.status_code, kind="auth")
        if resp.status_code != 200:
            raise KscError(f"KSC ответил {resp.status_code} на {method}", resp.status_code, kind="http")
        try:
            data = resp.json() if resp.content else {}
        except ValueError as exc:
            raise KscError(f"KSC вернул не JSON на {method}") from exc
        if not isinstance(data, dict):
            raise KscError(f"неожиданный ответ на {method}")
        err = data.get("PxgError")
        if isinstance(err, dict):
            raise KscError(f"{method}: {err.get('message') or 'ошибка KSC'}", err.get("code"))
        return data

    def login(self) -> None:
        data = self._post("Session.StartSession", {}, {"Authorization": self._auth})
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
