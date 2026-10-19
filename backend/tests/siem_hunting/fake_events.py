"""Поддельный API событий MaxPatrol (`POST /api/events/v3/events`) для тестов клиента, ночного прогона и проверки подключения."""
from __future__ import annotations

import json
from typing import Any

import httpx

#: Персональный API-токен подключения в тестах (не настоящий).
TOKEN = "pat_test_token"
PATH = "/api/events/v3/events"


class FakeEvents:
    def __init__(self, events_by_query: dict[str, list[dict[str, Any]]] | None = None) -> None:
        #: Подстрока PDQL-запроса → события; запрос без совпадения получает пустой список.
        self.events_by_query = events_by_query or {}
        #: Подстрока запроса → очередь кодов, которые вернутся до обычного ответа (500, 500, затем 200).
        self.status_once: dict[str, list[int]] = {}
        #: Начало окна запроса (`timeFrom`, секунды) → события: куски большого ханта отвечают по-разному.
        self.events_by_time_from: dict[int, list[dict[str, Any]]] = {}
        #: Сколько первых вызовов закончатся таймаутом.
        self.timeouts = 0
        self.calls: list[httpx.Request] = []

    def http_factory(self, conn: Any, timeout: float = 60.0) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        assert request.method == "POST" and request.url.path == PATH and request.url.port is None
        assert request.headers["Authorization"] == f"Bearer {TOKEN}"
        if self.timeouts > 0:
            self.timeouts -= 1
            raise httpx.ReadTimeout("timeout", request=request)
        body = json.loads(request.content)
        pdql = body["filter"]
        for needle, codes in self.status_once.items():
            if needle in pdql and codes:
                return httpx.Response(codes.pop(0), json={"detail": "по сценарию теста"})
        if body["timeFrom"] in self.events_by_time_from:
            return httpx.Response(200, json={"events": self.events_by_time_from[body["timeFrom"]]})
        for needle, events in self.events_by_query.items():
            if needle in pdql:
                return httpx.Response(200, json={"events": events})
        return httpx.Response(200, json={"events": []})
