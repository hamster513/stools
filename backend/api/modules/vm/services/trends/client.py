import json
import ssl
from typing import Any

import httpx


class CollectorError(ValueError):
    pass


class CollectorCursorExpired(CollectorError):
    pass


def tls_context(pem: Any) -> Any:
    context = ssl.create_default_context()
    if pem:
        try:
            context.load_verify_locations(cadata=pem)
        except (ssl.SSLError, ValueError) as exc:
            raise CollectorError("неверный сертификат CA") from exc
    return context


class CollectorClient:
    def __init__(self, connection: Any) -> None:
        if not connection.configured:
            raise CollectorError("подключение к сборщику не настроено")
        self.connection = connection
        proxy = None
        if connection.proxy_enabled:
            url = httpx.URL(scheme=connection.proxy_scheme, host=connection.proxy_host, port=connection.proxy_port)
            auth = (connection.proxy_username, connection.proxy_password) if connection.proxy_username else None
            proxy = httpx.Proxy(url, auth=auth, ssl_context=tls_context(connection.proxy_ca_pem)
                               if connection.proxy_scheme == "https" else None)
        self.client = httpx.Client(base_url=connection.url, proxy=proxy,
            verify=tls_context(connection.ca_pem), trust_env=False, follow_redirects=False,
            timeout=httpx.Timeout(30, connect=10), headers={"Authorization": "Bearer " + connection.token})

    def __enter__(self) -> Any:
        return self

    def __exit__(self, *args: object) -> None:
        self.client.close()

    def request(self, method: Any, path: Any, **kwargs: Any) -> Any:
        try:
            with self.client.stream(method, path, **kwargs) as response:
                if response.status_code >= 300:
                    messages = {401: "токен сборщика отклонён", 403: "недостаточно прав токена",
                                407: "прокси требует авторизацию (407)", 409: "конфликт версии или позиции синхронизации"}
                    error = CollectorCursorExpired if response.status_code == 409 else CollectorError
                    raise error(messages.get(response.status_code, f"сборщик вернул HTTP {response.status_code}"))
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > 8 * 1024 * 1024:
                        raise CollectorError("ответ сборщика превышает лимит")
                    chunks.append(chunk)
                return json.loads(b"".join(chunks))
        except httpx.ProxyError as exc:
            raise CollectorError("ошибка подключения или авторизации прокси (CONNECT)") from exc
        except httpx.TimeoutException as exc:
            raise CollectorError("истекло время ожидания выбранного маршрута") from exc
        except httpx.ConnectError as exc:
            if "CERTIFICATE_VERIFY_FAILED" in str(exc):
                raise CollectorError("сертификат TLS не прошёл проверку") from exc
            raise CollectorError("сборщик или прокси недоступен по выбранному маршруту") from exc
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            raise CollectorError("не удалось прочитать ответ сборщика") from exc

    def info(self) -> Any:
        info = self.request("GET", "/api/v1/info")
        if info.get("protocol_version") not in (1, 2):
            raise CollectorError("несовместимая версия протокола сборщика")
        return info

    def sources(self) -> Any:
        return self.request("GET", "/api/v1/sources")

    def changes(self, after: Any, until: Any=None) -> Any:
        params = {"after": after, "limit": 100}
        if until is not None:
            params["until"] = until
        return self.request("GET", "/api/v1/changes", params=params)


    def create_snapshot(self) -> Any:
        return self.request("POST", "/api/v1/snapshots")

    def snapshot_page(self, snapshot_id: str, after: int = 0) -> Any:
        return self.request("GET", "/api/v1/snapshots/" + snapshot_id, params={"after":after, "limit":100})
