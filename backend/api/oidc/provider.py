"""Клиент провайдера OpenID Connect: discovery, ключи, обмен кода, проверка id_token.

Наружу — только httpx с фабрикой клиента: тесты подменяют её поддельным
провайдером с настоящей RSA-подписью. Discovery и JWKS кэшируются на десять
минут: они меняются раз в год, а вход происходит постоянно.

Любой невнятный ответ провайдера (не JSON, JSON не той формы) превращается в
`ProviderError`, а не в исключение наружу: на другом конце — чужая система,
её поведение не наша ответственность, а вход должен падать понятно.

За редиректами следуем везде, кроме обмена кода: там в теле запроса уходит
секрет клиента, и 307 с подменённым Location увёл бы его на чужой адрес.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx
import jwt

from api.oidc.settings import OidcSettings

HttpFactory = Callable[[], httpx.Client]
TIMEOUT = 15.0
CACHE_TTL = 600.0
#: Потолок ответа провайдера. Разбор JSON держит в памяти всё тело целиком,
#: а на другом конце чужая система: мегабайтов там быть не должно ни в
#: discovery, ни в ключах, ни в токенах.
MAX_BODY = 1_000_000

#: Подпись id_token принимаем только асимметричную: HS256 на секрете клиента
#: позволил бы подделать токен любому, кто этот секрет знает.
ALLOWED_ALGS = ("RS256", "RS512", "PS256", "ES256")


class ProviderError(Exception):
    """Провайдер недоступен (`oidc_unavailable`) или ответил негодным (`oidc_token`)."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


@dataclass(frozen=True)
class Discovery:
    """Адреса провайдера из `.well-known/openid-configuration`."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None


_discovery: dict[str, tuple[float, Discovery]] = {}
_jwks: dict[str, tuple[float, list[dict[str, Any]]]] = {}


def invalidate_cache() -> None:
    """Забыть discovery и JWKS: настройки изменились или админ проверяет связь."""
    _discovery.clear()
    _jwks.clear()


def _json(response: httpx.Response, code: str, what: str) -> Any:
    """Разобрать ответ провайдера, если он не слишком длинный."""
    if len(response.content) > MAX_BODY:
        raise ProviderError(code, f"{what}: ответ длиннее {MAX_BODY} байт")
    return response.json()


def _client(http_factory: HttpFactory | None, *, follow_redirects: bool = True) -> httpx.Client:
    if http_factory:
        return http_factory()
    return httpx.Client(timeout=TIMEOUT, follow_redirects=follow_redirects)


def fetch_discovery(issuer_url: str, http_factory: HttpFactory | None = None) -> Discovery:
    """Адреса провайдера; ответ кэшируется на десять минут по `issuer_url`.

    `issuer` из ответа обязан совпасть с настроенным адресом — иначе токены
    пришли бы от одного издателя, а проверялись против имени другого.
    """
    cached = _discovery.get(issuer_url)
    if cached and cached[0] > time.monotonic():
        return cached[1]
    url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
    try:
        with _client(http_factory) as http:
            response = http.get(url)
            response.raise_for_status()
            data = _json(response, "oidc_unavailable", "discovery")
        disco = Discovery(
            issuer=data["issuer"],
            authorization_endpoint=data["authorization_endpoint"],
            token_endpoint=data["token_endpoint"],
            jwks_uri=data["jwks_uri"],
            userinfo_endpoint=data.get("userinfo_endpoint"),
        )
    except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
        raise ProviderError(
            "oidc_unavailable", f"discovery недоступен: {type(exc).__name__}"
        ) from exc
    if disco.issuer.rstrip("/") != issuer_url.rstrip("/"):
        raise ProviderError(
            "oidc_unavailable",
            f"провайдер называет себя {disco.issuer}, а в настройках указан {issuer_url}",
        )
    _discovery[issuer_url] = (time.monotonic() + CACHE_TTL, disco)
    return disco


def fetch_jwks(
    jwks_uri: str,
    http_factory: HttpFactory | None = None,
    *,
    force: bool = False,
) -> list[dict[str, Any]]:
    """Ключи подписи провайдера (только для подписи, RSA и EC); кэш на десять минут.

    `force=True` читает JWKS мимо кэша — на случай, когда провайдер сменил ключ.
    """
    cached = _jwks.get(jwks_uri)
    if cached and cached[0] > time.monotonic() and not force:
        return cached[1]
    try:
        with _client(http_factory) as http:
            response = http.get(jwks_uri)
            response.raise_for_status()
            data = _json(response, "oidc_unavailable", "JWKS")["keys"]
    except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
        raise ProviderError("oidc_unavailable", f"JWKS недоступен: {type(exc).__name__}") from exc
    if not isinstance(data, list):
        raise ProviderError("oidc_unavailable", "в JWKS вместо списка ключей что-то другое")
    keys = [
        key
        for key in data
        if isinstance(key, dict)
        and key.get("use") in (None, "sig")
        and key.get("kty") in ("RSA", "EC")
    ]
    _jwks[jwks_uri] = (time.monotonic() + CACHE_TTL, keys)
    return keys


def exchange_code(
    disco: Discovery,
    settings: OidcSettings,
    code: str,
    code_verifier: str,
    http_factory: HttpFactory | None = None,
) -> dict[str, Any]:
    """Обменять код авторизации на токены. Без следования редиректам: в теле — секрет."""
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.redirect_uri,
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
        "code_verifier": code_verifier,
    }
    try:
        with _client(http_factory, follow_redirects=False) as http:
            response = http.post(disco.token_endpoint, data=form)
    except httpx.HTTPError as exc:
        raise ProviderError(
            "oidc_unavailable", f"token endpoint недоступен: {type(exc).__name__}"
        ) from exc
    if response.status_code != 200:
        raise ProviderError("oidc_token", f"обмен кода отклонён: HTTP {response.status_code}")
    try:
        data = _json(response, "oidc_token", "token endpoint")
    except ValueError as exc:
        raise ProviderError("oidc_token", "ответ token endpoint — не JSON") from exc
    if not isinstance(data, dict) or "id_token" not in data:
        raise ProviderError("oidc_token", "в ответе провайдера нет id_token")
    return dict(data)


def _key_for(header: dict[str, Any], keys: list[dict[str, Any]]) -> jwt.PyJWK | None:
    for key in keys:
        if key.get("kid") == header.get("kid"):
            try:
                return jwt.PyJWK(key)
            except jwt.PyJWTError as exc:
                raise ProviderError(
                    "oidc_token", f"ключ подписи не разбирается: {type(exc).__name__}"
                ) from exc
    return None


def verify_id_token(
    id_token: str,
    disco: Discovery,
    settings: OidcSettings,
    nonce: str,
    http_factory: HttpFactory | None = None,
) -> dict[str, Any]:
    """Проверить подпись, издателя, аудиторию, срок и nonce; вернуть claims.

    Неизвестный `kid` — повод один раз перечитать JWKS мимо кэша: ключ могли
    сменить уже после того, как JWKS туда попал.
    """
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as exc:
        raise ProviderError("oidc_token", "id_token не разбирается") from exc
    alg = header.get("alg")
    if alg not in ALLOWED_ALGS:
        raise ProviderError("oidc_token", f"алгоритм подписи id_token не разрешён: {alg}")
    key = _key_for(header, fetch_jwks(disco.jwks_uri, http_factory))
    if key is None:
        key = _key_for(header, fetch_jwks(disco.jwks_uri, http_factory, force=True))
    if key is None:
        raise ProviderError("oidc_token", "ключ подписи id_token неизвестен провайдеру")
    try:
        claims = jwt.decode(
            id_token, key.key, algorithms=[alg],
            audience=settings.client_id, issuer=disco.issuer,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise ProviderError("oidc_token", f"id_token отклонён: {type(exc).__name__}") from exc
    if claims.get("nonce") != nonce:
        raise ProviderError("oidc_token", "nonce не совпал")
    return dict(claims)


def fetch_userinfo(
    disco: Discovery,
    access_token: str,
    expected_sub: str,
    http_factory: HttpFactory | None = None,
) -> dict[str, Any]:
    """Дополнительные claims по access_token; пусто, если провайдер не даёт userinfo.

    `sub` в ответе обязан совпасть с тем, что в id_token: ответ про другого
    человека решал бы роль этого — его группы оттуда и берутся.
    """
    if not disco.userinfo_endpoint:
        return {}
    try:
        with _client(http_factory) as http:
            response = http.get(
                disco.userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"}
            )
            response.raise_for_status()
            claims = dict(_json(response, "oidc_token", "userinfo"))
    except (httpx.HTTPError, TypeError, ValueError) as exc:
        raise ProviderError("oidc_token", f"userinfo недоступен: {type(exc).__name__}") from exc
    if str(claims.get("sub")) != expected_sub:
        raise ProviderError("oidc_token", "userinfo вернул другой sub")
    return claims
