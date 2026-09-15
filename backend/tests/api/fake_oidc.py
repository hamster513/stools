"""Поддельный провайдер OpenID Connect для тестов.

Отвечает на discovery, JWKS, обмен кода и userinfo через
`httpx.MockTransport` — сеть не поднимается, но id_token подписан
настоящим ключом RSA, так что проверка подписи в `api.oidc.provider`
работает по-честному.

`down`, `garbage` и `advertised_issuer` позволяют изобразить недоступный,
невнятный или чужой провайдер, `id_token_for` — выписать заведомо негодный
токен (чужой алгоритм, без `kid`, просроченный).
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.parse
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

#: Адрес возврата, который поддельный провайдер ждёт при обмене кода:
#: TestClient обращается к приложению как `http://testserver`.
DEFAULT_REDIRECT_URI = "http://testserver/api/auth/oidc/callback"


class FakeProvider:
    def __init__(self, issuer: str = "https://fam.test/realms/corp") -> None:
        self.issuer = issuer
        #: Что провайдер называет своим `issuer` в discovery — обычно себя.
        self.advertised_issuer = issuer
        self.client_id = "stools"
        self.client_secret = "s3cr3t"
        self.redirect_uri = DEFAULT_REDIRECT_URI
        self.calls: list[str] = []
        self.down = False
        #: Точки, которые отвечают мусором: "discovery", "certs", "token".
        self.garbage: set[str] = set()
        #: Точки, которые отвечают телом больше мегабайта: пока только "certs".
        self.oversized: set[str] = set()
        self._codes: dict[str, dict[str, Any]] = {}
        self._tokens: dict[str, dict[str, Any]] = {}
        self.rotate_key()

    def rotate_key(self) -> None:
        """Новый ключ подписи; старый из JWKS пропадает."""
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = secrets.token_hex(4)

    def _jwk(self) -> dict[str, Any]:
        jwk: dict[str, Any] = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self._key.public_key()))
        return {**jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}

    def id_token_for(
        self,
        claims: dict[str, Any],
        *,
        key: Any = None,
        aud: str | None = None,
        nonce: str | None = None,
        alg: str = "RS256",
        issuer: str | None = None,
        with_kid: bool = True,
    ) -> str:
        """Подписанный id_token. Значения из `claims` перекрывают умолчания."""
        now = int(time.time())
        payload = {
            "iss": issuer or self.issuer,
            "aud": aud or self.client_id,
            "iat": now,
            "exp": now + 300,
            **claims,
        }
        if nonce is not None:
            payload["nonce"] = nonce
        if key is None:
            key = "" if alg == "none" else self._key
        headers = {"kid": self.kid} if with_kid else {}
        return jwt.encode(payload, key, algorithm=alg, headers=headers)

    def issue_code(
        self,
        sub: str,
        login: str,
        name: str,
        groups: list[str],
        *,
        nonce: str,
        groups_in_id_token: bool = True,
        code_challenge: str | None = None,
        userinfo_sub: str | None = None,
    ) -> str:
        """Код авторизации. `code_challenge` — тот, что пришёл на authorize:
        обмен потребует к нему подходящий `code_verifier` (None — не
        проверять, для тестов самого клиента провайдера). `userinfo_sub` —
        чужой `sub` в ответе userinfo, испорченный провайдер."""
        code = secrets.token_urlsafe(16)
        self._codes[code] = {
            "sub": sub,
            "login": login,
            "name": name,
            "groups": groups,
            "nonce": nonce,
            "in_id_token": groups_in_id_token,
            "code_challenge": code_challenge,
            "userinfo_sub": userinfo_sub,
        }
        return code

    @staticmethod
    def challenge_for(code_verifier: str) -> str:
        """S256: base64url(sha256(verifier)) без выравнивающих '='."""
        digest = hashlib.sha256(code_verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    def _token_response(self, request: httpx.Request) -> httpx.Response:
        form = dict(urllib.parse.parse_qsl(request.content.decode()))
        issued = self._codes.pop(form.get("code", ""), None)
        verifier = form.get("code_verifier", "")
        if (
            issued is None
            or form.get("grant_type") != "authorization_code"
            or form.get("client_id") != self.client_id
            or form.get("client_secret") != self.client_secret
            or not verifier
            or form.get("redirect_uri") != self.redirect_uri
        ):
            return httpx.Response(400, json={"error": "invalid_grant"})
        #: PKCE: код годится только тому, кто знает verifier от challenge,
        #: с которым код запрашивали, — иначе перехваченный код обменял бы
        #: на токены кто угодно.
        challenge = issued["code_challenge"]
        if challenge is not None and not secrets.compare_digest(
            challenge, self.challenge_for(verifier)
        ):
            return httpx.Response(400, json={"error": "invalid_grant"})
        if "token" in self.garbage:
            return httpx.Response(200, text="<html>не JSON</html>")
        claims: dict[str, Any] = {
            "sub": issued["sub"],
            "preferred_username": issued["login"],
            "name": issued["name"],
        }
        if issued["in_id_token"]:
            claims["groups"] = issued["groups"]
        access = secrets.token_urlsafe(16)
        self._tokens[access] = {
            "sub": issued["userinfo_sub"] or issued["sub"],
            "groups": issued["groups"],
        }
        return httpx.Response(200, json={
            "access_token": access,
            "token_type": "Bearer",
            "id_token": self.id_token_for(claims, nonce=issued["nonce"]),
        })

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request.url.path)
        if self.down:
            raise httpx.ConnectError("down")
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            if "discovery" in self.garbage:
                return httpx.Response(200, text="<html>не JSON</html>")
            return httpx.Response(200, json={
                "issuer": self.advertised_issuer,
                "authorization_endpoint": f"{self.issuer}/protocol/openid-connect/auth",
                "token_endpoint": f"{self.issuer}/protocol/openid-connect/token",
                "jwks_uri": f"{self.issuer}/protocol/openid-connect/certs",
                "userinfo_endpoint": f"{self.issuer}/protocol/openid-connect/userinfo",
            })
        if path.endswith("/certs"):
            if "certs" in self.garbage:
                return httpx.Response(200, json="ключи? какие ключи")
            if "certs" in self.oversized:
                return httpx.Response(
                    200, json={"keys": [self._jwk()], "padding": "x" * 1_100_000}
                )
            # Второй ключ — не для подписи: настоящий JWKS тоже не одними
            # подписными ключами полон, клиент обязан их отсеять.
            symmetric = {"kty": "oct", "kid": "sym", "k": "AAAA"}
            return httpx.Response(200, json={"keys": [self._jwk(), symmetric]})
        if path.endswith("/token"):
            return self._token_response(request)
        if path.endswith("/userinfo"):
            token = request.headers.get("Authorization", "").removeprefix("Bearer ")
            info = self._tokens.get(token)
            return httpx.Response(200, json=info) if info else httpx.Response(401)
        return httpx.Response(404)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def http_factory(self) -> httpx.Client:
        return httpx.Client(transport=self.transport())
