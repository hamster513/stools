"""Вход в AD по NTLM (формат ДОМЕН\\имя) должен работать в сборке.

NTLM считает хеш пароля через MD4, а в OpenSSL 3 он выключен; ldap3 тогда
берёт MD4 из pycryptodome. Без пакета вход падал «ошибкой сервера».
"""
from __future__ import annotations

from ldap3.utils.ntlm import NtlmClient


def test_ntlm_password_hash_is_computable() -> None:
    digest = NtlmClient("CORP", "svc", "secret").ntowf_v2()
    assert isinstance(digest, bytes) and len(digest) == 16
