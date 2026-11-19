"""KSC TOTP: Base32 secret, SHA-1, 30-second steps, six digits."""
import base64
import binascii
import hashlib
import hmac
import re
import time

INVALID_SECRET = "Секрет TOTP должен быть ключом Base32 из приложения-аутентификатора, а не одноразовым кодом"


def normalize_secret(secret: str) -> str:
    if not secret.strip():
        return ""
    value = "".join(secret.split()).upper().rstrip("=")
    if len(secret) > 512 or not re.fullmatch(r"[A-Z2-7]+", value):
        raise ValueError(INVALID_SECRET)
    try:
        key = base64.b32decode(value + "=" * (-len(value) % 8))
    except (binascii.Error, ValueError):
        raise ValueError(INVALID_SECRET) from None
    if len(key) < 10 or base64.b32encode(key).decode().rstrip("=") != value:
        raise ValueError(INVALID_SECRET)
    return value


def totp_code(secret: str, *, at: float | None = None) -> str:
    value = normalize_secret(secret)
    if not value:
        raise ValueError(INVALID_SECRET)
    key = base64.b32decode(value + "=" * (-len(value) % 8))
    counter = int((time.time() if at is None else at) // 30)
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 15
    code = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"
