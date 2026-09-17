"""Разбор сертификата сервера KSC (`CertPoolCtrl.GetCertificateInfo`, поле `CPublic`).

Принимает обёртку `{"type": "binary", "value": …}`, бинарную обёртку KSC
после `unwrap` — сам base64, DER- или PEM-байты; на мусоре возвращает `None`.
"""
from __future__ import annotations

import base64
import binascii
import datetime as dt
from dataclasses import dataclass
from typing import Any

from cryptography import x509

from api.modules.ksc.core.export import unwrap


@dataclass
class CertInfo:
    subject: str
    not_after: dt.datetime


def _not_after(cert: x509.Certificate) -> dt.datetime:
    value = getattr(cert, "not_valid_after_utc", None)
    if isinstance(value, dt.datetime):
        return value
    return cert.not_valid_after.replace(tzinfo=dt.UTC)


def _load(der_or_pem: bytes) -> x509.Certificate | None:
    try:
        if der_or_pem.lstrip().startswith(b"-----BEGIN"):
            return x509.load_pem_x509_certificate(der_or_pem)
        return x509.load_der_x509_certificate(der_or_pem)
    except ValueError:
        return None


def parse_cert(cpublic: Any) -> CertInfo | None:
    value = unwrap(cpublic)
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("-----BEGIN"):
            data = text.encode("ascii", errors="ignore")
        else:
            try:
                data = base64.b64decode(text, validate=True)
            except (binascii.Error, ValueError):
                return None
    elif isinstance(value, bytes):
        data = value
    else:
        return None
    cert = _load(data)
    if cert is None:
        return None
    try:
        subject = cert.subject.rfc4514_string()
    except ValueError:
        return None
    return CertInfo(subject=subject, not_after=_not_after(cert))
