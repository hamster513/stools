"""Bounded offline X.509 inspection; no persistence, system roots or network access."""
from __future__ import annotations

import base64
import binascii
import re
from datetime import UTC, datetime
from ipaddress import ip_address

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

MAX_BYTES = 1024 * 1024
MAX_CERTIFICATES = 16
_PEM = re.compile(r'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----')


def _parse(data: str, encoding: str = 'pem') -> list[x509.Certificate]:
    if not isinstance(data, str) or not data.strip():
        raise ValueError('Добавьте сертификат PEM или DER.')
    if len(data) > (MAX_BYTES + 2) // 3 * 4:
        raise ValueError('Размер сертификатов превышает 1 МиБ.')
    if 'PRIVATE KEY' in data:
        raise ValueError('Приватные ключи не принимаются. Добавьте только сертификаты.')
    try:
        if encoding == 'der_base64':
            raw = base64.b64decode(data, validate=True)
            if len(raw) > MAX_BYTES:
                raise ValueError
            certificate = x509.load_der_x509_certificate(raw)
            if certificate.public_bytes(serialization.Encoding.DER) != raw:
                raise ValueError
            return [certificate]
        if encoding != 'pem' or len(data.encode('utf-8')) > MAX_BYTES:
            raise ValueError
        blocks = list(_PEM.finditer(data))
        if not blocks or len(blocks) > MAX_CERTIFICATES or _PEM.sub('', data).strip():
            raise ValueError
        return [x509.load_pem_x509_certificate(block.group().encode('ascii')) for block in blocks]
    except (ValueError, TypeError, binascii.Error, UnicodeError, UnsupportedAlgorithm):
        raise ValueError('Некорректный сертификат: нужен PEM (до 16 сертификатов) или один DER, до 1 МиБ.') from None


def _identity(hostname: str):
    name = hostname.strip().rstrip('.')
    if not name:
        return None
    try:
        return x509.IPAddress(ip_address(name))
    except ValueError:
        pass
    try:
        name = name.encode('idna').decode('ascii').lower()
        if len(name) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in name.split('.')):
            raise ValueError
        return x509.DNSName(name)
    except (UnicodeError, ValueError):
        raise ValueError('Укажите DNS-имя или IP-адрес без схемы, порта и пути.') from None


def _san(certificate):
    try:
        return list(certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        return []


def _matches(identity, names):
    if isinstance(identity, x509.IPAddress):
        return any(isinstance(name, x509.IPAddress) and name.value == identity.value for name in names)
    for name in names:
        if not isinstance(name, x509.DNSName):
            continue
        pattern = name.value.lower().rstrip('.')
        if pattern == identity.value:
            return True
        if pattern.startswith('*.') and '*' not in pattern[2:]:
            parts = identity.value.split('.')
            if len(parts) >= 3 and '.'.join(parts[1:]) == pattern[2:]:
                return True
    return False


def _key_description(key):
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f'EC {key.curve.name} ({key.key_size} bits)'
    if isinstance(key, rsa.RSAPublicKey):
        return f'RSA ({key.key_size} bits)'
    if isinstance(key, dsa.DSAPublicKey):
        return f'DSA ({key.key_size} bits)'
    if isinstance(key, ed25519.Ed25519PublicKey):
        return 'Ed25519'
    if isinstance(key, ed448.Ed448PublicKey):
        return 'Ed448'
    return 'Unknown'


def _describe(certificate, now):
    start, end = certificate.not_valid_before_utc, certificate.not_valid_after_utc
    oid = certificate.signature_algorithm_oid
    return {
        'subject': certificate.subject.rfc4514_string(),
        'issuer': certificate.issuer.rfc4514_string(),
        'serial': format(certificate.serial_number, 'X'),
        'san': [{'type': type(name).__name__, 'value': str(name.value)} for name in _san(certificate)],
        'validity': {'not_before': start.isoformat(), 'not_after': end.isoformat(),
                     'status': 'not_yet_valid' if now < start else 'expired' if now > end else 'valid'},
        'key_algorithm': _key_description(certificate.public_key()),
        'signature_algorithm': f'{oid._name} ({oid.dotted_string})',
        'sha256': ':'.join(f'{byte:02X}' for byte in certificate.fingerprint(hashes.SHA256())),
        'sha1': ':'.join(f'{byte:02X}' for byte in certificate.fingerprint(hashes.SHA1())),
    }


def inspect_certificates(data: str, *, encoding: str = 'pem', hostname: str = '', trust_roots: str = '') -> dict:
    certificates = _parse(data, encoding)
    roots = _parse(trust_roots) if trust_roots.strip() else []
    identity = _identity(hostname)
    now = datetime.now(UTC)
    try:
        details = [_describe(certificate, now) for certificate in certificates]
        matches = _matches(identity, _san(certificates[0])) if identity else None
    except (ValueError, UnsupportedAlgorithm, x509.DuplicateExtension):
        raise ValueError('Сертификат содержит некорректные или неподдерживаемые поля.') from None
    trust: dict[str, str | int] = {'status': 'not_checked', 'message': 'Корни доверия не заданы; доверие не проверено.'}
    if roots and identity is None:
        trust = {'status': 'hostname_required', 'message': 'Для проверки TLS-цепочки укажите DNS-имя или IP-адрес.'}
    elif roots:
        try:
            chain = (PolicyBuilder().store(Store(roots)).time(now).max_chain_depth(15)
                     .build_server_verifier(identity).verify(certificates[0], certificates[1:]))
            trust = {'status': 'trusted', 'message': 'TLS-цепочка проверена до явно заданного корня.', 'chain_length': len(chain)}
        except (VerificationError, ValueError, UnsupportedAlgorithm):
            trust = {'status': 'failed', 'message': 'TLS-проверка не пройдена: проверьте имя, сроки, промежуточные сертификаты, корни и ограничения X.509.'}
    return {'parse_status': 'parsed', 'certificates': details,
            'hostname': {'status': 'not_checked' if matches is None else 'match' if matches else 'mismatch',
                         'value': str(identity.value) if identity else ''}, 'trust': trust}
