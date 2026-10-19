"""Стойкость сертификатов ЦС из AD (спека §5): ключи RSA короче 2048 бит и с малой экспонентой, подписи
MD2, MD4, MD5 и SHA-1, ключи DSA, модуль RSA с отпечатком ROCA. Просроченные и неразборчивые сертификаты
пропускаются. Сертификат, который лежит в нескольких объектах, — одна находка на вид."""
from __future__ import annotations

import base64
import datetime as dt
import functools

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, rsa

from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import AdObject, ExportIndex
from api.modules.ad.core.findings import Finding, finalize

#: Простые, по которым у ключей уязвимой библиотеки Infineon (CVE-2017-15361) модуль — степень 65537.
ROCA_PRIMES = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
    109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
)
#: Алгоритм подписи по OID: для MD2 и MD4 у библиотеки нет хеша, signature_hash_algorithm бросает исключение.
MD_SIGNATURES = {"1.2.840.113549.1.1.2": "MD2", "1.2.840.113549.1.1.3": "MD4", "1.2.840.113549.1.1.4": "MD5", "1.3.14.3.2.3": "MD5"}
SHA1_SIGNATURES = frozenset({"1.2.840.113549.1.1.5", "1.3.14.3.2.29", "1.2.840.10040.4.3", "1.3.14.3.2.27", "1.2.840.10045.4.1"})

#: (вид, серьёзность, описание)
Hit = tuple[str, str, str]


@functools.cache
def _roca_residues(p: int) -> frozenset[int]:
    return frozenset(pow(65537, k, p) for k in range(p))


def is_roca(modulus: int, primes: tuple[int, ...] = ROCA_PRIMES) -> bool:
    return all(modulus % p in _roca_residues(p) for p in primes)


def _load(value: str) -> x509.Certificate | None:
    try:
        return x509.load_der_x509_certificate(base64.b64decode(value, validate=True))
    except ValueError:
        return None


def _holder_rank(obj: AdObject) -> tuple[int, str]:
    """Порядок объектов-держателей: корневое хранилище, AIA, NTAuth, ЦС выдачи; внутри — по DN."""
    if obj.cls == "certificationAuthority":
        rank = 0 if obj.store == "root" else 1
    else:
        rank = 2 if obj.cls == "pkiContainer" else 3
    return rank, obj.dn.lower()


def _store(holder: AdObject, cert: x509.Certificate) -> str:
    """Корневой — самоподписанный, где бы он ни лежал (в AIA бывают и корневые). Иначе хранилище первого
    держателя-certificationAuthority; у ЦС выдачи и NTAuth — промежуточный."""
    if cert.issuer == cert.subject:
        return "root"
    if holder.cls == "certificationAuthority" and holder.store in ("root", "intermediate"):
        return holder.store
    return "intermediate"


def _key_hits(cert: x509.Certificate) -> list[Hit]:
    try:
        key = cert.public_key()
    except (ValueError, UnsupportedAlgorithm):
        return []
    hits: list[Hit] = []
    if isinstance(key, rsa.RSAPublicKey):
        numbers = key.public_numbers()
        if key.key_size < 1024:
            hits.append(("rsa_weak", "High", f"ключ RSA {key.key_size} бит: меньше 1024"))
        elif key.key_size < 2048:
            hits.append(("rsa_weak", "Low", f"ключ RSA {key.key_size} бит: меньше 2048"))
        if numbers.e < 65537:
            hits.append(("rsa_exponent", "Low", f"открытая экспонента RSA {numbers.e}: меньше 65537"))
        if is_roca(numbers.n):
            hits.append(("roca", "High", "модуль RSA с отпечатком ROCA (CVE-2017-15361): закрытый ключ вычисляется по открытому"))
    elif isinstance(key, dsa.DSAPublicKey):
        hits.append(("dsa", "Info", f"ключ DSA {key.key_size} бит"))
    return hits


def _hash_hit(cert: x509.Certificate, store: str) -> Hit | None:
    oid = cert.signature_algorithm_oid.dotted_string
    where = "корневого" if store == "root" else "промежуточного"
    if oid in MD_SIGNATURES:
        return "hash", "Info" if store == "root" else "High", f"подпись {MD_SIGNATURES[oid]} у {where} сертификата"
    if oid in SHA1_SIGNATURES:
        return "hash", "Info" if store == "root" else "Low", f"подпись SHA-1 у {where} сертификата"
    return None


def check_certificate_strength(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    now = idx.export.collected_at
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.UTC)
    # Отпечаток → сертификат и его держатели в порядке _holder_rank.
    certs: dict[str, tuple[x509.Certificate, list[AdObject]]] = {}
    for obj in sorted((o for o in idx.export.objects if o.cACertificate), key=_holder_rank):
        for value in obj.cACertificate:
            cert = _load(value)
            if cert is None or cert.not_valid_after_utc < now:
                continue
            _, holders = certs.setdefault(cert.fingerprint(hashes.SHA256()).hex(), (cert, []))
            # Держатели перебираются по одному: повтор сертификата в том же объекте — тот же последний держатель.
            if not holders or holders[-1] is not obj:
                holders.append(obj)
    out: list[Finding] = []
    for fingerprint, (cert, holders) in certs.items():
        store = _store(holders[0], cert)
        subject = cert.subject.rfc4514_string()
        hits = _key_hits(cert)
        if (hash_hit := _hash_hit(cert, store)) is not None:
            hits.append(hash_hit)
        for kind, severity, text in hits:
            details: dict[str, object] = {
                "details": text, "kind": kind, "store": store, "subject": subject, "issuer": cert.issuer.rfc4514_string(),
                "not_after": cert.not_valid_after_utc.date().isoformat(), "sha256": fingerprint, "holders": [h.dn for h in holders],
            }
            f = Finding(check="CertificateStrength", severity=severity, identity=subject, target=holders[0].dn,
                        key_extra=f"{kind}|{fingerprint[:16]}", details=details)
            out.append(finalize(f, cfg, allowlist=False))
    return out
