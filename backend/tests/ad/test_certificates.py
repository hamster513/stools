"""CertificateStrength: стойкость сертификатов ЦС из AD (спека §5) и тест отпечатка ROCA."""
from __future__ import annotations

import base64
import datetime as dt
import random
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from api.modules.ad.core.checks.certificates import ROCA_PRIMES, is_roca
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.findings import Finding
from tests.ad.mini import NOW, mini_export, run
from tests.ad.synthetic import PKI, make_cert, rsa_key

ROOT_DN = f"CN=CORP-ROOT,CN=Certification Authorities,{PKI}"
AIA_DN = f"CN=CORP-ROOT,CN=AIA,{PKI}"
CA_DN = f"CN=CORP-CA,CN=Enrollment Services,{PKI}"
NTAUTH_DN = f"CN=NTAuthCertificates,{PKI}"
SHA1_RSA, MD5_RSA, MD2_RSA = "1.2.840.113549.1.1.5", "1.2.840.113549.1.1.4", "1.2.840.113549.1.1.2"
DSA_SHA1_OIW, MD5_RSA_OIW = "1.3.14.3.2.27", "1.3.14.3.2.3"


def b64(*ders: bytes) -> list[str]:
    return [base64.b64encode(d).decode() for d in ders]


def holder(*ders: bytes, store: str | None = "root", dn: str = ROOT_DN, cls: str = "certificationAuthority") -> dict[str, Any]:
    obj: dict[str, Any] = {"dn": dn, "class": cls, "cACertificate": b64(*ders)}
    if store:
        obj["store"] = store
    return obj


def check(*objects: dict[str, Any], cfg: AdConfig | None = None) -> list[Finding]:
    return run("CertificateStrength", mini_export(objects), cfg)


def kinds(*objects: dict[str, Any]) -> dict[str, str]:
    return {f.key_extra.split("|")[0]: f.severity for f in check(*objects)}


def _probable_prime(n: int, rng: random.Random) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(24):
        x = pow(rng.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def roca_prime(m: int, bits: int, rng: random.Random) -> int:
    """Простое вида k·M + 65537^a mod M — так строила ключи уязвимая библиотека Infineon (ROCA)."""
    # k — так, чтобы у p были два старших бита: тогда произведение двух таких простых ровно 2·bits бит.
    lo, hi = -(-(3 << (bits - 2)) // m), (1 << bits) // m
    while True:
        p = rng.randrange(lo, hi) * m + pow(65537, rng.randrange(1, 1 << 16), m)
        if p.bit_length() == bits and _probable_prime(p, rng):
            return p


def random_prime(bits: int, rng: random.Random) -> int:
    while True:
        p = rng.getrandbits(bits) | (3 << (bits - 2)) | 1
        if _probable_prime(p, rng):
            return p


def test_clean_and_expired_certificates_give_no_findings() -> None:
    clean = make_cert("CORP-ROOT")
    expired = make_cert("OLD-ROOT", bits=1024, not_after=NOW - dt.timedelta(days=1))
    assert check(holder(clean, expired)) == []


def test_root_rsa_1024_is_weak_low() -> None:
    assert kinds(holder(make_cert("CORP-ROOT", bits=1024))) == {"rsa_weak": "Low"}


def test_rsa_512_is_weak_high() -> None:
    # Ключ меньше 1024 бит библиотека не генерирует, но открытый ключ из чисел собрать даёт.
    rng = random.Random(512)
    small = rsa.RSAPublicNumbers(65537, random_prime(256, rng) * random_prime(256, rng)).public_key()
    assert kinds(holder(make_cert("CORP-ROOT", public_key=small))) == {"rsa_weak": "High"}


def test_sha1_is_low_for_intermediate_and_info_for_root() -> None:
    der = make_cert("CORP-SUB", issuer="CORP-ROOT", sig_oid=SHA1_RSA)
    assert kinds(holder(der, store="intermediate", dn=AIA_DN)) == {"hash": "Low"}
    assert kinds(holder(der, store="root")) == {"hash": "Info"}


def test_self_signed_is_root_in_any_store() -> None:
    """В CN=AIA лежат и корневые сертификаты: корневой определяется по самому сертификату."""
    assert kinds(holder(make_cert("CORP-ROOT", sig_oid=SHA1_RSA), store="intermediate", dn=AIA_DN)) == {"hash": "Info"}


def test_md_hashes_are_high_for_intermediate_and_info_for_root() -> None:
    assert kinds(holder(make_cert("CORP-SUB", issuer="CORP-ROOT", sig_oid=MD5_RSA), store="intermediate", dn=AIA_DN)) == {"hash": "High"}
    assert kinds(holder(make_cert("CORP-ROOT", sig_oid=MD2_RSA), store="root")) == {"hash": "Info"}


def test_oiw_signature_oids() -> None:
    dsa_sha1 = make_cert("CORP-SUB", issuer="CORP-ROOT", use_dsa=True, sig_oid=DSA_SHA1_OIW)
    assert kinds(holder(dsa_sha1, store="intermediate", dn=AIA_DN)) == {"dsa": "Info", "hash": "Low"}
    md5 = make_cert("CORP-SUB", issuer="CORP-ROOT", sig_oid=MD5_RSA_OIW)
    assert kinds(holder(md5, store="intermediate", dn=AIA_DN)) == {"hash": "High"}


def test_small_exponent_and_dsa() -> None:
    assert kinds(holder(make_cert("CORP-ROOT", exponent=3))) == {"rsa_exponent": "Low"}
    assert kinds(holder(make_cert("CORP-ROOT", use_dsa=True))) == {"dsa": "Info"}


def test_roca_modulus_is_high() -> None:
    rng = random.Random(167)
    m = 1
    for p in ROCA_PRIMES:
        m *= p
    n = roca_prime(m, 1024, rng) * roca_prime(m, 1024, rng)
    assert is_roca(n)
    vulnerable = rsa.RSAPublicNumbers(65537, n).public_key()
    assert kinds(holder(make_cert("CORP-ROOT", public_key=vulnerable))) == {"roca": "High"}


def test_is_roca_on_a_subset_of_primes() -> None:
    rng = random.Random(13)
    m = 2 * 3 * 5 * 7 * 11 * 13
    n = roca_prime(m, 128, rng) * roca_prime(m, 128, rng)
    assert is_roca(n, primes=(3, 5, 7, 11, 13))
    # 65537 по модулю 11 порождает только {1, 10}: остаток 2 — не произведение его степеней.
    assert not is_roca(11 * 1000 + 2, primes=(3, 5, 7, 11, 13))
    assert not is_roca(rsa_key().public_key().public_numbers().n)


def test_finding_fields() -> None:
    der = make_cert("CORP-SUB", issuer="CORP-ROOT", sig_oid=SHA1_RSA)
    fp = x509.load_der_x509_certificate(der).fingerprint(hashes.SHA256()).hex()[:16]
    [f] = check(holder(der, store="intermediate", dn=AIA_DN), cfg=AdConfig(allowlist_full=["CN=CORP-SUB"]))
    assert (f.check, f.target, f.identity, f.key_extra) == ("CertificateStrength", AIA_DN, "CN=CORP-SUB", f"hash|{fp}")
    assert not f.allowlisted and f.severity == "Low"
    assert f.details["kind"] == "hash" and f.details["store"] == "intermediate" and f.details["details"]
    assert f.details["holders"] == [AIA_DN]


def test_enrollment_service_and_ntauth_are_intermediate_unless_self_signed() -> None:
    issued = make_cert("CORP-CA", issuer="CORP-ROOT", sig_oid=SHA1_RSA)
    self_signed = make_cert("CORP-CA", sig_oid=SHA1_RSA)
    for dn, cls in ((CA_DN, "pKIEnrollmentService"), (NTAUTH_DN, "pkiContainer")):
        assert kinds(holder(issued, store=None, dn=dn, cls=cls)) == {"hash": "Low"}
        assert kinds(holder(self_signed, store=None, dn=dn, cls=cls)) == {"hash": "Info"}


def test_one_finding_per_certificate_and_kind_across_holders() -> None:
    """Порядок держателей: корневое хранилище, AIA, NTAuth, ЦС выдачи; цель — первый, в details — все."""
    weak = make_cert("CORP-ROOT", bits=1024)
    [f] = check(holder(weak, store=None, dn=CA_DN, cls="pKIEnrollmentService"), holder(weak, weak, store="intermediate", dn=AIA_DN),
                holder(weak, store=None, dn=NTAUTH_DN, cls="pkiContainer"), holder(weak))
    assert (f.target, f.details["holders"]) == (ROOT_DN, [ROOT_DN, AIA_DN, NTAUTH_DN, CA_DN])
    sub = make_cert("CORP-SUB", issuer="CORP-ROOT", sig_oid=SHA1_RSA)
    [g] = check(holder(sub, store=None, dn=CA_DN, cls="pKIEnrollmentService"), holder(sub, store=None, dn=NTAUTH_DN, cls="pkiContainer"))
    assert (g.target, g.severity, g.details["holders"]) == (NTAUTH_DN, "Low", [NTAUTH_DN, CA_DN])


def test_undecodable_values_are_skipped() -> None:
    weak = make_cert("CORP-ROOT", bits=1024)
    obj = holder(weak)
    obj["cACertificate"] = ["not base64!", base64.b64encode(b"\x30\x03\x02\x01\x00").decode(), *obj["cACertificate"]]
    assert kinds(obj) == {"rsa_weak": "Low"}
