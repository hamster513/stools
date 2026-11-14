"""Offline certificate inspection: strict parsing, identity and explicit trust."""
from base64 import b64encode
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from api.modules.toolbox.services.certificates import inspect_certificates


def _certificate(name, key, issuer=None, issuer_key=None, *, ca=False, expired=False):
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (x509.CertificateBuilder().subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=10))
        .not_valid_after(now + timedelta(days=-1 if expired else 30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key((issuer_key or key).public_key()), critical=False)
        .add_extension(x509.KeyUsage(True, False, False, False, False, ca, ca, False, False), critical=True))
    if not ca:
        builder = (builder.add_extension(x509.SubjectAlternativeName([
            x509.DNSName('example.test'), x509.DNSName('*.example.test'),
            x509.IPAddress(ip_address('192.0.2.10'))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    return builder.sign(issuer_key or key, hashes.SHA256())


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
def chain():
    root_key, intermediate_key, leaf_key = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
    root = _certificate('Root', root_key, ca=True)
    intermediate = _certificate('Intermediate', intermediate_key, root, root_key, ca=True)
    leaf = _certificate('example.test', leaf_key, intermediate, intermediate_key)
    return root, intermediate, leaf, intermediate_key, leaf_key


def test_metadata_and_absent_roots_never_trusted(chain):
    root, intermediate, leaf, _, _ = chain
    result = inspect_certificates(_pem(leaf) + _pem(intermediate) + _pem(root), hostname='example.test')
    assert result['parse_status'] == 'parsed'
    assert result['trust']['status'] == 'not_checked'
    assert result['hostname']['status'] == 'match'
    cert = result['certificates'][0]
    assert cert['subject'] == 'CN=example.test'
    assert cert['validity']['status'] == 'valid'
    assert cert['sha256'] == ':'.join(f'{b:02X}' for b in leaf.fingerprint(hashes.SHA256()))
    assert cert['key_algorithm'] == 'EC secp256r1 (256 bits)'
    assert cert['signature_algorithm']
    assert len(cert['san']) == 3


def test_explicit_chain_and_wrong_roots(chain):
    root, intermediate, leaf, _, _ = chain
    result = inspect_certificates(_pem(leaf) + _pem(intermediate), hostname='example.test', trust_roots=_pem(root))
    assert result['trust']['status'] == 'trusted'
    assert result['trust']['chain_length'] == 3
    other = _certificate('Other', ec.generate_private_key(ec.SECP256R1()), ca=True)
    assert inspect_certificates(_pem(leaf) + _pem(intermediate), hostname='example.test', trust_roots=_pem(other))['trust']['status'] == 'failed'
    assert inspect_certificates(_pem(leaf), hostname='example.test', trust_roots=_pem(root))['trust']['status'] == 'failed'


@pytest.mark.parametrize(('name', 'status'), [('a.example.test', 'match'), ('a.b.example.test', 'mismatch'), ('other.test', 'mismatch'), ('192.0.2.10', 'match'), ('192.0.2.11', 'mismatch')])
def test_hostname_matches_san_only(chain, name, status):
    result = inspect_certificates(_pem(chain[2]), hostname=name)
    assert result['hostname']['status'] == status
    assert result['trust']['status'] != 'trusted'


def test_expired_certificate_parses_but_fails_verification(chain):
    root, intermediate, _, intermediate_key, leaf_key = chain
    expired = _certificate('example.test', leaf_key, intermediate, intermediate_key, expired=True)
    result = inspect_certificates(_pem(expired) + _pem(intermediate), hostname='example.test', trust_roots=_pem(root))
    assert result['certificates'][0]['validity']['status'] == 'expired'
    assert result['hostname']['status'] == 'match'
    assert result['trust']['status'] == 'failed'


def test_der_and_missing_verification_name(chain):
    der = chain[2].public_bytes(serialization.Encoding.DER)
    result = inspect_certificates(b64encode(der).decode(), encoding='der_base64', trust_roots=_pem(chain[0]))
    assert len(result['certificates']) == 1
    assert result['hostname']['status'] == 'not_checked'
    assert result['trust']['status'] == 'hostname_required'
    with pytest.raises(ValueError):
        inspect_certificates(b64encode(der + b'junk').decode(), encoding='der_base64')


@pytest.mark.parametrize('text', ['', 'junk', '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----', '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----', 'x' * (1024 * 1024 + 1)])
def test_rejects_invalid_without_echoing_input(text):
    with pytest.raises(ValueError) as caught:
        inspect_certificates(text)
    assert 'secret' not in str(caught.value)
    assert 'AAAA' not in str(caught.value)


def test_strict_pem_bounds_and_invalid_roots(chain):
    pem = _pem(chain[2])
    for data in (pem + 'junk', pem * 17, pem + '-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----'):
        with pytest.raises(ValueError):
            inspect_certificates(data)
    with pytest.raises(ValueError):
        inspect_certificates(pem, trust_roots='junk')
    with pytest.raises(ValueError):
        inspect_certificates(pem, hostname='https://example.test/path')


def test_http_contract_and_sanitized_validation(chain):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from api.modules.toolbox.routers.certificates import router

    app = FastAPI()
    app.include_router(router, prefix='/api/toolbox')
    with TestClient(app) as client:
        response = client.post('/api/toolbox/certificates/inspect', json={'data': _pem(chain[2]), 'hostname': 'example.test'})
        assert response.status_code == 200
        assert response.json()['hostname']['status'] == 'match'
        for payload in ({'data': ['secret']}, {'data': 'secret'}, {'data': _pem(chain[2]), 'encoding': 'bad'}, []):
            response = client.post('/api/toolbox/certificates/inspect', json=payload)
            assert response.status_code == 422
            assert 'secret' not in response.text
        response = client.post('/api/toolbox/certificates/inspect', content=b'x' * (3 * 1024 * 1024 + 1))
        assert response.status_code == 413


def test_invalid_signature_cannot_be_trusted(chain):
    root, intermediate, leaf, _, _ = chain
    der = bytearray(leaf.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 1
    tampered = x509.load_der_x509_certificate(bytes(der))
    result = inspect_certificates(_pem(tampered) + _pem(intermediate), hostname='example.test', trust_roots=_pem(root))
    assert result['parse_status'] == 'parsed'
    assert result['trust']['status'] == 'failed'


def test_common_name_is_not_used_as_san_fallback():
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = _certificate('example.test', key, ca=True)
    result = inspect_certificates(_pem(certificate), hostname='example.test')
    assert result['hostname']['status'] == 'mismatch'


def test_deeply_nested_json_returns_safe_validation_error():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from api.modules.toolbox.routers.certificates import router

    app = FastAPI()
    app.include_router(router, prefix='/api/toolbox')
    with TestClient(app) as client:
        response = client.post('/api/toolbox/certificates/inspect', content='[' * 20000 + ']' * 20000)
        assert response.status_code == 422
        assert response.json() == {'detail': 'Нужен JSON с сертификатом.'}


def test_integrated_toolbox_read_boundary(chain, client, client_as):
    """The actual application allows inspection to readers, not unrelated module readers."""
    url = '/api/toolbox/certificates/inspect'
    payload = {'data': _pem(chain[2]), 'hostname': 'example.test'}
    assert client.post(url, json=payload).status_code == 401
    denied = client_as({'assets': 'read'})
    assert denied.post(url, json=payload).status_code == 403
    reader = client_as({'toolbox': 'read'})
    response = reader.post(url, json=payload)
    assert response.status_code == 200, response.text
    assert response.json()['trust']['status'] == 'not_checked'
    assert response.json()['hostname']['status'] == 'match'
