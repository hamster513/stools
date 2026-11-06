import hashlib
import json
from types import SimpleNamespace

import httpx
import pytest

from api.modules.vm.core.harbor import HarborClient, HarborError

CONFIG = 'sha256:' + 'a' * 64
CONN = SimpleNamespace(url='https://registry.example', robot_name='robot', robot_secret='test', verify_tls=True)


def manifest(config=CONFIG):
    raw = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                      'config': {'mediaType': 'application/vnd.oci.image.config.v1+json', 'digest': config}}).encode()
    return 'sha256:' + hashlib.sha256(raw).hexdigest(), raw


def test_index_resolves_configs_with_same_origin_token_and_skips_attestation():
    digest, raw = manifest()
    index = json.dumps({'schemaVersion': 2, 'manifests': [
        {'digest': digest, 'platform': {'os': 'linux', 'architecture': 'amd64'}},
        {'digest': 'sha256:' + 'f'*64, 'platform': {'os': 'unknown', 'architecture': 'unknown'}},
    ]}).encode()
    root = 'sha256:' + hashlib.sha256(index).hexdigest()
    calls = []

    def handler(request):
        assert request.url.host == 'registry.example'
        calls.append(request.url.path)
        if request.url.path == '/service/token':
            assert request.url.params['scope'] == 'repository:team/app:pull'
            return httpx.Response(200, json={'token': 'test-token'})
        if request.headers.get('Authorization') != 'Bearer test-token':
            return httpx.Response(401, headers={'WWW-Authenticate': 'Bearer realm="https://untrusted.example/token",service="harbor-registry"'})
        return httpx.Response(200, content=index if request.url.path.endswith(root) else raw)

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        ids = HarborClient(CONN, http).runtime_image_ids('team', 'app', root)
    assert set(ids) == {root, digest, CONFIG}
    assert calls.count('/service/token') == 1
    assert not any('f'*64 in path for path in calls)


def test_manifest_digest_mismatch_rejected():
    digest, raw = manifest()
    with (
        httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=raw+b' '))) as http,
        pytest.raises(HarborError),
    ):
        HarborClient(CONN, http).runtime_image_ids('team', 'app', digest)


def test_registry_redirect_not_followed():
    calls=[]
    digest, _ = manifest()
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={'Location':'https://untrusted.example/leak'})
    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True) as http, pytest.raises(HarborError):
        HarborClient(CONN,http).runtime_image_ids('team','app',digest)
    assert len(calls)==1 and calls[0].startswith(CONN.url)


def test_manifest_graph_is_bounded(monkeypatch):
    from api.modules.vm.core import registry_manifests
    monkeypatch.setattr(registry_manifests,'MAX_MANIFESTS',2)
    manifests=dict(manifest('sha256:'+c*64) for c in 'abc')
    raw=json.dumps({'schemaVersion':2,'manifests':[{'digest':key} for key in manifests]}).encode()
    root='sha256:'+hashlib.sha256(raw).hexdigest()
    manifests[root]=raw
    calls=[]
    def handler(request):
        ref=request.url.path.split('/')[-1]; calls.append(ref)
        return httpx.Response(200,content=manifests[ref])
    with httpx.Client(transport=httpx.MockTransport(handler)) as http, pytest.raises(HarborError, match='MANIFEST_LIMIT'):
        HarborClient(CONN,http).runtime_image_ids('team','app',root)
    assert len(calls)==2
