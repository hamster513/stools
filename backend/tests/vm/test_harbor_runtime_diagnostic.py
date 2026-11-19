import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from api.modules.vm.core.harbor import HarborClient


def load_probe():
    script = (Path(__file__).resolve().parents[3] / "ops" / "diagnose_harbor_runtime.sh").read_text()
    source = script.split("<<'HARBOR_PROBE_PY'\n", 1)[1].split("\nHARBOR_PROBE_PY\n", 1)[0]
    scope = {"__name__": "harbor_diagnostic"}
    exec(compile(source, "harbor_diagnostic", "exec"), scope)
    return scope


@pytest.mark.parametrize(("scenario", "expected"), [
    ("ok", ("metadata=200", "token=200", "pull=да", "manifest=200", "OK")),
    ("no_grant", ("metadata=200", "token=200", "pull=не выдан", "manifest=401", "MANIFEST_HTTP_401")),
    ("token_denied", ("token=403", "MANIFEST_AUTH_HTTP_403")),
    ("opaque", ("pull=неизвестно", "manifest=401")),
    ("policy", ("manifest=412", "PROJECTPOLICYVIOLATION", "уязвимост", "id=abcd-1234")),
    ("child_policy", ("manifest=412 (дочерний)", "требование подписи")),
    ("error_html", ("manifest=412", "ответ без известного кода", "id=abcd-1234")),
    ("missing_artifact", ("metadata=404", "manifest=404", "MANIFEST_HTTP_404")),
    ("public", ("token=—", "manifest=200", "OK")),
])
def test_registry_probe(scenario, expected, capsys):
    probe = load_probe()
    body = json.dumps({"schemaVersion": 2, "config": {
        "mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + "1" * 64,
    }}).encode()
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    child = "sha256:" + "2" * 64
    if scenario == "child_policy":
        body = json.dumps({"schemaVersion": 2, "manifests": [{"digest": child}]}).encode()
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
    secret = "dummy-secret-must-stay-private"
    grants = [] if scenario == "no_grant" else [{"type": "repository", "name": "ccr/a/b", "actions": ["pull"]}]
    payload = base64.urlsafe_b64encode(json.dumps({"access": grants}).encode()).rstrip(b"=").decode()
    token = "opaque-secret-token" if scenario == "opaque" else "x." + payload + ".dummy-signature"

    def handler(req):
        assert req.url.host == "harbor.test"
        if req.url.path.startswith("/api/"):
            assert req.headers["Authorization"].startswith("Basic ")
            return httpx.Response(404 if scenario == "missing_artifact" else 200, json={})
        if req.url.path == "/service/token":
            assert req.url.params["scope"] == "repository:ccr/a/b:pull"
            assert req.headers["Authorization"].startswith("Basic ")
            return httpx.Response(403 if scenario == "token_denied" else 200, json={"token": token})
        assert req.method == "GET" and req.url.path.startswith("/v2/ccr/a/b/manifests/")
        if req.url.path.endswith(child) and scenario == "child_policy":
            return httpx.Response(412, json={"errors": [{"code": "DENIED", "message": "image is not signed"}]})
        assert req.url.path.endswith(digest)
        if "Authorization" not in req.headers and scenario != "public":
            return httpx.Response(401, headers={"WWW-Authenticate": 'Bearer realm="https://elsewhere.test",service="harbor-registry"'})
        if scenario in {"no_grant", "opaque"}:
            return httpx.Response(401, json={"errors": [{"code": "UNAUTHORIZED", "message": secret}]})
        if scenario == "missing_artifact":
            return httpx.Response(404, json={"errors": [{"code": "MANIFEST_UNKNOWN"}]})
        if scenario == "error_html":
            return httpx.Response(412, content="<html>" + secret + "</html>", headers={"X-Request-Id": "abcd-1234"})
        if scenario == "policy":
            return httpx.Response(412, headers={"X-Request-Id": "abcd-1234"}, json={"errors": [{
                "code": "PROJECTPOLICYVIOLATION", "message": "image with 3 vulnerabilities " + secret,
            }]})
        return httpx.Response(200, content=body)

    conn = SimpleNamespace(url="https://harbor.test", robot_name="robot$test", robot_secret=secret)
    with httpx.Client(transport=httpx.MockTransport(handler), auth=(conn.robot_name, secret)) as http:
        probe["probe_sample"](HarborClient(conn, http), "ccr", "a/b", digest)
    output = capsys.readouterr().out
    assert all(part in output for part in expected), output
    assert secret not in output and token not in output and "elsewhere.test" not in output
