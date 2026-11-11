"""Harbor artifact types and effective vulnerability pull policies."""
import datetime as dt
from types import SimpleNamespace

import httpx
import pytest

from api.modules.vm.core.harbor import HarborClient, HarborError
from api.modules.vm.services.image_policy import evaluate
from tests.vm.test_harbor_client import client_for


@pytest.mark.parametrize(('raw', 'kind'), [
    ({'type': 'CHART'}, 'helm'),
    ({'type': 'IMAGE', 'media_type': 'application/vnd.cncf.helm.config.v1+json'}, 'helm'),
    ({'artifact_type': 'application/vnd.cncf.helm.config.v1+json'}, 'helm'),
    ({'type': 'IMAGE', 'manifest_media_type': 'application/vnd.oci.image.index.v1+json'}, 'image'),
    ({'media_type': 'application/vnd.docker.container.image.v1+json'}, 'image'),
    ({'manifest_media_type': 'application/vnd.oci.image.manifest.v1+json'}, 'unknown'),
    ({'type': 'SBOM'}, 'other'), ({}, 'unknown'),
])
def test_artifact_kind_uses_payload_type_not_manifest_wrapper(raw, kind):
    assert HarborClient._artifact(raw).artifact_kind == kind


def project(reuse=False):
    return {'name': '123', 'metadata': {'prevent_vul': 'true', 'severity': 'high',
        'reuse_sys_cve_allowlist': str(reuse).lower()},
        'cve_allowlist': {'items': [{'cve_id': 'CVE-2026-1111'}], 'expires_at': 0}}


def test_project_allowlist_replaces_system_and_numeric_name_header():
    calls = []
    client = client_for(lambda r: httpx.Response(200, json=project()), calls)
    policy = client.project_policy('123')
    assert policy['allowlist'] == ['CVE-2026-1111']
    assert policy['allowlist_source'] == 'project'
    assert len(calls) == 1 and calls[0].headers['X-Is-Resource-Name'] == 'true'


def test_system_allowlist_cached_once_and_project_ignored():
    calls = []
    client = client_for(lambda r: httpx.Response(200, json=(
        {'items': [{'cve_id': 'CVE-2026-2222'}]} if r.url.path.endswith('/system/CVEAllowlist') else project(True)
    )), calls)
    for _ in range(2):
        policy = client.project_policy('123')
        assert policy['allowlist'] == ['CVE-2026-2222']
        assert policy['allowlist_source'] == 'system'
    assert sum(r.url.path.endswith('/system/CVEAllowlist') for r in calls) == 1


def test_system_failure_is_cached_and_not_empty_allowlist():
    calls = []
    client = client_for(lambda r: httpx.Response(403) if r.url.path.endswith('/system/CVEAllowlist')
                        else httpx.Response(200, json=project(True)), calls)
    for _ in range(2):
        with pytest.raises(HarborError):
            client.project_policy('123')
    assert sum(r.url.path.endswith('/system/CVEAllowlist') for r in calls) == 1


NOW = dt.datetime(2026, 11, 10, tzinfo=dt.UTC)


def assess(*, findings=(('CVE-2026-1111', 'high'),), policy=None, **image):
    img = SimpleNamespace(artifact_kind='image', is_index=False, scan_status='success',
                          report_complete=True, sync_error=None)
    for k, v in image.items():
        setattr(img, k, v)
    payload = {'enabled': True, 'threshold': 'high', 'allowlist_source': 'project', 'allowlist': [], 'expires_at': 0}
    payload.update(policy or {})
    snapshot = SimpleNamespace(data=payload, checked_at=NOW, error='')
    return evaluate(img, snapshot, findings, now=NOW)


def test_equal_threshold_blocks_but_lower_does_not():
    assert assess()['state'] == 'blocked'
    assert assess(findings=(('CVE-2026-1111', 'medium'),))['state'] == 'allowed'


def test_exclusions_expire_and_counts_are_unique_cves():
    found = [('CVE-2026-1111', 'critical'), ('CVE-2026-1111', 'high')]
    active = assess(findings=found, policy={'allowlist': ['CVE-2026-1111']})
    assert active['state'] == 'allowed' and active['excluded_count'] == 1
    expired = assess(findings=found, policy={'allowlist': ['CVE-2026-1111'], 'expires_at': int(NOW.timestamp()) - 1})
    assert expired['state'] == 'blocked' and expired['allowlist_expired']
    assert expired['blocking_count'] == 1


@pytest.mark.parametrize('attrs', [
    {'artifact_kind': 'unknown'}, {'is_index': True}, {'report_complete': False},
    {'scan_status': 'none'}, {'sync_error': 'NO_LINK'},
])
def test_missing_evidence_never_confirms_download(attrs):
    assert assess(**attrs)['state'] == 'unknown'


def test_unknown_severity_never_confirms_download():
    assert assess(findings=(('CVE-2026-1111', 'unknown'),))['state'] == 'unknown'


def test_disabled_gate_allows_without_scan_and_nonimage_is_not_applicable():
    assert assess(scan_status='none', policy={'enabled': False})['state'] == 'allowed'
    assert assess(artifact_kind='helm')['state'] == 'not_applicable'
    assert assess(artifact_kind='other')['state'] == 'not_applicable'


def test_failed_scan_blocks_with_gate_enabled():
    assert assess(scan_status='error')['state'] == 'blocked'


def test_policy_unavailable_does_not_allow():
    img = SimpleNamespace(artifact_kind='image', sync_error=None)
    assert evaluate(img, None, [], now=NOW)['state'] == 'unknown'
    snapshot = SimpleNamespace(data={'enabled': False}, checked_at=NOW, error='NO_RIGHTS')
    assert evaluate(img, snapshot, [], now=NOW)['state'] == 'unknown'


@pytest.mark.parametrize('body', [{}, {'vulnerabilities': {}}, {'vulnerabilities': [{'package': 'missing id'}]}])
def test_malformed_report_is_not_an_empty_clean_report(body):
    from api.modules.vm.core.harbor import REPORT_MIME

    client = client_for(lambda r: httpx.Response(200, json={REPORT_MIME: body}))
    with pytest.raises(HarborError):
        client.vulnerabilities('123', 'image', 'sha256:aaa')
