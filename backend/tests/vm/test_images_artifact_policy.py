import datetime as dt

from sqlalchemy import func, select

from api.modules.vm.core.harbor import REPORT_MIME, HarborClient
from api.modules.vm.models import VmHarborProjectPolicy, VmImage, VmImageCve
from api.modules.vm.services.image_policy import summaries
from tests.vm.test_harbor_sync import API, LIB, STOOLS, _sync, fake_harbor, fixture


def test_type_filter_applies_before_pagination_facets_detail_and_export(auth_client, db_session):
    for kind in ['image', 'helm', 'other', 'unknown']:
        db_session.add(VmImage(project='k8s', repository=kind, digest='sha256:' + kind, artifact_kind=kind))
    db_session.commit()
    response = auth_client.get('/api/vm/images?artifact_kind=helm&limit=1').json()
    assert response['total'] == 1 and response['facets']['artifact_kind'] == {'helm': 1}
    image = response['items'][0]
    assert image['repository'] == 'helm' and image['runtime_state'] == 'not_applicable'
    assert image['pull_policy']['state'] == 'not_applicable'
    detail = auth_client.get(f"/api/vm/images/{image['id']}").json()
    assert detail['artifact_kind'] == 'helm'
    assert detail['pull_policy'] == image['pull_policy']
    export = auth_client.get('/api/vm/images/export?artifact_kind=helm').content.decode('utf-8-sig')
    assert 'Тип артефакта' in export and 'Helm-чарт' in export and 'k8s/image' not in export
    multiple = auth_client.get('/api/vm/images?artifact_kind=helm&artifact_kind=image').json()
    assert multiple['total'] == 2


def test_legacy_unknown_and_registry_mismatch_are_not_allowed(auth_client, db_session):
    db_session.add(VmImage(project='lib', repository='old', digest='old'))
    db_session.add(VmImage(project='lib', repository='new', digest='new', artifact_kind='image', registry_url='https://new'))
    db_session.add(VmHarborProjectPolicy(project='lib', registry_url='https://old',
        data={'enabled': False}, checked_at=dt.datetime.now(dt.UTC), error=''))
    db_session.commit()
    data = auth_client.get('/api/vm/images').json()
    assert all(i['pull_policy']['state'] == 'unknown' for i in data['items'])


def test_helm_sync_does_not_resolve_container_runtime(db_session, monkeypatch):
    art = fixture('artifacts_library_debian.json')[0]
    art['type'] = 'CHART'
    art['media_type'] = 'application/vnd.cncf.helm.config.v1+json'
    art['scan_overview'] = {}
    seen = []
    monkeypatch.setattr(HarborClient, 'runtime_image_ids', lambda self, project, repo, digest: seen.append((project, repo)) or [digest])
    job, result = _sync(fake_harbor({f'{LIB}/debian/artifacts': [art]}))
    assert job.status == 'done' and result is not None
    assert ('library', 'debian') not in seen
    image = db_session.scalar(select(VmImage).where(VmImage.repository == 'debian'))
    assert image.artifact_kind == 'helm' and not image.runtime_ids and not image.runtime_error


def scenario():
    art = fixture('artifacts_stools_web.json')[0]
    art['scan_overview'][REPORT_MIME]['summary'] = {'total': 1, 'summary': {'High': 1}}
    report = {REPORT_MIME: {'vulnerabilities': [{'id': 'CVE-2026-1111', 'package': 'lib', 'version': '1', 'severity': 'High'}]}}
    policy = {'metadata': {'prevent_vul': 'true', 'severity': 'high', 'reuse_sys_cve_allowlist': 'false'}, 'cve_allowlist': {'items': []}}
    return fake_harbor({LIB: [], f'{STOOLS}/stools-web/artifacts': [art],
        f'{STOOLS}/stools-web/artifacts/*': report, f'{API}/projects/stools': policy})


def test_policy_refresh_changes_decision_without_rescan_or_removing_findings(db_session):
    fake = scenario()
    assert _sync(fake)[0].status == 'done'
    image = db_session.scalar(select(VmImage).where(VmImage.project == 'stools'))
    assert image.report_complete and summaries(db_session, [image])[image.id]['state'] == 'blocked'
    initial_pairs = db_session.scalar(select(func.count()).select_from(VmImageCve))
    fake.routes[f'{API}/projects/stools']['cve_allowlist']['items'] = [{'cve_id': 'CVE-2026-1111'}]
    fake.calls.clear()
    assert _sync(fake)[0].status == 'done'
    db_session.expire_all()
    assert not any(path.endswith('/additions/vulnerabilities') for path in fake.calls)
    decision = summaries(db_session, [image])[image.id]
    assert decision['state'] == 'allowed' and decision['excluded_count'] == 1
    assert db_session.scalar(select(func.count()).select_from(VmImageCve)) == initial_pairs
    fake.routes[f'{API}/projects/stools'] = 403
    assert _sync(fake)[0].status == 'done'
    db_session.expire_all()
    assert summaries(db_session, [image])[image.id]['state'] == 'unknown'
    assert db_session.scalar(select(func.count()).select_from(VmImageCve)) == initial_pairs


def test_partial_report_cannot_be_used_to_allow_download(db_session):
    fake = scenario()
    fake.routes[f'{STOOLS}/stools-web/artifacts/*'][REPORT_MIME]['vulnerabilities'] = []
    assert _sync(fake)[0].status == 'done'
    image = db_session.scalar(select(VmImage).where(VmImage.project == 'stools'))
    assert not image.report_complete
    assert summaries(db_session, [image])[image.id]['state'] == 'unknown'


def test_missing_scan_total_is_not_a_complete_clean_report(db_session):
    fake = scenario()
    fake.routes[f'{STOOLS}/stools-web/artifacts'][0]['scan_overview'][REPORT_MIME]['summary'] = {}
    fake.routes[f'{STOOLS}/stools-web/artifacts/*'][REPORT_MIME]['vulnerabilities'] = []
    assert _sync(fake)[0].status == 'done'
    image = db_session.scalar(select(VmImage).where(VmImage.project == 'stools'))
    assert not image.report_complete
    assert summaries(db_session, [image])[image.id]['state'] == 'unknown'


def test_deduplication_cannot_discard_uncertain_severity_and_allow_pull(db_session):
    fake = scenario()
    art = fake.routes[f'{STOOLS}/stools-web/artifacts'][0]
    art['scan_overview'][REPORT_MIME]['summary'] = {'total': 2, 'summary': {'Low': 1, 'Unknown': 1}}
    items = fake.routes[f'{STOOLS}/stools-web/artifacts/*'][REPORT_MIME]['vulnerabilities']
    items[0]['severity'] = 'Low'
    items.append({**items[0], 'severity': 'unrecognized'})
    assert _sync(fake)[0].status == 'done'
    image = db_session.scalar(select(VmImage).where(VmImage.project == 'stools'))
    assert not image.report_complete
    assert summaries(db_session, [image])[image.id]['state'] == 'unknown'
