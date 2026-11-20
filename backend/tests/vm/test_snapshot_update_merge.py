import gzip
import json
from pathlib import Path

import pytest
from sqlalchemy import func, select

from api.modules.vm.core.ref_updates import SNAPSHOTS
from api.modules.vm.models import (
    VmRefAttack,
    VmRefEpss,
    VmRefExploitdb,
    VmRefExploitdbCve,
    VmRefKev,
    VmRefMsf,
    VmRefMsfCve,
    VmRefState,
)
from api.modules.vm.services.ref_updates import apply_update_bundle
from api.modules.vm.sync_models import VmRefSyncState
from tests.vm.test_archive_batches import URL, run, upload
from tests.vm.test_bundle import _zip
from tests.vm.test_ref_update_import import Handle
from tests.vm.test_ref_window_import import NVD_PATH, nvd, period_bundle


@pytest.mark.parametrize(('name', 'fixtures', 'model', 'key', 'old'), [
    ('epss', ['epss.csv'], VmRefEpss, 'CVE-2024-98765', {'epss': .2, 'percentile': .3}),
    ('kev', ['kev.json'], VmRefKev, 'CVE-2024-98765', {'name': 'saved'}),
    ('exploitdb', ['exploits.csv'], VmRefExploitdb, 999999, {'type': 'saved'}),
    ('msf', ['msf.json'], VmRefMsf, 'auxiliary/saved', {'name': 'saved'}),
    ('attack', ['ctid-kev.json', 'attack_to_cve.csv'], VmRefAttack,
     ('CVE-2024-98765', 'T1190'), {'mapping_type': 'primary_impact'}),
])
def test_update_snapshot_keeps_unmentioned_keys_and_links(tmp_path, db_session, name, fixtures, model, key, old):
    db = db_session
    pk = list(model.__table__.primary_key.columns.keys())
    db.add(model(**dict(zip(pk, key if isinstance(key, tuple) else (key,), strict=True)), **old))
    if name == 'exploitdb':
        db.add(VmRefExploitdbCve(exploit_id=key, cve_id='CVE-2024-98765'))
    if name == 'msf':
        db.add(VmRefMsfCve(fullname=key, cve_id='CVE-2024-98765'))
    db.commit()
    files = {}
    for (filename, _), fixture in zip(SNAPSHOTS[name], fixtures, strict=True):
        data = (Path(__file__).parent / 'fixtures' / fixture).read_bytes()
        files[filename] = gzip.compress(data) if filename.endswith('.gz') else data
    path = period_bundle(tmp_path, [{'name': name, 'mode': 'snapshot', 'paths': list(files)}], files)
    assert apply_update_bundle(db, Handle(db), path) == {name}
    assert db.get(model, key) is not None
    if name == 'exploitdb':
        assert db.get(VmRefExploitdbCve, ('CVE-2024-98765', key)) is not None
    if name == 'msf':
        assert db.get(VmRefMsfCve, ('CVE-2024-98765', key)) is not None
    total = db.scalar(select(func.count()).select_from(model))
    assert db.get(VmRefState, name).records == total
    assert db.get(VmRefSyncState, name).last_counts['upserted'] == total - 1
    assert apply_update_bundle(db, Handle(db), path) == set()


def test_batch_full_then_update_merges_by_cve_and_counts_writes(tmp_path, auth_client, db_session, monkeypatch):
    name = SNAPSHOTS['epss'][0][0]
    header = b'cve,epss,percentile\n'
    baseline = header + b'CVE-2025-1000,0.1,0.7\nCVE-2025-2000,0.2,0.8\nCVE-2025-3000,0.3,0.9\n'
    update = header + b'CVE-2025-1000,0.4,0.7\nCVE-2025-3000,0.3,0.9\nCVE-2025-4000,0.1,0.9\n'
    path = period_bundle(tmp_path, [{'name': 'epss', 'mode': 'snapshot', 'paths': [name]}], {name: gzip.compress(update)})
    response = upload(auth_client, ('epss-full.zip', _zip({name: gzip.compress(baseline)})),
                      ('epss-updates.zip', path.read_bytes()))
    assert response.status_code == 202
    run(db_session, monkeypatch)
    assert auth_client.get(URL).json()['items'][0]['status'] == 'done'
    values = dict(db_session.execute(select(VmRefEpss.cve_id, VmRefEpss.epss)).all())
    assert values == {'CVE-2025-1000': .4, 'CVE-2025-2000': .2, 'CVE-2025-3000': .3, 'CVE-2025-4000': .1}
    assert db_session.get(VmRefState, 'epss').records == 4
    counts = db_session.get(VmRefSyncState, 'epss').last_counts
    assert (counts['received'], counts['upserted'], counts['deleted']) == (3, 2, 0)
    # An explicit full catalogue still defines the entire source.
    assert upload(auth_client, ('epss-full.zip', _zip({name: gzip.compress(baseline)}))).status_code == 202
    run(db_session, monkeypatch)
    assert db_session.get(VmRefEpss, 'CVE-2025-4000') is None


@pytest.mark.parametrize("name", ["exploitdb", "msf"])
def test_changed_links_only_replace_references_of_the_supplied_parent(tmp_path, db_session, name):
    db = db_session
    payload = SNAPSHOTS[name][0][0]
    if name == 'exploitdb':
        model, link = VmRefExploitdb, VmRefExploitdbCve
        identity = {'exploit_id': 81}
        db.add(model(**identity, type='local', verified=False))
        data = b'id,type,codes\n81,local,CVE-2025-2000\n'
    else:
        model, link = VmRefMsf, VmRefMsfCve
        identity = {'fullname': 'sample'}
        db.add(model(**identity, name='sample', rank=0))
        data = b'{"sample":{"name":"sample","references":[["CVE","2025-2000"]]}}'
    db.add(link(**identity, cve_id='CVE-2025-1000'))
    db.commit()
    path = period_bundle(tmp_path, [{'name': name, 'mode': 'snapshot', 'paths': [payload]}], {payload: data})
    assert apply_update_bundle(db, Handle(db), path) == {name}
    assert list(db.scalars(select(link.cve_id))) == ['CVE-2025-2000']
    sync = db.get(VmRefSyncState, name)
    assert sync.last_counts == {'received': 1, 'upserted': 0, 'deleted': 0, 'links_changed': 2}
    assert sync.pending_rebuild
    sync.pending_rebuild = False
    db.commit()
    later = {'since': '2025-02-01T00:00:00Z', 'until': '2025-02-02T00:00:00Z'}
    identical = period_bundle(tmp_path, [{'name': name, 'mode': 'snapshot', 'paths': [payload]}],
                              {payload: data}, window=later, created_at=later['until'])
    assert apply_update_bundle(db, Handle(db), identical) == set()
    assert not db.get(VmRefSyncState, name).pending_rebuild
    assert db.get(VmRefSyncState, name).last_counts == {'received': 1, 'upserted': 0, 'deleted': 0, 'links_changed': 0}


def test_batch_nvd_keeps_old_cves_and_years_visible(tmp_path, auth_client, db_session, monkeypatch):
    from api.modules.vm.models import VmRefNvd

    before = nvd('old')
    before['timestamp'] = '2025-01-01T00:00:00Z'
    before['vulnerabilities'].append({'cve': {'id': 'CVE-2025-2000'}})
    previous_year = {'timestamp': before['timestamp'], **nvd('previous', year=2024)}
    base = _zip({'nvdcve-2.0-2025.json': json.dumps(before).encode(),
                 'nvdcve-2.0-2024.json': json.dumps(previous_year).encode()})
    update = nvd('updated')
    update['vulnerabilities'].append({'cve': {'id': 'CVE-2025-3000'}})
    path = period_bundle(tmp_path, payloads={NVD_PATH: update})
    assert upload(auth_client, ('nvd-full.zip', base), ('nvd-updates.zip', path.read_bytes())).status_code == 202
    run(db_session, monkeypatch)
    assert auth_client.get(URL).json()['items'][0]['status'] == 'done'
    state = next(row for row in auth_client.get('/api/vm/refs').json() if row['name'] == 'nvd')
    assert state['records'] == 4 and state['last_counts']['upserted'] == 2
    assert state['detail'] == 'годы: 2024, 2025'
    assert state['checkpoint']['years'] == [2024, 2025] and state['partial_window']
    assert db_session.get(VmRefNvd, 'CVE-2024-1000').description == 'previous'
    assert db_session.get(VmRefNvd, 'CVE-2025-1000').description == 'updated'
    assert db_session.get(VmRefNvd, 'CVE-2025-2000') and db_session.get(VmRefNvd, 'CVE-2025-3000')


@pytest.mark.parametrize("batch", [True, False])
def test_update_named_zip_without_its_manifest_cannot_replace_the_catalogue(auth_client, db_session, monkeypatch, batch):
    db_session.add(VmRefEpss(cve_id="CVE-2025-1000", epss=.4, percentile=.75))
    db_session.commit()
    # A recognisable native filename alone is enough to enter the legacy full-import path.
    data = _zip({"epss_scores-current.csv": b"cve,epss,percentile\nCVE-2025-2000,.2,.5\n"})
    if batch:
        assert upload(auth_client, ("epss-updates.zip", data)).status_code == 202
        run(db_session, monkeypatch)
        file = auth_client.get(URL).json()["items"][0]["files"][0]
        assert file["status"] == "failed" and "stools-reference-update.json" in file["error"]
    else:
        response = auth_client.post("/api/vm/refs/bundle/upload", files={"file": ("epss-updates.zip", data)})
        assert response.status_code == 422 and "stools-reference-update.json" in response.json()["detail"]
    assert db_session.get(VmRefEpss, "CVE-2025-1000") is not None
    assert db_session.get(VmRefEpss, "CVE-2025-2000") is None


def test_invalid_second_snapshot_rolls_back_first_source(tmp_path, db_session):
    epss = SNAPSHOTS["epss"][0][0]
    kev = SNAPSHOTS["kev"][0][0]
    db_session.add(VmRefEpss(cve_id="CVE-2025-1000", epss=.1, percentile=.5))
    db_session.commit()
    path = period_bundle(
        tmp_path,
        [{"name": "epss", "mode": "snapshot", "paths": [epss]},
         {"name": "kev", "mode": "snapshot", "paths": [kev]}],
        {epss: gzip.compress(b"cve,epss,percentile\nCVE-2025-1000,.8,.95\nCVE-2025-2000,.9,.99\n"),
         kev: {"vulnerabilities": []}},
    )
    with pytest.raises(ValueError, match="нет записей KEV"):
        apply_update_bundle(db_session, Handle(db_session), path)
    assert db_session.get(VmRefEpss, "CVE-2025-1000").epss == .1
    assert db_session.get(VmRefEpss, "CVE-2025-2000") is None
    assert db_session.get(VmRefSyncState, "epss") is None
