import copy
import datetime as dt

import pytest
from sqlalchemy import func, select

from api.modules.vm.services.trends import ingest
from api.modules.vm.services.trends.analyze import process_pending
from api.modules.vm.trend_models import VmTrendEventReceipt, VmTrendIngestState, VmTrendPublication
from tests.vm.test_trend_sync import page


def test_compacted_receipt_accepts_exact_replay_and_rejects_modified(db_session):
    payload = page()
    ingest.apply_page(db_session, payload)
    for row in db_session.scalars(select(VmTrendEventReceipt)):
        row.received_at = dt.datetime.now(dt.UTC) - dt.timedelta(days=40)
    db_session.commit()
    result = ingest.compact_receipts(db_session, 14, execute=True)
    assert result['eligible_rows'] == 2
    db_session.commit()
    assert all(r.data is None and len(r.payload_hash) == 64 for r in db_session.scalars(select(VmTrendEventReceipt)))
    ingest.apply_page(db_session, payload)
    broken = copy.deepcopy(payload)
    broken['events'][1]['payload']['text'] = 'changed'
    with pytest.raises(ValueError, match='повторное'):
        ingest.apply_page(db_session, broken)


def test_snapshot_pages_keep_active_generation_until_complete_and_deltas_apply(db_session):
    ingest.apply_page(db_session, page())
    process_pending(db_session)
    old = db_session.get(VmTrendIngestState, 1).active_generation
    payload = copy.deepcopy(page())
    payload.update(snapshot_id='frozen', baseline_seq=100)
    first = {**payload, 'events':payload['events'][:1], 'next_cursor':1, 'has_more':True}
    ingest.apply_snapshot_page(db_session, first, reset=True)
    process_pending(db_session)
    assert db_session.get(VmTrendIngestState,1).active_generation == old
    ingest.apply_snapshot_page(db_session, {**payload, 'events':payload['events'][1:]})
    state = db_session.get(VmTrendIngestState,1)
    assert state.cursor == 100 and state.snapshot_id is None
    assert state.active_generation == old
    delta = copy.deepcopy(page())
    delta.update(until_seq=101,next_cursor=101,events=[delta['events'][1]])
    delta['events'][0].update(seq=101,revision=2)
    delta['events'][0]['payload']['text']='updated after snapshot'
    ingest.apply_page(db_session,delta)
    process_pending(db_session)
    assert state.active_generation == state.generation != old
    row = db_session.scalar(select(VmTrendPublication).where(VmTrendPublication.generation==state.generation))
    assert row.data['text']=='updated after snapshot'
    ingest.apply_page(db_session,delta)
    assert db_session.scalar(select(func.count()).select_from(VmTrendEventReceipt).where(VmTrendEventReceipt.generation==state.generation))==1


@pytest.mark.parametrize("protocol", [1, 2])
def test_real_collector_compaction_recovers_vm_and_receives_later_delta(db_session, tmp_path, protocol):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'collector' / 'src'))
    from stools_threat_collector.storage import Store

    from api.modules.vm.services.trends.sync import receive_changes
    store = Store(tmp_path / 'collector.db')
    if protocol == 2:
        store.enable_protocol_v2()
        store.save_monitoring('cve_enrichment', 'cve:CVE-2026-12345', {'cve_id':'CVE-2026-12345','cvss':9.8,'epss':None,'providers':{},'fetched_at':'2026-11-07T00:00:00Z'})
    source = store.save_source({'name':'Source','publisher_id':'test','url':'https://example.org/rss'})
    store.ingest(source['id'],[{'external_id':'a','url':'https://example.org/a','title':'CVE-2026-12345','text':'old'}],{})
    with store.connection() as db:
        db.execute("UPDATE changes SET observed_at='2020-01-01T00:00:00+00:00'")
    store.retention({}, execute=True)
    class Client:
        def info(self): return store.info()
        def create_snapshot(self): return store.create_snapshot()
        def snapshot_page(self, id_, cursor): return store.snapshot_page(id_, cursor, limit=1)
        def changes(self, cursor, until): return store.changes(cursor, until)
    class Handle:
        def stage(self,*a,**kw): pass
        def tick(self,*a,**kw): pass
    receive_changes(db_session,Client(),Handle())
    assert db_session.get(VmTrendIngestState,1).cursor==store.info()['last_seq']
    process_pending(db_session)
    assert db_session.scalar(select(VmTrendPublication)).data['text']=='old'
    store.ingest(source['id'],[{'external_id':'a','url':'https://example.org/a','title':'CVE-2026-12345','text':'new'}],{})
    receive_changes(db_session,Client(),Handle())
    assert db_session.scalar(select(VmTrendPublication)).data['text']=='new'


def test_snapshot_archive_roundtrip_after_cleanup(db_session, tmp_path):
    import sys
    from pathlib import Path
    sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'collector'/'src'))
    from stools_threat_collector.bundle import export_bundle
    from stools_threat_collector.storage import Store

    from api.modules.vm.services.trends.bundle import import_bundle
    store=Store(tmp_path/'collector.db')
    source=store.save_source({'name':'Source','publisher_id':'test','url':'https://example.org/rss'})
    store.ingest(source['id'],[{'external_id':'a','url':'https://example.org/a','title':'CVE-2026-12345','text':'evidence'}],{})
    with store.connection() as db:
        db.execute("UPDATE changes SET observed_at='2020-01-01T00:00:00Z'")
    store.retention({},execute=True)
    archive=tmp_path/'export.zip'
    export_bundle(store,0,archive)
    import_bundle(db_session,archive)
    assert db_session.get(VmTrendIngestState,1).cursor==store.info()['last_seq']
    process_pending(db_session)
    assert db_session.scalar(select(VmTrendPublication)).data['text']=='evidence'
