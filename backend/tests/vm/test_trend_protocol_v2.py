import copy
import pytest
from api.modules.vm.services.trends.ingest import apply_page
from api.modules.vm.services.trends.analyze import process_pending
from api.modules.vm.trend_models import VmTrendIngestState
from tests.vm.test_trend_sync import page


def enriched_page():
    data = page()
    data['protocol_version'] = 2
    data['events'][0]['payload']['url'] = 'https://example.org/feed'
    data['events'].append({'seq': 3, 'entity_type': 'cve_enrichment', 'operation': 'upsert',
        'entity_id': 'cve:CVE-2026-12345', 'revision': 1, 'observed_at': '2026-11-07T00:00:00Z',
        'payload': {'cve_id': 'CVE-2026-12345', 'cvss': 9.8, 'epss': None, 'providers': {}, 'fetched_at': '2026-11-07T00:00:00Z'}})
    data.update(until_seq=3, next_cursor=3)
    return data


def test_v2_replay_and_cursor_atomicity(db_session):
    from api.modules.vm.trend_models import VmTrendEnrichment
    data = enriched_page()
    apply_page(db_session, data)
    state = db_session.get(VmTrendIngestState, 1)
    generation = state.generation
    apply_page(db_session, data)
    assert state.cursor == 3
    assert db_session.get(VmTrendEnrichment, (generation, 'cve:CVE-2026-12345')).data['epss'] is None
    broken = copy.deepcopy(data)
    broken['events'][2]['payload']['cvss'] = 100
    broken['events'][2]['revision'] = 2
    broken['events'][2]['seq'] = 4
    broken['events'] = broken['events'][2:]
    broken.update(until_seq=4, next_cursor=4)
    with pytest.raises(ValueError):
        apply_page(db_session, broken)
    db_session.rollback()
    assert db_session.get(VmTrendIngestState, 1).cursor == 3


def test_unknown_protocol_does_not_advance_cursor(db_session):
    apply_page(db_session, page())
    before = db_session.get(VmTrendIngestState, 1).cursor
    unknown = enriched_page(); unknown['protocol_version'] = 99
    with pytest.raises(ValueError):
        apply_page(db_session, unknown)
    assert db_session.get(VmTrendIngestState, 1).cursor == before


def test_incomplete_generation_keeps_previous_visible(db_session):
    apply_page(db_session, page())
    process_pending(db_session)
    state = db_session.get(VmTrendIngestState, 1)
    active = state.active_generation
    data = enriched_page(); data['events'] = data['events'][:1]
    data.update(next_cursor=1, has_more=True)
    apply_page(db_session, data, reset=True)
    assert state.active_generation == active and state.generation != active


def test_poc_decision_survives_full_replay(db_session):
    from api.modules.vm.trend_models import VmTrendPocReview
    row = VmTrendPocReview(candidate_id='poc:CVE-2026-12345:1', commit_sha='a' * 40, actor='analyst', state='confirmed', reason='Verified in lab', evidence=['https://example.org/report'])
    db_session.add(row); db_session.commit()
    apply_page(db_session, page(), reset=True)
    assert db_session.get(VmTrendPocReview, row.id).state == 'confirmed'


def test_wire_contracts_match_collector():
    from pathlib import Path
    import api.modules.vm.services.trends.monitoring_contracts as module
    root = Path(__file__).resolve().parents[3]
    assert Path(module.__file__).read_bytes() == (root / 'collector/src/stools_threat_collector/monitoring_contracts.py').read_bytes()
