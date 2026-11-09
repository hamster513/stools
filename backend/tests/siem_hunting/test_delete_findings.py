import pytest
from sqlalchemy import func, select

from api.modules.siem.hunting.models import ThEvent, ThFinding, ThHunt, ThQuery, ThRun, ThRunQuery
from api.platform.findings.models import FindingEvent, FindingState
from tests.siem_hunting.test_findings_api import finding_of, put_state, seed_night

PATH = "/api/siem/hunting/findings/delete"


def test_delete_findings_cleans_dependents_and_preserves_hunt(auth_client, db_session, fake):
    run = seed_night(db_session, fake)
    finding = finding_of(db_session, "TH-WIN-001")
    fid, run_id, hunt_id = finding.id, run.id, finding.hunt_id
    put_state(auth_client, fid, status="in_work", comment="Investigated")
    state_id = db_session.scalar(select(FindingState.id).where(FindingState.key == f"th:{fid}"))
    assert state_id
    response = auth_client.post(PATH, json={"ids": [fid], "expected_count": 1})
    assert response.status_code == 200, response.text
    assert response.json() == {"deleted": 1}
    db_session.expire_all()
    assert db_session.get(ThFinding, fid) is None
    assert db_session.scalar(select(func.count()).select_from(ThEvent).where(ThEvent.finding_id == fid)) == 0
    assert db_session.get(FindingState, state_id) is None
    assert db_session.scalar(select(func.count()).select_from(FindingEvent).where(FindingEvent.state_id == state_id)) == 0
    assert db_session.get(ThHunt, hunt_id) is not None
    assert db_session.scalar(select(func.count()).select_from(ThQuery).where(ThQuery.hunt_id == hunt_id)) == 2
    assert db_session.get(ThRun, run_id).findings == 1
    assert db_session.scalar(select(func.count()).select_from(ThRunQuery).where(ThRunQuery.finding_id == fid)) == 0
    assert finding_of(db_session, "TH-WIN-002") is not None
    assert auth_client.get(f"/api/siem/hunting/findings/{fid}").status_code == 404


def test_delete_by_filter_and_stale_count(auth_client, db_session, fake):
    seed_night(db_session, fake)
    body = {"filter": {"hunt": ["TH-WIN-001"], "status": "all"}, "expected_count": 2}
    assert auth_client.post(PATH, json=body).status_code == 409
    assert db_session.scalar(select(func.count()).select_from(ThFinding)) == 2
    body["expected_count"] = 1
    assert auth_client.post(PATH, json=body).json() == {"deleted": 1}
    assert finding_of(db_session, "TH-WIN-002") is not None


def test_delete_rejects_running_and_unknown_findings(auth_client, db_session, fake):
    run = seed_night(db_session, fake)
    fid = finding_of(db_session, "TH-WIN-001").id
    run.status = "running"
    db_session.commit()
    assert auth_client.post(PATH, json={"ids": [fid], "expected_count": 1}).status_code == 409
    assert auth_client.post(PATH, json={"ids": [fid, 999999], "expected_count": 2}).status_code == 409
    assert db_session.get(ThFinding, fid) is not None


@pytest.mark.parametrize("body", [
    {"expected_count": 1}, {"ids": [], "expected_count": 1},
    {"ids": [1], "filter": {}, "expected_count": 1},
    {"filter": {"typo": "all"}, "expected_count": 1},
    {"filter": {"status": "bad"}, "expected_count": 1},
])
def test_delete_rejects_ambiguous_selection(auth_client, body):
    assert auth_client.post(PATH, json=body).status_code == 422


def test_delete_permissions(client, client_as):
    body = {"ids": [1], "expected_count": 1}
    assert client.post(PATH, json=body).status_code == 401
    assert client_as("auditor").post(PATH, json=body).status_code == 403
