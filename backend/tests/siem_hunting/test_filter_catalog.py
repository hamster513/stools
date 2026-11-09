# ruff: noqa: F811
"""Каталог фильтров SIEM, метаданные запросов и только ручная публикация."""
import json

from api.modules.siem.hunting import saved_filters as sf
from tests.siem_hunting.test_findings_api import started  # noqa: F401
from tests.siem_hunting.test_saved_filters import FILTER, FOLDER, setup_filters  # noqa: F401

PDQL = 'filter(subject.name = "catalog") | select(time, src.ip) | sort(time asc)'


def seed_catalog(setup_filters):
    _, _, _, remote = setup_filters
    remote[FILTER] = {"folderId": FOLDER, "name": "Account investigation", "pdqlQuery": PDQL}


def test_catalog_selection_preserves_full_query_and_name(auth_client, setup_filters):
    seed_catalog(setup_filters)
    catalog = auth_client.get("/api/siem/hunting/filters/catalog")
    assert catalog.status_code == 200
    assert catalog.json()["items"][0]["name"] == "Account investigation"
    selected = auth_client.get(f"/api/siem/hunting/filters/catalog/{FILTER}").json()
    assert selected["query"] == PDQL and selected["is_full_pdql"] is True
    response = auth_client.post("/api/siem/hunting/hunts", json={
        "code": "FROM-SIEM", "name": "A hunt", "queries": [
            {**selected, "query_id": "Q1", "description": "Investigate a service account"},
        ],
    })
    assert response.status_code == 201, response.text
    query = response.json()["queries"][0]
    assert query["name"] == "Account investigation"
    assert query["description"] == "Investigate a service account"
    assert query["query"] == PDQL and query["is_full_pdql"]
    assert query["saved_filter"]["status"] == "available"
    assert query["saved_filter"]["id"] == FILTER
    assert not any(method in ("POST", "PUT") for method, _ in setup_filters[2])


def test_missing_filter_highlighted_after_refresh(auth_client, setup_filters):
    seed_catalog(setup_filters)
    selected = auth_client.get(f"/api/siem/hunting/filters/catalog/{FILTER}").json()
    created = auth_client.post("/api/siem/hunting/hunts", json={
        "code": "MISSING", "name": "A hunt", "queries": [{**selected, "query_id": "Q1"}],
    }).json()
    setup_filters[3].clear()
    assert auth_client.get("/api/siem/hunting/filters/catalog").status_code == 200
    query = auth_client.get(f"/api/siem/hunting/hunts/{created['id']}").json()["queries"][0]
    assert query["saved_filter"]["status"] == "missing"
    assert query["saved_filter"]["url"] is None


def test_local_query_name_is_filter_name_and_automatic_mode_is_ignored(auth_client, setup_filters):
    assert auth_client.put("/api/siem/hunting/settings", json={
        "filter_folder_id": FOLDER, "filters_auto_create": True,
    }).status_code == 200
    response = auth_client.post("/api/siem/hunting/hunts", json={
        "code": "LOCAL", "name": "Local hunt", "queries": [{
            "query_id": "Q1", "name": "My filter", "description": "Local explanation",
            "query": "normalized = true", "fields": "time",
        }],
    })
    assert response.status_code == 201
    query = response.json()["queries"][0]
    assert query["saved_filter"]["status"] == "not_published"
    assert not any(method in ("POST", "PUT") for method, _ in setup_filters[2])
    assert auth_client.post(f"/api/siem/hunting/filters/query/{query['id']}").json()["url"]
    assert setup_filters[3][FILTER]["name"] == "My filter"


def test_full_pdql_is_not_wrapped():
    from api.modules.siem.hunting.pdql import build_pdql
    assert build_pdql(PDQL, [], is_full_pdql=True) == PDQL


def test_catalog_only_in_configured_folder(auth_client, setup_filters):
    # Чужой ID не принимается как ссылка из каталога даже при корректном UUID.
    response = auth_client.get("/api/siem/hunting/filters/catalog/33333333-3333-4333-8333-333333333333")
    assert response.status_code == 404


def test_full_pdql_nightly_uses_original_query_and_infers_columns(db_session, fake):
    from sqlalchemy import select

    from api.modules.siem.hunting.library import HuntIn, QueryIn, create_hunt
    from api.modules.siem.hunting.models import ThFinding
    from api.modules.siem.hunting.nightly import create_run
    from api.modules.siem.hunting.settings import ThSettings
    from tests.siem_hunting.test_nightly import NIGHT, TZ, run
    fake.events_by_query["catalog"] = [{"time": "t", "src.ip": "10.0.0.1"}]
    create_hunt(db_session, HuntIn(code="FULL", name="Full", queries=[
        QueryIn(query_id="Q1", name="A filter", query=PDQL, fields="", is_full_pdql=True),
    ]), "test")
    task = create_run(db_session, NIGHT, ThSettings(), TZ)
    run(db_session, task.id)
    assert json.loads(fake.calls[0].content)["filter"] == PDQL
    finding = db_session.scalar(select(ThFinding).where(ThFinding.run_id == task.id))
    assert [column["field"] for column in json.loads(finding.columns_json)] == ["time", "src.ip"]


def test_full_pdql_deep_rerun_and_save_preserve_mode(db_session, fake, auth_client, started):
    from sqlalchemy import select

    from api.jobs import JobHandle
    from api.modules.siem.hunting.deep import create_deep, run_deep
    from api.modules.siem.hunting.models import ThDeepHunt, ThFinding, ThJob
    from tests.siem_hunting.test_deep import NOW, D
    from tests.siem_hunting.test_nightly import Clock, Sleeper
    fake.events_by_query["catalog"] = [{"time": "t", "src.ip": "10.0.0.2"}]
    deep = create_deep(db_session, title="Full", hunt=None, query=None, query_text=PDQL,
                       fields=[], labels=[], is_full_pdql=True, limit=100,
                       period_from=NOW-D, period_to=NOW, login="test", now=NOW)
    job = ThJob(kind="deep", started_by="test")
    db_session.add(job); db_session.commit()
    run_deep(db_session, JobHandle(db_session, job), deep.id, sleeper=Sleeper(), clock=Clock(NOW))
    assert json.loads(fake.calls[0].content)["filter"] == PDQL
    finding = db_session.scalar(select(ThFinding).where(ThFinding.deep_id == deep.id))
    assert len(json.loads(finding.columns_json)) == 2
    rerun = auth_client.post(f"/api/siem/hunting/deep/{deep.id}/rerun")
    assert rerun.status_code == 202
    assert db_session.get(ThDeepHunt, rerun.json()["id"]).is_full_pdql
    saved = auth_client.post(f"/api/siem/hunting/deep/{deep.id}/save-to-library", json={"code":"DEEP-COPY","name":"Copy"})
    assert saved.status_code == 201
    assert saved.json()["queries"][0]["is_full_pdql"]


def test_query_metadata_round_trip_yaml(db_session):
    from api.modules.siem.hunting.library import HuntIn, QueryIn, create_hunt
    from api.modules.siem.hunting.yaml_io import export_library_yaml, parse_library_yaml
    create_hunt(db_session, HuntIn(code="YAML", name="YAML", queries=[
        QueryIn(query_id="Q1", name="Name from SIEM", description="Notes\nSecond line",
                query=PDQL, fields="", is_full_pdql=True),
    ]), "test")
    query = parse_library_yaml(export_library_yaml(db_session))[0].queries[0]
    assert query.name == "Name from SIEM" and query.description == "Notes\nSecond line"
    assert query.is_full_pdql and query.query == PDQL


def test_unavailable_siem_is_unknown_not_missing(auth_client, setup_filters, monkeypatch):
    import httpx
    seed_catalog(setup_filters)
    selected = auth_client.get(f"/api/siem/hunting/filters/catalog/{FILTER}").json()
    created = auth_client.post("/api/siem/hunting/hunts", json={
        "code":"UNKNOWN", "name":"Unknown", "queries":[{**selected,"query_id":"Q1"}],
    }).json()
    monkeypatch.setattr(sf, "make_client", lambda conn: httpx.Client(
        transport=httpx.MockTransport(lambda req: httpx.Response(503))))
    assert auth_client.get("/api/siem/hunting/filters/catalog").status_code == 502
    card = auth_client.get(f"/api/siem/hunting/hunts/{created['id']}").json()
    assert card["queries"][0]["saved_filter"]["status"] == "unknown"
