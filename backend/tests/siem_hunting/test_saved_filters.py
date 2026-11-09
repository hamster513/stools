"""Контракт сохранённых фильтров MaxPatrol и защита от повторного создания."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from api.modules.siem.hunting import saved_filters as sf
from api.modules.siem.hunting.library import HuntIn, QueryIn, create_hunt
from api.modules.siem.hunting.settings import ThSettings, save_th_settings
from api.modules.siem.services.kb_settings import KbConnectionIn, save_connection

FOLDER = "11111111-1111-4111-8111-111111111111"
FILTER = "22222222-2222-4222-8222-222222222222"


@pytest.fixture
def setup_filters(db_session, monkeypatch):
    save_connection(db_session, KbConnectionIn(host="mp.test", api_token="test-token"), "test")
    save_th_settings(db_session, ThSettings(filter_folder_id=FOLDER), "test")
    hunt = create_hunt(db_session, HuntIn(code="TH-TEST", name="Test", queries=[
        QueryIn(query_id="Q1", query='subject.name = "test"', fields="time, src.ip"),
    ]), "test")
    query = db_session.scalar(sf.select(sf.ThQuery).where(sf.ThQuery.hunt_id == hunt.id))
    calls = []
    remote = {}

    def handle(request):
        calls.append((request.method, request.url.path))
        assert request.headers["Authorization"] == "Bearer test-token"
        if request.url.path.endswith("filters_hierarchy"):
            children = [{"id": k, "name": v["name"], "type": "filter_node"} for k, v in remote.items()]
            return httpx.Response(200, json={"roots": [
                {"id": FOLDER, "name": "Hunting", "type": "folder_node", "children": children},
            ]})
        if request.method == "POST":
            body = json.loads(request.content)
            assert set(body) == {"folderId", "name", "pdqlQuery"}
            assert body["folderId"] == FOLDER
            remote[FILTER] = body
            return httpx.Response(200, json={"id": FILTER})
        if request.method == "PUT":
            remote[FILTER] = json.loads(request.content)
            return httpx.Response(204)
        if request.method == "GET" and request.url.path.endswith(FILTER):
            return httpx.Response(200, json=dict(remote[FILTER], id=FILTER))
        raise AssertionError(request.url.path)

    monkeypatch.setattr(sf, "make_client", lambda conn: httpx.Client(transport=httpx.MockTransport(handle)))
    return hunt, query, calls, remote


def test_publish_is_idempotent_and_updates(db_session, setup_filters):
    _, query, calls, remote = setup_filters
    first = sf.publish(db_session, "query", query.id, "test")
    assert first["url"].endswith("filterId=" + FILTER)
    assert "historyId" not in first["url"]
    assert remote[FILTER]["pdqlQuery"] == 'filter(subject.name = "test") | select(time, src.ip) | sort(time desc)'
    sf.publish(db_session, "query", query.id, "test")
    assert sum(method == "POST" for method, _ in calls) == 1
    query.query = 'subject.name = "changed"'
    db_session.commit()
    assert sf.filter_view(db_session, "query", query)["url"] is None
    sf.publish(db_session, "query", query.id, "test")
    assert sum(method == "POST" for method, _ in calls) == 1
    assert sum(method == "PUT" for method, _ in calls) == 2
    assert 'changed' in remote[FILTER]["pdqlQuery"]


def test_recover_creation_after_local_state_lost(db_session, setup_filters):
    _, query, calls, _ = setup_filters
    sf.publish(db_session, "query", query.id, "test")
    row = db_session.get(sf.AppSetting, sf.state_key("query", query.id))
    db_session.delete(row)
    db_session.commit()
    sf.publish(db_session, "query", query.id, "test")
    assert sum(method == "POST" for method, _ in calls) == 1


def test_errors_do_not_lose_hunt_or_expose_tokens(db_session, setup_filters, monkeypatch):
    _, query, _, _ = setup_filters
    monkeypatch.setattr(sf, "make_client", lambda conn: httpx.Client(
        transport=httpx.MockTransport(lambda req: httpx.Response(403, text="secret test-token"))))
    result = sf.publish(db_session, "query", query.id, "test")
    assert result["url"] is None
    assert "403" in result["error"]
    assert "test-token" not in result["error"]
    assert db_session.get(sf.ThQuery, query.id).query


def test_filter_api_permissions_and_folders(auth_client: TestClient, client_as, setup_filters):
    _, query, _, _ = setup_filters
    folders = auth_client.get("/api/siem/hunting/filters/folders")
    assert folders.status_code == 200
    assert folders.json() == [{"id": FOLDER, "name": "Hunting"}]
    result = auth_client.post(f"/api/siem/hunting/filters/query/{query.id}")
    assert result.status_code == 200
    assert result.json()["url"]
    reader = client_as("auditor")
    assert reader.post(f"/api/siem/hunting/filters/query/{query.id}").status_code == 403


def test_legacy_automatic_mode_does_not_publish(db_session, setup_filters):
    from api.modules.siem.hunting.library import update_hunt
    hunt, query, calls, _ = setup_filters
    save_th_settings(db_session, ThSettings(filter_folder_id=FOLDER, filters_auto_create=True), "test")
    update_hunt(db_session, hunt, HuntIn(code=hunt.code, name=hunt.name, queries=[
        QueryIn(query_id="Q1", query="changed = true", fields="time"),
    ]), "test")
    assert query.query == "changed = true"
    assert not calls


def test_deep_uses_own_query_and_findings_get_filter_link(db_session, setup_filters, auth_client):
    import datetime as dt

    from api.modules.siem.hunting.deep import create_deep
    from api.modules.siem.hunting.nightly import persist_finding
    hunt, query, _, remote = setup_filters
    start = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    end = start + dt.timedelta(days=1)
    deep = create_deep(db_session, title="Own deep", hunt=hunt, query=query,
                       query_text="own = true", fields=["time"], labels=["Time"],
                       limit=100, period_from=start, period_to=end, login="test")
    result = sf.publish(db_session, "deep", deep.id, "test")
    assert result["url"]
    assert remote[FILTER]["pdqlQuery"] == "filter(own = true) | select(time) | sort(time desc)"
    finding = persist_finding(db_session, kind="deep", hunt=hunt, query=None,
                              period_from=start, period_to=end, events=[], fields=["time"],
                              labels=["Time"], limit=100, deep_id=deep.id)
    db_session.commit()
    card = auth_client.get(f"/api/siem/hunting/findings/{finding.id}").json()
    assert card["saved_filter"]["entity_id"] == deep.id
    assert card["saved_filter"]["url"] == result["url"]


def test_missing_folder_and_new_host_do_not_reuse_link(db_session, setup_filters):
    _, query, _, _ = setup_filters
    sf.publish(db_session, "query", query.id, "test")
    save_connection(db_session, KbConnectionIn(host="different.test", api_token="another-token"), "test")
    assert sf.filter_view(db_session, "query", query)["url"] is None
    save_th_settings(db_session, ThSettings(), "test")
    result = sf.publish(db_session, "query", query.id, "test")
    assert "папку" in result["error"]


def test_simultaneous_publishing_creates_one_filter(db_session, setup_filters):
    from concurrent.futures import ThreadPoolExecutor

    from sqlalchemy.orm import Session
    _, query, calls, _ = setup_filters
    engine = db_session.get_bind()
    query_id = query.id
    db_session.commit()

    def run():
        with Session(engine) as db:
            return sf.publish(db, "query", query_id, "test")

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run(), range(2)))
    assert all(result["url"] for result in results)
    assert sum(method == "POST" for method, _ in calls) == 1


def test_folders_are_nested_and_malformed_replies_are_errors():
    conn = KbConnectionIn(host="mp.test", api_token="test-token")
    response = {"roots": [{"id": "root", "name": "User", "type": "folder_node", "children": [
        {"id": FOLDER, "name": "Hunts", "type": "folder_node"},
    ]}]}
    with httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json=response))) as http:
        folders, _ = sf.FiltersClient(conn, http).hierarchy()
    assert any(item["id"] == FOLDER and item["name"] == "User / Hunts" for item in folders)
    with (
        httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, text="<html>login</html>"))) as http,
        pytest.raises(sf.FilterError, match="формат"),
    ):
        sf.FiltersClient(conn, http).hierarchy()


def test_retry_after_remote_creation_timeout_does_not_duplicate(db_session, setup_filters, monkeypatch):
    _, query, calls, remote = setup_filters
    original = sf.make_client

    def factory(conn):
        client = original(conn)
        transport = client._transport

        def handle(request):
            response = transport.handle_request(request)
            if request.method == "POST":
                raise httpx.ReadTimeout("response lost", request=request)
            return response

        return httpx.Client(transport=httpx.MockTransport(handle))

    monkeypatch.setattr(sf, "make_client", factory)
    result = sf.publish(db_session, "query", query.id, "test")
    assert result["error"] and FILTER in remote
    monkeypatch.setattr(sf, "make_client", original)
    assert sf.publish(db_session, "query", query.id, "test")["url"]
    assert sum(method == "POST" for method, _ in calls) == 1


def test_folder_change_moves_existing_filter(db_session, setup_filters, monkeypatch):
    _, query, _, _ = setup_filters
    sf.publish(db_session, "query", query.id, "test")
    other = "33333333-3333-4333-8333-333333333333"
    save_th_settings(db_session, ThSettings(filter_folder_id=other), "test")
    assert sf.filter_view(db_session, "query", query)["url"] is None
    updates = []

    def handle(request):
        if request.method == "GET":
            return httpx.Response(200, json={"roots": [
                {"id": FOLDER, "name": "Old", "type": "folder_node", "children":
                    [] if updates else [{"id": FILTER, "name": "Existing", "type": "filter_node"}]},
                {"id": other, "name": "New", "type": "folder_node", "children":
                    [{"id": FILTER, "name": updates[-1]["name"], "type": "filter_node"}] if updates else []},
            ]})
        assert request.method == "PUT"
        assert request.url.path.endswith(FILTER)
        updates.append(json.loads(request.content))
        return httpx.Response(204)

    monkeypatch.setattr(sf, "make_client", lambda conn: httpx.Client(transport=httpx.MockTransport(handle)))
    assert sf.publish(db_session, "query", query.id, "test")["url"]
    assert updates[0]["folderId"] == other


def test_settings_ignore_legacy_mode_and_validate_folder(auth_client, client_as):
    result = auth_client.put("/api/siem/hunting/settings", json={"filters_auto_create": True})
    assert result.status_code == 200
    assert "filters_auto_create" not in result.json()
    result = auth_client.put("/api/siem/hunting/settings", json={"filter_folder_id": "../invalid"})
    assert result.status_code == 422
    assert client_as("analyst").put("/api/siem/hunting/settings", json={"filter_folder_id": FOLDER}).status_code == 403
