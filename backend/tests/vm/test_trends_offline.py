import httpx
import pytest
from api.modules.vm.services.trends.client import CollectorClient, CollectorError
from api.modules.vm.services.trends.settings import TrendConnectionIn
from tests.siem_hunting.test_intel import bundle, item


def test_offline_client_never_constructs_http(monkeypatch):
    monkeypatch.setattr(
        httpx, "Client", lambda **kw: pytest.fail("Offline must not construct HTTP")
    )
    with pytest.raises(CollectorError, match="[Oo]ffline"):
        CollectorClient(
            TrendConnectionIn(mode="offline", url="https://collector.test", token="secret")
        )


def test_offline_setting_preserves_credentials_and_blocks_remote_api(auth_client, monkeypatch):
    base = "/api/vm/trends"
    online = {
        "mode": "online",
        "url": "https://collector.test",
        "token": "secret",
        "proxy_enabled": True,
        "proxy_host": "proxy.test",
        "proxy_password": "proxy-secret",
    }
    assert auth_client.put(base + "/settings", json=online).status_code == 200
    offline = {**online, "mode": "offline", "token": "", "proxy_password": ""}
    response = auth_client.put(base + "/settings", json=offline)
    assert response.status_code == 200
    assert (
        response.json()["mode"] == "offline"
        and response.json()["token_set"]
        and response.json()["proxy_password_set"]
    )
    monkeypatch.setattr(httpx, "Client", lambda **kw: pytest.fail("Offline contacted collector"))
    for path in ("/monitoring", "/sources", "/catalog/preview", "/outbound-profiles"):
        response = auth_client.get(base + path)
        assert response.status_code in (400, 409), (path, response.status_code, response.text)
        assert "offline" in response.text.lower()
    assert auth_client.post(base + "/sync").status_code in (400, 409)
    assert auth_client.post(base + "/sync/full").status_code in (400, 409)
    assert (
        auth_client.post(base + "/settings/test", json={**offline, "mode": "online"}).json()["ok"]
        is False
    )
    assert auth_client.get(base + "/status").json()["mode"] == "offline"
    assert auth_client.get(base + "?view=mentions").status_code == 200
    restored = auth_client.put(base + "/settings", json={**offline, "mode": "online"})
    assert (
        restored.status_code == 200
        and restored.json()["configured"]
        and restored.json()["token_set"]
    )


@pytest.mark.parametrize("mode", ["online", "offline"])
def test_news_archives_import_in_both_modes(auth_client, mode, monkeypatch):
    base = "/api/vm/trends"
    assert auth_client.put(base + "/settings", json={"mode": mode}).status_code == 200
    monkeypatch.setattr(
        httpx, "Client", lambda **kw: pytest.fail("Archive import contacted collector")
    )
    response = auth_client.post(
        base + "/news-archive", files={"file": ("news.zip", bundle([item()]), "application/zip")}
    )
    assert response.status_code == 200 and response.json()["news_total"] == 1


def test_queued_sync_rechecks_offline_before_start(auth_client, db_session, monkeypatch):
    from api.modules.vm.services.trends import sync
    from types import SimpleNamespace

    base = "/api/vm/trends/settings"
    config = {"url": "https://collector.test", "token": "secret", "mode": "online"}
    assert auth_client.put(base, json=config).status_code == 200
    callbacks = []
    monkeypatch.setattr(
        sync,
        "run_job",
        lambda job, work: work(db_session, SimpleNamespace(stage=lambda *a, **kw: None)),
    )
    sync.start_trend_sync(db_session, "test", callbacks.append)
    assert auth_client.put(base, json={**config, "token": "", "mode": "offline"}).status_code == 200
    monkeypatch.setattr(
        httpx, "Client", lambda **kw: pytest.fail("Queued sync opened HTTP in offline")
    )
    with pytest.raises(CollectorError, match="Offline"):
        callbacks[0]()


def test_running_sync_stops_before_next_request(auth_client, db_session, monkeypatch):
    import json
    from types import SimpleNamespace
    from api.db.models import AppSetting
    from api.modules.vm.services.trends import sync
    from api.modules.vm.services.trends.settings import SETTING_KEY

    assert (
        auth_client.put(
            "/api/vm/trends/settings", json={"url": "https://collector.test", "token": "secret"}
        ).status_code
        == 200
    )
    calls = []
    real = httpx.Client

    def respond(request):
        calls.append(request.url.path)
        row = db_session.get(AppSetting, SETTING_KEY)
        row.value_json = json.dumps({**json.loads(row.value_json), "mode": "offline"})
        db_session.commit()
        return httpx.Response(200, json={})

    monkeypatch.setattr(
        httpx, "Client", lambda **kw: real(**kw, transport=httpx.MockTransport(respond))
    )

    def receive(session, client, handle, **kwargs):
        client.request("GET", "/first")
        client.request("GET", "/second")

    monkeypatch.setattr(sync, "receive_changes", receive)
    monkeypatch.setattr(
        sync,
        "run_job",
        lambda job, work: work(db_session, SimpleNamespace(stage=lambda *a, **kw: None)),
    )
    callbacks = []
    sync.start_trend_sync(db_session, "test", callbacks.append)
    with pytest.raises(CollectorError, match="Offline"):
        callbacks[0]()
    assert calls == ["/first"]
