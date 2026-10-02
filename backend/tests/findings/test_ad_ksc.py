"""AD и антивирус на общих статусах находок: автоматика по снапшотам, списки,
карточка, массовая смена, обзор и подсчёты (спека §1, §3–§5)."""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.modules.attack.layers import LAYERS
from api.platform.findings import service as svc
from api.platform.findings.adapters import get_adapter
from tests.ad.synthetic import NOW as AD_NOW
from tests.ad.synthetic import build_export as build_ad
from tests.ksc.synthetic import NOW as KSC_NOW
from tests.ksc.synthetic import build_export as build_ksc

TODAY = svc.today()


def _done(client: TestClient, module: str, raw: dict[str, Any]) -> None:
    r = client.post(f"/api/{module}/snapshots/file", files={"file": (f"{module}.json", json.dumps(raw).encode(), "application/json")})
    assert r.status_code == 202, r.text
    job = client.get(f"/api/{module}/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "done", job


def _ad_without_svc_sql(now: dt.datetime) -> dict[str, Any]:
    """Kerberoast у svc_sql закрыт, у helpdesk появился."""
    raw = build_ad(now=now)
    for o in raw["objects"]:
        if o.get("sam") == "svc_sql":
            o["spn"] = []
        if o.get("sam") == "helpdesk":
            o["spn"] = ["HTTP/help.corp.local"]
    return raw


def _ad_latest(client: TestClient) -> tuple[int, int]:
    snap = client.get("/api/ad/snapshots").json()[0]
    return int(snap["domain_id"]), int(snap["id"])


def _state(client: TestClient, module: str, scope_id: int, key: str) -> dict[str, Any]:
    r = client.get("/api/findings/state", params={"module": module, "scope_id": scope_id, "key": key})
    assert r.status_code == 200, r.text
    return dict(r.json())


# ---- AD: автоматика -----------------------------------------------------------


def test_ad_disappeared_finding_resolves_and_returning_one_reopens(auth_client: TestClient) -> None:
    _done(auth_client, "ad", build_ad())
    domain_id, snap1 = _ad_latest(auth_client)
    body = auth_client.get(f"/api/ad/snapshots/{snap1}/findings").json()
    first = body["items"][0]
    assert (first["status"], first["status_title"], first["delta"], first["assignee"], first["overdue"]) == ("new", "Новая", "same", None, False)
    assert first["first_seen_at"].startswith(AD_NOW.date().isoformat()) and first["age_days"] >= 0
    assert body["facets"]["status"]["new"] == body["total"] and body["facets"]["delta"]["new"] == 0
    svc_sql = auth_client.get(f"/api/ad/snapshots/{snap1}/findings?check=Kerberoast").json()["items"][0]
    assert svc_sql["identity"] == "CORP\\svc_sql"

    # Находка пропала, о ней никто ничего не решал — всё равно видна как устранённая.
    _done(auth_client, "ad", _ad_without_svc_sql(AD_NOW + dt.timedelta(days=7)))
    _, snap2 = _ad_latest(auth_client)
    kerb = auth_client.get(f"/api/ad/snapshots/{snap2}/findings?check=Kerberoast").json()
    assert [(i["identity"], i["status"], i["delta"]) for i in kerb["items"]] == [("CORP\\helpdesk", "new", "new")]
    resolved = auth_client.get(f"/api/ad/snapshots/{snap2}/findings?status=resolved").json()
    assert resolved["total"] == 1
    item = resolved["items"][0]
    assert (item["key"], item["identity"], item["status"], item["delta"]) == (svc_sql["key"], "CORP\\svc_sql", "resolved", "gone")
    assert kerb["facets"]["status"]["resolved"] == 1
    state = _state(auth_client, "ad", domain_id, svc_sql["key"])
    assert state["status"] == "resolved" and state["present"] is False
    assert state["events"][0]["kind"] == "auto_resolved" and state["events"][0]["details"]["ref"] == f"снапшот #{snap2}"
    # Карточка пропавшей находки открывается из списка последнего снапшота.
    detail = auth_client.get(f"/api/ad/snapshots/{snap2}/findings/{svc_sql['key']}").json()
    assert detail["identity"] == "CORP\\svc_sql" and detail["status"] == "resolved" and len(detail["history"]) == 1

    # Вернулась — переоткрыта, исполнитель сохраняется.
    assert auth_client.put("/api/findings/state", json={"module": "ad", "scope_id": domain_id, "key": svc_sql["key"], "assignee": "tester"}).status_code == 200
    _done(auth_client, "ad", build_ad(now=AD_NOW + dt.timedelta(days=14)))
    _, snap3 = _ad_latest(auth_client)
    kerb = auth_client.get(f"/api/ad/snapshots/{snap3}/findings?check=Kerberoast").json()
    back = next(i for i in kerb["items"] if i["key"] == svc_sql["key"])
    assert (back["status"], back["assignee"], back["delta"]) == ("reopened", "tester", "new")
    assert back["first_seen_at"].startswith(AD_NOW.date().isoformat())
    state = _state(auth_client, "ad", domain_id, svc_sql["key"])
    assert state["status"] == "reopened" and state["present"] is True and state["events"][0]["kind"] == "auto_reopened"
    assert auth_client.get(f"/api/ad/snapshots/{snap3}/findings?status=resolved").json()["total"] == 1  # helpdesk пропал


def test_ad_risk_accepted_survives_disappearance(auth_client: TestClient) -> None:
    _done(auth_client, "ad", build_ad())
    domain_id, snap1 = _ad_latest(auth_client)
    key = auth_client.get(f"/api/ad/snapshots/{snap1}/findings?check=Kerberoast").json()["items"][0]["key"]
    r = auth_client.put("/api/findings/state", json={"module": "ad", "scope_id": domain_id, "key": key, "status": "risk_accepted", "comment": "сервисная учётка, пароль 32 символа"})
    assert r.status_code == 200, r.text
    _done(auth_client, "ad", _ad_without_svc_sql(AD_NOW + dt.timedelta(days=7)))
    state = _state(auth_client, "ad", domain_id, key)
    assert state["status"] == "risk_accepted" and state["present"] is False
    _, snap2 = _ad_latest(auth_client)
    accepted = auth_client.get(f"/api/ad/snapshots/{snap2}/findings?status=risk_accepted").json()
    assert [(i["key"], i["delta"]) for i in accepted["items"]] == [(key, "gone")]


def test_reconcile_failure_does_not_break_import(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*_args: Any, **_kwargs: Any) -> dict[str, int]:
        raise RuntimeError("платформа сломана")

    monkeypatch.setattr(svc, "reconcile", broken)
    _done(auth_client, "ad", build_ad())
    assert len(auth_client.get("/api/ad/snapshots").json()) == 1


# ---- AD: список, фильтры, массовая смена ---------------------------------------


def test_ad_list_filters_facets_and_bulk(auth_client: TestClient) -> None:
    _done(auth_client, "ad", build_ad())
    domain_id, snap = _ad_latest(auth_client)
    url = f"/api/ad/snapshots/{snap}/findings"
    everything = auth_client.get(url).json()
    total = everything["total"]
    k1, k2, k3 = (i["key"] for i in everything["items"][:3])

    yesterday = (TODAY - dt.timedelta(days=1)).isoformat()
    r = auth_client.post("/api/findings/bulk", json={"module": "ad", "scope_id": domain_id, "keys": [k1, k2],
                                                     "change": {"status": "in_work", "assignee": "tester", "due_date": yesterday}})
    assert r.status_code == 200 and r.json() == {"changed": 2}
    until = (TODAY + dt.timedelta(days=10)).isoformat()
    r = auth_client.put("/api/findings/state", json={"module": "ad", "scope_id": domain_id, "key": k3, "status": "risk_accepted",
                                                     "risk_until": until, "comment": "компенсирующая мера"})
    assert r.status_code == 200, r.text

    # По умолчанию — открытые: принятый риск не виден.
    default = auth_client.get(url).json()
    assert default["total"] == total - 1 and k3 not in {i["key"] for i in default["items"]}
    assert default["facets"]["status"]["in_work"] == 2 and default["facets"]["status"]["risk_accepted"] == 1
    assert default["facets"]["status"]["new"] == total - 3
    assert default["facets"]["assignee"]["tester"] == 2 and default["facets"]["assignee"]["none"] == total - 3
    assert default["facets"]["flags"] == {"overdue": 2, "risk_expiring": 1}

    mine = auth_client.get(f"{url}?assignee=me").json()
    assert mine["total"] == 2
    item = mine["items"][0]
    assert (item["status"], item["assignee"], item["due_date"], item["overdue"]) == ("in_work", "tester", yesterday, True)
    assert auth_client.get(f"{url}?assignee=tester").json()["total"] == 2
    assert auth_client.get(f"{url}?assignee=none").json()["total"] == total - 3
    assert auth_client.get(f"{url}?overdue=true").json()["total"] == 2
    assert auth_client.get(f"{url}?status=risk_accepted").json()["total"] == 1
    assert auth_client.get(f"{url}?status=in_work,risk_accepted").json()["total"] == 3
    assert auth_client.get(f"{url}?status=all").json()["total"] == total
    # «Риск истекает» без статуса — среди принятых.
    expiring = auth_client.get(f"{url}?risk_expiring=true").json()
    assert [(i["key"], i["risk_until"]) for i in expiring["items"]] == [(k3, until)]
    assert auth_client.get(f"{url}?status=bogus").status_code == 422
    assert auth_client.get(f"{url}?delta=bogus").status_code == 422


def test_ad_detail_carries_state_fields(auth_client: TestClient) -> None:
    _done(auth_client, "ad", build_ad())
    domain_id, snap = _ad_latest(auth_client)
    key = auth_client.get(f"/api/ad/snapshots/{snap}/findings?check=Kerberoast").json()["items"][0]["key"]
    auth_client.put("/api/findings/state", json={"module": "ad", "scope_id": domain_id, "key": key, "status": "in_work", "assignee": "tester"})
    detail = auth_client.get(f"/api/ad/snapshots/{snap}/findings/{key}").json()
    assert (detail["status"], detail["status_title"], detail["assignee"]) == ("in_work", "В работе", "tester")
    assert detail["description"] and len(detail["history"]) == 1 and "verdict" not in detail
    assert auth_client.get(f"/api/ad/snapshots/{snap}/findings/nope").status_code == 404


def test_old_verdict_routes_are_gone(auth_client: TestClient) -> None:
    assert auth_client.put("/api/ad/verdicts/k", json={"domain_id": 1, "reason": "x"}).status_code in (404, 405)
    assert auth_client.delete("/api/ad/verdicts/k?domain_id=1").status_code in (404, 405)
    assert auth_client.put("/api/ksc/verdicts/k", json={"server_id": 1, "reason": "x"}).status_code in (404, 405)
    assert auth_client.delete("/api/ksc/verdicts/k?server_id=1").status_code in (404, 405)


def test_adapters_link_and_first_seen(auth_client: TestClient, db_session: Any) -> None:
    _done(auth_client, "ad", build_ad())
    _done(auth_client, "ad", build_ad(now=AD_NOW + dt.timedelta(days=3)))
    domain_id, snap = _ad_latest(auth_client)
    ad = get_adapter("ad")
    assert ad.link(domain_id, "abc") == f"/ad/domains/{domain_id}/findings?key=abc"
    assert get_adapter("ksc").link(5, "abc") == "/ksc/servers/5/findings?key=abc"
    assert list(ad.scopes(db_session)) == [domain_id]
    current = list(ad.current(db_session, domain_id))
    kerb = next(c for c in current if "svc_sql" in c.title)
    assert kerb.severity and len(current) == auth_client.get(f"/api/ad/snapshots/{snap}").json()["findings"]
    seen = ad.first_seen(db_session, domain_id, kerb.key)
    assert seen is not None and seen.date() == AD_NOW.date()


# ---- AD: обзор, подсчёты, ATT&CK -----------------------------------------------


def test_ad_overview_and_counted_setting(auth_client: TestClient, db_session: Any) -> None:
    _done(auth_client, "ad", build_ad())
    domain_id, snap = _ad_latest(auth_client)
    key = auth_client.get(f"/api/ad/snapshots/{snap}/findings?check=Kerberoast").json()["items"][0]["key"]
    layer_before = LAYERS["ad"].build(db_session).cells["T1558"].count
    overview = auth_client.get(f"/api/ad/domains/{domain_id}/overview").json()
    findings = overview["snapshot"]["findings"]
    assert "accepted_total" not in overview
    assert overview["summary"]["by_status"]["new"] == findings and overview["summary"]["unassigned"] == findings
    assert overview["counted"]["total"] == findings
    kerb = next(c for c in overview["checks"] if c["code"] == "Kerberoast")
    assert (kerb["total"], kerb["all"], kerb["open"], kerb["new"], kerb["resolved"]) == (1, 1, 1, 0, 0)

    r = auth_client.put("/api/findings/state", json={"module": "ad", "scope_id": domain_id, "key": key, "status": "risk_accepted", "comment": "норма"})
    assert r.status_code == 200, r.text
    overview = auth_client.get(f"/api/ad/domains/{domain_id}/overview").json()
    kerb = next(c for c in overview["checks"] if c["code"] == "Kerberoast")
    assert (kerb["total"], kerb["all"], kerb["open"]) == (0, 1, 0)
    assert overview["counted"]["total"] == findings - 1
    assert overview["summary"]["by_status"]["risk_accepted"] == 1 and overview["summary"]["by_status"]["new"] == findings - 1
    db_session.expire_all()
    assert LAYERS["ad"].build(db_session).cells["T1558"].count == layer_before - 1

    # Принятый риск велено считать — снова в подсчётах обзора и в слое ATT&CK.
    assert auth_client.put("/api/settings/findings", json={"counted": {"risk_accepted": True}}).status_code == 200
    kerb = next(c for c in auth_client.get(f"/api/ad/domains/{domain_id}/overview").json()["checks"] if c["code"] == "Kerberoast")
    assert kerb["total"] == 1
    db_session.expire_all()
    assert LAYERS["ad"].build(db_session).cells["T1558"].count == layer_before


def test_ad_overview_resolved_since_previous(auth_client: TestClient) -> None:
    _done(auth_client, "ad", build_ad())
    _done(auth_client, "ad", _ad_without_svc_sql(AD_NOW + dt.timedelta(days=7)))
    domain_id, _ = _ad_latest(auth_client)
    overview = auth_client.get(f"/api/ad/domains/{domain_id}/overview").json()
    kerb = next(c for c in overview["checks"] if c["code"] == "Kerberoast")
    assert (kerb["new"], kerb["resolved"], kerb["total"]) == (1, 1, 1)
    assert overview["compared_to"]["new"] == 1 and overview["compared_to"]["fixed"] == 1
    assert overview["summary"]["by_status"]["resolved"] == 1


# ---- KSC -------------------------------------------------------------------------


def _ksc_latest(client: TestClient) -> tuple[int, int]:
    snap = client.get("/api/ksc/snapshots").json()[0]
    return int(snap["server_id"]), int(snap["id"])


def _ksc_rtp(raw: dict[str, Any], ws02_off: bool) -> dict[str, Any]:
    for h in raw["hosts"]:
        if h["KLHST_WKS_DN"] == "WS02" and not ws02_off:
            h["KLHST_WKS_RTP_STATE"] = 7
    return raw


def test_ksc_statuses_follow_snapshots_and_hosts_count_counted(auth_client: TestClient) -> None:
    _done(auth_client, "ksc", build_ksc())
    server_id, snap1 = _ksc_latest(auth_client)
    rtp = auth_client.get(f"/api/ksc/snapshots/{snap1}/findings?check=RTP_OFF").json()["items"][0]
    assert (rtp["host"], rtp["status"], rtp["delta"]) == ("WS02", "new", "same")

    # Принятый риск: хост не считает находку, карточка хоста показывает статус.
    r = auth_client.put("/api/findings/state", json={"module": "ksc", "scope_id": server_id, "key": rtp["key"], "status": "risk_accepted", "comment": "стенд"})
    assert r.status_code == 200, r.text
    hosts = auth_client.get(f"/api/ksc/snapshots/{snap1}/hosts?q=ws02").json()["items"]
    assert next(h for h in hosts if h["host_id"] == "h-ws02")["findings"] == 0
    detail = auth_client.get(f"/api/ksc/snapshots/{snap1}/hosts/h-ws02").json()
    assert [(f["check"], f["status"]) for f in detail["findings"]] == [("RTP_OFF", "risk_accepted")]
    overview = auth_client.get(f"/api/ksc/servers/{server_id}/overview").json()
    card = next(c for c in overview["checks"] if c["code"] == "RTP_OFF")
    assert (card["total"], card["all"]) == (0, 1) and overview["summary"]["by_status"]["risk_accepted"] == 1

    # В работе → пропала → устранена → вернулась → переоткрыта.
    auth_client.put("/api/findings/state", json={"module": "ksc", "scope_id": server_id, "key": rtp["key"], "status": "in_work"})
    _done(auth_client, "ksc", _ksc_rtp(build_ksc(now=KSC_NOW + dt.timedelta(days=1)), ws02_off=False))
    _, snap2 = _ksc_latest(auth_client)
    assert _state(auth_client, "ksc", server_id, rtp["key"])["status"] == "resolved"
    gone = auth_client.get(f"/api/ksc/snapshots/{snap2}/findings?status=resolved").json()
    assert [(i["key"], i["host"], i["delta"]) for i in gone["items"]] == [(rtp["key"], "WS02", "gone")]
    _done(auth_client, "ksc", build_ksc(now=KSC_NOW + dt.timedelta(days=2)))
    state = _state(auth_client, "ksc", server_id, rtp["key"])
    assert state["status"] == "reopened" and state["events"][0]["details"]["ref"].startswith("снапшот #")
