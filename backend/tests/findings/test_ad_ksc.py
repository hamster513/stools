"""AD и антивирус на общих статусах находок: автоматика по снапшотам, списки,
карточка, массовая смена, обзор и подсчёты (спека §1, §3–§5)."""
from __future__ import annotations

import datetime as dt
import gzip
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from api.modules.attack.layers import LAYERS
from api.platform.findings import service as svc
from api.platform.findings.adapters import get_adapter
from api.platform.findings.models import FindingEvent, FindingState
from tests.ad.synthetic import NOW as AD_NOW
from tests.ad.synthetic import build_export as build_ad
from tests.ksc.synthetic import NOW as KSC_NOW
from tests.ksc.synthetic import build_export as build_ksc


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


def _scope_rows(db: Any, module: str, scope_id: int) -> tuple[dict[str, tuple[str, bool]], list[str]]:
    """Строки состояния области (ключ → статус, present) и виды всех её событий."""
    db.expire_all()
    states = db.scalars(select(FindingState).where(FindingState.module == module, FindingState.scope_id == scope_id)).all()
    events = db.scalars(select(FindingEvent.kind).join(FindingState).where(
        FindingState.module == module, FindingState.scope_id == scope_id).order_by(FindingEvent.id)).all()
    return {s.key: (s.status, s.present) for s in states}, list(events)


def test_reanalyze_of_older_snapshot_leaves_statuses_alone(auth_client: TestClient, app_settings: Any, db_session: Any) -> None:
    _done(auth_client, "ad", build_ad())
    domain_id, snap1 = _ad_latest(auth_client)
    _done(auth_client, "ad", build_ad(now=AD_NOW + dt.timedelta(days=7)))
    key = auth_client.get(f"/api/ad/snapshots/{snap1}/findings?check=Kerberoast").json()["items"][0]["key"]
    auth_client.put("/api/findings/state", json={"module": "ad", "scope_id": domain_id, "key": key, "status": "in_work"})
    before = _scope_rows(db_session, "ad", domain_id)
    # Пересчёт старого снапшота даёт в нём находку, которой нет в последнем: статусы — по последнему, они не меняются.
    raw = build_ad()
    for o in raw["objects"]:
        if o.get("sam") == "helpdesk":
            o["spn"] = ["HTTP/help.corp.local"]
    (app_settings.data_dir / "ad" / f"{snap1}.json.gz").write_bytes(gzip.compress(json.dumps(raw).encode()))
    r = auth_client.post(f"/api/ad/snapshots/{snap1}/reanalyze")
    assert r.status_code == 202, r.text
    assert auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()["status"] == "done"
    assert auth_client.get(f"/api/ad/snapshots/{snap1}/findings?check=Kerberoast").json()["total"] == 2
    assert _scope_rows(db_session, "ad", domain_id) == before


def test_older_export_imported_after_newer_changes_nothing(auth_client: TestClient, db_session: Any) -> None:
    _done(auth_client, "ad", _ad_without_svc_sql(AD_NOW + dt.timedelta(days=7)))
    domain_id, newer = _ad_latest(auth_client)
    _done(auth_client, "ad", build_ad())
    assert _ad_latest(auth_client) == (domain_id, newer)
    # svc_sql есть только в старой выгрузке: «пропавшей» с последнего снапшота она не считается.
    assert _scope_rows(db_session, "ad", domain_id) == ({}, [])
    older = next(s["id"] for s in auth_client.get("/api/ad/snapshots").json() if s["id"] != newer)
    old_list = auth_client.get(f"/api/ad/snapshots/{older}/findings").json()
    assert (old_list["is_latest"], old_list["statuses_as_of"]) == (False, "today")
    new_list = auth_client.get(f"/api/ad/snapshots/{newer}/findings").json()
    assert (new_list["is_latest"], new_list["statuses_as_of"]) == (True, "today")


def test_analyzer_version_change_does_not_auto_resolve(auth_client: TestClient, db_session: Any, caplog: pytest.LogCaptureFixture) -> None:
    from api.modules.ad.models import AdSnapshot

    _done(auth_client, "ad", build_ad())
    domain_id, snap1 = _ad_latest(auth_client)
    key = auth_client.get(f"/api/ad/snapshots/{snap1}/findings?check=Kerberoast").json()["items"][0]["key"]
    auth_client.put("/api/findings/state", json={"module": "ad", "scope_id": domain_id, "key": key, "status": "in_work"})
    db_session.get(AdSnapshot, snap1).analyzer_version = "0-old"
    db_session.commit()
    _, events_before = _scope_rows(db_session, "ad", domain_id)
    caplog.clear()
    _done(auth_client, "ad", _ad_without_svc_sql(AD_NOW + dt.timedelta(days=7)))
    states, events = _scope_rows(db_session, "ad", domain_id)
    # Ключи разных версий анализатора не сравниваются: ни «устранена», ни событий.
    assert states == {key: ("in_work", False)}
    assert events == events_before and "auto_resolved" not in events
    warnings = [r for r in caplog.records if r.levelname == "WARNING" and "версией анализатора" in r.getMessage()]
    assert len(warnings) == 1


def test_detail_of_older_snapshot_does_not_borrow_other_snapshots(auth_client: TestClient) -> None:
    _done(auth_client, "ad", build_ad())
    _, snap1 = _ad_latest(auth_client)
    _done(auth_client, "ad", _ad_without_svc_sql(AD_NOW + dt.timedelta(days=7)))
    _, snap2 = _ad_latest(auth_client)
    helpdesk = auth_client.get(f"/api/ad/snapshots/{snap2}/findings?check=Kerberoast").json()["items"][0]["key"]
    # В старом снапшоте helpdesk не было: карточка не подставляет данные из нового.
    assert auth_client.get(f"/api/ad/snapshots/{snap1}/findings/{helpdesk}").status_code == 404
    # Статусы — на сегодня и у старого снапшота: svc_sql уже устранена, среди открытых её нет.
    svc_sql = auth_client.get(f"/api/ad/snapshots/{snap1}/findings?check=Kerberoast&status=all").json()["items"][0]["key"]
    assert auth_client.get(f"/api/ad/snapshots/{snap2}/findings/{svc_sql}").json()["delta"] == "gone"


def _add_states(db: Any, module: str, scope_id: int, rows: list[tuple[str, str, bool]]) -> None:
    """Строки состояния, как их оставляет перенос вердиктов: (ключ, статус, present)."""
    for key, status_, present in rows:
        db.add(FindingState(module=module, scope_id=scope_id, key=key, status=status_, reason="норма" if status_ == "risk_accepted" else "",
                            present=present, title="", severity="", updated_by="analyst1"))
    db.commit()


def test_migrated_verdicts_without_finding_in_latest_are_absent_rows(auth_client: TestClient, db_session: Any) -> None:
    _done(auth_client, "ad", build_ad())
    domain_id, snap1 = _ad_latest(auth_client)
    svc_sql = auth_client.get(f"/api/ad/snapshots/{snap1}/findings?check=Kerberoast").json()["items"][0]["key"]
    _done(auth_client, "ad", _ad_without_svc_sql(AD_NOW + dt.timedelta(days=7)))
    _, snap2 = _ad_latest(auth_client)
    findings = auth_client.get(f"/api/ad/snapshots/{snap2}").json()["findings"]
    # svc_sql нет в последнем снапшоте, orphan — ни в одном (вердикт пережил свою находку).
    db_session.execute(delete(FindingState).where(FindingState.key == svc_sql))
    _add_states(db_session, "ad", domain_id, [(svc_sql, "risk_accepted", False), ("orphan-key", "risk_accepted", False)])
    accepted = auth_client.get(f"/api/ad/snapshots/{snap2}/findings?status=risk_accepted").json()
    assert accepted["total"] == 2
    assert sorted((i["key"], i["delta"], i["status"]) for i in accepted["items"]) == sorted(
        [(svc_sql, "gone", "risk_accepted"), ("orphan-key", "gone", "risk_accepted")])
    assert accepted["facets"]["status"]["risk_accepted"] == 2
    assert auth_client.get(f"/api/ad/snapshots/{snap2}/findings/orphan-key").json()["status"] == "risk_accepted"
    summary = auth_client.get(f"/api/ad/domains/{domain_id}/overview").json()["summary"]
    assert summary["by_status"]["risk_accepted"] == 2 and summary["by_status"]["new"] == findings


def test_default_list_does_not_load_absent_rows(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import api.collector_routes as routes

    _done(auth_client, "ad", build_ad())
    _done(auth_client, "ad", _ad_without_svc_sql(AD_NOW + dt.timedelta(days=7)))
    _, snap2 = _ad_latest(auth_client)
    calls: list[int] = []
    real = routes.last_known

    def spy(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(routes, "last_known", spy)
    default = auth_client.get(f"/api/ad/snapshots/{snap2}/findings").json()
    assert calls == []
    # Устранённая не загружена, но в фасете статуса посчитана.
    assert default["facets"]["status"]["resolved"] == 1
    assert auth_client.get(f"/api/ad/snapshots/{snap2}/findings?status=resolved").json()["total"] == 1
    assert calls == [1]
    # Фильтр по данным находки: для фасетов первой страницы устранённые загружаются.
    assert auth_client.get(f"/api/ad/snapshots/{snap2}/findings?check=Kerberoast").json()["facets"]["status"]["resolved"] == 1
    assert len(calls) == 2
    assert auth_client.get(f"/api/ad/snapshots/{snap2}/findings?check=Kerberoast&offset=1").status_code == 200
    assert len(calls) == 2


def test_pagination_with_absent_rows_is_stable(auth_client: TestClient, db_session: Any) -> None:
    _done(auth_client, "ad", build_ad())
    _done(auth_client, "ad", _ad_without_svc_sql(AD_NOW + dt.timedelta(days=7)))
    domain_id, snap2 = _ad_latest(auth_client)
    _add_states(db_session, "ad", domain_id, [(f"orphan-{n}", "risk_accepted", False) for n in range(5)])
    url = f"/api/ad/snapshots/{snap2}/findings?status=all&limit=3"
    first = auth_client.get(url).json()
    total, keys, offset = first["total"], [i["key"] for i in first["items"]], 3
    while offset < total:
        page = auth_client.get(f"{url}&offset={offset}").json()
        assert page["total"] == total and page["facets"] is None
        keys += [i["key"] for i in page["items"]]
        offset += 3
    assert len(keys) == len(set(keys)) == total
    assert {f"orphan-{n}" for n in range(5)} <= set(keys)
    assert sum(first["facets"]["status"].values()) == total


def test_reconcile_failure_does_not_break_import(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*_args: Any, **_kwargs: Any) -> dict[str, int]:
        raise RuntimeError("платформа сломана")

    monkeypatch.setattr(svc, "reconcile", broken)
    _done(auth_client, "ad", build_ad())
    assert len(auth_client.get("/api/ad/snapshots").json()) == 1


# ---- AD: список, фильтры, массовая смена ---------------------------------------


def test_ad_list_filters_facets_and_bulk(auth_client: TestClient, today: dt.date) -> None:
    _done(auth_client, "ad", build_ad())
    domain_id, snap = _ad_latest(auth_client)
    url = f"/api/ad/snapshots/{snap}/findings"
    everything = auth_client.get(url).json()
    total = everything["total"]
    k1, k2, k3 = (i["key"] for i in everything["items"][:3])

    yesterday = (today - dt.timedelta(days=1)).isoformat()
    r = auth_client.post("/api/findings/bulk", json={"module": "ad", "scope_id": domain_id, "keys": [k1, k2],
                                                     "change": {"status": "in_work", "assignee": "tester", "due_date": yesterday}})
    assert r.status_code == 200 and r.json() == {"changed": 2}
    until = (today + dt.timedelta(days=10)).isoformat()
    r = auth_client.put("/api/findings/state", json={"module": "ad", "scope_id": domain_id, "key": k3, "status": "risk_accepted",
                                                     "risk_until": until, "comment": "компенсирующая мера"})
    assert r.status_code == 200, r.text

    # По умолчанию — открытые: принятый риск не виден.
    default = auth_client.get(url).json()
    assert default["total"] == total - 1 and k3 not in {i["key"] for i in default["items"]}
    assert default["facets"]["status"]["in_work"] == 2 and default["facets"]["status"]["risk_accepted"] == 1
    assert default["facets"]["status"]["new"] == total - 3
    assert default["facets"]["assignee"]["tester"] == 2 and default["facets"]["assignee"]["none"] == total - 3
    # Флаги — под выбранным статусом: принятого риска среди открытых нет.
    assert default["facets"]["flags"] == {"overdue": 2, "risk_expiring": 0}
    assert auth_client.get(f"{url}?risk_expiring=true").json()["facets"]["flags"] == {"overdue": 0, "risk_expiring": 1}
    assert auth_client.get(f"{url}?status=all").json()["facets"]["flags"] == {"overdue": 2, "risk_expiring": 1}

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
    assert ad.first_seen_many(db_session, domain_id, [kerb.key, "nope"]) == {kerb.key: seen}
    assert ad.has_scope(db_session, domain_id) and not ad.has_scope(db_session, domain_id + 1000)


def test_deleting_latest_snapshot_reconciles_with_previous(auth_client: TestClient) -> None:
    _done(auth_client, "ad", build_ad())
    domain_id, snap1 = _ad_latest(auth_client)
    key = auth_client.get(f"/api/ad/snapshots/{snap1}/findings?check=Kerberoast").json()["items"][0]["key"]
    _done(auth_client, "ad", _ad_without_svc_sql(AD_NOW + dt.timedelta(days=7)))
    _, snap2 = _ad_latest(auth_client)
    assert _state(auth_client, "ad", domain_id, key)["status"] == "resolved"
    # Последний снапшот удалён — данными снова стал первый, где находка есть.
    assert auth_client.delete(f"/api/ad/snapshots/{snap2}").status_code == 204
    state = _state(auth_client, "ad", domain_id, key)
    assert (state["status"], state["present"]) == ("reopened", True)


def test_scope_without_snapshots_has_no_data(auth_client: TestClient, db_session: Any) -> None:
    _done(auth_client, "ksc", build_ksc())
    server_id, snap = _ksc_latest(auth_client)
    key = auth_client.get(f"/api/ksc/snapshots/{snap}/findings?check=RTP_OFF").json()["items"][0]["key"]
    r = auth_client.put("/api/findings/state", json={"module": "ksc", "scope_id": server_id, "key": key, "status": "in_work"})
    assert r.status_code == 200, r.text
    assert auth_client.delete(f"/api/ksc/snapshots/{snap}").status_code == 204
    assert get_adapter("ksc").current(db_session, server_id) is None
    # Нет данных — не значит «всё устранено».
    state = _state(auth_client, "ksc", server_id, key)
    assert (state["status"], state["present"]) == ("in_work", True)


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


def test_overview_severity_count_matches_its_list(auth_client: TestClient) -> None:
    _done(auth_client, "ad", build_ad())
    domain_id, snap = _ad_latest(auth_client)
    url = f"/api/ad/snapshots/{snap}/findings"
    key = auth_client.get(f"{url}?check=Kerberoast").json()["items"][0]["key"]
    auth_client.put("/api/findings/state", json={"module": "ad", "scope_id": domain_id, "key": key, "status": "risk_accepted", "comment": "норма"})
    auth_client.put("/api/settings/findings", json={"counted": {"risk_accepted": True, "new": False}})
    counted = auth_client.get(f"/api/ad/domains/{domain_id}/overview").json()["counted"]
    assert counted["statuses"] == [s for s in svc.STATUSES if s in {"in_work", "risk_accepted", "fixed", "reopened"}]
    # Плитка ведёт на список с теми же статусами — числа совпадают.
    for severity, n in counted["by_severity"].items():
        listed = auth_client.get(url, params={"severity": severity, "status": ",".join(counted["statuses"])}).json()
        assert listed["total"] == n, severity


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
    assert detail["findings_counted"] == 0
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
