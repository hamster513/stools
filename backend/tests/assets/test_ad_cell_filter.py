"""Фильтр «состав ячейки сводки AD» в списках «Активов» (дизайн «Интерактивная сводка AD» §5.3–5.4):
пользователи и активы по множеству ключей ячейки, выгрузка и выбор «всех по фильтру», сверка `ad_cell`.
Состав ячейки подменяется на уровне сервиса; один сквозной тест — на настоящем снапшоте AD."""
from __future__ import annotations

import datetime as dt
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.modules.ad.services import summary_cells as ad_cells_svc
from api.modules.ad.services.summary_cells import CellInfo, CellNotFound, CellUnavailable
from api.modules.assets.models import Asset, AssetObservation, AssetSettings, AssetUser
from api.modules.assets.routers import assets as assets_router
from api.modules.assets.services.users import ad_user_managed
from tests.ad.synthetic import DN as AD_DN
from tests.ad.synthetic import build_export, rid
from tests.assets.test_users_sync import account, ad_raw, corp_objects, csid, load_ad, sync, users
from tests.export_check import csv_rows

SNAP = 7
CELL = "password_age:admins:365"
COLLECTED = dt.datetime(2026, 10, 23, 21, 38, tzinfo=dt.UTC)
BASE = "S-1-5-21-7777777777-8888888888-9999999999"


def sid(n: int) -> str:
    return f"{BASE}-{n}"


TRUST = sid(1099)
#: 1001, 1002 — живые записи «Активов»; 1004 — только слитая; 1005 — в «Активах» нет; TRUST — учётка доверия.
CELL_USERS = frozenset({sid(1001), sid(1002), sid(1004), sid(1005), TRUST})
#: 2001 — живое наблюдение AD, 2002 — пропавшее, 2003 — у слитого актива.
CELL_COMPUTERS = frozenset({sid(2001), sid(2002), sid(2003)})
SAMS = {sid(1001): "user01", sid(1002): "user02", sid(1004): "user04", sid(1005): "user05", TRUST: "PARTNER$"}


def info(users: frozenset[str] = CELL_USERS, computers: frozenset[str] = CELL_COMPUTERS,
         sams: dict[str, str] | None = None) -> CellInfo:
    return CellInfo(SNAP, COLLECTED, "corp.example", CELL, "Возраст пароля 181–365 дн., админы", users, computers,
                    sams if sams is not None else SAMS)


@pytest.fixture
def cell(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Подмена `cell_info`: снапшот `SNAP`, ячейка `broken` — выгрузка не читается, другая — нет ячейки.
    Счётчик вызовов — `calls`: ячейка резолвится один раз на запрос."""
    calls: list[tuple[int, str]] = []
    current: dict[str, Any] = {"info": info(), "calls": calls}

    def fake(_db: Session, _data_dir: Path, snapshot_id: int, cell_id: str) -> CellInfo:
        calls.append((snapshot_id, cell_id))
        if snapshot_id != SNAP:
            raise CellNotFound("снапшот не найден")
        if cell_id == "broken":
            raise CellUnavailable("файл выгрузки снапшота недоступен")
        if cell_id != CELL:
            raise CellNotFound("ячейки сводки нет")
        return current["info"]

    monkeypatch.setattr(assets_router, "cell_info", fake)
    return current


@pytest.fixture
def registry(db_session: Session) -> dict[str, int]:
    """Пользователи и активы «Активов» для ячейки; имена — ключи для проверок."""
    now = dt.datetime.now(dt.UTC)
    u1 = AssetUser(sid=sid(1001), sam="user01", domain="corp.example", privileged=True, enabled=True)
    u2 = AssetUser(sid=sid(1002), sam="user02", domain="corp.example", enabled=True)
    u3 = AssetUser(sid=sid(1003), sam="user03", domain="corp.example", enabled=True)
    db_session.add_all([u1, u2, u3])
    db_session.flush()
    db_session.add(AssetUser(sid=sid(1004), sam="user04", domain="corp.example", merged_into=u1.id))
    a1, a2, a3 = Asset(name="ws01", name_key="ws01"), Asset(name="ws02", name_key="ws02"), Asset(name="ws03", name_key="ws03")
    db_session.add_all([a1, a2, a3])
    db_session.flush()
    a4 = Asset(name="ws04", name_key="ws04", merged_into=a1.id)
    db_session.add(a4)
    db_session.flush()
    db_session.add_all([
        AssetObservation(asset_id=a1.id, source="ad", source_key=sid(2001), name="ws01", seen_at=now),
        AssetObservation(asset_id=a2.id, source="ad", source_key=sid(2002), name="ws02", seen_at=now, gone_at=now),
        AssetObservation(asset_id=a3.id, source="ad", source_key=sid(2999), name="ws03", seen_at=now),
        # Тот же ключ, что в ячейке, но не из AD — не подходит.
        AssetObservation(asset_id=a3.id, source="ksc", source_key=sid(2001), name="ws03", seen_at=now),
        AssetObservation(asset_id=a4.id, source="ad", source_key=sid(2003), name="ws04", seen_at=now),
    ])
    db_session.commit()
    return {"u1": u1.id, "u2": u2.id, "u3": u3.id, "a1": a1.id, "a2": a2.id, "a3": a3.id}


PARAMS = {"ad_snapshot": SNAP, "ad_cell": CELL}


def test_ad_user_managed() -> None:
    assert ad_user_managed(sid(1), "user01")
    assert ad_user_managed(sid(1), "")
    assert ad_user_managed(sid(1), None)
    assert not ad_user_managed(sid(1), "PARTNER$")
    assert not ad_user_managed(None, "user01")
    assert not ad_user_managed("", "user01")


def test_users_filtered_by_cell(auth_client: TestClient, registry: dict[str, int], cell: dict[str, Any]) -> None:
    r = auth_client.get("/api/assets/users", params=PARAMS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert {u["id"] for u in body["items"]} == {registry["u1"], registry["u2"]}
    assert body["total"] == 2
    assert body["facets"]["privileged"] == {"yes": 1, "no": 1}
    assert body["ad_cell"] == {"label": "Возраст пароля 181–365 дн., админы", "collected_at": COLLECTED.isoformat(),
                               "domain": "corp.example", "in_summary": 5, "found": 2, "not_managed": 1, "other": 3}
    assert cell["calls"] == [(SNAP, CELL)]


def test_users_not_managed_dn_key_and_no_sam(auth_client: TestClient, registry: dict[str, int], cell: dict[str, Any]) -> None:
    """Ключ-DN — учётка без SID, «Активы» её не заводят; пустой sAMAccountName — не учётка доверия."""
    dn_key = "CN=nosid,CN=Users,DC=corp,DC=example"
    cell["info"] = info(users=frozenset({sid(1001), sid(1006), dn_key}), computers=frozenset(),
                        sams={sid(1001): "user01", sid(1006): "", dn_key: "nosid"})
    body = auth_client.get("/api/assets/users", params=PARAMS).json()
    assert body["ad_cell"]["in_summary"] == 3
    assert body["ad_cell"]["found"] == 1
    assert body["ad_cell"]["not_managed"] == 1
    assert body["ad_cell"]["other"] == 0


def test_users_found_ignores_other_filters(auth_client: TestClient, registry: dict[str, int], cell: dict[str, Any]) -> None:
    body = auth_client.get("/api/assets/users", params={**PARAMS, "privileged": "yes"}).json()
    assert [u["id"] for u in body["items"]] == [registry["u1"]]
    assert body["total"] == 1
    assert body["ad_cell"]["found"] == 2


def test_users_without_cell_or_on_next_page_have_no_check(auth_client: TestClient, registry: dict[str, int], cell: dict[str, Any]) -> None:
    body = auth_client.get("/api/assets/users").json()
    assert "ad_cell" not in body and body["total"] == 3
    body = auth_client.get("/api/assets/users", params={**PARAMS, "offset": 1}).json()
    assert "ad_cell" not in body and body["total"] == 2 and len(body["items"]) == 1


def test_users_cell_70k_sids(auth_client: TestClient, registry: dict[str, int], cell: dict[str, Any]) -> None:
    many = frozenset({sid(1001), sid(1002), sid(1003), *(sid(100_000 + i) for i in range(70_000 - 3))})
    assert len(many) == 70_000
    cell["info"] = info(users=many, sams={})
    r = auth_client.get("/api/assets/users", params=PARAMS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 3
    assert body["ad_cell"]["in_summary"] == 70_000
    assert body["ad_cell"]["found"] == 3


def test_assets_filtered_by_cell(auth_client: TestClient, registry: dict[str, int], cell: dict[str, Any]) -> None:
    r = auth_client.get("/api/assets/assets", params=PARAMS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert {a["id"] for a in body["items"]} == {registry["a1"], registry["a2"]}
    assert body["total"] == 2
    assert body["ad_cell"] == {"label": "Возраст пароля 181–365 дн., админы", "collected_at": COLLECTED.isoformat(),
                               "domain": "corp.example", "in_summary": 3, "found": 2, "not_managed": 0, "other": 5}
    assert cell["calls"] == [(SNAP, CELL)]
    body = auth_client.get("/api/assets/assets", params={**PARAMS, "q": "ws01"}).json()
    assert [a["id"] for a in body["items"]] == [registry["a1"]] and body["ad_cell"]["found"] == 2
    assert "ad_cell" not in auth_client.get("/api/assets/assets").json()


def test_assets_cell_70k_sids(auth_client: TestClient, registry: dict[str, int], cell: dict[str, Any]) -> None:
    many = frozenset({sid(2001), *(sid(100_000 + i) for i in range(70_000 - 1))})
    cell["info"] = info(computers=many)
    body = auth_client.get("/api/assets/assets", params=PARAMS).json()
    assert body["total"] == 1 and body["ad_cell"]["found"] == 1 and body["ad_cell"]["in_summary"] == 70_000


def test_asset_ids_respect_cell(auth_client: TestClient, registry: dict[str, int], cell: dict[str, Any]) -> None:
    r = auth_client.get("/api/assets/assets/ids", params=PARAMS)
    assert r.status_code == 200, r.text
    assert sorted(r.json()["ids"]) == sorted([registry["a1"], registry["a2"]])
    assert r.json()["total"] == 2


def test_export_respects_cell(auth_client: TestClient, registry: dict[str, int], cell: dict[str, Any]) -> None:
    rows = csv_rows(auth_client, "/api/assets/users/export", **PARAMS)
    assert sorted(row[0] for row in rows[1:]) == ["user01", "user02"]
    rows = csv_rows(auth_client, "/api/assets/assets/export", **PARAMS)
    assert sorted(row[0] for row in rows[1:]) == ["ws01", "ws02"]


@pytest.mark.parametrize("url", ["/api/assets/users", "/api/assets/assets", "/api/assets/assets/ids",
                                 "/api/assets/users/export", "/api/assets/assets/export"])
def test_cell_param_pair_required_422(auth_client: TestClient, cell: dict[str, Any], url: str) -> None:
    for params in ({"ad_snapshot": SNAP}, {"ad_cell": CELL}):
        r = auth_client.get(url, params=params)
        assert r.status_code == 422, (params, r.text)
    assert auth_client.get(url, params={"ad_snapshot": 0, "ad_cell": CELL}).status_code == 422
    assert auth_client.get(url, params={"ad_snapshot": SNAP, "ad_cell": "x" * 601}).status_code == 422
    assert cell["calls"] == []


@pytest.mark.parametrize("url", ["/api/assets/users", "/api/assets/assets", "/api/assets/assets/ids"])
def test_cell_unknown_404(auth_client: TestClient, cell: dict[str, Any], url: str) -> None:
    r = auth_client.get(url, params={"ad_snapshot": SNAP + 1, "ad_cell": CELL})
    assert r.status_code == 404 and r.json()["detail"] == "снапшот не найден", r.text
    r = auth_client.get(url, params={"ad_snapshot": SNAP, "ad_cell": "accounts:users:nope"})
    assert r.status_code == 404 and r.json()["detail"] == "ячейки сводки нет", r.text


@pytest.mark.parametrize("url", ["/api/assets/users", "/api/assets/assets", "/api/assets/users/export"])
def test_cell_unavailable_409(auth_client: TestClient, cell: dict[str, Any], url: str) -> None:
    r = auth_client.get(url, params={"ad_snapshot": SNAP, "ad_cell": "broken"})
    assert r.status_code == 409 and r.json()["detail"] == "файл выгрузки снапшота недоступен", r.text


def test_sync_skips_trust_and_sidless_accounts(db_session: Session, app_settings: Any) -> None:
    """Синхронизация и сверка — одно правило `ad_user_managed`: учётка доверия и учётка без SID не заводятся."""
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    db_session.add(AssetSettings(data={"sync_after_import": False}))
    db_session.commit()
    objects = [*corp_objects(now), account("PARTNER$", csid(1190)), account("nosid", "")]
    load_ad(db_session, Path(app_settings.data_dir), ad_raw(objects, now - dt.timedelta(hours=1)))
    sync(db_session)
    sams = {u.sam.lower() for u in users(db_session)}
    assert "user01" in sams
    assert "partner$" not in sams and "nosid" not in sams


@pytest.fixture
def _clear_ad_cache() -> Iterator[None]:
    """Номера снапшотов между тестами повторяются (TRUNCATE … RESTART IDENTITY)."""
    ad_cells_svc.clear_cache()
    yield
    ad_cells_svc.clear_cache()


@pytest.mark.usefixtures("_clear_ad_cache")
def test_cell_filter_on_real_snapshot(auth_client: TestClient) -> None:
    """Сквозной: снапшот AD с учёткой доверия → синхронизация «Активов» после импорта → списки по ячейкам."""
    raw = build_export()
    raw["objects"].append({"dn": f"CN=PARTNER$,CN=Users,{AD_DN}", "class": "user", "sid": rid(1300), "sam": "PARTNER$",
                           "name": "PARTNER", "uac": 2080, "primaryGroupID": 513})
    r = auth_client.post("/api/ad/snapshots/file", files={"file": ("ad.json", json.dumps(raw).encode(), "application/json")})
    assert r.status_code == 202, r.text
    assert auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()["status"] == "done"
    snap_id = auth_client.get("/api/ad/snapshots").json()[0]["id"]

    cell_users = auth_client.get(f"/api/ad/snapshots/{snap_id}/summary-cell", params={"cell": "accounts:users:total"}).json()
    body = auth_client.get("/api/assets/users", params={"ad_snapshot": snap_id, "ad_cell": "accounts:users:total"}).json()
    check = body["ad_cell"]
    assert check["in_summary"] == cell_users["users"] > 0
    assert check["not_managed"] == 1
    assert check["found"] == check["in_summary"] - 1 == body["total"]
    assert "PARTNER$" not in {u["sam"] for u in body["items"]}
    assert check["domain"] == cell_users["domain"] and check["label"] == cell_users["label"]

    cell_hosts = auth_client.get(f"/api/ad/snapshots/{snap_id}/summary-cell", params={"cell": "accounts:computers:total"}).json()
    body = auth_client.get("/api/assets/assets", params={"ad_snapshot": snap_id, "ad_cell": "accounts:computers:total"}).json()
    assert body["ad_cell"]["in_summary"] == cell_hosts["computers"] > 0
    assert body["ad_cell"]["found"] == body["total"] == cell_hosts["computers"]
    assert body["ad_cell"]["other"] == 0
