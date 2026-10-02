"""Слой экспозиции AD: маппинг проверок на техники и ячейки матрицы."""
from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from api.modules.ad.core.checks import CHECKS
from api.modules.ad.core.findings import SEVERITY_RANK
from api.modules.attack.layers import LAYERS
from api.modules.attack.services.attack_bundle import current as current_bundle
from tests.ad.synthetic import export_bytes


def test_every_check_maps_to_known_techniques(db_session: Any) -> None:
    known = set(current_bundle(db_session).by_id())
    for spec in CHECKS:
        assert spec.techniques, spec.code
        for technique in spec.techniques:
            assert technique in known, f"{spec.code}: {technique}"


def _upload(auth_client: TestClient, data: bytes) -> tuple[int, int]:
    r = auth_client.post("/api/ad/snapshots/file", files={"file": ("ad.json", data, "application/json")})
    assert r.status_code == 202, r.text
    assert auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()["status"] == "done"
    snap = auth_client.get("/api/ad/snapshots").json()[0]
    return int(snap["domain_id"]), int(snap["id"])


def test_ad_layer_counts_findings_and_respects_statuses(auth_client: TestClient, db_session: Any) -> None:
    domain_id, snapshot_id = _upload(auth_client, export_bytes())
    before = LAYERS["ad"].build(db_session)
    # Kerberoast размечен как T1558.003 — ячейка достаётся родителю,
    # а полный идентификатор остаётся для цепочек.
    assert before.available and "T1558" in before.cells
    assert "T1558.003" in before.technique_ids
    kerb = before.cells["T1558"]
    assert kerb.count > 0 and len(kerb.items) <= kerb.count
    assert all(i.href.startswith(f"/ad/domains/{domain_id}/findings?check=") for i in kerb.items)
    # В карточку помещаются не все находки, поэтому сначала тяжёлые.
    # Серьёзность берётся у самих находок, а не разбирается из подписи:
    # подпись — формат экрана, и правка формата не должна ронять проверку
    # порядка.
    found = auth_client.get(f"/api/ad/snapshots/{snapshot_id}/findings?limit=500").json()["items"]
    severity = {(f["check"], f["identity"] or f["target"]): f["severity"] for f in found}
    mixed = before.cells["T1078"]
    ranks = [
        SEVERITY_RANK[severity[(parse_qs(urlparse(i.href).query)["check"][0], i.title)]]
        for i in mixed.items
    ]
    assert len(set(ranks)) > 1 and ranks == sorted(ranks)

    # Принятый риск перестаёт быть экспозицией.
    key = auth_client.get(f"/api/ad/snapshots/{snapshot_id}/findings?check=Kerberoast").json()["items"][0]["key"]
    r = auth_client.put("/api/findings/state", json={"module": "ad", "scope_id": domain_id, "key": key, "status": "risk_accepted", "comment": "норма"})
    assert r.status_code == 200, r.text
    db_session.expire_all()
    after = LAYERS["ad"].build(db_session)
    assert after.cells["T1558"].count == kerb.count - 1


def test_ad_layer_skips_allowlisted_findings(auth_client: TestClient, db_session: Any) -> None:
    _upload(auth_client, export_bytes())
    listed = LAYERS["ad"].build(db_session)
    counted = sum(cell.count for cell in listed.cells.values())
    assert counted > 0
    # Находки в allowlist — сознательно принятая норма, не экспозиция.
    cfg = auth_client.get("/api/ad/settings").json()["config"]
    cfg["allowlist_short"].append("SVC_BACKUP")
    assert auth_client.put("/api/ad/settings", json=cfg).status_code == 200
    snapshot_id = auth_client.get("/api/ad/snapshots").json()[0]["id"]
    r = auth_client.post(f"/api/ad/snapshots/{snapshot_id}/reanalyze")
    assert auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()["status"] == "done"
    db_session.expire_all()
    after = LAYERS["ad"].build(db_session)
    assert sum(cell.count for cell in after.cells.values()) < counted


def test_ad_layer_without_snapshots(db_session: Any) -> None:
    result = LAYERS["ad"].build(db_session)
    assert result.available is False and result.cells == {} and result.note
