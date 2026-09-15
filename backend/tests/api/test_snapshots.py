from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.api.conftest import upload_and_wait


def test_upload_runs_through_all_stages_to_done(auth_client: TestClient, kb_zip_bytes: bytes) -> None:
    body = upload_and_wait(auth_client, kb_zip_bytes)
    job = auth_client.get(f"/api/siem/jobs/{body['job_id']}").json()
    assert job["stage"] == "done"
    assert job["status"] == "done"
    assert job["progress"] == 100
    assert job["error"] is None


def test_snapshot_summary_matches_synthetic_fixture(
    auth_client: TestClient, snapshot_id: int
) -> None:
    summary = auth_client.get(f"/api/siem/snapshots/{snapshot_id}").json()
    assert summary["rule_count"] == 2
    # class 1 (дублирует список) + class 2 (внутренний IP) — по одному
    assert summary["finding_count"] == 2
    assert summary["findings_by_kind"].get("1") == 1
    assert summary["findings_by_kind"].get("2") == 1
    assert summary["divergence_count"] == 1
    assert summary["delta"] is None, "первый снапшот — дельты быть не должно"
    # kb_version — в элементе списка (контракт), не в полной сводке.


def test_snapshot_appears_in_list(auth_client: TestClient, snapshot_id: int) -> None:
    listing = auth_client.get("/api/siem/snapshots").json()
    assert any(row["id"] == snapshot_id for row in listing)
    row = next(row for row in listing if row["id"] == snapshot_id)
    assert row["rule_count"] == 2
    assert row["finding_count"] == 2
    assert row["kb_version"] == "test-1.0"


def test_reupload_same_archive_is_idempotent(
    auth_client: TestClient, kb_zip_bytes: bytes, snapshot_id: int
) -> None:
    before = auth_client.get("/api/siem/snapshots").json()

    response = auth_client.post(
        "/api/siem/snapshots", files={"file": ("kb.zip", kb_zip_bytes, "application/zip")}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["duplicate"] is True
    assert body["snapshot_id"] == snapshot_id

    after = auth_client.get("/api/siem/snapshots").json()
    assert len(after) == len(before), "повторная загрузка не должна создавать второй снапшот"


def test_second_distinct_archive_produces_delta(
    auth_client: TestClient, snapshot_id: int, kb_zip_bytes_v2: bytes
) -> None:
    body = upload_and_wait(auth_client, kb_zip_bytes_v2, filename="kb2.zip")
    assert body["duplicate"] is False
    second_id = body["snapshot_id"]
    assert second_id != snapshot_id

    summary = auth_client.get(f"/api/siem/snapshots/{second_id}").json()
    assert summary["rule_count"] == 3
    assert summary["delta"] == {"finding_count": 0, "rule_count": 1}


def test_reparse_picks_up_improvements_in_parsing(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """После доработки разбора старый снапшот должен уметь догнать её.

    Кэш разбора записан прежним кодом, и новые сведения в старом снапшоте
    иначе не появятся никогда. Архив хранится целиком именно для этого.
    """
    response = auth_client.post(f"/api/siem/snapshots/{snapshot_id}/reparse")
    assert response.status_code == 202
    job = auth_client.get(f"/api/siem/jobs/{response.json()['job_id']}").json()
    assert job["status"] == "done", job

    rules = auth_client.get(f"/api/siem/rules?snapshot_id={snapshot_id}").json()
    assert rules["total"] > 0, "снапшот остался рабочим"


def test_reparse_of_a_missing_snapshot_is_refused(auth_client: TestClient) -> None:
    assert auth_client.post("/api/siem/snapshots/9999/reparse").status_code == 404


def test_reparse_keeps_the_snapshot_when_parsing_fails(
    auth_client: TestClient, snapshot_id: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Снапшот был рабочим до переразбора. Стирать его из-за неудачной
    попытки улучшить — значит наказывать за обновление."""
    import api.modules.siem.services.ingest as service

    def explode(*args: object, **kwargs: object) -> object:
        raise RuntimeError("разбор сломался")

    monkeypatch.setattr(service, "parse_archive", explode)
    response = auth_client.post(f"/api/siem/snapshots/{snapshot_id}/reparse")
    job = auth_client.get(f"/api/siem/jobs/{response.json()['job_id']}").json()
    assert job["status"] == "failed"

    assert auth_client.get(f"/api/siem/snapshots/{snapshot_id}").status_code == 200
    assert auth_client.get(f"/api/siem/rules?snapshot_id={snapshot_id}").json()["total"] > 0
