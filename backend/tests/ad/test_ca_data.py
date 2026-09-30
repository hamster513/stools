"""Данные ЦС (`stools-ad-ca/1`): разбор, хранение, свежесть по разделам, загрузка и удаление."""
from __future__ import annotations

import datetime as dt
import gzip
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.modules.ad.core.ca_data import CA_FORMAT, CaDataFormatError, parse_ca_data, sniff_format
from api.modules.ad.core.checks import ANALYZER_VERSION
from api.modules.ad.core.export import ExportFormatError, ExportIndex, load_export, load_export_path
from api.modules.ad.models import AdCaData, AdDomain, AdSnapshot
from api.modules.ad.services.ca_data import delete_ca_data, effective_ca_data, store_ca_data
from api.modules.ad.services.snapshots import snapshot_path
from tests.ad.synthetic import DOMAIN_SID, NOW, build_ca_data, build_export
from tests.api.conftest import TEST_LOGIN

#: Заголовок gzip цел, а поток deflate битый: zlib.error, не OSError.
CORRUPT_GZIP = b"\x1f\x8b\x08\x00" + b"\x00" * 6 + b"\xff" * 20

# ---- Формат ----------------------------------------------------------------


def test_parse_accepts_synthetic_ca_data() -> None:
    data = parse_ca_data(build_ca_data())
    assert data.sections == ["ca", "dc", "web"] and data.domain.sid == DOMAIN_SID
    assert data.cas[0].name == "CORP-CA" and data.cas[0].edit_flags == 0x11014E and data.cas[0].security
    assert data.dcs[0].strong_binding == 2 and data.web[0].status == 404 and data.web[0].auth == []


def test_parse_rejects_ad_export() -> None:
    with pytest.raises(CaDataFormatError, match=CA_FORMAT):
        parse_ca_data(build_export())


def test_parse_rejects_incomplete_file() -> None:
    raw = build_ca_data()
    del raw["domain"]
    with pytest.raises(CaDataFormatError, match="domain"):
        parse_ca_data(raw)


def test_ca_entry_with_error_and_without_flags_is_read() -> None:
    data = parse_ca_data(build_ca_data(cas=[{"name": "CORP-CA", "host": "ca01.corp.local", "error": "доступ запрещён"}]))
    ca = data.cas[0]
    assert ca.error == "доступ запрещён" and ca.edit_flags is None and ca.interface_flags is None
    assert ca.security is None and ca.disable_extension_list == []


def test_null_values_from_registry_are_kept_as_none() -> None:
    data = parse_ca_data(build_ca_data(dcs=[{"host": "dc01.corp.local", "strong_binding": None, "mapping_methods": None, "error": ""}]))
    assert data.dcs[0].strong_binding is None and data.dcs[0].mapping_methods is None


def test_sniff_format_reads_json_and_gzip(tmp_path: Path) -> None:
    text = json.dumps(build_ca_data()).encode()
    plain, packed = tmp_path / "ca.json", tmp_path / "ca.json.gz"
    plain.write_bytes(text)
    packed.write_bytes(gzip.compress(text))
    assert sniff_format(plain) == CA_FORMAT and sniff_format(packed) == CA_FORMAT
    export = tmp_path / "ad.json"
    export.write_bytes(json.dumps(build_export()).encode())
    assert sniff_format(export) == "stools-ad/1"


def test_sniff_format_gives_up_on_large_or_foreign_files(tmp_path: Path) -> None:
    text = json.dumps(build_ca_data()).encode()
    plain, packed = tmp_path / "ca.json", tmp_path / "ca.json.gz"
    plain.write_bytes(text)
    packed.write_bytes(gzip.compress(text))
    assert sniff_format(plain, max_bytes=len(text) - 1) is None
    assert sniff_format(packed, max_bytes=len(text) - 1) is None
    other = tmp_path / "kb.zip"
    other.write_bytes(b"PK\x03\x04not json")
    assert sniff_format(other) is None
    broken = tmp_path / "broken.gz"
    broken.write_bytes(b"\x1f\x8bnot gzip")
    assert sniff_format(broken) is None
    array = tmp_path / "array.json"
    array.write_bytes(b"[1, 2]")
    assert sniff_format(array) is None


def test_sniff_format_gives_up_on_corrupt_deflate(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json.gz"
    broken.write_bytes(CORRUPT_GZIP)
    assert sniff_format(broken) is None


def test_export_reader_explains_corrupt_deflate(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json.gz"
    broken.write_bytes(CORRUPT_GZIP)
    with pytest.raises(ExportFormatError, match="^выгрузка не распакована: ") as exc:
        load_export_path(broken)
    assert "Error -3" not in str(exc.value)
    with pytest.raises(ExportFormatError, match="^выгрузка не распакована: "):
        load_export(CORRUPT_GZIP)


def test_parse_rejects_unknown_section() -> None:
    with pytest.raises(CaDataFormatError, match="неизвестный раздел «pki»"):
        parse_ca_data(build_ca_data(sections=["ca", "pki"]))


def test_parse_rejects_records_of_unlisted_section() -> None:
    with pytest.raises(CaDataFormatError, match="«dc»"):
        parse_ca_data(build_ca_data(sections=["ca", "web"]))
    # Пустой список раздела, которого нет в sections, — не противоречие.
    assert parse_ca_data(build_ca_data(sections=["ca"], dcs=[], web=None)).sections == ["ca"]


def test_parse_explains_other_ca_format_version() -> None:
    raw = build_ca_data()
    raw["format"] = "stools-ad-ca/2"
    with pytest.raises(CaDataFormatError, match="^данные ЦС формата stools-ad-ca/2 не поддерживаются, нужен stools-ad-ca/1$"):
        parse_ca_data(raw)


def test_naive_collected_at_is_utc() -> None:
    data = parse_ca_data(build_ca_data(now=NOW.replace(tzinfo=None)))
    assert data.collected_at.tzinfo is not None and data.collected_at == NOW


def test_export_index_carries_ca_data() -> None:
    export = load_export(json.dumps(build_export()).encode())
    ca = parse_ca_data(build_ca_data())
    assert ExportIndex(export).ca is None
    assert ExportIndex(export, ca).ca is ca


# ---- Хранение --------------------------------------------------------------


def _domain(db: Any) -> AdDomain:
    domain = AdDomain(sid=DOMAIN_SID, dns_root="corp.local", netbios="CORP")
    db.add(domain)
    db.commit()
    return domain


def _store(db: Any, raw: dict[str, Any]) -> AdCaData:
    row = store_ca_data(db, parse_ca_data(raw), filename="adca.json.gz", sha256="0" * 64, uploaded_by="tester")
    db.commit()
    return row


def test_store_requires_known_domain(db_session: Any) -> None:
    with pytest.raises(ValueError, match="сначала загрузите выгрузку домена"):
        store_ca_data(db_session, parse_ca_data(build_ca_data()), filename="x", sha256="", uploaded_by="tester")


def test_effective_ca_data_takes_freshest_section_each(db_session: Any) -> None:
    domain = _domain(db_session)
    assert effective_ca_data(db_session, domain.id) == (None, None)
    older = build_ca_data(now=NOW - dt.timedelta(days=1), sections=["ca", "dc"], web=[])
    newer = build_ca_data(sections=["ca"], dcs=[], web=[])
    newer["cas"][0]["name"] = "CORP-CA2"
    first = _store(db_session, older)
    second = _store(db_session, newer)
    ca, ca_id = effective_ca_data(db_session, domain.id)
    assert ca is not None and ca_id == second.id and first.id != second.id
    assert [c.name for c in ca.cas] == ["CORP-CA2"]
    assert [d.host for d in ca.dcs] == ["dc01.corp.local"]
    assert ca.web == [] and ca.sections == ["ca", "dc"] and ca.collected_at == NOW


def test_effective_ca_data_dates_each_section_by_its_upload(db_session: Any) -> None:
    domain = _domain(db_session)
    yesterday = NOW - dt.timedelta(days=1)
    first = _store(db_session, build_ca_data(now=yesterday, sections=["ca", "dc"], web=[]))
    second = _store(db_session, build_ca_data(sections=["ca"], dcs=[], web=[]))
    ca, _ = effective_ca_data(db_session, domain.id)
    assert ca is not None
    assert ca.section_dates == {"ca": NOW, "dc": yesterday}
    assert ca.section_sources == {"ca": second.id, "dc": first.id}
    # В хранимый файл служебные поля не пишутся.
    assert "section_dates" not in second.data and "section_sources" not in second.data


def test_effective_ca_data_ignores_upload_order(db_session: Any) -> None:
    """Свежесть — по дате сбора, а не по порядку загрузки."""
    domain = _domain(db_session)
    newer = _store(db_session, build_ca_data())
    older = build_ca_data(now=NOW - dt.timedelta(days=3))
    older["cas"][0]["name"] = "OLD-CA"
    _store(db_session, older)
    ca, ca_id = effective_ca_data(db_session, domain.id)
    assert ca is not None and ca_id == newer.id and [c.name for c in ca.cas] == ["CORP-CA"]
    assert ca.sections == ["ca", "dc", "web"]


def test_deleting_ca_data_clears_snapshot_link(db_session: Any) -> None:
    domain = _domain(db_session)
    row = _store(db_session, build_ca_data())
    snap = AdSnapshot(domain_id=domain.id, collected_at=NOW, source="file", ca_data_id=row.id)
    db_session.add(snap)
    db_session.commit()
    delete_ca_data(db_session, row)
    db_session.refresh(snap)
    assert snap.ca_data_id is None


# ---- API -------------------------------------------------------------------


def _post(client: TestClient, raw: dict[str, Any], name: str = "adca.json", packed: bool = False) -> Any:
    body = json.dumps(raw).encode()
    return client.post("/api/ad/snapshots/file", files={"file": (name, gzip.compress(body) if packed else body, "application/octet-stream")})


def _upload(client: TestClient, raw: dict[str, Any], name: str = "adca.json", packed: bool = False) -> dict[str, Any]:
    r = _post(client, raw, name, packed)
    assert r.status_code == 202, r.text
    return client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()


def test_ca_data_before_domain_fails_job(auth_client: TestClient) -> None:
    job = _upload(auth_client, build_ca_data())
    assert job["status"] == "failed" and "сначала загрузите выгрузку домена" in job["error"]
    assert auth_client.get("/api/ad/domains").json() == []


def test_broken_ca_data_fails_job_with_message(auth_client: TestClient) -> None:
    assert _upload(auth_client, build_export(), "ad.json")["status"] == "done"
    raw = build_ca_data()
    raw["cas"] = "не список"
    job = _upload(auth_client, raw)
    assert job["status"] == "failed" and "данные ЦС неполные" in job["error"]


def test_corrupt_gzip_upload_fails_with_readable_message(auth_client: TestClient) -> None:
    r = auth_client.post("/api/ad/snapshots/file", files={"file": ("adca.json.gz", CORRUPT_GZIP, "application/octet-stream")})
    assert r.status_code == 202, r.text
    job = auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "failed" and job["error"].startswith("выгрузка не распакована: ")
    assert "Error -3" not in job["error"]


def test_other_ca_format_version_upload_is_explained(auth_client: TestClient) -> None:
    assert _upload(auth_client, build_export(), "ad.json")["status"] == "done"
    raw = build_ca_data()
    raw["format"] = "stools-ad-ca/2"
    job = _upload(auth_client, raw)
    assert job["status"] == "failed"
    assert job["error"] == "данные ЦС формата stools-ad-ca/2 не поддерживаются, нужен stools-ad-ca/1"


def test_failed_reanalyze_after_ca_upload_says_data_is_stored(auth_client: TestClient, app_settings: Any) -> None:
    assert _upload(auth_client, build_export(), "ad.json")["status"] == "done"
    domain_id = auth_client.get("/api/ad/domains").json()[0]["id"]
    snap_id = auth_client.get(f"/api/ad/snapshots?domain_id={domain_id}").json()[0]["id"]
    snapshot_path(app_settings.data_dir, snap_id).unlink()
    job = _upload(auth_client, build_ca_data())
    assert job["status"] == "failed"
    assert job["error"].startswith(f"данные ЦС сохранены, но снапшот #{snap_id} не пересчитан: ")
    assert len(auth_client.get(f"/api/ad/domains/{domain_id}/ca-data").json()) == 1


def test_ca_data_upload_is_stored_and_reanalyzes_latest_snapshot(auth_client: TestClient, db_session: Any) -> None:
    assert _upload(auth_client, build_export(), "ad.json")["status"] == "done"
    domain_id = auth_client.get("/api/ad/domains").json()[0]["id"]
    snap_id = auth_client.get(f"/api/ad/snapshots?domain_id={domain_id}").json()[0]["id"]
    job = _upload(auth_client, build_ca_data(), "adca-CORP.json.gz", packed=True)
    assert job["status"] == "done", job
    assert job["message"] == f"данные ЦС: центров 1, контроллеров 1; снапшот #{snap_id} пересчитан"
    items = auth_client.get(f"/api/ad/domains/{domain_id}/ca-data").json()
    assert len(items) == 1
    item = items[0]
    assert item["sections"] == ["ca", "dc", "web"] and (item["cas"], item["dcs"], item["web"]) == (1, 1, 1)
    assert item["filename"] == "adca-CORP.json.gz" and item["uploaded_by"] == TEST_LOGIN
    assert item["collected_at"].startswith("2026-09-09T12:00:00")
    # Снапшот не добавился, а последний пересчитан по этим данным.
    assert len(auth_client.get(f"/api/ad/snapshots?domain_id={domain_id}").json()) == 1
    snap = db_session.get(AdSnapshot, snap_id)
    assert snap.ca_data_id == item["id"] and snap.analyzer_version == ANALYZER_VERSION


def test_new_snapshot_uses_stored_ca_data(auth_client: TestClient, db_session: Any) -> None:
    assert _upload(auth_client, build_export(), "ad.json")["status"] == "done"
    domain_id = auth_client.get("/api/ad/domains").json()[0]["id"]
    assert _upload(auth_client, build_ca_data())["status"] == "done"
    ca_id = auth_client.get(f"/api/ad/domains/{domain_id}/ca-data").json()[0]["id"]
    assert _upload(auth_client, build_export(now=NOW + dt.timedelta(days=1)), "ad2.json")["status"] == "done"
    newest = auth_client.get(f"/api/ad/snapshots?domain_id={domain_id}").json()[0]["id"]
    assert db_session.get(AdSnapshot, newest).ca_data_id == ca_id


def test_ca_data_for_domain_without_snapshots(auth_client: TestClient) -> None:
    assert _upload(auth_client, build_export(), "ad.json")["status"] == "done"
    domain_id = auth_client.get("/api/ad/domains").json()[0]["id"]
    snap_id = auth_client.get(f"/api/ad/snapshots?domain_id={domain_id}").json()[0]["id"]
    assert auth_client.delete(f"/api/ad/snapshots/{snap_id}").status_code == 204
    job = _upload(auth_client, build_ca_data())
    assert job["status"] == "done" and job["message"] == "данные ЦС: центров 1, контроллеров 1; снапшотов домена пока нет"
    ca_id = auth_client.get(f"/api/ad/domains/{domain_id}/ca-data").json()[0]["id"]
    r = auth_client.delete(f"/api/ad/ca-data/{ca_id}")
    assert r.status_code == 204 and r.content == b""
    assert auth_client.get(f"/api/ad/domains/{domain_id}/ca-data").json() == []


def test_delete_ca_data_reanalyzes_latest_snapshot(auth_client: TestClient, db_session: Any) -> None:
    assert _upload(auth_client, build_export(), "ad.json")["status"] == "done"
    domain_id = auth_client.get("/api/ad/domains").json()[0]["id"]
    snap_id = auth_client.get(f"/api/ad/snapshots?domain_id={domain_id}").json()[0]["id"]
    assert _upload(auth_client, build_ca_data())["status"] == "done"
    ca_id = auth_client.get(f"/api/ad/domains/{domain_id}/ca-data").json()[0]["id"]
    r = auth_client.delete(f"/api/ad/ca-data/{ca_id}")
    assert r.status_code == 202, r.text
    job = auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "done" and job["kind"] == "reanalyze"
    assert auth_client.get(f"/api/ad/domains/{domain_id}/ca-data").json() == []
    assert db_session.get(AdSnapshot, snap_id).ca_data_id is None
    assert auth_client.delete(f"/api/ad/ca-data/{ca_id}").status_code == 404


def test_ca_data_list_of_unknown_domain_is_404(auth_client: TestClient) -> None:
    assert auth_client.get("/api/ad/domains/999/ca-data").status_code == 404


def test_auditor_reads_but_cannot_upload_or_delete_ca_data(auth_client: TestClient, client_as: Any) -> None:
    assert _upload(auth_client, build_export(), "ad.json")["status"] == "done"
    assert _upload(auth_client, build_ca_data())["status"] == "done"
    domain_id = auth_client.get("/api/ad/domains").json()[0]["id"]
    ca_id = auth_client.get(f"/api/ad/domains/{domain_id}/ca-data").json()[0]["id"]
    auditor = client_as("auditor")
    assert _post(auditor, build_ca_data()).status_code == 403
    assert auditor.delete(f"/api/ad/ca-data/{ca_id}").status_code == 403
    assert len(auditor.get(f"/api/ad/domains/{domain_id}/ca-data").json()) == 1
