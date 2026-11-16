"""Образы контейнеров: список с фасетами, карточка образа, уязвимости образа, экспорт."""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.modules.vm.models import VmCve, VmImage, VmImageCve

EXPORT_HEADER = [
    "Образ", "Тип артефакта", "Платформа", "Теги", "CVE", "Пакет", "Установлена", "Исправлена", "Trivy", "CVSS Trivy",
    "Риск", "Уровень", "EPSS", "KEV", "Статус скана", "Дата скана",
]


def _image(db: Any, project: str, repository: str, *, risk: int | None, tags: list[str] | None = None, **kw: Any) -> VmImage:
    image = VmImage(
        project=project, repository=repository, digest=f"sha256:{project}{repository}".ljust(71, "0"),
        tags=json.dumps(tags or ["latest"]), risk_max=risk, scan_status=kw.pop("scan_status", "success"), **kw,
    )
    db.add(image)
    db.flush()
    return image


def _pair(db: Any, image: VmImage, cve_id: str, package: str, severity: str, **kw: Any) -> None:
    db.add(VmImageCve(
        image_id=image.id, cve_id=cve_id, package=package, installed_version=kw.pop("installed_version", "1.0"),
        trivy_severity=severity, **kw,
    ))


@pytest.fixture
def seeded(db_session: Any, auth_client: TestClient) -> dict[str, int]:
    db_session.add(VmCve(
        cve_id="CVE-2024-1111", epss=0.5, kev=True, cvss=9.8, cvss_source="nvd_v3", v3_av="NETWORK",
        likelihood=1.0, cvss10=0.98, av_class="network", description="mart",
    ))
    web = _image(db_session, "stools", "web", risk=80, tags=["1.2.3", "stable"], pushed_at=dt.datetime(2026, 1, 1, tzinfo=dt.UTC), trivy_critical=1, trivy_high=1, trivy_total=2)
    api = _image(db_session, "stools", "api", risk=10, trivy_high=2, trivy_total=2, pushed_at=dt.datetime(2026, 2, 1, tzinfo=dt.UTC), platform="linux/amd64, linux/arm64")
    other = _image(db_session, "library", "alpine", risk=None, scan_status="none")
    _pair(db_session, web, "CVE-2024-1111", "openssl", "critical", fixed_version="3.0.2", risk=80, risk_raw=0.8, trivy_cvss=9.8)
    _pair(db_session, web, "CVE-2024-2222", "zlib", "high", fixed_version="1.3", risk=20, trivy_cvss=7.5)
    _pair(db_session, web, "CVE-2024-3333", "curl", "high", risk=5)
    _pair(db_session, web, "GHSA-aaaa-bbbb-cccc", "pkg", "medium")
    _pair(db_session, api, "CVE-2024-2222", "zlib", "high", risk=10)
    db_session.commit()
    return {"web": web.id, "api": api.id, "other": other.id}


def test_list_sorted_nulls_last_with_facets(auth_client: TestClient, seeded: dict[str, int]) -> None:
    body = auth_client.get("/api/vm/images").json()
    assert body["total"] == 3
    assert [i["repository"] for i in body["items"]] == ["web", "api", "alpine"]
    assert [i["risk_max"] for i in body["items"]] == [80, 10, None]
    web = body["items"][0]
    assert web["name"] == "stools/web" and web["tags"] == ["1.2.3", "stable"]
    assert len(web["digest_short"]) == 12 and web["digest"].startswith("sha256:")
    assert web["trivy"] == {"critical": 1, "high": 1, "medium": 0, "low": 0, "unknown": 0, "total": 2}
    assert web["level"] == "high" and body["items"][2]["level"] is None
    facets = body["facets"]
    assert facets["level"] == {"none": 1, "low": 1, "medium": 0, "high": 1, "critical": 0}
    assert facets["project"] == {"stools": 2, "library": 1}
    assert facets["scan_status"] == {"success": 2, "none": 1}
    page = auth_client.get("/api/vm/images?offset=1&limit=1").json()
    assert page["total"] is None and page["facets"] is None
    assert [i["repository"] for i in page["items"]] == ["api"]


def test_list_filters_project_and_search(auth_client: TestClient, seeded: dict[str, int]) -> None:
    def names(query: str) -> list[str]:
        r = auth_client.get(f"/api/vm/images?{query}")
        assert r.status_code == 200, r.text
        return [i["name"] for i in r.json()["items"]]

    assert names("project=stools") == ["stools/web", "stools/api"]
    assert names("project=stools&project=library") == ["stools/web", "stools/api", "library/alpine"]
    assert names("q=web") == ["stools/web"]
    # По тегу.
    assert names("q=stable") == ["stools/web"]
    assert names("q=web&project=library") == []
    assert names("level=none") == ["library/alpine"]
    assert names("level=high&level=low") == ["stools/web", "stools/api"]
    assert names("scan_status=none") == ["library/alpine"]
    assert names("trivy=critical") == ["stools/web"]
    assert names("trivy=high") == ["stools/web", "stools/api"]
    assert names("q=100%25") == []
    # `_` в запросе — обычный символ, а не «любой знак»: `w_b` не находит `web`.
    assert names("q=w_b") == []
    # Фасеты считаются с теми же фильтрами.
    filtered = auth_client.get("/api/vm/images?project=stools").json()
    assert filtered["total"] == 2 and filtered["facets"]["project"] == {"stools": 2}


def test_list_other_sorts(auth_client: TestClient, seeded: dict[str, int]) -> None:
    def order(sort: str) -> list[str]:
        r = auth_client.get(f"/api/vm/images?sort={sort}")
        assert r.status_code == 200, r.text
        return [i["repository"] for i in r.json()["items"]]

    assert order("name") == ["alpine", "api", "web"]
    assert order("trivy_desc")[:2] == ["web", "api"]
    # Дата отправки: свежие выше, без даты — в конце.
    assert order("pushed_desc") == ["api", "web", "alpine"]


def test_equal_risk_ordered_by_name_then_id(auth_client: TestClient, db_session: Any) -> None:
    # Вставлены в обратном порядке: при равном риске порядок задаёт имя, а не вставка.
    for repo in ("zeta", "beta", "alpha"):
        _image(db_session, "stools", repo, risk=50)
    _image(db_session, "stools", "norisk", risk=None)
    db_session.commit()
    first = [i["repository"] for i in auth_client.get("/api/vm/images").json()["items"]]
    assert first == ["alpha", "beta", "zeta", "norisk"]
    paged = [auth_client.get(f"/api/vm/images?limit=1&offset={n}").json()["items"][0]["repository"] for n in range(4)]
    assert paged == first


def test_list_bad_sort_422(auth_client: TestClient, seeded: dict[str, int]) -> None:
    assert auth_client.get("/api/vm/images?sort=bogus").status_code == 422
    assert auth_client.get(f"/api/vm/images/{seeded['web']}/vulns?sort=bogus").status_code == 422
    assert auth_client.get("/api/vm/images/export?sort=bogus").status_code == 422
    assert auth_client.get("/api/vm/images?limit=1001").status_code == 422


def test_image_detail(auth_client: TestClient, seeded: dict[str, int]) -> None:
    body = auth_client.get(f"/api/vm/images/{seeded['api']}").json()
    assert body["name"] == "stools/api" and body["platform"] == "linux/amd64, linux/arm64"
    assert "last_sync_at" in body and body["last_sync_at"] is None
    assert auth_client.get("/api/vm/images/999999").status_code == 404
    assert auth_client.get("/api/vm/images/999999/vulns").status_code == 404


def test_image_vulns_filters_and_card(auth_client: TestClient, seeded: dict[str, int]) -> None:
    base = f"/api/vm/images/{seeded['web']}/vulns"
    body = auth_client.get(base).json()
    assert body["total"] == 4
    assert [i["cve_id"] for i in body["items"]] == ["CVE-2024-1111", "CVE-2024-2222", "CVE-2024-3333", "GHSA-aaaa-bbbb-cccc"]
    top = body["items"][0]
    assert top["risk"] == 80 and top["level"] == "high" and top["is_cve"] is True
    assert top["epss"] == 0.5 and top["kev"] is True and top["cvss"] == 9.8 and top["trivy_cvss"] == 9.8
    ghsa = body["items"][-1]
    assert ghsa["risk"] is None and ghsa["level"] is None and ghsa["is_cve"] is False and ghsa["epss"] is None
    assert body["facets"]["severity"] == {"critical": 1, "high": 2, "medium": 1}
    assert body["facets"]["fixed"] == {"yes": 2, "no": 2}
    assert body["facets"]["level"]["none"] == 1

    # Регистр серьёзности не важен.
    found = auth_client.get(f"{base}?severity=High&fixed=yes&sort=package").json()
    assert [i["package"] for i in found["items"]] == ["zlib"] and found["total"] == 1
    assert [i["cve_id"] for i in auth_client.get(f"{base}?sort=package").json()["items"]] == [
        "CVE-2024-3333", "CVE-2024-1111", "GHSA-aaaa-bbbb-cccc", "CVE-2024-2222"]
    assert [i["cve_id"] for i in auth_client.get(f"{base}?sort=severity_desc").json()["items"]][-1] == "GHSA-aaaa-bbbb-cccc"
    assert [i["cve_id"] for i in auth_client.get(f"{base}?q=ZLIB").json()["items"]] == ["CVE-2024-2222"]
    assert [i["cve_id"] for i in auth_client.get(f"{base}?q=2024-3").json()["items"]] == ["CVE-2024-3333"]
    assert [i["cve_id"] for i in auth_client.get(f"{base}?level=none").json()["items"]] == ["GHSA-aaaa-bbbb-cccc"]
    assert auth_client.get(f"{base}?fixed=maybe").status_code == 422
    assert auth_client.get(f"{base}?offset=1").json()["facets"] is None

    card = auth_client.get(f"{base}/CVE-2024-1111", params={"package": "openssl", "installed_version": "1.0"})
    assert card.status_code == 200, card.text
    body = card.json()
    assert body["image"]["name"] == "stools/web" and body["vuln"]["cve_id"] == "CVE-2024-1111"
    factors = body["factors"]
    assert factors["score"] == 80 and factors["level"] == "high"
    assert factors["blocks"]["exploitation"]["points"] == 40
    assert factors["blocks"]["exposure"]["points"] == 12
    assert factors["blocks"]["exposure"]["assumed"] is True
    assert factors["blocks"]["asset"]["assumed"] is True
    assert factors["computed_score"] == 85  # stored 80 remains visible until recalc
    assert body["nvd_url"] == "https://nvd.nist.gov/vuln/detail/CVE-2024-1111"

    ghsa_card = auth_client.get(f"{base}/GHSA-aaaa-bbbb-cccc", params={"package": "pkg", "installed_version": "1.0"})
    assert ghsa_card.status_code == 200, ghsa_card.text
    assert ghsa_card.json()["factors"] is None and ghsa_card.json()["nvd_url"] is None
    # CVE без строки в витрине: расчёта нет.
    no_mart = auth_client.get(f"{base}/cve-2024-2222", params={"package": "zlib", "installed_version": "1.0"})
    assert no_mart.status_code == 200 and no_mart.json()["factors"] is None
    assert auth_client.get(f"{base}/CVE-2024-1111", params={"package": "nope"}).status_code == 404


def test_export_csv_rows(auth_client: TestClient, seeded: dict[str, int]) -> None:
    r = auth_client.get(f"/api/vm/images/export?format=csv&image_id={seeded['web']}")
    assert r.status_code == 200, r.text
    assert r.content.startswith("﻿".encode())
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig")), delimiter=";"))
    assert rows[0] == EXPORT_HEADER
    assert len(rows) == 5 and {row[0] for row in rows[1:]} == {"stools/web"}
    first = dict(zip(rows[0], rows[1], strict=True))
    assert first["CVE"] == "CVE-2024-1111" and first["Пакет"] == "openssl" and first["Исправлена"] == "3.0.2"
    assert first["Риск"] == "80" and first["Уровень"] == "high" and first["KEV"] == "да"
    assert first["Теги"] == "1.2.3, stable" and first["Статус скана"] == "success"
    ghsa = dict(zip(rows[0], rows[-1], strict=True))
    assert ghsa["CVE"] == "GHSA-aaaa-bbbb-cccc" and ghsa["Риск"] == "" and ghsa["Уровень"] == "" and ghsa["EPSS"] == ""

    everything = list(csv.reader(io.StringIO(auth_client.get("/api/vm/images/export").content.decode("utf-8-sig")), delimiter=";"))
    # 5 пар и образ без находок одной строкой.
    assert len(everything) == 1 + 5 + 1
    narrowed = auth_client.get("/api/vm/images/export?project=library").content.decode("utf-8-sig")
    assert len(narrowed.strip().splitlines()) == 2
    assert auth_client.get("/api/vm/images/export?format=pdf").status_code == 422
    xlsx = auth_client.get("/api/vm/images/export?format=xlsx")
    assert xlsx.status_code == 200 and xlsx.content[:2] == b"PK"


def test_read_level_allowed(client_as: Callable[[Any], TestClient], seeded: dict[str, int]) -> None:
    reader = client_as({"vm": "read"})
    web = seeded["web"]
    assert reader.get("/api/vm/images").status_code == 200
    assert reader.get(f"/api/vm/images/{web}").status_code == 200
    assert reader.get(f"/api/vm/images/{web}/vulns").status_code == 200
    assert reader.get(
        f"/api/vm/images/{web}/vulns/CVE-2024-1111", params={"package": "openssl", "installed_version": "1.0"},
    ).status_code == 200
    assert reader.get("/api/vm/images/export").status_code == 200
    stranger = client_as({"ad": "read"})
    assert stranger.get("/api/vm/images").status_code == 403
