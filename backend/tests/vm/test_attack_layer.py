"""Слой экспозиции VM: правило по вектору, порог, справочник CTID и кэш."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.db.models import AppSetting
from api.jobs import JobHandle
from api.modules.attack.layers import LAYERS, MAX_ITEMS
from api.modules.vm.core.attack_map import technique_for
from api.modules.vm.models import VmCve, VmHost, VmHostCve, VmJob, VmRefAttack, VmZone
from api.modules.vm.services.attack_layer import CACHE_KEY, _exposure
from api.modules.vm.services.refs import _load_attack

FIXTURES = Path(__file__).parent / "fixtures"


def _upload_ref(client: TestClient, name: str, *files: str) -> dict[str, Any]:
    payload = [("files", (f, (FIXTURES / f).read_bytes(), "application/octet-stream")) for f in files]
    r = client.post(f"/api/vm/refs/{name}/upload", files=payload)
    assert r.status_code == 202, r.text
    return dict(client.get(f"/api/vm/jobs/{r.json()['job_id']}").json())


def _set_threshold(client: TestClient, value: int) -> None:
    r = client.put("/api/vm/settings", json={"attack_min_risk": value})
    assert r.status_code == 200, r.text
    assert r.json()["attack_min_risk"] == value


def _cache(db_session: Any) -> dict[str, Any]:
    db_session.expire_all()
    row = db_session.get(AppSetting, CACHE_KEY)
    assert row is not None, "кэш слоя не записан"
    return dict(json.loads(row.value_json))


@pytest.fixture
def loaded(auth_client: TestClient) -> TestClient:
    """Два хоста: srv01 в интернет-зоне с сетевой CVE, srv02 внутри с локальной."""
    r = auth_client.post(
        "/api/vm/import/file",
        files={"file": ("attack-hosts.csv", (FIXTURES / "attack-hosts.csv").read_bytes(), "text/csv")},
    )
    assert r.status_code == 202, r.text
    assert _upload_ref(auth_client, "nvd", "nvd-attack.json")["status"] == "done"
    r = auth_client.put("/api/vm/zones", json=[{"name": "DMZ", "internet_access": True, "confidential_data": True}])
    assert r.status_code == 204, r.text
    assert auth_client.post("/api/vm/recalculate").status_code == 202
    return auth_client


def test_rule_fills_cells_and_threshold_narrows_them(loaded: TestClient, db_session: Any) -> None:
    # Пересчёт риска обновляет кэш слоя заодно: порог по умолчанию — 40.
    assert _cache(db_session)["threshold"] == 40

    pairs = {i["cve_id"]: i for i in loaded.get("/api/vm/vulns").json()["items"]}
    assert set(pairs) == {"CVE-2021-44228", "CVE-2021-4034"}
    _set_threshold(loaded, 0)

    db_session.expire_all()
    result = LAYERS["vm"].build(db_session)
    assert result.available and result.note == "риск ≥ 0"
    # Сетевой вектор без привилегий на хосте, смотрящем наружу, — эксплуатация
    # публичного сервиса; локальный вектор — повышение привилегий.
    assert set(result.cells) == {"T1190", "T1068"}
    assert result.technique_ids == frozenset({"T1190", "T1068"})
    cell = result.cells["T1190"]
    assert cell.count == 1 and 0 < len(cell.items) <= MAX_ITEMS
    item = cell.items[0]
    assert item.title == "srv01.corp.local: CVE-2021-44228"
    assert item.subtitle == f"риск {pairs['CVE-2021-44228']['risk']} · T1190 · DMZ"
    assert item.href == f"/vm/vulns?host={pairs['CVE-2021-44228']['host_id']}&cve=CVE-2021-44228"

    high, low = pairs["CVE-2021-44228"]["risk"], pairs["CVE-2021-4034"]["risk"]
    assert low < high
    _set_threshold(loaded, high)
    db_session.expire_all()
    narrowed = LAYERS["vm"].build(db_session)
    # Порог сменился — кэш пересчитан, хотя пары не трогали.
    assert set(narrowed.cells) == {"T1190"} and narrowed.note == f"риск ≥ {high}"
    assert _cache(db_session)["threshold"] == high

    # Порог выше любого риска: слой доступен, но пуст — данные есть, экспозиции нет.
    _set_threshold(loaded, 100)
    db_session.expire_all()
    empty = LAYERS["vm"].build(db_session)
    assert empty.available and empty.cells == {} and empty.note == "риск ≥ 100"


def test_ctid_reference_replaces_the_rule(loaded: TestClient, db_session: Any) -> None:
    _set_threshold(loaded, 0)
    assert _upload_ref(loaded, "attack", "ctid-kev.json", "attack_to_cve.csv")["status"] == "done"
    state = {s["name"]: s for s in loaded.get("/api/vm/refs").json()}["attack"]
    # Два файла — один справочник: JSON заменяет, CSV дописывается.
    assert state["title"] == "CVE → ATT&CK (CTID)" and state["records"] == 9

    # Загрузка справочника сбрасывает кэш сама, без обращения к слою.
    assert "T1059" in _cache(db_session)["cells"]
    result = LAYERS["vm"].build(db_session)
    # Для размеченной CTID CVE правило по вектору не применяется вовсе.
    assert set(result.cells) == {"T1059", "T1068"}
    assert result.cells["T1059"].items[0].title == "srv01.corp.local: CVE-2021-44228"


def test_techniques_outside_the_bundle_are_dropped(loaded: TestClient, db_session: Any) -> None:
    _set_threshold(loaded, 0)
    bogus = json.dumps(
        {"mapping_objects": [{"capability_id": "CVE-2021-44228", "attack_object_id": "T9999", "mapping_type": "primary_impact"}]}
    ).encode()
    r = loaded.post("/api/vm/refs/attack/upload", files=[("files", ("ctid.json", bogus, "application/json"))])
    assert r.status_code == 202, r.text
    assert loaded.get(f"/api/vm/jobs/{r.json()['job_id']}").json()["status"] == "done"
    assert {s["name"]: s for s in loaded.get("/api/vm/refs").json()}["attack"]["records"] == 0

    db_session.expire_all()
    # Техники нет в бандле — размётки не появилось, работает правило.
    assert set(LAYERS["vm"].build(db_session).cells) == {"T1190", "T1068"}


def test_reference_job_counts_the_loaded_rows(db_session: Any) -> None:
    """Счётчик задачи говорит, сколько связей принято.

    Без него загрузка справочника доходила до конца с нулём обработанных
    записей, и на экране задач это читалось как «ничего не сделано».
    """
    job = VmJob(kind="ref_attack", stage="pending", status="running")
    db_session.add(job)
    db_session.commit()
    n = _load_attack(db_session, FIXTURES / "attack_to_cve.csv", JobHandle(db_session, job), replace=True)
    assert n > 0
    assert job.processed == n and job.total == n


#: Вектор v3, вектор v2, «зона смотрит наружу» — тот же набор случаев,
#: что у `test_attack_map`, плюс пустые строки вместо NULL.
VECTORS = [
    (("NETWORK", "NONE", "NONE"), (None, None), True),
    (("NETWORK", "NONE", "NONE"), (None, None), False),
    (("NETWORK", "LOW", "REQUIRED"), (None, None), False),
    (("NETWORK", "NONE", "REQUIRED"), (None, None), True),
    (("NETWORK", "LOW", "NONE"), (None, None), True),
    (("NETWORK", "HIGH", "NONE"), (None, None), False),
    (("NETWORK", None, None), (None, None), True),
    (("ADJACENT_NETWORK", "NONE", "NONE"), (None, None), True),
    (("LOCAL", "LOW", "NONE"), (None, None), True),
    (("PHYSICAL", "NONE", "NONE"), (None, None), True),
    ((None, None, None), ("NETWORK", "NONE"), True),
    ((None, None, None), ("NETWORK", "NONE"), False),
    ((None, None, None), ("NETWORK", "SINGLE"), True),
    ((None, None, None), ("NETWORK", None), True),
    ((None, None, None), ("ADJACENT_NETWORK", "MULTIPLE"), False),
    ((None, None, None), ("LOCAL", "NONE"), False),
    ((None, None, None), (None, None), True),
    (("", "", ""), ("NETWORK", "NONE"), True),
    (("", "", ""), ("", ""), True),
]


def test_sql_case_matches_the_python_rule(db_session: Any) -> None:
    """Выражение `CASE` в SQL и `technique_for` дают одно и то же."""
    db_session.add(VmZone(name="out", internet_access=True, marked=True))
    db_session.add(VmZone(name="in", internet_access=False, marked=True))
    for i, (v3, v2, internet) in enumerate(VECTORS):
        cve = f"CVE-2000-{i:04d}"
        db_session.add(VmCve(cve_id=cve, v3_av=v3[0], v3_pr=v3[1], v3_ui=v3[2], v2_av=v2[0], v2_au=v2[1]))
        db_session.add(VmHost(id=i + 1, hostname=f"h{i:02d}", zone="out" if internet else "in"))
        db_session.add(VmHostCve(host_id=i + 1, cve_id=cve, risk=50))
    db_session.commit()

    sub = _exposure(0)
    got = dict(db_session.execute(select(sub.c.cve_id, sub.c.technique)).all())
    assert len(got) == len(VECTORS)
    for i, (v3, v2, internet) in enumerate(VECTORS):
        assert got[f"CVE-2000-{i:04d}"] == technique_for(*v3, *v2, internet), (v3, v2, internet)


def test_card_keeps_the_worst_pairs_of_the_whole_parent(db_session: Any) -> None:
    """Двадцать строк карточки выбираются по родителю, а не по подтехнике.

    Подтехники одного родителя делят одну ячейку, поэтому и двадцатку они
    делят: отбор внутри каждой подтехники по отдельности отвечал бы на
    другой вопрос. Часть пар размечена обеими подтехниками сразу — такая
    пара остаётся одной строкой и не занимает в двадцатке два места.
    """
    total = MAX_ITEMS + 10
    db_session.add(VmZone(name="in", internet_access=False, marked=True))
    for i in range(total):
        cve = f"CVE-2030-{i:04d}"
        db_session.add(VmCve(cve_id=cve, v3_av="LOCAL", v3_pr="LOW", v3_ui="NONE"))
        db_session.add(VmHost(id=i + 1, hostname=f"h{i:02d}", zone="in"))
        # Риск растёт с номером: худшие пары — последние.
        db_session.add(VmHostCve(host_id=i + 1, cve_id=cve, risk=50 + i))
        db_session.add(VmRefAttack(cve_id=cve, technique_id="T1059.001", mapping_type="primary_impact"))
        if i % 2:
            db_session.add(VmRefAttack(cve_id=cve, technique_id="T1059.003", mapping_type="primary_impact"))
    db_session.commit()

    cell = LAYERS["vm"].build(db_session).cells["T1059"]
    assert cell.count == total
    assert len(cell.items) == MAX_ITEMS
    worst = [f"CVE-2030-{i:04d}" for i in range(total - 1, total - 1 - MAX_ITEMS, -1)]
    assert [i.title.split(": ")[1] for i in cell.items] == worst


def test_layer_unavailable_without_hosts(db_session: Any) -> None:
    result = LAYERS["vm"].build(db_session)
    assert result.available is False and result.cells == {} and result.note
