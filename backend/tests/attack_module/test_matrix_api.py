from __future__ import annotations

from fastapi.testclient import TestClient

from api.modules.attack.layers import Layer, LayerCell, LayerItem, LayerResult, register_layer


def _fake_layers(clean_layers) -> None:
    register_layer(Layer("siem", "Покрытие SIEM", "coverage", ("группа", "группы", "групп"),
        lambda db: LayerResult(cells={"T1003": LayerCell(1, status="confirmed", items=(LayerItem("G1", "группа правил", "/siem/x"),))}, technique_ids=frozenset({"T1003.001"}))))
    register_layer(Layer("vm", "Уязвимости", "exposure", ("хост", "хоста", "хостов"),
        lambda db: LayerResult(cells={"T1190": LayerCell(12), "T1003": LayerCell(2)}, technique_ids=frozenset({"T1190", "T1003"}), note="риск ≥ 40")))
    register_layer(Layer("ad", "Active Directory", "exposure", ("находка", "находки", "находок"),
        lambda db: LayerResult(cells={}, available=False, note="нет снапшотов")))


def test_matrix_composes_layers_and_gaps(auth_client: TestClient, clean_layers) -> None:
    _fake_layers(clean_layers)
    body = auth_client.get("/api/attack/matrix").json()
    layers = {layer["id"]: layer for layer in body["layers"]}
    assert layers["vm"]["available"] and layers["vm"]["note"] == "риск ≥ 40" and layers["vm"]["unit"] == ["хост", "хоста", "хостов"]
    assert layers["ad"]["available"] is False
    cells = {c["technique_id"]: c for t in body["tactics"] for c in t["techniques"]}
    assert cells["T1190"]["layers"]["vm"]["count"] == 12 and cells["T1190"]["layers"]["siem"] is None
    assert cells["T1190"]["gap"] is True
    assert cells["T1003"]["layers"]["siem"]["status"] == "confirmed" and cells["T1003"]["gap"] is False
    initial = next(t for t in body["tactics"] if t["shortname"] == "initial-access")
    assert initial["gaps"] >= 1 and initial["covered"] == 0


def test_technique_detail_has_layer_items(auth_client: TestClient, clean_layers) -> None:
    _fake_layers(clean_layers)
    body = auth_client.get("/api/attack/technique/T1003").json()
    assert body["layers"]["siem"]["items"][0]["href"] == "/siem/x"
    assert body["layers"]["vm"]["count"] == 2 and body["layers"]["ad"] is None
    sub = {s["technique_id"]: s for s in body["subtechniques"]}
    assert sub["T1003.001"]["covered"] is True
    assert auth_client.get("/api/attack/technique/T9999").status_code == 404


def test_chains_use_coverage_and_exposure(auth_client: TestClient, clean_layers) -> None:
    _fake_layers(clean_layers)
    body = auth_client.get("/api/attack/chains?limit=60").json()
    assert "items" in body and "exposed" in body and "T1190" in body["exposed"]

    # Разметка слоя покрытия должна доезжать до шагов цепочки, а не только
    # до списка `exposed`: `T1003.001` закрыт фейковым слоем SIEM, значит
    # ни на одном шаге он не может числиться пробелом — а T1190 закрыт
    # ничем и обязан числиться.
    steps = [step for chain in body["items"] for step in chain["steps"]]
    gaps = {t["technique_id"] for step in steps for t in step["uncovered"]}
    assert "T1003.001" not in gaps
    assert "T1190" in gaps
    assert any(
        step["covered"] > 0
        for step in steps
    ), "шаг с закрытой техникой обязан быть — иначе покрытие не доехало"
