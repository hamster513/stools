"""General software inventory is distinct from protective KSC products."""
from __future__ import annotations

import json
from typing import Any

import pytest

from api.modules.ksc.core import client as client_mod
from api.modules.ksc.core.client import KscClient
from api.modules.ksc.core.collector import collect
from api.modules.ksc.core.export import KscExport, load_export, strip_params
from tests.ksc.fake_ksc import PASSWORD, USER, FakeKsc, http_factory_for

PRODUCT = {"ProductID": "app-1", "DisplayName": "Editor", "DisplayVersion": "2.3",
           "Publisher": "Example", "InstallDate": "20261030", "InstallDir": "C:\\Editor"}


def collected(monkeypatch: Any, responses: dict[str, Any], *, denied: bool = False) -> dict[str, Any]:
    fake = FakeKsc()
    original = fake._handle

    def handle(method: str, body: dict[str, Any], headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
        if method == "InventoryApi.GetHostInvProducts":
            assert body == {"szwHostId": body["szwHostId"], "pParams": {}}
            if denied:
                return 200, {"PxgError": {"code": 1, "message": "unsupported method"}}
            return 200, responses.get(body["szwHostId"], {"PxgRetVal": {"KLEVP_EA_PARAM_1": []}})
        return original(method, body, headers)

    monkeypatch.setattr(fake, "_handle", handle)
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(fake))
    with KscClient("https://ksc01:13299", USER, PASSWORD) as client:
        return collect(client, skip_products=True)


def test_inventory_collected_for_all_hosts_even_when_products_skipped(monkeypatch: Any) -> None:
    item = {"type": "params", "value": {**PRODUCT, "ProductID": {"type": "wstring", "value": "app-1"}}}
    raw = collected(monkeypatch, {"h-ws01": {"PxgRetVal": {"type": "params", "value": {"KLEVP_EA_PARAM_1": [item]}}}})
    inventory = raw["host_inventory"]
    assert set(inventory) == {h["KLHST_WKS_HOSTNAME"] for h in strip_params(raw["hosts"])}
    assert inventory["h-ws01"] == {"status": "complete", "items": [item]}
    assert inventory["h-ws02"] == {"status": "complete", "items": []}
    assert not raw["host_products"]
    assert load_export(json.dumps(raw).encode()).host_inventory == strip_params(inventory)


@pytest.mark.parametrize("response", [{}, {"PxgRetVal": {}}, {"PxgRetVal": {"KLEVP_EA_PARAM_1": None}},
                                     {"PxgRetVal": {"KLEVP_EA_PARAM_1": {}}}, {"PxgRetVal": {"KLEVP_EA_PARAM_1": [42]}},
                                     {"PxgRetVal": {"KLEVP_EA_PARAM_1": [{"type": "params", "value": None}]}}])
def test_malformed_inventory_is_error_and_other_hosts_continue(monkeypatch: Any, response: Any) -> None:
    raw = collected(monkeypatch, {"h-ws01": response})
    assert raw["host_inventory"]["h-ws01"]["status"] == "error"
    assert raw["host_inventory"]["h-ws01"]["error"]
    assert raw["host_inventory"]["h-ws02"] == {"status": "complete", "items": []}
    assert sum(w.startswith("host_inventory:") for w in raw["server"]["warnings"]) == 1


def test_unsupported_inventory_api_is_nonfatal(monkeypatch: Any) -> None:
    raw = collected(monkeypatch, {}, denied=True)
    assert raw["host_inventory"]
    assert all(e["status"] == "error" and e["items"] == [] for e in raw["host_inventory"].values())
    assert any(w.startswith("host_inventory:") for w in raw["server"]["warnings"])


def test_old_export_has_no_inventory() -> None:
    assert "host_inventory" in KscExport.model_fields
    raw = {"format": "stools-ksc/1", "server": {"name": "old", "collected_at": "2026-10-30T00:00:00Z"}}
    assert load_export(json.dumps(raw).encode()).host_inventory == {}


def test_normalize_inventory_preserves_raw_and_parses_fields() -> None:
    from api.modules.ksc.core.software import normalize_inventory

    item = {"type": "params", "value": {**PRODUCT, "DisplayVersion": {"type": "wstring", "value": "2.3"}}}
    assert normalize_inventory({"status": "complete", "items": [item]}) == ("complete", [{
        "product_id": "app-1", "name": "Editor", "version": "2.3", "publisher": "Example",
        "installed_on": "2026-10-30", "install_dir": "C:\\Editor", "raw": item,
    }])
    assert normalize_inventory(None) == ("not_collected", [])
    assert normalize_inventory({"status": "error", "items": [], "error": "denied"}) == ("error", [])
    assert normalize_inventory({"status": "complete", "items": []}) == ("complete", [])
    assert normalize_inventory({"status": "complete"}) == ("error", [])
    assert normalize_inventory({"status": "complete", "items": [42]}) == ("error", [])
    assert normalize_inventory({"status": "complete", "items": [{**PRODUCT, "InstallDate": "20260231"}]})[1][0]["installed_on"] is None
