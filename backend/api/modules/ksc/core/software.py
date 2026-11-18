"""General installed software from KSC InventoryApi, separate from protection products."""
from __future__ import annotations

import datetime as dt
from typing import Any

from api.modules.ksc.core.export import strip_params, unwrap


def _params_value(value: Any) -> Any:
    while isinstance(value, dict) and set(value) == {"type", "value"} and value["type"] == "params":
        value = value["value"]
    return value


def inventory_items(value: Any) -> list[dict[str, Any]]:
    """Validate GetHostInvProducts without discarding the original product fields/wrappers."""
    value = _params_value(value)
    keys = ("KLEVP_EA_PARAM_1", "GNRL_EA_PARAM_1")
    present = [key for key in keys if isinstance(value, dict) and key in value]
    if not present:
        raise ValueError("InventoryApi.GetHostInvProducts: отсутствует список ПО (KLEVP_EA_PARAM_1 / GNRL_EA_PARAM_1)")
    for key in present:
        items = value[key]
        if not isinstance(items, list) or any(not isinstance(_params_value(item), dict) for item in items):
            raise ValueError(f"InventoryApi.GetHostInvProducts: некорректный {key}")
    if len(present) == 2 and value[present[0]] != value[present[1]]:
        raise ValueError("InventoryApi.GetHostInvProducts: противоречивые списки ПО")
    return value[present[0]]


def _field(item: dict[str, Any], name: str) -> str:
    value = unwrap(item.get(name))
    return str(value) if isinstance(value, (str, int, float)) and not isinstance(value, bool) else ""


def normalize_inventory(entry: Any) -> tuple[str, list[dict[str, Any]]]:
    """Missing, failed and successfully empty inventories remain distinct."""
    if entry is None:
        return "not_collected", []
    if not isinstance(entry, dict) or entry.get("status") != "complete":
        return "error", []
    try:
        items = inventory_items({"KLEVP_EA_PARAM_1": entry.get("items")})
    except ValueError:
        return "error", []
    rows = []
    for raw in items:
        item = strip_params(raw)

        installed_on = None
        date = _field(item, "InstallDate")
        if len(date) == 8 and date.isascii() and date.isdigit():
            try:
                installed_on = dt.date.fromisoformat(f"{date[:4]}-{date[4:6]}-{date[6:]}").isoformat()
            except ValueError:
                pass
        rows.append({"product_id": _field(item, "ProductID"), "name": _field(item, "DisplayName"), "version": _field(item, "DisplayVersion"),
                     "publisher": _field(item, "Publisher"), "installed_on": installed_on, "install_dir": _field(item, "InstallDir"), "raw": raw})
    return "complete", rows
