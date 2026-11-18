#!/bin/sh
# Read one host inventory using the existing STools connection; save structure only.
# Usage: sh ops/diagnose_ksc_inventory.sh SNAPSHOT_ID HOST [CONNECTION_ID] [API_CONTAINER]
set -eu
if [ "$#" -lt 2 ] || [ "$#" -gt 4 ]; then
  echo "Usage: $0 SNAPSHOT_ID HOST [CONNECTION_ID] [API_CONTAINER]" >&2
  exit 2
fi
umask 077
report="ksc-inventory-$(date -u +%Y%m%dT%H%M%SZ)-$$.json"
set -C
docker exec -i "${4:-stools-api-1}" python - "$1" "$2" "${3:-}" > "$report" <<'KSC_PROBE_PY'
import json
import logging
import sys

KEYS = ("KLEVP_EA_PARAM_1", "GNRL_EA_PARAM_1")


def unwrap_params(value):
    while isinstance(value, dict) and set(value) == {"type", "value"} and value["type"] == "params":
        value = value["value"]
    return value


def response_shape(response):
    result = {"response_type": type(response).__name__}
    result["return_present"] = isinstance(response, dict) and "PxgRetVal" in response
    value = unwrap_params(response.get("PxgRetVal")) if isinstance(response, dict) else None
    result["return_type"] = type(value).__name__
    fields = {}
    if isinstance(value, dict):
        result["other_field_count"] = len(set(value) - set(KEYS))
        for key in KEYS:
            if key not in value:
                continue
            items = value[key]
            field = {"type": type(items).__name__}
            if isinstance(items, list):
                records = [unwrap_params(item) for item in items]
                field["count"] = len(records)
                field["invalid_record_count"] = sum(not isinstance(item, dict) for item in records)
                for name, label in (("DisplayName", "named"), ("DisplayVersion", "versioned")):
                    field[label + "_record_count"] = sum(
                        bool(item.get(name)) for item in records if isinstance(item, dict)
                    )
            fields[key] = field
    result["fields"] = fields
    return result


def probe(snapshot_id, host_query, connection_id):
    from sqlalchemy import func, or_, select, text
    from api.db.base import get_sessionmaker
    from api.modules.ksc.models import KscConnection, KscHost, KscSnapshot
    from api.modules.ksc.services.connections import _client
    from api.modules.ksc.core.software import inventory_items

    with get_sessionmaker()() as db:
        db.execute(text("SET TRANSACTION READ ONLY"))
        snapshot = db.scalar(select(KscSnapshot).where(KscSnapshot.id == snapshot_id).limit(1))
        if snapshot is None:
            return {"status": "snapshot_not_found"}
        hosts = list(db.scalars(select(KscHost).where(
            KscHost.snapshot_id == snapshot_id,
            or_(KscHost.host_id == host_query, func.lower(KscHost.name) == host_query.lower(),
                func.lower(KscHost.fqdn) == host_query.lower()),
        ).limit(2)))
        if len(hosts) != 1:
            return {"status": "host_not_found_or_ambiguous"}
        query = select(KscConnection).where(KscConnection.server_id == snapshot.server_id)
        if connection_id is not None:
            query = query.where(KscConnection.id == connection_id)
        connections = list(db.scalars(query.order_by(KscConnection.id).limit(2)))
        if len(connections) != 1:
            return {"status": "connection_not_found_or_ambiguous", "candidate_connection_ids": [c.id for c in connections]}
        with _client(connections[0]) as client:
            response = client.call("InventoryApi.GetHostInvProducts", {"szwHostId": hosts[0].host_id, "pParams": {}})
        result = response_shape(response)
        try:
            inventory_items(response.get("PxgRetVal") if isinstance(response, dict) else None)
        except (ValueError, TypeError):
            result["installed_parser_accepts"] = False
        else:
            result["installed_parser_accepts"] = True
        result["status"] = "ok"
        return result


def main():
    logging.disable(logging.CRITICAL)
    try:
        result = probe(int(sys.argv[1]), sys.argv[2], int(sys.argv[3]) if sys.argv[3] else None)
    except Exception as exc:
        # Exception messages can contain connection addresses or response values.
        result = {"status": "probe_failed", "error_type": type(exc).__name__}
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
KSC_PROBE_PY
printf 'Report: %s\n' "$report"
