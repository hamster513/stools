"""Selected native snapshots and independent inventory state for normal-module imports."""
from __future__ import annotations

import copy
import datetime as dt
import gzip
import json
import re
from pathlib import Path

from sqlalchemy import select

from api.modules.ad import models as ad
from api.modules.assets import models as assets
from api.modules.ksc import models as ksc

from . import exporter as legacy
from .module_schema import MODULE_EXTRA_FIELDS, PIN_FIELDS
from .schema import BundleError

FORMAT = "stools-diagnostic/2"
MAX_SOURCE_BYTES = 200 * 1024 * 1024
WARNINGS = [
    "Срез содержит выбранные объекты и необходимые связи. Состав групп и общая статистика относятся только к срезу.",
    "Текущий снимок AD и сохранённые связи Assets передаются независимо: их расхождения не исправляются при импорте.",
    "Сохранены обезличенные исходные снимки, содержимое политик AD/KSC, профили, теги и условия firewall для обычных модулей и повторного анализа.",
    "Имена, идентификаторы и адреса заменены согласованно; даты сдвинуты на один интервал. Структура связей и параметры политик остаются видимыми.",
    "Пароли, ключи, подключения, задания синхронизации, произвольные заметки и несвязанные объекты не переносятся.",
    "Импорт добавляет объекты и снимки в обычные AD, Assets и AV/KSC. Неполнота исходного сбора сохраняется; отсутствующие данные не восстанавливаются.",
]
_UUID = re.compile(r"\{?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?")
_META_IDS = {"domain_id": "ad_domain", "server_id": "ksc_server"}
_META_BOOL = {"enabled", "pwd_never_expires", "laps", "dc", "agent_alive", "users_collected"}
_META_INT = {"uac", "admin_count"}
_META_IDENTITY = {"dn", "group_path"}
_META_FIELDS = set(_META_IDS) | _META_BOOL | _META_INT | _META_IDENTITY | {"last_logon", "tags", "protection"}


def _read_native(data_dir, module, snapshot_id):
    try:
        with gzip.open(Path(data_dir) / module / f"{snapshot_id}.json.gz", "rb") as stream:
            data = stream.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES:
            raise BundleError("Diagnostic source size limit exceeded.")
        raw = json.loads(data)
        if not isinstance(raw, dict):
            raise TypeError
        return raw
    except BundleError:
        raise
    except (OSError, ValueError, TypeError, RecursionError, EOFError):
        name = "directory" if module == "ad" else "KSC"
        raise BundleError(f"Latest {name} export is unavailable or unsupported.") from None


def _ad_sources(selection, data_dir):
    identities = {}
    for model, field in [(assets.AssetUserObservation, "data"), (assets.AssetObservation, "extra")]:
        for row in selection.values(model):
            info = getattr(row, field)
            domain_id = info.get("domain_id") if isinstance(info, dict) else None
            if row.source == "ad" and type(domain_id) is int:
                identities.setdefault(domain_id, set()).add(row.source_key)
    selection.add(ad.AdDomain, ad.AdDomain.id.in_(identities))
    result = []
    for domain_id, keys in identities.items():
        snapshot = selection.db.scalar(select(ad.AdSnapshot).where(
            ad.AdSnapshot.domain_id == domain_id,
        ).order_by(ad.AdSnapshot.collected_at.desc(), ad.AdSnapshot.id.desc()).limit(1))
        if snapshot is None:
            raise BundleError("Latest directory export is unavailable or unsupported.")
        selection.add(ad.AdSnapshot, ad.AdSnapshot.id == snapshot.id)
        result.append((snapshot, keys, _read_native(data_dir, "ad", snapshot.id)))
    return result


def _ksc_sources(selection, data_dir):
    identities = {}
    for observation in selection.values(assets.AssetObservation):
        if observation.source != "ksc":
            continue
        server, separator, host = observation.source_key.partition(":")
        if not separator or not server.isdigit() or not host:
            raise BundleError("Unsupported diagnostic relationship.")
        identities.setdefault(int(server), set()).add(host)
    snapshots = {row.server_id: row for row in selection.values(ksc.KscSnapshot)}
    result = []
    for server_id, keys in identities.items():
        if server_id not in selection.ids(ksc.KscServer) or server_id not in snapshots:
            raise BundleError("Latest KSC export is unavailable or unsupported.")
        snapshot = snapshots[server_id]
        result.append((snapshot, keys, _read_native(data_dir, "ksc", snapshot.id)))
    return result


def _metadata(anon, value, selection):
    if not isinstance(value, dict):
        return {}
    result = {}
    for key in _META_FIELDS & value.keys():
        item = value[key]
        if key in _META_IDS:
            table = _META_IDS[key]
            if type(item) is int and item in selection.rows[table]:
                result[key] = anon.identifier(table, item)
        elif key in _META_BOOL and type(item) is bool or key in _META_INT and (item is None or type(item) is int):
            result[key] = item
        elif key == "last_logon" and (item is None or isinstance(item, str)):
            result[key] = anon.date(item) if item else None
        elif key == "dn" and isinstance(item, str):
            result[key] = anon.dn(item)
        elif key == "group_path" and isinstance(item, str):
            result[key] = anon.group_path(item)
        elif key == "tags" and isinstance(item, list) and all(isinstance(tag, str) for tag in item):
            result[key] = [anon.tag(tag) for tag in item]
        elif key == "protection" and item in {"none", "on", "off"}:
            result[key] = item
    return result


def _cached_row(anon, model, row, selection):
    result = legacy._row(anon, model, row, selection)
    for field in {"domain", "member_domain"} & result.keys():
        result[field] = anon.directory_domain(getattr(row, field))
    if model is assets.AssetUser:
        if "\\" in row.sam:
            result["sam"] = anon.principal(row.sam, directory=True)
        if not row.local and "\\" in row.name_key:
            domain, _, account = row.name_key.rpartition("\\")
            result["name_key"] = anon.directory_domain(domain) + "\\" + anon.name(account)
    if model in {assets.Asset, assets.AssetUser}:
        result["tags"] = [anon.tag(tag) for tag in row.tags]
    if model is assets.Asset:
        if row.pinned.keys() - PIN_FIELDS or any(type(flag) is not bool for flag in row.pinned.values()):
            raise BundleError("Unsupported diagnostic pinned field.")
        result["pinned"] = dict(row.pinned)
    if model is assets.AssetGroupGpo:
        names = {name.lower().rstrip("$") for host in selection.values(assets.Asset) for name in (host.name, host.fqdn) if name}
        result["hosts"] = [anon.fqdn(host.rstrip("$")) for host in row.hosts if host.lower().rstrip("$") in names]
        result["hosts_total"] = len(result["hosts"])
    if model in {assets.AssetObservation, assets.AssetUserObservation}:
        field = "extra" if model is assets.AssetObservation else "data"
        result[field] = _metadata(anon, getattr(row, field), selection)
        if row.source == "ksc":
            server, separator, identity = row.source_key.partition(":")
            if not separator or not server.isdigit() or int(server) not in selection.ids(ksc.KscServer):
                raise BundleError("Unsupported diagnostic relationship.")
            if model is assets.AssetObservation:
                identity = anon.token(identity)
            else:
                user = selection.rows["asset_user"][row.user_id]
                if identity.upper().startswith("S-1-"):
                    identity = anon.sid(identity)
                elif user.local:
                    host, separator, account = identity.rpartition("\\")
                    if not separator:
                        raise BundleError("Unsupported diagnostic relationship.")
                    identity = anon.token(host) + "\\" + anon.name(account)
                else:
                    identity = anon.principal(identity, directory=True)
            result["source_key"] = f'{anon.identifier("ksc_server", int(server))}:{identity}'
    if model is assets.AssetUser and row.local and row.name_key.startswith("local:"):
        match = re.fullmatch(r"local:(\d+)\\(.+)", row.name_key)
        if not match or int(match[1]) not in selection.ids(assets.Asset):
            raise BundleError("Unsupported diagnostic relationship.")
        result["name_key"] = f'local:{anon.identifier("asset", int(match[1]))}\\{anon.name(match[2])}'
    return result


def _summary_counts(tables, ad_exports, ksc_exports):
    counts = {name: len(rows) for name, rows in tables.items()}
    if ad_exports:
        counts["ad_native_objects"] = sum(len(item["export"]["objects"]) for item in ad_exports)
    if ksc_exports:
        for key in ("hosts", "groups", "policies"):
            counts[f"ksc_native_{key}"] = sum(len(item["export"].get(key, [])) for item in ksc_exports)
        counts["ksc_native_profiles"] = sum(len(entry.get("profiles", [])) for item in ksc_exports
                                           for entry in (item["export"].get("policy_profiles") or {}).values())
    return counts


def build_module_bundle(db, data_dir, kind: str, entity_id: int) -> dict:
    from .ad_payload import build_ad_payload
    from .ksc_payload import build_ksc_payload, prepare_ksc_addresses
    from .module_privacy import ModuleAnonymizer

    if kind not in {"user", "host"} or type(entity_id) is not int or entity_id <= 0:
        raise BundleError("Invalid diagnostic selection.")
    with db.no_autoflush:
        selection = legacy.Selection(db)
        legacy._assets(selection, kind, entity_id)
        directory_sources = _ad_sources(selection, data_dir)
        legacy._ksc(selection)
        ksc_sources = _ksc_sources(selection, data_dir)
        anon = ModuleAnonymizer()
        for table, rows in selection.rows.items():
            for row_id in sorted(rows):
                anon.identifier(table, row_id)
        for domain in selection.values(ad.AdDomain):
            anon.register_directory_domain(domain.dns_root, domain.netbios)
        for _, keys, raw in ksc_sources:
            prepare_ksc_addresses(raw, keys, anon)
        ad_exports = [{"snapshot_id": anon.identifier("ad_snapshot", snap.id),
                       "export": build_ad_payload(raw, keys, anon)} for snap, keys, raw in directory_sources]
        ksc_exports = [{"snapshot_id": anon.identifier("ksc_snapshot", snap.id),
                        "export": build_ksc_payload(raw, keys, anon, snap.id)} for snap, keys, raw in ksc_sources]
        tables = {table: [_cached_row(anon, legacy.TABLE_MODELS[table], row, selection) for row in rows.values()]
                  for table, rows in selection.rows.items() if rows}
        for name, exports, count_field, list_field in [
            ("ad_snapshot", ad_exports, "objects", "objects"),
            ("ksc_snapshot", ksc_exports, "hosts", "hosts"),
        ]:
            counts = {item["snapshot_id"]: len(item["export"].get(list_field, [])) for item in exports}
            for row in tables.get(name, []):
                row[count_field] = counts[row["id"]]
        bundle = {"format": FORMAT, "created_at": dt.datetime.now(dt.UTC).isoformat(),
                  "root": {"kind": kind, "id": anon.identifier("asset_user" if kind == "user" else "asset", entity_id)},
                  "tables": tables, "ad_exports": ad_exports, "ksc_exports": ksc_exports,
                  "report": {"counts": _summary_counts(tables, ad_exports, ksc_exports), "limitations": list(WARNINGS)}}
        return validate_module_bundle(bundle)


def _validate_metadata(value, tables):
    if not isinstance(value, dict) or value.keys() - _META_FIELDS:
        raise BundleError("Invalid diagnostic metadata.")
    for key, item in value.items():
        if key in _META_IDS:
            if type(item) is not int or item not in {row["id"] for row in tables.get(_META_IDS[key], [])}:
                raise BundleError("Invalid diagnostic relationship.")
        elif key in _META_BOOL:
            if type(item) is not bool:
                raise BundleError("Invalid diagnostic metadata.")
        elif key in _META_INT:
            if item is not None and (type(item) is not int or not 0 <= item <= 2**32):
                raise BundleError("Invalid diagnostic metadata.")
        elif key == "last_logon":
            if item is not None:
                legacy._date(item)
        elif key == "protection":
            if item not in {"none", "on", "off"}:
                raise BundleError("Invalid diagnostic metadata.")
        elif key == "tags":
            if not isinstance(item, list) or len(item) > legacy.MAX_RECORDS:
                raise BundleError("Invalid diagnostic metadata.")
            for tag in item:
                legacy._safe_string("name", tag)
        else:
            if not isinstance(item, str):
                raise BundleError("Invalid diagnostic metadata.")
            if key == "group_path":
                for part in item.split("/"):
                    legacy._safe_string("name", part)
            else:
                legacy._safe_string("dn", _UUID.sub("entity-0000000000000000", item))


def _validate_tables(bundle):
    # Reuse the strict v1 table/FK validator; only v2 observation metadata and
    # local inventory keys have a different grammar. Native exports are checked below.
    projected = copy.deepcopy({key: value for key, value in bundle.items() if key != "ksc_exports"})
    projected.update(format="stools-diagnostic/1", ad_exports=[])
    projected["report"] = {"counts": {name: value for name, value in bundle["report"]["counts"].items() if name in legacy.TABLE_MODELS}, "limitations": []}
    for table, rows in projected["tables"].items():
        for row in rows:
            if table in {"asset_observation", "asset_user_observation"} and row.get("source") == "ksc":
                source_key = row.get("source_key")
                if not isinstance(source_key, str):
                    raise BundleError("Invalid diagnostic relationship.")
                server, separator, identity = source_key.partition(":")
                if not separator or not identity or not server.isdigit() or int(server) not in {r["id"] for r in bundle["tables"].get("ksc_server", [])}:
                    raise BundleError("Invalid diagnostic relationship.")
            for field in MODULE_EXTRA_FIELDS.get(table, set()) & row.keys():
                value = row[field]
                if field in {"tags", "hosts"}:
                    if not isinstance(value, list) or len(value) > legacy.MAX_RECORDS:
                        raise BundleError("Invalid diagnostic inventory field.")
                    for item in value:
                        legacy._safe_string("name", item)
                elif field == "pinned":
                    if not isinstance(value, dict) or value.keys() - PIN_FIELDS or any(type(flag) is not bool for flag in value.values()):
                        raise BundleError("Invalid diagnostic pinned field.")
                elif field == "hosts_total" and (type(value) is not int or value != len(row.get("hosts", []))):
                    raise BundleError("Invalid diagnostic host count.")
            for field in MODULE_EXTRA_FIELDS.get(table, set()):
                row.pop(field, None)
            for field in ("data", "extra"):
                if field in row:
                    _validate_metadata(row[field], bundle["tables"])
                    row[field] = {key: value for key, value in row[field].items() if key == "domain_id"}
            for field in ("dn", "gpo_dn", "source_key"):
                if isinstance(row.get(field), str):
                    row[field] = _UUID.sub("entity-0000000000000000", row[field])
            if table == "asset_user" and row.get("local") and str(row.get("name_key", "")).startswith("local:"):
                match = re.fullmatch(r"local:(\d+)\\(entity-[0-9a-f]{16})", row["name_key"])
                if not match or int(match[1]) not in {r["id"] for r in bundle["tables"].get("asset", [])}:
                    raise BundleError("Invalid diagnostic relationship.")
                row["name_key"] = "entity-0000000000000000\\" + match[2]
    legacy.validate_bundle(projected)


def _validate_native(bundle, module, validator):
    snapshots = {row["id"]: row for row in bundle["tables"].get(f"{module}_snapshot", [])}
    table = "ad_domain" if module == "ad" else "ksc_server"
    parents = {row["id"]: row for row in bundle["tables"].get(table, [])}
    seen = set()
    count = 0
    exports = bundle[f"{module}_exports"]
    if not isinstance(exports, list):
        raise BundleError("Invalid diagnostic exports.")
    for item in exports:
        if not isinstance(item, dict) or set(item) != {"snapshot_id", "export"}:
            raise BundleError("Invalid diagnostic export.")
        sid = item["snapshot_id"]
        if type(sid) is not int or sid not in snapshots or sid in seen:
            raise BundleError("Invalid diagnostic relationship.")
        seen.add(sid)
        raw = item["export"]
        validator(raw)
        snapshot = snapshots[sid]
        parent = parents[snapshot["domain_id" if module == "ad" else "server_id"]]
        if module == "ad":
            if any(raw["domain"].get(key, "") != parent[key] for key in ("sid", "dn", "dns_root", "netbios")):
                raise BundleError("Invalid diagnostic relationship.")
            collected_at = raw["collected_at"]
            count += len(raw["objects"]) + sum(len(obj.get("member", [])) for obj in raw["objects"])
        else:
            if raw["server"]["name"] != parent["name"]:
                raise BundleError("Invalid diagnostic relationship.")
            collected_at = raw["server"]["collected_at"]
            count += sum(len(raw.get(key, [])) for key in ("hosts", "groups", "policies"))
        count_field = "objects" if module == "ad" else "hosts"
        if snapshot[count_field] != len(raw[count_field]):
            raise BundleError("Invalid diagnostic snapshot count.")
        native_time = dt.datetime.fromisoformat(collected_at)
        table_time = dt.datetime.fromisoformat(snapshot["collected_at"])
        if native_time.replace(tzinfo=native_time.tzinfo or dt.UTC) != table_time.replace(tzinfo=table_time.tzinfo or dt.UTC):
            raise BundleError("Invalid diagnostic relationship.")
    if seen != snapshots.keys():
        raise BundleError("Missing native diagnostic snapshot.")
    return count


def validate_module_bundle(bundle):
    from .ad_payload import validate_ad_payload
    from .ksc_payload import validate_ksc_payload

    try:
        expected = {"format", "created_at", "root", "tables", "ad_exports", "ksc_exports", "report"}
        if not isinstance(bundle, dict) or set(bundle) != expected or bundle["format"] != FORMAT:
            raise BundleError("Invalid diagnostic module package.")
        report = bundle["report"]
        if (not isinstance(report, dict) or set(report) != {"counts", "limitations"}
                or not isinstance(report["limitations"], list)
                or any(warning not in WARNINGS for warning in report["limitations"])):
            raise BundleError("Invalid diagnostic report.")
        if not isinstance(report["counts"], dict) or any(type(value) is not int for value in report["counts"].values()):
            raise BundleError("Invalid diagnostic report.")
        _validate_tables(bundle)
        count = sum(len(rows) for rows in bundle["tables"].values())
        count += _validate_native(bundle, "ad", validate_ad_payload)
        count += _validate_native(bundle, "ksc", validate_ksc_payload)
        if report["counts"] != _summary_counts(bundle["tables"], bundle["ad_exports"], bundle["ksc_exports"]):
            raise BundleError("Invalid diagnostic report.")
        if count > legacy.MAX_RECORDS:
            raise BundleError("Diagnostic record limit exceeded.")
        if len(json.dumps(bundle, ensure_ascii=False, allow_nan=False).encode()) > legacy.MAX_BYTES:
            raise BundleError("Diagnostic package size limit exceeded.")
        return bundle
    except BundleError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError, RecursionError):
        raise BundleError("Invalid diagnostic module package.") from None
