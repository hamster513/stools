"""Docker inventory CSV: rows may repeat for tags and published ports."""
from __future__ import annotations

import csv
import hashlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from api.modules.vm.core.sources import split_host

ENGINE = "Host.Softs<DockerEngine>"
IMAGE_FIELDS = ("Registry", "Repo", "Tag", "ID", "OsFamily", "Architecture")
COMMON = ("@Host", "Host.OsName", "Host.@CreationTime", "Host.@UpdateTime")


class DockerFormatError(ValueError):
    pass


def build_docker_pdql(kind: str) -> str:
    """Inventory is independent of CVEs: do not apply the vulnerable-host filter."""
    if kind not in {"images", "containers"}:
        raise ValueError(kind)
    prefix = ENGINE + (".Images." if kind == "images" else ".Containers.Image.")
    columns = [*COMMON, *(prefix + field for field in IMAGE_FIELDS)]
    if kind == "containers":
        columns += [ENGINE + ".Containers." + field for field in (
            "@Id", "ID", "Name", "Status", "Created", "Started",
            "Ports.ContainerPort", "Ports.HostPorts", "Ports.Protocol",
        )]
    return f"select({', '.join(columns)})"


def _rows(path: Path, kind: str) -> Iterator[dict[str, str]]:
    prefix = ENGINE + (".Images." if kind == "images" else ".Containers.Image.")
    required = {"@Host", *(prefix + field for field in IMAGE_FIELDS)}
    if kind == "containers":
        required |= {ENGINE + ".Containers." + field for field in ("Name", "Status", "@Id")}
    with path.open(encoding="utf-8-sig", newline="") as fh:
        first = fh.readline()
        delimiter = ";" if first.count(";") >= first.count(",") else ","
        fh.seek(0)
        reader = csv.DictReader(fh, delimiter=delimiter, strict=True)
        try:
            if not required.issubset(reader.fieldnames or []):
                raise DockerFormatError(f"{kind}: отсутствуют обязательные колонки Docker")
            for row in reader:
                if None in row or any(value is None for value in row.values()):
                    raise DockerFormatError(f"{kind}: повреждённая строка CSV")
                yield {key: value.strip() for key, value in row.items()}
        except csv.Error as exc:
            raise DockerFormatError(f"{kind}: повреждённый CSV") from exc


def state(containers: list[dict[str, Any]]) -> str:
    if not containers:
        return "unused"
    values = {c["status"] for c in containers}
    if "running" in values:
        return "running"
    if values <= {"exited", "dead", "created"}:
        return "stopped"
    return "unknown"


def parse_inventory(images: Path, containers: Path) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for kind, path in (("images", images), ("containers", containers)):
        prefix = ENGINE + (".Images." if kind == "images" else ".Containers.Image.")
        cp = ENGINE + ".Containers."
        for row in _rows(path, kind):
            hostname, ip = split_host(row["@Host"])
            image_id = row[prefix + "ID"]
            name = row.get(cp + "Name", "")
            container_id = row.get(cp + "ID") or row.get(cp + "@Id") or name
            if not hostname:
                if image_id or container_id:
                    raise DockerFormatError(f"{kind}: образ или контейнер без хоста")
                continue
            if kind == "containers" and not container_id:
                continue  # outer-join row for a host with no containers
            reference = {field.lower(): row[prefix + field] for field in ("Registry", "Repo", "Tag")}
            if kind == "images" and not image_id and not any(reference.values()):
                continue  # host without images
            # Missing IDs are not evidence of identity, even if repo/tag match.
            identity = ["id", image_id] if image_id else ["unknown", hostname, ip, kind, container_id, *reference.values()]
            key = hashlib.sha256(repr(identity).encode()).hexdigest()
            record = records.setdefault(key, {
                "key": key, "image_id": image_id, "references": [], "platforms": [], "hosts": {},
            })
            if any(reference.values()) and reference not in record["references"]:
                record["references"].append(reference)
            platform = "/".join(filter(None, (row[prefix + "OsFamily"], row[prefix + "Architecture"])))
            if platform and platform not in record["platforms"]:
                record["platforms"].append(platform)
            host = record["hosts"].setdefault((hostname, ip), {
                "hostname": hostname, "ip": ip, "os_name": row.get("Host.OsName", ""),
                "host_created_at": row.get("Host.@CreationTime", ""),
                "host_updated_at": row.get("Host.@UpdateTime", ""),
                "inventory_present": False, "containers": {},
            })
            if kind == "images":
                host["inventory_present"] = True
                continue
            container = host["containers"].setdefault(container_id, {
                "id": container_id, "name": name, "status": row[cp + "Status"],
                "created_at": row.get(cp + "Created", ""), "started_at": row.get(cp + "Started", ""),
                "ports": [],
            })
            # A conflicting snapshot must not silently claim the container stopped.
            if container["status"] != row[cp + "Status"]:
                container["status"] = "unknown"
            port = {"container_port": row.get(cp + "Ports.ContainerPort", ""),
                    "host_ports": row.get(cp + "Ports.HostPorts", ""), "protocol": row.get(cp + "Ports.Protocol", "")}
            if any(port.values()) and port not in container["ports"]:
                container["ports"].append(port)
    unresolved_hosts = {
        host_key for record in records.values() if not record["image_id"]
        for host_key, host in record["hosts"].items() if host["containers"]
    }
    result = []
    for record in records.values():
        hosts = list(record["hosts"].values())
        for host in hosts:
            host["containers"] = list(host["containers"].values())
            host["status"] = state(host["containers"])
            if host["status"] == "unused" and (host["hostname"], host["ip"]) in unresolved_hosts:
                host["status"] = "unknown"
        record["hosts"] = hosts
        record["status"] = state([c for host in hosts for c in host["containers"]])
        if record["status"] != "running" and any(h["status"] == "unknown" for h in hosts):
            record["status"] = "unknown"
        result.append(record)
    return result
