"""Синтетика трёх источников с заведомыми расхождениями (план, задача 2).

- `msk1` — VM `192.168.6.53` и KSC `192.168.2.23`, оба сегодня (KSC свежее на час);
- `ws01` — только AD (нет агента антивируса);
- `srv01` — во всех трёх источниках с одним адресом;
- `old01` — только AD, последний вход 120 дней назад.

VM пишется прямыми вставками (`vm_host` + `vm_import`), KSC и AD — через `import_export` модулей.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import datetime_to_filetime
from api.modules.ad.models import AdSnapshot
from api.modules.ad.services.snapshots import import_export as import_ad
from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.models import KscSnapshot
from api.modules.ksc.services.snapshots import import_export as import_ksc
from api.modules.vm.models import VmHost, VmImport
from tests.ad.synthetic import DN, rid
from tests.ad.synthetic import build_export as build_ad_export
from tests.ksc.synthetic import _host
from tests.ksc.synthetic import build_export as build_ksc_export


def ip_long(ip: str) -> int:
    a, b, c, d = (int(x) for x in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def load_vm(db: Session, hosts: list[tuple[str, str, str]], finished_at: dt.datetime) -> None:
    """hosts — (hostname, ip, os). Время импорта VM — единственное время наблюдения у VM."""
    for hostname, ip, os_name in hosts:
        db.add(VmHost(hostname=hostname, ip=ip, os_name=os_name, zone="Office", groups="Windows"))
    db.add(VmImport(finished_at=finished_at, source="file", filename="vm.csv", hosts=len(hosts)))
    db.commit()


def ksc_export(hosts: list[tuple[str, str]], collected_at: dt.datetime) -> dict[str, Any]:
    """Выгрузка KSC с хостами (имя, IP) вместо стандартного набора синтетики."""
    raw = build_ksc_export(now=collected_at)
    ok = 1 | 4 | 8 | 16
    raw["hosts"] = [
        _host(i, name, 3, ok, 7, now=collected_at, KLHST_WKS_IP_LONG={"type": "long", "value": ip_long(ip)})
        for i, (name, ip) in enumerate(hosts, start=1)
    ]
    keep = {h["KLHST_WKS_HOSTNAME"] for h in raw["hosts"]}
    raw["host_products"] = {k: v for k, v in raw["host_products"].items() if k in keep}
    raw["host_components"] = {k: v for k, v in raw["host_components"].items() if k in keep}
    raw["update_agents"] = []
    return raw


def load_ksc(db: Session, data_dir: Path, hosts: list[tuple[str, str]], collected_at: dt.datetime) -> KscSnapshot:
    path = data_dir / "ksc-upload.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(ksc_export(hosts, collected_at)), encoding="utf-8")
    return import_ksc(db, None, path, "file", "ksc.json", KscConfig(), data_dir)


def computer(sam: str, n: int, *, last_logon: dt.datetime, os_name: str = "Windows 11 Pro") -> dict[str, Any]:
    name = sam.rstrip("$")
    return {
        "dn": f"CN={name},CN=Computers,{DN}", "class": "computer", "sid": rid(n), "sam": sam, "name": name,
        "uac": 4096, "lastLogonTimestamp": datetime_to_filetime(last_logon), "pwdLastSet": datetime_to_filetime(last_logon),
        "dNSHostName": f"{name.lower()}.corp.local", "operatingSystem": os_name, "operatingSystemVersion": "10.0 (22631)",
    }


def ad_export(computers: list[dict[str, Any]], collected_at: dt.datetime) -> dict[str, Any]:
    raw = build_ad_export(now=collected_at)
    raw["objects"] = [o for o in raw["objects"] if o["class"] != "computer"] + computers
    return raw


def load_ad(db: Session, data_dir: Path, computers: list[dict[str, Any]], collected_at: dt.datetime) -> AdSnapshot:
    path = data_dir / "ad-upload.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(ad_export(computers, collected_at)), encoding="utf-8")
    return import_ad(db, None, path, "file", "ad.json", AdConfig(), data_dir)


def load_all(db: Session, data_dir: Path, now: dt.datetime) -> None:
    load_vm(db, [("msk1", "192.168.6.53", "Windows 10"), ("srv01.corp.local", "10.10.0.11", "Windows Server 2022")], now - dt.timedelta(hours=2))
    load_ksc(db, data_dir, [("MSK1", "192.168.2.23"), ("SRV01", "10.10.0.11")], now - dt.timedelta(hours=1))
    load_ad(db, data_dir, [
        computer("WS01$", 1201, last_logon=now - dt.timedelta(days=3)),
        computer("SRV01$", 1202, last_logon=now - dt.timedelta(days=1), os_name="Windows Server 2022 Standard"),
        computer("OLD01$", 1203, last_logon=now - dt.timedelta(days=120)),
    ], now - dt.timedelta(hours=3))
