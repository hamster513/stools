"""Онлайн-подключения к KSC: проверка и сбор выгрузки."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from api.hosts import (
    LOGIN_REJECTED,
    NO_LINK,
    NO_RIGHTS,
    TLS_FAILED,
    is_tls_error,
    server_error,
    url_host,
)
from api.jobs import JobHandle
from api.modules.ksc.core.client import KscClient, KscError
from api.modules.ksc.core.collector import collect
from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.models import KscConnection, KscSnapshot
from api.modules.ksc.services.snapshots import import_export


def _client(conn: KscConnection) -> KscClient:
    return KscClient(f"https://{url_host(conn.host)}:{conn.port}", conn.username, conn.password, verify_tls=conn.verify_tls, internal=conn.internal, domain=conn.domain)


def public_error(exc: BaseException) -> str:
    """Класс причины отказа для ответа проверки: без адреса и текста KSC."""
    if not isinstance(exc, KscError):
        return server_error()
    if exc.kind == "link":
        return TLS_FAILED if is_tls_error(exc) else NO_LINK
    if exc.kind == "auth":
        return LOGIN_REJECTED
    if exc.kind == "forbidden":
        return NO_RIGHTS
    return server_error(exc.code if exc.kind == "http" else None)


def test_connection(conn: KscConnection) -> dict[str, Any]:
    with _client(conn) as c:
        static = c.call("HostGroup.GetStaticInfo", {"pValues": ["KLADMSRV_SERVER_HOSTNAME", "KLADMSRV_PRODUCT_FULL_VERSION"]}).get("PxgRetVal") or {}
    name = str(static.get("KLADMSRV_SERVER_HOSTNAME") or conn.host)
    version = str(static.get("KLADMSRV_PRODUCT_FULL_VERSION") or "")
    return {"ok": True, "message": f"подключились, сервер {name} {version}".strip(), "server_name": name, "version": version}


def collect_snapshot(db: Session, handle: JobHandle, conn: KscConnection, cfg: KscConfig, data_dir: Path) -> KscSnapshot:
    handle.stage("connecting", message=conn.host)
    with _client(conn) as c:
        handle.stage("collecting", message="группы, хосты, продукты, политики, задачи")
        raw = collect(c, skip_policy_contents=conn.skip_policy_contents, max_policies=cfg.policy_contents_max_policies,
                      progress=lambda done, total: handle.tick(done, total=total, message=f"продукты хостов {done} из {total}"), username=conn.username, host=conn.host)
    data = json.dumps(raw, ensure_ascii=False).encode("utf-8")
    snap = import_export(db, handle, data, "online", f"{conn.host} ({conn.title or conn.username})", cfg, data_dir)
    conn.server_id = snap.server_id
    db.commit()
    return snap
