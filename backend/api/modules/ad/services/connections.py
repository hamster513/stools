"""Онлайн-подключения к доменам: ldap3-соединение и сбор выгрузки."""
from __future__ import annotations

import contextlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from api.crypto import SecretUnreadable, decrypt
from api.export_files import write_json_gz
from api.hosts import LOGIN_REJECTED, NO_LINK, NO_RIGHTS, TLS_FAILED, is_tls_error, server_error
from api.jobs import JobCancelled, JobHandle
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.ldap_collector import LdapCollector, Pacer, ldap3_searcher, smb_access
from api.modules.ad.models import AdConnection, AdSnapshot
from api.modules.ad.services.snapshots import import_export

#: Фабрика соединения подменяется в тестах: сети там нет.
ConnectionFactory = Callable[[AdConnection], Any]


class NoNamingContext(ValueError):
    """Наш собственный текст без адреса и ответа сервера: доходит до человека как есть."""


def ldap3_connection(conn: AdConnection) -> Any:
    import ssl

    from ldap3 import NTLM, SIMPLE, Connection, Server, Tls

    tls = Tls(validate=ssl.CERT_REQUIRED if conn.verify_tls else ssl.CERT_NONE)
    server = Server(conn.host, port=conn.port, use_ssl=conn.use_ssl, get_info="ALL", tls=tls, connect_timeout=15)
    auth = NTLM if "\\" in conn.username else SIMPLE
    c = Connection(server, user=conn.username, password=decrypt(conn.password), authentication=auth, auto_bind=True, receive_timeout=120)
    return c


def root_dse_of(connection: Any, base_dn: str) -> dict[str, Any]:
    info = getattr(connection.server, "info", None)
    other = getattr(info, "other", {}) or {}
    def first(key: str) -> str:
        v = other.get(key)
        return str(v[0]) if isinstance(v, list) and v else str(v or "")
    root = {
        "defaultNamingContext": base_dn or first("defaultNamingContext"),
        "configurationNamingContext": first("configurationNamingContext"),
        "schemaNamingContext": first("schemaNamingContext"),
    }
    if not root["defaultNamingContext"]:
        raise NoNamingContext("rootDSE не отдал defaultNamingContext — укажите base DN")
    return root


def public_error(exc: BaseException) -> str:
    """Класс причины отказа для ответа проверки: без адреса и текста LDAP."""
    from ldap3.core.exceptions import (
        LDAPBindError,
        LDAPCommunicationError,
        LDAPInsufficientAccessRightsResult,
        LDAPInvalidCredentialsResult,
        LDAPStartTLSError,
    )

    if isinstance(exc, (NoNamingContext, SecretUnreadable)):
        return str(exc)
    if isinstance(exc, (LDAPBindError, LDAPInvalidCredentialsResult)):
        return LOGIN_REJECTED
    if isinstance(exc, LDAPInsufficientAccessRightsResult):
        return NO_RIGHTS
    if isinstance(exc, (LDAPCommunicationError, LDAPStartTLSError, OSError)):
        return TLS_FAILED if is_tls_error(exc) else NO_LINK
    return server_error()


def test_connection(conn: AdConnection, factory: ConnectionFactory | None = None) -> dict[str, Any]:
    # Фабрика берётся в момент вызова, а не определения: тесты подменяют её.
    c = (factory or ldap3_connection)(conn)
    try:
        root = root_dse_of(c, conn.base_dn)
        return {"ok": True, "message": f"подключились, домен {root['defaultNamingContext']}", "default_naming_context": root["defaultNamingContext"]}
    finally:
        with contextlib.suppress(Exception):
            c.unbind()


def collect_snapshot(
    db: Session,
    handle: JobHandle,
    conn: AdConnection,
    cfg: AdConfig,
    data_dir: Path,
    factory: ConnectionFactory | None = None,
) -> AdSnapshot:
    handle.stage("connecting", message=conn.host)
    c = (factory or ldap3_connection)(conn)
    try:
        root = root_dse_of(c, conn.base_dn)

        def check_cancel() -> None:
            if handle.cancelled():
                raise JobCancelled()

        # Один дозатор на LDAP и SMB: пауза между любыми двумя запросами к контроллеру.
        pacer = Pacer(conn.pause_ms, check_cancel=check_cancel)
        reader = lister = None
        # Почему SYSVOL не прочитан, уходит в выгрузку: обзор покажет «не проверено», а не «без находок».
        notes: list[str] = []
        if conn.collect_sysvol:
            try:
                reader, lister = smb_access(conn.host, conn.username, decrypt(conn.password), pacer=pacer)
            except Exception as exc:  # noqa: BLE001 — без SYSVOL сбор всё равно полезен
                notes.append(f"SYSVOL недоступен по SMB: {exc.__class__.__name__}")
                handle.tick(0, message=f"SYSVOL недоступен: {exc.__class__.__name__}; User Rights пропущены")
        else:
            notes.append("чтение SYSVOL выключено в подключении")
        handle.stage("collecting", message="объекты и дескрипторы")

        # tick фиксирует сессию задачи: на этой стадии в ней нет ничего, кроме строки задачи.
        searcher = ldap3_searcher(
            c, page_size=conn.page_size, pacer=pacer, on_page=lambda n: handle.tick(n, message=f"прочитано объектов {n}"),
        )
        export = LdapCollector(searcher, root, smb_reader=reader, smb_lister=lister, host=conn.host, account=conn.username, notes=notes).collect()
    finally:
        with contextlib.suppress(Exception):
            c.unbind()
    # Собранное — сразу в gzip-файл потоком и из памяти вон: словарь, его текст и
    # разобранная выгрузка не живут одновременно. Файл станет файлом снапшота.
    path = data_dir / "ad" / f"collect-{handle.id}.json.gz"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        sha256 = write_json_gz(export, path)
        del export
        snap = import_export(db, handle, path, "ldap", f"{conn.host} ({conn.title or conn.username})", cfg, data_dir, sha256=sha256)
    finally:
        path.unlink(missing_ok=True)
    conn.domain_id = snap.domain_id
    db.commit()
    return snap
