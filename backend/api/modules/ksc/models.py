"""Таблицы модуля KSC: сервер, подключения, снапшоты, хосты, находки, вердикты, задачи."""
from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base, _utcnow
from api.jobs import JobColumns


class KscServer(Base):
    __tablename__ = "ksc_server"

    id: Mapped[int] = mapped_column(primary_key=True)
    #: Имя сервера из выгрузки (KLADMSRV_SERVER_HOSTNAME); аналог домена в AD.
    name: Mapped[str] = mapped_column(String(255), unique=True)
    version: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class KscConnection(Base):
    """Онлайн-подключение к Open API. Пароль зашифрован, как у AD-подключений (api/crypto.py)."""

    __tablename__ = "ksc_connection"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255), default="")
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=13299)
    username: Mapped[str] = mapped_column(String(255), default="")
    password: Mapped[str] = mapped_column(Text, default="")
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    #: Внутренняя учётка KSC (internal="1") или доменная с именем домена.
    internal: Mapped[bool] = mapped_column(Boolean, default=True)
    domain: Mapped[str] = mapped_column(String(255), default="")
    server_id: Mapped[int | None] = mapped_column(ForeignKey("ksc_server.id", ondelete="SET NULL"), nullable=True)
    #: Не собирать содержимое политик (секция policy_contents) — файл заметно больше.
    skip_policy_contents: Mapped[bool] = mapped_column(Boolean, default=False)


class KscSnapshot(Base):
    __tablename__ = "ksc_snapshot"

    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("ksc_server.id", ondelete="CASCADE"), index=True)
    collected_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    imported_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    #: file | online
    source: Mapped[str] = mapped_column(String(16))
    collector: Mapped[str] = mapped_column(String(255), default="")
    filename: Mapped[str] = mapped_column(String(255), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    hosts: Mapped[int] = mapped_column(Integer, default=0)
    findings: Mapped[int] = mapped_column(Integer, default=0)
    #: {"checks": {code: {severity: n}}, "coverage": {...}}
    stats_json: Mapped[str] = mapped_column(Text, default="{}")
    analyzer_version: Mapped[str] = mapped_column(String(16), default="")


class KscHost(Base):
    """Инвентарь снапшота: одна строка на хост KSC, для экрана хостов и карточек покрытия."""

    __tablename__ = "ksc_host"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("ksc_snapshot.id", ondelete="CASCADE"), index=True)
    host_id: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(255), default="")
    fqdn: Mapped[str] = mapped_column(String(255), default="")
    domain: Mapped[str] = mapped_column(String(255), default="")
    group_path: Mapped[str] = mapped_column(String(1024), default="")
    os: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    agent_installed: Mapped[bool] = mapped_column(Boolean, default=False)
    agent_alive: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    agent_version: Mapped[str] = mapped_column(String(64), default="")
    product: Mapped[str] = mapped_column(String(255), default="")
    product_version: Mapped[str] = mapped_column(String(64), default="")
    #: none | off | on — из KLHST_WKS_STATUS и KLHST_WKS_RTP_STATE
    protection: Mapped[str] = mapped_column(String(8), default="none")
    rtp_state: Mapped[int] = mapped_column(Integer, default=0)
    bases_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_fullscan_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: ok | warning | critical
    status: Mapped[str] = mapped_column(String(16), default="ok")
    threats: Mapped[int] = mapped_column(Integer, default=0)
    unassigned: Mapped[bool] = mapped_column(Boolean, default=False)
    #: both | ksc_only | NULL — нет данных AD
    in_ad: Mapped[str | None] = mapped_column(String(16), nullable=True)
    components_json: Mapped[str] = mapped_column(Text, default="[]")
    #: {os_build, cpu_arch, vm_type, reboot_required, reboot_requested_at, reboot_reason, edr_status, managed_by_other_server}
    extra_json: Mapped[str] = mapped_column(Text, default="{}")


class KscFinding(Base):
    __tablename__ = "ksc_finding"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("ksc_snapshot.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(64), index=True)
    check: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    severity_original: Mapped[str] = mapped_column(String(16))
    #: Имя хоста; пусто для находок про группы и лицензии.
    host: Mapped[str] = mapped_column(String(255), default="")
    #: FQDN хоста (иначе имя в нижнем регистре) — по нему находки связываются с хостом.
    host_key: Mapped[str] = mapped_column(String(255), default="", index=True)
    #: Группа, политика, задача, лицензия.
    target: Mapped[str] = mapped_column(String(1024), default="")
    allowlisted: Mapped[bool] = mapped_column(Boolean, default=False)
    details_json: Mapped[str] = mapped_column(Text, default="{}")


class KscVerdict(Base):
    __tablename__ = "ksc_verdict"

    server_id: Mapped[int] = mapped_column(ForeignKey("ksc_server.id", ondelete="CASCADE"), primary_key=True)
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), default="accepted")
    reason: Mapped[str] = mapped_column(Text, default="")
    decided_by: Mapped[str] = mapped_column(String(255), default="")
    decided_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class KscJob(JobColumns, Base):
    """kind: import_file | collect | reanalyze."""

    __tablename__ = "ksc_job"
