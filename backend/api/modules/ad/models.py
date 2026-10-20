"""Таблицы модуля Active Directory (префикс ad_), спека §4.

Снапшот — одна выгрузка домена; сама выгрузка лежит файлом, чтобы
пересчитывать находки новыми правилами. Решения людей о находках — общие
статусы платформы (api/platform/findings) по домену и ключу находки, а не
по снапшоту: принятое переживает следующий сбор.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base, _utcnow
from api.jobs import JobColumns


class AdDomain(Base):
    __tablename__ = "ad_domain"

    id: Mapped[int] = mapped_column(primary_key=True)
    #: SID домена — единственное, что не меняется при переименованиях.
    sid: Mapped[str] = mapped_column(String(64), unique=True)
    dns_root: Mapped[str] = mapped_column(String(255), default="")
    dn: Mapped[str] = mapped_column(String(512), default="")
    netbios: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AdConnection(Base):
    """Профиль онлайн-подключения. Домен заполняется после первого сбора."""

    __tablename__ = "ad_connection"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255), default="")
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=636)
    use_ssl: Mapped[bool] = mapped_column(Boolean, default=True)
    #: Проверка сертификата включена по умолчанию; выключается явно,
    #: если у контроллера сертификат внутреннего CA, неизвестного контейнеру.
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    username: Mapped[str] = mapped_column(String(255), default="")
    #: Зашифрован (api/crypto.py): `enc:v1:…`; открытый — сохранён до шифрования.
    password: Mapped[str] = mapped_column(Text, default="")
    #: '' — defaultNamingContext из rootDSE.
    base_dn: Mapped[str] = mapped_column(String(512), default="")
    collect_sysvol: Mapped[bool] = mapped_column(Boolean, default=True)
    #: Щадят контроллер: объектов в одной странице LDAP и пауза между запросами к нему.
    page_size: Mapped[int] = mapped_column(Integer, default=500, server_default="500")
    pause_ms: Mapped[int] = mapped_column(Integer, default=500, server_default="500")
    domain_id: Mapped[int | None] = mapped_column(ForeignKey("ad_domain.id", ondelete="SET NULL"), nullable=True)


class AdSnapshot(Base):
    __tablename__ = "ad_snapshot"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("ad_domain.id", ondelete="CASCADE"), index=True)
    collected_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    imported_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    #: ldap | file
    source: Mapped[str] = mapped_column(String(16))
    collector: Mapped[str] = mapped_column(String(255), default="")
    filename: Mapped[str] = mapped_column(String(255), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    objects: Mapped[int] = mapped_column(Integer, default=0)
    findings: Mapped[int] = mapped_column(Integer, default=0)
    #: {check: {severity: n}} — для обзора и списка снапшотов.
    stats_json: Mapped[str] = mapped_column(Text, default="{}")
    analyzer_version: Mapped[str] = mapped_column(String(16), default="")
    #: {check: причина} — проверки, для которых в выгрузке не было данных.
    unchecked_json: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")
    #: По каким данным ЦС посчитан снапшот (самая свежая из учтённых загрузок).
    ca_data_id: Mapped[int | None] = mapped_column(ForeignKey("ad_ca_data.id", ondelete="SET NULL"), nullable=True)
    #: Сводка домена (core/summary.py); '' — снапшот посчитан до её появления.
    summary_json: Mapped[str] = mapped_column(Text, default="", server_default="")
    #: Сырая оценка домена (core/score.py) по находкам вне allowlist; '' — посчитан до её появления.
    score_json: Mapped[str] = mapped_column(Text, default="", server_default="")


class AdCaData(Base):
    """Загрузка данных ЦС (`stools-ad-ca/1`) — сущность домена, не снапшота:
    собирается отдельно и реже, анализ берёт самые свежие разделы."""

    __tablename__ = "ad_ca_data"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("ad_domain.id", ondelete="CASCADE"), index=True)
    collected_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    imported_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    filename: Mapped[str] = mapped_column(String(255), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    uploaded_by: Mapped[str] = mapped_column(String(255), default="")
    #: ["ca", "dc", "web"] — какие разделы собраны.
    sections_json: Mapped[str] = mapped_column(Text, default="[]")
    #: Файл целиком.
    data: Mapped[dict[str, Any]] = mapped_column(JSON().with_variant(JSONB(), "postgresql"))


class AdFinding(Base):
    __tablename__ = "ad_finding"
    __table_args__ = (
        Index("ix_ad_finding_snapshot_check", "snapshot_id", "check"),
        Index("ix_ad_finding_snapshot_severity", "snapshot_id", "severity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("ad_snapshot.id", ondelete="CASCADE"), index=True)
    #: Стабильный между снапшотами ключ находки (спека §4).
    key: Mapped[str] = mapped_column(String(64), index=True)
    check: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    severity_original: Mapped[str] = mapped_column(String(16))
    identity: Mapped[str] = mapped_column(String(512), default="")
    identity_sid: Mapped[str] = mapped_column(String(64), default="")
    target: Mapped[str] = mapped_column(String(1024), default="")
    right: Mapped[str] = mapped_column(String(255), default="")
    allowlisted: Mapped[bool] = mapped_column(Boolean, default=False)
    details_json: Mapped[str] = mapped_column(Text, default="{}")


class AdJob(JobColumns, Base):
    """kind: import_file | collect | reanalyze"""

    __tablename__ = "ad_job"
