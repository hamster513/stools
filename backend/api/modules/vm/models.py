"""Таблицы модуля Vulnerability Management (префикс vm_).

Модель нормализована намеренно (спека §3): пара хост–CVE хранит только
риск, всё остальное лежит в `vm_host` и `vm_cve`. Формула раскладывается
на множитель CVE (`vm_cve.cve_factor`) и множитель хоста (`vm_host.impact`),
поэтому пересчёт миллионов пар — один UPDATE, а не проход по строкам.

Справочники `vm_ref_*` хранятся сырыми и заменяются целиком; `vm_cve` —
витрина, которая собирается из них для CVE, встречающихся у хостов.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base, _utcnow
from api.jobs import JobColumns


class VmHost(Base):
    __tablename__ = "vm_host"
    __table_args__ = (
        UniqueConstraint("hostname", "ip", name="uq_vm_host_name_ip"),
        # Статусы пар присоединяются по `hostname|ip` (query.host_key): индекс даёт Postgres
        # статистику этого выражения.
        Index("ix_vm_host_key", text("(hostname || '|' || ip)")),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    os_name: Mapped[str] = mapped_column(String(255), default="")
    groups: Mapped[str] = mapped_column(Text, default="")
    #: Как пришло из VM: Critical | High | Medium | Low | None | ''.
    criticality: Mapped[str] = mapped_column(String(32), default="", index=True)
    zone: Mapped[str] = mapped_column(String(255), default="", index=True)
    #: Слагаемые Impact по критичности и разметке зоны — пересчитывается.
    impact: Mapped[float] = mapped_column(Float, default=0.0)


class VmCve(Base):
    __tablename__ = "vm_cve"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    #: nvd_v3 | nvd_v2 | none — откуда взят балл, показывается в карточке.
    cvss_source: Mapped[str] = mapped_column(String(16), default="none")
    v3_av: Mapped[str | None] = mapped_column(String(32), nullable=True)
    v3_pr: Mapped[str | None] = mapped_column(String(32), nullable=True)
    v3_ui: Mapped[str | None] = mapped_column(String(32), nullable=True)
    v2_av: Mapped[str | None] = mapped_column(String(32), nullable=True)
    v2_ac: Mapped[str | None] = mapped_column(String(32), nullable=True)
    v2_au: Mapped[str | None] = mapped_column(String(32), nullable=True)
    epss: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    exploitdb_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    exploits_count: Mapped[int] = mapped_column(Integer, default=0)
    msf_rank: Mapped[str | None] = mapped_column(String(16), nullable=True)
    msf_modules: Mapped[int] = mapped_column(Integer, default=0)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    published: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    #: EPSS × CVSS/10 × CVE_param × ExDB × MSF — пересчитывается.
    cve_factor: Mapped[float] = mapped_column(Float, default=0.0)


class VmHostCve(Base):
    __tablename__ = "vm_host_cve"
    __table_args__ = (Index("ix_vm_host_cve_risk", "risk"),)

    host_id: Mapped[int] = mapped_column(
        ForeignKey("vm_host.id", ondelete="CASCADE"), primary_key=True
    )
    cve_id: Mapped[str] = mapped_column(
        ForeignKey("vm_cve.cve_id", ondelete="CASCADE"), primary_key=True, index=True
    )
    risk_raw: Mapped[float] = mapped_column(Float, default=0.0)
    risk: Mapped[int] = mapped_column(Integer, default=0)


class VmFindingStateRef(Base):
    """Строка статуса пары (`platform_finding_state`, module = vm) как хост и CVE.

    Ключ пары — `hostname|ip|cve`; список пар присоединяет статусы по этой таблице
    и индексу (hostname, ip, cve_id), а не разбирает ключи всех строк состояния в
    каждом запросе. Заводится адаптером VM вместе со строкой состояния
    (`on_states_created`), строки, заведённые в обход, дописывает `backfill`.
    """

    __tablename__ = "vm_finding_state_ref"
    #: То же выражение, что у `ix_vm_host_key`: пары присоединяют статусы по `hostname|ip` и CVE.
    __table_args__ = (Index("ix_vm_finding_state_ref_pair", text("(hostname || '|' || ip)"), "cve_id"),)

    state_id: Mapped[int] = mapped_column(
        ForeignKey("platform_finding_state.id", ondelete="CASCADE"), primary_key=True
    )
    hostname: Mapped[str] = mapped_column(String(255))
    ip: Mapped[str] = mapped_column(String(64))
    cve_id: Mapped[str] = mapped_column(String(32))


class VmZone(Base):
    """Зона из Host.UF_Zone и её разметка человеком.

    Разметка — единственный источник «доступа из интернета» и
    «конфиденциальных данных» для Impact: сам VM этого не отдаёт.
    """

    __tablename__ = "vm_zone"

    name: Mapped[str] = mapped_column(String(255), primary_key=True)
    internet_access: Mapped[bool] = mapped_column(Boolean, default=False)
    confidential_data: Mapped[bool] = mapped_column(Boolean, default=False)
    #: Человек посмотрел на зону; снятые галочки у неразмеченной зоны —
    #: не решение, а отсутствие решения, и обзор это показывает.
    marked: Mapped[bool] = mapped_column(Boolean, default=False)


class VmRefEpss(Base):
    __tablename__ = "vm_ref_epss"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    epss: Mapped[float] = mapped_column(Float)
    percentile: Mapped[float] = mapped_column(Float)


class VmRefNvd(Base):
    __tablename__ = "vm_ref_nvd"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    #: Год фида, из которого пришла запись: замена идёт по годам.
    year: Mapped[int] = mapped_column(Integer, index=True)
    cvss_v3: Mapped[float | None] = mapped_column(Float, nullable=True)
    v3_av: Mapped[str | None] = mapped_column(String(32), nullable=True)
    v3_pr: Mapped[str | None] = mapped_column(String(32), nullable=True)
    v3_ui: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cvss_v2: Mapped[float | None] = mapped_column(Float, nullable=True)
    v2_av: Mapped[str | None] = mapped_column(String(32), nullable=True)
    v2_ac: Mapped[str | None] = mapped_column(String(32), nullable=True)
    v2_au: Mapped[str | None] = mapped_column(String(32), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    published: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    modified: Mapped[dt.date | None] = mapped_column(Date, nullable=True)


class VmRefExploitdb(Base):
    __tablename__ = "vm_ref_exploitdb"

    exploit_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=False)
    type: Mapped[str] = mapped_column(String(32), default="")
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    published: Mapped[dt.date | None] = mapped_column(Date, nullable=True)


class VmRefExploitdbCve(Base):
    __tablename__ = "vm_ref_exploitdb_cve"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    exploit_id: Mapped[int] = mapped_column(Integer, primary_key=True)


class VmRefMsf(Base):
    __tablename__ = "vm_ref_msf"

    fullname: Mapped[str] = mapped_column(String(512), primary_key=True)
    name: Mapped[str] = mapped_column(Text, default="")
    rank: Mapped[int] = mapped_column(Integer, default=0)


class VmRefMsfCve(Base):
    __tablename__ = "vm_ref_msf_cve"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    fullname: Mapped[str] = mapped_column(String(512), primary_key=True)


class VmRefAttack(Base):
    """CVE → техника ATT&CK из справочника CTID (Mappings Explorer / attack_to_cve)."""

    __tablename__ = "vm_ref_attack"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    technique_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    #: exploitation_technique | primary_impact | secondary_impact
    mapping_type: Mapped[str] = mapped_column(String(32), default="")


class VmRefState(Base):
    """Когда, откуда и сколько загружено в каждый справочник."""

    __tablename__ = "vm_ref_state"

    name: Mapped[str] = mapped_column(String(16), primary_key=True)
    loaded_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    #: network | file
    source: Mapped[str] = mapped_column(String(16), default="file")
    records: Mapped[int] = mapped_column(Integer, default=0)
    #: Годы NVD, имя файла — что угодно, полезное человеку.
    detail: Mapped[str] = mapped_column(Text, default="")


class VmImport(Base):
    """Журнал импортов; последняя запись описывает текущее состояние."""

    __tablename__ = "vm_import"

    id: Mapped[int] = mapped_column(primary_key=True)
    finished_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    #: vm | file
    source: Mapped[str] = mapped_column(String(16))
    filename: Mapped[str] = mapped_column(String(255), default="")
    hosts: Mapped[int] = mapped_column(Integer, default=0)
    pairs: Mapped[int] = mapped_column(Integer, default=0)
    cves: Mapped[int] = mapped_column(Integer, default=0)
    new_zones: Mapped[int] = mapped_column(Integer, default=0)


class VmJob(JobColumns, Base):
    """Фоновая задача модуля: импорт, справочник, пересчёт.

    kind: import_vm | import_file | ref_epss | ref_nvd | ref_exploitdb | ref_msf | recalculate
    """

    __tablename__ = "vm_job"


class VmStageHost(Base):
    """Промежуточная таблица импорта: хосты до атомарной замены."""

    __tablename__ = "vm_stage_host"

    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255))
    ip: Mapped[str] = mapped_column(String(64), default="")
    os_name: Mapped[str] = mapped_column(String(255), default="")
    groups: Mapped[str] = mapped_column(Text, default="")
    criticality: Mapped[str] = mapped_column(String(32), default="")
    zone: Mapped[str] = mapped_column(String(255), default="")


class VmStagePair(Base):
    """Промежуточная таблица импорта: пары до дедупликации и замены.

    Пары пишутся сюда пакетами по мере разбора, чтобы миллионы строк
    не копились в памяти процесса; дубли убирает `INSERT … SELECT DISTINCT`.
    """

    __tablename__ = "vm_stage_pair"

    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255))
    ip: Mapped[str] = mapped_column(String(64), default="")
    cve_id: Mapped[str] = mapped_column(String(32))
