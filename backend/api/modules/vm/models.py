"""Таблицы модуля Vulnerability Management (префикс vm_).

Модель нормализована намеренно (спека §3): пара хост–CVE хранит только
риск, всё остальное лежит в `vm_host` и `vm_cve`. Формула (спека 2026-10-21 §9)
раскладывается на члены CVE (`vm_cve.likelihood`, `cvss10`, `av_class`) и хоста
(`vm_host.value`, `internet`), поэтому пересчёт миллионов пар — один UPDATE,
а не проход по строкам. Уровень не хранится: он вычисляется из балла по порогам
настроек при чтении.

Справочники `vm_ref_*` хранятся сырыми и заменяются целиком; `vm_cve` —
витрина, которая собирается из них для CVE, встречающихся у хостов и образов.

Образы контейнеров из Harbor (`vm_image`, `vm_image_cve`) — вторая сторона пар:
находки Trivy получают риск по той же витрине `vm_cve`, но без внешнего ключа на неё
(в отчёте бывают не-CVE идентификаторы, у них риска нет).
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    JSON,
    BigInteger,
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
    #: V формулы: ценность по критичности и разметке зоны — пересчитывается.
    value: Mapped[float] = mapped_column(Float, default=0.6)
    #: Доступ из интернета по разметке зоны — копия на хосте, чтобы reach
    #: считался в том же UPDATE пар без соединения с зонами.
    internet: Mapped[bool] = mapped_column(Boolean, default=False)


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
    #: В каталоге CISA KEV: эксплуатация — факт, L = 1.
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_added: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    kev_ransomware: Mapped[bool] = mapped_column(Boolean, default=False)
    #: Срок устранения по CISA — показывается в карточке, в балл не входит.
    kev_due: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    #: L формулы: вероятность эксплуатации — пересчитывается.
    likelihood: Mapped[float] = mapped_column(Float, default=0.0)
    #: CVSS ÷ 10; NULL — балла нет, в пересчёте подставляется `cvss_missing` из весов.
    cvss10: Mapped[float | None] = mapped_column(Float, nullable=True)
    #: network | adjacent | local | none — класс вектора атаки для reach.
    av_class: Mapped[str] = mapped_column(String(16), default="none")


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
    «конфиденциальных данных» для ценности хоста: сам VM этого не отдаёт.
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


class VmRefKev(Base):
    """Каталог эксплуатируемых уязвимостей CISA KEV; заменяется целиком."""

    __tablename__ = "vm_ref_kev"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    date_added: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    #: knownRansomwareCampaignUse = Known.
    ransomware: Mapped[bool] = mapped_column(Boolean, default=False)
    vendor: Mapped[str] = mapped_column(Text, default="")
    product: Mapped[str] = mapped_column(Text, default="")
    name: Mapped[str] = mapped_column(Text, default="")
    due_date: Mapped[dt.date | None] = mapped_column(Date, nullable=True)


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


class VmHostGroup(Base):
    """Локальная группа хоста из второго и третьего PDQL (спека 2026-10-23 §2).

    Строка на участника; группа без участников — строка с пустыми полями участника.
    Хост — по FQDN, имени и IP, без внешнего ключа на `vm_host`: импорт отбрасывает
    хосты без CVE, а группы у пропатченных серверов нужны не меньше. Заменяется
    целиком успешным снимком; семейство, чей запрос не прошёл, остаётся прежним.
    """

    __tablename__ = "vm_host_group"
    #: Строки хоста читаются по (семейство, FQDN, имя, IP) — шаг групп Assets; ведущий `os_family` — замена семейства.
    __table_args__ = (Index("ix_vm_host_group_host", "os_family", "fqdn", "hostname", "ip"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    #: windows | linux
    os_family: Mapped[str] = mapped_column(String(8))
    fqdn: Mapped[str] = mapped_column(String(255), default="")
    hostname: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    group_name: Mapped[str] = mapped_column(String(512), default="")
    #: Верхний регистр; у Linux пусто.
    group_sid: Mapped[str] = mapped_column(String(255), default="")
    #: Только Linux.
    group_gid: Mapped[str] = mapped_column(String(32), default="")
    group_description: Mapped[str] = mapped_column(Text, default="")
    member_name: Mapped[str] = mapped_column(String(512), default="")
    member_domain: Mapped[str] = mapped_column(String(255), default="")
    member_sid: Mapped[str] = mapped_column(String(255), default="")
    #: account | group | '' (группа без участников)
    member_type: Mapped[str] = mapped_column(String(16), default="")
    member_local: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    member_system: Mapped[bool | None] = mapped_column(Boolean, nullable=True)


class VmGroupImport(Base):
    """Снимок локальных групп; последний по `finished_at` описывает `vm_host_group`.

    `windows_ok` / `linux_ok` — в этом снимке записан полный снимок семейства. False — строки
    семейства остались от прежнего (запрос не прошёл, выгрузка не того формата или пуста при
    непустом прежнем) либо записаны с лимитом подключения (неполные): по ним пропавшие не судятся.
    """

    __tablename__ = "vm_group_import"

    id: Mapped[int] = mapped_column(primary_key=True)
    finished_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    hosts: Mapped[int] = mapped_column(Integer, default=0)
    rows: Mapped[int] = mapped_column(Integer, default=0)
    windows_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    linux_ok: Mapped[bool] = mapped_column(Boolean, default=False)


class VmJob(JobColumns, Base):
    """Фоновая задача модуля: импорт, справочник, пересчёт.

    kind: import_vm | import_file | ref_epss | ref_nvd | ref_exploitdb | ref_msf | ref_kev | recalculate
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


class VmHarborProjectPolicy(Base):
    """Effective vulnerability policy read from Harbor at the last sync."""

    __tablename__ = "vm_harbor_project_policy"
    project: Mapped[str] = mapped_column(String(255), primary_key=True)
    registry_url: Mapped[str] = mapped_column(String(512))
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    checked_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    error: Mapped[str] = mapped_column(String(255), default="")


class VmImage(Base):
    """Образ контейнера из Harbor: один тегированный артефакт. Мультиархитектурный индекс —
    одна строка (отчёт Trivy Harbor хранит на самом индексе), его платформы — в `platform`.

    `id` стабилен между синхронизациями: запись — upsert по (проект, репозиторий, digest),
    чтобы ссылки на карточку образа жили.
    """

    __tablename__ = "vm_image"
    __table_args__ = (
        UniqueConstraint("project", "repository", "digest", name="uq_vm_image_ref"),
        Index("ix_vm_image_repo", "project", "repository"),
        Index("ix_vm_image_risk", "risk_max"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project: Mapped[str] = mapped_column(String(255))
    #: Путь внутри проекта, например `web`.
    repository: Mapped[str] = mapped_column(String(255))
    digest: Mapped[str] = mapped_column(String(80))
    #: Адрес реестра на момент получения, без учётных данных; старые строки — пусто до синхронизации.
    registry_url: Mapped[str] = mapped_column(String(512), default="", server_default="")
    #: image | helm | other | unknown. Legacy rows stay unknown until sync.
    artifact_kind: Mapped[str] = mapped_column(String(16), default="unknown", server_default="unknown")
    is_index: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    report_complete: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    #: Verified root/child manifest and runnable configuration hashes for host matching.
    runtime_ids: Mapped[list[str]] = mapped_column(JSON, default=list, server_default="[]")
    runtime_checked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    runtime_error: Mapped[str] = mapped_column(Text, default="", server_default="")
    #: Платформы мультиархитектурного индекса через «, » (`linux/amd64, linux/arm64`), в пределах
    #: столбца — лишние платформы отбрасываются целиком; у обычного образа — NULL.
    platform: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: JSON-список тегов.
    tags: Mapped[str] = mapped_column(Text, default="[]")
    size: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    pushed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: success | pending | running | error | none
    scan_status: Mapped[str] = mapped_column(String(16), default="none")
    scanned_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scanner: Mapped[str | None] = mapped_column(String(64), nullable=True)
    trivy_critical: Mapped[int] = mapped_column(Integer, default=0)
    trivy_high: Mapped[int] = mapped_column(Integer, default=0)
    trivy_medium: Mapped[int] = mapped_column(Integer, default=0)
    trivy_low: Mapped[int] = mapped_column(Integer, default=0)
    trivy_unknown: Mapped[int] = mapped_column(Integer, default=0)
    trivy_total: Mapped[int] = mapped_column(Integer, default=0)
    #: Наибольший риск по парам образа; NULL — ни одна пара не получила риск.
    risk_max: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: Сколько пар получили риск по формуле.
    cves_scored: Mapped[int] = mapped_column(Integer, default=0)
    #: Синхронизация, которой образ виден.
    synced_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    #: Почему образ не обновлён в последней синхронизации.
    sync_error: Mapped[str | None] = mapped_column(String(255), nullable=True)


class VmImageCve(Base):
    """Находка Trivy в образе. `cve_id` — идентификатор из отчёта как есть, не внешний
    ключ на `vm_cve`: пересчёт соединяет по нему, а не-CVE (GHSA-…) остаются без риска."""

    __tablename__ = "vm_image_cve"

    image_id: Mapped[int] = mapped_column(
        ForeignKey("vm_image.id", ondelete="CASCADE"), primary_key=True
    )
    cve_id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    package: Mapped[str] = mapped_column(String(255), primary_key=True)
    #: Пустая строка, если в отчёте версии нет: часть ключа не бывает NULL.
    installed_version: Mapped[str] = mapped_column(String(128), primary_key=True, default="")
    fixed_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: critical | high | medium | low | unknown (строчными) — оценка Trivy, в риск не входит.
    trivy_severity: Mapped[str] = mapped_column(String(16))
    trivy_cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    link: Mapped[str | None] = mapped_column(String(512), nullable=True)
    #: NULL — идентификатора нет в витрине `vm_cve` (не CVE или витрина пуста).
    risk_raw: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)


class VmImageSync(Base):
    """Журнал синхронизаций с Harbor; последняя запись описывает текущее состояние."""

    __tablename__ = "vm_image_sync"

    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    images: Mapped[int] = mapped_column(Integer, default=0)
    #: Пар «образ × идентификатор».
    cves: Mapped[int] = mapped_column(Integer, default=0)
    repositories: Mapped[int] = mapped_column(Integer, default=0)
    skipped_unscanned: Mapped[int] = mapped_column(Integer, default=0)
    #: Краткий перечень репозиториев с ошибкой.
    errors: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_by: Mapped[str] = mapped_column(String(64), default="")
