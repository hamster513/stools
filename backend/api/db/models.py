"""SQLAlchemy-модели: слой хранения поверх ядра `kbaudit`.

Ядро (`kbaudit/`) ничего не знает про эти таблицы — оно принимает и отдаёт
Pydantic-модели, а сюда их раскладывает `api/services/ingest.py`. Схема
следует §4.4 дизайн-спеки, с тремя поправками оттуда же:

1. `finding` ключуется `object_type` + `object_uuid`, а не `rule_uuid` —
   находки бывают не только у корреляционных правил.
2. Решения по находкам — вне снапшотов: прежде таблица `finding_verdict`,
   с 02.10.2026 — общие статусы находок платформы (api/platform/findings,
   ключ — api/modules/siem/findings_adapter.py). Значение не хранится.
3. `rule.parse_status` различает «не разобрали» и «событий не требует».
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


# --------------------------------------------------------------------------
# Аутентификация
# --------------------------------------------------------------------------


#: Роли платформы. Порядок — от широкой к узкой, им пользуется api/rbac.py.
ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_AUDITOR = "auditor"
ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_AUDITOR)


class AppUser(Base):
    __tablename__ = "app_user"

    id: Mapped[int] = mapped_column(primary_key=True)
    login: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    #: NULL у пользователей из OIDC — пароля в этой базе для них нет.
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: admin — всё; analyst — чтение и запись в модулях; auditor — только чтение.
    role: Mapped[str] = mapped_column(String(16), default=ROLE_ADMIN)
    #: local — пароль в этой базе; oidc — вход через провайдера, пароля нет.
    auth_source: Mapped[str] = mapped_column(String(8), default="local", server_default="local")
    #: claim `sub` провайдера: логин в FAM могут переименовать, sub — нет.
    oidc_subject: Mapped[str | None] = mapped_column(String(255), nullable=True, unique=True)
    #: Заблокированный не проходит вход, его сессии сброшены.
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: Оформление интерфейса: dark по умолчанию, light — выбор пользователя.
    theme: Mapped[str] = mapped_column(String(8), default="dark", server_default="dark")
    last_login_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class SessionRow(Base):
    """Сессия. В cookie `stools_session` — сырой токен, здесь — его SHA-256."""

    __tablename__ = "session"

    #: hash_token(токен из cookie), hex (api/crypto.py).
    token: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("app_user.id", ondelete="CASCADE"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    #: Последний запрос по сессии; нужен таймауту бездействия. Обновляется
    #: не чаще раза в минуту (api/deps.py), чтобы не писать на каждый GET.
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


#: Уровни доступа по порядку включения: каждый следующий разрешает всё, что предыдущий.
LEVELS = ("deny", "read", "write", "admin")
#: Идентификаторы модулей — они же префиксы `/api/<id>/` (api/modules/__init__.py).
MODULE_IDS = ("attack", "siem", "vm", "ad", "ksc", "assets", "toolbox")
#: Области, по которым роль задаёт уровень: модули и платформа (пользователи, настройки).
AREAS = MODULE_IDS + ("platform",)


class AccessRole(Base):
    """Роль: матрица «область × уровень». Нет строки в `levels` — это `deny`."""

    __tablename__ = "access_role"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    #: Встроенные роли заводит ensure_builtin (api/platform/services/access.py).
    builtin: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    levels: Mapped[list[AccessRoleLevel]] = relationship(cascade="all, delete-orphan")


class AccessRoleLevel(Base):
    __tablename__ = "access_role_level"

    role_id: Mapped[int] = mapped_column(ForeignKey("access_role.id", ondelete="CASCADE"), primary_key=True)
    area: Mapped[str] = mapped_column(String(16), primary_key=True)
    level: Mapped[str] = mapped_column(String(8))


class AccessGroup(Base):
    """Группа: к ней привязана ровно одна роль, в неё входят пользователи.

    `oidc` — группа, членство в которой выдаётся при входе по claim провайдера
    (`external_name` — значение claim); `local` — членство назначает человек."""

    __tablename__ = "access_group"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    source: Mapped[str] = mapped_column(String(8), default="local", server_default="local")
    #: NULL у local; у oidc уникально (в Postgres NULL-ы в UNIQUE не конфликтуют).
    external_name: Mapped[str | None] = mapped_column(String(255), nullable=True, unique=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("access_role.id", ondelete="RESTRICT"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    role: Mapped[AccessRole] = relationship()


class AccessMembership(Base):
    __tablename__ = "access_membership"

    user_id: Mapped[int] = mapped_column(ForeignKey("app_user.id", ondelete="CASCADE"), primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("access_group.id", ondelete="CASCADE"), primary_key=True)


class OidcLoginState(Base):
    """Состояние начатого входа через провайдера: живёт 10 минут.

    В базе, а не в cookie: callback приходит с любого таба, а подписывать
    cookie значит заводить ещё один ключ."""

    __tablename__ = "oidc_login_state"

    state: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(64))
    code_verifier: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AuditEvent(Base):
    """Журнал действий: кто, когда, что и чем кончилось.

    Тела запросов сюда не попадают — там пароли и файлы. Пишется каждый
    мутирующий запрос, вход, неудачный вход, выход и любой отказ 403.
    """

    __tablename__ = "audit_event"
    #: Троттлинг входа считает неудачи по (path, status, at) — api/routers/auth.py.
    __table_args__ = (Index("ix_audit_event_path_status_at", "path", "status", "at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    #: NULL у неудачного входа: пользователя могло не быть вовсе.
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("app_user.id", ondelete="SET NULL"), nullable=True, index=True
    )
    login: Mapped[str] = mapped_column(String(255))
    role: Mapped[str | None] = mapped_column(String(16), nullable=True)
    method: Mapped[str] = mapped_column(String(8))
    path: Mapped[str] = mapped_column(Text)
    status: Mapped[int] = mapped_column(Integer)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)


# --------------------------------------------------------------------------
# Задания
# --------------------------------------------------------------------------


class Job(Base):
    __tablename__ = "job"

    id: Mapped[int] = mapped_column(primary_key=True)
    #: NULL, пока снапшот не создан (стадия ещё не дошла до persisting) —
    #: см. api/services/ingest.py про порядок создания строк.
    snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshot.id", ondelete="SET NULL"), nullable=True
    )
    stage: Mapped[str] = mapped_column(String(32), default="pending")
    status: Mapped[str] = mapped_column(String(16), default="running")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    #: upload — загрузка файла, collect — сбор из базы знаний: см. kb_collect.active_collect.
    kind: Mapped[str] = mapped_column(String(16), default="upload")


# --------------------------------------------------------------------------
# Снапшоты
# --------------------------------------------------------------------------


class Snapshot(Base):
    __tablename__ = "snapshot"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    filename: Mapped[str] = mapped_column(String(512))
    archive_path: Mapped[str] = mapped_column(String(1024))
    #: Кэш уже разобранного архива (ParsedArchive в JSON) — чтобы пересчёт
    #: производных чисел при смене профиля не требовал повторного разбора
    #: zip (контракт §«Профиль инсталляции»).
    parsed_cache_path: Mapped[str] = mapped_column(String(1024))
    #: Обе колонки берутся из одного и того же источника — версии сборки
    #: taxonomy.json: отдельного "номера KB" в выгрузке нет (см. отчёт).
    kb_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    taxonomy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_type: Mapped[str] = mapped_column(String(32), default="upload")
    #: Чем посчитаны находки: версия разбора (`kbaudit`) и отпечаток той части
    #: профиля, от которой они зависят. Автоматика статусов сравнивает соседние
    #: снапшоты, только если они посчитаны одинаково (findings_adapter).
    #: У снапшотов до 02.10.2026 пусто.
    parser_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    profile_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Снапшот, собранный из базы знаний по API (source_type='api'): адрес
    #: сервера (без учётки) и имя БД контента. У снапшотов из файла пусто.
    kb_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kb_database: Mapped[str | None] = mapped_column(String(255), nullable=True)

    #: Производные числа сводки (см. api/services/summary.py) — пересчитываются
    #: при загрузке и при смене профиля, не при каждом GET.
    rule_count: Mapped[int] = mapped_column(Integer, default=0)
    group_count: Mapped[int] = mapped_column(Integer, default=0)
    rules_without_code: Mapped[int] = mapped_column(Integer, default=0)
    unsupported_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)
    scoped_count: Mapped[int] = mapped_column(Integer, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    findings_by_kind_json: Mapped[str] = mapped_column(Text, default="{}")
    findings_by_polarity_json: Mapped[str] = mapped_column(Text, default="{}")
    findings_by_object_type_json: Mapped[str] = mapped_column(Text, default="{}")
    objects_with_findings: Mapped[int] = mapped_column(Integer, default=0)
    in_table_count: Mapped[int] = mapped_column(Integer, default=0)
    divergence_count: Mapped[int] = mapped_column(Integer, default=0)
    clone_count: Mapped[int] = mapped_column(Integer, default=0)
    rules_without_msgid: Mapped[int] = mapped_column(Integer, default=0)
    name_scheme_coverage: Mapped[str | None] = mapped_column(String(32), nullable=True)
    table_ranking_json: Mapped[str] = mapped_column(Text, default="[]")
    authors_json: Mapped[str] = mapped_column(Text, default="{}")
    #: Ссылки на несуществующие правила: rule.name -> [ссылки]. Спека §5.3 —
    #: сообщаются отдельным списком, а не теряются молча.
    unresolved_json: Mapped[str] = mapped_column(Text, default="{}")

    rules: Mapped[list[RuleRow]] = relationship(
        back_populates="snapshot", cascade="all, delete-orphan"
    )


class SnapshotProfile(Base):
    """Профиль инсталляции, привязанный к снапшоту (контракт: PUT /profile
    принимает snapshot_id и пересчитывает именно его производные числа)."""

    __tablename__ = "snapshot_profile"

    snapshot_id: Mapped[int] = mapped_column(
        ForeignKey("snapshot.id", ondelete="CASCADE"), primary_key=True
    )
    #: Сериализованный kbaudit.profile.Profile (JSON).
    profile_json: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


# --------------------------------------------------------------------------
# Правила и связанные факты
# --------------------------------------------------------------------------


class RuleRow(Base):
    __tablename__ = "rule"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshot.id", ondelete="CASCADE"))
    uuid: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    object_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    origin: Mapped[str | None] = mapped_column(String(64), nullable=True)
    body_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    parse_status: Mapped[str] = mapped_column(String(16), default="ok")
    type_id_cat: Mapped[str | None] = mapped_column(String(64), nullable=True)
    type_id_group: Mapped[str | None] = mapped_column(String(64), nullable=True)
    type_id_num: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Автор — четвёртая позиция кода (RuleCode.author), не в исходном §4.4,
    #: но нужна контракту `/rules?author=` и сводке `authors`.
    author: Mapped[str | None] = mapped_column(String(64), nullable=True)
    body_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    title_ru: Mapped[str | None] = mapped_column(Text, nullable=True)
    title_en: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Шаблоны сообщений правила из локализации, склеенные через перевод
    #: строки. Единственное место в выгрузке, где словами написано, что
    #: правило обнаруживает.
    description_ru: Mapped[str | None] = mapped_column(Text, nullable=True)
    description_en: Mapped[str | None] = mapped_column(Text, nullable=True)
    scoped_by_list: Mapped[bool] = mapped_column(Boolean, default=False)
    body_text: Mapped[str | None] = mapped_column(Text, nullable=True)

    snapshot: Mapped[Snapshot] = relationship(back_populates="rules")

    __table_args__ = (
        UniqueConstraint("snapshot_id", "uuid", name="uq_rule_snapshot_uuid"),
        Index("ix_rule_snapshot_author", "snapshot_id", "author"),
    )


class RuleMsgid(Base):
    __tablename__ = "rule_msgid"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshot.id", ondelete="CASCADE"))
    rule_uuid: Mapped[str] = mapped_column(String(64), index=True)
    msgid: Mapped[str] = mapped_column(String(255))
    #: Собственный msgid правила или унаследованный по графу зависимостей.
    inherited: Mapped[bool] = mapped_column(Boolean, default=False)


class RuleField(Base):
    __tablename__ = "rule_field"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshot.id", ondelete="CASCADE"))
    rule_uuid: Mapped[str] = mapped_column(String(64), index=True)
    field: Mapped[str] = mapped_column(String(255))


class RuleTableRef(Base):
    __tablename__ = "rule_table_ref"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshot.id", ondelete="CASCADE"))
    rule_uuid: Mapped[str] = mapped_column(String(64), index=True)
    table_name: Mapped[str] = mapped_column(String(255), index=True)
    direction: Mapped[str] = mapped_column(String(8))  # read | write


class RuleFilterRef(Base):
    __tablename__ = "rule_filter_ref"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshot.id", ondelete="CASCADE"))
    rule_uuid: Mapped[str] = mapped_column(String(64), index=True)
    filter_name: Mapped[str] = mapped_column(String(255))


class RuleDependency(Base):
    __tablename__ = "rule_dependency"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshot.id", ondelete="CASCADE"))
    parent: Mapped[str] = mapped_column(String(255), index=True)
    child: Mapped[str] = mapped_column(String(255), index=True)


class TableListRow(Base):
    __tablename__ = "table_list"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshot.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(255), index=True)
    value_count: Mapped[int] = mapped_column(Integer, default=0)


# --------------------------------------------------------------------------
# Находки и вердикты
# --------------------------------------------------------------------------


class Finding(Base):
    __tablename__ = "finding"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshot.id", ondelete="CASCADE"))
    object_type: Mapped[str] = mapped_column(String(16), index=True)
    object_uuid: Mapped[str] = mapped_column(String(64), index=True)
    object_name: Mapped[str] = mapped_column(String(255))
    kind: Mapped[int] = mapped_column(Integer, index=True)
    severity: Mapped[str] = mapped_column(String(8))
    field: Mapped[str] = mapped_column(String(255), index=True)
    value: Mapped[str] = mapped_column(Text)
    #: sha256 значения — входит в ключ статуса находки без хранения самого
    #: значения вне снапшота (спека §4.2; findings_adapter).
    value_hash: Mapped[str] = mapped_column(String(64), index=True)
    polarity: Mapped[str] = mapped_column(String(16), index=True)
    #: Форма значения: ip | cidr | fqdn. Отдельно от класса, потому что
    #: классы взаимоисключающи: «дублирует список» перекрывает
    #: «IP / CIDR / FQDN», и сетевые имена в нём становятся невидимы.
    shape: Mapped[str | None] = mapped_column(String(8), nullable=True, index=True)
    in_table: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    #: Перечисление всех списков, где встречается значение. Длина не
    #: ограничивается: на реальной выгрузке встретилось значение,
    #: лежащее в стольких whitelist'ах, что их имена заняли 654 символа.
    table_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_finding_snapshot_kind", "snapshot_id", "kind"),
        #: Ключ статуса находки (findings_adapter): по нему ищутся прежние снапшоты находки.
        Index("ix_finding_identity", "object_uuid", "kind", "field", "value_hash"),
    )


class ClonePairRow(Base):
    __tablename__ = "clone_pair"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshot.id", ondelete="CASCADE"))
    rule_a: Mapped[str] = mapped_column(String(255))
    rule_b: Mapped[str] = mapped_column(String(255))
    similarity: Mapped[float] = mapped_column(Float)


class DivergenceRow(Base):
    """Расхождение правило ↔ список — производная от находок класса 1,
    но кешируется как отдельная таблица: пересчёт при каждом GET
    (`affected_rules` для всех 488 находок) дороже, чем при смене профиля."""

    __tablename__ = "divergence"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshot.id", ondelete="CASCADE"))
    value: Mapped[str] = mapped_column(Text)
    field: Mapped[str] = mapped_column(String(255))
    table_name: Mapped[str] = mapped_column(Text)
    hardcoded_in: Mapped[str] = mapped_column(String(255))
    affected_rules_json: Mapped[str] = mapped_column(Text, default="[]")
    blast_radius: Mapped[int] = mapped_column(Integer, default=0)


# --------------------------------------------------------------------------
# Инвентарь базы знаний по API: наборы установки и статус установки правил
# --------------------------------------------------------------------------


class SiemDeploymentSet(Base):
    """Набор установки базы знаний на момент сбора снапшота (спека §6)."""

    __tablename__ = "siem_deployment_set"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshot.id", ondelete="CASCADE"), index=True)
    kb_id: Mapped[str] = mapped_column(String(64))
    parent_kb_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    system_name: Mapped[str] = mapped_column(String(255), default="")
    general_status: Mapped[str] = mapped_column(String(64), default="")
    compilation_status: Mapped[str] = mapped_column(String(64), default="")
    #: {конвейер: статус} — как отдала KB, без толкования.
    deployment_statuses_json: Mapped[str] = mapped_column(Text, default="{}")
    #: Правил корреляции в составе набора.
    rule_count: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (UniqueConstraint("snapshot_id", "kb_id", name="uq_siem_deployment_set"),)


class SiemRuleDeployment(Base):
    """Статус установки правила в SIEM, папка и наборы — из списка объектов KB.

    Правило без строки здесь у снапшота из API — «есть в выгрузке, нет в
    списке объектов KB»: API отдаёт `installed = null`.
    """

    __tablename__ = "siem_rule_deployment"

    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshot.id", ondelete="CASCADE"), primary_key=True)
    rule_uuid: Mapped[str] = mapped_column(String(64), primary_key=True)
    installed: Mapped[bool] = mapped_column(Boolean, default=False)
    folder_path: Mapped[str] = mapped_column(String(1024), default="")
    #: SystemName объекта KB — чтобы назвать правило, которого нет в выгрузке.
    name: Mapped[str] = mapped_column(String(255), default="")
    #: [kb_id набора, …]
    set_ids_json: Mapped[str] = mapped_column(Text, default="[]")


# --------------------------------------------------------------------------
# Настройки и разметка ATT&CK
# --------------------------------------------------------------------------


class AppSetting(Base):
    """Настройки сервиса — одна строка на раздел, значение в JSON.

    В базе, а не в переменных окружения: адрес модели задаёт человек через
    интерфейс, и менять его перезапуском контейнера — не настройка.
    """

    __tablename__ = "app_setting"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value_json: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class AttackMarkup(Base):
    """Разметка правила по ATT&CK — вне снапшотов намеренно.

    Разметка привязана к правилу, а не к загрузке: подтверждённая человеком
    работа обязана пережить следующую выгрузку. Это единственное в системе,
    что стоит человеко-часов, — привязка к snapshot_id обнуляла бы её при
    каждом обновлении базы знаний.

    По правилу, а не по группе: на выгрузке заказчика в группе `DEMO/HC/002`
    двадцать одно правило и девятнадцать разных техник по его собственной
    ручной разметке. Одна запись на группу такого не выражает, а из 32
    сверенных групп лишь у 14 все правила сходятся на одной технике.

    Ключ — `uuid` правила: имя правки переживает переименование хуже
    (в выгрузке встречаются `..._copy` и `..._sidorov`), а код правила
    вообще не уникален — на 187 правил приходится 14 совпадающих кодов.
    """

    __tablename__ = "attack_markup"

    id: Mapped[int] = mapped_column(primary_key=True)
    #: UUID правила из выгрузки — идентичность правила между выгрузками.
    rule_uuid: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    #: Имя группы правил по схеме именования профиля (например DEMO/HC).
    #: Хранится для сводок и групповых операций, ключом больше не служит.
    group_name: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    #: Разметка пришла от группы, а не выбрана для этого правила отдельно.
    #: Различать обязательно: унаследованная разметка ничего не утверждает
    #: о конкретном правиле, и выдавать её за проверенную — та же ложь,
    #: что и родительская техника вместо подтехники.
    inherited: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    #: unmapped | suggested | confirmed
    status: Mapped[str] = mapped_column(String(16), default="suggested", index=True)
    #: Список TechniqueSuggestion с добавленным `source`.
    techniques_json: Mapped[str] = mapped_column(Text, default="[]")
    #: Что видела модель. Без этого спорную разметку через полгода
    #: не разобрать: кандидаты меняются вместе с бандлом, моделью и выжимкой.
    candidates_json: Mapped[str] = mapped_column(Text, default="[]")
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: Версия ATT&CK на момент разметки: техника может переехать или
    #: раздробиться на подтехники, и тогда подтверждение устареет.
    attack_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AttackReference(Base):
    """Эталонная разметка из чужой таблицы — вне снапшотов намеренно.

    Нужна, чтобы качество разметки обсуждалось числом, а не примерами:
    столько-то правил размечено так же, столько-то иначе. Живёт рядом
    с разметкой, а не вместо неё: эталон — мнение человека, с которым
    сверяются, а не запись, которую продукт правит.

    Строки, которым не нашлось правила, тоже хранятся — с пустым
    `rule_uuid`. «В вашей таблице есть правило, которого нет в выгрузке» —
    это находка, а не мусор, и молча её терять нельзя.
    """

    __tablename__ = "attack_reference"

    id: Mapped[int] = mapped_column(primary_key=True)
    #: UUID правила выгрузки. Пусто, если сопоставить не удалось.
    rule_uuid: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    #: Идентификатор правила в исходной таблице, как его написал человек.
    source_key: Mapped[str] = mapped_column(String(255), index=True)
    #: Список идентификаторов техник, уже перенесённых на действующую
    #: версию ATT&CK: в таблице заказчика 17 ссылок на отозванное
    #: семейство T1562, и без переноса они читались бы как расхождение.
    techniques_json: Mapped[str] = mapped_column(Text, default="[]")
    #: Что стояло в таблице до переноса — чтобы перенос был виден.
    original_json: Mapped[str] = mapped_column(Text, default="[]")
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    imported_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    imported_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class TechniqueVector(Base):
    """Кэш векторов техник.

    Бандл ATT&CK меняется раз в квартал, разметка запускается на каждой
    выгрузке: пересчитывать 222 вектора каждый раз — это минуты ожидания
    и лишняя зависимость от доступности эмбеддера.
    """

    __tablename__ = "technique_vector"
    __table_args__ = (
        UniqueConstraint("technique_id", "embed_model", name="uq_technique_vector_model"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    technique_id: Mapped[str] = mapped_column(String(32), index=True)
    embed_model: Mapped[str] = mapped_column(String(128))
    #: Версия бандла, на которой посчитан вектор: описание техники меняется
    #: между версиями, и старый вектор тогда описывает не то.
    attack_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    vector_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


# --------------------------------------------------------------------------
# Бандл ATT&CK и его перевод
# --------------------------------------------------------------------------


class AttackBundleRow(Base):
    """Действующий бандл ATT&CK — одна строка.

    В базе, а не только в образе, потому что заказчик обновляет матрицу
    сам, не дожидаясь поставки. Хранится выжимка (техники и тактики),
    а не исходные пятьдесят мегабайт STIX: всё остальное в нём —
    группировки, ПО, меры и связи, которых разметка не касается.
    """

    __tablename__ = "attack_bundle"

    id: Mapped[int] = mapped_column(primary_key=True)
    version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    techniques_json: Mapped[str] = mapped_column(Text, default="[]")
    tactics_json: Mapped[str] = mapped_column(Text, default="[]")
    #: builtin — вложенный в образ, uploaded — загруженный человеком.
    source: Mapped[str] = mapped_column(String(16), default="builtin")
    #: Отпечаток вложенного бандла на момент записи. По его смене видно,
    #: что обновился софт: тогда вложенный перекрывает загруженный, а
    #: обычный перезапуск ничего не трогает.
    builtin_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    loaded_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    loaded_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    #: Версия, которую перекрыла поставка. Заполняется только когда
    #: вложенный бандл заменил загруженный человеком: он загружал её
    #: руками, и подмену нельзя проводить молча — особенно если поставка
    #: оказалась старее.
    replaced_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    replaced_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: Человек увидел сообщение о замене. До этого оно показывается.
    notice_dismissed: Mapped[bool] = mapped_column(Boolean, default=False)


class AttackTranslation(Base):
    """Русский перевод техники поверх вложенного.

    Хранит отпечаток английского исходника, с которого переводили. Без
    него устаревший перевод не отличить от актуального: MITRE правит
    описания чаще, чем добавляет техники, и старый русский текст молча
    ложился бы на новый английский.
    """

    __tablename__ = "attack_translation"

    technique_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name_ru: Mapped[str] = mapped_column(Text)
    description_ru: Mapped[str] = mapped_column(Text, default="")
    #: sha256 английского названия и описания на момент перевода.
    source_hash: Mapped[str] = mapped_column(String(64))
    #: builtin — из поставки, llm — перевела модель, manual — правил человек.
    origin: Mapped[str] = mapped_column(String(16), default="llm")
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class RuTtpProcedure(Base):
    """Процедура из выгрузки применяемости — вне снапшотов намеренно.

    Выгрузка описывает мир, а не конкретную базу правил: она не устаревает
    от того, что заказчик выгрузил правила заново.

    Хранится строка на процедуру, а не свёрнутый счётчик по технике. Ради
    процедур выгрузку и загружают: у непокрытой техники это готовый ответ
    на вопрос «что писать», а счётчик отвечает только «сколько».

    Тактика из исходного файла не хранится: она в точности повторяет
    тактики техники по матрице. Копия одной и той же правды разойдётся
    с оригиналом при первом же обновлении матрицы.
    """

    __tablename__ = "attack_ru_ttp"

    id: Mapped[int] = mapped_column(primary_key=True)
    #: Идентификатор, уже перенесённый на действующую версию ATT&CK.
    technique_id: Mapped[str] = mapped_column(String(32), index=True)
    technique_name: Mapped[str] = mapped_column(String(255), default="")
    procedure: Mapped[str] = mapped_column(Text, default="")
    command_line: Mapped[str] = mapped_column(Text, default="")
    actors_json: Mapped[str] = mapped_column(Text, default="[]")
    malware_json: Mapped[str] = mapped_column(Text, default="[]")
    tools_json: Mapped[str] = mapped_column(Text, default="[]")


class RuTtpImport(Base):
    """Чья выгрузка и когда загружена — одна строка на загрузку.

    Без неё на экране нельзя сказать, чьё это мнение и насколько оно
    свежее, а показывать чужую аналитику как безымянный факт нельзя.
    """

    __tablename__ = "attack_ru_import"

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(255), default="")
    imported_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    imported_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    #: Версия матрицы, на которую переносились идентификаторы.
    attack_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    technique_count: Mapped[int] = mapped_column(Integer, default=0)
    #: Идентификаторы, которых нет в действующей матрице и которым не нашлось
    #: замены. Это не мусор, а расхождение версий, и человек должен его видеть.
    unknown_json: Mapped[str] = mapped_column(Text, default="[]")
