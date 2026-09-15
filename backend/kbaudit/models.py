"""Доменные модели. Единственный источник истины по формам данных."""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, computed_field

#: kind → severity. Класс — источник истины, severity выводится (спека §4.1).
SEVERITY_BY_KIND: dict[int, str] = {1: "high", 2: "high", 3: "medium", 4: "medium", 5: "low"}


class ObjectType(StrEnum):
    CORRELATION = "correlation"
    FILTER = "filter"
    ENRICHMENT = "enrichment"
    AGGREGATION = "aggregation"


class Polarity(StrEnum):
    ASSERTION = "assertion"
    NEGATION = "negation"


class ParseStatus(StrEnum):
    OK = "ok"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"


class RuleCode(BaseModel):
    """Структурный код правила, разобранный по схеме именования инсталляции.

    Все позиции необязательны: у разных авторов контента схемы разной
    глубины, а часть правил может не разбираться вовсе. Код не выводится
    из зашитого шаблона — он строится применением схемы, определённой
    по данным выгрузки (см. `kbaudit.naming`).
    """

    author: str | None = None
    category: str | None = None
    group: str | None = None
    rule_id: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def group_key(self) -> str:
        """Человекочитаемый ключ группы: код без номера самого правила."""
        parts = [p for p in (self.author, self.category, self.group) if p]
        return "/".join(parts)


class Taxonomy(BaseModel):
    fields: set[str] = Field(default_factory=set)
    version: str | None = None
    #: Роль поля по описанию самой таксономии: environmental | technical.
    #: Поля, о которых таксономия ничего определённого не говорит, сюда
    #: не попадают — их роль остаётся вопросом к человеку.
    field_roles: dict[str, str] = Field(default_factory=dict)


class MetaInfo(BaseModel):
    object_id: str | None = None
    origin: str | None = None
    category: str | None = None
    rule_name: str | None = None
    criteria: list[str] = Field(default_factory=list)
    correlation_names: list[str] = Field(default_factory=list)


class RuleBody(BaseModel):
    events: list[str] = Field(default_factory=list)
    msgids: list[str] = Field(default_factory=list)
    corr_refs: list[str] = Field(default_factory=list)
    taxonomy_fields: list[str] = Field(default_factory=list)
    filter_refs: list[str] = Field(default_factory=list)
    table_reads: list[str] = Field(default_factory=list)
    table_writes: list[str] = Field(default_factory=list)
    line_count: int = 0


class KbObject(BaseModel):
    """Любой объект KB с телом — для анализа хардкода."""

    uuid: str
    object_type: ObjectType
    name: str
    body_text: str
    body_ext: str


class Rule(BaseModel):
    uuid: str
    name: str
    object_id: str | None = None
    origin: str | None = None
    body_type: str | None = None
    parse_status: ParseStatus = ParseStatus.OK
    code: RuleCode | None = None
    body_hash: str | None = None
    title_ru: str | None = None
    title_en: str | None = None
    #: Шаблоны сообщений правила из локализации — единственное место в
    #: выгрузке, где словами написано, что правило обнаруживает. Заголовок
    #: этого не заменяет: в него вендоры дописывают служебные коды.
    descriptions_ru: list[str] = Field(default_factory=list)
    descriptions_en: list[str] = Field(default_factory=list)
    events: list[str] = Field(default_factory=list)
    msgids: list[str] = Field(default_factory=list)
    corr_refs: list[str] = Field(default_factory=list)
    taxonomy_fields: list[str] = Field(default_factory=list)
    filter_refs: list[str] = Field(default_factory=list)
    table_reads: list[str] = Field(default_factory=list)
    table_writes: list[str] = Field(default_factory=list)
    line_count: int = 0

    def is_scoped_by(self, scoping_tables: list[str] | set[str]) -> bool:
        """Ограничено ли правило перечисленными списками.

        Суждение принимает вызывающий: имена ограничивающих списков живут
        в профиле инсталляции, а не в доменной модели. Раньше здесь было
        зашито имя списка конкретного вендора — после его ухода такое
        допущение перестало быть верным.
        """
        return any(t in self.table_reads for t in scoping_tables)


class Comparison(BaseModel):
    """Одно сравнение поля с литералом, найденное в теле."""

    field: str
    value: str
    count: int = 1
    polarity: Polarity = Polarity.ASSERTION


class Finding(BaseModel):
    object_type: ObjectType
    object_uuid: str
    object_name: str
    kind: int = Field(ge=1, le=5)
    field: str
    value: str
    polarity: Polarity
    #: Форма значения: ip | cidr | fqdn или None. Отдельно от класса
    #: намеренно. Классы взаимоисключающи и «дублирует список» перекрывает
    #: «IP / CIDR / FQDN»: продублированное значение — более тяжёлое
    #: замечание. Но человек, глядя на класс, делает неверный вывод
    #: о числе сетевых имён в правилах: на эталонной выгрузке их 585,
    #: а в классе видно 371. Класс отвечает «что не так», форма —
    #: «что это за значение», и это разные вопросы.
    shape: str | None = None
    in_table: bool = False
    table_name: str | None = None
    body_excerpt: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity(self) -> str:
        return SEVERITY_BY_KIND[self.kind]


class ClonePair(BaseModel):
    rule_a: str
    rule_b: str
    similarity: float


class DependencyEdge(BaseModel):
    parent: str
    child: str


class TableList(BaseModel):
    name: str
    value_count: int = 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_empty(self) -> bool:
        return self.value_count == 0


class ParsedArchive(BaseModel):
    taxonomy: Taxonomy = Field(default_factory=Taxonomy)
    rules: list[Rule] = Field(default_factory=list)
    bodies: list[KbObject] = Field(default_factory=list)
    table_values: set[str] = Field(default_factory=set)
    values_by_table: dict[str, set[str]] = Field(default_factory=dict)
    #: Строки списков как они лежат в выгрузке, с колонками. Нужны,
    #: чтобы показать состав человеку: в плоском множестве значений
    #: идентификатор, имя и описание неразличимы, а решают по ним разное.
    table_rows: dict[str, list[dict[str, str]]] = Field(default_factory=dict)
    table_lists: list[TableList] = Field(default_factory=list)
