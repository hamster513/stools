"""Сводка по выгрузке: то, что печатает CLI и потом отдаёт API."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from pydantic import BaseModel, Field

from kbaudit.analyzers.clones import find_clones
from kbaudit.analyzers.dependencies import build_edges, inherited_msgids, unresolved_refs
from kbaudit.analyzers.divergence import Divergence, find_divergences
from kbaudit.analyzers.fields import FieldPolicy
from kbaudit.analyzers.hardcode import analyze_hardcode
from kbaudit.analyzers.scope import TableStatus, critical_table_status, rank_tables
from kbaudit.catalog import CatalogGroup, build_catalog
from kbaudit.models import ClonePair, Finding, ParsedArchive, ParseStatus, Rule
from kbaudit.naming import apply_scheme
from kbaudit.parsers.snapshot import parse_archive
from kbaudit.profile import Profile, detect_profile


class AuditReport(BaseModel):
    rule_count: int
    origins: dict[str, int] = Field(default_factory=dict)
    group_count: int
    rules_without_code: int
    unsupported_count: int
    edge_count: int
    unresolved: dict[str, list[str]] = Field(default_factory=dict)
    scoped_count: int
    finding_count: int
    findings_by_kind: dict[int, int] = Field(default_factory=dict)
    findings_by_polarity: dict[str, int] = Field(default_factory=dict)
    findings_by_object_type: dict[str, int] = Field(default_factory=dict)
    objects_with_findings: int
    in_table_count: int
    divergence_count: int = 0
    divergences: list[Divergence] = Field(default_factory=list)
    clone_count: int
    rules_without_msgid: int
    table_status: list[TableStatus] = Field(default_factory=list)
    table_ranking: list[TableStatus] = Field(default_factory=list)
    profile_confirmed: bool = False
    name_scheme_coverage: str | None = None
    catalog: list[CatalogGroup] = Field(default_factory=list)
    clones: list[ClonePair] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    rules: list[Rule] = Field(default_factory=list)


def build_report(parsed: ParsedArchive, profile: Profile | None = None) -> AuditReport:
    """Анализ разобранной выгрузки с учётом профиля инсталляции.

    Разбор и анализ разведены намеренно: схема именования определяется
    по уже разобранным именам, а анализ от неё зависит. Без этого шва
    профиль негде применить, а стадии обработки негде показать.
    """
    rules = parsed.rules
    profile = profile or Profile()
    # Схема в профиле — уточнение, а не условие: профиль, в котором человек
    # отметил только критичные списки, не должен отключать автоопределение.
    scheme = profile.name_scheme or detect_profile([r.name for r in rules]).name_scheme
    for rule in rules:
        rule.code = apply_scheme(rule.name, scheme)
    # Дополнения справочников из профиля: какие ещё принципалы считать
    # служебными и какие поля средовыми — вопрос инсталляции, не кода.
    # Роли полей берутся прежде всего из самой таксономии выгрузки: она
    # описывает каждое поле машиночитаемо, и догадываться за неё незачем.
    # Встроенный список дополняет её там, где она молчит, а решения
    # человека перекрывают оба.
    policy = FieldPolicy.from_taxonomy(
        parsed.taxonomy.field_roles,
        environmental=profile.field_roles.environmental,
        technical=profile.field_roles.technical,
        builtin_accounts=profile.builtin_accounts,
    )
    findings = analyze_hardcode(
        parsed.bodies, parsed.table_values, parsed.values_by_table, policy
    )
    divergences = find_divergences(findings, rules)
    edges = build_edges(rules)
    inherited = inherited_msgids(rules, edges)
    catalog = build_catalog(rules, scheme)
    clones = find_clones(rules)
    scoping = profile.tables.scoping

    return AuditReport(
        rule_count=len(rules),
        origins=dict(Counter(r.origin or "—" for r in rules)),
        group_count=len(catalog),
        rules_without_code=sum(1 for r in rules if r.code is None),
        unsupported_count=sum(
            1 for r in rules if r.parse_status is ParseStatus.UNSUPPORTED
        ),
        edge_count=len(edges),
        unresolved=unresolved_refs(rules),
        scoped_count=sum(1 for r in rules if r.is_scoped_by(scoping)),
        finding_count=len(findings),
        findings_by_kind=dict(sorted(Counter(f.kind for f in findings).items())),
        findings_by_polarity=dict(Counter(str(f.polarity) for f in findings)),
        findings_by_object_type=dict(Counter(str(f.object_type) for f in findings)),
        objects_with_findings=len({f.object_uuid for f in findings}),
        in_table_count=sum(1 for f in findings if f.in_table),
        divergence_count=len(divergences),
        divergences=divergences,
        clone_count=len(clones),
        rules_without_msgid=sum(1 for r in rules if not inherited.get(r.name)),
        table_status=critical_table_status(rules, parsed.table_lists, profile.tables.watched),
        table_ranking=rank_tables(rules, parsed.table_lists, scoping),
        profile_confirmed=profile.is_confirmed,
        name_scheme_coverage=(
            f"{scheme.coverage}/{scheme.total}" if scheme else None
        ),
        catalog=catalog,
        clones=clones,
        findings=findings,
        rules=rules,
    )


def run_audit(path: Path, profile: Profile | None = None) -> AuditReport:
    """Разбор архива и анализ одним вызовом — удобство для CLI и тестов."""
    return build_report(parse_archive(path), profile)
