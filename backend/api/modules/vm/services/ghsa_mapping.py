"""Local, bounded explicit GHSA aliases and shared reference selection.

No related IDs, package display names, or external inventory lookups become
confirmed links. Withdrawn advisories remain public metadata, not match evidence.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import case, func, literal, select, true, union_all
from sqlalchemy.orm import Session, aliased
from sqlalchemy.sql.elements import ColumnElement

from api.modules.vm.ghsa_models import VmRefGhsa, VmRefGhsaAlias, VmRefGhsaPackage
from api.modules.vm.models import (
    VmRefEpss,
    VmRefExploitdb,
    VmRefExploitdbCve,
    VmRefKev,
    VmRefMsf,
    VmRefMsfCve,
    VmRefNvd,
)

MAX_EQUIVALENTS = 256
BATCH = 2000
_GHSA = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE)


def is_ghsa(identifier: str) -> bool:
    return _GHSA.fullmatch(identifier) is not None


def _normalized(identifier: str) -> str:
    if is_ghsa(identifier):
        return "GHSA-" + identifier[5:].lower()
    return identifier.upper() if identifier.upper().startswith("CVE-") else identifier


def _groups(db: Session, identifiers: set[str]) -> tuple[dict[str, set[str]], dict[str, VmRefGhsa]]:
    if not identifiers:
        return {}, {}
    found: dict[str, VmRefGhsa] = {}
    ordered = sorted(identifiers)
    for start in range(0, len(ordered), BATCH):
        chunk = ordered[start:start + BATCH]
        candidates = select(VmRefGhsa.ghsa_id).where(VmRefGhsa.ghsa_id.in_(chunk)).union(
            select(VmRefGhsaAlias.ghsa_id).where(VmRefGhsaAlias.alias.in_(chunk)),
        )
        rows = db.scalars(select(VmRefGhsa).where(
            VmRefGhsa.withdrawn.is_(None), VmRefGhsa.ghsa_id.in_(candidates),
        ).order_by(VmRefGhsa.ghsa_id).limit(len(chunk) * (MAX_EQUIVALENTS + 1)))
        found.update((row.ghsa_id, row) for row in rows)
    groups = {identifier: {identifier} for identifier in found}
    ids = sorted(found)
    for start in range(0, len(ids), BATCH):
        chunk = ids[start:start + BATCH]
        for ghsa_id, alias in db.execute(select(VmRefGhsaAlias.ghsa_id, VmRefGhsaAlias.alias)
                .where(VmRefGhsaAlias.ghsa_id.in_(chunk))
                .order_by(VmRefGhsaAlias.ghsa_id, VmRefGhsaAlias.alias)
                .limit(len(chunk) * (MAX_EQUIVALENTS + 1))):
            if len(groups[ghsa_id]) <= MAX_EQUIVALENTS:
                groups[ghsa_id].add(alias)
    return groups, found


def _resolve(db: Session, identifiers: Sequence[str]) -> tuple[dict[str, set[str]], dict[str, VmRefGhsa]]:
    matches = {identifier: {_normalized(identifier)} for identifier in identifiers}
    advisories: dict[str, VmRefGhsa] = {}
    pending = set(matches)
    # Complete small components, rather than choosing a different representative
    # depending on the starting ID. Oversized components do not create aliases.
    for _ in range(MAX_EQUIVALENTS + 1):
        if not pending:
            break
        groups, rows = _groups(db, set().union(*(matches[key] for key in pending)))
        advisories.update(rows)
        index: dict[str, set[str]] = {}
        for group in groups.values():
            for identifier in group:
                index.setdefault(identifier, set()).update(group)
        for original in list(pending):
            current = matches[original]
            expanded = set(current)
            for identifier in current:
                expanded.update(index.get(identifier, ()))
            if len(expanded) > MAX_EQUIVALENTS:
                matches[original] = {_normalized(original)}
                pending.remove(original)
            elif expanded == current:
                pending.remove(original)
            else:
                matches[original] = expanded
    for original, matched in matches.items():
        matched.add(original)
    return matches, advisories


def equivalents(db: Session, identifier: str) -> set[str]:
    """Original ID plus a complete active alias component, bounded to 256 canonical IDs."""
    return _resolve(db, [identifier])[0][identifier]


def public_advisories(db: Session, identifier: str) -> list[VmRefGhsa]:
    ids = equivalents(db, identifier)
    candidates = select(VmRefGhsa.ghsa_id).where(VmRefGhsa.ghsa_id.in_(ids)).union(
        select(VmRefGhsaAlias.ghsa_id).where(VmRefGhsaAlias.alias.in_(ids)),
    )
    return list(db.scalars(select(VmRefGhsa).where(
        VmRefGhsa.ghsa_id.in_(candidates),
    ).order_by(VmRefGhsa.reviewed.desc(), VmRefGhsa.ghsa_id).limit(MAX_EQUIVALENTS)))


def public_packages(db: Session, ghsa_ids: Iterable[str]) -> list[VmRefGhsaPackage]:
    ids = sorted(set(ghsa_ids))[:MAX_EQUIVALENTS]
    if not ids:
        return []
    return list(db.scalars(select(VmRefGhsaPackage).where(VmRefGhsaPackage.ghsa_id.in_(ids))
                          .order_by(VmRefGhsaPackage.ghsa_id, VmRefGhsaPackage.position).limit(4096)))


@dataclass
class ReferenceMetrics:
    identifiers: frozenset[str]
    nvd: VmRefNvd | None = None
    ghsa: VmRefGhsa | None = None
    epss: VmRefEpss | None = None
    kev: VmRefKev | None = None
    exploit_types: list[str] = field(default_factory=list)
    msf_ranks: list[int] = field(default_factory=list)


def reference_metrics(db: Session, identifiers: Sequence[str]) -> dict[str, ReferenceMetrics]:
    """NVD/EPSS/KEV direct rows first; GHSA is an active fallback, not an EPSS estimate."""
    matches, advisories = _resolve(db, identifiers)
    expanded = sorted(set().union(*matches.values())) if matches else []
    nvd: dict[str, VmRefNvd] = {}
    epss: dict[str, VmRefEpss] = {}
    kev: dict[str, VmRefKev] = {}
    exploits: dict[str, dict[int, str]] = {}
    modules: dict[str, dict[str, int]] = {}
    for start in range(0, len(expanded), BATCH):
        chunk = expanded[start:start + BATCH]
        nvd.update((r.cve_id, r) for r in db.scalars(select(VmRefNvd).where(VmRefNvd.cve_id.in_(chunk))))
        epss.update((r.cve_id, r) for r in db.scalars(select(VmRefEpss).where(VmRefEpss.cve_id.in_(chunk))))
        kev.update((r.cve_id, r) for r in db.scalars(select(VmRefKev).where(VmRefKev.cve_id.in_(chunk))))
        for cve_id, exploit_id, kind in db.execute(
            select(VmRefExploitdbCve.cve_id, VmRefExploitdb.exploit_id, VmRefExploitdb.type)
            .join(VmRefExploitdb, VmRefExploitdb.exploit_id == VmRefExploitdbCve.exploit_id)
            .where(VmRefExploitdbCve.cve_id.in_(chunk)),
        ):
            exploits.setdefault(cve_id, {})[exploit_id] = kind
        for cve_id, name, rank in db.execute(
            select(VmRefMsfCve.cve_id, VmRefMsf.fullname, VmRefMsf.rank)
            .join(VmRefMsf, VmRefMsf.fullname == VmRefMsfCve.fullname)
            .where(VmRefMsfCve.cve_id.in_(chunk)),
        ):
            modules.setdefault(cve_id, {})[name] = rank
    result: dict[str, ReferenceMetrics] = {}
    for original, related in matches.items():
        ordered = [original, *sorted(related - {original})]
        ghsa = sorted((advisories[key] for key in related if key in advisories),
                      key=lambda row: (row.ghsa_id != _normalized(original), not row.reviewed,
                                       row.cvss is None, row.ghsa_id))
        exploit_union = {key: value for identifier in ordered for key, value in exploits.get(identifier, {}).items()}
        module_union = {key: value for identifier in ordered for key, value in modules.get(identifier, {}).items()}
        nvd_rows = [nvd[key] for key in ordered if key in nvd]
        usable_nvd = next((row for row in nvd_rows
                           if row.cvss_v3 is not None or row.cvss_v2 is not None), None)
        result[original] = ReferenceMetrics(
            identifiers=frozenset(related),
            nvd=usable_nvd or next(iter(nvd_rows), None),
            ghsa=ghsa[0] if ghsa else None,
            epss=next((epss[key] for key in ordered if key in epss), None),
            kev=next((kev[key] for key in ordered if key in kev), None),
            exploit_types=list(exploit_union.values()), msf_ranks=list(module_union.values()),
        )
    return result


def canonical_finding_id(identifier: ColumnElement[Any]) -> ColumnElement[Any]:
    """SQL identity used only for counting equal package findings, never persisted."""
    advisory = aliased(VmRefGhsa)
    link = aliased(VmRefGhsaAlias)
    normalized = case(
        (func.upper(identifier).like("GHSA-%"), literal("GHSA-") + func.lower(func.substr(identifier, 6))),
        (func.upper(identifier).like("CVE-%"), func.upper(identifier)),
        else_=identifier,
    )
    # Follow only indexed neighbors of each reached ID. Keeping the conditions
    # inside LATERAL prevents a full-catalogue edge scan at every recursive step.
    nodes = select(normalized.label("identifier")).correlate_except().cte(
        "ghsa_component", recursive=True, nesting=True,
    )
    neighbors = union_all(
        select(link.alias.label("identifier"))
        .join(advisory, advisory.ghsa_id == link.ghsa_id)
        .where(link.ghsa_id == nodes.c.identifier, advisory.withdrawn.is_(None))
        .correlate(nodes),
        select(link.ghsa_id.label("identifier"))
        .join(advisory, advisory.ghsa_id == link.ghsa_id)
        .where(link.alias == nodes.c.identifier, advisory.withdrawn.is_(None))
        .correlate(nodes),
    ).lateral("alias_neighbors")
    nodes = nodes.union(select(neighbors.c.identifier).select_from(nodes.join(neighbors, true())))
    bounded = select(nodes.c.identifier).limit(MAX_EQUIVALENTS + 1).subquery("bounded_aliases")
    representative = func.coalesce(
        func.min(case((bounded.c.identifier.like("CVE-%"), bounded.c.identifier))),
        func.min(case((bounded.c.identifier.like("GHSA-%"), bounded.c.identifier))),
        func.min(bounded.c.identifier),
    )
    return select(case((func.count() <= MAX_EQUIVALENTS, representative), else_=normalized))        .select_from(bounded).correlate_except(bounded).scalar_subquery()
