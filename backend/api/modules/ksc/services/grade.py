"""Оценка политики «плохая / нормальная / хорошая» по считаемым находкам правил оценки.

Находка относится к политике по `details["policy_id"]`; считается ли она — по статусу платформы и настройке `counted`, как
счётчик находок хоста (`routers/hosts.py`). `bad` — среди считаемых есть Critical или High, `ok` — только Medium или Low,
`good` — нет ни одной из них. Без оценки (`None`) — содержимого нет, политика неактивна, словаря продукта нет, словарь не
распознал ни одной настройки политики (правила молчат от незнания — это не «хорошая») или снапшот посчитан анализатором
другой версии (у находок прежних версий нет `policy_id`).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.ksc.core.checks import ANALYZER_VERSION, CHECKS
from api.modules.ksc.core.dictionary import dictionary_for
from api.modules.ksc.models import KscFinding, KscPolicy, KscSnapshot
from api.platform.findings import service as finding_svc

#: Проверки, находки которых портят оценку политики: все `POLICY_*`, кроме проверок групп и справочной «не собрано».
GRADE_CHECKS: frozenset[str] = frozenset(
    c.code for c in CHECKS if c.code.startswith("POLICY_") and c.code not in {"POLICY_NONE", "POLICY_INHERIT_BROKEN", "POLICY_CONTENT_MISSING"}
)
GRADES = ("bad", "ok", "good")
OLD_ANALYZER = "пересчитайте снапшот: оценка считается с версии анализатора 2"


@dataclass(frozen=True)
class GradeFinding:
    finding: KscFinding
    details: dict[str, Any]
    #: Статус платформы («new», если строки состояния нет).
    status: str
    counted: bool


def policy_findings(db: Session, snapshot: KscSnapshot) -> dict[int, list[GradeFinding]]:
    """Находки оценки снапшота по id политики со статусами; находки без `details.policy_id` не относятся ни к одной."""
    rows = list(db.scalars(select(KscFinding).where(KscFinding.snapshot_id == snapshot.id, KscFinding.check.in_(GRADE_CHECKS))))
    states = finding_svc.state_map(db, "ksc", snapshot.server_id, [f.key for f in rows])
    counted = finding_svc.counted_statuses(db)
    out: dict[int, list[GradeFinding]] = {}
    for f in rows:
        details = json.loads(f.details_json or "{}")
        policy_id = details.get("policy_id")
        if not isinstance(policy_id, int):
            continue
        status = finding_svc.effective_status(states.get(f.key))
        out.setdefault(policy_id, []).append(GradeFinding(f, details, status, status in counted))
    return out


def _grade(p: KscPolicy, counted: list[GradeFinding], old: bool) -> tuple[str | None, str]:
    if not p.has_contents:
        return None, "содержимое не собрано"
    if not p.active:
        return None, "политика неактивна"
    if dictionary_for(p.product) is None:
        return None, "структура продукта не описана"
    if p.settings_known == 0:
        return None, "настройки политики не распознаны словарём"
    if old:
        return None, OLD_ANALYZER
    severities = {g.finding.severity for g in counted}
    if severities & {"Critical", "High"}:
        return "bad", "есть считаемые находки Critical или High"
    if severities & {"Medium", "Low"}:
        return "ok", "есть считаемые находки Medium или Low, нет Critical и High"
    return "good", "нет считаемых находок Critical, High, Medium, Low"


def policy_grades(db: Session, snapshot: KscSnapshot) -> dict[int, tuple[str | None, str, int]]:
    """policy_id → (оценка `bad` | `ok` | `good` | None, причина, считаемых находок оценки) для всех политик снапшота."""
    found = policy_findings(db, snapshot)
    old = snapshot.analyzer_version != ANALYZER_VERSION
    out: dict[int, tuple[str | None, str, int]] = {}
    for p in db.scalars(select(KscPolicy).where(KscPolicy.snapshot_id == snapshot.id)):
        counted = [g for g in found.get(p.policy_id, []) if g.counted]
        grade, reason = _grade(p, counted, old)
        out[p.policy_id] = (grade, reason, len(counted))
    return out
