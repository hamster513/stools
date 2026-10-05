"""Находки антивируса на общих статусах платформы (спека §3): область —
сервер KSC, свежие данные — находки последнего снапшота сервера."""
from __future__ import annotations

import json

from api.collector_findings import SnapshotFindingAdapter
from api.modules.ksc.core.checks import CHECK_BY_CODE
from api.modules.ksc.models import KscFinding, KscServer, KscSnapshot
from api.modules.ksc.services.grade import GRADE_CHECKS


def _title(f: KscFinding) -> str:
    spec = CHECK_BY_CODE.get(f.check)
    return f"{spec.title if spec else f.check}: {f.host or f.target}"


#: Проверки сверки с AD: без снапшота AD для доменов сервера они не проверяются.
_AD_COVERAGE = frozenset({"COVER_AD_MISSING", "COVER_KSC_ONLY"})


def _unchecked(snapshot: KscSnapshot) -> set[str]:
    """Сверка с AD без снапшота AD; проверки по содержимому политик (`GRADE_CHECKS`), если у какой-то активной политики защиты
    содержимое не собрано («не собрано» ≠ «пусто»; грубо — по проверке, а не по политике). `POLICY_CONTENT_MISSING` сюда не
    входит: она сама и есть признак несобранного."""
    stats = json.loads(snapshot.stats_json or "{}")
    coverage = stats.get("coverage") or {}
    out = set(_AD_COVERAGE) if coverage.get("ad_total") is None else set()
    if (stats.get("policies") or {}).get("without_contents"):
        out |= GRADE_CHECKS
    return out


ADAPTER = SnapshotFindingAdapter(
    module="ksc", scope_model=KscServer, snapshot_model=KscSnapshot, finding_model=KscFinding,
    owner="server_id", path="/ksc/servers/{scope_id}/findings", title=_title, title_fields=("host", "target"),
    unchecked=_unchecked,
)
