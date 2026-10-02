"""Находки AD на общих статусах платформы (спека §3): область — домен,
свежие данные — находки последнего снапшота домена."""
from __future__ import annotations

from api.collector_findings import SnapshotFindingAdapter
from api.modules.ad.core.checks import CHECK_BY_CODE
from api.modules.ad.models import AdDomain, AdFinding, AdSnapshot


def _title(f: AdFinding) -> str:
    spec = CHECK_BY_CODE.get(f.check)
    return f"{spec.title if spec else f.check}: {f.identity or f.target}"


ADAPTER = SnapshotFindingAdapter(
    module="ad", scope_model=AdDomain, snapshot_model=AdSnapshot, finding_model=AdFinding,
    owner="domain_id", path="/ad/domains/{scope_id}/findings", title=_title, title_fields=("identity", "target"),
)
