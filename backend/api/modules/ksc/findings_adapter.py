"""Находки антивируса на общих статусах платформы (спека §3): область —
сервер KSC, свежие данные — находки последнего снапшота сервера."""
from __future__ import annotations

from api.collector_findings import SnapshotFindingAdapter
from api.modules.ksc.core.checks import CHECK_BY_CODE
from api.modules.ksc.models import KscFinding, KscServer, KscSnapshot


def _title(f: KscFinding) -> str:
    spec = CHECK_BY_CODE.get(f.check)
    return f"{spec.title if spec else f.check}: {f.host or f.target}"


ADAPTER = SnapshotFindingAdapter(
    module="ksc", scope_model=KscServer, snapshot_model=KscSnapshot, finding_model=KscFinding,
    owner="server_id", path="/ksc/servers/{scope_id}/findings", title=_title, title_fields=("host", "target"),
)
