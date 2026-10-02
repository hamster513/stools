"""вердикты SIEM → статусы находок; старая таблица — в архив

Revision ID: c6d7e8f9a0b1
Revises: b5c6d7e8f9a0
Create Date: 2026-10-02 00:00:00.000000

`in_progress` становится «В работе», `accepted` — «Принят риск» с тем же
обоснованием, автором и датой и событием `migrated` в истории. Строки
`open` не переносятся: строка «открыта» — то же, что её отсутствие, а ручка
вердиктов такие строки удаляла. Переносятся только вердикты с
`key_kind = 'uuid'`: по имени (`name`) код вердикты не писал и не читал
никогда, они остаются только в архиве.

Ключ — как в api/modules/siem/findings_adapter.py (`finding_key`): подпись с
солью установки, без хеша значения. Соль заводится здесь же в `app_setting`
и при `downgrade` не удаляется — повторный `upgrade` даёт те же ключи.
`present`, подпись и тяжесть — по активному снапшоту (последнему разобранному).

Таблица вердиктов не удаляется, а переименовывается в
`finding_verdict_archive_20261002`. `downgrade` возвращает её и удаляет
строки состояния SIEM с событием `migrated`. Он теряет то, что сделано
после миграции: смены статусов перенесённых находок и новые строки
состояния SIEM в старую таблицу не возвращаются (новые строки остаются в
`platform_finding_state`).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import secrets
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c6d7e8f9a0b1"
down_revision: str | Sequence[str] | None = "b5c6d7e8f9a0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "finding_verdict"
ARCHIVE = TABLE + "_archive_20261002"
SALT_SETTING = "siem_finding_key"
STATUS = {"in_progress": "in_work", "accepted": "risk_accepted"}
KIND_TITLES = {1: "дублирует список", 2: "IP / CIDR / FQDN", 3: "not in_list из 3+", 4: "доменный SID", 5: "одиночный литерал"}


def _key(salt: bytes, object_uuid: str, kind: int, field: str, value_hash: str) -> str:
    """Копия findings_adapter.finding_key: миграция не зависит от будущих правок кода."""
    sign = hmac.new(salt, f"{object_uuid}|{kind}|{field}|{value_hash}".encode(), hashlib.sha256).hexdigest()
    return f"{object_uuid}|{kind}|{sign[:32]}"


def _salt(conn: sa.Connection) -> bytes:
    conn.execute(sa.text(
        "INSERT INTO app_setting (key, value_json, updated_at, updated_by) VALUES (:k, :v, now(), 'system') "
        "ON CONFLICT (key) DO NOTHING"
    ), {"k": SALT_SETTING, "v": json.dumps({"salt": secrets.token_hex(32)})})
    raw = conn.execute(sa.text("SELECT value_json FROM app_setting WHERE key = :k"), {"k": SALT_SETTING}).scalar_one()
    return bytes.fromhex(json.loads(raw)["salt"])


def upgrade() -> None:
    conn = op.get_bind()
    salt = _salt(conn)
    active = conn.execute(sa.text(
        "SELECT max(s.id) FROM snapshot s WHERE EXISTS (SELECT 1 FROM job j WHERE j.snapshot_id = s.id AND j.status = 'done')"
    )).scalar()
    present: dict[str, tuple[str, str]] = {}
    if active is not None:
        for uuid, name, kind, field, value_hash, severity in conn.execute(sa.text(
            "SELECT object_uuid, object_name, kind, field, value_hash, severity FROM finding WHERE snapshot_id = :s"
        ), {"s": active}):
            title = f"{name}: {KIND_TITLES.get(kind, f'класс {kind}')}, поле {field}"
            present[_key(salt, uuid, kind, field, value_hash)] = (title[:512], severity[:16])

    verdicts = conn.execute(sa.text(
        f"SELECT object_key, kind, field, value_hash, status, reason, decided_by, decided_at FROM {TABLE} "
        "WHERE key_kind = 'uuid' AND status IN ('in_progress', 'accepted') ORDER BY id"
    )).all()
    for uuid, kind, field, value_hash, old, reason, decided_by, decided_at in verdicts:
        key = _key(salt, uuid, kind, field, value_hash)
        status = STATUS[old]
        title, severity = present.get(key, ("", ""))
        at = decided_at or dt.datetime.now(dt.UTC)
        state_id = conn.execute(sa.text(
            "INSERT INTO platform_finding_state "
            "(module, scope_id, key, status, reason, present, title, severity, updated_by, updated_at) "
            "VALUES ('siem', 0, :key, :status, :reason, :present, :title, :severity, :by, :at) RETURNING id"
        ), {"key": key, "status": status, "reason": reason or "", "present": key in present, "title": title,
            "severity": severity, "by": decided_by or "", "at": at}).scalar_one()
        conn.execute(sa.text(
            "INSERT INTO platform_finding_event (state_id, at, actor, kind, from_status, to_status, comment, details) "
            "VALUES (:sid, :at, :actor, 'migrated', NULL, :status, :comment, CAST(:details AS jsonb))"
        ), {"sid": state_id, "at": at, "actor": decided_by or "system", "status": status, "comment": reason or "",
            "details": json.dumps({"from": TABLE, "status": old})})
    op.rename_table(TABLE, ARCHIVE)


def downgrade() -> None:
    op.rename_table(ARCHIVE, TABLE)
    op.execute(sa.text("""
        DELETE FROM platform_finding_state
        WHERE module = 'siem'
          AND id IN (SELECT state_id FROM platform_finding_event WHERE kind = 'migrated')
    """))
