"""Таблицы модуля attack. Таблицы базы знаний ATT&CK остаются в api/db/models.py."""
from __future__ import annotations

from api.db.models import Base
from api.jobs import JobColumns


class AttackJob(JobColumns, Base):
    """Фоновая задача модуля. kind: translate | download."""

    __tablename__ = "attack_job"
