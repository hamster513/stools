"""Адаптер статусов находок для модулей-сборщиков (AD, KSC; спека §3).

Модули устроены одинаково: область — домен или сервер, свежие данные —
находки последнего по времени сбора снапшота области. Отличаются модели,
колонка области у снапшота, подпись находки и путь страницы находок —
они приходят параметрами. Без зависимостей HTTP-слоя: адаптер вызывают
и сервисы импорта.
"""
from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from itertools import batched
from typing import Any
from urllib.parse import urlencode

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.platform.findings.adapters import CurrentFinding, safe_reconcile

log = logging.getLogger(__name__)
#: Ключей в одном IN — как у платформы.
_CHUNK = 5000


@dataclass
class SnapshotFindingAdapter:
    module: str
    scope_model: type[Any]
    snapshot_model: type[Any]
    finding_model: type[Any]
    #: Колонка области у снапшота: `domain_id`, `server_id`.
    owner: str
    #: Путь страницы находок области, `{scope_id}` подставляется.
    path: str
    #: Короткая подпись находки для «Моих находок».
    title: Callable[[Any], str]

    def _owner(self) -> Any:
        return getattr(self.snapshot_model, self.owner)

    def latest(self, db: Session, scope_id: int) -> Any | None:
        s = self.snapshot_model
        return db.scalars(
            select(s).where(self._owner() == scope_id).order_by(s.collected_at.desc(), s.id.desc())
        ).first()

    def _previous(self, db: Session, snapshot: Any) -> Any | None:
        s = self.snapshot_model
        return db.scalars(
            select(s).where(self._owner() == getattr(snapshot, self.owner), s.collected_at < snapshot.collected_at)
            .order_by(s.collected_at.desc(), s.id.desc())
        ).first()

    def _current_of(self, rows: Iterable[Any]) -> list[CurrentFinding]:
        return [CurrentFinding(key=f.key, title=self.title(f), severity=f.severity) for f in rows]

    def _findings(self, db: Session, snapshot_id: int) -> list[Any]:
        return list(db.scalars(select(self.finding_model).where(self.finding_model.snapshot_id == snapshot_id)))

    def scopes(self, db: Session) -> Iterable[int]:
        return list(db.scalars(select(self.scope_model.id).order_by(self.scope_model.id)))

    def has_scope(self, db: Session, scope_id: int) -> bool:
        return db.get(self.scope_model, scope_id) is not None

    def current(self, db: Session, scope_id: int) -> Iterable[CurrentFinding] | None:
        """Находки последнего снапшота; у области без снапшотов данных нет — None."""
        snap = self.latest(db, scope_id)
        return self._current_of(self._findings(db, snap.id)) if snap is not None else None

    def first_seen_many(self, db: Session, scope_id: int, keys: Iterable[str]) -> dict[str, dt.datetime]:
        return first_seen_map(db, self, scope_id, keys)

    def first_seen(self, db: Session, scope_id: int, key: str) -> dt.datetime | None:
        return first_seen_map(db, self, scope_id, [key]).get(key)

    def link(self, scope_id: int, key: str) -> str:
        return f"{self.path.format(scope_id=scope_id)}?{urlencode({'key': key})}"

    def reconcile(self, db: Session, scope_id: int) -> None:
        """Сверка статусов с последним снапшотом области — в конце импорта, пересчёта
        и удаления снапшота, после commit данных модуля. Пропавшие с предыдущего
        снапшота находки получают строки состояния, чтобы закрыться системой, а
        не исчезнуть молча. Область без снапшотов не сверяется: данных нет."""
        try:
            # Точка сохранения: сбой чтения откатывает только её, не работу вызывающего.
            with db.begin_nested():
                snap = self.latest(db, scope_id)
                if snap is None:
                    return
                prev = self._previous(db, snap)
                disappeared: list[CurrentFinding] = []
                if prev is not None:
                    now = {f.key for f in self._findings(db, snap.id)}
                    disappeared = self._current_of(f for f in self._findings(db, prev.id) if f.key not in now)
        # Данные модуля уже записаны: сбой здесь, как и в самой сверке, их не роняет.
        except Exception:
            log.exception("сверка статусов находок %s/%s не начата", self.module, scope_id)
            return
        safe_reconcile(db, self.module, scope_id, f"снапшот #{snap.id}", disappeared=disappeared)


def first_seen_map(db: Session, adapter: SnapshotFindingAdapter, scope_id: int, keys: Iterable[str]) -> dict[str, dt.datetime]:
    """Возраст находок: время сбора самого раннего снапшота области, где был ключ.
    Один запрос на пачку до `_CHUNK` ключей; ключей, которых в снапшотах нет, в ответе нет."""
    s, f = adapter.snapshot_model, adapter.finding_model
    found: dict[str, dt.datetime] = {}
    for chunk in batched(set(keys), _CHUNK):
        found.update((str(k), at) for k, at in db.execute(
            select(f.key, func.min(s.collected_at)).join(s, f.snapshot_id == s.id)
            .where(getattr(s, adapter.owner) == scope_id, f.key.in_(chunk)).group_by(f.key)
        ))
    return found


def last_known(db: Session, adapter: SnapshotFindingAdapter, scope_id: int, keys: Iterable[str]) -> list[Any]:
    """Находки, которых нет в последнем снапшоте: каждая — из самого позднего снапшота области, где была."""
    s, f = adapter.snapshot_model, adapter.finding_model
    found: list[Any] = []
    for chunk in batched(set(keys), _CHUNK):
        found.extend(db.scalars(
            select(f).join(s, f.snapshot_id == s.id)
            .where(getattr(s, adapter.owner) == scope_id, f.key.in_(chunk))
            .order_by(f.key, s.collected_at.desc(), s.id.desc()).distinct(f.key)
        ))
    return found
