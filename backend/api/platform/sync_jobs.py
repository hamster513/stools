"""Запуск штатной задачи синхронизации из тика планировщика."""
from collections.abc import Callable

from fastapi import HTTPException
from sqlalchemy.orm import Session

from api.platform.scheduler import Handler, PlatformSchedule

Submit = Callable[[Callable[[], None]], None]


def scheduled(start: Callable[[Session, str, Submit], int]) -> Handler:
    def handle(db: Session, schedule: PlatformSchedule) -> int | None:
        from api import collector_routes

        try:
            return start(db, collector_routes.SCHEDULE_STARTED_BY, collector_routes.spawn)
        except HTTPException as exc:
            if exc.status_code == 409:
                return None  # Идущая задача освободит слот, повторяем на следующем тике.
            if exc.status_code == 400:
                schedule.enabled = False  # Подключение больше не настроено.
                return None
            raise

    return handle
