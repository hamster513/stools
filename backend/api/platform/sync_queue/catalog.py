"""Queueable targets deliberately exclude hunting and internal maintenance jobs."""
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import HTTPException
from sqlalchemy.orm import Session

from api.platform.services.access import Access, allows


@dataclass(frozen=True)
class Task:
    module: str
    kind: str
    target_id: int
    title: str

    @property
    def key(self) -> str:
        return f"{self.module}/{self.kind}/{self.target_id}"

    @property
    def level(self) -> Literal["admin", "write"]:
        if self.module in ("platform", "attack") or (self.module == "vm" and (self.kind.startswith("ref_") or self.kind == "archive_import")):
            return "admin"
        return "write"

    @property
    def dependency_allowed(self) -> bool:
        # Cleanup produces no reusable source; downloading ATT&CK still requires confirmation.
        return (self.module, self.kind) not in {("platform", "storage_cleanup"), ("attack", "download"), ("vm", "archive_import")}


def targets(db: Session) -> list[Task]:
    from api.platform.routers.schedules import _sources
    return [Task(module, target.kind, target.id, target.title)
            for module in ("ad", "ksc", "vm", "assets", "siem", "attack", "platform")
            for target in _sources(db, module)]


def resolve(db: Session, key: str) -> Task:
    # Uploaded files can be queued, but cannot be scheduled or used as a reusable source.
    if key == "vm/archive_import/0":
        return Task("vm", "archive_import", 0, "Импорт пачки архивов VM")
    for task in targets(db):
        if task.key == key:
            return task
    raise HTTPException(404, "Задача больше не существует или не входит в общий планировщик")


def authorized(task: Task, access: Access, *, configure: bool = False, options: dict[str, Any] | None = None) -> None:
    reset = task.key == "vm/trends_pull/0" and (options or {}).get("reset")
    level = "admin" if configure or reset else task.level
    if not allows(access, task.module, level):
        raise HTTPException(403, "Недостаточно прав для задачи или её зависимости")


def is_queueable(module: str, kind: str) -> bool:
    return ((module in ("ad", "ksc") and kind == "collect")
            or (module == "assets" and kind in ("sync", "dns", "rt"))
            or (module == "vm" and (kind in ("import_vm", "harbor", "trends_pull") or kind.startswith("ref_")))
            or (module == "siem" and kind in ("kb_collect", "logons"))
            or (module == "platform" and kind in ("storage", "storage_cleanup", "assets_read_refresh"))
            or (module == "attack" and kind == "download"))
