"""Public queue API with per-target permissions, including dependency visibility."""
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.platform.services.access import Access, allows
from api.rbac import current_access

from . import service
from .catalog import targets
from .models import SyncRun

router = APIRouter(tags=["settings"])
Db = Annotated[Session, Depends(get_db)]
Permissions = Annotated[Access, Depends(current_access)]
User = Annotated[AppUser, Depends(get_current_user)]


class TaskIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    module: str = Field(max_length=32)
    kind: str = Field(max_length=32)
    target_id: int = Field(ge=0)
    options: dict[str, Any] = Field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.module}/{self.kind}/{self.target_id}"


class DependencyIn(TaskIn):
    max_age_minutes: int = Field(ge=1, le=43200)


class DependenciesIn(BaseModel):
    dependencies: list[DependencyIn] = Field(max_length=64)


class RunIn(BaseModel):
    tasks: list[TaskIn] = Field(min_length=1, max_length=100)


@router.get("/sync-tasks")
def catalog(db: Db, access: Permissions) -> dict[str, Any]:
    graph = service.configs(db)
    from .adapters import observations
    available = [task for task in targets(db) if allows(access, task.module, "read")]
    stamps = observations(db, available)
    items = []
    for task in available:
        needs = graph.get(task.key, [])
        # Do not disclose identifiers from inaccessible modules.
        shown = [e for e in needs if allows(access, e["key"].split("/")[0], "read")]
        items.append({"module": task.module, "kind": task.kind, "target_id": task.target_id,
                      "key": task.key, "title": task.title, "dependencies": shown,
                      "last_updated_at": stamps.get(task.key), "hidden_dependencies": len(needs) - len(shown),
                      "can_run": allows(access, task.module, task.level),
                      "can_configure": allows(access, task.module, "admin"), "dependency_allowed": task.dependency_allowed})
    return {"items": items}


@router.put("/schedules/{module}/{kind}/{target_id}/dependencies")
def set_dependencies(module: str, kind: str, target_id: int, payload: DependenciesIn,
                     db: Db, access: Permissions) -> dict[str, Any]:
    return {"dependencies": service.save_dependencies(db, f"{module}/{kind}/{target_id}",
            [{"key": e.key, "max_age_minutes": e.max_age_minutes} for e in payload.dependencies], access)}


@router.post("/sync-runs", status_code=202)
def submit(payload: RunIn, db: Db, access: Permissions, user: User) -> dict[str, Any]:
    run = service.enqueue(db, [{"key": task.key, "options": task.options} for task in payload.tasks],
                          actor=user.login, user_id=user.id, access=access)
    return service.view(db, run)


@router.get("/sync-runs")
def history(db: Db, access: Permissions, limit: Annotated[int, Query(ge=1, le=100)] = 30,
            before: Annotated[int | None, Query(ge=1)] = None) -> dict[str, Any]:
    query = select(SyncRun)
    if before is not None:
        query = query.where(SyncRun.id < before)
    rows = list(db.scalars(query.order_by(SyncRun.id.desc()).limit(limit)))
    return {"items": [service.view(db, run, include_result=False) for run in rows if service.visible(db, run, access)],
            "next_before": rows[-1].id if len(rows) == limit else None}


@router.get("/sync-runs/{run_id}")
def detail(run_id: int, db: Db, access: Permissions) -> dict[str, Any]:
    return service.view(db, service.get_run(db, run_id, access))


@router.post("/sync-runs/{run_id}/cancel")
def cancel(run_id: int, db: Db, access: Permissions) -> dict[str, Any]:
    run = service.get_run(db, run_id, access)
    service.cancel(db, run, access)
    return service.view(db, run)


@router.post("/sync-runs/{run_id}/retry", status_code=202)
def retry(run_id: int, db: Db, access: Permissions, user: User) -> dict[str, Any]:
    old = service.get_run(db, run_id, access)
    if old.status not in service.TERMINAL:
        raise HTTPException(409, "Запуск ещё не завершён")
    roots = [{"key": row.key, "options": row.options} for row in service.steps(db, old)
             if row.is_root and row.status not in service.SUCCESS]
    if not roots:
        raise HTTPException(409, "Нет незавершённых задач для повтора")
    run = service.enqueue(db, roots, actor=user.login, user_id=user.id, access=access)
    return service.view(db, run)
