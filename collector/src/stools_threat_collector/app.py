# ruff: noqa: B008 — FastAPI dependency declarations
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .contracts import Source, SourceUpdate
from .retention import RetentionPolicy
from .scheduler import Runner
from .monitoring_contracts import CollectionWindow
from . import management, monitoring


def create_app(store, run_scheduler=True):
    runner = Runner(store)

    @asynccontextmanager
    async def lifespan(app):
        if run_scheduler:
            runner.start()
        yield
        runner.close()

    app = FastAPI(title="STools threat collector", version="1", lifespan=lifespan, docs_url=None, redoc_url=None)
    bearer = HTTPBearer(auto_error=False)

    def reader(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
        scopes = store.scopes(credentials.credentials) if credentials else []
        if "data:read" not in scopes:
            raise HTTPException(401, "Collector token required")
        return scopes

    def writer(scopes=Depends(reader)):
        if "sources:write" not in scopes:
            raise HTTPException(403, "sources:write scope required")

    @app.get("/health/live")
    def live():
        return {"ok": True}

    @app.get("/health/ready")
    def ready():
        store.info()
        return {"ok": True}

    @app.get("/api/v1/info")
    def info(scopes=Depends(reader)):
        sizes = {}
        for key, suffix in [('database_bytes', ''), ('wal_bytes', '-wal'), ('shm_bytes', '-shm')]:
            try:
                sizes[key] = Path(str(store.path) + suffix).stat().st_size
            except FileNotFoundError:
                sizes[key] = 0
        return {**store.info(), "scopes": scopes, "storage_bytes": sizes['database_bytes'], "storage": sizes}

    @app.get("/api/v1/sources", dependencies=[Depends(reader)])
    def sources():
        return {"items": [store.public_source(row) for row in store.sources()]}

    @app.post("/api/v1/sources", dependencies=[Depends(writer)])
    def create_source(payload: Source):
        try:
            return store.public_source(store.save_source(payload.model_dump()))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.patch("/api/v1/sources/{id}", dependencies=[Depends(writer)])
    def update_source(id: str, payload: SourceUpdate):
        try:
            store.source(id)
            return store.public_source(store.save_source(payload.model_dump(), id))
        except KeyError as exc:
            raise HTTPException(404, "Source not found") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/v1/sources/{id}/collect", status_code=202, dependencies=[Depends(writer)])
    def collect(id: str, payload: CollectionWindow | None = None):
        try:
            return {"job_id": runner.submit(id, window=payload)}
        except KeyError as exc:
            raise HTTPException(404, "Source not found") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/v1/jobs/{id}", dependencies=[Depends(reader)])
    def job(id: str):
        try:
            try:
                return monitoring.run(store,id)
            except KeyError:
                return store.job(id)
        except KeyError as exc:
            raise HTTPException(404, "Job not found") from exc

    @app.get("/api/v1/changes", dependencies=[Depends(reader)])
    def changes(after: int = Query(0, ge=0), until: int | None = Query(None, ge=0), limit: int = Query(100, ge=1, le=500)):
        try:
            return store.changes(after, until, limit)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/v1/retention/preview", dependencies=[Depends(writer)])
    def retention_preview(payload: RetentionPolicy):
        return store.retention(payload.model_dump())

    @app.post("/api/v1/retention/run", dependencies=[Depends(writer)])
    def retention_run(payload: RetentionPolicy):
        return store.retention(payload.model_dump(), execute=True)

    @app.post("/api/v1/snapshots", dependencies=[Depends(reader)])
    def create_snapshot():
        try:
            return store.create_snapshot()
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/v1/snapshots/{snapshot_id}", dependencies=[Depends(reader)])
    def snapshot_page(snapshot_id: str, after: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500)):
        try:
            return store.snapshot_page(snapshot_id, after, limit)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    management.register(app,store,runner,reader,writer)
    return app
