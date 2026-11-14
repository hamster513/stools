"""Administrative API for exported previews and isolated diagnostic workspaces."""

from contextlib import contextmanager
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, Response, UploadFile
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.assets.models import Asset, AssetUser
from api.platform.search.models import SearchRequest, SearchResult
from api.platform.search.service import search
from api.platform.services.access import allows
from api.rbac import current_access
from api.settings import Settings, get_settings

from . import storage, workspace


def diagnostic_access(
    access: Annotated[dict, Depends(current_access)],
    user: Annotated[AppUser, Depends(get_current_user)],
):
    if not allows(access, "platform", "admin") or any(
        not allows(access, area, "read") for area in workspace.ACCESS
    ):
        raise HTTPException(403, "Нужны права администратора платформы и чтение AD, Assets и AV.")
    return user


router = APIRouter(
    prefix="/api/settings/diagnostics",
    tags=["diagnostics"],
    dependencies=[Depends(diagnostic_access)],
)


class ExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["user", "host"]
    entity_id: int = Field(gt=0)


def package_store(settings: Annotated[Settings, Depends(get_settings)]):
    return storage.PackageStore(settings.data_dir)


@contextmanager
def export_snapshot(db):
    """Read one consistent source snapshot without changing the caller's transaction."""
    bind = db.get_bind()
    if bind.dialect.name == "postgresql":
        engine = getattr(bind, "engine", bind)
        with (
            engine.connect().execution_options(
                isolation_level="REPEATABLE READ", postgresql_readonly=True
            ) as connection,
            connection.begin(),
            Session(connection, autoflush=False) as snapshot,
        ):
            yield snapshot
    else:
        with Session(bind, autoflush=False) as snapshot:
            yield snapshot


def _failure(exc):
    if isinstance(exc, FileNotFoundError):
        return HTTPException(404, "Диагностический пакет не найден или срок хранения истёк.")
    return HTTPException(422, "Некорректный или неподдерживаемый диагностический пакет.")


@router.get("/candidates")
def candidates(
    db: Annotated[Session, Depends(get_db)],
    query: str = Query(min_length=1, max_length=255),
    kind: Literal["user", "host"] = "host",
):
    query = query.strip()
    if not query or any(ord(char) < 32 for char in query):
        return {"items": []}
    model = Asset if kind == "host" else AssetUser
    columns = (
        (Asset.name, Asset.fqdn, Asset.ip)
        if kind == "host"
        else (AssetUser.sam, AssetUser.upn, AssetUser.display_name, AssetUser.name_key)
    )
    rows = db.scalars(
        select(model)
        .where(
            model.merged_into.is_(None),
            or_(
                *(func.lower(column).contains(query.lower(), autoescape=True) for column in columns)
            ),
        )
        .order_by(model.id)
        .limit(20)
    )
    return {
        "items": [
            {
                "id": row.id,
                "kind": kind,
                "title": (row.fqdn or row.name or row.ip)
                if kind == "host"
                else (row.display_name or row.upn or row.sam),
                "subtitle": row.domain,
            }
            for row in rows
        ]
    }


_EXPORT_FAILURE = (
    "Не удалось подготовить диагностический пакет. Проверьте выбранный объект и полноту снимков."
)
_EXPORT_REASONS = {
    "Diagnostic record limit exceeded.": "Пакет превышает лимит 5000 записей. Выберите объект с меньшим числом связей.",
    "Diagnostic source size limit exceeded.": "Превышен допустимый размер исходного снимка для диагностического пакета.",
    "Selected entity is unavailable.": "Выбранный объект недоступен. Обновите поиск и выберите объект снова.",
    "Latest directory export is unavailable or unsupported.": "Последний снимок AD недоступен или имеет неподдерживаемый формат. Проверьте сохранённую выгрузку AD.",
    "Unsupported directory identity.": "Обнаружен неподдерживаемый идентификатор AD. Проверьте исходный снимок AD.",
}


@router.post("/exports")
def create_export(
    payload: ExportRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    user: Annotated[AppUser, Depends(diagnostic_access)],
    store: Annotated[storage.PackageStore, Depends(package_store)],
):
    from .exporter import BundleError, build_bundle

    request.state.audit_summary = "Подготовлен обезличенный диагностический пакет"
    try:
        with export_snapshot(db) as snapshot:
            bundle = build_bundle(snapshot, settings.data_dir, payload.kind, payload.entity_id)
        return store.create_export(bundle, user.id)
    except BundleError as exc:
        raise HTTPException(422, _EXPORT_REASONS.get(str(exc), _EXPORT_FAILURE)) from None
    except (ValueError, SQLAlchemyError):
        raise HTTPException(422, _EXPORT_FAILURE) from None


@router.get("/exports/{package_id}/download")
def download_export(
    package_id: str,
    user: Annotated[AppUser, Depends(diagnostic_access)],
    store: Annotated[storage.PackageStore, Depends(package_store)],
):
    try:
        data = store.download_export(package_id, user.id)
    except (ValueError, OSError) as exc:
        raise _failure(exc) from None
    return Response(
        data,
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="diagnostic-package.zip"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/imports")
def list_imports(store: Annotated[storage.PackageStore, Depends(package_store)]):
    return {"items": store.list_imports()}


@router.post("/imports")
def import_package(
    request: Request,
    file: Annotated[UploadFile, File()],
    store: Annotated[storage.PackageStore, Depends(package_store)],
):
    request.state.audit_summary = "Импортирован изолированный диагностический пакет"
    try:
        data = file.file.read(storage.MAX_COMPRESSED + 1)
        return store.import_archive(data)
    except (ValueError, OSError, SQLAlchemyError, KeyError, StopIteration) as exc:
        raise _failure(exc) from None
    finally:
        file.file.close()


@router.delete("/imports/{package_id}", status_code=204)
def delete_import(
    package_id: str,
    request: Request,
    store: Annotated[storage.PackageStore, Depends(package_store)],
):
    request.state.audit_summary = "Удалён диагностический пакет"
    try:
        store.delete_import(package_id)
    except (ValueError, OSError) as exc:
        raise _failure(exc) from None
    return Response(status_code=204)


@router.post("/imports/{package_id}/search", response_model=SearchResult)
def search_import(
    package_id: str,
    payload: SearchRequest,
    request: Request,
    store: Annotated[storage.PackageStore, Depends(package_store)],
):
    request.state.audit_summary = "Просмотр изолированного диагностического досье"
    try:
        directory = store.import_path(package_id)
        with workspace.open_dataset(directory) as db:
            result = search(db, payload, workspace.ACCESS, directory)
            return workspace.without_live_links(result.model_dump(mode="json"))
    except (ValueError, OSError, SQLAlchemyError) as exc:
        raise _failure(exc) from None
