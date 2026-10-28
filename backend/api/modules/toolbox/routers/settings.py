"""Настройки ToolBox (спека §6): слова, подсети, срок хранения файлов. Ключ HMAC наружу не отдаётся."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.audit import changes_summary
from api.db.base import get_db
from api.modules.toolbox.services.dictionaries import RulesError, parse_subnets
from api.modules.toolbox.services.scrub import get_settings_row
from api.platform.services.access import Access, allows
from api.rbac import current_access

router = APIRouter(prefix="/settings", tags=["toolbox"])


class WordIn(BaseModel):
    word: str = Field(min_length=1, max_length=255)
    alias: str = Field(default="", max_length=255)


class SubnetIn(BaseModel):
    cidr: str = Field(max_length=64)
    to: str = Field(max_length=64)


class ToolboxSettingsIn(BaseModel):
    words: list[WordIn] = Field(default_factory=list, max_length=1000)
    subnets: list[SubnetIn] = Field(default_factory=list, max_length=1000)
    retention_days: int = Field(default=7, ge=0, le=3650)


def require_admin(access: Access) -> None:
    if not allows(access, "toolbox", "admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="нет доступа: toolbox, нужен уровень администратор")


@router.get("", response_model=ToolboxSettingsIn)
def get_settings(db: Session = Depends(get_db), access: Access = Depends(current_access)) -> ToolboxSettingsIn:
    # Настройки — только администратору (спека §6): в словах и подсетях — настоящие значения.
    require_admin(access)
    row = get_settings_row(db)
    return ToolboxSettingsIn.model_validate(
        {"words": row.words, "subnets": row.subnets, "retention_days": row.retention_days},
    )


@router.put("", response_model=ToolboxSettingsIn)
def put_settings(
    payload: ToolboxSettingsIn, request: Request, db: Session = Depends(get_db), access: Access = Depends(current_access),
) -> ToolboxSettingsIn:
    require_admin(access)
    data = payload.model_dump()
    try:
        parse_subnets(data["subnets"])
    except RulesError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from None
    # Одинаковые слова или псевдонимы слов дали бы одно значение двум псевдонимам или наоборот.
    for field in ("word", "alias"):
        values = [w[field].lower() for w in data["words"] if w[field]]
        if len(values) != len(set(values)):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"повторяется {field} в списке слов")
    row = get_settings_row(db)
    changed = [name for name in ("words", "subnets", "retention_days") if getattr(row, name) != data[name]]
    row.words, row.subnets, row.retention_days = data["words"], data["subnets"], data["retention_days"]
    db.commit()
    request.state.audit_summary = changes_summary(changed)
    return ToolboxSettingsIn(**data)
