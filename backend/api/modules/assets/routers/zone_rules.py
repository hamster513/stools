"""Правила групп сетей (спека §4): по имени, тегу и адресу сети, по порядку, первое подошедшее.

Любая правка, удаление и перестановка пересчитывают группы всех не ручных сетей в той же транзакции.
Роутер подключается до `routers/networks.py`, иначе `/networks/{network_id}` перехватит `/networks/zone-rules`.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from fastapi import APIRouter, Body, Depends, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.assets.routers.networks import _errors
from api.modules.assets.services.networks import (
    apply_zone_rules,
    create_rule,
    delete_rule,
    get_rule,
    list_rules,
    preview_rule,
    reorder_rules,
    rule_networks,
    rule_view,
    update_rule,
)

router = APIRouter(prefix="/networks/zone-rules", tags=["assets"])


class RuleIn(BaseModel):
    #: name_prefix | name_contains | name_regex | tag | cidr — проверяет ядро (русский текст ошибки).
    match: str = Field(max_length=32)
    value: str = Field(max_length=500)
    zone: str = Field(max_length=64)
    enabled: bool = True
    note: str = Field(default="", max_length=4000)


class RuleView(BaseModel):
    id: int
    position: int
    enabled: bool
    zone: str
    match: str
    value: str
    note: str
    #: Сколько сетей сейчас в группе по этому правилу.
    networks: int
    created_at: dt.datetime
    updated_at: dt.datetime


class PreviewIn(BaseModel):
    match: str = Field(max_length=32)
    value: str = Field(max_length=500)
    zone: str = Field(max_length=64)
    #: Номер, на который встанет правило; не указан — в конец.
    position: int | None = Field(default=None, ge=1)


class PreviewSample(BaseModel):
    id: int
    cidr: str
    title: str
    zone_before: str | None


class PreviewView(BaseModel):
    count: int
    sample: list[PreviewSample]


class ApplyView(BaseModel):
    changed: int


@router.get("", response_model=list[RuleView])
def get_rules(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[dict[str, Any]]:
    return list_rules(db)


@router.post("", response_model=RuleView, status_code=status.HTTP_201_CREATED)
def post_rule(payload: RuleIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    rule = _errors(create_rule, db, payload.model_dump())
    db.commit()
    return rule_view(rule, rule_networks(db, rule.id))


@router.put("/order", response_model=list[RuleView])
def put_order(ids: list[int] = Body(...), db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[dict[str, Any]]:
    """Тело — id всех правил в новом порядке; объявлена до `/{rule_id}`."""
    _errors(reorder_rules, db, ids)
    db.commit()
    return list_rules(db)


@router.post("/preview", response_model=PreviewView)
def post_preview(payload: PreviewIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    """Число не ручных сетей, которые забрало бы правило, и первые 20; база не меняется."""
    result: dict[str, Any] = _errors(preview_rule, db, payload.model_dump())
    db.rollback()
    return result


@router.post("/apply", response_model=ApplyView)
def post_apply(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ApplyView:
    changed = apply_zone_rules(db)
    db.commit()
    return ApplyView(changed=changed)


@router.put("/{rule_id}", response_model=RuleView)
def put_rule(rule_id: int, payload: RuleIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    rule = _errors(get_rule, db, rule_id)
    _errors(update_rule, db, rule, payload.model_dump())
    db.commit()
    return rule_view(rule, rule_networks(db, rule.id))


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_rule(rule_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> Response:
    rule = _errors(get_rule, db, rule_id)
    delete_rule(db, rule)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
