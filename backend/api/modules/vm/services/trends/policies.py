import datetime as dt
from typing import Literal
from pydantic import BaseModel,Field,field_validator
from sqlalchemy import select,or_
from api.modules.vm.trend_models import VmTrendPolicy


class LocalPolicy(BaseModel):
    scope: Literal['publication','cve_product','match','cve_global']
    target_key: str = Field(min_length=1,max_length=2000)
    reason: str = Field(min_length=5,max_length=2000)
    expires_at: dt.datetime | None = None
    enabled: bool = True
    version: int = Field(default=0,ge=0)
    @field_validator('reason','target_key')
    @classmethod
    def nonblank(cls,value):
        if not value.strip(): raise ValueError('Поле не должно быть пустым')
        return value.strip()
    @field_validator('expires_at')
    @classmethod
    def aware(cls,value):
        if value and value.tzinfo is None: raise ValueError('Укажите часовой пояс')
        return value


def view(row):
    return {k:getattr(row,k) for k in ('id','scope','target_key','reason','expires_at','enabled','version','actor','history')} | {
        'active':row.enabled and (not row.expires_at or row.expires_at>dt.datetime.now(dt.UTC))}


def active_policies(db):
    return db.scalars(select(VmTrendPolicy).where(VmTrendPolicy.enabled.is_(True),
        or_(VmTrendPolicy.expires_at.is_(None),VmTrendPolicy.expires_at>dt.datetime.now(dt.UTC))).limit(5000)).all()


def save_policy(db,payload,actor,id_=None):
    row=db.get(VmTrendPolicy,id_,with_for_update=True) if id_ else None
    if id_ and row is None: raise KeyError(id_)
    if row and (row.version!=payload.version or row.scope!=payload.scope or row.target_key!=payload.target_key):
        raise ValueError('Версия или область исключения изменена; обновите страницу')
    if not row:
        if payload.version: raise ValueError('Неверная версия новой записи')
        row=VmTrendPolicy(scope=payload.scope,target_key=payload.target_key,version=0,history=[]); db.add(row)
    audit=payload.model_dump(mode='json'); audit.update(actor=actor,at=dt.datetime.now(dt.UTC).isoformat())
    row.history=[*row.history,audit]; row.reason=payload.reason; row.expires_at=payload.expires_at
    row.enabled=payload.enabled; row.actor=actor; row.version+=1
    db.commit(); db.refresh(row)
    return view(row)


def publication_policy(policies,card_id,publication_key):
    return next((p for p in policies if (p.scope=='publication' and p.target_key==publication_key)
        or (p.scope=='cve_global' and p.target_key==card_id)),None)


def match_policy(policies,card_id,kind,id_,product=''):
    return next((p for p in policies if (p.scope=='match' and p.target_key==f'{card_id}|{kind}:{id_}')
        or (p.scope=='cve_product' and p.target_key==f'{card_id}|{product}')
        or (p.scope=='cve_global' and p.target_key==card_id)),None)


def visible_match(cve_column, id_column, kind, product_column=None):
    from sqlalchemy import and_,func
    keys = [and_(VmTrendPolicy.scope == "cve_global", VmTrendPolicy.target_key == func.upper(cve_column)),
        and_(VmTrendPolicy.scope == "match", VmTrendPolicy.target_key == func.concat(func.upper(cve_column), "|", kind, ":", id_column))]
    if product_column is not None:
        keys.append(and_(VmTrendPolicy.scope == "cve_product", VmTrendPolicy.target_key == func.concat(func.upper(cve_column), "|", product_column)))
    return ~select(VmTrendPolicy.id).where(VmTrendPolicy.enabled.is_(True),
        or_(VmTrendPolicy.expires_at.is_(None),VmTrendPolicy.expires_at>dt.datetime.now(dt.UTC)),or_(*keys)).exists()
