from typing import Literal
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select,text
from api.modules.vm.trend_models import VmTrendIngestState,VmTrendPoc,VmTrendPocReview
from .monitoring_contracts import HttpUrl


class PocDecision(BaseModel):
    commit_sha: str = Field(pattern=r'^[a-f0-9]{40,64}$')
    version: int = Field(ge=0)
    state: Literal['confirmed','rejected','candidate']
    reason: str = Field(min_length=5,max_length=2000)
    evidence: list[HttpUrl] = Field(default_factory=list,max_length=20)
    @model_validator(mode='after')
    def require_evidence(self):
        if not self.reason.strip() or (self.state=='confirmed' and not self.evidence):
            raise ValueError('Подтверждение требует причины и ссылки на доказательство')
        return self


def list_pocs(db,cve_id):
    state=db.get(VmTrendIngestState,1)
    if not state or not state.active_generation: return []
    rows=db.scalars(select(VmTrendPoc).where(VmTrendPoc.generation==state.active_generation,VmTrendPoc.retracted.is_(False),
        VmTrendPoc.data['cve_id'].astext==cve_id).limit(100)).all()
    result=[]
    for row in rows:
        history=db.scalars(select(VmTrendPocReview).where(VmTrendPocReview.candidate_id==row.external_id).order_by(VmTrendPocReview.id.desc()).limit(100)).all()
        current=next((r for r in history if r.commit_sha==row.data.get('commit_sha')),None)
        result.append({**row.data,'id':row.external_id,'effective_state':current.state if current else row.data['state'],
            'decision_version':current.version if current else 0,'needs_recheck':not current and any(r.state=='confirmed' for r in history),
            'history':[{'actor':r.actor,'at':r.created_at,'commit_sha':r.commit_sha,'state':r.state,'reason':r.reason,'evidence':r.evidence} for r in history]})
    return result


def decide(db,identity,payload,actor):
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"),{'key':'trend_poc:'+identity})
    state=db.get(VmTrendIngestState,1)
    row=db.get(VmTrendPoc,(state.active_generation,identity)) if state else None
    if row is None or row.retracted: raise KeyError(identity)
    if row.data.get('commit_sha')!=payload.commit_sha: raise ValueError('SHA изменилась; откройте новую версию')
    latest=db.scalar(select(VmTrendPocReview).where(VmTrendPocReview.candidate_id==identity,
        VmTrendPocReview.commit_sha==payload.commit_sha).order_by(VmTrendPocReview.version.desc()).limit(1))
    version=latest.version if latest else 0
    if version!=payload.version: raise ValueError('Решение уже изменено другим аналитиком')
    db.add(VmTrendPocReview(candidate_id=identity,commit_sha=payload.commit_sha,version=version+1,actor=actor,
        state=payload.state,reason=payload.reason.strip(),evidence=payload.evidence))
    db.commit()
    return {'version':version+1,'state':payload.state}
