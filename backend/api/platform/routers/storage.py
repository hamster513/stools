from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.platform import storage_retention as retention
from api.platform.storage_usage.service import history, measure

router = APIRouter(prefix='/storage', tags=['settings'])


@router.get('')
def get_storage(days: int = Query(30, ge=1, le=365), db: Session = Depends(get_db)):
    return history(db, days)


@router.post('/measure')
def measure_storage(db: Session = Depends(get_db)):
    result = measure(db, manual=True)
    db.commit()
    return result


class RetentionRunIn(BaseModel):
    preview_id: str = Field(min_length=36, max_length=36)


@router.get('/retention')
def get_retention(db: Session = Depends(get_db)):
    return retention.settings(db)


@router.put('/retention')
def put_retention(value: retention.Policy, db: Session = Depends(get_db)):
    return retention.save_policy(db, value)


@router.post('/retention/preview')
def preview_retention(db: Session = Depends(get_db)):
    return retention.preview(db)


@router.post('/retention/run')
def run_retention(value: RetentionRunIn, db: Session = Depends(get_db)):
    return retention.run(db, value.preview_id)
