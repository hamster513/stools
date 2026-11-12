from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from api.db.base import get_db
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
