"""Upload offline ZIPs once; the shared queue owns processing."""
from typing import Any

from fastapi import APIRouter, Depends, UploadFile
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.vm.services import archive_batches

router = APIRouter(prefix='/refs/batches', tags=['vm'])


@router.get('')
def history(db: Session = Depends(get_db)) -> dict[str, Any]:
    return {'items': archive_batches.history(db)}


@router.post('', status_code=202)
async def upload(files: list[UploadFile], db: Session = Depends(get_db),
                 user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    return {'run_id': await archive_batches.accept(db, files, user.login, user.id)}
