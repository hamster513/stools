"""Platform SMTP configuration and an explicit test message. RBAC is centralized."""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.platform.mail import (
    Mailbox,
    MailError,
    MailUpdate,
    MailView,
    load_mail,
    save_mail,
    send_test_email,
)


class MailRoute(APIRoute):
    def get_route_handler(self):
        original = super().get_route_handler()

        async def handler(request):
            try:
                return await original(request)
            except RequestValidationError as exc:
                # Pydantic model-level errors otherwise echo the complete form,
                # including the plaintext password. Keep only safe diagnostics.
                errors = [{key: error[key] for key in ('loc', 'msg', 'type')} for error in exc.errors()]
                raise HTTPException(422, errors) from None
        return handler


router = APIRouter(prefix='/mail', tags=['settings'], route_class=MailRoute)


@router.get('', response_model=MailView)
def get_mail(db: Session = Depends(get_db)) -> MailView:
    return load_mail(db)


@router.put('', status_code=204)
def put_mail(payload: MailUpdate, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> None:
    try:
        save_mail(db, payload, user.login)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    except MailError as exc:
        raise HTTPException(400, str(exc)) from None


class TestMailRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    settings: MailUpdate
    recipient: Mailbox


@router.post('/test')
def test_mail(payload: TestMailRequest, db: Session = Depends(get_db)) -> dict[str, bool | str]:
    try:
        message_id = send_test_email(db, payload.settings, payload.recipient)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    except MailError as exc:
        raise HTTPException(502, str(exc)) from None
    return {'accepted': True, 'message_id': message_id}
