"""Read-only certificate inspection; POST keeps certificate input out of URLs."""
import json

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from api.modules.toolbox.services.certificates import inspect_certificates

router = APIRouter()
_MAX_BODY = 3 * 1024 * 1024


@router.post('/certificates/inspect')
async def inspect(request: Request) -> dict:
    request.state.audit_summary = 'TBX: локальная проверка сертификатов'
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > _MAX_BODY:
            raise HTTPException(413, detail='Размер запроса превышает 3 МиБ.')
        body.extend(chunk)
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        raise HTTPException(422, detail='Нужен JSON с сертификатом.') from None
    fields = {'data', 'encoding', 'hostname', 'trust_roots'}
    if (not isinstance(payload, dict) or 'data' not in payload or set(payload) - fields
            or any(not isinstance(value, str) for value in payload.values())):
        raise HTTPException(422, detail='Нужны строковые поля data, encoding, hostname и trust_roots.')
    if payload.get('encoding', 'pem') not in {'pem', 'der_base64'} or len(payload.get('hostname', '')) > 253:
        raise HTTPException(422, detail='Проверьте формат сертификата и длину DNS-имени.')
    try:
        return await run_in_threadpool(inspect_certificates, **payload)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from None
