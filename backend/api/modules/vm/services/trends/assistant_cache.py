"""Durable, content-addressed answers. Provider settings never invalidate paid work."""
import hashlib
import json

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from api.modules.vm.trend_models import VmTrendAiAnswer


def target(card_id: str, publication_key: str) -> str:
    return 'publication:' + publication_key if publication_key else 'card:' + card_id


def key(target_id: str, mode: str, context: dict) -> str:
    content = json.loads(json.dumps(context['content']))
    cve = content['cve']
    cve.pop('fetched_at', None)
    cve.pop('expires_at', None)
    if mode == 'translate':
        content['cve'] = {'description': cve['description']} if cve.get('description') else {}
        content['publications'] = [{k: article[k] for k in ('title', 'text')} for article in content['publications']]
    payload = {'target': target_id, 'mode': mode, 'content': content, 'sources': context['sources'],
               'data_class': context['data_class'], 'truncated': context['truncated']}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def view(row: VmTrendAiAnswer, expected: str) -> dict:
    return {**row.answer, 'cached': True, 'stale': row.cache_key != expected}


def saved(db: Session, card_id: str, request, context_fn) -> dict:
    target_id = target(card_id, request.publication_key)
    latest = {mode: db.scalar(select(VmTrendAiAnswer).where(
        VmTrendAiAnswer.target == target_id, VmTrendAiAnswer.mode == mode,
    ).order_by(VmTrendAiAnswer.created_at.desc(), VmTrendAiAnswer.cache_key).limit(1)) for mode in ('translate', 'explain')}
    if not any(latest.values()):
        return latest
    original = context_fn(db, card_id, request)
    result = {}
    for mode, row in latest.items():
        expected = key(target_id, mode, original)
        exact = db.get(VmTrendAiAnswer, expected)
        result[mode] = view(exact or row, expected) if exact or row else None
    return result


def respond(db: Session, card_id: str, request, context_fn, generate_fn) -> dict:
    original = context_fn(db, card_id, request)
    target_id = target(card_id, request.publication_key)
    expected = key(target_id, request.mode, original)
    existing = db.get(VmTrendAiAnswer, expected)
    if existing:
        return view(existing, expected)
    db.commit()  # Release the request connection before waiting on another generation.
    # The lock and worker share ONE connection: queued callers cannot exhaust the
    # pool and prevent the generating caller from saving its answer.
    with db.get_bind().connect() as connection:
        connection.execute(text('SELECT pg_advisory_lock(hashtextextended(:key, 0))'), {'key': 'vm-ai:' + expected})
        connection.commit()
        try:
            with Session(bind=connection, expire_on_commit=False) as worker:
                current = context_fn(worker, card_id, request)
                if key(target_id, request.mode, current) != expected:
                    from fastapi import HTTPException
                    raise HTTPException(409, 'Исходные материалы изменились. Обновите карточку.')
                existing = worker.get(VmTrendAiAnswer, expected)
                if existing:
                    return view(existing, expected)
                answer = generate_fn(worker, card_id, request, current)
                worker.add(VmTrendAiAnswer(cache_key=expected, target=target_id, mode=request.mode, answer=answer))
                worker.commit()
                # Preserve a valid paid answer even if input changed while the model ran.
                # The current view marks it stale instead of silently discarding it.
                after = context_fn(worker, card_id, request)
                return {**answer, 'cached': False, 'stale': key(target_id, request.mode, after) != expected}
        finally:
            connection.execute(text('SELECT pg_advisory_unlock(hashtextextended(:key, 0))'), {'key': 'vm-ai:' + expected})
            connection.commit()
