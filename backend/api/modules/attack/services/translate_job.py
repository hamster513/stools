"""Перевод недостающих техник фоновым заданием.

Запускает человек кнопкой, а не сервис сам: перевод обращается наружу,
и решение об этом принимает тот, кто знает, можно ли сейчас.
"""
from __future__ import annotations

import datetime as dt
import logging

from sqlalchemy.orm import Session

from api.db.models import AttackTranslation
from api.jobs import JobHandle
from api.llm_settings import load_llm
from api.modules.attack.services.attack_bundle import ORIGIN_LLM, current, gaps, source_hash
from kbaudit.attack.provider import ModelError, OllamaCompletion
from kbaudit.attack.translate import (
    BATCH_SIZE,
    TranslationError,
    TranslationRequest,
    translate_batch,
)

logger = logging.getLogger(__name__)

#: Столько подряд идущих сбоев считаем отказом модели. То же правило, что
#: и в разметке: дописывать пустоту до конца списка — значит выдавать
#: молчание модели за её ответ.
_GIVE_UP_AFTER = 3

#: Сколько уже принятых переводов класть в промпт как глоссарий.
_GLOSSARY_SIZE = 20


def _glossary(db: Session, bundle_by_id: dict[str, object]) -> dict[str, str]:
    """Выдержка из уже принятого перевода — чтобы терминология не разъезжалась."""
    rows = (
        db.query(AttackTranslation)
        .filter(AttackTranslation.name_ru != "")
        .order_by(AttackTranslation.technique_id)
        .limit(_GLOSSARY_SIZE * 5)
        .all()
    )
    out: dict[str, str] = {}
    for row in rows:
        technique = bundle_by_id.get(row.technique_id)
        name = getattr(technique, "name", None)
        if name and name != row.name_ru:
            out[name] = row.name_ru
        if len(out) >= _GLOSSARY_SIZE:
            break
    return out


def run_translation(db: Session, handle: JobHandle) -> None:
    """Тело задания перевода; сессию и запись состояния даёт run_job."""
    llm = load_llm(db)
    if not llm.task_configured("attack_translation"):
        raise ModelError("адрес модели не задан — перевод требует настроенной модели")

    bundle = current(db)
    by_id = bundle.by_id()
    pending = gaps(db, bundle)
    if not pending:
        handle.stage("done", message="переводить нечего")
        return

    provider = llm.for_task("attack_translation", data_class="public")
    completion = OllamaCompletion(provider)
    glossary = _glossary(db, by_id)

    # Счёт техник — в сообщении самого этапа: сообщение, поставленное
    # при запуске задания, первый же stage() затирает.
    handle.stage("translating", total=len(pending), message=f"техник: {len(pending)}")

    failed = 0
    in_a_row = 0
    for start in range(0, len(pending), BATCH_SIZE):
        chunk = pending[start : start + BATCH_SIZE]
        requests = [
            TranslationRequest(
                technique_id=g.technique_id,
                name=by_id[g.technique_id].name,
                description=by_id[g.technique_id].description,
            )
            for g in chunk
            if g.technique_id in by_id
        ]
        try:
            translated = translate_batch(requests, completion, glossary)
        except (TranslationError, ModelError):
            # Прежний перевод остаётся: молчание модели не является
            # утверждением, что перевода нет.
            logger.exception("перевод пачки не удался")
            failed += len(requests)
            in_a_row += 1
            if in_a_row >= _GIVE_UP_AFTER:
                raise ModelError(
                    f"модель перестала отвечать: переведено "
                    f"{start - failed + len(requests)} техник из {len(pending)}"
                ) from None
            continue

        in_a_row = 0
        now = dt.datetime.now(dt.UTC)
        for item in translated:
            row = db.get(AttackTranslation, item.technique_id)
            if row is None:
                row = AttackTranslation(technique_id=item.technique_id)
                db.add(row)
            row.name_ru = item.name_ru
            row.description_ru = item.description_ru
            row.source_hash = source_hash(by_id[item.technique_id])
            row.origin = ORIGIN_LLM
            row.model = f"{provider.provider}:{provider.model}"
            row.updated_at = now
        db.commit()
        handle.tick(start + len(chunk))

    # Ничего не переведено — это провал, а не завершённое задание:
    # «сделано ноль из одного» успехом не является.
    if failed >= len(pending):
        raise ModelError(f"модель не перевела ни одной техники из {len(pending)}")

    if failed:
        # tick, а не новый этап: stage() обнулил бы processed и total,
        # и итог «переведено столько-то из стольких-то» пропал бы с экрана
        # ровно там, где он нужнее всего.
        handle.tick(
            len(pending),
            message=(
                f"модель не перевела {failed} техник из {len(pending)}; "
                "их прежний перевод сохранён"
            ),
        )
