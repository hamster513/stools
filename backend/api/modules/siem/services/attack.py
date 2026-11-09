"""Разметка групп правил по ATT&CK.

Два шага, разделённые намеренно. Отбор кандидатов детерминирован: близость
векторов, никакой модели, один и тот же результат на одной и той же выгрузке.
Выбор из отобранных — работа языковой модели, и только он требует внешнего
сервиса, включаемого явной настройкой.

Порядок проверок здесь не косметический: выжимка проходит защиту от утечки
ДО того, как появится хоть одно обращение наружу. Выгрузка — инвентарь
внутренней инфраструктуры, и цена ошибки в том, что он уедет к модели.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
from pathlib import Path

from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db.base import get_sessionmaker
from api.db.models import AttackMarkup, Job, Snapshot, SnapshotProfile, TechniqueVector
from api.modules.attack.services.attack_bundle import current as current_bundle
from api.modules.siem.services.appsettings import load_attack, load_llm
from kbaudit.attack.bundle import AttackBundle, Technique
from kbaudit.attack.candidates import select_candidates
from kbaudit.attack.payload import (
    LeakGuardError,
    assert_no_leak,
    build_payload,
    literal_frequency,
)
from kbaudit.attack.prompt import GroupSuggestion
from kbaudit.attack.provider import ModelError, OllamaCompletion, OllamaEmbedder, suggest_techniques
from kbaudit.models import KbObject, ParsedArchive, Rule
from kbaudit.naming import apply_scheme
from kbaudit.profile import Profile, detect_profile

logger = logging.getLogger(__name__)

STATUS_UNMAPPED = "unmapped"
STATUS_SUGGESTED = "suggested"
STATUS_CONFIRMED = "confirmed"

SOURCE_LLM = "llm"
SOURCE_MANUAL = "manual"
#: Разметка принята из эталонной таблицы. Отличается от «выбрано человеком»
#: намеренно: решение принимал человек, но не здесь и не сейчас, а в чужом
#: документе — и через полгода это единственный способ вспомнить, откуда
#: у правила взялась именно эта техника.
SOURCE_REFERENCE = "reference"

#: Сколько подряд идущих сбоев модели считать её отказом. Одиночный сбой
#: бывает — таймаут, выгрузка весов из памяти. Три подряд означают, что
#: спрашивать дальше бессмысленно, и дописывать «не размечено» до конца
#: списка — это выдавать молчание модели за её ответ.
_GIVE_UP_AFTER = 3

#: Стадии задания разметки. Векторы техник считаются один раз и потом
#: берутся из кэша, поэтому первый прогон заметно дольше следующих.
_STAGE_PROGRESS = {"pending": 0, "embedding": 15, "suggesting": 35, "done": 100}


class MarkupTechnique(BaseModel):
    """Одна техника в разметке группы."""

    technique_id: str
    confidence: str = "низкая"
    evidence: str = ""
    source: str = SOURCE_LLM


# --------------------------------------------------------------------------
# Бандл ATT&CK
# --------------------------------------------------------------------------


def bundle(db: Session) -> AttackBundle:
    """Действующий бандл: вложенный или загруженный человеком.

    Читается из базы, а не из файла образа: заказчик обновляет матрицу
    сам, и разметка обязана идти по той версии, которую он принял.
    """
    return current_bundle(db)


# --------------------------------------------------------------------------
# Векторы техник
# --------------------------------------------------------------------------


def ensure_vectors(
    db: Session, embedder: OllamaEmbedder, embed_model: str, techniques: list[Technique]
) -> dict[str, list[float]]:
    """Векторы техник из кэша, недостающие — досчитать и сохранить.

    Ключ кэша включает модель эмбеддингов: вектор, посчитанный другой
    моделью, лежит в другом пространстве, и сравнивать его с новыми —
    значит получать правдоподобную чушь вместо кандидатов.
    """
    version = bundle(db).version
    cached = {
        row.technique_id: json.loads(row.vector_json)
        for row in db.query(TechniqueVector).filter(
            TechniqueVector.embed_model == embed_model,
            TechniqueVector.attack_version == version,
        )
    }
    missing = [t for t in techniques if t.technique_id not in cached]
    if not missing:
        return cached

    # Пачками: 222 текста по несколько абзацев одним запросом упираются
    # в размер тела и в таймаут.
    for start in range(0, len(missing), 32):
        chunk = missing[start : start + 32]
        vectors = embedder.embed([t.embedding_text for t in chunk])
        for technique, vector in zip(chunk, vectors, strict=True):
            db.add(
                TechniqueVector(
                    technique_id=technique.technique_id,
                    embed_model=embed_model,
                    attack_version=version,
                    vector_json=json.dumps(vector),
                )
            )
            cached[technique.technique_id] = vector
        db.commit()
    return cached


# --------------------------------------------------------------------------
# Группировка правил
# --------------------------------------------------------------------------


def group_rules(parsed: ParsedArchive, profile: Profile) -> dict[str, list[Rule]]:
    """Правила по группам.

    Схема именования применяется здесь же: кэш разбора пишется до стадии
    анализа, поэтому разобранного кода в нём нет — его проставляет
    `build_report`, и повторить это дешевле, чем пересобирать весь отчёт.

    Правила без разобранного кода отбрасываются: группа «пусто» не единица
    разметки.
    """
    scheme = profile.name_scheme or detect_profile([r.name for r in parsed.rules]).name_scheme
    for rule in parsed.rules:
        rule.code = apply_scheme(rule.name, scheme)

    out: dict[str, list[Rule]] = {}
    for rule in parsed.rules:
        key = rule.code.group_key if rule.code else ""
        if not key:
            continue
        out.setdefault(key, []).append(rule)
    return out


def _bodies_by_uuid(parsed: ParsedArchive) -> dict[str, KbObject]:
    return {b.uuid: b for b in parsed.bodies}


# --------------------------------------------------------------------------
# Прогон разметки
# --------------------------------------------------------------------------


def run_markup(job_id: int, snapshot_id: int) -> None:
    session_factory = get_sessionmaker()
    db = session_factory()
    try:
        _run(db, job_id, snapshot_id)
    finally:
        db.close()


def _set_stage(db: Session, job: Job, stage: str) -> None:
    job.stage = stage
    job.progress = _STAGE_PROGRESS[stage]
    db.commit()


def _run(db: Session, job_id: int, snapshot_id: int) -> None:
    job = db.get(Job, job_id)
    snapshot = db.get(Snapshot, snapshot_id)
    if job is None or snapshot is None:
        return
    try:
        llm = load_llm(db)
        if not llm.task_configured("attack_markup") or not llm.task_configured("attack_embeddings"):
            raise ModelError("адрес модели не задан — разметка требует настроенной модели")
        top_k = load_attack(db).top_k
        provider = llm.for_task("attack_markup", data_class="redacted")
        embedding_provider = llm.for_task("attack_embeddings", data_class="redacted")
        model_name = f"{provider.provider}:{provider.model}"
        # Include endpoint and model so unrelated vector spaces never share a cache.
        import hashlib
        vector_key = "task:" + hashlib.sha256(
            f"{embedding_provider.provider}|{embedding_provider.base_url.rstrip('/')}|{embedding_provider.embed_model}".encode()
        ).hexdigest()

        parsed = ParsedArchive.model_validate_json(
            Path(snapshot.parsed_cache_path).read_text(encoding="utf-8")
        )
        groups = group_rules(parsed, snapshot_profile(db, snapshot_id))
        blocklist = frozenset(v.lower() for v in parsed.table_values)
        frequency = literal_frequency(parsed.bodies)
        bodies = _bodies_by_uuid(parsed)

        _set_stage(db, job, "embedding")
        book = bundle(db)
        parents = book.parents_only()
        vectors = ensure_vectors(db, OllamaEmbedder(embedding_provider), vector_key, parents)

        _set_stage(db, job, "suggesting")
        embedder = OllamaEmbedder(embedding_provider)
        completion = OllamaCompletion(provider)
        existing = {m.rule_uuid: m for m in db.query(AttackMarkup)}

        # Разметка идёт по правилам, а не по группам. Выжимка по группе
        # сливала заголовки и описания всех её правил в одну: у `DEMO/HC/002`
        # это двадцать одно описание, из которых модель выбирала три техники.
        # По ручной разметке заказчика в той же группе девятнадцать разных
        # техник — сигнал был размыт до неразличимости.
        targets = [(group, rule) for group, rules in sorted(groups.items()) for rule in rules]
        total = len(targets) or 1
        done = 0
        failed: list[str] = []
        in_a_row = 0
        for group, rule in targets:
            done += 1
            job.progress = 35 + int(60 * done / total)
            db.commit()

            row = existing.get(rule.uuid)
            # Подтверждённое человеком не перезаписывается: это единственное
            # в системе, что стоит человеко-часов.
            if row is not None and row.status == STATUS_CONFIRMED and not row.inherited:
                continue

            try:
                suggestion = _suggest_one(
                    rule, bodies, blocklist, frequency, book, vectors,
                    embedder, completion, model_name, top_k,
                )
            except ModelError:
                # Прежняя разметка правила остаётся нетронутой: модель молчит,
                # а не сообщает, что техник нет.
                logger.exception("модель не ответила по правилу")
                failed.append(rule.uuid)
                in_a_row += 1
                if in_a_row >= _GIVE_UP_AFTER:
                    raise ModelError(
                        f"модель перестала отвечать: размечено {done - len(failed)} правил "
                        f"из {len(targets)}, остальные не тронуты"
                    ) from None
                continue

            in_a_row = 0
            _store(
                db, rule.uuid, group, suggestion, book.version, model_name,
                had_row=row is not None,
            )

        job.stage = "done"
        job.status = "done"
        job.progress = 100
        # Предупреждение при завершившемся задании: часть работы сделана,
        # и объявлять весь прогон провалившимся из-за одной группы неверно,
        # но и молчать о пропусках нельзя — иначе пробел в матрице читается
        # как «техник нет», а не как «спросить не удалось».
        job.error = (
            None
            if not failed
            else f"модель не ответила по {len(failed)} правилам из {len(targets)}; "
            "их прежняя разметка сохранена"
        )
        db.commit()
    except Exception as exc:  # noqa: BLE001 — любая ошибка проваливает задание
        db.rollback()
        _fail(db, job_id, _safe_error(exc))


def _suggest_one(
    rule: Rule,
    bodies: dict[str, KbObject],
    blocklist: frozenset[str],
    frequency: dict[str, int],
    book: AttackBundle,
    vectors: dict[str, list[float]],
    embedder: OllamaEmbedder,
    completion: OllamaCompletion,
    model_name: str,
    top_k: int,
) -> GroupSuggestion | None:
    """Разметка одного правила.

    `None` означает «отправлять нечего»: выжимка не прошла проверку на
    утечку или оказалась пустой. Это законный результат.

    Недоступность модели результатом не является и поднимается как
    `ModelError` — решение, что с этим делать, принимает вызывающий.
    """
    rule_bodies = [bodies[rule.uuid]] if rule.uuid in bodies else []
    payload, _review = build_payload(
        rule.name, [rule], rule_bodies, blocklist, frequency=frequency
    )
    try:
        # Защита от утечки — до первого обращения наружу, а не после.
        assert_no_leak(payload, blocklist)
    except LeakGuardError:
        logger.warning("выжимка по правилу не прошла проверку и отправлена не будет")
        return None
    if not payload.embedding_text.strip():
        return None

    # ModelError намеренно не глотается: «модель недоступна» и «модель
    # посмотрела и ничего не нашла» — разные вещи, и первое, выданное
    # за второе, стирает уже сделанную разметку. Ровно это и произошло
    # на живом прогоне: модель отвалилась на двадцать восьмой группе,
    # и шестнадцать оставшихся были записаны как «не размечено»
    # за сто сорок миллисекунд — по десять на группу.
    query = embedder.embed([payload.embedding_text])[0]
    candidates = select_candidates(query, book.parents_only(), vectors, top_k=top_k)
    if not candidates:
        return None
    return suggest_techniques(
        payload, candidates, book.by_id(), completion,
        model_name=model_name, attack_version=book.version,
    )


def _store(
    db: Session,
    rule_uuid: str,
    group: str,
    suggestion: GroupSuggestion | None,
    version: str | None,
    model: str,
    had_row: bool = False,
) -> None:
    """Сохранить результат разметки правила.

    Пустой результат не затирает прежнюю разметку: «в этот раз модель
    ничего не выбрала» — не основание стереть то, что она выбрала в
    прошлый раз, и уж тем более не основание объявить правило
    неразмеченным задним числом.
    """
    row = db.query(AttackMarkup).filter(AttackMarkup.rule_uuid == rule_uuid).one_or_none()
    if suggestion is not None and not suggestion.techniques and had_row:
        return
    if row is None:
        row = AttackMarkup(rule_uuid=rule_uuid)
        db.add(row)
    row.group_name = group
    # Разметка получена по этому правилу — наследованием она больше не является.
    row.inherited = False
    if suggestion is None or not suggestion.techniques:
        row.status = STATUS_UNMAPPED
        row.techniques_json = "[]"
        row.candidates_json = json.dumps(suggestion.candidates if suggestion else [])
    else:
        row.status = STATUS_SUGGESTED
        row.techniques_json = json.dumps(
            [
                MarkupTechnique(
                    technique_id=t.technique_id,
                    confidence=t.confidence,
                    evidence=t.evidence,
                    source=SOURCE_LLM,
                ).model_dump()
                for t in suggestion.techniques
            ],
            ensure_ascii=False,
        )
        row.candidates_json = json.dumps(suggestion.candidates)
    row.model = model
    row.attack_version = version
    row.updated_at = dt.datetime.now(dt.UTC)
    db.commit()


def _safe_error(exc: Exception) -> str:
    """Наружу — только класс исключения.

    Текст исключения может нести содержимое запроса к модели, то есть
    выжимку по правилам; в интерфейс это отдавать нельзя.
    """
    logger.exception("разметка ATT&CK провалилась")
    if isinstance(exc, ModelError):
        return str(exc)
    return f"разметка прервана: {type(exc).__name__}. Подробности — в журнале сервера."


def _fail(db: Session, job_id: int, message: str) -> None:
    job = db.get(Job, job_id)
    if job is not None:
        job.status = "failed"
        job.error = message
        db.add(job)
    db.commit()


# --------------------------------------------------------------------------
# Чтение разметки
# --------------------------------------------------------------------------


def markup_by_rule(db: Session) -> dict[str, AttackMarkup]:
    """Разметка по UUID правила."""
    return {row.rule_uuid: row for row in db.query(AttackMarkup)}


def techniques_of(row: AttackMarkup) -> list[MarkupTechnique]:
    return [MarkupTechnique.model_validate(t) for t in json.loads(row.techniques_json or "[]")]


def describe(db: Session, technique_id: str) -> Technique | None:
    return bundle(db).by_id().get(technique_id)


def snapshot_profile(db: Session, snapshot_id: int) -> Profile:
    row = db.get(SnapshotProfile, snapshot_id)
    if row is None or row.profile_json in ("{}", "", None):
        return Profile()
    return Profile.model_validate_json(row.profile_json)
