"""Применяемость техник в России — слой поверх мировых данных MITRE.

Слой общий для всех модулей: он говорит о технике, а не о правиле, узле
или уязвимости. Загружает его человек своим файлом; в образ такая
выгрузка не вкладывается.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.attack.services.attack_bundle import current as current_bundle
from api.modules.attack.services.prevalence import prevalence_raw
from api.modules.attack.services.ru_ttp import (
    STATE_RU_ONLY,
    STATE_WORLD_ONLY,
    import_ru_ttp,
    ru_actors,
    ru_cell,
    ru_source,
    state_of,
)
from api.modules.attack.services.ru_ttp import (
    drop as drop_ru_layer,
)
from api.modules.attack.services.ru_ttp import (
    layer as ru_layer,
)
from kbaudit.attack.ru_ttp import parse as ru_parse

router = APIRouter(tags=["attack"])


@router.post("/ru-ttp")
def upload_ru_ttp(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Загрузить выгрузку «техника → процедура» с применяемостью здесь.

    Файл не покидает периметр: он разбирается на месте и ложится в базу.
    В образ такая выгрузка не вкладывается — это чужая аналитика,
    а не открытые данные MITRE, и раздавать её продукт не вправе.

    Загрузка заменяет прежнюю целиком: выгрузка — один документ на дату,
    и слияние двух её версий дало бы картину, которой нет ни в одной.
    """
    data = file.file.read()
    if not data:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail="файл пуст")
    parsed = ru_parse(data, file.filename or "")
    if not parsed.rows:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "в файле не нашлось ни строки с техникой ATT&CK. Нужны колонка "
                "с идентификатором техники вида T1059 и колонка с процедурой или связями"
            ),
        )
    return import_ru_ttp(db, parsed, file.filename or "файл", user.login)


@router.get("/ru-ttp")
def ru_ttp_state(
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Слой применяемости и его расхождение с мировыми данными.

    Четыре состояния, а не два флага. «Только мир» не значит «здесь не
    применяют», «только здесь» не значит «в мире не применяют»: и то и
    другое означает лишь, что источник об этом не отчитывался. Ценность
    ровно в этих двух списках — мировая статистика занижает первый
    и завышает второй.
    """
    ru = ru_layer(db)
    book = current_bundle(db)
    stats = prevalence_raw()

    def world_of(technique_id: str) -> int:
        stat = stats.stats.get(technique_id)
        return (stat.groups + stat.campaigns) if stat else 0

    counts: dict[str, int] = {}
    ru_only: list[dict[str, Any]] = []
    world_only: list[dict[str, Any]] = []
    for technique in book.techniques:
        world = world_of(technique.technique_id)
        state = state_of(technique.technique_id, ru, world > 0)
        counts[state] = counts.get(state, 0) + 1
        stat = stats.stats.get(technique.technique_id)
        item: dict[str, Any] = {
            "technique_id": technique.technique_id,
            "name": technique.name_ru or technique.name,
            "ru": ru_cell(ru, technique.technique_id),
            "world_groups": stat.groups if stat else 0,
        }
        if state == STATE_RU_ONLY:
            ru_only.append(item)
        elif state == STATE_WORLD_ONLY:
            world_only.append(item)

    ru_only.sort(key=lambda i: (-ru_actors(ru, i["technique_id"]), i["technique_id"]))
    world_only.sort(key=lambda i: (-i["world_groups"], i["technique_id"]))
    return {
        "source": ru_source(ru),
        "attack_version": book.version,
        "counts": counts,
        "ru_only": ru_only[:limit],
        "world_only": world_only[:limit],
        "unknown": ru.unknown,
    }


@router.delete("/ru-ttp", status_code=status.HTTP_204_NO_CONTENT)
def drop_ru_ttp(
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> None:
    """Снять слой. Разметки и мировых данных это не касается."""
    drop_ru_layer(db)
