"""Safe, persisted Harbor failure details; legacy sync summaries remain readable."""
from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, ValidationError

from api.hosts import LOGIN_REJECTED, NO_LINK, NO_RIGHTS, TLS_FAILED
from api.modules.vm.core.harbor import BAD_FORMAT, HarborError

Stage = Literal["repositories", "artifacts", "report", "unknown"]


class SyncErrorDetail(BaseModel):
    target: str
    stage: Stage
    reason: str | None = None
    http_status: int | None = None
    hint: str


def unknown_error(target: str) -> SyncErrorDetail:
    return SyncErrorDetail(
        target=target, stage="unknown",
        hint="Причина не была сохранена старой версией STools. Повторите синхронизацию, чтобы получить подробности.",
    )


def describe_error(target: str, stage: Stage, exc: HarborError) -> SyncErrorDetail:
    """Use only classified errors/status, never response bodies, URLs or credentials."""
    status = exc.status
    if status == 401 or exc.kind == LOGIN_REJECTED:
        reason = "Harbor отклонил вход робота"
        hint = "Проверьте имя робота, срок действия и секрет его учётной записи в настройках Harbor."
    elif status == 403 or exc.kind == NO_RIGHTS:
        reason = "Недостаточно прав робота"
        hint = "Проверьте права робота на чтение проекта, репозиториев, артефактов и отчётов об уязвимостях."
    elif exc.kind == TLS_FAILED:
        reason = "Не удалось проверить TLS-сертификат Harbor"
        hint = "Проверьте срок действия сертификата, имя сервера и доверенную цепочку сертификатов."
    elif exc.kind == NO_LINK:
        reason = "Нет связи с Harbor"
        hint = "Проверьте доступность Harbor из STools: DNS, маршрут, порт и сетевые ограничения."
    elif exc.kind == BAD_FORMAT:
        reason = "Harbor вернул неожиданный формат данных"
        hint = "Проверьте адрес API Harbor и прокси: вместо JSON мог вернуться HTML или слишком большой ответ."
    elif status == 404:
        reason = "Объект не найден в Harbor"
        hint = "Проверьте, существует ли проект, репозиторий или отчёт. Объект мог быть удалён во время синхронизации."
    elif status == 429:
        reason = "Harbor ограничил частоту запросов"
        hint = "Повторите синхронизацию позже и проверьте лимиты запросов на Harbor и прокси."
    elif status is not None and status >= 500:
        reason = "Ошибка на стороне Harbor или его прокси"
        hint = "Проверьте состояние сервисов и журналы Harbor или прокси, затем повторите синхронизацию."
    else:
        reason = "Не удалось прочитать данные Harbor"
        hint = "Проверьте доступность объекта, права робота и журналы Harbor, затем повторите синхронизацию."
    return SyncErrorDetail(target=target, stage=stage, reason=reason, http_status=status, hint=hint)


def errors_text(errors: list[str], details: list[SyncErrorDetail]) -> str | None:
    if not errors:
        return None
    return json.dumps({"version": 2, "errors": errors, "details": [item.model_dump() for item in details]}, ensure_ascii=False)


def read_errors(text: str | None) -> tuple[list[str], list[SyncErrorDetail]]:
    if not text:
        return [], []
    try:
        value = json.loads(text)
    except ValueError:
        value = [text]
    details: list[SyncErrorDetail] = []
    if isinstance(value, dict) and isinstance(value.get("errors"), list):
        names = [str(name) for name in value["errors"]]
        entries = value.get("details", [])
        for entry in entries if isinstance(entries, list) else []:
            try:
                detail = SyncErrorDetail.model_validate(entry)
            except ValidationError:
                continue
            if detail.target in names and detail not in details:
                details.append(detail)
    else:
        names = [str(name) for name in value] if isinstance(value, list) else [text]
    known = {item.target for item in details}
    details.extend(unknown_error(name) for name in names if name not in known)
    return names, details
