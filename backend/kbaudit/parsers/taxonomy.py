"""Чтение taxonomy.json: поля, их роли и версия сборки.

Роль поля не выдумывается: taxonomy.json описывает каждое поле сам, и
описание это машиночитаемое. Догадки по имени поля здесь не место —
там, где таксономия молчит, роль остаётся вопросом к человеку.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import PurePosixPath

from kbaudit.analyzers.mp_taxonomy import role_by_documentation
from kbaudit.models import Taxonomy


def load_taxonomy(zf: zipfile.ZipFile) -> Taxonomy:
    hits = [n for n in zf.namelist() if PurePosixPath(n).name == "taxonomy.json"]
    if not hits:
        return Taxonomy()
    try:
        doc = json.loads(zf.read(hits[0]).decode("utf-8-sig"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return Taxonomy()
    if not isinstance(doc, dict):
        return Taxonomy()
    build = doc.get("_build_info")
    version = build.get("version") if isinstance(build, dict) else None
    fields = {k for k in doc if not k.startswith("_")}
    # Документация описывает назначение поля словами, машиночитаемая
    # таксономия — его форму. Там, где форма ничего не решает (а это
    # почти весь `String`), назначение решает.
    roles: dict[str, str] = {}
    for name in fields:
        role = _role_of(doc.get(name)) or role_by_documentation(name)
        if role is not None:
            roles[name] = role
    return Taxonomy(fields=fields, version=version, field_roles=roles)


#: Ключи разрешения актива, означающие адресацию узла. Именно они дают
#: значение, уникальное для инсталляции: имя хоста, полное имя, адрес.
#:
#: `entity` сюда не входит намеренно, и это не мелочь: по нему проходит
#: `event_src.title` — название источника событий вроде «windows»,
#: одинаковое всюду. Без этой оговорки одно поле давало 325 ложных
#: находок из 349 новых.
_ASSET_ADDRESS_KEYS = frozenset({"fqdn", "hostname", "ipv4", "ipv6"})

#: Типы, значение которых зависит от инсталляции по самой своей природе.
_ENVIRONMENTAL_TYPES = frozenset({"IPAddress", "MACAddress"})

#: Типы, литерал в которых не может быть именем чего-либо в инфраструктуре.
_TECHNICAL_TYPES = frozenset({"Number", "Bool", "Datetime", "UUID", "UUIDList"})


def _role_of(spec: object) -> str | None:
    """Роль поля по его описанию в таксономии.

    Порядок проверок — от самого надёжного признака к менее надёжному.

    `asset_resolution` с адресным ключом — прямое указание: по этому полю
    SIEM разрешает актив по имени или адресу, то есть значение уникально
    для инсталляции. Разрешение по сущности (`entity`) таким признаком
    не является: через него проходит название источника событий.

    `class: tag` — поле с фиксированным перечнем значений (`action`,
    `importance`, `incident.severity`). Литерал в таком поле — часть
    языка детекта, а не описание инсталляции.

    Тип поля — последний по надёжности, но однозначный на краях:
    адрес и MAC зависят от инсталляции всегда, число и дата — никогда.

    Про `String` таксономия ничего не говорит, и догадываться по имени
    здесь не следует: `object.process.fullpath` может быть и системным
    путём, одинаковым везде, и путём к самописному приложению.
    """
    if not isinstance(spec, dict):
        return None
    resolution = spec.get("asset_resolution")
    if isinstance(resolution, dict):
        if resolution.get("key") in _ASSET_ADDRESS_KEYS:
            return "environmental"
        # Разрешение актива не по адресу, а по сущности: название
        # источника событий инсталляции не принадлежит.
        return "technical"
    if spec.get("class") == "tag":
        return "technical"
    field_type = spec.get("type")
    if field_type in _ENVIRONMENTAL_TYPES:
        return "environmental"
    if field_type in _TECHNICAL_TYPES:
        return "technical"
    # Поле заполняется системой, а не приходит из события: сравнивать
    # его с литералом инсталляции незачем.
    if spec.get("auto") is True:
        return "technical"
    return None
