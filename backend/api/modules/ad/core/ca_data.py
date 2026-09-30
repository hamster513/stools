"""Формат данных центра сертификации `stools-ad-ca/1` (спека ADCS §2).

Настройки и права ЦС, реестр контроллеров и веб-выдачу по LDAP не прочитать:
их собирает только PowerShell-сборщик отдельным файлом. Файл приходит той же
ручкой, что и выгрузка домена, поэтому формат сначала определяется по полю
`format` (`sniff_format`), а уже потом файл разбирается целиком.
"""
from __future__ import annotations

import datetime as dt
import json
import zlib
from pathlib import Path
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, Field, field_validator

from api.export_files import GZIP_MAGIC
from api.modules.ad.core.export import CollectorInfo, StrList, describe_validation
from kbaudit.safe_io import MB, decompress_gzip_file

CA_FORMAT = "stools-ad-ca/1"
SECTIONS = ("ca", "dc", "web")
#: Данные ЦС — десятки записей; выгрузка домена больше этого потолка не
#: читается дважды ради одного поля `format`.
MAX_CA_BYTES = 5 * MB


def _as_records(value: Any) -> Any:
    """ConvertTo-Json в PowerShell 5.1 отдаёт пустой список как null или {}, одиночный — объектом."""
    if value is None or value == {}:
        return []
    if isinstance(value, dict):
        return [value]
    return value


class CaDomain(BaseModel):
    sid: str
    dns_root: str = ""


class CaAuthority(BaseModel):
    name: str
    host: str = ""
    os_build: str = ""
    edit_flags: int | None = None
    interface_flags: int | None = None
    disable_extension_list: StrList = Field(default_factory=list)
    #: Дескриптор безопасности ЦС (`CA\Security`), base64.
    security: str | None = None
    error: str = ""


class DcBinding(BaseModel):
    host: str
    strong_binding: int | None = None
    mapping_methods: int | None = None
    error: str = ""


class WebEndpoint(BaseModel):
    url: str
    status: int | None = None
    auth: StrList = Field(default_factory=list)
    error: str = ""


class CaData(BaseModel):
    format: str
    collected_at: dt.datetime
    collector: CollectorInfo = Field(default_factory=CollectorInfo)
    domain: CaDomain
    sections: StrList = Field(default_factory=list)
    cas: Annotated[list[CaAuthority], BeforeValidator(_as_records)] = Field(default_factory=list)
    dcs: Annotated[list[DcBinding], BeforeValidator(_as_records)] = Field(default_factory=list)
    web: Annotated[list[WebEndpoint], BeforeValidator(_as_records)] = Field(default_factory=list)
    #: Только у сведённых данных (`effective_ca_data`): раздел → дата сбора и
    #: id загрузки, откуда он взят. В файле и в базе их нет.
    section_dates: dict[str, dt.datetime] = Field(default_factory=dict)
    section_sources: dict[str, int] = Field(default_factory=dict)

    @field_validator("collected_at")
    @classmethod
    def _utc_if_naive(cls, value: dt.datetime) -> dt.datetime:
        return value if value.tzinfo is not None else value.replace(tzinfo=dt.UTC)


#: Раздел → поле CaData с его записями.
SECTION_FIELD = {"ca": "cas", "dc": "dcs", "web": "web"}
#: Служебные поля сведённых данных: в хранимый файл не пишутся.
MERGED_FIELDS = {"section_dates", "section_sources"}


class CaDataFormatError(ValueError):
    pass


def parse_ca_data(raw: Any) -> CaData:
    found = raw.get("format") if isinstance(raw, dict) else None
    if isinstance(found, str) and found.startswith("stools-ad-ca/") and found != CA_FORMAT:
        raise CaDataFormatError(f"данные ЦС формата {found} не поддерживаются, нужен {CA_FORMAT}")
    if found != CA_FORMAT:
        raise CaDataFormatError(f"это не данные ЦС формата {CA_FORMAT}: в файле «{found if isinstance(raw, dict) else '—'}»")
    try:
        data = CaData.model_validate(raw)
    except ValueError as exc:
        raise CaDataFormatError("данные ЦС неполные: " + describe_validation(exc)) from exc
    _check_sections(data)
    return data


def _check_sections(data: CaData) -> None:
    """Проверка здесь, а не валидатором модели: pydantic завернул бы текст в свой."""
    unknown = [s for s in data.sections if s not in SECTIONS]
    if unknown:
        raise CaDataFormatError(f"данные ЦС: неизвестный раздел «{unknown[0]}», допустимы {', '.join(SECTIONS)}")
    for section, field in SECTION_FIELD.items():
        if getattr(data, field) and section not in data.sections:
            raise CaDataFormatError(f"данные ЦС противоречивы: есть записи раздела «{section}», но его нет в sections")


def _read_capped(path: Path, max_bytes: int) -> bytes | bytearray | None:
    """Текст файла (gzip распаковывается), если он не больше `max_bytes`; иначе None."""
    with path.open("rb") as f:
        packed = f.read(2) == GZIP_MAGIC
        f.seek(0)
        if packed:
            try:
                return decompress_gzip_file(f, max_bytes)
            except (ValueError, OSError, EOFError, zlib.error):
                return None
        data = f.read(max_bytes + 1)
        return data if len(data) <= max_bytes else None


def _loads(data: bytes | bytearray) -> Any:
    try:
        return json.loads(data)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None


def sniff_format(path: Path, max_bytes: int = MAX_CA_BYTES) -> str | None:
    """Поле format файла не больше max_bytes в распакованном виде (JSON или gzip); больше или не JSON — None."""
    data = _read_capped(path, max_bytes)
    raw = _loads(data) if data is not None else None
    fmt = raw.get("format") if isinstance(raw, dict) else None
    return fmt if isinstance(fmt, str) else None


def load_ca_data_path(path: Path) -> CaData:
    data = _read_capped(path, MAX_CA_BYTES)
    if data is None:
        raise CaDataFormatError(f"файл данных ЦС не прочитан или больше {MAX_CA_BYTES // MB} МБ")
    raw = _loads(data)
    if raw is None:
        raise CaDataFormatError("файл не разобран как JSON данных ЦС")
    return parse_ca_data(raw)
