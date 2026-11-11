"""Validate an offline bundle before atomic import. No network, HTML or rule execution."""
from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import stat
import zipfile
import zlib
from collections import Counter
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    model_validator,
)
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from api.modules.siem.hunting.models import ThIntelImport, ThIntelItem

MAX_ZIP = 64 * 1024 * 1024
MAX_DATA = 128 * 1024 * 1024
MAX_ITEMS = 30_000


class IntelError(ValueError):
    pass


def safe_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password or any(ord(c) < 32 for c in value):
        raise ValueError('Допускаются только HTTP(S)-ссылки без учётных данных')
    return value


Url = Annotated[str, Field(max_length=2048), AfterValidator(safe_url)]
Technique = Annotated[str, Field(pattern=r'^T\d{4}(\.\d{3})?$')]
SourceId = Annotated[str, Field(min_length=1, max_length=100, pattern=r'^[A-Za-z0-9_.-]+$')]


class Source(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: SourceId
    name: str = Field(min_length=1, max_length=200)
    kind: Literal['news', 'rule']
    url: Url
    status: Literal['ok', 'partial', 'error']
    items: int = Field(ge=0, le=MAX_ITEMS)
    error: str = Field(default='', max_length=1000)
    revision: str = Field(default='', max_length=64)
    license_text: str = Field(default='', max_length=100_000)
    license_url: Url | None = None


class Manifest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    format: Literal['stools-th-intel']
    version: Literal[1]
    generated_at: AwareDatetime
    items_count: int = Field(ge=0, le=MAX_ITEMS)
    items_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    sources: list[Source] = Field(min_length=1, max_length=300)

    @model_validator(mode='after')
    def check_sources(self):
        if len({s.id for s in self.sources}) != len(self.sources):
            raise ValueError('Повторяющиеся источники')
        if self.generated_at > dt.datetime.now(dt.UTC) + dt.timedelta(hours=24):
            raise ValueError('Дата архива находится в будущем')
        return self


class Material(BaseModel):
    model_config = ConfigDict(extra='forbid')
    source_id: SourceId
    external_id: str = Field(min_length=1, max_length=1024)
    kind: Literal['news', 'rule']
    title: str = Field(min_length=1, max_length=2000)
    url: Url
    text: str = Field(max_length=1_048_576)
    format: Literal['article', 'sigma', 'elastic']
    published_at: AwareDatetime | None = None
    technique_ids: list[Technique] = Field(default_factory=list, max_length=100)
    full_text: bool = False

    @model_validator(mode='after')
    def compatible_format(self):
        if (self.kind == 'news') != (self.format == 'article'):
            raise ValueError('Формат не соответствует виду материала')
        if any('\x00' in v for v in (self.external_id, self.title, self.text, self.url)):
            raise ValueError('Недопустимый нулевой символ')
        return self

    @property
    def key(self):
        return hashlib.sha256((self.source_id+'\x00'+self.external_id).encode()).hexdigest()


def read_bundle(data: bytes) -> tuple[Manifest, list[Material]]:
    if len(data) > MAX_ZIP: raise IntelError('Архив превышает 64 МиБ')
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) != 2 or {i.filename for i in infos} != {'manifest.json', 'items.jsonl'}:
                raise IntelError('Ожидались только manifest.json и items.jsonl без каталогов')
            for info in infos:
                limit = 2*1024*1024 if info.filename == 'manifest.json' else MAX_DATA
                if info.flag_bits & 1 or stat.S_ISLNK(info.external_attr >> 16) or info.file_size > limit or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise IntelError('Недопустимый размер, тип или шифрование файла в архиве')
            with archive.open('manifest.json') as stream:
                raw_manifest = stream.read(2*1024*1024 + 1)
            if len(raw_manifest) > 2*1024*1024: raise IntelError('Слишком большой манифест')
            manifest = Manifest.model_validate_json(raw_manifest)
            with archive.open('items.jsonl') as stream:
                raw = stream.read(MAX_DATA+1)
            if len(raw) > MAX_DATA: raise IntelError('Материалы превышают 128 МиБ')
            if hashlib.sha256(raw).hexdigest() != manifest.items_sha256:
                raise IntelError('Контрольная сумма не совпадает: архив повреждён')
            sources = {s.id: s for s in manifest.sources}
            rows, seen = [], set()
            counts = Counter()
            stream = io.BytesIO(raw)
            while line := stream.readline(8*1024*1024+1):
                if len(rows) >= manifest.items_count: raise IntelError('Количество материалов не совпадает с манифестом')
                if len(line) > 8*1024*1024: raise IntelError('Слишком большой материал')
                row = Material.model_validate_json(line)
                source = sources.get(row.source_id)
                if source is None or source.kind != row.kind or source.status == 'error':
                    raise IntelError('Материал ссылается на неизвестный или недоступный источник')
                if row.key in seen: raise IntelError('Повторяющийся материал в архиве')
                seen.add(row.key); counts[row.source_id] += 1; rows.append(row)
            if len(rows) != manifest.items_count: raise IntelError('Количество материалов не совпадает с манифестом')
            if any(counts[s.id] != s.items for s in manifest.sources):
                raise IntelError('Количество материалов источника не совпадает')
            return manifest, rows
    except IntelError:
        raise
    except (zipfile.BadZipFile, zlib.error, ValidationError, ValueError, OSError, RuntimeError, EOFError, NotImplementedError):
        raise IntelError('Некорректный архив материалов Threat Hunting или неподдерживаемый формат') from None


def import_bundle(db: Session, data: bytes, login: str, *, after_import=None) -> dict:
    manifest, rows = read_bundle(data)
    archive_id = hashlib.sha256(data).hexdigest()
    # Serialize imports so concurrent copies cannot race or roll back a newer item.
    db.execute(text('SELECT pg_advisory_xact_lock(1414023502)'))
    previous = db.get(ThIntelImport, archive_id)
    if previous:
        result = {**json.loads(previous.result_json), 'duplicate': True}
        if after_import:
            try:
                result.update(after_import(db))
                db.commit()
            except Exception:
                db.rollback()
                raise
        else:
            db.rollback()
        return result
    result = {'id': archive_id, 'added': 0, 'updated': 0, 'unchanged': 0, 'stale': 0,
              'duplicate': False, 'generated_at': manifest.generated_at.isoformat(),
              'sources': [s.model_dump(mode='json', exclude={'license_text'}) for s in manifest.sources]}
    imported = ThIntelImport(id=archive_id, created_by=login, result_json='{}', manifest_json=manifest.model_dump_json())
    try:
        db.add(imported)
        db.flush()
        for offset in range(0, len(rows), 500):
            chunk = rows[offset:offset+500]
            existing = {r.id: r for r in db.scalars(select(ThIntelItem).where(ThIntelItem.id.in_([r.key for r in chunk])))}
            for item in chunk:
                row = existing.get(item.key)
                digest = hashlib.sha256(item.model_dump_json().encode()).hexdigest()
                if row and row.collected_at > manifest.generated_at:
                    result['stale'] += 1
                    continue
                if row and row.content_hash == digest:
                    result['unchanged'] += 1
                else:
                    result['updated' if row else 'added'] += 1
                if row is None:
                    row = ThIntelItem(id=item.key)
                    db.add(row)
                for field in ('source_id', 'external_id', 'kind', 'title', 'url', 'text', 'format', 'published_at', 'full_text'):
                    setattr(row, field, getattr(item, field))
                row.collected_at = manifest.generated_at
                row.technique_ids_json = json.dumps(item.technique_ids)
                row.import_id = archive_id
                row.content_hash = digest
            db.flush()
        if after_import:
            result.update(after_import(db))
        imported.result_json = json.dumps(result, ensure_ascii=False)
        db.commit()
        return result
    except Exception:
        db.rollback()
        raise
