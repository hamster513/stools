"""Add newly shipped sources without resetting operator configuration or cursors."""
import json
from pathlib import Path

from .contracts import Source


def import_catalog(store, rows=None):
    if rows is None:
        rows = json.loads(Path(__file__).with_name('sources.json').read_text())
    sources = [Source.model_validate(row).model_dump() for row in rows]
    known = {source['url'] for source in store.sources()}
    added = 0
    for source in sources:
        if source['url'] in known:
            continue
        # Enabling collection remains an explicit operator choice, including upgrades.
        source['enabled'] = False
        store.save_source(source)
        known.add(source['url'])
        added += 1
    return added


from hashlib import sha256
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from pydantic import BaseModel, Field


def canonical_source_url(value: str) -> str:
    parts = urlsplit(value.strip())
    host = (parts.hostname or '').lower().removeprefix('www.')
    path = parts.path.rstrip('/')
    if host == 't.me':
        path = '/' + path.removeprefix('/s/').lstrip('/').casefold()
    port = parts.port
    if port and not ((parts.scheme == 'https' and port == 443) or (parts.scheme == 'http' and port == 80)):
        host += ':' + str(port)
    return urlunsplit((parts.scheme.lower(), host, path, urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True))), ''))


class CatalogRow(BaseModel):
    index: int
    action: str
    source: dict
    existing_id: str | None = None
    selected: bool = False
    changed_fields: list[str] = Field(default_factory=list)
    conflicting_ids: list[str] = Field(default_factory=list)
    error: str | None = None


class CatalogPlan(BaseModel):
    expected_revision: str
    rows: list[CatalogRow]


class CatalogApplyResult(BaseModel):
    added: int = 0
    updated: int = 0
    skipped: int = 0


def catalog_revision(existing: list[dict]) -> str:
    values = sorted(({k: v for k, v in source.items() if k not in ('checkpoint', 'status')} for source in existing), key=lambda x: x.get('id', x.get('url', '')))
    return sha256(json.dumps(values, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


def build_catalog_plan(existing: list[dict], incoming: list[dict]) -> CatalogPlan:
    by_url: dict[str, list[dict]] = {}
    by_key: dict[str, list[dict]] = {}
    for source in existing:
        by_url.setdefault(canonical_source_url(source['url']), []).append(source)
        if source.get('catalog_key'):
            by_key.setdefault(source['catalog_key'], []).append(source)
    seen: set[str] = set()
    rows = []
    for index, source in enumerate(incoming):
        url = canonical_source_url(source.get('url', ''))
        key = source.get('catalog_key')
        options = [*by_url.get(url, []), *by_key.get(key, [])]
        for alias in source.get('fallback_urls', []):
            options.extend(by_url.get(canonical_source_url(alias), []))
        matches = {item['id']: item for item in options}
        row = CatalogRow(index=index, action='add', source=source, selected=True)
        if url in seen:
            row.action, row.selected = 'duplicate', False
        elif len(matches) > 1:
            row.action, row.selected = 'conflict', False
            row.conflicting_ids = sorted(matches)
        elif matches:
            old = next(iter(matches.values()))
            row.action, row.selected, row.existing_id = 'existing', False, old['id']
            row.changed_fields = sorted(k for k, v in source.items() if k not in ('id', 'version', 'checkpoint', 'status') and old.get(k) != v)
        seen.add(url)
        rows.append(row)
    return CatalogPlan(expected_revision=catalog_revision(existing), rows=rows)


def apply_catalog_plan(store, plan: CatalogPlan, expected_revision: str) -> CatalogApplyResult:
    result = CatalogApplyResult()
    with store.connection() as db:
        db.execute('BEGIN IMMEDIATE')
        existing = [{"id": row['id'], **json.loads(row['config'])} for row in db.execute('SELECT id,config FROM sources ORDER BY id LIMIT 5000')]
        if plan.expected_revision != expected_revision or catalog_revision(existing) != expected_revision:
            raise ValueError('catalog revision conflict')
        selected = [row for row in plan.rows if row.selected]
        validated = []
        updated_ids = set()
        urls = {canonical_source_url(s["url"]):s["id"] for s in existing}
        by_id = {row['id']: row for row in existing}
        for row in selected:
            if row.action not in ('add', 'update'):
                raise ValueError('resolve catalog conflicts before applying')
            if row.existing_id and row.existing_id in updated_ids:
                raise ValueError('duplicate update for one source')
            if row.existing_id: updated_ids.add(row.existing_id)
            previous = by_id.get(row.existing_id, {})
            if row.action == 'update' and not previous:
                raise ValueError('source no longer exists')
            values = Source.model_validate({**previous, **row.source, 'version': previous.get('version', 1)}).model_dump(mode='json')
            url = canonical_source_url(values['url'])
            if url in urls and (row.action == 'add' or urls[url] != row.existing_id):
                raise ValueError('duplicate source URL')
            urls[url] = row.existing_id or 'new:'+str(row.index)
            if values['retired'] and values['enabled']:
                raise ValueError('retired sources cannot be enabled')
            validated.append((row, values))
        for row, values in validated:
            store._save_source(db, values, row.existing_id if row.action == 'update' else None)
            if row.action == 'add': result.added += 1
            else: result.updated += 1
        result.skipped = len(plan.rows) - len(selected)
    return result
