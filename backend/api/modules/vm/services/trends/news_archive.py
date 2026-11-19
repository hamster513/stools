"""Project offline news into VM; retain the original ZIP catalog and reference rules."""
import datetime as dt
import hashlib
import json
import re
import uuid
from urllib.parse import urlsplit

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from api.modules.siem.hunting.intel import import_bundle
from api.modules.siem.hunting.models import ThIntelImport, ThIntelItem
from api.modules.vm.trend_models import VmTrendEvidence, VmTrendIngestState, VmTrendPublication, VmTrendSource

from .classify import classify_publication
from .rules import extract_identifiers

OFFLINE_COLLECTOR = 'offline-news-archives'


def _source_identity(source):
    parts = urlsplit(source['url'])
    publisher = (parts.hostname or source['id']).lower().removeprefix('www.')
    channel = parts.path.removeprefix('/s/').strip('/')
    if (parts.netloc.lower() == 't.me' and not parts.query and not parts.fragment
            and re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{3,31}', channel)):
        return {'adapter': 'telegram', 'publisher_id': 'telegram:' + channel.lower(),
                'telegram_mode': 'web', 'telegram_channel': channel.lower()}
    return {'adapter': 'rss', 'publisher_id': publisher}


def project_news(db: Session) -> dict:
    """Idempotent projection, in the caller's transaction and under the ingest lock.

    Rebuild into each collector generation, so a full collector reset cannot hide
    local archives. Stable keys/revisions preserve analyst decisions and AI cache.
    """
    from .analyze import process_publication, refresh_cards

    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('vm_trend_ingest'))"))
    total = db.scalar(select(func.count()).select_from(ThIntelItem).where(ThIntelItem.kind == 'news'))
    if not total:
        return {'news_total': 0}
    state = db.get(VmTrendIngestState, 1)
    if state is None:
        generation = str(uuid.uuid4())
        state = VmTrendIngestState(id=1, collector_id=OFFLINE_COLLECTOR, epoch='1',
                                  generation=generation, active_generation=generation, cursor=0, batch_until=0)
        db.add(state)
        db.flush()
    elif state.active_generation is None:
        # An interrupted first collector download must not hide independent ZIP news
        # or expose the collector's incomplete generation.
        state.active_generation = str(uuid.uuid4())
    generations = {state.generation, state.active_generation} - {None}
    last = ''
    sources, manifests = {}, {}
    changed = {g: set() for g in generations}
    while True:
        rows = list(db.scalars(select(ThIntelItem).where(ThIntelItem.kind == 'news', ThIntelItem.id > last)
                               .order_by(ThIntelItem.id).limit(200)))
        if not rows:
            break
        keys = ['archive-' + row.id for row in rows]
        existing = {(p.generation, p.external_id): p for p in db.scalars(select(VmTrendPublication).where(
            VmTrendPublication.generation.in_(generations), VmTrendPublication.external_id.in_(keys)))}
        for row in rows:
            if row.import_id not in manifests:
                imported = db.get(ThIntelImport, row.import_id)
                manifests[row.import_id] = {s['id']: s for s in json.loads(imported.manifest_json)['sources']}
            source = manifests[row.import_id][row.source_id]
            source_id = 'archive-' + hashlib.sha256(row.source_id.encode()).hexdigest()[:32]
            identity = _source_identity(source)
            publisher = identity['publisher_id']
            for generation in generations:
                if (generation, source_id) not in sources:
                    config = {'id': source_id, 'name': source['name'], 'url': source['url'], **identity,
                              'publisher_id': publisher, 'language': '', 'region': '', 'llm_allowed': False,
                              'content_scope': 'security_news', 'offline_archive': True}
                    saved_source = db.get(VmTrendSource, (generation, source_id))
                    if saved_source is None:
                        db.add(VmTrendSource(generation=generation, external_id=source_id, data=config))
                    else:
                        saved_source.data = config
                    sources[generation, source_id] = config
                external_id = 'archive-' + row.id
                publication = existing.get((generation, external_id))
                if (publication and publication.data.get('archive_content_hash') == row.content_hash
                        and publication.data.get('origin_adapter') == identity['adapter']
                        and publication.data.get('publisher_id') == publisher):
                    continue
                if publication:
                    changed[generation].update(db.scalars(select(VmTrendEvidence.card_id).where(
                        VmTrendEvidence.publication_id == publication.id)))
                value = {'title': row.title, 'text': row.text, 'url': row.url, 'source_id': source_id,
                         'publisher_id': publisher, 'origin_adapter': identity['adapter'], 'evidence_kind': 'publication',
                         'published_at': row.published_at.isoformat() if row.published_at else None,
                         'full_text': row.full_text, 'links': [row.url],
                         'identifiers': extract_identifiers(row.title + '\n' + row.text),
                         'archive_content_hash': row.content_hash, 'offline_archive': True}
                if identity['adapter'] == 'telegram':
                    value['links'] = list(dict.fromkeys([row.url] + [
                        link for link in re.findall(r'https?://[^\s<>\"\']+', row.text)
                        if len(link) <= 2048]))[:100]
                value['classification'] = classify_publication(value, sources[generation, source_id]).model_dump()
                # Deterministic within signed-32-bit storage, including full generation rebuilds.
                revision = int(row.content_hash[:7], 16) + 1
                if publication is None:
                    publication = VmTrendPublication(generation=generation, external_id=external_id,
                                                      source_id=source_id, revision=revision, data=value)
                    db.add(publication)
                publication.data, publication.revision = value, revision
                publication.error = None
                db.flush()
                process_publication(db, publication)
                changed[generation].update(db.scalars(select(VmTrendEvidence.card_id).where(
                    VmTrendEvidence.publication_id == publication.id)))
        last = rows[-1].id
    if state.active_generation:
        refresh_cards(db, changed[state.active_generation], state.active_generation)
    if any(changed.values()):
        state.received_at = dt.datetime.now(dt.UTC)
    return {'news_total': total}


def import_news(db: Session, data: bytes, login: str) -> dict:
    return import_bundle(db, data, login, after_import=project_news)
