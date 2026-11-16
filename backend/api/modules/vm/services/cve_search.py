from api.modules.vm.core.priority import strongest_msf_rank

"""Read-only CVE lookup across locally loaded references and observations."""
import math
import re

from fastapi import HTTPException
from sqlalchemy import case, func, literal, select, union_all
from sqlalchemy.orm import Session

from api.modules.vm.core.risk import best_exploit_type
from api.modules.vm.ghsa_models import VmRefGhsa, VmRefGhsaAlias
from api.modules.vm.models import (
    VmCve,
    VmImageCve,
    VmRefAttack,
    VmRefEpss,
    VmRefExploitdb,
    VmRefExploitdbCve,
    VmRefKev,
    VmRefMsf,
    VmRefMsfCve,
    VmRefNvd,
    VmRefState,
)
from api.modules.vm.trend_models import VmTrendEnrichment, VmTrendIngestState

from .ghsa_mapping import public_advisories, public_packages, reference_metrics
from .settings import load_settings
from .trends.severity import assessment, valid_score

SOURCES = {'nvd': 'NVD', 'epss': 'EPSS', 'kev': 'CISA KEV', 'exploitdb': 'ExploitDB',
           'msf': 'Metasploit', 'ghsa': 'GitHub Advisory Database', 'attack': 'ATT&CK', 'vm': 'Локальные данные VM', 'harbor': 'Harbor / Trivy', 'collector': 'Контекст сборщика'}
TABLES = [(VmRefNvd, 'nvd'), (VmRefEpss, 'epss'), (VmRefKev, 'kev'), (VmRefExploitdbCve, 'exploitdb'),
          (VmRefMsfCve, 'msf'), (VmRefAttack, 'attack'), (VmCve, 'vm'), (VmImageCve, 'harbor')]


def identifier(value: str, *, prefix: bool = False) -> str:
    value = value.strip().upper()
    pattern = r'CVE-\d{4}(?:-\d{0,19})?' if prefix else r'CVE-\d{4}-\d{4,19}'
    if re.fullmatch(pattern, value):
        return value
    ghsa = r'GHSA(?:-[23456789CFGHJMPQRVWX]{0,4}){0,3}' if prefix else r'GHSA(?:-[23456789CFGHJMPQRVWX]{4}){3}'
    if re.fullmatch(ghsa, value):
        return 'GHSA'+value[4:].lower()
    raise HTTPException(422, 'Введите номер CVE или GHSA' + (' либо начало номера' if prefix else ''))


def primary_url(key: str) -> str:
    return 'https://github.com/advisories/'+key if key.startswith('GHSA-') else 'https://www.cve.org/CVERecord?id='+key


def search(db: Session, q: str, limit: int, offset: int) -> dict:
    prefix = identifier(q, prefix=True)
    match_prefix = prefix.upper()
    queries = []
    for model, source in TABLES:
        column = func.upper(model.cve_id) if source == 'harbor' or match_prefix.startswith('GHSA') else model.cve_id
        queries.append(select(column.label('id'), literal(source).label('source')).where(column.like(match_prefix+'%')))
    queries.extend([
        select(func.upper(VmRefGhsa.ghsa_id).label('id'), literal('ghsa').label('source')).where(VmRefGhsa.ghsa_id.like(prefix+'%')),
        select(func.upper(VmRefGhsaAlias.alias).label('id'), literal('ghsa').label('source')).where(VmRefGhsaAlias.alias.like(prefix+'%')),
    ])
    state = db.get(VmTrendIngestState, 1)
    if state and state.active_generation:
        queries.append(select(func.substr(VmTrendEnrichment.external_id, 5).label('id'), literal('collector').label('source')).where(
            VmTrendEnrichment.generation == state.active_generation, VmTrendEnrichment.retracted.is_(False),
            VmTrendEnrichment.external_id.like('cve:'+match_prefix+'%')))
    candidates = union_all(*queries).subquery()
    rows = db.execute(select(candidates.c.id, func.array_agg(func.distinct(candidates.c.source))).group_by(candidates.c.id)
                      .order_by(case((candidates.c.id == match_prefix, 0), else_=1), candidates.c.id).limit(limit+1).offset(offset)).all()
    return {'items': [{'id': identifier(key), 'sources': [SOURCES[s] for s in sorted(sources)]} for key, sources in rows[:limit]],
            'has_more': len(rows) > limit, 'query': prefix}


def probability(value):
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0 <= value <= 1 else None


def public_cve(db: Session, value: str) -> dict:
    key = identifier(value)
    states = {s.name: s for s in db.scalars(select(VmRefState).limit(20))}
    metrics = reference_metrics(db, [key])[key]
    ids = metrics.identifiers
    upper_ids = [value.upper() for value in ids]
    nvd, epss, kev, ghsa = metrics.nvd, metrics.epss, metrics.kev, metrics.ghsa
    local = db.scalar(select(VmCve).where(func.upper(VmCve.cve_id).in_(upper_ids)).order_by(case((VmCve.cve_id == key, 0), else_=1), VmCve.cve_id).limit(1))
    advisories = public_advisories(db, key)
    packages = public_packages(db, [a.ghsa_id for a in advisories])
    direct_advisory = next((a for a in advisories if a.ghsa_id == key), None)
    catalog = ghsa or direct_advisory
    display_aliases = set(ids)-{key}
    if direct_advisory:
        display_aliases.update(db.scalars(select(VmRefGhsaAlias.alias).where(VmRefGhsaAlias.ghsa_id == key).limit(256)))
    exploits = list(db.execute(select(VmRefExploitdb.exploit_id, VmRefExploitdb.type, VmRefExploitdb.verified)
        .join(VmRefExploitdbCve, VmRefExploitdbCve.exploit_id == VmRefExploitdb.exploit_id)
        .where(VmRefExploitdbCve.cve_id.in_(ids)).distinct().order_by(VmRefExploitdb.exploit_id).limit(500)))
    modules = list(db.execute(select(VmRefMsf.fullname, VmRefMsf.rank, VmRefMsf.name)
        .join(VmRefMsfCve, VmRefMsfCve.fullname == VmRefMsf.fullname).where(VmRefMsfCve.cve_id.in_(ids))
        .distinct().order_by(VmRefMsf.rank.desc(), VmRefMsf.fullname).limit(500)))
    attack = list(db.scalars(select(VmRefAttack.technique_id).where(VmRefAttack.cve_id.in_(ids)).distinct().limit(100)))
    image = db.scalar(select(VmImageCve).where(func.upper(VmImageCve.cve_id).in_(upper_ids))
                      .order_by(VmImageCve.trivy_cvss.desc().nulls_last(), VmImageCve.image_id, VmImageCve.package, VmImageCve.installed_version).limit(1))
    state = db.get(VmTrendIngestState, 1)
    metadata = db.scalar(select(VmTrendEnrichment).where(VmTrendEnrichment.generation == state.active_generation, VmTrendEnrichment.external_id.in_(['cve:'+i for i in ids]), VmTrendEnrichment.retracted.is_(False)).order_by(case((VmTrendEnrichment.external_id == 'cve:'+key, 0), else_=1), VmTrendEnrichment.external_id).limit(1)) if state and state.active_generation else None
    context = metadata.data if metadata and not metadata.retracted else {}
    found = {name for name, present in [('nvd', nvd), ('ghsa', advisories), ('vm', local), ('epss', epss), ('kev', kev),
             ('exploitdb', exploits), ('msf', modules), ('attack', attack), ('harbor', image), ('collector', metadata if metadata and not metadata.retracted else None)] if present}
    for model, name in [(VmRefExploitdbCve, 'exploitdb'), (VmRefMsfCve, 'msf')]:
        if name not in found and db.scalar(select(model.cve_id).where(model.cve_id.in_(ids)).limit(1)):
            found.add(name)
    if not found:
        raise HTTPException(404, 'Уязвимость не найдена в загруженных базах. Проверьте номер и актуальность справочников.')
    score, score_source, version, av, vector = None, '', '', None, ''
    if nvd and valid_score(nvd.cvss_v3): score, score_source, version, av = nvd.cvss_v3, 'nvd_v3', '3.x', nvd.v3_av
    elif nvd and valid_score(nvd.cvss_v2): score, score_source, version, av = nvd.cvss_v2, 'nvd_v2', '2.0', nvd.v2_av
    elif catalog and valid_score(catalog.cvss):
        score, score_source, version, vector = catalog.cvss, 'ghsa', catalog.cvss_version, catalog.cvss_vector
        av = {'N': 'NETWORK', 'A': 'ADJACENT_NETWORK', 'L': 'LOCAL', 'P': 'PHYSICAL'}.get(next((p[3:] for p in vector.split('/') if p.startswith('AV:')), ''))
    elif local and valid_score(local.cvss): score, score_source, version, av = local.cvss, local.cvss_source, '2.0' if local.cvss_source == 'nvd_v2' else '', local.v3_av or local.v2_av
    elif valid_score(context.get('cvss')):
        score, score_source = context['cvss'], 'collector_'+context.get('provenance', {}).get('cvss', 'unknown')
        vector = context.get('cvss_vector', '')
        version = vector.split('/')[0].removeprefix('CVSS:') if vector.startswith('CVSS:') else '2.0' if vector else ''
        av = {'N': 'NETWORK', 'A': 'ADJACENT_NETWORK', 'L': 'LOCAL', 'P': 'PHYSICAL'}.get(next((p[3:] for p in vector.split('/') if p.startswith('AV:')), ''))
    elif image and valid_score(image.trivy_cvss): score, score_source = image.trivy_cvss, 'trivy'
    image_description = (image.description or '') if image else ''
    if image and not image_description.strip():
        image_description = db.scalar(select(VmImageCve.description).where(
            func.upper(VmImageCve.cve_id).in_(upper_ids), func.trim(VmImageCve.description) != '')
            .order_by(VmImageCve.trivy_cvss.desc().nulls_last(), VmImageCve.image_id, VmImageCve.package, VmImageCve.installed_version).limit(1)) or ''
    descriptions = [('nvd', nvd.description if nvd else ''), ('ghsa', (ghsa or direct_advisory).description if ghsa or direct_advisory else ''), ('vm', local.description if local else ''),
                    ('collector', context.get('description', '')), ('harbor', image_description),
                    ('kev', kev.name if kev else '')]
    description_source, description = next(((s, d) for s, d in descriptions if d), ('', ''))
    epss_value = next((p for p in [probability(epss.epss if epss else None), probability(local.epss if local else None), probability(context.get('epss'))] if p is not None), None)
    known = True if kev or (local and local.kev) or context.get('known_exploited') is True else False if ('kev' in states and any(i.startswith('CVE-') for i in ids)) or context.get('known_exploited') is False else None
    weights = load_settings(db).weights
    fallback = (ghsa or direct_advisory).severity if ghsa or direct_advisory else 'unknown'
    if image and score is None and fallback == 'unknown':
        ranks = {'none': 1, 'low': 2, 'medium': 3, 'high': 4, 'critical': 5}
        rank = db.scalar(select(func.max(case(ranks, value=func.lower(VmImageCve.trivy_severity), else_=0)))
                         .where(func.upper(VmImageCve.cve_id).in_(upper_ids)))
        fallback = next((label for label, value in ranks.items() if value == rank), 'unknown')
    if score is None and fallback != 'unknown': score_source = 'ghsa' if ghsa or direct_advisory else 'trivy'
    urls = {'ghsa': primary_url(advisories[0].ghsa_id) if advisories else '', 'nvd': 'https://nvd.nist.gov/vuln/detail/'+(nvd.cve_id if nvd else key), 'kev': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext='+(kev.cve_id if kev else key)}
    return {'id': key, 'primary_url': primary_url(key), 'aliases': sorted(display_aliases),
            'withdrawn': direct_advisory.withdrawn.isoformat() if direct_advisory and direct_advisory.withdrawn else None,
            'advisories': [{'id': a.ghsa_id, 'url': primary_url(a.ghsa_id), 'summary': a.summary, 'reviewed': a.reviewed, 'withdrawn': a.withdrawn.isoformat() if a.withdrawn else None} for a in advisories],
            'packages': [{'ghsa_id': p.ghsa_id, 'ecosystem': p.ecosystem, 'name': p.name, 'purl': p.purl, 'ranges': p.ranges, 'versions': p.versions, 'fixed_versions': p.fixed_versions} for p in packages],
            **assessment(score, score_source, vector=vector, version=version, fallback=fallback), 'description': description,
            'description_source': SOURCES.get(description_source, ''), 'epss': epss_value, 'known_exploited': known,
            'published': nvd.published.isoformat() if nvd and nvd.published else (ghsa or direct_advisory).published.isoformat() if (ghsa or direct_advisory) and (ghsa or direct_advisory).published else local.published.isoformat() if local and local.published else None,
            'modified': nvd.modified.isoformat() if nvd and nvd.modified else (ghsa or direct_advisory).modified.isoformat() if (ghsa or direct_advisory) and (ghsa or direct_advisory).modified else None, 'av': av,
            'exploitdb_type': best_exploit_type([e.type for e in exploits], weights) or (local.exploitdb_type if local else None),
            'msf_rank': strongest_msf_rank(m.rank for m in modules) or (local.msf_rank if local else None),
            'exploits': [{'id': e.exploit_id, 'type': e.type, 'verified': e.verified, 'url': f'https://www.exploit-db.com/exploits/{e.exploit_id}'} for e in exploits],
            'msf_modules': [{'name': m.fullname, 'title': m.name} for m in modules], 'attack': attack,
            'sources': [{'id': s, 'name': SOURCES[s], 'url': urls.get(s, ''),
                         'loaded_at': states[s].loaded_at.isoformat() if s in states else context.get('fetched_at') if s == 'collector' else None} for s in sorted(found)],
            'affected_products': [{'ecosystem': p.ecosystem, 'name': p.name, 'ranges': p.ranges, 'fixed_versions': p.fixed_versions} for p in packages] or context.get('affected_products', [])}
