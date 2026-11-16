"""Local host observations and scenario risk; never sent to the reading assistant."""
from itertools import product

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import aggregate_order_by
from sqlalchemy.orm import Session

from api.modules.ksc.models import KscSnapshot
from api.modules.ksc.software_models import KscSoftware, KscSoftwareInventory
from api.modules.vm.core.priority import AssetContext, priority_score
from api.modules.vm.core.risk import CveInputs, level
from api.modules.vm.core.weights import CRITICALITIES
from api.modules.vm.models import VmHost, VmHostCve, VmImage, VmImageCve
from api.modules.vm.software_models import VmKscCve

from .ghsa_mapping import equivalents
from .settings import load_settings
from .software import latest_snapshot_ids


def risk_range(data: dict, weights) -> dict:
    inputs = CveInputs(epss=data['epss'], cvss=data['cvss'], av=data['av'],
        exploitdb_type=data['exploitdb_type'], msf_rank=data['msf_rank'],
        kev=data['known_exploited'] is True, kev_loaded=data['known_exploited'] is not None)
    scenarios, assumptions = [], set()
    for criticality, internet, confidential in product((c for c in CRITICALITIES if c != 'None'), (False, True), (False, True)):
        result = priority_score(inputs, AssetContext(criticality, internet, confidential))
        scenarios.append({'score': result.score, 'criticality': criticality, 'internet': internet, 'confidential': confidential})
        assumptions.update(result.missing)
    low, high = min(scenarios, key=lambda v: v['score']), max(scenarios, key=lambda v: v['score'])
    return {'min': low['score'], 'max': high['score'], 'min_profile': low, 'max_profile': high,
        'min_level': level(low['score'], weights.levels), 'max_level': level(high['score'], weights.levels),
        'assumptions': sorted(assumptions), 'scenario_count': len(scenarios)}


def hosts(db: Session, cve_id: str, limit: int = 50, offset: int = 0) -> dict:
    weights = load_settings(db).weights
    ids = equivalents(db, cve_id)
    matches = select(VmHostCve.host_id, func.max(VmHostCve.risk).label('risk'),
        func.array_agg(aggregate_order_by(VmHostCve.cve_id, VmHostCve.risk.desc(), VmHostCve.cve_id)).label('identifiers'))        .where(func.upper(VmHostCve.cve_id).in_([i.upper() for i in ids])).group_by(VmHostCve.host_id).subquery()
    total, low, high = db.execute(select(func.count(),func.min(matches.c.risk),func.max(matches.c.risk))).one()
    rows = db.execute(select(VmHost, matches.c.risk, matches.c.identifiers).join(matches, matches.c.host_id == VmHost.id)
        .order_by(matches.c.risk.desc(), VmHost.hostname, VmHost.id).limit(limit).offset(offset))
    return {'hosts_total': total, 'risk_min': low, 'risk_max': high,
        'hosts': [{'id': h.id, 'hostname': h.hostname, 'ip': h.ip, 'os': h.os_name, 'criticality': h.criticality,
        'zone': h.zone, 'internet': h.internet, 'risk': score, 'level': level(score, weights.levels),
        'identifier': observed[0], 'identifiers': observed} for h, score, observed in rows]}


def images(db: Session, identifier: str, limit: int = 50, offset: int = 0) -> dict:
    ids = [i.upper() for i in equivalents(db, identifier)]
    matches = select(VmImageCve.image_id, func.max(VmImageCve.risk).label('risk'),
        func.array_agg(func.distinct(VmImageCve.cve_id)).label('identifiers'),
        func.array_agg(func.distinct(VmImageCve.package)).label('packages')).where(
        func.upper(VmImageCve.cve_id).in_(ids)).group_by(VmImageCve.image_id).subquery()
    total = db.scalar(select(func.count()).select_from(matches))
    rows = db.execute(select(VmImage, matches.c.risk, matches.c.identifiers, matches.c.packages)
        .join(matches, matches.c.image_id == VmImage.id).order_by(matches.c.risk.desc().nulls_last(), VmImage.id).limit(limit).offset(offset))
    return {'total': total, 'items': [{'id': image.id, 'project': image.project, 'repository': image.repository,
        'digest': image.digest, 'risk': score, 'identifiers': sorted(observed), 'packages': sorted(packages)} for image,score,observed,packages in rows]}


def software_matches(db: Session, cve_id: str, limit: int = 50, offset: int = 0) -> dict:
    ids = equivalents(db, cve_id)
    query = select(VmKscCve, KscSoftware, KscSoftwareInventory, KscSnapshot.server_id).join(
        KscSoftware, VmKscCve.software_id == KscSoftware.id).join(KscSoftwareInventory,
        KscSoftware.inventory_id == KscSoftwareInventory.id).join(KscSnapshot,
        KscSoftwareInventory.snapshot_id == KscSnapshot.id).where(VmKscCve.cve_id.in_(ids),
        VmKscCve.state.in_(['affected', 'unknown']), KscSnapshot.id.in_(latest_snapshot_ids()))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.execute(query.order_by(KscSoftwareInventory.host_name, VmKscCve.id).limit(limit).offset(offset))
    return {'total': total, 'items': [{'id': f.id, 'hostname': inv.host_name, 'host_id': inv.host_id, 'server_id': server,
        'software': s.name, 'version': s.version, 'state': f.state, 'reason': f.reason,
        'identifier': f.cve_id, 'checked_at': f.checked_at} for f, s, inv, server in rows]}


def details(db: Session, data: dict) -> dict:
    image_matches = images(db, data['id'])
    return {**data, 'risk': risk_range(data, load_settings(db).weights), 'matches': hosts(db, data['id']),
        'software_matches': software_matches(db, data['id']), 'images_total': image_matches['total'], 'images': image_matches}
