"""Public CVSS severity, separate from local risk and trend confidence."""
import math
from sqlalchemy import case, func, select
from api.modules.vm.models import VmCve, VmImageCve, VmRefNvd
from api.modules.vm.trend_models import VmTrendEnrichment


def valid_score(score):
    return isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(score) and 0 <= score <= 10


def severity_level(score, version='3.1'):
    if not valid_score(score):
        return 'unknown'
    if version.startswith('2'):
        return 'high' if score >= 7 else 'medium' if score >= 4 else 'low'
    return 'critical' if score >= 9 else 'high' if score >= 7 else 'medium' if score >= 4 else 'low' if score > 0 else 'none'


def assessment(score=None, source='', vector='', version='', fallback='unknown'):
    if not valid_score(score):
        score = None
    return {'cvss': score, 'severity': severity_level(score, version) if score is not None else fallback,
            'cvss_source': source, 'cvss_vector': vector, 'cvss_version': version}


def card_severities(db, identifiers, generation):
    if not identifiers:
        return {}
    result = {key: assessment() for key in identifiers}
    # Whole-page queries; no per-row DB/provider calls and no outbound inventory.
    metadata = db.scalars(select(VmTrendEnrichment).where(VmTrendEnrichment.generation == generation,
        VmTrendEnrichment.external_id.in_(['cve:'+key for key in identifiers]), VmTrendEnrichment.retracted.is_(False)))
    for row in metadata:
        data = row.data
        if valid_score(data.get('cvss')):
            vector = data.get('cvss_vector', '')
            version = vector.split('/')[0].removeprefix('CVSS:') if vector.startswith('CVSS:') else '2.0' if vector else ''
            result[row.external_id.removeprefix('cve:')] = assessment(data['cvss'], 'collector_'+data.get('provenance', {}).get('cvss', 'unknown'), vector, version)
    for row in db.scalars(select(VmRefNvd).where(VmRefNvd.cve_id.in_(identifiers))):
        if result[row.cve_id]['cvss'] is None:
            score, version = (row.cvss_v3, '3.x') if valid_score(row.cvss_v3) else (row.cvss_v2, '2.0')
            if valid_score(score):
                result[row.cve_id] = assessment(score, 'nvd_v3' if version == '3.x' else 'nvd_v2', version=version)
    for row in db.scalars(select(VmCve).where(VmCve.cve_id.in_(identifiers))):
        if result[row.cve_id]['cvss'] is None and valid_score(row.cvss):
            result[row.cve_id] = assessment(row.cvss, row.cvss_source, version='2.0' if row.cvss_source == 'nvd_v2' else '3.x' if row.cvss_source == 'nvd_v3' else '')
    ranks = {'none': 1, 'low': 2, 'medium': 3, 'high': 4, 'critical': 5}
    images = db.execute(select(func.upper(VmImageCve.cve_id), func.max(VmImageCve.trivy_cvss),
        func.max(case(ranks, value=func.lower(VmImageCve.trivy_severity), else_=0))).where(
        func.upper(VmImageCve.cve_id).in_(identifiers)).group_by(func.upper(VmImageCve.cve_id)))
    labels = {rank: level for level, rank in ranks.items()}
    for identifier, score, rank in images:
        if result[identifier]['cvss'] is None:
            result[identifier] = assessment(score, 'trivy', fallback=labels.get(rank, 'unknown'))
    return result
