"""Normalize Harbor project policy; system and project allowlists are alternatives."""
from collections.abc import Callable
from typing import Any

ARTIFACT_LABELS = {'image': 'Контейнерный образ', 'helm': 'Helm-чарт', 'other': 'Другой артефакт', 'unknown': 'Тип не определён'}
_IMAGE_CONFIGS = {'application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json'}
_WRAPPERS = {'application/vnd.oci.image.manifest.v1+json', 'application/vnd.oci.image.index.v1+json',
             'application/vnd.docker.distribution.manifest.v2+json', 'application/vnd.docker.distribution.manifest.list.v2+json'}


def artifact_kind(raw: dict[str, Any]) -> str:
    media = {str(raw.get(k) or '').lower() for k in ('media_type', 'artifact_type')} - {''}
    kind = str(raw.get('type') or '').upper()
    if any(m.startswith('application/vnd.cncf.helm.') for m in media) or kind in {'CHART', 'HELM'}:
        return 'helm'
    if media - _WRAPPERS - _IMAGE_CONFIGS:
        return 'other'
    if media & _IMAGE_CONFIGS or kind == 'IMAGE':
        return 'image'
    return 'other' if kind else 'unknown'


def _flag(metadata: dict, key: str, default: bool = False) -> bool:
    value = str(metadata.get(key, default)).lower()
    if value not in {'true', 'false', '1', '0'}:
        raise ValueError('invalid policy flag')
    return value in {'true', '1'}


def project_policy(raw: Any, system_allowlist: Callable[[], Any]) -> dict[str, Any]:
    if not isinstance(raw, dict) or not isinstance(raw.get('metadata'), dict):
        raise TypeError('project metadata missing')
    metadata = raw['metadata']
    enabled = _flag(metadata, 'prevent_vul')
    reuse = _flag(metadata, 'reuse_sys_cve_allowlist', True)
    threshold = str(metadata.get('severity') or '').lower()
    if enabled and threshold not in {'none', 'low', 'medium', 'high', 'critical'}:
        raise ValueError('unknown threshold')
    result = {'enabled': enabled, 'threshold': threshold or None,
                  'allowlist_source': 'system' if reuse else 'project', 'allowlist': [], 'expires_at': 0,
                  'signature_required': _flag(metadata, 'enable_content_trust') or _flag(metadata, 'enable_content_trust_cosign')}
    # No allowlist is needed to establish that this gate is disabled.
    if not enabled:
        return result
    allowlist = system_allowlist() if reuse else raw.get('cve_allowlist')
    if not isinstance(allowlist, dict):
        raise TypeError('allowlist missing')
    items = allowlist.get('items') or []
    expiry = allowlist.get('expires_at') or 0
    if not isinstance(items, list) or not isinstance(expiry, int) or isinstance(expiry, bool) or expiry < 0:
        raise ValueError('invalid allowlist')
    ids = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get('cve_id'), str) or not item['cve_id'].strip():
            raise ValueError('invalid allowlist item')
        ids.append(item['cve_id'].strip().upper())
    return {**result, 'allowlist': sorted(set(ids)), 'expires_at': expiry}
