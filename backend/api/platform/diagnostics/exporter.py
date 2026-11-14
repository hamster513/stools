"""Read-only bounded relationship selection and strict sanitized bundle validation."""
from __future__ import annotations

import datetime as dt
import gzip
import json
import re
from pathlib import Path

from sqlalchemy import Boolean, DateTime, Integer, String, func, or_, select

from api.modules.ad import models as ad
from api.modules.assets import models as a
from api.modules.ksc import models as k

from .sanitize import Anonymizer
from .schema import AD_DOMAIN_FIELDS, AD_OBJECT_FIELDS, FIELDS, TABLE_MODELS, WARNINGS, BundleError

MAX_RECORDS = 5000
MAX_BYTES = 50 * 1024 * 1024
ENUMS = {
    'source': {'ad', 'ksc', 'vm', 'file', 'ldap', 'online'},
    'kind': {'session', 'owner', 'local_group'},
    'member_kind': {'user', 'group', 'computer', 'well_known', 'unknown'},
    'os_family': {'', 'windows', 'linux'},
    'criticality': {'', 'Critical', 'High', 'Medium', 'Low'},
    'protection': {'none', 'on', 'off'},
    'status': {'ok', 'warning', 'critical'},
    'in_ad': {'both', 'ksc_only'},
    'via': {'restricted_groups', 'gpp', ''},
    'action': {'', 'member', 'memberof', 'add', 'replace', 'delete', 'разрешить', 'запретить', 'по правилам программ', 'allow', 'deny'},
    'layer': {'packet', 'application', 'app'},
    'direction': {'', 'входящий (пакет)', 'исходящий (пакет)', 'входящий/исходящий', 'входящий (поток)', 'исходящий (поток)'},
    'protocol': {'', 'TCP', 'UDP', 'ICMP', 'ICMPv6', 'любой'},
}
PSEUDO = re.compile(r'(?:entity|domain|key)-[a-f0-9]{16}')


class Selection:
    def __init__(self, db):
        self.db = db
        self.rows = {name: {} for name in TABLE_MODELS}

    def add(self, model, condition):
        rows = self.db.scalars(select(model).where(condition).order_by(model.id).limit(MAX_RECORDS + 1)).all()
        dest = self.rows[model.__tablename__]
        previous = set(dest)
        dest.update((row.id, row) for row in rows)
        if sum(map(len, self.rows.values())) > MAX_RECORDS:
            raise BundleError('Diagnostic record limit exceeded.')
        return set(dest) - previous

    def values(self, model):
        return list(self.rows[model.__tablename__].values())

    def ids(self, model):
        return set(self.rows[model.__tablename__])


def _assets(selection, kind, entity_id):
    s = selection
    root = a.AssetUser if kind == 'user' else a.Asset
    s.add(root, root.id == entity_id)
    if not s.ids(root):
        raise BundleError('Selected entity is unavailable.')
    s.add(a.AssetUserHost, a.AssetUserHost.user_id == entity_id if kind == 'user' else a.AssetUserHost.asset_id == entity_id)
    links = s.values(a.AssetUserHost)
    s.add(a.Asset, a.Asset.id.in_({r.asset_id for r in links}))
    s.add(a.AssetUser, a.AssetUser.id.in_({r.user_id for r in links}))
    # The account/host seed set stays fixed after these first-hop links.
    s.add(a.AssetUserGroup, a.AssetUserGroup.user_id.in_(s.ids(a.AssetUser)))
    users = {row.id: row for row in s.values(a.AssetUser)}
    group_scopes = {}
    for link in s.values(a.AssetUserGroup):
        user = users[link.user_id]
        group_scopes.setdefault((user.domain.lower(), user.local), set()).add(link.group_sid)
    for (domain, local), sids in group_scopes.items():
        scope = a.AssetGroup.host_asset_id.in_(s.ids(a.Asset)) if local else func.lower(a.AssetGroup.domain) == domain
        s.add(a.AssetGroup, a.AssetGroup.sid.in_(sids) & (a.AssetGroup.local == local) & scope)
    s.add(a.AssetGroupMember, or_(a.AssetGroupMember.user_id.in_(s.ids(a.AssetUser)), a.AssetGroupMember.asset_id.in_(s.ids(a.Asset))))
    # Keep complete parent chains for the seeds, without expanding a group's roster.
    while True:
        previous = sum(map(len, s.rows.values()))
        members = s.values(a.AssetGroupMember)
        s.add(a.AssetGroup, a.AssetGroup.id.in_({row.group_id for row in members}))
        s.add(a.AssetGroupMember, a.AssetGroupMember.member_group_id.in_(s.ids(a.AssetGroup)))
        if previous == sum(map(len, s.rows.values())):
            break
    gpo_scopes = {}
    for group in s.values(a.AssetGroup):
        if not group.local:
            gpo_scopes.setdefault(group.domain.lower(), set()).add(group.sid)
    for domain, sids in gpo_scopes.items():
        s.add(a.AssetGroupGpo, (func.lower(a.AssetGroupGpo.domain) == domain) & a.AssetGroupGpo.group_sid.in_(sids))
    s.add(a.AssetObservation, (a.AssetObservation.asset_id.in_(s.ids(a.Asset))) & a.AssetObservation.source.in_(['ad', 'ksc']))
    s.add(a.AssetUserObservation, (a.AssetUserObservation.user_id.in_(s.ids(a.AssetUser))) & a.AssetUserObservation.source.in_(['ad', 'ksc']))


def _ad_slice(raw, keys):
    from api.modules.ad.core.account_groups import account_groups
    from api.modules.ad.core.export import AdExport, ExportIndex, fsp_sid

    export = AdExport.model_validate(raw)
    idx = ExportIndex(export)
    key_dns = {key.lower() for key in keys}
    subjects = [obj for obj in export.objects if obj.sid in keys or obj.dn.lower() in key_dns]
    selected = {obj.dn.lower() for obj in subjects}
    account_memberships = account_groups(idx)
    subject_sids = keys | {obj.sid for obj in subjects if obj.sid}
    group_sids = {group['sid'] for sid in subject_sids for group in account_memberships.groups.get(sid, [])}
    selected |= {obj.dn.lower() for obj in export.objects if obj.sid in group_sids}
    # Retain every group in each selected account's membership chain. Only the
    # roster is scoped: unrelated users/computers and child groups stay outside.
    membership_dns = selected.copy()
    # All OU ancestors and their GPOs are needed for existing applicability calculations.
    for dn in list(selected):
        parts = re.split(r'(?<!\\),', dn)
        selected.update(','.join(parts[i:]) for i in range(1, len(parts)))
    for obj in export.objects:
        if obj.dn.lower() in selected and obj.gpLink:
            selected.update(dn.lower() for dn in re.findall(r'\[LDAP://(.+?);\d+\]', obj.gpLink, re.IGNORECASE))
    objects = []
    for obj in export.objects:
        if obj.dn.lower() not in selected:
            continue
        row = obj.model_dump(mode='json', by_alias=True, exclude_none=True)
        row['member'] = [dn for dn in obj.member if dn.lower() in membership_dns or fsp_sid(dn) in subject_sids]
        objects.append(row)
    # Count all retained objects and membership edges; never trim a seed's groups.
    if len(objects) + sum(len(obj.get('member', [])) for obj in objects) > MAX_RECORDS:
        raise BundleError('Diagnostic record limit exceeded.')
    return {'format': 'stools-ad/1', 'collected_at': export.collected_at.isoformat(), 'domain': export.domain.model_dump(), 'objects': objects}


def _ad(s, data_dir):
    identities = {}
    for model, attr in [(a.AssetUserObservation, 'data'), (a.AssetObservation, 'extra')]:
        for row in s.values(model):
            info = getattr(row, attr)
            did = info.get('domain_id') if isinstance(info, dict) else None
            if row.source == 'ad' and type(did) is int:
                identities.setdefault(did, set()).add(row.source_key)
    s.add(ad.AdDomain, ad.AdDomain.id.in_(identities))
    exports = []
    for did, keys in identities.items():
        snapshot = s.db.scalar(select(ad.AdSnapshot).where(ad.AdSnapshot.domain_id == did).order_by(ad.AdSnapshot.collected_at.desc(), ad.AdSnapshot.id.desc()).limit(1))
        if snapshot is None:
            continue
        s.add(ad.AdSnapshot, ad.AdSnapshot.id == snapshot.id)
        path = Path(data_dir) / 'ad' / f'{snapshot.id}.json.gz'
        try:
            with gzip.open(path, 'rb') as stream:
                data = stream.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise BundleError('Diagnostic source size limit exceeded.')
            exports.append({'snapshot_id': snapshot.id, 'export': _ad_slice(json.loads(data), keys)})
        except BundleError:
            raise
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            raise BundleError('Latest directory export is unavailable or unsupported.') from None
    return exports


def _ksc(s):
    keys = {}
    for row in s.values(a.AssetObservation):
        if row.source != 'ksc':
            continue
        server_id, sep, host_id = row.source_key.partition(':')
        if sep and server_id.isdigit():
            keys.setdefault(int(server_id), set()).add(host_id)
    s.add(k.KscServer, k.KscServer.id.in_(keys))
    for server_id, host_ids in keys.items():
        snapshot = s.db.scalar(select(k.KscSnapshot).where(k.KscSnapshot.server_id == server_id).order_by(k.KscSnapshot.collected_at.desc(), k.KscSnapshot.id.desc()).limit(1))
        if snapshot is None:
            continue
        s.add(k.KscSnapshot, k.KscSnapshot.id == snapshot.id)
        s.add(k.KscHost, (k.KscHost.snapshot_id == snapshot.id) & k.KscHost.host_id.in_(host_ids))
        groups = {r.group_id for r in s.values(k.KscHost) if r.snapshot_id == snapshot.id and r.group_id is not None}
        s.add(k.KscPolicyScope, (k.KscPolicyScope.snapshot_id == snapshot.id) & k.KscPolicyScope.group_id.in_(groups))
        policies = {r.policy_id for r in s.values(k.KscPolicyScope) if r.snapshot_id == snapshot.id}
        for model in (k.KscPolicy, k.KscProfile, k.KscNetRule, k.KscPolicyFirewall):
            s.add(model, (model.snapshot_id == snapshot.id) & model.policy_id.in_(policies))


def _string(anon, table, row, field, value):
    if not value:
        return value
    if field in ENUMS:
        if value not in ENUMS[field]:
            if '' in ENUMS[field]:
                return ''
            raise BundleError('Unsupported diagnostic source value.')
        return value
    if field == 'source_key':
        if row.source == 'ad':
            return anon.sid(value) if value.upper().startswith('S-1-') else anon.dn(value)
        if table == 'asset_observation':
            server, sep, host = value.partition(':')
            if sep and server.isdigit():
                return f'{anon.identifier("ksc_server", int(server))}:{anon.token(host)}'
        return anon.token(value)
    if field in {'sid', 'group_sid', 'member_sid', 'local_group_sid'}:
        return anon.sid(value)
    if field in {'dn', 'gpo_dn'}:
        return anon.dn(value)
    if field in {'domain', 'dns_root', 'member_domain'}:
        return anon.domain(value)
    if field == 'fqdn':
        return anon.fqdn(value)
    if field in {'member_name', 'group_name'}:
        return anon.principal(value, directory=True)
    if field in {'upn', 'name_key'}:
        return anon.principal(value)
    if field == 'ip':
        return anon.ip(value)
    if field in {'local_ports', 'remote_ports'}:
        return value if re.fullmatch(r'[0-9,; \-]{0,255}', value) else ''
    if field in {'name', 'sam', 'netbios'}:
        return anon.name(value)
    return anon.token(value, 'key' if field in {'key', 'group_key'} else 'entity')


def _row(anon, model, row, s):
    table = model.__tablename__
    result = {}
    for field in sorted(FIELDS[table]):
        value = getattr(row, field)
        column = model.__table__.c[field]
        if field == 'id':
            value = anon.identifier(table, value)
        elif column.foreign_keys:
            target = next(iter(column.foreign_keys)).column.table.name
            if value is not None and value not in s.rows[target]:
                if not column.nullable:
                    raise BundleError('Unsupported diagnostic relationship.')
                value = None
            value = anon.identifier(target, value)
        elif table.startswith('ksc_') and field in {'policy_id', 'group_id'}:
            value = anon.identifier(f'{field}:{row.snapshot_id}', value)
        elif isinstance(column.type, DateTime):
            value = anon.date(value)
        elif field in {'data', 'extra'}:
            did = value.get('domain_id') if isinstance(value, dict) else None
            value = {'domain_id': anon.identifier('ad_domain', did)} if type(did) is int and did in s.ids(ad.AdDomain) else {}
        elif field == 'ips':
            value = [anon.ip(ip) for ip in value if isinstance(ip, str) and anon.ip(ip)]
        elif field == 'hosts' and table == 'asset_group_gpo':
            value = [anon.fqdn(host) for host in value if isinstance(host, str)]
        elif field == 'sources':
            value = [source for source in value if source in {'ad', 'vm', 'ksc'}]
        elif isinstance(value, str):
            value = _string(anon, table, row, field, value)
        result[field] = value
    return result


def _sanitize_ad(anon, item):
    raw = item['export']
    domain = raw['domain']
    clean = {'format': 'stools-ad/1', 'collected_at': anon.date(raw['collected_at']), 'domain': {'dn': anon.dn(domain['dn']), 'sid': anon.sid(domain['sid']), 'dns_root': anon.domain(domain.get('dns_root', '')), 'netbios': anon.name(domain.get('netbios', ''))}, 'objects': []}
    for obj in raw['objects']:
        row = {}
        for field in AD_OBJECT_FIELDS & obj.keys():
            value = obj[field]
            if field == 'dn':
                value = anon.dn(value)
            elif field == 'sid':
                value = anon.sid(value)
            elif field == 'member':
                value = [anon.dn(dn) for dn in value]
            elif field == 'gpLink':
                value = anon.gp_link(value)
            elif field in {'whenCreated', 'whenChanged'}:
                value = anon.date(value)
            elif field == 'userPrincipalName':
                value = anon.principal(value)
            elif field == 'dNSHostName':
                value = anon.fqdn(value)
            elif field in {'sam', 'name', 'displayName'}:
                value = anon.name(value)
            row[field] = value
        clean['objects'].append(row)
    return {'snapshot_id': anon.identifier('ad_snapshot', item['snapshot_id']), 'export': clean}


def build_bundle(db, data_dir, kind: str, entity_id: int) -> dict:
    if kind not in {'user', 'host'} or type(entity_id) is not int or entity_id <= 0:
        raise BundleError('Invalid diagnostic selection.')
    # Even sessions configured with autoflush=True must not flush unrelated pending changes.
    with db.no_autoflush:
        selection = Selection(db)
        _assets(selection, kind, entity_id)
        exports = _ad(selection, data_dir)
        _ksc(selection)
        anon = Anonymizer()
        for domain in selection.values(ad.AdDomain):
            anon.register_directory_domain(domain.dns_root, domain.netbios)
        for item in exports:
            domain = item['export']['domain']
            anon.register_directory_domain(domain.get('dns_root', ''), domain.get('netbios', ''))
        # Preallocate IDs in stable row order, remapping all numeric table identities.
        for table, rows in selection.rows.items():
            for row_id in sorted(rows):
                anon.identifier(table, row_id)
        tables = {table: [_row(anon, TABLE_MODELS[table], row, selection) for row in rows.values()] for table, rows in selection.rows.items() if rows}
        bundle = {'format': 'stools-diagnostic/1', 'created_at': dt.datetime.now(dt.UTC).isoformat(), 'root': {'kind': kind, 'id': anon.identifier('asset_user' if kind == 'user' else 'asset', entity_id)}, 'tables': tables, 'ad_exports': [_sanitize_ad(anon, item) for item in exports], 'report': {'counts': {name: len(rows) for name, rows in tables.items()}, 'limitations': list(WARNINGS)}}
        return validate_bundle(bundle)


def _invalid():
    raise BundleError('Invalid or unsupported diagnostic package.')


def _date(value):
    if not isinstance(value, str) or len(value) > 40:
        _invalid()
    try:
        dt.datetime.fromisoformat(value)
    except ValueError:
        _invalid()


def _safe_string(field, value, maxlen=2048):
    if not isinstance(value, str) or len(value) > maxlen:
        _invalid()
    if not value:
        return
    if field in ENUMS:
        if value not in ENUMS[field]:
            _invalid()
        return
    if field in {'sid', 'group_sid', 'member_sid', 'local_group_sid'}:
        if not re.fullmatch(r'S-1-[0-9-]{1,100}', value):
            _invalid()
        return
    if field == 'ip':
        import ipaddress
        try:
            ipaddress.ip_address(value)
        except ValueError:
            _invalid()
        return
    if field in {'local_ports', 'remote_ports'}:
        if not re.fullmatch(r'[0-9,; \-]{1,255}', value):
            _invalid()
        return
    # Only generated identity grammar; no arbitrary uploaded labels or source text.
    remainder = PSEUDO.sub('', value)
    remainder = re.sub(r'S-1-[0-9-]+', '', remainder)
    remainder = remainder.replace('.invalid', '')
    remainder = re.sub(r'(?:CN|OU|DC)=', '', remainder)
    if re.sub(r'[.,:@\\0-9-]', '', remainder):
        _invalid()


def _validate_ad(export):
    if not isinstance(export, dict) or set(export) != {'format', 'collected_at', 'domain', 'objects'} or export['format'] != 'stools-ad/1':
        _invalid()
    _date(export['collected_at'])
    domain = export['domain']
    if not isinstance(domain, dict) or set(domain) != AD_DOMAIN_FIELDS:
        _invalid()
    for field, value in domain.items():
        _safe_string(field, value)
    objects = export['objects']
    if not isinstance(objects, list):
        _invalid()
    count = len(objects)
    for obj in objects:
        if not isinstance(obj, dict) or not {'dn', 'class'} <= obj.keys() or obj.keys() - AD_OBJECT_FIELDS:
            _invalid()
        for field, value in obj.items():
            if field == 'class':
                if value not in {'user', 'computer', 'group', 'domainDNS', 'organizationalUnit', 'groupPolicyContainer', 'container', 'site', 'foreignSecurityPrincipal'}:
                    _invalid()
            elif field in {'uac', 'primaryGroupID', 'gpOptions', 'flags'}:
                if type(value) is not int or not 0 <= value <= 2**32:
                    _invalid()
            elif field in {'whenCreated', 'whenChanged'}:
                _date(value)
            elif field == 'member':
                if not isinstance(value, list):
                    _invalid()
                count += len(value)
                for dn in value:
                    _safe_string('dn', dn)
            elif field == 'gpLink':
                if not isinstance(value, str) or len(value) > MAX_BYTES:
                    _invalid()
                parts = re.findall(r'\[LDAP://([^\[\]]+);(\d+)\]', value)
                if ''.join(f'[LDAP://{dn};{flag}]' for dn, flag in parts) != value:
                    _invalid()
                for dn, flag in parts:
                    _safe_string('dn', dn)
                    if int(flag) > 3:
                        _invalid()
            else:
                _safe_string(field, value)
    return count


def _validate_bundle(bundle) -> dict:
    if not isinstance(bundle, dict) or set(bundle) != {'format', 'created_at', 'root', 'tables', 'ad_exports', 'report'} or bundle['format'] != 'stools-diagnostic/1':
        _invalid()
    _date(bundle['created_at'])
    root = bundle['root']
    if not isinstance(root, dict) or set(root) != {'kind', 'id'} or root['kind'] not in {'user', 'host'} or type(root['id']) is not int:
        _invalid()
    tables = bundle['tables']
    if not isinstance(tables, dict) or tables.keys() - TABLE_MODELS.keys():
        _invalid()
    ids = {}
    count = 0
    for table, rows in tables.items():
        model = TABLE_MODELS[table]
        if not isinstance(rows, list):
            _invalid()
        count += len(rows)
        ids[table] = set()
        for row in rows:
            if not isinstance(row, dict) or row.keys() - FIELDS[table] or type(row.get('id')) is not int or row['id'] <= 0 or row['id'] in ids[table]:
                _invalid()
            ids[table].add(row['id'])
            for column in model.__table__.columns:
                if column.name not in row and not column.nullable and column.default is None and column.server_default is None and not column.primary_key:
                    _invalid()
            for field, value in row.items():
                column = model.__table__.c[field]
                if value is None:
                    if not column.nullable:
                        _invalid()
                elif isinstance(column.type, Boolean):
                    if type(value) is not bool:
                        _invalid()
                elif isinstance(column.type, Integer):
                    if type(value) is not int or not -(2**63) < value < 2**63:
                        _invalid()
                elif isinstance(column.type, DateTime):
                    _date(value)
                elif field in {'data', 'extra'}:
                    if not isinstance(value, dict) or value.keys() - {'domain_id'} or any(type(v) is not int for v in value.values()):
                        _invalid()
                elif field in {'ips', 'hosts', 'sources'}:
                    if not isinstance(value, list) or len(value) > MAX_RECORDS:
                        _invalid()
                    for entry in value:
                        _safe_string('ip' if field == 'ips' else 'source' if field == 'sources' else 'name', entry)
                elif isinstance(column.type, String):
                    _safe_string(field, value, column.type.length or 2048)
                else:
                    _invalid()
    for table, rows in tables.items():
        for row in rows:
            for field, value in row.items():
                column = TABLE_MODELS[table].__table__.c[field]
                for fk in column.foreign_keys:
                    if value is not None and value not in ids.get(fk.column.table.name, set()):
                        _invalid()
                if field in {'data', 'extra'} and value.get('domain_id') is not None and value['domain_id'] not in ids.get('ad_domain', set()):
                    _invalid()
    root_table = 'asset_user' if root['kind'] == 'user' else 'asset'
    if root['id'] not in ids.get(root_table, set()):
        _invalid()
    exports = bundle['ad_exports']
    if not isinstance(exports, list):
        _invalid()
    snapshots = set()
    for item in exports:
        if not isinstance(item, dict) or set(item) != {'snapshot_id', 'export'} or type(item['snapshot_id']) is not int or item['snapshot_id'] not in ids.get('ad_snapshot', set()) or item['snapshot_id'] in snapshots:
            _invalid()
        snapshots.add(item['snapshot_id'])
        count += _validate_ad(item['export'])
    if count > MAX_RECORDS:
        raise BundleError('Diagnostic record limit exceeded.')
    report = bundle['report']
    if not isinstance(report, dict) or set(report) != {'counts', 'limitations'} or report['counts'] != {table: len(rows) for table, rows in tables.items()} or not isinstance(report['limitations'], list) or any(warning not in WARNINGS for warning in report['limitations']):
        _invalid()
    try:
        if len(json.dumps(bundle, ensure_ascii=False, allow_nan=False).encode()) > MAX_BYTES:
            raise BundleError('Diagnostic package size limit exceeded.')
    except (TypeError, ValueError, RecursionError):
        _invalid()
    return bundle


def validate_bundle(bundle) -> dict:
    try:
        return _validate_bundle(bundle)
    except BundleError:
        raise
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError):
        raise BundleError('Invalid or unsupported diagnostic package.') from None
