"""Native AD diagnostic slices. Policy syntax is preserved or rejected explicitly."""
from __future__ import annotations

import base64
import datetime as dt
import re
import struct
from collections import defaultdict, deque
from urllib.parse import urlsplit, urlunsplit

from api.modules.ad.core.checks.domain import functional_level_value
from api.modules.ad.core.export import (
    CRITICAL_ACL_UNREAD,
    AdExport,
    fsp_sid,
)
from api.modules.ad.core.gpo_files import (
    inf_group_membership,
    keep_registry,
    parse_gplink,
    parse_inf,
)
from api.modules.ad.core.gpo_rights import BUILTIN_LOCAL_GROUPS
from api.modules.ad.core.sd import sid_to_str, str_to_sid

from .schema import BundleError

_DN_FIELDS = {'dn', 'msDS-OIDToGroupLink', 'site', 'krbTgtLink'}
_DNS = {'dNSHostName', 'trustPartner'}
_DN_LISTS = {'member', 'revealOnDemand', 'neverReveal', 'revealedUsers', 'psoAppliesTo'}
_NAMES = {'sam', 'name', 'displayName', 'cn', 'flatName'}
_SIDS = {'sid', 'creatorSid'}
_SD = {'sd', 'allowedToActOnBehalf'}
_DATES = {'whenCreated', 'whenChanged'}
_FILETIMES = {'lastLogonTimestamp', 'pwdLastSet', 'lapsExpiry', 'lapsNewExpiry'}
_NUMBERS = {'uac', 'supportedEncryptionTypes', 'adminCount', 'primaryGroupID', 'trustAttributes', 'trustDirection', 'trustType', 'allowUpdate', 'psoMinLength', 'psoLockoutThreshold', 'psoPrecedence', 'gpOptions', 'flags', 'msPKI-Enrollment-Flag', 'msPKI-Certificate-Name-Flag', 'msPKI-RA-Signature', 'msPKI-Template-Schema-Version'}
_BOOLS = {'trustedForDelegation', 'trustedToAuthForDelegation', 'hasUnixPassword', 'psoReversible', 'psoComplexity'}
_OIDS = {'pKIExtendedKeyUsage', 'msPKI-Certificate-Policy', 'msPKI-Certificate-Application-Policy', 'msPKI-RA-Application-Policies'}
_OBJECT_FIELDS = _DN_FIELDS | _DNS | _DN_LISTS | _NAMES | _SIDS | _SD | _DATES | _FILETIMES | _NUMBERS | _BOOLS | _OIDS | {
    'class', 'sIDHistory', 'spn', 'allowedToDelegateTo', 'userPrincipalName', 'gpcFileSysPath', 'gpLink',
    'scriptPath', 'operatingSystem', 'operatingSystemVersion', 'certificateTemplates', 'store', 'partition', 'msPKI-Cert-Template-OID',
}
_DOMAIN_FIELDS = {'dn', 'sid', 'dns_root', 'netbios', 'configuration_dn', 'schema_dn', 'machine_account_quota', 'functional_level', 'forest_functional_level', 'min_pwd_length', 'lockout_threshold', 'pwd_properties', 'pwd_history_length', 'recycle_bin', 'ds_heuristics', 'smartcard_rotation', 'laps_legacy_schema', 'laps_schema', 'last_backup', 'backup_read', 'sysvol_replication', 'schema_poss_superiors'}
_GPO_FIELDS = {'registry', 'gpp', 'audit', 'scripts', 'acl', 'notes'}
_GPP_FIELDS = {'scope', 'file', 'kind', 'name', 'user', 'cpassword', 'action', 'members', 'group_sid', 'group_name', 'path', 'filtered', 'delete_all', 'disabled'}
_REG_FIELDS = {'scope', 'key', 'value', 'type', 'data'}
_SID = re.compile(r'S-\d+-\d+(?:-\d+)+', re.IGNORECASE)
_UUID = re.compile(r'\{?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}?', re.IGNORECASE)
_BUILTINS = {name.casefold(): f'S-1-5-32-{rid}' for rid, name in BUILTIN_LOCAL_GROUPS.items()}
_WINLOGON = r'software\microsoft\windows nt\currentversion\winlogon'
_HARDENED = r'software\policies\microsoft\windows\networkprovider\hardenedpaths'
_PUBLIC_PATH = {'sysvol', 'netlogon', 'policies', 'machine', 'user', 'microsoft', 'windows nt', 'secedit', 'scripts', 'startup', 'shutdown', 'logon', 'logoff'}
_EXTENSIONS = {'ps1', 'bat', 'cmd', 'vbs', 'js', 'exe', 'dll', 'xml', 'inf', 'ini', 'pol', 'csv'}
_ENVIRONMENT = {'%systemroot%', '%windir%', '%systemdrive%', '%userprofile%', '%programfiles%', '%programfiles(x86)%', '%appdata%', '%localappdata%', '%temp%', '%tmp%'}
_CLASSES = {'domainDNS', 'organizationalUnit', 'groupPolicyContainer', 'group', 'user', 'computer', 'foreignSecurityPrincipal', 'container', 'msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount', 'msDS-DelegatedManagedServiceAccount', 'msDS-PasswordSettings', 'site', 'subnet', 'trustedDomain', 'dnsZone', 'pKIEnrollmentService', 'pKICertificateTemplate', 'msPKI-Enterprise-Oid', 'certificationAuthority'}
_GUID_NAMES = {'DS-Replication-Get-Changes', 'DS-Replication-Get-Changes-All', 'DS-Replication-Get-Changes-In-Filtered-Set', 'Enroll', 'AutoEnroll', 'msDS-KeyCredentialLink', 'msDS-DelegatedManagedServiceAccount'}
_SYSTEM_ACCESS = {'MinimumPasswordAge', 'MaximumPasswordAge', 'MinimumPasswordLength', 'PasswordComplexity', 'PasswordHistorySize', 'LockoutBadCount', 'ResetLockoutCount', 'LockoutDuration', 'RequireLogonToChangePassword', 'ForceLogoffWhenHourExpire', 'ClearTextPassword', 'LSAAnonymousNameLookup', 'EnableAdminAccount', 'EnableGuestAccount', 'RelaxMinimumPasswordLengthLimits', 'MinimumPasswordLengthAudit', 'AllowAdministratorLockout'}
_EVENT_AUDIT = {'AuditSystemEvents', 'AuditLogonEvents', 'AuditObjectAccess', 'AuditPrivilegeUse', 'AuditPolicyChange', 'AuditAccountManage', 'AuditProcessTracking', 'AuditDSAccess', 'AuditAccountLogon'}
_PUBLIC_SERVICES = {'host', 'restrictedkrbhost', 'http', 'cifs', 'ldap', 'gc', 'termsrv', 'wsman', 'mssqlsvc', 'dns', 'rpc'}
_PUBLIC_OIDS = {'2.5.29.37.0', '2.5.29.32.0', '1.3.6.1.4.1.311.20.2.1', '1.3.6.1.4.1.311.20.2.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.25.2'} | {f'1.3.6.1.5.5.7.3.{number}' for number in range(1, 10)}
_MAX_NODES = 200_000
_MAX_RECORDS = 50_000


def _known(value, fields, message='Unsupported AD policy fields.'):
    if not isinstance(value, dict) or value.keys() - fields:
        raise BundleError(message)


def _list(value):
    return value if isinstance(value, list) else [value] if isinstance(value, dict) else []


def _bounded(value, depth=0, budget=None):
    budget = [_MAX_NODES] if budget is None else budget
    budget[0] -= 1
    if budget[0] < 0 or depth > 16:
        raise BundleError('AD diagnostic content limit exceeded.')
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 4096:
                raise BundleError('Unsupported AD diagnostic field.')
            _bounded(item, depth + 1, budget)
    elif isinstance(value, list):
        for item in value:
            _bounded(item, depth + 1, budget)
    elif isinstance(value, str):
        if len(value) > 4 * 1024 * 1024 or '\x00' in value:
            raise BundleError('AD diagnostic content limit exceeded.')
    elif value is not None and type(value) not in (bool, int, float):
        raise BundleError('Unsupported AD diagnostic value.')


def _guid(value, anon):
    if hasattr(anon, 'guid'):
        return anon.guid(value)
    # Legacy Anonymizer compatibility; its DN method uses exactly this token.
    return anon.token(value)


def _principal(value, anon):
    value = value.strip().lstrip('*')
    if _SID.fullmatch(value):
        return anon.sid(value)
    short = re.sub(r' \(built-in\)$', '', value, flags=re.IGNORECASE)
    if short.lower().startswith('builtin\\'):
        short = short[8:]
    if short.casefold() in _BUILTINS:
        return _BUILTINS[short.casefold()]
    return anon.principal(value, directory=True) + ('$' if value.endswith('$') else '')


def _oid(value, anon):
    if not re.fullmatch(r'\d+(?:\.\d+)+', value):
        raise BundleError('Unsupported AD policy object identifier.')
    return value if value in _PUBLIC_OIDS else '2.25.' + str(int(anon.token(value, 'oid').rsplit('-', 1)[1], 16))


def _path(value, anon):
    """Keep UNC/drive/glob separators and public SYSVOL segments, map identities."""
    if not value:
        return ''
    if not isinstance(value, str) or any(c in value for c in '\r\n\x00'):
        raise BundleError('Unsupported AD policy path.')
    parts = re.split(r'([\\/])', value)
    unc = value.startswith('\\\\')
    for i, part in enumerate(parts):
        if not part or part in {'\\', '/'} or re.fullmatch('[A-Za-z]:', part):
            continue
        if _UUID.fullmatch(part):
            parts[i] = _guid(part, anon)
        elif unc and i == 4:
            parts[i] = getattr(anon, 'directory_labels', {}).get(part.casefold(), anon.fqdn(part))
        elif part.casefold() in _PUBLIC_PATH | _ENVIRONMENT or part in {'*', '**', '.', '..'}:
            continue
        elif '.' in part and unc and i == 8:
            parts[i] = anon.domain(part)
        else:
            stem, dot, suffix = part.rpartition('.')
            if stem == '*' and suffix.lower() in _EXTENSIONS:
                continue
            if any(char in part for char in '*?[]%'):
                raise BundleError('Unsupported AD policy path pattern.')
            parts[i] = anon.name(stem) + dot + suffix.lower() if dot and suffix.lower() in _EXTENSIONS else anon.name(part)
    return ''.join(parts)


def _url(value, anon):
    parsed = urlsplit(value)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise BundleError('Unsupported AD registry URL.')
    host = anon.ip(parsed.hostname) if re.fullmatch(r'[\d.:]+', parsed.hostname) else anon.fqdn(parsed.hostname)
    if ':' in host:
        host = '[' + host + ']'
    if parsed.port:
        host += ':' + str(parsed.port)
    return urlunsplit((parsed.scheme, host, _path(parsed.path, anon), '', ''))


def _security_descriptor(value, anon=None):
    """Rebuild self-relative SD including SACL; never copy unparsed opaque bytes."""
    try:
        data = base64.b64decode(value, validate=True)
        revision, reserved, control, owner, group, sacl, dacl = struct.unpack_from('<BBHIIII', data)
        if revision != 1 or reserved or not control & 0x8000:
            raise ValueError()
        used = set(range(20))
        identities = set()

        def sid_at(offset, end):
            if offset < 20 or offset + 8 > end:
                raise ValueError()
            size = 8 + 4 * data[offset + 1]
            if offset + size > end:
                raise ValueError()
            sid = sid_to_str(data[offset:offset + size])
            identities.add(sid)
            used.update(range(offset, offset + size))
            return str_to_sid(anon.sid(sid)) if anon else data[offset:offset + size], size

        def acl_at(offset):
            if offset < 20:
                raise ValueError()
            rev, sbz, size, count, sbz2 = struct.unpack_from('<BBHHH', data, offset)
            end = offset + size
            if rev not in {2, 4} or sbz or sbz2 or end > len(data):
                raise ValueError()
            pos = offset + 8
            aces = []
            used.update(range(offset, pos))
            for _ in range(count):
                kind, flags, length = struct.unpack_from('<BBH', data, pos)
                ace_end = pos + length
                if length < 16 or ace_end > end or kind not in {0, 1, 2, 3, 5, 6, 7, 8, 17, 19, 20}:
                    raise ValueError()
                cursor = pos + 8
                if kind in {5, 6, 7, 8}:
                    obj_flags = struct.unpack_from('<I', data, cursor)[0]
                    if obj_flags & ~3:
                        raise ValueError()
                    cursor += 4 + 16 * bool(obj_flags & 1) + 16 * bool(obj_flags & 2)
                sid, sid_size = sid_at(cursor, ace_end)
                if cursor + sid_size != ace_end:
                    raise ValueError()
                body = data[pos + 4:cursor] + sid
                used.update(range(pos, cursor))
                aces.append(struct.pack('<BBH', kind, flags, len(body) + 4) + body)
                pos = ace_end
            # Padding has no semantic content, but must not hide source bytes.
            if any(data[pos:end]):
                raise ValueError()
            used.update(range(pos, end))
            body = b''.join(aces)
            return struct.pack('<BBHHH', rev, 0, 8 + len(body), count, 0) + body

        chunks, offsets, cursor = [], [], 20
        for offset, is_acl in [(owner, False), (group, False), (sacl, True), (dacl, True)]:
            chunk = acl_at(offset) if offset and is_acl else sid_at(offset, len(data))[0] if offset else b''
            offsets.append(cursor if offset else 0)
            chunks.append(chunk)
            cursor += len(chunk)
        if any(byte and i not in used for i, byte in enumerate(data)):
            raise ValueError()
        output = struct.pack('<BBHIIII', revision, 0, control, *offsets) + b''.join(chunks)
        return base64.b64encode(output).decode(), identities
    except (ValueError, TypeError, IndexError, struct.error, OverflowError):
        raise BundleError('Unsupported AD security descriptor.') from None


def _registry(row, anon):
    _known(row, _REG_FIELDS)
    key, name, value = row['key'], row['value'], row.get('data')
    typ = row['type']
    if row['scope'] not in {'machine', 'user'} or not keep_registry(key, name):
        raise BundleError('Unsupported AD registry policy setting.')
    low = key.strip('\\').lower()
    if low == _HARDENED:
        name = _path(name, anon)
    if low == _WINLOGON and name.lower() == 'defaultpassword':
        value = ''
    elif type(value) is int and typ == 4:
        pass
    elif value is None:
        pass  # Collector explicitly reports an undecodable/missing value.
    elif isinstance(value, str) and typ in {1, 2}:
        if low == _WINLOGON and name.lower() == 'defaultusername':
            value = _principal(value, anon)
        elif name.lower() == 'wuserver':
            value = _url(value, anon)
        elif low == _HARDENED and re.fullmatch(r'\s*(?:Require(?:MutualAuthentication|Integrity|Privacy)\s*=\s*[01]\s*,?\s*)+', value, re.IGNORECASE):
            pass
        else:
            raise BundleError('Unsupported AD registry string policy setting.')
    else:
        raise BundleError('Unsupported AD registry policy encoding.')
    return {**row, 'key': key, 'value': name, 'data': value}


def _inf(text, anon):
    """Interpret each INF section; unknown sections/lines are never dropped."""
    if not isinstance(text, str) or len(text) > 4 * 1024 * 1024:
        raise BundleError('Unsupported AD INF policy content.')
    allowed = {'unicode', 'version', 'system access', 'event audit', 'registry values', 'group membership', 'privilege rights'}
    section, output = '', []
    for raw_line in text.lstrip('\ufeff').splitlines():
        line = raw_line.strip()
        if not line or line.startswith(';'):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1].strip().lower()
            if section not in allowed:
                raise BundleError('Unsupported AD INF policy section.')
            output.append('[' + line[1:-1].strip() + ']')
            continue
        key, equals, value = line.partition('=')
        key, value = key.strip(), value.strip()
        if not section or not equals:
            raise BundleError('Unsupported AD INF policy syntax.')
        if section == 'unicode':
            if key.lower() != 'unicode' or value.lower() not in {'yes', 'no'}:
                raise BundleError('Unsupported AD INF metadata.')
        elif section == 'version':
            if (key.lower(), value.lower()) not in {('signature', '"$chicago$"'), ('revision', '1')}:
                raise BundleError('Unsupported AD INF metadata.')
        elif section in {'system access', 'event audit'}:
            if key in {'NewAdministratorName', 'NewGuestName'}:
                value = '"' + anon.name(value.strip('"')) + '"'
            elif key not in (_SYSTEM_ACCESS if section == 'system access' else _EVENT_AUDIT) or not re.fullmatch(r'-?\d+', value):
                raise BundleError('Unsupported AD INF numeric policy setting.')
        elif section == 'registry values':
            root, sep, path = key.partition('\\')
            reg_key, sep2, name = path.rpartition('\\')
            type_text, comma, data = value.partition(',')
            if root.upper() not in {'MACHINE', 'USER'} or not sep or not sep2 or not comma or not type_text.isdecimal():
                raise BundleError('Unsupported AD INF registry setting.')
            typ = int(type_text)
            data = data.strip().strip('"')
            typed = int(data) if typ == 4 and re.fullmatch('-?\\d+', data) else data
            entry = _registry({'scope': 'machine' if root.upper() == 'MACHINE' else 'user', 'key': reg_key, 'value': name, 'type': typ, 'data': typed}, anon)
            key = root + '\\' + entry['key'] + '\\' + entry['value']
            value = str(typ) + ',' + ('"' + entry['data'] + '"' if isinstance(entry['data'], str) else str(entry['data']))
        else:
            if section == 'group membership':
                subject, separator, kind = key.rpartition('__')
                if not separator or kind.lower() not in {'members', 'memberof'}:
                    raise BundleError('Unsupported AD INF group assignment.')
                key = '*' + _principal(subject, anon) + '__' + kind
            elif not re.fullmatch(r'Se[A-Za-z]+(?:Privilege|Right)', key):
                raise BundleError('Unsupported AD INF privilege setting.')
            value = ','.join('*' + _principal(item.strip().strip('"'), anon) for item in value.split(',') if item.strip())
        output.append(key + '=' + value)
    return '\n'.join(output) + ('\n' if output else '')


def _notes(notes):
    out = []
    for note in notes:
        if not isinstance(note, str):
            raise BundleError('Unsupported AD collection status.')
        markers = [marker for marker in ('сертификаты ЦС (', CRITICAL_ACL_UNREAD, 'PSO не прочитаны', 'PSO не найдены', 'схема не прочитана', 'зоны DNS не прочитаны', 'SYSVOL', 'GptTmpl.inf', 'Groups.xml', 'Registry.pol', 'путь GPO вне домена') if marker.lower() in note.lower()]
        if re.search(r'папка .*не прочитана', note, re.IGNORECASE):
            markers.append('папка SYSVOL не прочитана')
        out.append(('; '.join(markers) or 'Source collection') + ': incomplete')
    return out


def _policy(data, anon):
    _known(data, _GPO_FIELDS)
    output = {'registry': [_registry(row, anon) for row in _list(data.get('registry', []))], 'gpp': [], 'audit': [], 'scripts': [], 'acl': None, 'notes': _notes(data.get('notes', []))}
    for row in _list(data.get('gpp', [])):
        _known(row, _GPP_FIELDS)
        if row.get('scope') not in {'machine', 'user'} or row.get('file') not in {'Groups.xml', 'Services.xml', 'ScheduledTasks.xml', 'DataSources.xml', 'Drives.xml', 'Printers.xml'} or row.get('kind') not in {'Group', 'User', 'NTService', 'Service', 'Task', 'TaskV2', 'ImmediateTask', 'ImmediateTaskV2', 'DataSource', 'Drive', 'Printer', 'SharedPrinter', 'PortPrinter', 'LocalPrinter'}:
            raise BundleError('Unsupported AD preference policy kind.')
        if row.get('action', '').upper() not in {'', 'C', 'D', 'R', 'U'}:
            raise BundleError('Unsupported AD preference policy action.')
        clean = {k: v for k, v in row.items() if k in {'scope', 'file', 'kind', 'action', 'cpassword', 'filtered', 'delete_all', 'disabled'}}
        for key in {'name', 'user', 'group_name'} & row.keys():
            clean[key] = _principal(row[key], anon)
        if 'group_sid' in row:
            clean['group_sid'] = anon.sid(row['group_sid'])
        if 'path' in row:
            clean['path'] = _path(row['path'], anon)
        clean['members'] = []
        for member in _list(row.get('members', [])):
            _known(member, {'sid', 'name', 'action'})
            if member.get('action', '').upper() not in {'', 'ADD', 'REMOVE'}:
                raise BundleError('Unsupported AD preference member action.')
            clean['members'].append({'sid': anon.sid(member.get('sid', '')), 'name': _principal(member.get('name', ''), anon), 'action': member.get('action', '')})
        output['gpp'].append(clean)
    for row in _list(data.get('audit', [])):
        _known(row, {'subcategory', 'setting'})
        if not _UUID.fullmatch(row.get('subcategory', '')) or type(row.get('setting')) is not int or row['setting'] not in range(4):
            raise BundleError('Unsupported AD audit policy setting.')
        output['audit'].append(dict(row))
    for row in _list(data.get('scripts', [])):
        _known(row, {'scope', 'phase', 'command', 'parameters'})
        if row.get('scope') not in {'machine', 'user'} or row.get('phase', '').lower() not in {'startup', 'shutdown', 'logon', 'logoff'} or row.get('parameters') or not re.fullmatch(r'(?:[A-Za-z]:\\|\\\\|[^\s/\\]+[\\/])?[^\r\n"<>|]*\.(?:ps1|bat|cmd|vbs|js)', row.get('command', ''), re.IGNORECASE):
            raise BundleError('Unsupported AD script policy arguments or command.')
        output['scripts'].append({**row, 'command': _path(row['command'], anon), 'parameters': ''})
    if data.get('acl') is not None:
        output['acl'] = []
        for row in _list(data['acl']):
            _known(row, {'path', 'writers'})
            output['acl'].append({'path': _path(row['path'], anon), 'writers': [anon.sid(sid) for sid in row.get('writers', [])]})
    return output


def _references(obj, raw_policy, raw_sysvol):
    refs = set()
    for field in _SD:
        if obj.get(field):
            refs.update(_security_descriptor(obj[field])[1])
    for field in _DN_FIELDS - {'dn'}:
        if obj.get(field):
            refs.add(obj[field])
    for field in _DN_LISTS - {'member'}:
        refs.update(obj.get(field, []))
    refs.update(obj.get('sIDHistory', []))
    for field in _OIDS:
        refs.update(obj.get(field, []))
    if obj.get('creatorSid'):
        refs.add(obj['creatorSid'])
    for row in _list(raw_policy.get('gpp', [])):
        refs.update(row.get(key, '') for key in ('user', 'group_sid', 'group_name'))
        for member in _list(row.get('members', [])):
            refs.update(member.get(key, '') for key in ('sid', 'name'))
    for row in _list(raw_policy.get('acl', [])):
        refs.update(row.get('writers', []))
    sections = parse_inf(raw_sysvol.get('GptTmpl.inf', ''))
    for subject, _kind, entries in inf_group_membership(sections):
        refs.add(subject)
        refs.update(entries)
    for value in sections.get('privilege rights', {}).values():
        refs.update(s.strip().lstrip('*') for s in value.split(','))
    return {ref for ref in refs if ref}


def _selection(export, raw, keys):
    by_dn = {obj.dn.casefold(): obj for obj in export.objects}
    lookup = {obj.dn.casefold(): obj.dn.casefold() for obj in export.objects}
    parents = defaultdict(set)
    templates = {obj.rdn_value.casefold(): obj.dn.casefold() for obj in export.objects if obj.cls == 'pKICertificateTemplate'}
    for obj in export.objects:
        dn = obj.dn.casefold()
        if obj.sid:
            lookup[obj.sid.casefold()] = dn
        if obj.sam:
            lookup[obj.sam.casefold()] = dn
            lookup[(export.domain.netbios + '\\' + obj.sam).casefold()] = dn
        if obj.cls == 'msPKI-Enterprise-Oid' and obj.template_oid:
            lookup[obj.template_oid] = dn
        for name in obj.certificateTemplates:
            if template_dn := templates.get(name.casefold()):
                parents[dn].add(template_dn)
                parents[template_dn].add(dn)
        for member in obj.member:
            parents[member.casefold()].add(dn)
            if sid := fsp_sid(member):
                parents[sid.casefold()].add(dn)
        for subject in obj.psoAppliesTo:
            parents[subject.casefold()].add(dn)
    gpos = {dn.casefold(): data for dn, data in (raw.get('gpo') or {}).items()}
    sysvol = {dn.casefold(): data for dn, data in raw.get('sysvol', {}).items()}
    pending = deque(str(key).casefold() for key in keys)
    seen, selected, references = set(), set(), set(keys)
    while pending:
        key = pending.popleft()
        if key in seen:
            continue
        seen.add(key)
        pending.extend(parents.get(key, ()))
        dn = lookup.get(key)
        if dn is None or dn in selected:
            continue
        selected.add(dn)
        if len(selected) > _MAX_RECORDS:
            raise BundleError('AD diagnostic record limit exceeded.')
        obj = by_dn[dn]
        pending.extend(parents.get(dn, ()))
        parts = re.split(r'(?<!\\),', dn)
        pending.extend(','.join(parts[i:]) for i in range(1, len(parts)))
        if obj.primaryGroupID is not None:
            pending.append((export.domain.sid + '-' + str(obj.primaryGroupID)).casefold())
        if obj.gpLink:
            links = parse_gplink(obj.gpLink)
            if ''.join('[LDAP://' + target + ';' + str(int(disabled) + 2 * int(enforced)) + ']' for target, disabled, enforced in links).casefold() != obj.gpLink.casefold():
                raise BundleError('Unsupported AD policy link.')
            pending.extend(target.casefold() for target, *_ in links)
        refs = _references(obj.model_dump(by_alias=True, exclude_none=True), gpos.get(dn, {}), sysvol.get(dn, {}))
        references.update(refs)
        pending.extend(ref.casefold() for ref in refs)
    return selected, references


def _filetime(value, anon):
    if value in {None, 0, 0x7FFFFFFFFFFFFFFF}:
        return value
    date = dt.datetime(1601, 1, 1, tzinfo=dt.UTC) + dt.timedelta(microseconds=value // 10)
    shifted = dt.datetime.fromisoformat(anon.date(date))
    return int((shifted - dt.datetime(1601, 1, 1, tzinfo=dt.UTC)).total_seconds() * 10_000_000)


def _object(obj, selected, referenced, anon):
    source = obj.model_dump(mode='json', by_alias=True, exclude_none=True)
    if obj.cls not in _CLASSES:
        raise BundleError('Unsupported AD object class.')
    if any(source.get(key) for key in ('altSecurityIdentities', 'cACertificate', 'msPKI-Enrollment-Servers')):
        raise BundleError('Unsupported AD certificate or authentication identity content.')
    out = {}
    for key in source.keys() & _OBJECT_FIELDS:
        value = source[key]
        if key in _DN_FIELDS:
            value = anon.dn(value)
        elif key in _DN_LISTS:
            value = [anon.dn(dn) for dn in value if key != 'member' or dn.casefold() in selected or fsp_sid(dn) in referenced]
        elif key in _DNS:
            value = anon.fqdn(value)
        elif key in _NAMES:
            value = _guid(value, anon) if _UUID.fullmatch(value) else anon.name(value)
            if key == 'sam' and source[key].endswith('$'):
                value += '$'
        elif key in _SIDS:
            value = anon.sid(value)
        elif key == 'sIDHistory':
            value = [anon.sid(sid) for sid in value]
        elif key in _SD:
            value = _security_descriptor(value, anon)[0] if value else value
        elif key in _DATES:
            value = anon.date(value)
        elif key in _FILETIMES:
            value = _filetime(value, anon)
        elif key == 'userPrincipalName':
            value = anon.principal(value)
        elif key == 'gpLink':
            value = anon.gp_link(value)
        elif key in {'gpcFileSysPath', 'scriptPath'}:
            value = _path(value, anon)
        elif key in {'spn', 'allowedToDelegateTo'}:
            mapped = []
            for entry in value:
                service, slash, host = entry.partition('/')
                host, realm_sep, realm = host.partition('/')
                if not slash or not re.fullmatch('[A-Za-z][A-Za-z0-9._-]*', service) or '/' in realm:
                    raise BundleError('Unsupported AD service principal identity.')
                name, colon, port = host.partition(':')
                if colon and not port.isdecimal():
                    raise BundleError('Unsupported AD service principal identity.')
                service = service if service.casefold() in _PUBLIC_SERVICES else anon.name(service)
                mapped.append(service + '/' + anon.fqdn(name) + (colon + port if colon else '') + (realm_sep + anon.domain(realm) if realm_sep else ''))
            value = mapped
        elif key == 'certificateTemplates':
            value = [anon.name(name) for name in value]
        elif key in _OIDS or key == 'msPKI-Cert-Template-OID':
            value = [_oid(oid, anon) for oid in value] if isinstance(value, list) else _oid(value, anon)
        elif key == 'operatingSystem':
            if not re.fullmatch(r'(?:Microsoft )?Windows(?: Server)? (?:XP|Vista|7|8(?:\.1)?|10|11|2000|2003|2008|2012|2016|2019|2022|2025)(?: (?:Standard|Datacenter|Enterprise|Professional|Pro|Home|Essentials|Evaluation|Edition|R2|SP\d+))*', value, re.IGNORECASE):
                value = anon.name(value)
        elif key == 'operatingSystemVersion':
            value = value if re.fullmatch(r'[\d. ()]+', value) else anon.name(value)
        elif key in {'partition', 'store'} and value not in {'root', 'intermediate', 'domain', 'forest', 'legacy'}:
            value = anon.name(value)
        out[key] = value
    return out


def build_ad_payload(raw: dict, keys: set[str], anon) -> dict:
    try:
        if not isinstance(raw, dict) or raw.get('format') != 'stools-ad/1':
            raise BundleError('Unsupported native AD export.')
        export = AdExport.model_validate(raw)
        anon.register_directory_domain(export.domain.dns_root, export.domain.netbios)
        selected, references = _selection(export, raw, keys)
        domain = export.domain.model_dump(mode='json', exclude_none=True)
        for key, value in domain.items():
            if key in {'dn', 'configuration_dn', 'schema_dn'}:
                domain[key] = anon.dn(value)
            elif key == 'sid':
                domain[key] = anon.sid(value)
            elif key == 'dns_root':
                domain[key] = anon.domain(value)
            elif key == 'netbios':
                domain[key] = anon.name(value)
            elif key == 'last_backup':
                domain[key] = anon.date(value)
            elif key in {'functional_level', 'forest_functional_level'} and value:
                level = functional_level_value(value)
                if level is None:
                    raise BundleError('Unsupported AD domain policy metadata.')
                domain[key] = str(level)
            elif key == 'ds_heuristics' and not re.fullmatch(r'\d*', value) or key == 'sysvol_replication' and value not in {'dfsr', 'ntfrs'}:
                raise BundleError('Unsupported AD domain policy metadata.')
            elif key == 'schema_poss_superiors' and (value.keys() - {'msExchStorageGroup'} or any(name not in _CLASSES | {'msExchExchangeServer', 'msExchInformationStore'} for entries in value.values() for name in entries)):
                raise BundleError('Unsupported AD schema policy metadata.')
        objects = [_object(obj, selected, references, anon) for obj in export.objects if obj.dn.casefold() in selected]
        out = {'format': 'stools-ad/1', 'collected_at': anon.date(export.collected_at), 'domain': domain, 'objects': objects,
               'collector': {'kind': 'diagnostic', 'version': '2', 'critical_acl': export.collector.critical_acl, 'notes': _notes(export.collector.notes)},
               'principals': {}, 'sysvol': {}, 'guids': {}}
        for dn, files in raw.get('sysvol', {}).items():
            if dn.casefold() in selected:
                _known(files, {'GptTmpl.inf'}, 'Unsupported AD SYSVOL policy file.')
                out['sysvol'][anon.dn(dn)] = {name: _inf(text, anon) for name, text in files.items()}
        if raw.get('gpo') is not None:
            out['gpo'] = {anon.dn(dn): _policy(data, anon) for dn, data in raw['gpo'].items() if dn.casefold() in selected}
        else:
            out['gpo'] = None
        principal_sids = references | {obj.sid for obj in export.objects if obj.dn.casefold() in selected and obj.sid}
        for sid, principal in export.principals.items():
            if sid in principal_sids:
                if principal.cls and principal.cls not in _CLASSES:
                    raise BundleError('Unsupported AD principal class.')
                out['principals'][anon.sid(sid)] = {'name': _principal(principal.name, anon), 'class': principal.cls}
        for category, mapping in export.guids.model_dump().items():
            if any(name not in _GUID_NAMES or value and not _UUID.fullmatch(value) for name, value in mapping.items()):
                raise BundleError('Unsupported AD schema policy identifier.')
            out['guids'][category] = mapping
        validate_ad_payload(out)
        return out
    except BundleError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, OverflowError, RecursionError):
        raise BundleError('Unsupported native AD policy payload.') from None


class _ValidationIdentity:
    """Run typed policy parsers without modifying the received archive."""
    @staticmethod
    def _same(value, **_kwargs):
        return value

    name = sid = fqdn = domain = ip = guid = principal = _same


def validate_ad_payload(raw: dict) -> None:
    try:
        _bounded(raw)
        _known(raw, {'format', 'collected_at', 'domain', 'objects', 'collector', 'principals', 'sysvol', 'gpo', 'guids'})
        if raw.get('format') != 'stools-ad/1':
            raise BundleError('Unsupported native AD payload format.')
        _known(raw['domain'], _DOMAIN_FIELDS)
        _known(raw.get('collector', {}), {'kind', 'version', 'critical_acl', 'notes'})
        object_dns, policy_dns = set(), set()
        for obj in raw['objects']:
            _known(obj, _OBJECT_FIELDS)
            dn = obj['dn'].casefold()
            if dn in object_dns or obj.get('class') not in _CLASSES:
                raise BundleError('Invalid AD diagnostic object identity.')
            object_dns.add(dn)
            if obj.get('class') == 'groupPolicyContainer':
                policy_dns.add(dn)
            for field in _SD:
                if obj.get(field):
                    _security_descriptor(obj[field])
        if len(raw['objects']) + sum(len(obj.get('member', [])) for obj in raw['objects']) > _MAX_RECORDS:
            raise BundleError('AD diagnostic record limit exceeded.')
        for principal in raw.get('principals', {}).values():
            _known(principal, {'name', 'class'})
        _known(raw.get('guids', {}), {'extended_rights', 'schema_attributes', 'schema_classes'})
        if any(dn.casefold() not in policy_dns for dn in set(raw.get('sysvol', {})) | set(raw.get('gpo') or {})):
            raise BundleError('Invalid AD diagnostic policy reference.')
        identity = _ValidationIdentity()
        for files in raw.get('sysvol', {}).values():
            _known(files, {'GptTmpl.inf'}, 'Unsupported AD SYSVOL policy file.')
            for text in files.values():
                _inf(text, identity)
        for policy in (raw.get('gpo') or {}).values():
            _policy(policy, identity)
        AdExport.model_validate(raw)
    except BundleError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, OverflowError, RecursionError):
        raise BundleError('Invalid native AD diagnostic payload.') from None
