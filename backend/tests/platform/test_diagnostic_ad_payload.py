import base64
import copy
import importlib
import json
import struct
import uuid

import pytest

from api.modules.ad.core.account_groups import account_groups
from api.modules.ad.core.checks.coverage import coverage_gaps
from api.modules.ad.core.export import AdExport, ExportIndex
from api.modules.ad.core.gpo_rights import gpo_rights
from api.modules.ad.core.sd import build_ace, build_sd, parse_sd, str_to_sid
from api.platform.diagnostics.module_privacy import ModuleAnonymizer as Anonymizer
from api.platform.diagnostics.schema import BundleError

DN = 'DC=private,DC=example'
SID = 'S-1-5-21-123-456-789'
OU = f'OU=Private Workstations,{DN}'
USER = f'CN=Private Alice,{OU}'
HOST = f'CN=Private Workstation,{OU}'
GUID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
GPO = f'CN={{{GUID}}},CN=Policies,CN=System,{DN}'
APPLY = uuid.UUID('edacfd8f-ffb3-11d1-b41d-00a0c968f939')
LSA = r'System\CurrentControlSet\Control\Lsa'
WINLOGON = r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'


def _api():
    name = 'api.platform.diagnostics.ad_payload'
    assert importlib.util.find_spec(name) is not None, 'Native AD diagnostic payload builder is missing'
    return importlib.import_module(name)


def _raw():
    group_dn = f'CN=Private Group,{DN}'
    policy_group = f'CN=Private Policy Subject,{DN}'
    sd = build_sd([
        build_ace(f'{SID}-2100', 0x100, object_type=APPLY),
        build_ace(f'{SID}-1100', 0x100, allow=False, object_type=APPLY),
        build_ace('S-1-5-11', 0x20094, flags=0x10),
    ], owner=f'{SID}-500')
    inf = ('[Unicode]\nUnicode=yes\n[Version]\nsignature="$CHICAGO$"\nRevision=1\n'
           '[System Access]\nMinimumPasswordLength=14\nClearTextPassword=0\n'
           f'[Group Membership]\n*S-1-5-32-544__Members=*{SID}-2200\n'
           f'[Privilege Rights]\nSeDebugPrivilege=*{SID}-2100\n'
           f'[Registry Values]\nMACHINE\\{LSA}\\LmCompatibilityLevel=4,2\n')
    return {
        'format': 'stools-ad/1', 'collected_at': '2026-11-01T12:00:00+00:00',
        'domain': {'dn': DN, 'sid': SID, 'dns_root': 'private.example', 'netbios': 'PRIVATE', 'min_pwd_length': 14},
        'collector': {'host': 'PRIVATE-CONTROLLER', 'account': 'PRIVATE\\Secret Collector', 'notes': ['secret-password'], 'critical_acl': True},
        'objects': [
            {'dn': DN, 'class': 'domainDNS', 'sid': SID, 'gpLink': ''},
            {'dn': OU, 'class': 'organizationalUnit', 'gpOptions': 1, 'gpLink': f'[LDAP://{GPO};2]'},
            {'dn': USER, 'class': 'user', 'sid': f'{SID}-1100', 'sam': 'Private Alice', 'primaryGroupID': 513, 'description': 'secret-password'},
            {'dn': HOST, 'class': 'computer', 'sid': f'{SID}-3100', 'sam': 'Private Workstation$', 'dNSHostName': 'private-workstation.private.example'},
            {'dn': group_dn, 'class': 'group', 'sid': f'{SID}-2100', 'sam': 'Private Group', 'member': [USER, f'CN=Private Sibling,{DN}']},
            {'dn': f'CN=Primary Group,{DN}', 'class': 'group', 'sid': f'{SID}-513', 'sam': 'Primary Group', 'member': []},
            {'dn': policy_group, 'class': 'group', 'sid': f'{SID}-2200', 'sam': 'Private Policy Subject', 'member': []},
            {'dn': f'CN=Private Sibling,{DN}', 'class': 'user', 'sid': f'{SID}-1101', 'sam': 'Private Sibling'},
            {'dn': GPO, 'class': 'groupPolicyContainer', 'name': '{' + GUID + '}', 'displayName': 'Private Policy',
             'gpcFileSysPath': '\\\\private.example\\SYSVOL\\private.example\\Policies\\{' + GUID + '}', 'flags': 0,
             'sd': base64.b64encode(sd).decode()},
        ],
        'sysvol': {GPO: {'GptTmpl.inf': inf}},
        'gpo': {GPO: {
            'registry': [{'scope': 'machine', 'key': LSA, 'value': 'NoLMHash', 'type': 4, 'data': 1},
                         {'scope': 'machine', 'key': WINLOGON, 'value': 'DefaultPassword', 'type': 1, 'data': 'secret-password'},
                         {'scope': 'machine', 'key': WINLOGON, 'value': 'DefaultUserName', 'type': 1, 'data': 'PRIVATE\\Private Alice'}],
            'gpp': [{'scope': 'machine', 'file': 'Groups.xml', 'kind': 'Group', 'name': 'Administrators (built-in)',
                     'group_sid': 'S-1-5-32-544', 'action': 'U', 'cpassword': True, 'filtered': True,
                     'delete_all': False, 'disabled': False, 'members': [{'sid': f'{SID}-2200', 'name': 'PRIVATE\\Private Policy Subject', 'action': 'ADD'}]}],
            'audit': [{'subcategory': '0cce9215-69ae-11d9-bed3-505054503030', 'setting': 3}],
            'acl': [{'path': '\\\\private.example\\SYSVOL\\private.example\\Policies\\{' + GUID + '}\\Machine', 'writers': [f'{SID}-2100']}],
            'scripts': [], 'notes': [],
        }},
        'principals': {f'{SID}-2100': {'name': 'PRIVATE\\Private Group', 'class': 'group'}},
    }


def test_native_policy_slice_preserves_analysis_and_acl_semantics_without_private_values():
    api = _api()
    anon = Anonymizer()
    raw = _raw()
    before = copy.deepcopy(raw)
    clean = api.build_ad_payload(raw, {f'{SID}-1100', f'{SID}-3100'}, anon)
    api.validate_ad_payload(clean)
    idx = ExportIndex(AdExport.model_validate(clean))
    [policy] = idx.objects('groupPolicyContainer')
    assert idx.gpo_links(policy)[0].enforced is True
    assert idx.objects('organizationalUnit')[0].gpOptions == 1
    assert idx.gpo_data(policy).registry[0].data == 1
    assert idx.inf_sections(policy)['registry values'][f'MACHINE\\{LSA}\\LmCompatibilityLevel'] == '4,2'
    assert idx.inf_sections(policy)['system access']['MinimumPasswordLength'] == '14'
    acl = idx.sd_of(policy)
    assert acl.owner == anon.sid(f'{SID}-500')
    assert [(ace.type, ace.mask, ace.flags, ace.object_type) for ace in acl.dacl] == [
        (5, 0x100, 0, APPLY), (6, 0x100, 0, APPLY), (0, 0x20094, 0x10, None)]
    assert acl.dacl[0].sid == anon.sid(f'{SID}-2100')
    assert acl.dacl[1].sid == anon.sid(f'{SID}-1100')
    assert acl.dacl[2].sid == 'S-1-5-11'
    assert anon.sid(f'{SID}-2200') in idx.by_sid
    assert anon.sid(f'{SID}-1101') not in idx.by_sid
    [group] = [g for g in idx.objects('group') if g.sid == anon.sid(f'{SID}-2100')]
    assert group.member == [anon.dn(USER)]
    memberships = account_groups(idx).groups[anon.sid(f'{SID}-1100')]
    assert {g['sid'] for g in memberships} == {anon.sid(f'{SID}-2100'), anon.sid(f'{SID}-513')}
    rights = gpo_rights(idx)['rights']
    assert {r['via'] for r in rights} == {'restricted_groups', 'gpp'}
    assert all(r['group_sid'] == anon.sid(f'{SID}-2200') for r in rights)
    assert next(r for r in rights if r['via'] == 'gpp')['filtered'] is True
    assert next(r for r in rights if r['via'] == 'gpp')['hosts'] == [anon.fqdn('private-workstation.private.example')]
    assert idx.gpo_data(policy).registry[1].data == ''
    assert idx.gpo_data(policy).gpp[0].cpassword is True
    assert idx.gpo_data(policy).acl[0].writers == [anon.sid(f'{SID}-2100')]
    assert policy.name in policy.gpcFileSysPath
    assert policy.name in policy.dn
    assert raw == before
    serialized = json.dumps(clean).lower()
    for private in ['private', 'secret-password', '123-456-789', GUID]:
        assert private not in serialized


def test_all_67_current_memberships_and_nested_parents_are_kept_without_siblings():
    api = _api()
    raw = _raw()
    raw['objects'] = raw['objects'][:4] + [raw['objects'][-1]]
    groups = [{'dn': f'CN=Membership {i},{DN}', 'class': 'group', 'sid': f'{SID}-{4000+i}', 'sam': f'Membership {i}', 'member': [USER]} for i in range(66)]
    groups.append({'dn': f'CN=Parent Group,{DN}', 'class': 'group', 'sid': f'{SID}-5000', 'member': [groups[0]['dn']]})
    raw['objects'].extend(groups)
    anon = Anonymizer()
    clean = api.build_ad_payload(raw, {f'{SID}-1100'}, anon)
    idx = ExportIndex(AdExport.model_validate(clean))
    assert len(account_groups(idx).groups[anon.sid(f'{SID}-1100')]) == 67


@pytest.mark.parametrize('mutation, reason', [
    (lambda r: r['sysvol'][GPO].update({'opaque.bin': 'secret-password'}), 'SYSVOL'),
    (lambda r: r['sysvol'][GPO].update({'GptTmpl.inf': '[Custom Secret]\nvalue=secret-password'}), 'INF'),
    (lambda r: r['gpo'][GPO]['registry'].append({'scope': 'machine', 'key': 'Software\\Private', 'value': 'opaque', 'type': 3, 'data': 'secret-password'}), 'registry'),
    (lambda r: r['gpo'][GPO]['scripts'].append({'scope': 'machine', 'phase': 'Startup', 'command': 'cmd.exe', 'parameters': '/c echo secret-password'}), 'script'),
    (lambda r: r['gpo'][GPO].update({'opaque_private_policy': 'secret-password'}), 'policy'),
])
def test_unsupported_policy_content_fails_without_echoing_values(mutation, reason):
    api = _api()
    raw = _raw()
    mutation(raw)
    with pytest.raises(BundleError, match=reason) as exc:
        api.build_ad_payload(raw, {f'{SID}-1100'}, Anonymizer())
    assert 'secret-password' not in str(exc.value)
    assert 'private' not in str(exc.value).lower()


def test_unknown_ace_is_rejected_instead_of_silently_losing_security_filter():
    api = _api()
    raw = _raw()
    ace = bytearray(build_ace(f'{SID}-2100', 0x100))
    ace[0] = 9  # callback ACE carries opaque condition data in real descriptors
    raw['objects'][-1]['sd'] = base64.b64encode(build_sd([bytes(ace)])).decode()
    with pytest.raises(BundleError, match='security descriptor'):
        api.build_ad_payload(raw, {f'{SID}-1100'}, Anonymizer())


def test_validator_rejects_unknown_fields_malformed_acl_and_nested_overflow():
    api = _api()
    clean = api.build_ad_payload(_raw(), {f'{SID}-1100'}, Anonymizer())
    for target in [clean, clean['domain'], clean['objects'][0], next(iter(clean['gpo'].values()))]:
        target['unapproved'] = 'secret-password'
        with pytest.raises(BundleError):
            api.validate_ad_payload(clean)
        del target['unapproved']
    policy = next(o for o in clean['objects'] if o['class'] == 'groupPolicyContainer')
    policy['sd'] = base64.b64encode(struct.pack('<BBHIIII', 1, 0, 0x8004, 0, 0, 0, 999)).decode()
    with pytest.raises(BundleError):
        api.validate_ad_payload(clean)


def test_shared_guid_mapping_paths_and_well_known_acl_identities():
    api = _api()
    raw = _raw()
    source = build_sd([build_ace('S-1-5-7', 0x100, allow=False, object_type=APPLY)], owner=f'{SID}-500')
    # SACL audit ACE and DACL both carry SIDs; preserve the SD control flags.
    audit = bytearray(build_ace(f'{SID}-2100', 0x100, flags=0x40))
    audit[0] = 2
    sacl = struct.pack('<BBHHH', 2, 0, 8 + len(audit), 1, 0) + audit
    descriptor = bytearray(source + sacl)
    struct.pack_into('<H', descriptor, 2, 0x9014)
    struct.pack_into('<I', descriptor, 12, len(source))
    raw['objects'][-1]['sd'] = base64.b64encode(descriptor).decode()
    anon = Anonymizer()
    clean = api.build_ad_payload(raw, {f'{SID}-3100'}, anon)
    policy = next(obj for obj in clean['objects'] if obj['class'] == 'groupPolicyContainer')
    assert policy['dn'] == anon.dn(GPO)
    assert policy['name'] == '{' + str(uuid.UUID(policy['name'].strip('{}'))) + '}'
    assert policy['name'] in policy['gpcFileSysPath']
    assert policy['name'] in clean['gpo'][policy['dn']]['acl'][0]['path']
    actual = base64.b64decode(policy['sd'])
    assert struct.unpack_from('<H', actual, 2)[0] == 0x9014
    assert parse_sd(actual).dacl[0].sid == 'S-1-5-7'
    sacl_offset = struct.unpack_from('<I', actual, 12)[0]
    assert actual[sacl_offset + 8] == 2
    assert str_to_sid(anon.sid(f'{SID}-2100')) in actual[sacl_offset:]
    assert str_to_sid(f'{SID}-2100') not in actual


@pytest.mark.parametrize('mutation', [
    lambda r: r['domain'].update({'functional_level': 'Private Company'}),
    lambda r: r['domain'].update({'schema_poss_superiors': {'Private Schema': ['Private Parent']}}),
    lambda r: r['gpo'][GPO]['gpp'][0].update({'action': 'secret-password'}),
    lambda r: r['gpo'][GPO]['gpp'][0]['members'][0].update({'action': 'secret-password'}),
    lambda r: r['gpo'][GPO]['scripts'].append({'scope': 'secret-password', 'phase': 'secret-password', 'command': 'script.ps1'}),
])
def test_unrecognized_semantic_fields_never_copy_private_free_text(mutation):
    raw = _raw()
    mutation(raw)
    with pytest.raises(BundleError):
        _api().build_ad_payload(raw, {f'{SID}-3100'}, Anonymizer())


def test_validator_parses_policy_content_and_enforces_depth_limit():
    api = _api()
    clean = api.build_ad_payload(_raw(), {f'{SID}-1100'}, Anonymizer())
    policy_dn = next(iter(clean['sysvol']))
    clean['sysvol'][policy_dn]['GptTmpl.inf'] = '[opaque]\nsecret-password=data'
    with pytest.raises(BundleError, match='INF'):
        api.validate_ad_payload(clean)
    nested = 'secret-password'
    for _ in range(20):
        nested = [nested]
    clean['objects'][0]['member'] = nested
    with pytest.raises(BundleError, match='limit'):
        api.validate_ad_payload(clean)


def test_sysvol_domain_hardened_path_and_spn_references_share_identity_mapping():
    raw = _raw()
    raw['objects'][3]['spn'] = ['LDAP/private-workstation.private.example/private.example']
    raw['gpo'][GPO]['registry'].append({'scope': 'machine', 'key': r'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths', 'value': r'\\private-workstation.private.example\private-share', 'type': 1, 'data': None})
    anon = Anonymizer()
    clean = _api().build_ad_payload(raw, {f'{SID}-3100'}, anon)
    idx = ExportIndex(AdExport.model_validate(clean))
    [policy] = idx.objects('groupPolicyContainer')
    assert policy.gpcFileSysPath.startswith('\\\\' + clean['domain']['dns_root'] + '\\SYSVOL\\' + clean['domain']['dns_root'])
    assert idx.objects('computer')[0].spn == ['LDAP/' + anon.fqdn('private-workstation.private.example') + '/' + clean['domain']['dns_root']]
    assert idx.gpo_data(policy).registry[-1].value.startswith('\\\\' + anon.fqdn('private-workstation.private.example') + '\\')
    assert 'private' not in json.dumps(clean).lower()


def test_inf_unknown_numeric_keys_and_partial_path_globs_are_rejected():
    raw = _raw()
    raw['sysvol'][GPO]['GptTmpl.inf'] += '[System Access]\nPrivateCustomer=1\n'
    with pytest.raises(BundleError, match='INF'):
        _api().build_ad_payload(raw, {f'{SID}-3100'}, Anonymizer())
    raw = _raw()
    raw['gpo'][GPO]['gpp'][0]['path'] = r'\\private.example\share\secret-*'
    with pytest.raises(BundleError, match='pattern'):
        _api().build_ad_payload(raw, {f'{SID}-3100'}, Anonymizer())


def test_unicode_dns_and_custom_operating_system_labels_are_safe():
    raw = _raw()
    raw['objects'][3]['dn'] = f'CN=Straße,{OU}'
    raw['objects'][3]['operatingSystem'] = 'Windows PrivateCustomer'
    clean = _api().build_ad_payload(raw, {f'{SID}-3100'}, Anonymizer())
    assert len([obj for obj in clean['objects'] if obj['class'] == 'computer']) == 1
    assert 'privatecustomer' not in json.dumps(clean).lower()


def test_validator_rejects_duplicate_objects_and_orphan_policy_content():
    api = _api()
    clean = api.build_ad_payload(_raw(), {f'{SID}-3100'}, Anonymizer())
    clean['objects'].append(copy.deepcopy(clean['objects'][0]))
    with pytest.raises(BundleError):
        api.validate_ad_payload(clean)
    clean['objects'].pop()
    clean['gpo'][clean['objects'][0]['dn']] = {'registry': []}
    with pytest.raises(BundleError):
        api.validate_ad_payload(clean)


@pytest.mark.parametrize('marker', ['PSO не прочитаны', 'PSO не найдены'])
def test_collection_failure_markers_keep_password_coverage_incomplete(marker):
    raw = _raw()
    raw['domain'].update({'min_pwd_length': 14, 'lockout_threshold': 5, 'pwd_properties': 1})
    raw['collector']['notes'] = [marker + ': Private-Collector-Error']
    before = coverage_gaps(AdExport.model_validate(raw))
    clean = _api().build_ad_payload(raw, {f'{SID}-1100'}, Anonymizer())
    after = coverage_gaps(AdExport.model_validate(clean))
    assert 'PasswordPolicy' in before and 'PasswordPolicy' in after
    assert 'private' not in json.dumps(clean).lower()


def test_machine_sam_suffix_and_name_only_policy_principals_stay_linked():
    raw = _raw()
    raw['gpo'][GPO]['gpp'][0]['members'] = [{'name': 'PRIVATE\\Private Workstation$', 'action': 'ADD'}]
    anon = Anonymizer()
    clean = _api().build_ad_payload(raw, {f'{SID}-1100'}, anon)
    idx = ExportIndex(AdExport.model_validate(clean))
    [computer] = idx.objects('computer')
    assert computer.sam == anon.name('Private Workstation') + '$'
    row = next(row for row in gpo_rights(idx)['rights'] if row['via'] == 'gpp')
    assert row['group_sid'] == computer.sid


def test_custom_certificate_oids_are_mapped_consistently_and_public_ekus_survive():
    raw = _raw()
    oid = '1.3.6.1.4.1.311.21.8.314159265.271828182.161803398'
    template_dn = f'CN=Private Template,CN=Certificate Templates,{DN}'
    raw['objects'].append({'dn': template_dn, 'class': 'pKICertificateTemplate', 'cn': 'Private Template',
                           'msPKI-Cert-Template-OID': oid, 'msPKI-Certificate-Policy': [oid],
                           'msPKI-Certificate-Application-Policy': [oid],
                           'pKIExtendedKeyUsage': [oid, '1.3.6.1.5.5.7.3.2']})
    clean = _api().build_ad_payload(raw, {template_dn}, Anonymizer())
    template = next(obj for obj in clean['objects'] if obj['class'] == 'pKICertificateTemplate')
    mapped = template['msPKI-Cert-Template-OID']
    assert mapped != oid and mapped.startswith('2.25.')
    assert template['msPKI-Certificate-Policy'] == template['msPKI-Certificate-Application-Policy'] == [mapped]
    assert template['pKIExtendedKeyUsage'] == [mapped, '1.3.6.1.5.5.7.3.2']
    assert oid not in json.dumps(clean)


@pytest.mark.parametrize('seed', ['template', 'ca'])
def test_certificate_publication_dependencies_are_kept_in_both_directions(seed):
    raw = _raw()
    template_dn = f'CN=Private Template,CN=Certificate Templates,{DN}'
    ca_dn = f'CN=Private CA,CN=Enrollment Services,{DN}'
    raw['objects'].extend([
        {'dn': template_dn, 'class': 'pKICertificateTemplate', 'cn': 'Private Template'},
        {'dn': ca_dn, 'class': 'pKIEnrollmentService', 'cn': 'Private CA', 'certificateTemplates': ['Private Template']},
    ])
    anon = Anonymizer()
    clean = _api().build_ad_payload(raw, {template_dn if seed == 'template' else ca_dn}, anon)
    idx = ExportIndex(AdExport.model_validate(clean))
    [template] = idx.objects('pKICertificateTemplate')
    assert idx.published_on(template) == [anon.name('Private CA')]
