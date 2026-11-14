import copy
import datetime as dt
import gzip
import json

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from api.db.models import Base
from api.modules.ad.models import AdDomain, AdSnapshot
from api.modules.assets.models import Asset, AssetUser, AssetUserGroup, AssetUserObservation
from api.platform.diagnostics.exporter import (
    TABLE_MODELS,
    BundleError,
    build_bundle,
    validate_bundle,
)

NOW = dt.datetime(2026, 10, 20, 12, tzinfo=dt.UTC)
DOMAIN = 'secret.corp'
SID = 'S-1-5-21-123-456-789'
DN = 'DC=secret,DC=corp'


@pytest.fixture
def source(tmp_path):
    engine = create_engine('sqlite://')
    tables = {model.__table__ for model in TABLE_MODELS.values()}
    pending = list(tables)
    while pending:
        for fk in pending.pop().foreign_keys:
            if fk.column.table not in tables:
                tables.add(fk.column.table)
                pending.append(fk.column.table)
    Base.metadata.create_all(engine, tables=list(tables))
    with Session(engine) as db:
        db.add(AdDomain(id=1, sid=SID, dns_root=DOMAIN, dn=DN, netbios='SECRET'))
        db.add(AdSnapshot(id=1, domain_id=1, collected_at=NOW, source='file'))
        db.add(AssetUser(id=1, sid=f'{SID}-1100', sam='alice', name_key=f'{DOMAIN}\\alice', domain=DOMAIN, upn=f'alice@{DOMAIN}', display_name='Alice Private', note='password=hunter2'))
        db.add(AssetUserObservation(id=1, user_id=1, source='ad', source_key=f'{SID}-1100', seen_at=NOW, data={'domain_id': 1, 'password': 'hunter2', 'raw': {'secret': 'TOPSECRET'}}))
        for i in range(101):
            db.add(AssetUserGroup(user_id=1, group_sid=f'{SID}-{2000+i}', group_name=f'secret-group-{i}', direct=True, source='ad'))
        db.add(Asset(id=1, name='unrelated-secret-host', name_key='unrelated-secret-host'))
        db.commit()
        user_dn = f'CN=alice,OU=People,{DN}'
        objects = [{'dn': user_dn, 'class': 'user', 'sid': f'{SID}-1100', 'sam': 'alice', 'userPrincipalName': f'alice@{DOMAIN}', 'description': 'TOPSECRET'}]
        objects += [{'dn': f'CN=secret-group-{i},{DN}', 'class': 'group', 'sid': f'{SID}-{2000+i}', 'sam': f'secret-group-{i}', 'member': [user_dn]} for i in range(67)]
        export = {'format': 'stools-ad/1', 'collected_at': NOW.isoformat(), 'domain': {'dn': DN, 'sid': SID, 'dns_root': DOMAIN, 'netbios': 'SECRET'}, 'collector': {'host': 'secret-controller', 'account': 'password=hunter2'}, 'objects': objects, 'sysvol': {'secret-file': {'password': 'hunter2'}}}
        (tmp_path / 'ad').mkdir()
        with gzip.open(tmp_path / 'ad/1.json.gz', 'wt') as f:
            json.dump(export, f)
        yield db, tmp_path


def test_export_preserves_current_and_cached_memberships_without_secrets(source):
    from api.modules.ad.core.account_groups import account_groups
    from api.modules.ad.core.export import AdExport, ExportIndex
    db, data_dir = source
    bundle = build_bundle(db, data_dir, 'user', 1)
    assert validate_bundle(bundle) is bundle
    assert len(bundle['tables']['asset_user_group']) == 101
    export = AdExport.model_validate(bundle['ad_exports'][0]['export'])
    sid = bundle['tables']['asset_user'][0]['sid']
    assert len(account_groups(ExportIndex(export)).groups[sid]) == 67
    assert bundle['tables'].get('asset', []) == []
    assert bundle['tables']['asset_user_observation'][0]['source_key'] == sid
    raw = json.dumps(bundle).lower()
    for secret in ['alice', 'secret.corp', 'secret-group', 'hunter2', 'topsecret', '123-456-789', 'secret-controller']:
        assert secret not in raw
    assert bundle['report']['limitations']
    assert db.scalar(select(AssetUser.note).where(AssetUser.id == 1)) == 'password=hunter2'


def test_unknown_nested_fields_rejected(source):
    db, data_dir = source
    bundle = build_bundle(db, data_dir, 'user', 1)
    bad = copy.deepcopy(bundle)
    bad['tables']['asset_user_observation'][0]['data']['password'] = 'leak'
    with pytest.raises(BundleError):
        validate_bundle(bad)
    bad = copy.deepcopy(bundle)
    bad['ad_exports'][0]['export']['objects'][0]['raw'] = {'password': 'leak'}
    with pytest.raises(BundleError):
        validate_bundle(bad)


def test_limit_fails_instead_of_truncating_membership(source, monkeypatch):
    from api.platform.diagnostics import exporter
    monkeypatch.setattr(exporter, 'MAX_RECORDS', 50)
    db, data_dir = source
    with pytest.raises(BundleError, match='limit|large|больш|лимит'):
        build_bundle(db, data_dir, 'user', 1)


def test_host_identity_ou_gpo_primary_group_and_ksc_closure(source):
    from api.modules.ad.core.account_groups import account_groups
    from api.modules.ad.core.export import AdExport, ExportIndex
    from api.modules.assets.models import AssetObservation
    from api.modules.ksc.models import (
        KscHost,
        KscNetRule,
        KscPolicy,
        KscPolicyScope,
        KscProfile,
        KscServer,
        KscSnapshot,
    )
    db, data_dir = source
    host = db.get(Asset, 1)
    host.name = 'secret-pc'
    host.name_key = 'secret-pc'
    host.fqdn = f'secret-pc.{DOMAIN}'
    host.domain = DOMAIN
    host.ip = '10.2.3.4'
    db.add(AssetObservation(id=11, asset_id=1, source='ad', source_key=f'{SID}-3100', name=host.name, fqdn=host.fqdn, domain=DOMAIN, ip=host.ip, ips=[host.ip, '2001:db8:1234::7'], seen_at=NOW, extra={'domain_id': 1, 'mac': 'ab:cd:ef:12:34:56', 'password': 'hunter2'}))
    db.add(AssetObservation(id=12, asset_id=1, source='ksc', source_key='77:private-guid', name=host.name, fqdn=host.fqdn, domain=DOMAIN, ip=host.ip, seen_at=NOW, extra={'username': 'alice'}))
    db.add(KscServer(id=77, name='private-server'))
    db.add(KscSnapshot(id=88, server_id=77, collected_at=NOW, source='file', filename='secret-company.json'))
    db.add(KscHost(id=99, snapshot_id=88, host_id='private-guid', name=host.name, fqdn=host.fqdn, domain=DOMAIN, ip=host.ip, group_id=123, group_path='Private/PCs', extra_json='{"password":"hunter2"}'))
    db.add(KscPolicy(id=11, snapshot_id=88, policy_id=321, name='private-policy', group_id=123, group_path='Private/PCs'))
    db.add(KscPolicyScope(id=12, snapshot_id=88, policy_id=321, group_id=123, group_path='Private/PCs'))
    db.add(KscProfile(id=13, snapshot_id=88, policy_id=321, name='private-profile', condition_json='{"password":"hunter2"}'))
    db.add(KscNetRule(id=14, snapshot_id=88, policy_id=321, profile='private-profile', layer='packet', name='private-rule', action='разрешить', local_ports='443', addresses='10.0.0.0/8', key='private-key', scope_json='{"raw":"TOPSECRET"}'))
    db.commit()
    ou = f'OU=PCs,{DN}'
    host_dn = f'CN=secret-pc,{ou}'
    gpo_dn = f'CN={{secret-guid}},CN=Policies,CN=System,{DN}'
    with gzip.open(data_dir / 'ad/1.json.gz', 'rt') as f:
        raw = json.load(f)
    raw['objects'] = [
        {'dn': host_dn, 'class': 'computer', 'sid': f'{SID}-3100', 'sam': 'secret-pc$', 'dNSHostName': host.fqdn, 'primaryGroupID': 515},
        {'dn': f'CN=Domain Computers,{DN}', 'class': 'group', 'sid': f'{SID}-515', 'sam': 'Domain Computers', 'member': []},
        {'dn': ou, 'class': 'organizationalUnit', 'gpLink': f'[LDAP://{gpo_dn};0]', 'gpOptions': 0},
        {'dn': gpo_dn, 'class': 'groupPolicyContainer', 'name': '{secret-guid}', 'displayName': 'Private GPO'},
    ]
    with gzip.open(data_dir / 'ad/1.json.gz', 'wt') as f:
        json.dump(raw, f)
    bundle = build_bundle(db, data_dir, 'host', 1)
    tables = bundle['tables']
    asset, ksc_host = tables['asset'][0], tables['ksc_host'][0]
    assert asset['name'] == ksc_host['name']
    assert asset['fqdn'] == ksc_host['fqdn']
    assert asset['ip'] == ksc_host['ip'] == tables['asset_observation'][0]['ip']
    assert tables['asset_observation'][0]['ips'][1].startswith('2001:db8:')
    assert tables['asset_observation'][1]['source_key'] == f"{tables['ksc_server'][0]['id']}:{ksc_host['host_id']}"
    assert tables['ksc_policy'][0]['policy_id'] == tables['ksc_policy_scope'][0]['policy_id'] == tables['ksc_profile'][0]['policy_id']
    assert tables['ksc_policy_scope'][0]['group_id'] == ksc_host['group_id']
    assert tables['ksc_profile'][0]['name'] == tables['ksc_net_rule'][0]['profile']
    idx = ExportIndex(AdExport.model_validate(bundle['ad_exports'][0]['export']))
    computer = idx.objects('computer')[0]
    assert computer.sam == asset['name']
    assert account_groups(idx).groups[computer.sid][0]['primary'] is True
    gpo = idx.objects('groupPolicyContainer')[0]
    assert idx.gpo_links(gpo)
    assert computer.dn.lower().endswith(idx.objects('organizationalUnit')[0].dn.lower())
    raw_text = json.dumps(bundle)
    for private in ['secret-pc', DOMAIN, 'private-', 'Private', 'hunter2', 'TOPSECRET', '10.2.3.4', '2001:db8:1234::7', 'ab:cd:ef:12:34:56', '10.0.0.0/8', 'secret-guid']:
        assert private not in raw_text


@pytest.mark.parametrize('mutate', [
    lambda b: b['root'].update(kind=[]),
    lambda b: b['report'].update(limitations=[{}]),
    lambda b: b['tables']['asset_user'][0].update(enabled='false'),
    lambda b: b['tables']['asset_user'][0].update(display_name='original company name'),
    lambda b: b['tables']['asset_user_observation'][0].update(user_id=9999),
    lambda b: b['tables'].update(ksc_connection=[]),
])
def test_untrusted_invalid_bundle_has_safe_error(source, mutate):
    db, data_dir = source
    bundle = build_bundle(db, data_dir, 'user', 1)
    mutate(bundle)
    with pytest.raises(BundleError):
        validate_bundle(bundle)


def test_identity_names_do_not_collapse_dotted_accounts_and_dates_shift():
    from api.platform.diagnostics.sanitize import Anonymizer
    anon = Anonymizer()
    assert anon.name('alice.smith') != anon.name('alice.jones')
    assert anon.principal(f'alice.smith@{DOMAIN}').split('@')[0] == anon.name('alice.smith')
    assert anon.principal(f'{DOMAIN}\\alice.smith').split('\\')[1] == anon.name('alice.smith')
    assert anon.fqdn(f'host.{DOMAIN}').split('.')[0] == anon.name('host$')
    assert anon.name('Group.One') != anon.name('Group.Two')
    assert anon.sid(f'{SID}-515') == anon.sid(SID) + '-515'
    shifted = dt.datetime.fromisoformat(anon.date(NOW))
    assert shifted != NOW
    later = dt.datetime.fromisoformat(anon.date(NOW + dt.timedelta(days=2)))
    assert later - shifted == dt.timedelta(days=2)
    assert Anonymizer().name('alice.smith') != anon.name('alice.smith')


def test_export_does_not_flush_pending_production_changes(source):
    db, data_dir = source
    pending = Asset(name='pending-private-host')
    db.add(pending)
    build_bundle(db, data_dir, 'user', 1)
    assert pending in db.new
    assert pending.id is None


def test_large_group_roster_keeps_small_selected_slice_and_all_root_memberships(source):
    from api.modules.ad.core.account_groups import account_groups
    from api.modules.ad.core.export import AdExport, ExportIndex
    from api.modules.assets.models import AssetGroup, AssetGroupMember

    db, data_dir = source
    db.add(AssetGroup(id=7, group_key='private-domain-group', sid=f'{SID}-2000', name='secret-group-0', domain=DOMAIN, members_direct=5002))
    db.add(AssetGroupMember(group_id=7, member_kind='user', user_id=1, member_sid=f'{SID}-1100', member_name='alice', source='ad'))
    db.flush()
    db.execute(AssetUser.__table__.insert(), [{'id': 100+i, 'sid': f'{SID}-{4000+i}', 'sam': f'private-person-{i}', 'domain': DOMAIN} for i in range(5001)])
    db.execute(AssetGroupMember.__table__.insert(), [{'group_id': 7, 'member_kind': 'user', 'user_id': 100+i, 'member_sid': f'{SID}-{4000+i}', 'member_name': f'private-person-{i}', 'source': 'ad'} for i in range(5001)])
    db.commit()
    with gzip.open(data_dir / 'ad/1.json.gz', 'rt') as f:
        raw = json.load(f)
    raw['objects'][1]['member'].extend(f'CN=private-person-{i},{DN}' for i in range(5001))
    raw['objects'].extend({'dn': f'CN=private-person-{i},{DN}', 'class': 'user', 'sid': f'{SID}-{4000+i}', 'sam': f'private-person-{i}'} for i in range(5001))
    with gzip.open(data_dir / 'ad/1.json.gz', 'wt') as f:
        json.dump(raw, f)
    bundle = build_bundle(db, data_dir, 'user', 1)
    assert len(bundle['tables']['asset_user']) == 1
    assert len(bundle['tables']['asset_group_member']) == 1
    assert 'members_direct' not in bundle['tables']['asset_group'][0]
    assert len(bundle['tables']['asset_user_group']) == 101
    export = AdExport.model_validate(bundle['ad_exports'][0]['export'])
    sid = bundle['tables']['asset_user'][0]['sid']
    assert len(account_groups(ExportIndex(export)).groups[sid]) == 67
    assert len(export.objects) == 68
    assert sum(len(obj.member) for obj in export.objects) == 67
    assert any('Состав групп ограничен' in warning for warning in bundle['report']['limitations'])


def test_cached_builtin_group_lookup_is_scoped_to_selected_domain(source):
    from api.modules.assets.models import AssetGroup
    db, data_dir = source
    db.add(AssetUserGroup(user_id=1, group_sid='S-1-5-32-544', group_name='Administrators', direct=True, source='ad'))
    db.add_all([
        AssetGroup(id=8, group_key='selected-admins', sid='S-1-5-32-544', name='Selected Administrators', domain=DOMAIN),
        AssetGroup(id=9, group_key='other-admins', sid='S-1-5-32-544', name='Other Administrators', domain='other.private'),
    ])
    db.commit()
    bundle = build_bundle(db, data_dir, 'user', 1)
    groups = bundle['tables']['asset_group']
    assert len(groups) == 1
    assert groups[0]['domain'] == bundle['tables']['asset_user'][0]['domain']


def test_parent_group_chains_survive_without_exporting_siblings(source):
    from api.modules.ad.core.account_groups import account_groups
    from api.modules.ad.core.export import AdExport, ExportIndex
    from api.modules.assets.models import AssetGroup, AssetGroupMember

    db, data_dir = source
    db.add_all([
        AssetGroup(id=7, group_key='child', sid=f'{SID}-2000', name='secret-group-0', domain=DOMAIN),
        AssetGroup(id=8, group_key='parent', sid=f'{SID}-2001', name='secret-group-1', domain=DOMAIN),
        AssetGroup(id=9, group_key='sibling', sid=f'{SID}-9999', name='unrelated-sibling', domain=DOMAIN),
    ])
    db.add_all([
        AssetGroupMember(group_id=7, user_id=1, member_kind='user', member_sid=f'{SID}-1100', member_name='alice', source='ad'),
        AssetGroupMember(group_id=8, member_group_id=7, member_kind='group', member_sid=f'{SID}-2000', source='ad'),
        AssetGroupMember(group_id=8, member_group_id=9, member_kind='group', member_sid=f'{SID}-9999', source='ad'),
    ])
    db.commit()
    with gzip.open(data_dir / 'ad/1.json.gz', 'rt') as f:
        raw = json.load(f)
    raw['objects'][2]['member'] = [raw['objects'][1]['dn'], f'CN=unrelated-sibling,{DN}']
    raw['objects'].append({'dn': f'CN=unrelated-sibling,{DN}', 'class': 'group', 'sid': f'{SID}-9999', 'sam': 'unrelated-sibling', 'member': []})
    with gzip.open(data_dir / 'ad/1.json.gz', 'wt') as f:
        json.dump(raw, f)
    bundle = build_bundle(db, data_dir, 'user', 1)
    assert len(bundle['tables']['asset_user']) == 1
    assert len(bundle['tables']['asset_group']) == 2
    assert len(bundle['tables']['asset_group_member']) == 2
    idx = ExportIndex(AdExport.model_validate(bundle['ad_exports'][0]['export']))
    sid = bundle['tables']['asset_user'][0]['sid']
    links = account_groups(idx).groups[sid]
    assert len(links) == 67
    assert sum(not link['direct'] for link in links) == 1
    assert len(idx.objects('group')) == 67


def test_local_group_sid_lookup_is_scoped_to_first_hop_host(source):
    from api.modules.assets.models import AssetGroup, AssetUserHost
    db, data_dir = source
    user = db.get(AssetUser, 1)
    user.local = True
    user.domain = ''
    db.add(Asset(id=2, name='other-private-host'))
    db.add(AssetUserHost(user_id=1, asset_id=1, source='ksc', kind='owner', seen_at=NOW))
    db.add(AssetUserGroup(user_id=1, group_sid='S-1-5-32-544', group_name='Administrators', direct=True, source='ad'))
    db.add_all([
        AssetGroup(id=8, group_key='selected-local-admins', sid='S-1-5-32-544', name='Administrators', domain='', local=True, host_asset_id=1),
        AssetGroup(id=9, group_key='other-local-admins', sid='S-1-5-32-544', name='Administrators', domain='', local=True, host_asset_id=2),
    ])
    db.commit()
    bundle = build_bundle(db, data_dir, 'user', 1)
    assert len(bundle['tables']['asset']) == 1
    assert len(bundle['tables']['asset_group']) == 1
    assert bundle['tables']['asset_group'][0]['host_asset_id'] == bundle['tables']['asset'][0]['id']


@pytest.mark.parametrize(('dns_root', 'netbios'), [(DOMAIN, 'SECRET'), ('intranet', ''), ('intranet', 'INTRANET')])
def test_qualified_cached_group_names_match_latest_ad_principal_names(source, dns_root, netbios):
    from api.modules.ad.core.account_groups import account_groups
    from api.modules.ad.core.export import AdExport, ExportIndex
    from api.modules.assets.models import AssetGroup, AssetGroupMember

    db, data_dir = source
    user = db.get(AssetUser, 1)
    user.domain = dns_root
    user.name_key = f'{dns_root}\\alice'
    user.upn = f'alice@{dns_root}'
    domain = db.get(AdDomain, 1)
    domain.dns_root = dns_root
    domain.netbios = netbios
    for group in db.scalars(select(AssetUserGroup)):
        group.group_name = f'{netbios or dns_root}\\{group.group_name}'
    db.add(AssetGroup(id=7, group_key='qualified-group', sid=f'{SID}-2000', name='secret-group-0', domain=dns_root))
    db.add(AssetGroupMember(group_id=7, user_id=1, member_kind='user', member_sid=user.sid, member_name=f'{netbios or dns_root}\\alice', member_domain=dns_root, source='ad'))
    db.commit()
    with gzip.open(data_dir / 'ad/1.json.gz', 'rt') as f:
        raw = json.load(f)
    raw['domain']['dns_root'] = dns_root
    raw['domain']['netbios'] = netbios
    raw['objects'][0]['userPrincipalName'] = user.upn
    with gzip.open(data_dir / 'ad/1.json.gz', 'wt') as f:
        json.dump(raw, f)
    bundle = build_bundle(db, data_dir, 'user', 1)
    cached = {row['group_sid']: row['group_name'] for row in bundle['tables']['asset_user_group']}
    idx = ExportIndex(AdExport.model_validate(bundle['ad_exports'][0]['export']))
    user_row = bundle['tables']['asset_user'][0]
    current = account_groups(idx).groups[user_row['sid']]
    assert len(current) == 67
    assert all(cached[group['sid']] == group['name'] for group in current)
    assert user_row['name_key'] == user_row['domain'] + '\\' + user_row['sam']
    assert user_row['upn'] == user_row['sam'] + '@' + user_row['domain']
    assert idx.objects('user')[0].userPrincipalName == user_row['upn']

    assert bundle['tables']['asset_group_member'][0]['member_name'] == idx.principal_name(user_row['sid'])
