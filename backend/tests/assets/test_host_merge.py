"""Analyst merges inconsistent inventory names without losing host information."""
import datetime as dt

import pytest
from sqlalchemy import select

from api.modules.assets.core.groups import group_key
from api.modules.assets.core.matching import Observed, canonical
from api.modules.assets.models import (
    Asset,
    AssetGroup,
    AssetGroupMember,
    AssetObservation,
    AssetUser,
    AssetUserHost,
)
from api.modules.assets.services.assets import apply_observation, recompute

NOW = dt.datetime(2026, 11, 25, tzinfo=dt.UTC)


@pytest.mark.parametrize('order', [False, True])
def test_ad_identity_wins_over_newer_racktables_ksc_dns(order):
    ad = Observed(source='ad', source_key='sid', name='SRV01', fqdn='srv01.corp.test', domain='corp.test', seen_at=NOW-dt.timedelta(days=10))
    rows = [ad, *[Observed(source=s, source_key=s, name=s+'-label', fqdn=s+'.other.test', domain='other.test', ip='192.0.2.10', os='Linux', seen_at=NOW) for s in ('rt', 'ksc', 'dns')]]
    result = canonical(rows[::-1] if order else rows, {}, {})
    assert (result['name'], result['fqdn'], result['domain']) == ('SRV01', 'srv01.corp.test', 'corp.test')
    assert result['ip'] == '192.0.2.10' and result['os'] == 'Linux'
    assert canonical(rows, {'name': True}, {'name': 'analyst choice'})['name'] == 'analyst choice'
    ad.gone_at = NOW
    assert canonical(rows, {}, {})['name'] == 'dns-label'


def host(db, source, key, name, *, fqdn='', domain='', days=0, ips=None):
    a = Asset(name=name, tags=[], note='')
    db.add(a); db.flush()
    values = ips or ['192.0.2.10']
    o = AssetObservation(asset_id=a.id, source=source, source_key=key, name=name, fqdn=fqdn, domain=domain,
                         ip=values[0], ips=values, os='Linux', seen_at=NOW-dt.timedelta(days=days), extra={})
    db.add(o); db.flush(); recompute(db, a)
    return a, o


@pytest.mark.parametrize('into_ad', [True, False])
def test_analyst_merge_keeps_sources_ips_and_ad_identity_after_resync(db_session, client_as, into_ad):
    db = db_session
    ad, _ = host(db, 'ad', 'S-1-host', 'SRV01', fqdn='srv01.corp.test', domain='corp.test', days=10)
    rt, _ = host(db, 'rt', '192.0.2.10', 'Rack 1 / Server A', ips=['192.0.2.10', '2001:db8::10'])
    ad.tags, ad.note = ['domain'], 'domain note'
    rt.tags, rt.note = ['rack'], 'rack note'
    into, other = (ad, rt) if into_ad else (rt, ad)
    ids = into.id, other.id
    db.commit()
    c = client_as('analyst')
    response = c.post(f'/api/assets/assets/{ids[0]}/merge', json={'other_id': ids[1]})
    assert response.status_code == 200, response.text
    card = response.json()
    assert card['name'] == 'SRV01' and card['fqdn'] == 'srv01.corp.test'
    assert {x['source'] for x in card['observations']} == {'ad', 'rt'}
    assert next(x for x in card['observations'] if x['source'] == 'rt')['ips'] == ['192.0.2.10', '2001:db8::10']
    assert set(card['tags']) == {'domain', 'rack'} and 'domain note' in card['note'] and 'rack note' in card['note']
    assert c.get(f'/api/assets/assets/{ids[1]}').json()['merged_into'] == ids[0]
    # The next RackTables import must attach by the original source key.
    db.expire_all()
    updated, _ = apply_observation(db, Observed(source='rt', source_key='192.0.2.10', name='Changed rack label', ip='192.0.2.10', seen_at=NOW+dt.timedelta(days=1)))
    assert updated.id == ids[0] and updated.name == 'SRV01'


@pytest.mark.parametrize('pinned_target', [False, True])
def test_merge_transfers_pinned_value_with_flag(db_session, client_as, pinned_target):
    db = db_session
    into, _ = host(db, 'rt', 'rt', 'rack label')
    other, _ = host(db, 'ksc', '1:ksc', 'ksc label', ips=['192.0.2.20'])
    other.ip, other.pinned = '192.0.2.99', {'ip': True}
    into.pinned = {'ip': pinned_target}
    ids = into.id, other.id
    db.commit()
    response = client_as('analyst').post(f'/api/assets/assets/{ids[0]}/merge', json={'other_id': ids[1]})
    assert response.status_code == 200, response.text
    assert response.json()['pinned']['ip'] and response.json()['ip'] == ('192.0.2.10' if pinned_target else '192.0.2.99')


def test_merge_moves_users_and_group_memberships_immediately(db_session, client_as):
    db = db_session
    into, _ = host(db, 'ad', 'sid', 'SRV01', fqdn='srv01.corp.test', domain='corp.test')
    other, ksc = host(db, 'ksc', '1:ksc', 'KSC alias')
    ksc.extra = {'users_collected': True}
    user = AssetUser(sam='alice', name_key='corp.test\\alice', domain='corp.test')
    db.add(user); db.flush()
    db.add_all([AssetUserHost(user_id=user.id, asset_id=into.id, source='ksc', kind='session', active=False, seen_at=NOW-dt.timedelta(days=1), gone_at=NOW),
                AssetUserHost(user_id=user.id, asset_id=other.id, source='ksc', kind='session', active=True, seen_at=NOW)])
    group = AssetGroup(group_key='domain-group', name='servers', local=False, domain='corp.test', first_seen=NOW, last_seen=NOW)
    db.add(group); db.flush()
    db.add(AssetGroupMember(group_id=group.id, source='ad', member_kind='computer', member_name='SRV01', asset_id=other.id))
    locals = []
    for a in (into, other):
        g = AssetGroup(group_key=group_key(local=True, domain='', host_asset_id=a.id, sid='', name='sudo'), name='sudo', local=True, host_asset_id=a.id, first_seen=NOW, last_seen=NOW, sources=['vm'])
        db.add(g); db.flush(); locals.append(g.id)
    for gid, sam in [(locals[0], 'root'), (locals[1], 'root'), (locals[1], 'alice')]:
        db.add(AssetGroupMember(group_id=gid, source='vm', member_kind='user', member_name=sam, user_id=user.id if sam=='alice' else None))
    ids = into.id, other.id
    uid = user.id
    db.commit()
    response = client_as('analyst').post(f'/api/assets/assets/{ids[0]}/merge', json={'other_id': ids[1]})
    assert response.status_code == 200, response.text
    assert [(u['user_id'], u['active'], u['gone']) for u in response.json()['users']] == [(uid, True, False)]
    db.expire_all()
    assert db.scalars(select(AssetUserHost).where(AssetUserHost.asset_id == ids[1]).limit(5)).all() == []
    assert db.scalar(select(AssetGroupMember.asset_id).where(AssetGroupMember.member_kind == 'computer').limit(1)) == ids[0]
    groups = db.scalars(select(AssetGroup).where(AssetGroup.local.is_(True)).limit(5)).all()
    assert len(groups) == 1 and groups[0].host_asset_id == ids[0]
    assert groups[0].members_direct == 2
    assert set(db.scalars(select(AssetGroupMember.member_name).where(AssetGroupMember.group_id == groups[0].id).limit(5))) == {'root', 'alice'}


def test_merge_rekeys_unique_local_group_and_keeps_members(db_session, client_as):
    db = db_session
    into, _ = host(db, 'ad', 'sid', 'SRV01')
    other, _ = host(db, 'rt', 'rt', 'Rack A')
    group = AssetGroup(group_key=group_key(local=True, domain='', host_asset_id=other.id, sid='', name='wheel'), name='wheel', local=True, host_asset_id=other.id, members_direct=1)
    db.add(group); db.flush()
    member = AssetGroupMember(group_id=group.id, member_kind='user', member_name='root', source='vm')
    db.add(member); db.flush()
    ids, gid, mid = (into.id, other.id), group.id, member.id
    db.commit()
    response = client_as('analyst').post(f'/api/assets/assets/{ids[0]}/merge', json={'other_id': ids[1]})
    assert response.status_code == 200, response.text
    db.expire_all()
    saved = db.get(AssetGroup, gid)
    assert saved.host_asset_id == ids[0] and saved.group_key == f'l:{ids[0]}:n:wheel'
    assert saved.members_direct == 1 and db.get(AssetGroupMember, mid).group_id == gid
