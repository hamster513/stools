"""AD contacts survive collection, snapshots, sync and user views."""
import datetime as dt
from pathlib import Path

from sqlalchemy import select

from api.modules.ad.core.ldap_collector import LdapCollector
from api.modules.assets.models import AssetUser, AssetUserObservation
from tests.ad.fake_ldap import FakeLdap
from tests.assets.test_users_sync import load_ad, sync


def collected():
    fake = FakeLdap()
    users = {o.get('sam'): o for o in fake.objects}
    users['admin1']['displayName'] = 'Team Manager'
    users['helpdesk'].update(mail='helpdesk@example.test', manager=users['admin1']['dn'])
    return LdapCollector(fake.search, fake.root_dse()).collect()


def test_contacts_import_list_card_search_export_and_clear(db_session, app_settings, client_as):
    db = db_session
    data_dir = Path(app_settings.data_dir)
    raw = collected()
    load_ad(db, data_dir, raw); db.commit(); sync(db)
    users = {u.sam: u for u in db.scalars(select(AssetUser).limit(100))}
    uid, manager_id = users['helpdesk'].id, users['admin1'].id
    db.commit()
    c = client_as('analyst')
    card = c.get(f'/api/assets/users/{uid}').json()
    assert card['mail'] == 'helpdesk@example.test'
    assert card['manager']['name'] == 'Team Manager' and card['manager']['user_id'] == manager_id
    dn = card['manager']['dn']
    obs = next(o for o in card['observations'] if o['source']=='ad')
    assert obs['data']['mail'] == card['mail'] and obs['data']['manager'] == dn
    found = c.get('/api/assets/users',params={'q':'HELPDESK@example.test'}).json()
    assert [u['id'] for u in found['items']] == [uid]
    assert found['items'][0]['manager']['user_id'] == manager_id
    export = c.get('/api/assets/users/export',params={'format':'csv','q':'helpdesk@example.test'})
    assert export.status_code == 200 and 'Почта' in export.text and 'Руководитель' in export.text
    assert 'helpdesk@example.test' in export.text and 'Team Manager' in export.text
    db.expire_all()
    db.add(AssetUserObservation(user_id=uid,source='ksc',source_key='ksc-contact',seen_at=dt.datetime.now(dt.UTC)+dt.timedelta(days=1),data={'mail':'wrong@example.test','manager':'wrong'}))
    db.commit()
    assert c.get(f'/api/assets/users/{uid}').json()['mail'] == 'helpdesk@example.test'
    # A new export clears fields explicitly removed in AD, without losing the user identity.
    for row in raw['objects']:
        if row.get('sam')=='helpdesk':row['mail']=None;row['manager']=None
    raw['collected_at'] = (dt.datetime.now(dt.UTC)+dt.timedelta(seconds=1)).isoformat()
    load_ad(db,data_dir,raw);db.commit();sync(db);db.commit()
    card = c.get(f'/api/assets/users/{uid}').json()
    assert card['mail'] == '' and card['manager'] is None


def test_unknown_and_ambiguous_manager_never_link_to_wrong_user(db_session, client_as):
    db = db_session
    dn = 'CN=Unseen,OU=People,DC=example,DC=test'
    user = AssetUser(sam='employee',name_key='example.test\\employee')
    db.add(user);db.flush()
    db.add(AssetUserObservation(user_id=user.id,source='ad',source_key='employee',seen_at=dt.datetime.now(dt.UTC),data={'mail':'a@example.test','manager':dn}))
    uid=user.id;db.commit();c=client_as('analyst')
    manager=c.get(f'/api/assets/users/{uid}').json()['manager']
    assert manager=={'dn':dn,'name':dn,'user_id':None}
    for i in range(2):
        other=AssetUser(sam=f'manager{i}',name_key=f'manager{i}')
        db.add(other);db.flush()
        db.add(AssetUserObservation(user_id=other.id,source='ad',source_key=f'manager{i}',seen_at=dt.datetime.now(dt.UTC),data={'dn':dn.upper()}))
    db.commit()
    assert c.get(f'/api/assets/users/{uid}').json()['manager']['user_id'] is None


def test_legacy_and_gone_ad_contacts_are_not_current(db_session, client_as):
    db=db_session;u=AssetUser(sam='legacy',name_key='legacy');db.add(u);db.flush()
    o=AssetUserObservation(user_id=u.id,source='ad',source_key='legacy',seen_at=dt.datetime.now(dt.UTC),data={'upn':'legacy@example.test'})
    db.add(o);uid=u.id;db.commit();c=client_as('analyst')
    card=c.get(f'/api/assets/users/{uid}').json()
    assert card['mail']=='' and card['manager'] is None
    o.data={'mail':'old@example.test','manager':'CN=Old'};o.gone_at=dt.datetime.now(dt.UTC);db.commit()
    card=c.get(f'/api/assets/users/{uid}').json()
    assert card['mail']=='' and card['manager'] is None
    assert card['observations'][0]['data']['mail']=='old@example.test'


def test_contacts_use_batched_queries_and_resolve_manager_across_domains(db_session):
    from sqlalchemy import event

    from api.modules.assets.services.user_views import _ad_contacts
    db = db_session
    now = dt.datetime.now(dt.UTC)
    manager = AssetUser(sam='chief',display_name='Manager in another domain',name_key='other.test\\chief')
    db.add(manager);db.flush()
    dn='CN=Chief,DC=other,DC=test'
    db.add(AssetUserObservation(user_id=manager.id,source='ad',source_key='chief',seen_at=now,data={'dn':dn}))
    ids=[]
    for i in range(5):
        u=AssetUser(sam=f'person{i}',name_key=f'corp.test\\person{i}');db.add(u);db.flush();ids.append(u.id)
        db.add(AssetUserObservation(user_id=u.id,source='ad',source_key=f'person{i}',seen_at=now,data={'mail':f'person{i}@example.test','manager':dn.upper()}))
    db.commit();manager_id=manager.id
    calls=[]
    def count(*args):calls.append(1)
    connection=db.connection();event.listen(connection,'before_cursor_execute',count)
    try:
        values=_ad_contacts(db,ids)
    finally:
        event.remove(connection,'before_cursor_execute',count)
    assert len(calls)==2
    assert all(x['manager']['user_id']==manager_id for x in values.values())
