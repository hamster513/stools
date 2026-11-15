"""Versioned native module exports, using synthetic data only."""
import copy
import gzip
import json

import pytest
from sqlalchemy import inspect

from api.modules.assets.models import AssetUser
from api.platform.diagnostics.schema import BundleError
from api.platform.diagnostics.storage import decode_archive, encode_archive
from tests.platform.test_diagnostic_export import source  # noqa: F401


def _native_source(source_data):
    db, directory = source_data
    path = directory / "ad/1.json.gz"
    with gzip.open(path, "rt") as stream:
        raw = json.load(stream)
    # Legacy fixture deliberately contains malformed SYSVOL, not a native export.
    raw.pop("sysvol", None)
    raw.pop("collector", None)
    with gzip.open(path, "wt") as stream:
        json.dump(raw, stream)
    return db, directory


def test_module_archive_keeps_native_ad_and_independent_cached_memberships(source):  # noqa: F811
    from api.modules.ad.core.account_groups import account_groups
    from api.modules.ad.core.export import AdExport, ExportIndex
    from api.platform.diagnostics.module_export import build_module_bundle

    db, directory = _native_source(source)
    bundle = build_module_bundle(db, directory, "user", 1)
    assert bundle["format"] == "stools-diagnostic/2"
    native = AdExport.model_validate(bundle["ad_exports"][0]["export"])
    sid = bundle["tables"]["asset_user"][0]["sid"]
    assert len(account_groups(ExportIndex(native)).groups[sid]) == 67
    assert len(bundle["tables"]["asset_user_group"]) == 101
    assert bundle["ksc_exports"] == []
    assert decode_archive(encode_archive(bundle)) == bundle
    rendered = json.dumps(bundle).lower()
    assert all(marker not in rendered for marker in ["alice", "secret.corp", "secret-group", "hunter2", "topsecret", "123-456-789"])


def test_module_export_is_readonly_and_never_flushes_pending_changes(source):  # noqa: F811
    from api.platform.diagnostics.module_export import build_module_bundle

    db, directory = _native_source(source)
    pending = AssetUser(sam="unsaved", name_key="unsaved", domain="")
    db.add(pending)
    build_module_bundle(db, directory, "user", 1)
    assert pending.id is None
    assert inspect(pending).pending


def test_module_export_requires_saved_native_snapshot(source):  # noqa: F811
    from api.platform.diagnostics.module_export import build_module_bundle

    db, directory = _native_source(source)
    (directory / "ad/1.json.gz").unlink()
    with pytest.raises(BundleError, match="directory export"):
        build_module_bundle(db, directory, "user", 1)


@pytest.mark.parametrize("mutation", [
    lambda b: b["ad_exports"].clear(),
    lambda b: b["ad_exports"][0].update(snapshot_id=999),
    lambda b: b["tables"]["ad_domain"][0].update(sid="S-1-5-21-1-2-3"),
    lambda b: b.update(connections=[{"password": "should-not-be-here"}]),
    lambda b: b["report"]["counts"].update(asset_user=999),
    lambda b: b["tables"]["ad_snapshot"][0].update(objects=999999),
    lambda b: b["tables"]["asset_user_observation"][0].update(source="ksc", source_key="999999:entity-0000000000000000", data={}),
])
def test_module_validation_rejects_broken_snapshot_links_and_unknown_data(source, mutation):  # noqa: F811
    from api.platform.diagnostics.module_export import build_module_bundle, validate_module_bundle

    db, directory = _native_source(source)
    bundle = copy.deepcopy(build_module_bundle(db, directory, "user", 1))
    mutation(bundle)
    with pytest.raises(BundleError):
        validate_module_bundle(bundle)


@pytest.mark.parametrize("cached_host", [True, False])
@pytest.mark.parametrize("qualified", [True, False])
def test_full_slice_keeps_ksc_policy_firewall_and_user_links_in_normal_modules(source, db_session, tmp_path, cached_host, qualified):  # noqa: F811
    import datetime as dt

    from sqlalchemy import select

    from api.modules.assets.models import (
        Asset,
        AssetObservation,
        AssetUserHost,
        AssetUserObservation,
    )
    from api.modules.ksc.core.profile_activation import evaluate, parse_condition
    from api.modules.ksc.models import (
        KscHost,
        KscPolicy,
        KscPolicyScope,
        KscProfile,
        KscServer,
        KscSnapshot,
    )
    from api.platform.diagnostics.module_export import build_module_bundle
    from api.platform.diagnostics.module_import import import_bundle
    from tests.platform.test_diagnostic_ksc_payload import fixture

    db, directory = _native_source(source)
    raw = fixture()
    user = db.get(AssetUser, 1)
    raw['host_users']['PRIVATE-HOST-ID'][0].update(sid='' if qualified else user.sid, sam='SECRET\\alice' if qualified else user.sam, upn=user.upn, display_name=user.display_name, domain=user.domain)
    user_source_key = '77:SECRET\\alice' if qualified else f'77:{user.sid}'
    from api.modules.ksc.core.export import ExportIndex, KscExport
    source_path = ExportIndex(KscExport.model_validate(raw)).hosts[0].group_path
    collected = dt.datetime.fromisoformat(raw['server']['collected_at'])
    host = db.get(Asset, 1)
    host.name = host.name_key = 'private-workstation'
    host.fqdn = 'private-workstation.private.test'
    host.domain = 'private.test'
    host.ip = '10.26.9.20'
    db.add(KscServer(id=77, name=raw['server']['name']))
    db.add(KscSnapshot(id=88, server_id=77, collected_at=collected, source='file'))
    if cached_host:
        db.add(KscHost(id=99, snapshot_id=88, host_id='PRIVATE-HOST-ID', name=host.name, fqdn=host.fqdn,
                       domain=host.domain, ip=host.ip, group_id=7, group_path='PRIVATE-ROOT/PRIVATE-GROUP'))
    db.add(KscPolicy(id=11, snapshot_id=88, policy_id=41, name='PRIVATE-POLICY', group_id=0))
    db.add(KscPolicyScope(id=12, snapshot_id=88, policy_id=41, group_id=7, own=False, hosts=1))
    db.add(KscProfile(id=13, snapshot_id=88, policy_id=41, name='PRIVATE-PROFILE'))
    db.add(AssetObservation(asset_id=1, source='ksc', source_key='77:PRIVATE-HOST-ID', name=host.name,
                            fqdn=host.fqdn, domain=host.domain, ip=host.ip, seen_at=collected, extra={'server_id':77, 'tags':['private-tag'], 'group_path':source_path}))
    db.add(AssetUserObservation(user_id=1, source='ksc', source_key=user_source_key, seen_at=collected, data={'server_id':77}))
    db.add(AssetUserHost(user_id=1, asset_id=1, source='ksc', kind='session', active=True, seen_at=collected))
    db.commit()
    (directory/'ksc').mkdir()
    with gzip.open(directory/'ksc/88.json.gz', 'wt') as stream:
        json.dump(raw, stream)
    wire = decode_archive(encode_archive(build_module_bundle(db, directory, 'host', 1)))
    assert len(wire['ad_exports']) == len(wire['ksc_exports']) == 1
    result = import_bundle(db_session, tmp_path/'target', wire)
    target_host = db_session.get(Asset, result['root']['id'])
    imported_host = db_session.scalar(select(KscHost).limit(1))
    assert imported_host.ip == target_host.ip and imported_host.fqdn == target_host.fqdn
    observation = db_session.scalar(select(AssetObservation).where(AssetObservation.asset_id == target_host.id).limit(1))
    snapshot = db_session.get(KscSnapshot, imported_host.snapshot_id)
    assert observation.source_key == f'{snapshot.server_id}:{imported_host.host_id}'
    assert observation.extra['server_id'] == snapshot.server_id
    [profile] = db_session.scalars(select(KscProfile).limit(2)).all()
    host_extra = json.loads(imported_host.extra_json)
    assert observation.extra['tags'] == host_extra['tags']
    assert observation.extra['group_path'] == imported_host.group_path
    from api.modules.assets.services.users import _ksc_seen
    seen = _ksc_seen(snapshot.server_id, imported_host.host_id, target_host.id, host_extra['users'][0], snapshot.collected_at)
    cached_user = db_session.scalar(select(AssetUserObservation).where(AssetUserObservation.source == 'ksc').limit(1))
    assert cached_user.source_key == seen.source_key
    assert evaluate(parse_condition(json.loads(profile.condition_json)), host_extra['tags']).active is True
    from api.modules.ksc.models import KscNetRule
    rule = db_session.scalar(select(KscNetRule).limit(1))
    assert rule.scope_json and rule.addresses
    assert 'private' not in json.dumps(wire).casefold()


def test_cached_tags_pins_and_selected_gpo_hosts_survive_export(source):  # noqa: F811
    from api.modules.assets.models import Asset, AssetGroup, AssetGroupGpo, AssetUserHost
    from api.platform.diagnostics.module_export import build_module_bundle
    from tests.platform.test_diagnostic_export import DOMAIN, NOW, SID

    db, directory = _native_source(source)
    host = db.get(Asset, 1)
    host.tags = ['PRIVATE-TAG']
    host.pinned = {'name': True, 'ip': False}
    db.get(AssetUser, 1).tags = ['PRIVATE-TAG']
    db.add(AssetUserHost(user_id=1, asset_id=1, source='ad', kind='session', seen_at=NOW))
    db.add(AssetGroup(id=7, group_key='private-key', name='secret-group-0', sid=f'{SID}-2000', domain=DOMAIN, sources=['ad']))
    db.add(AssetGroupGpo(domain=DOMAIN, group_sid=f'{SID}-2000', group_name='secret-group-0',
                         gpo_name='Private policy', hosts=[host.name, 'not-selected-private-host'], hosts_total=2, seen_at=NOW))
    db.commit()
    bundle = build_module_bundle(db, directory, 'user', 1)
    asset = bundle['tables']['asset'][0]
    assert asset['tags'] == bundle['tables']['asset_user'][0]['tags']
    assert asset['pinned'] == host.pinned
    rights = bundle['tables']['asset_group_gpo'][0]
    assert rights['hosts'] == [asset['name']]
    assert rights['hosts_total'] == 1
    assert 'private' not in json.dumps(bundle).lower()


def test_ksc_observation_requires_native_snapshot_instead_of_silent_omission(source):  # noqa: F811
    from api.modules.assets.models import AssetObservation
    from api.modules.ksc.models import KscServer
    from api.platform.diagnostics.module_export import build_module_bundle
    from tests.platform.test_diagnostic_export import NOW

    db, directory = _native_source(source)
    db.add(KscServer(id=77, name="private-server"))
    db.add(AssetObservation(asset_id=1, source="ksc", source_key="77:private-host", seen_at=NOW, extra={"server_id":77}))
    db.commit()
    with pytest.raises(BundleError, match="KSC export"):
        build_module_bundle(db, directory, "host", 1)
