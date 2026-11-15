"""Ordinary Assets sync must not rewrite imported diagnostic evidence."""
import copy
import importlib
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine, delete, func, select, update
from sqlalchemy.orm import Session, aliased

from api.modules.assets.models import (
    Asset,
    AssetDns,
    AssetGroupGpo,
    AssetJob,
    AssetObservation,
    AssetRacktables,
    AssetUser,
    AssetUserGroup,
    AssetUserObservation,
)
from api.modules.vm.models import VmHost
from api.platform.diagnostics.models import DiagnosticImport
from api.platform.diagnostics.module_import import get_import, import_bundle
from api.platform.diagnostics.schema import TABLE_MODELS
from tests.assets.synthetic import load_vm
from tests.assets.test_sync import sync
from tests.platform.test_diagnostic_module_import import DOMAIN, NOW, bundle  # noqa: F401 — fixture


def guard():
    return importlib.import_module("api.platform.diagnostics.sync_guard").diagnostic_sync_guard


def _snapshot(db, owned):
    return {name: [dict(row) for row in db.execute(select(TABLE_MODELS[name].__table__)
                  .where(TABLE_MODELS[name].id.in_(ids)).order_by(TABLE_MODELS[name].id)).mappings()]
            for name, ids in owned.items()}


@pytest.fixture
def imported(bundle, db_session, app_settings):  # noqa: F811 — shared fixture
    fqdn = f"computer.{DOMAIN}"
    bundle["tables"]["asset"][0].update(fqdn=fqdn, ip="192.0.2.77")
    bundle["tables"]["asset_observation"][0].update(fqdn=f"observed.{DOMAIN}", ip="192.0.2.78")
    bundle["tables"]["asset_group_gpo"] = [{"id": 1001, "domain": DOMAIN, "group_name": "cached-group", "gpo_name": "cached-policy",
        "local_group": "Administrators", "via": "gpp", "action": "add", "seen_at": NOW.isoformat()}]
    metadata = import_bundle(db_session, app_settings.data_dir, bundle)
    owned = {name: list(db_session.scalars(select(model.id))) for name, model in TABLE_MODELS.items()}
    owned = {name: ids for name, ids in owned.items() if ids}
    return metadata, owned


def test_guard_supports_sqlite_queries_and_core_writes():
    engine = create_engine("sqlite://")
    DiagnosticImport.__table__.create(engine)
    Asset.__table__.create(engine)
    try:
        with Session(engine) as db:
            diagnostic, normal = Asset(name="diagnostic"), Asset(name="normal")
            db.add_all([diagnostic, normal])
            db.flush()
            diagnostic_id, normal_id = diagnostic.id, normal.id
            db.add(DiagnosticImport(id="sqlite", sha256="test", records_json=json.dumps({
                "tables": {"asset": [{"id": diagnostic_id}]},
            })))
            db.commit()
            with guard()(db):
                assert list(db.scalars(select(Asset.id))) == [normal_id]
                db.execute(update(Asset.__table__).values(name="updated"))
                db.execute(delete(Asset))
                db.commit()
            assert list(db.scalars(select(Asset.id))) == [diagnostic_id]
            assert db.get(Asset, diagnostic_id).name == "diagnostic"
    finally:
        engine.dispose()


@pytest.mark.parametrize("with_live_host", [False, True])
def test_scheduled_dns_uses_only_live_targets(imported, db_session, app_settings, monkeypatch, with_live_host):
    from api.modules.assets.core.dns import Answer
    from api.modules.assets.services import dns
    from api.platform.scheduler import PlatformSchedule

    metadata, owned = imported
    before = copy.deepcopy(_snapshot(db_session, owned))
    calls = []

    def server_address(name):
        calls.append(("server", name))
        return "127.0.0.1"

    def forward(name, *_args, **_kwargs):
        calls.append(("forward", name))
        return Answer(["192.0.2.10"], 60, "A")

    def reverse(ip, *_args, **_kwargs):
        calls.append(("reverse", ip))
        return Answer(["live.invalid"], 60, "PTR")

    monkeypatch.setattr(dns, "spawn", lambda fn: fn())
    monkeypatch.setattr(dns.dns_core, "server_address", server_address)
    monkeypatch.setattr(dns.dns_core, "lookup_a", forward)
    monkeypatch.setattr(dns.dns_core, "lookup_ptr", reverse)
    if with_live_host:
        db_session.add(Asset(name="live", name_key="live", fqdn="live.invalid", ip="192.0.2.10"))
    row = AssetDns(server="resolver.invalid", mode="direct", forward=True, reverse=True)
    db_session.add(row)
    db_session.commit()
    job_id = dns.schedule_handler(db_session, PlatformSchedule(module="assets", kind="dns", target_id=row.id))
    db_session.expire_all()
    job = db_session.get(AssetJob, job_id)
    assert job.status == "done", job.error
    assert calls == ([("server", "resolver.invalid"), ("forward", "live.invalid"), ("reverse", "192.0.2.10")] if with_live_host else [])
    assert _snapshot(db_session, owned) == before
    assert get_import(db_session, metadata["id"], data_dir=app_settings.data_dir)["status"] == "ready"
    live_rows = list(db_session.scalars(select(AssetObservation).where(AssetObservation.source == "dns",
        AssetObservation.id.not_in(owned["asset_observation"]))))
    assert len(live_rows) == (2 if with_live_host else 0)


@pytest.mark.parametrize("source", ["dns", "rt"])
def test_collection_writes_preserve_imported_rows_and_update_live_rows(imported, db_session, app_settings, source):
    from api.jobs import JobHandle, start_job
    from api.modules.assets.core.matching import Observed
    from api.modules.assets.core.racktables import RtNetwork
    from api.modules.assets.services import dns, racktables

    metadata, owned = imported
    before = copy.deepcopy(_snapshot(db_session, owned))
    service, config_model = (dns, AssetDns) if source == "dns" else (racktables, AssetRacktables)
    cfg = config_model() if source == "dns" else config_model(url="https://racktables.invalid")
    db_session.add(cfg)
    db_session.commit()
    job_id = start_job(db_session, AssetJob, source, "test")
    run = service._Run(db_session, JobHandle(db_session, db_session.get(AssetJob, job_id)), service._Settings.of(cfg), NOW)
    key = f"computer.{DOMAIN}" if source == "dns" else "192.0.2.77"
    run.found = [
        Observed(source=source, source_key=key, name="computer", fqdn=f"computer.{DOMAIN}", ip="192.0.2.99", seen_at=NOW),
        Observed(source=source, source_key="192.0.2.10", name="live", fqdn="live.invalid", ip="192.0.2.10", seen_at=NOW),
        Observed(source=source, source_key="192.0.2.88", name="computer", fqdn=f"computer.{DOMAIN}", ip="192.0.2.88", seen_at=NOW),
    ]
    if source == "rt":
        run.networks = [RtNetwork(rt_id="1", cidr="192.0.2.0/24", name="test-network")]
    assert service._write(run) is True
    db_session.expire_all()
    assert _snapshot(db_session, owned) == before
    assert get_import(db_session, metadata["id"], data_dir=app_settings.data_dir)["status"] == "ready"
    live = db_session.scalar(select(AssetObservation).where(AssetObservation.source == source, AssetObservation.source_key == "192.0.2.10"))
    assert live is not None and live.asset_id not in owned["asset"]
    same_name = db_session.scalar(select(AssetObservation).where(AssetObservation.source == source, AssetObservation.source_key == "192.0.2.88"))
    assert same_name is not None and same_name.asset_id not in owned["asset"]


def test_full_assets_sync_preserves_diagnostic_evidence_and_updates_normal_host(imported, db_session, app_settings):
    metadata, owned = imported
    before = copy.deepcopy(_snapshot(db_session, owned))
    load_vm(db_session, [("live-host", "192.0.2.10", "Windows")], NOW)
    first = sync(db_session)
    assert first["vm"] == 1 and "users_failed" not in first and "groups_failed" not in first
    assert db_session.scalar(select(func.count()).select_from(AssetUserGroup).where(AssetUserGroup.user_id == metadata["root"]["id"])) == 101
    assert _snapshot(db_session, owned) == before
    live = db_session.scalar(select(Asset).where(Asset.name_key == "live-host"))
    assert live is not None and live.ip == "192.0.2.10"
    source = db_session.scalar(select(VmHost).where(VmHost.hostname == "live-host"))
    source.ip = "192.0.2.20"
    db_session.commit()
    second = sync(db_session)
    assert second["vm"] == 1 and "users_failed" not in second and "groups_failed" not in second
    assert db_session.get(Asset, live.id).ip == "192.0.2.20"
    assert _snapshot(db_session, owned) == before
    assert get_import(db_session, metadata["id"], data_dir=app_settings.data_dir)["status"] == "ready"


def test_guard_filters_aliases_bulk_deletes_and_core_updates(imported, db_session):
    _metadata, owned = imported
    normal = AssetUser(sid="S-1-5-21-1-2-3-1100", sam="normal")
    db_session.add(normal)
    db_session.flush()
    observation = AssetUserObservation(user_id=normal.id, source="ad", source_key=normal.sid, seen_at=NOW)
    policy = AssetGroupGpo(domain="normal.invalid", seen_at=NOW)
    db_session.add_all([observation, policy])
    db_session.commit()
    original = copy.deepcopy(_snapshot(db_session, owned))
    policy_id = policy.id
    user_alias = aliased(AssetUser)
    with guard()(db_session):
        assert list(db_session.scalars(select(user_alias.id))) == [normal.id]
        assert list(db_session.scalars(select(AssetUser.id))) == [normal.id]
        db_session.execute(update(AssetUserObservation.__table__).values(gone_at=NOW))
        db_session.execute(delete(AssetGroupGpo))
        db_session.execute(update(AssetUser), [{"id": normal.id, "sam": "normal-updated"}])
        db_session.commit()
    db_session.expire_all()
    assert _snapshot(db_session, owned) == original
    assert db_session.get(AssetUser, normal.id).sam == "normal-updated"
    assert db_session.get(AssetUserObservation, observation.id).gone_at == NOW
    assert db_session.get(AssetGroupGpo, policy_id) is None


def test_guard_is_session_local_and_removed_on_error(imported, db_session):
    metadata, _owned = imported
    engine = db_session.get_bind()

    def ordinary_read():
        with Session(engine) as other:
            return other.scalar(select(func.count()).select_from(AssetUser))

    with pytest.raises(RuntimeError, match="synthetic failure"), guard()(db_session):
        assert db_session.scalar(select(func.count()).select_from(AssetUser)) == 0
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(ordinary_read).result(timeout=5) == 1
        raise RuntimeError("synthetic failure")
    assert db_session.scalar(select(func.count()).select_from(AssetUser)) == 1
    assert db_session.get(AssetUser, metadata["root"]["id"]) is not None


def test_guard_handles_imported_observations_missing_from_all_live_sources(imported, db_session):
    _metadata, owned = imported
    before = copy.deepcopy(_snapshot(db_session, owned))
    sync(db_session)
    assert _snapshot(db_session, owned) == before
    assert all(row.gone_at is None for row in db_session.scalars(select(AssetObservation)))


def test_normal_ad_membership_reconciliation_continues_beside_imported_cache(imported, db_session, app_settings):
    import gzip
    import json

    from api.modules.ad.models import AdDomain, AdSnapshot
    from api.modules.ad.services.snapshots import snapshot_path
    from api.modules.assets.models import AssetGroup, AssetGroupMember

    _metadata, owned = imported
    before = copy.deepcopy(_snapshot(db_session, owned))
    live_sid = "S-1-5-21-101-102-103"
    live_dn = "DC=live,DC=invalid"
    user_dn = "CN=live-user," + live_dn
    domain = AdDomain(sid=live_sid, dns_root="live.invalid", dn=live_dn, netbios="LIVE")
    db_session.add(domain)
    db_session.flush()
    snapshot = AdSnapshot(domain_id=domain.id, source="file", collected_at=NOW)
    db_session.add(snapshot)
    db_session.commit()
    raw = {"format": "stools-ad/1", "collected_at": NOW.isoformat(),
           "domain": {"sid": live_sid, "dns_root": "live.invalid", "dn": live_dn, "netbios": "LIVE"},
           "objects": [{"dn": user_dn, "class": "user", "sid": live_sid + "-1100", "sam": "live-user", "uac": 512},
                       {"dn": "CN=one," + live_dn, "class": "group", "sid": live_sid + "-2100", "sam": "one", "member": [user_dn]},
                       {"dn": "CN=two," + live_dn, "class": "group", "sid": live_sid + "-2200", "sam": "two", "member": [user_dn]}]}
    path = snapshot_path(app_settings.data_dir, snapshot.id)

    def save():
        with gzip.open(path, "wt") as output:
            json.dump(raw, output)

    save()
    counts = sync(db_session)
    assert "users_failed" not in counts and "groups_failed" not in counts
    user = db_session.scalar(select(AssetUser).where(AssetUser.sid == live_sid + "-1100"))
    assert user is not None
    assert db_session.scalar(select(func.count()).select_from(AssetUserGroup).where(AssetUserGroup.user_id == user.id)) == 2
    raw["objects"][1]["sam"] = "one-renamed"
    raw["objects"][2]["member"] = []
    save()
    counts = sync(db_session)
    assert "users_failed" not in counts and "groups_failed" not in counts
    assert list(db_session.scalars(select(AssetUserGroup.group_name).where(AssetUserGroup.user_id == user.id))) == ["LIVE\\one-renamed"]
    group = db_session.scalar(select(AssetGroup).where(AssetGroup.sid == live_sid + "-2100"))
    assert group.members_direct == 1
    assert db_session.scalar(select(func.count()).select_from(AssetGroupMember).where(AssetGroupMember.user_id == user.id)) == 1
    assert _snapshot(db_session, owned) == before
