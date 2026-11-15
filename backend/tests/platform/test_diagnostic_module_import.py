"""Production-like diagnostic import into ordinary module stores (PostgreSQL)."""
import datetime as dt
import importlib
import json

import pytest
from sqlalchemy import func, select

from api.modules.ad.models import AdDomain, AdSnapshot
from api.modules.assets.models import (
    Asset,
    AssetGroup,
    AssetGroupMember,
    AssetObservation,
    AssetUser,
    AssetUserGroup,
    AssetUserObservation,
)
from api.modules.ksc.models import KscHost, KscPolicy, KscProfile, KscServer, KscSnapshot
from api.platform.diagnostics.schema import BundleError

NOW = dt.datetime(2026, 10, 20, 12, tzinfo=dt.UTC)
SID = "S-1-5-21-910-920-930"
DOMAIN = "directory.invalid"
DN = "DC=directory,DC=invalid"


def importer():
    return importlib.import_module("api.platform.diagnostics.module_import")


@pytest.fixture
def bundle():
    user_dn = f"CN=account,OU=People,{DN}"
    ad = {
        "format": "stools-ad/1", "collected_at": NOW.isoformat(),
        "domain": {"sid": SID, "dns_root": DOMAIN, "dn": DN, "netbios": "DIRECTORY", "min_pwd_length": 14},
        "objects": [{"dn": user_dn, "class": "user", "sid": f"{SID}-1100", "sam": "account", "uac": 512}],
    }
    ad["objects"] += [
        {"dn": f"CN=group-{i},{DN}", "class": "group", "sid": f"{SID}-{2000+i}", "sam": f"group-{i}", "member": [user_dn]}
        for i in range(67)
    ]
    policy = {"KLPOL_ID": 7, "KLPOL_DN": "Protection", "KLPOL_PRODUCT": "KES", "KLPOL_VERSION": "12.0.0.0",
              "KLPOL_GROUP_ID": 0, "KLPOL_ACTIVE": True, "KLPOL_ACCEPT_PARENT": True}
    ksc = {
        "format": "stools-ksc/1", "server": {"name": "security.invalid", "collected_at": NOW.isoformat()},
        "groups": [{"id": 0, "parentId": -1, "name": "Managed devices"}],
        "hosts": [{"KLHST_WKS_HOSTNAME": "host-token", "KLHST_WKS_DN": "computer", "KLHST_WKS_GROUPID": 0,
                   "KLHST_WKS_FQDN": f"computer.{DOMAIN}", "KLHST_WKS_DNSDOMAIN": DOMAIN, "KLHST_WKS_STATUS": 20}],
        "policies": [policy], "effective_policies": {"0": [policy]},
        "policy_contents": {"7": {"product": "KES", "version": "12.0.0.0", "sections": {
            "Settings": {"enabled": {"KLPRSS_Val": True, "KLPRSS_Mnd": True}}
        }, "errors": []}},
        "host_tags": {"host-token": ["tag-one"]},
        "policy_profiles": {"7": {"profiles": [{"name": "Profile", "attrs": {"KLSSPOL_PRF_ENABLED": True},
                                                    "sections": {}, "errors": []}], "priorities": ["Profile"], "errors": []}},
    }
    return {
        "format": "stools-diagnostic/2", "created_at": NOW.isoformat(),
        "root": {"kind": "user", "id": 601, "title": "account"},
        "tables": {
            "ad_domain": [{"id": 401, "sid": SID, "dns_root": DOMAIN, "dn": DN, "netbios": "DIRECTORY"}],
            "ad_snapshot": [{"id": 402, "domain_id": 401, "collected_at": NOW.isoformat(), "source": "file", "objects": 68}],
            "ksc_server": [{"id": 501, "name": "security.invalid"}],
            "ksc_snapshot": [{"id": 502, "server_id": 501, "collected_at": NOW.isoformat(), "source": "file", "hosts": 1}],
            "asset": [{"id": 701, "name": "computer", "name_key": "computer", "domain": DOMAIN}],
            "asset_user": [{"id": 601, "sid": f"{SID}-1100", "sam": "account", "name_key": f"{DOMAIN}\\account", "domain": DOMAIN}],
            "asset_user_observation": [{"id": 611, "user_id": 601, "source": "ad", "source_key": f"{SID}-1100",
                                        "seen_at": NOW.isoformat(), "data": {"domain_id": 401}}],
            "asset_observation": [{"id": 711, "asset_id": 701, "source": "ksc", "source_key": "501:host-token",
                                   "seen_at": NOW.isoformat(), "extra": {}}],
            "asset_user_host": [{"id": 721, "user_id": 601, "asset_id": 701, "source": "ksc", "kind": "session", "active": True,
                                 "seen_at": NOW.isoformat()}],
            "asset_user_group": [{"id": 800+i, "user_id": 601, "group_sid": f"{SID}-{2000+i}", "group_name": f"group-{i}",
                                  "direct": True, "source": "ad"} for i in range(101)],
            "asset_group": [{"id": 901, "group_key": "wire-key", "sid": f"{SID}-2000", "name": "group-0", "domain": DOMAIN,
                             "local": False, "sources": ["ad"], "in_ad": True}],
            "asset_group_member": [{"id": 911, "group_id": 901, "member_kind": "user", "user_id": 601,
                                    "member_sid": f"{SID}-1100", "member_name": "account", "source": "ad"}],
        },
        "ad_exports": [{"snapshot_id": 402, "export": ad}],
        "ksc_exports": [{"snapshot_id": 502, "export": ksc}],
        "report": {"limitations": ["Selected diagnostic slice"]},
    }


def test_import_is_available():
    assert importlib.util.find_spec("api.platform.diagnostics.module_import") is not None


def test_normal_modules_read_independent_memberships_and_native_policy(bundle, db_session, app_settings, monkeypatch):
    from api.modules.ad.routers.snapshots import get_account_groups
    from api.modules.ad.routers.snapshots import get_snapshot as get_ad_snapshot
    from api.modules.assets.routers.users import get_user
    from api.modules.ksc.core.export import load_export_path
    from api.modules.ksc.routers.policies import get_policies
    from api.modules.ksc.services.snapshots import snapshot_path

    def forbidden_sync(*args, **kwargs):
        pytest.fail("diagnostic import started Assets synchronization")

    monkeypatch.setattr("api.modules.assets.services.sync.request_sync", forbidden_sync)
    existing = AssetUser(sid="S-1-5-21-101-102-103-1100", sam="existing", note="keep")
    db_session.add_all([existing, AdDomain(sid="S-1-5-21-101-102-103", dns_root="existing.invalid"), KscServer(name="existing")])
    db_session.commit()
    old_id = existing.id
    result = importer().import_bundle(db_session, app_settings.data_dir, bundle)
    user_id = result["root"]["id"]
    user = get_user(user_id, db=db_session)
    domain_id = user["observations"][0]["data"]["domain_id"]
    snapshot = db_session.scalar(select(AdSnapshot).where(AdSnapshot.domain_id == domain_id))
    assert domain_id != 401 and user_id != 601
    assert len(user["groups"]) == 101
    current = get_account_groups(snapshot.id, user["sid"], db=db_session, settings=app_settings)
    assert len(current["groups"]) == 67
    assert get_ad_snapshot(snapshot.id, db=db_session).objects == 68
    assert snapshot.analyzer_version
    assert user["groups"][0]["group_id"] is not None
    group = db_session.get(AssetGroup, user["groups"][0]["group_id"])
    assert group.members_direct == 1
    assert db_session.get(AssetUser, old_id).note == "keep"
    server = db_session.scalar(select(KscServer).where(KscServer.name == "security.invalid"))
    ksnap = db_session.scalar(select(KscSnapshot).where(KscSnapshot.server_id == server.id))
    host = db_session.scalar(select(KscHost).where(KscHost.snapshot_id == ksnap.id))
    observation = db_session.scalar(select(AssetObservation).where(AssetObservation.asset_id == user["devices"][0]["asset_id"]))
    assert observation.source_key == f"{server.id}:{host.host_id}"
    assert get_policies(ksnap.id, db=db_session, settings=app_settings).groups
    policy = db_session.scalar(select(KscPolicy).where(KscPolicy.snapshot_id == ksnap.id))
    assert policy.product == "KES" and policy.settings_total > 0 and policy.has_contents
    assert db_session.scalar(select(KscProfile).where(KscProfile.snapshot_id == ksnap.id)).name == "Profile"
    native = load_export_path(snapshot_path(app_settings.data_dir, ksnap.id))
    assert native.policy_contents["7"]["sections"]["Settings"]["enabled"]["KLPRSS_Mnd"] is True
    assert result["mode"] == "modules" and result["links"]
    assert importer().list_imports(db_session)[0]["id"] == result["id"]


def test_duplicate_import_is_idempotent_with_canonical_hash(bundle, db_session, app_settings):
    first = importer().import_bundle(db_session, app_settings.data_dir, bundle)
    reordered = json.loads(json.dumps(bundle, sort_keys=True))
    second = importer().import_bundle(db_session, app_settings.data_dir, reordered)
    assert second["id"] == first["id"] and second["root"] == first["root"]
    assert db_session.scalar(select(func.count()).select_from(AssetUser)) == 1
    assert len(list(app_settings.data_dir.glob("*/*.json.gz"))) == 2


def test_failed_native_store_rolls_back_database_files_and_provenance(bundle, db_session, app_settings, monkeypatch):
    from api.modules.ksc.services import snapshots
    db_session.add(Asset(name="existing", note="keep"))
    db_session.commit()

    def reject(*args, **kwargs):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(snapshots, "_store", reject)
    with pytest.raises(BundleError):
        importer().import_bundle(db_session, app_settings.data_dir, bundle)
    assert db_session.scalar(select(func.count()).select_from(AdSnapshot)) == 0
    assert db_session.scalar(select(func.count()).select_from(AdDomain)) == 0
    assert db_session.scalar(select(func.count()).select_from(KscServer)) == 0
    assert db_session.scalar(select(func.count()).select_from(AssetUser)) == 0
    assert db_session.scalar(select(Asset.note)) == "keep"
    assert importer().list_imports(db_session) == []
    assert list(app_settings.data_dir.glob("*/*.json.gz")) == []


def test_existing_identity_conflict_does_not_modify_existing_rows(bundle, db_session, app_settings):
    db_session.add(AdDomain(sid=SID, dns_root="keep.invalid", dn="keep"))
    db_session.commit()
    with pytest.raises(BundleError):
        importer().import_bundle(db_session, app_settings.data_dir, bundle)
    assert db_session.scalar(select(AdDomain.dns_root)) == "keep.invalid"
    assert db_session.scalar(select(func.count()).select_from(AdSnapshot)) == 0
    assert importer().list_imports(db_session) == []


def test_rejects_embedded_reference_to_existing_unrelated_domain(bundle, db_session, app_settings):
    domain = AdDomain(sid="S-1-5-21-101-102-103", dns_root="existing.invalid")
    db_session.add(domain)
    db_session.commit()
    bundle["tables"]["asset_user_observation"][0]["data"]["domain_id"] = domain.id
    with pytest.raises(BundleError):
        importer().import_bundle(db_session, app_settings.data_dir, bundle)
    assert importer().list_imports(db_session) == []
    assert db_session.scalar(select(func.count()).select_from(AssetUser)) == 0


def test_pending_changes_are_not_committed_by_import(bundle, db_session, app_settings):
    pending = Asset(name="pending")
    db_session.add(pending)
    with pytest.raises(BundleError):
        importer().import_bundle(db_session, app_settings.data_dir, bundle)
    assert pending in db_session.new


def test_denied_file_write_rolls_back_without_removing_existing_file(bundle, db_session, app_settings, monkeypatch):
    from pathlib import Path
    original = Path.open
    marker = app_settings.data_dir / "ad" / "existing.json.gz"
    marker.parent.mkdir(parents=True)
    marker.write_bytes(b"existing")

    def deny(self, mode="r", *args, **kwargs):
        if "x" in mode and self.suffix == ".gz":
            raise PermissionError("synthetic denied write")
        return original(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny)
    with pytest.raises(BundleError):
        importer().import_bundle(db_session, app_settings.data_dir, bundle)
    assert marker.read_bytes() == b"existing"
    assert db_session.scalar(select(func.count()).select_from(AdSnapshot)) == 0
    assert importer().list_imports(db_session) == []


def test_provenance_detects_removed_records_and_does_not_silently_reimport(bundle, db_session, app_settings):
    from sqlalchemy import delete
    result = importer().import_bundle(db_session, app_settings.data_dir, bundle)
    assert importer().get_import(db_session, result["id"])["status"] == "ready"
    assert importer().get_import(db_session, "unknown") is None
    db_session.execute(delete(AssetUserGroup).where(AssetUserGroup.user_id == result["root"]["id"]))
    db_session.commit()
    metadata = importer().get_import(db_session, result["id"])
    assert metadata["status"] == "incomplete" and metadata["missing_records"] == 101
    assert metadata["links"] == []
    with pytest.raises(BundleError, match="incomplete"):
        importer().import_bundle(db_session, app_settings.data_dir, bundle)
    assert db_session.scalar(select(func.count()).select_from(AdSnapshot)) == 1


def test_package_deletion_refuses_without_erasing_normal_module_data(bundle, db_session, app_settings):
    result = importer().import_bundle(db_session, app_settings.data_dir, bundle)
    with pytest.raises(BundleError, match="diagnostic_module_delete_unavailable"):
        importer().delete_import(db_session, app_settings.data_dir, result["id"])
    assert importer().get_import(db_session, result["id"])["status"] == "ready"
    assert db_session.get(AssetUser, result["root"]["id"]) is not None
    assert len(list(app_settings.data_dir.glob("*/*.json.gz"))) == 2


def test_missing_native_file_marks_package_incomplete(bundle, db_session, app_settings):
    result = importer().import_bundle(db_session, app_settings.data_dir, bundle)
    next(app_settings.data_dir.glob("ad/*.json.gz")).unlink()
    metadata = importer().get_import(db_session, result["id"])
    assert metadata["status"] == "incomplete" and metadata["missing_files"] == 1
    assert metadata["can_delete"] is False and metadata["links"] == []
    with pytest.raises(BundleError, match="incomplete"):
        importer().import_bundle(db_session, app_settings.data_dir, bundle)


def test_modified_cached_membership_is_reported_without_overwriting_it(bundle, db_session, app_settings):
    result = importer().import_bundle(db_session, app_settings.data_dir, bundle)
    membership = db_session.scalar(select(AssetUserGroup).limit(1))
    membership.direct = False
    db_session.commit()
    metadata = importer().get_import(db_session, result["id"])
    assert metadata["status"] == "modified" and metadata["changed_records"] == 1
    with pytest.raises(BundleError):
        importer().import_bundle(db_session, app_settings.data_dir, bundle)
    assert db_session.get(AssetUserGroup, membership.id).direct is False


@pytest.mark.parametrize(("model", "field", "value"), [
    (AssetUser, "sid", f"{SID}-9999"),
    (AssetUser, "name_key", f"{DOMAIN}\\changed-account"),
    (AssetUser, "enabled", False),
    (Asset, "fqdn", f"changed-host.{DOMAIN}"),
    (Asset, "ip", "192.0.2.99"),
    (AssetGroup, "name", "changed-group"),
    (AssetGroup, "in_ad", False),
    (AdDomain, "dns_root", "changed.invalid"),
    (KscServer, "name", "changed-security.invalid"),
    (AdSnapshot, "collected_at", NOW + dt.timedelta(seconds=1)),
    (KscSnapshot, "source", "online"),
])
def test_changed_cached_content_marks_import_modified_without_overwrite(bundle, db_session, app_settings, model, field, value):
    result = importer().import_bundle(db_session, app_settings.data_dir, bundle)
    row = db_session.scalar(select(model).limit(1))
    row_id = row.id
    setattr(row, field, value)
    db_session.commit()
    metadata = importer().get_import(db_session, result["id"], data_dir=app_settings.data_dir)
    assert metadata["status"] == "modified" and metadata["changed_records"] == 1
    assert metadata["links"] == []
    with pytest.raises(BundleError, match="changed or removed"):
        importer().import_bundle(db_session, app_settings.data_dir, bundle)
    assert getattr(db_session.get(model, row_id), field) == value
    assert db_session.scalar(select(func.count()).select_from(model)) == 1


def test_concurrent_duplicate_import_writes_one_dataset(bundle, db_session, app_settings):
    from concurrent.futures import ThreadPoolExecutor

    from sqlalchemy.orm import Session
    engine = db_session.get_bind()

    def run():
        with Session(engine) as session:
            return importer().import_bundle(session, app_settings.data_dir, bundle)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run(), range(2)))
    assert results[0]["id"] == results[1]["id"]
    assert db_session.scalar(select(func.count()).select_from(AdSnapshot)) == 1
    assert db_session.scalar(select(func.count()).select_from(KscSnapshot)) == 1
    assert len(list(app_settings.data_dir.glob("*/*.json.gz"))) == 2


def test_local_identities_and_embedded_observation_references_are_remapped(bundle, db_session, app_settings):
    bundle["tables"]["asset_user"].append({"id": 602, "sid": "", "sam": "local-account", "local": True,
                                         "name_key": "local:701\\local-account"})
    bundle["tables"]["asset_user_observation"].append({"id": 612, "user_id": 602, "source": "ksc",
        "source_key": "501:host-token\\local-account", "seen_at": NOW.isoformat(), "data": {"server_id": 501}})
    bundle["tables"]["asset_group"].append({"id": 902, "group_key": "wire-local-key", "sid": "S-1-5-32-544",
        "name": "Administrators", "local": True, "host_asset_id": 701, "sources": ["vm"]})
    bundle["tables"]["asset_group_member"].append({"id": 912, "group_id": 902, "member_kind": "group",
        "member_group_id": 901, "member_sid": f"{SID}-2000", "member_name": "group-0", "source": "vm"})
    importer().import_bundle(db_session, app_settings.data_dir, bundle)
    host = db_session.scalar(select(Asset).where(Asset.name == "computer"))
    local = db_session.scalar(select(AssetUser).where(AssetUser.local.is_(True)))
    server = db_session.scalar(select(KscServer))
    observation = db_session.scalar(select(AssetUserObservation).where(AssetUserObservation.user_id == local.id))
    assert local.name_key == f"local:{host.id}\\local-account"
    assert observation.source_key == f"{server.id}:host-token\\local-account"
    assert observation.data["server_id"] == server.id
    group = db_session.scalar(select(AssetGroup).where(AssetGroup.local.is_(True)))
    assert group.host_asset_id == host.id and group.group_key == f"l:{host.id}:S-1-5-32-544"
    member = db_session.scalar(select(AssetGroupMember).where(AssetGroupMember.group_id == group.id))
    assert db_session.get(AssetGroup, member.member_group_id).sid == f"{SID}-2000"


def test_import_does_not_write_connections_jobs_or_global_settings(bundle, db_session, app_settings):
    from api.db.models import AppSetting
    from api.modules.ad.models import AdConnection, AdJob
    from api.modules.assets.models import AssetJob, AssetSettings
    from api.modules.ksc.models import KscConnection, KscJob
    protected = [AppSetting, AdConnection, AdJob, KscConnection, KscJob, AssetJob, AssetSettings]
    before = {model: list(db_session.execute(select(model.__table__)).mappings()) for model in protected}
    importer().import_bundle(db_session, app_settings.data_dir, bundle)
    after = {model: list(db_session.execute(select(model.__table__)).mappings()) for model in protected}
    assert after == before


def test_metadata_title_comes_from_imported_root_and_routes_use_parent_ids(bundle, db_session, app_settings):
    bundle["root"].pop("title")
    result = importer().import_bundle(db_session, app_settings.data_dir, bundle)
    assert result["root"]["title"] == "account"
    assert result["summary"] == bundle["report"]
    domain_id = db_session.scalar(select(AdDomain.id))
    server_id = db_session.scalar(select(KscServer.id))
    assert {link["href"] for link in result["links"]} == {
        f"/assets/users?user={result['root']['id']}", f"/ad/domains/{domain_id}", f"/ksc/servers/{server_id}"}
    assert result["counts"]["ksc_policy"] == 1


def test_removed_derived_policy_rows_are_reported(bundle, db_session, app_settings):
    from sqlalchemy import delete
    result = importer().import_bundle(db_session, app_settings.data_dir, bundle)
    db_session.execute(delete(KscPolicy))
    db_session.commit()
    metadata = importer().get_import(db_session, result["id"])
    assert metadata["status"] == "incomplete" and metadata["missing_records"] >= 1


def test_final_commit_failure_rolls_back_both_native_modules(bundle, db_session, app_settings, monkeypatch):
    def reject():
        raise RuntimeError("synthetic commit failure")

    monkeypatch.setattr(db_session, "commit", reject)
    with pytest.raises(BundleError):
        importer().import_bundle(db_session, app_settings.data_dir, bundle)
    assert db_session.scalar(select(func.count()).select_from(AdSnapshot)) == 0
    assert db_session.scalar(select(func.count()).select_from(KscSnapshot)) == 0
    assert db_session.scalar(select(func.count()).select_from(AssetUser)) == 0
    assert list(app_settings.data_dir.glob("*/*.json.gz")) == []
    assert importer().list_imports(db_session) == []


def test_normal_reanalysis_preserves_cached_membership_and_package_identity(bundle, db_session, app_settings, monkeypatch):
    from api.modules.ad.core.config import AdConfig
    from api.modules.ad.services import snapshots as ad_snapshots
    from api.modules.ksc.core.config import KscConfig
    from api.modules.ksc.services import snapshots as ksc_snapshots

    def forbidden_sync(*args, **kwargs):
        pytest.fail("reanalyzing diagnostic snapshots started Assets synchronization")

    monkeypatch.setattr("api.modules.assets.services.sync.request_sync", forbidden_sync)
    result = importer().import_bundle(db_session, app_settings.data_dir, bundle)
    ad = db_session.scalar(select(AdSnapshot))
    ksc = db_session.scalar(select(KscSnapshot))
    ad_snapshots.reanalyze(db_session, None, ad, AdConfig(), app_settings.data_dir)
    ksc_snapshots.reanalyze(db_session, None, ksc, KscConfig(), app_settings.data_dir)
    assert db_session.scalar(select(func.count()).select_from(AssetUserGroup)) == 101
    assert importer().get_import(db_session, result["id"], data_dir=app_settings.data_dir)["status"] == "ready"
    assert importer().import_bundle(db_session, app_settings.data_dir, bundle)["id"] == result["id"]
