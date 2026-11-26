"""Full backup of the migrated schema with synthetic module data."""

from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

OPS = Path(__file__).resolve().parents[3] / "ops"
sys.path.insert(0, str(OPS))
from stools_db import Postgres, backup, verified_backup
from stools_db_anonymize import run


@pytest.mark.skipif(
    os.environ.get("STOOLS_ANONYMIZE_DOCKER_TESTS") != "1",
    reason="Explicit opt-in to full Docker roundtrip",
)
def test_full_stools_schema_retains_ad_assets_and_ksc(migrated_database, tmp_path):
    # Only the disposable container made by tests/conftest.py may be used here.
    assert not os.environ.get("STOOLS_TEST_DATABASE_URL")
    url = migrated_database.url
    ids = subprocess.check_output(
        ["docker", "ps", "-q", "--filter", f"publish={url.port}"], text=True
    ).split()
    assert len(ids) == 1
    pg = Postgres(ids[0])
    assert pg.default_database() == url.database
    from api.db.models import AppSetting, AppUser
    from api.modules.ad.models import AdDomain, AdSnapshot
    from api.modules.assets.models import Asset, AssetUser, AssetUserGroup, AssetUserHost
    from api.modules.ksc.models import KscHost, KscPolicy, KscProfile, KscServer, KscSnapshot

    now = dt.datetime.now(dt.UTC)
    with Session(migrated_database) as db:
        domain = AdDomain(sid="S-1-5-21-123", dns_root="corp.example", dn="DC=corp,DC=example")
        asset = Asset(name="pc.corp.example", ip="10.10.1.7")
        user = AssetUser(
            sid="S-1-5-21-123-1001",
            sam="alice",
            name_key="corp.example\\alice",
            upn="alice@corp.example",
            domain="corp.example",
            enabled=True,
        )
        server = KscServer(name="ksc.corp.example")
        db.add_all(
            [domain, asset, user, server, AppUser(login="alice", password_hash="synthetic-hash")]
        )
        db.flush()
        ad = AdSnapshot(
            domain_id=domain.id, collected_at=now, source="file", summary_json="", score_json=""
        )
        ksc = KscSnapshot(server_id=server.id, collected_at=now, source="file")
        db.add_all([ad, ksc])
        db.flush()
        db.add_all(
            [
                AssetUserHost(
                    user_id=user.id,
                    asset_id=asset.id,
                    source="ksc",
                    kind="session",
                    active=True,
                    seen_at=now,
                ),
                AssetUserGroup(
                    user_id=user.id,
                    group_sid="S-1-5-21-123-2001",
                    group_name="corp.example admins",
                    direct=True,
                ),
                KscHost(
                    snapshot_id=ksc.id,
                    host_id="1",
                    name="pc.corp.example",
                    ip="10.10.1.7",
                    product_version="10.10.1.2",
                ),
                KscPolicy(
                    snapshot_id=ksc.id,
                    policy_id=11,
                    name="corp.example policy",
                    active=True,
                    accept_parent=True,
                    has_contents=True,
                ),
                KscProfile(
                    snapshot_id=ksc.id,
                    policy_id=11,
                    name="corp.example profile",
                    enabled=True,
                    condition_json='{"host":"pc.corp.example","port":443,"action":"allow","enabled":true}',
                ),
                AppSetting(key="siem_th", value_json='{"nightly_enabled":true}'),
            ]
        )
        db.merge(AppSetting(key="siem_finding_key", value_json='{"salt":"0123456789abcdef"}'))
        db.commit()
    original = tmp_path / "original"
    backup(pg, original, str(url.database))
    config = tmp_path / "rules.json"
    config.write_text(
        json.dumps(
            {
                "format": "stools-db-anonymize/1",
                "replacements": [
                    {"from": "corp.example", "to": "lab.example"},
                    {"from": "DC=corp,DC=example", "to": "DC=lab,DC=example"},
                    {"from": "alice", "to": "person-001"},
                ],
                "networks": [{"from": "10.10.0.0/16", "to": "10.200.0.0/16"}],
            }
        )
    )
    output = tmp_path / "clean"
    report = run(original, config, output)
    assert report["restore_verified"]
    assert report["table_count"] > 100
    pg.run("createdb", "checked")
    with verified_backup(pg, output) as (_, stream):
        pg.run(
            "pg_restore",
            "--exit-on-error",
            "--no-owner",
            "--no-privileges",
            "--dbname=checked",
            source=stream,
        )
    data = json.loads(
        pg.sql(
            "SELECT json_build_object('sam',u.sam,'name',a.name,'ip',a.ip,'enabled',u.enabled,'active',h.active) FROM asset_user_host h JOIN asset a ON a.id=h.asset_id JOIN asset_user u ON u.id=h.user_id LIMIT 1",
            "checked",
        )
    )
    assert data == {
        "sam": "person-001",
        "name": "pc.lab.example",
        "ip": "10.200.1.7",
        "enabled": True,
        "active": True,
    }
    assert pg.sql("SELECT dns_root FROM ad_domain LIMIT 1", "checked") == "lab.example"
    assert pg.sql("SELECT summary_json FROM ad_snapshot LIMIT 1", "checked") == ""
    assert (
        pg.sql(
            "SELECT active AND accept_parent AND has_contents FROM ksc_policy LIMIT 1", "checked"
        )
        == "t"
    )
    assert pg.sql("SELECT enabled FROM ksc_profile LIMIT 1", "checked") == "t"
    condition = json.loads(pg.sql("SELECT condition_json FROM ksc_profile LIMIT 1", "checked"))
    assert condition == {"host": "pc.lab.example", "port": 443, "action": "allow", "enabled": True}
    assert pg.sql("SELECT product_version FROM ksc_host LIMIT 1", "checked") == "10.10.1.2"
    assert (
        pg.sql(
            "SELECT value_json::json->>'salt' FROM app_setting WHERE key='siem_finding_key' LIMIT 1",
            "checked",
        )
        == "0123456789abcdef"
    )
    assert (
        pg.sql(
            "SELECT count(*) FROM app_user WHERE is_active OR password_hash IS NOT NULL", "checked"
        )
        == "0"
    )
    print(f"Full schema roundtrip: {report['table_count']} tables, {report['rows']} rows")
