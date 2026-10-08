"""Словари очистки из базы STools (спека §4): домены и хосты из AD, Активов и KSC, подсети Активов
и настроек, учётки AD по галочке."""
from __future__ import annotations

import datetime as dt
from ipaddress import IPv4Network
from pathlib import Path
from typing import Any

import pytest

from api.export_files import write_json_gz
from api.modules.ad.models import AdDomain, AdSnapshot
from api.modules.ad.services.snapshots import snapshot_path
from api.modules.assets.models import Asset, Network
from api.modules.ksc.models import KscHost, KscServer, KscSnapshot
from api.modules.toolbox.services.dictionaries import RulesError, build_ctx, parse_subnets
from api.modules.toolbox.services.scrub import get_settings_row
from tests.ad.synthetic import build_export

NOW = dt.datetime(2026, 10, 8, 10, 0, tzinfo=dt.UTC)


@pytest.fixture
def filled(db_session: Any) -> Any:
    db_session.add(AdDomain(sid="S-1-5-21-1000-2000-3000", dns_root="corp.test", netbios="CORP"))
    db_session.add(Asset(name="msk1", name_key="msk1", fqdn="msk1.corp.test", domain="corp.test"))
    db_session.add(Asset(name="ab", name_key="ab", fqdn="", domain=""))
    server = KscServer(name="ksc01")
    db_session.add(server)
    db_session.flush()
    old = KscSnapshot(server_id=server.id, collected_at=NOW - dt.timedelta(days=1), source="file")
    new = KscSnapshot(server_id=server.id, collected_at=NOW, source="file")
    db_session.add_all([old, new])
    db_session.flush()
    db_session.add(KscHost(snapshot_id=old.id, host_id="h0", name="gone-host", domain="old.test"))
    db_session.add(KscHost(snapshot_id=new.id, host_id="h1", name="srv-db01", domain="other.test"))
    db_session.add(Network(cidr="10.1.2.0/24"))
    db_session.commit()
    return db_session


def test_build_ctx_collects_domains_hosts_and_subnets(filled: Any, app_settings: Any) -> None:
    ctx = build_ctx(filled, get_settings_row(filled), users_from_ad=False, data_dir=app_settings.data_dir)
    assert {"corp.test", "corp", "other.test"} <= ctx.domains
    assert {"msk1", "msk1.corp.test", "srv-db01"} <= ctx.hosts
    # Короче 3 символов — слишком много ложных; хосты старого снапшота KSC — не в словаре.
    assert "ab" not in ctx.hosts and "gone-host" not in ctx.hosts and "old.test" not in ctx.domains
    assert ctx.users == frozenset()
    [(old, new)] = ctx.subnets
    assert old == IPv4Network("10.1.2.0/24")
    # Та же приватная зона и та же длина, но другая сеть: адреса подсети остаются одной подсетью.
    assert new.prefixlen == 24 and new.subnet_of(IPv4Network("10.0.0.0/8")) and new != old


def test_build_ctx_takes_settings_words_and_subnets(filled: Any, app_settings: Any) -> None:
    row = get_settings_row(filled)
    row.words = [{"word": "Acme", "alias": "Contoso"}]
    row.subnets = [{"cidr": "192.168.1.0/24", "to": "192.168.77.0/24"}]
    filled.commit()
    ctx = build_ctx(filled, row, users_from_ad=False, data_dir=app_settings.data_dir, extra_words={"Petrov": ""})
    assert ctx.words == {"Acme": "Contoso", "Petrov": ""}
    assert (IPv4Network("192.168.1.0/24"), IPv4Network("192.168.77.0/24")) in ctx.subnets


def test_build_ctx_users_from_ad_snapshot(filled: Any, app_settings: Any) -> None:
    domain = filled.query(AdDomain).one()
    snap = AdSnapshot(domain_id=domain.id, collected_at=NOW, source="file")
    filled.add(snap)
    filled.commit()
    export = build_export()
    export["objects"].append({"dn": "CN=jdoe,CN=Users,DC=corp,DC=test", "class": "user", "sam": "jdoe", "name": "jdoe"})
    path: Path = snapshot_path(app_settings.data_dir, snap.id)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json_gz(export, path)

    ctx = build_ctx(filled, get_settings_row(filled), users_from_ad=True, data_dir=app_settings.data_dir)
    assert "jdoe" in ctx.users and "admin1" in ctx.users
    # Компьютеры и группы — не учётки людей.
    assert "ws01$" not in ctx.users and "domain admins" not in ctx.users
    without = build_ctx(filled, get_settings_row(filled), users_from_ad=False, data_dir=app_settings.data_dir)
    assert without.users == frozenset()


def test_parse_subnets_rejects_pairs_of_different_length() -> None:
    assert parse_subnets([{"cidr": "10.1.2.0/24", "to": "10.9.9.0/24"}]) == [
        (IPv4Network("10.1.2.0/24"), IPv4Network("10.9.9.0/24")),
    ]
    with pytest.raises(RulesError):
        parse_subnets([{"cidr": "10.1.2.0/24", "to": "10.9.0.0/16"}])
    with pytest.raises(RulesError):
        parse_subnets([{"cidr": "not-a-net", "to": "10.9.9.0/24"}])
