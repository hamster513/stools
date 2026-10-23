"""Локальные группы хостов из VM (план «Группы как активы», задача 4): сопоставление хостов (с CVE и без),
участники доменные, локальные и встроенные, контроллер домена, пропавшие по снимку групп, Linux по имени."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from api.jobs import run_job, start_job
from api.modules.assets.models import (
    Asset,
    AssetGroup,
    AssetGroupMember,
    AssetJob,
    AssetObservation,
    AssetSettings,
    AssetUser,
    AssetUserHost,
)
from api.modules.assets.services.sync import run_sync
from api.modules.vm.models import VmGroupImport, VmHostGroup
from tests.assets.synthetic import load_vm
from tests.assets.test_users_sync import account, ad_raw, computer, csid, dn, group, load_ad, sync

MACHINE = "S-1-5-21-4444444444-5555555555-6666666666"
FOREIGN = "S-1-5-21-9999999999-8888888888-7777777777-1105"
SRV01 = ("srv01.corp.local", "srv01", "10.0.0.11")
SRV02 = ("srv02.corp.local", "srv02", "10.0.0.12")
SRV03 = ("srv03.corp.local", "srv03", "10.0.0.13")
DC01 = ("dc01.corp.local", "dc01", "10.0.0.2")
LIN01 = ("lin01.corp.local", "lin01", "10.0.0.21")
ADMINS = "S-1-5-32-544"


def msid(rid: int) -> str:
    return f"{MACHINE}-{rid}"


def win(host: tuple[str, str, str], name: str, sid: str, member: str = "", domain: str = "", member_sid: str = "",
        kind: str = "", local: bool | None = None, system: bool | None = None, description: str = "") -> VmHostGroup:
    fqdn, hostname, ip = host
    return VmHostGroup(os_family="windows", fqdn=fqdn, hostname=hostname, ip=ip, group_name=name, group_sid=sid, group_gid="",
                       group_description=description, member_name=member, member_domain=domain, member_sid=member_sid,
                       member_type=kind, member_local=local, member_system=system)


def lin(host: tuple[str, str, str], name: str, gid: str, member: str = "") -> VmHostGroup:
    fqdn, hostname, ip = host
    return VmHostGroup(os_family="linux", fqdn=fqdn, hostname=hostname, ip=ip, group_name=name, group_sid="", group_gid=gid,
                       group_description="", member_name=member, member_domain="", member_sid="",
                       member_type="account" if member else "", member_local=True if member else None, member_system=None)


def srv01_admins(*, without: tuple[str, ...] = ()) -> list[VmHostGroup]:
    """administrators srv01: доменная desktop admins (есть в AD), локальная учётка pcadmin, встроенные Authenticated
    Users и NT SERVICE, локальная группа helpers, Administrator (RID 500, нет пользователя), доменные группы,
    которых нет в AD: remote helpers (CORP) и группа чужого леса (домен не в карте NetBIOS)."""
    rows = [
        win(SRV01, "administrators", ADMINS, "desktop admins", "corp", csid(1302), "group", False, False, "администраторы"),
        win(SRV01, "administrators", ADMINS, "pcadmin", "", msid(1001), "account", True, False, "администраторы"),
        win(SRV01, "administrators", ADMINS, "authenticated users", "nt authority", "S-1-5-11", "group", True, True, "администраторы"),
        win(SRV01, "administrators", ADMINS, "trustedinstaller", "nt service", "S-1-5-80-1-2-3-4-5", "group", True, False, "администраторы"),
        win(SRV01, "administrators", ADMINS, "helpers", "", msid(1010), "group", True, False, "администраторы"),
        win(SRV01, "administrators", ADMINS, "administrator", "", msid(500), "account", True, False, "администраторы"),
        win(SRV01, "administrators", ADMINS, "remote helpers", "corp", csid(1400), "group", False, False, "администраторы"),
        win(SRV01, "administrators", ADMINS, "foreign admins", "other", FOREIGN, "group", False, False, "администраторы"),
        win(SRV01, "helpers", msid(1010)),
    ]
    return [r for r in rows if r.member_name not in without and r.group_name not in without]


def snapshot(*, without: tuple[str, ...] = ()) -> list[VmHostGroup]:
    return [
        *srv01_admins(without=without),
        *[r for r in [win(SRV02, "administrators", ADMINS, "desktop admins", "corp", csid(1302), "group", False, False)] if "srv02" not in without],
        win(SRV03, "administrators", ADMINS, "desktop admins", "corp", csid(1302), "group", False, False),
        win(DC01, "administrators", ADMINS, "domain admins", "corp", csid(512), "group", False, False),
        lin(LIN01, "wheel", "10", "user01"),
        lin(LIN01, "daemon", "2"),
    ]


def put_groups(db: Session, rows: list[VmHostGroup], when: dt.datetime, *, windows_ok: bool = True, linux_ok: bool = True) -> None:
    """Как `importer.import_groups`: семейство, чей запрос прошёл, заменяется; прочее остаётся."""
    for family, ok in (("windows", windows_ok), ("linux", linux_ok)):
        if ok:
            db.execute(delete(VmHostGroup).where(VmHostGroup.os_family == family))
            db.add_all([r for r in rows if r.os_family == family])
    db.add(VmGroupImport(finished_at=when, hosts=0, rows=0, windows_ok=windows_ok, linux_ok=linux_ok))
    db.commit()


def corp_ad(*, without: tuple[str, ...] = (), extra: tuple[dict[str, Any], ...] = ()) -> list[dict[str, Any]]:
    objects = [
        account("user01", csid(1101)),
        computer("SRV01", 1202, "Windows Server 2022"),
        computer("SRV02", 1203, "Windows Server 2022"),
        {**computer("DC01", 1000, "Windows Server 2022"), "uac": 0x2000},
        group("desktop admins", csid(1302), [dn("user01")]),
        group("Domain Admins", csid(512), []),
        *extra,
    ]
    return [o for o in objects if o.get("sam") not in without]


@pytest.fixture
def now() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(microsecond=0)


@pytest.fixture
def loaded(db_session: Session, app_settings: Any, now: dt.datetime) -> Session:
    """AD: SRV01, SRV02, контроллер DC01; VM (хосты с CVE): srv01 и lin01; srv02 — без CVE; srv03 — нигде."""
    db_session.add(AssetSettings(data={"sync_after_import": False}))
    db_session.commit()
    load_ad(db_session, Path(app_settings.data_dir), ad_raw(corp_ad(), now - dt.timedelta(hours=3)))
    load_vm(db_session, [("srv01.corp.local", "10.0.0.11", "Windows Server 2022"), ("lin01.corp.local", "10.0.0.21", "Astra Linux")],
            now - dt.timedelta(hours=3))
    put_groups(db_session, snapshot(), now - dt.timedelta(hours=2))
    return db_session


def asset_id(db: Session, name: str) -> int:
    return int(db.execute(select(Asset.id).where(Asset.name_key == name, Asset.merged_into.is_(None))).scalar_one())


def local_group(db: Session, host: str, name: str) -> AssetGroup:
    return db.execute(select(AssetGroup).where(AssetGroup.host_asset_id == asset_id(db, host), AssetGroup.name == name)).scalar_one()


def domain_group(db: Session, sid: str) -> AssetGroup:
    return db.execute(select(AssetGroup).where(AssetGroup.local.is_(False), AssetGroup.sid == sid)).scalar_one()


def members(db: Session, group_id: int) -> dict[str, AssetGroupMember]:
    return {m.member_name: m for m in db.execute(select(AssetGroupMember).where(AssetGroupMember.group_id == group_id)).scalars()}


def add_local_user(db: Session, host: str, sam: str, now: dt.datetime) -> int:
    """Локальная учётка этапа пользователей (её заводит KSC); связь с хостом держит её от удаления."""
    host_id = asset_id(db, host)
    user = AssetUser(name_key=f"local:{host_id}\\{sam}", sam=sam, local=True)
    db.add(user)
    db.flush()
    db.add(AssetUserHost(user_id=user.id, asset_id=host_id, source="ksc", kind="session", active=False, seen_at=now))
    db.commit()
    return user.id


def snapshot_rows(db: Session) -> dict[tuple[int, str, str], int]:
    return {(m.group_id, m.member_sid, m.member_name): m.id for m in db.execute(select(AssetGroupMember)).scalars()}


def test_windows_local_groups(loaded: Session, now: dt.datetime) -> None:
    got = sync(loaded)
    assert "groups_failed" not in got and got["vm_hosts_unmatched"] == 1
    srv01 = asset_id(loaded, "srv01")
    adm = local_group(loaded, "srv01", "administrators")
    assert (adm.local, adm.sid, adm.domain, adm.sources, adm.in_ad, adm.description, adm.gone_at, adm.group_key) == (
        True, ADMINS, "", ["vm"], False, "администраторы", None, f"l:{srv01}:{ADMINS}")
    assert adm.last_seen == now - dt.timedelta(hours=2) and adm.first_seen == adm.last_seen
    got_m = members(loaded, adm.id)
    assert set(got_m) == {"desktop admins", "pcadmin", "authenticated users", "trustedinstaller", "helpers", "administrator",
                          "remote helpers", "foreign admins"}
    assert all(m.source == "vm" and m.primary is False for m in got_m.values())
    da = domain_group(loaded, csid(1302))
    assert (got_m["desktop admins"].member_kind, got_m["desktop admins"].member_group_id, got_m["desktop admins"].member_domain) == (
        "group", da.id, "corp.local")
    assert da.sources == ["ad", "vm"] and da.in_ad is True
    # Состав AD доменной группы строками VM не тронут.
    assert {m.member_name: m.source for m in members(loaded, da.id).values()} == {"user01": "ad"}
    assert (got_m["pcadmin"].member_kind, got_m["pcadmin"].user_id, got_m["pcadmin"].member_sid) == ("user", None, msid(1001))
    assert (got_m["authenticated users"].member_kind, got_m["authenticated users"].member_sid) == ("well_known", "S-1-5-11")
    assert (got_m["trustedinstaller"].member_kind, got_m["trustedinstaller"].member_domain) == ("well_known", "nt service")
    helpers = local_group(loaded, "srv01", "helpers")
    assert (helpers.sid, members(loaded, helpers.id)) == (msid(1010), {})
    assert (got_m["helpers"].member_kind, got_m["helpers"].member_group_id) == ("group", helpers.id)
    assert (got_m["administrator"].member_kind, got_m["administrator"].user_id, got_m["administrator"].member_sid) == ("user", None, msid(500))
    rh = domain_group(loaded, csid(1400))
    assert (rh.in_ad, rh.sources, rh.domain, rh.name, rh.group_key) == (False, ["vm"], "corp.local", "remote helpers", f"d:corp.local:{csid(1400)}")
    assert got_m["remote helpers"].member_group_id == rh.id
    fa = domain_group(loaded, FOREIGN)
    assert (fa.in_ad, fa.domain) == (False, "other")
    assert (got_m["foreign admins"].member_group_id, got_m["foreign admins"].member_domain) == (fa.id, "other")
    # Локальная учётка появилась у пользователей — участник связан.
    pcadmin = add_local_user(loaded, "srv01", "pcadmin", now)
    sync(loaded)
    assert members(loaded, adm.id)["pcadmin"].user_id == pcadmin


def test_host_without_cve_found_by_fqdn(loaded: Session) -> None:
    sync(loaded)
    srv02 = asset_id(loaded, "srv02")
    assert {o.source for o in loaded.execute(select(AssetObservation).where(AssetObservation.asset_id == srv02)).scalars()} == {"ad"}
    adm = local_group(loaded, "srv02", "administrators")
    assert adm.group_key == f"l:{srv02}:{ADMINS}"
    assert members(loaded, adm.id)["desktop admins"].member_group_id == domain_group(loaded, csid(1302)).id
    # Хост без актива групп не получает: локальных групп ровно у srv01 (2), srv02 (1) и lin01 (2).
    hosts = loaded.execute(select(AssetGroup.host_asset_id).where(AssetGroup.local.is_(True))).scalars().all()
    assert sorted(hosts) == sorted([asset_id(loaded, "srv01")] * 2 + [srv02] + [asset_id(loaded, "lin01")] * 2)


def test_domain_controller_groups_not_created(loaded: Session) -> None:
    sync(loaded)
    dc01 = asset_id(loaded, "dc01")
    obs = loaded.execute(select(AssetObservation).where(AssetObservation.asset_id == dc01, AssetObservation.source == "ad")).scalar_one()
    assert obs.extra["dc"] is True
    srv = loaded.execute(select(AssetObservation).where(AssetObservation.name == "SRV02", AssetObservation.source == "ad")).scalar_one()
    assert srv.extra["dc"] is False
    assert loaded.execute(select(AssetGroup).where(AssetGroup.host_asset_id == dc01)).first() is None


def test_linux_groups(loaded: Session, now: dt.datetime) -> None:
    sync(loaded)
    lin01 = asset_id(loaded, "lin01")
    wheel = local_group(loaded, "lin01", "wheel")
    assert (wheel.sid, wheel.description, wheel.group_key, wheel.sources) == ("", "GID 10", f"l:{lin01}:n:wheel", ["vm"])
    m = members(loaded, wheel.id)["user01"]
    assert (m.member_kind, m.user_id, m.member_sid, m.source) == ("user", None, "", "vm")
    daemon = local_group(loaded, "lin01", "daemon")
    assert (daemon.description, members(loaded, daemon.id)) == ("GID 2", {})
    user01 = add_local_user(loaded, "lin01", "user01", now)
    sync(loaded)
    assert members(loaded, wheel.id)["user01"].user_id == user01


def test_resync_no_duplicates(loaded: Session) -> None:
    sync(loaded)
    groups = {g.group_key: g.id for g in loaded.execute(select(AssetGroup)).scalars()}
    rows = snapshot_rows(loaded)
    sync(loaded)
    assert {g.group_key: g.id for g in loaded.execute(select(AssetGroup)).scalars()} == groups
    assert snapshot_rows(loaded) == rows


def test_gone_by_new_snapshot_and_back(loaded: Session, now: dt.datetime) -> None:
    sync(loaded)
    adm = local_group(loaded, "srv02", "administrators")
    put_groups(loaded, snapshot(without=("srv02", "helpers")), now - dt.timedelta(hours=1))
    sync(loaded)
    loaded.refresh(adm)
    assert adm.gone_at is not None and members(loaded, adm.id) == {}
    srv01_adm = local_group(loaded, "srv01", "administrators")
    assert "helpers" not in members(loaded, srv01_adm.id) and srv01_adm.gone_at is None
    assert local_group(loaded, "srv01", "helpers").gone_at is not None
    assert srv01_adm.last_seen == now - dt.timedelta(hours=1)
    put_groups(loaded, snapshot(), now)
    sync(loaded)
    loaded.refresh(adm)
    assert adm.gone_at is None and set(members(loaded, adm.id)) == {"desktop admins"}


def test_family_not_refreshed_is_not_judged(loaded: Session, now: dt.datetime) -> None:
    sync(loaded)
    daemon = local_group(loaded, "lin01", "daemon")
    # Снимок без Linux: строки Linux прежние; даже если строки группы пропали, она не судится.
    loaded.execute(delete(VmHostGroup).where(VmHostGroup.group_name == "daemon"))
    put_groups(loaded, snapshot(), now - dt.timedelta(hours=1), linux_ok=False)
    sync(loaded)
    loaded.refresh(daemon)
    assert daemon.gone_at is None
    wheel = local_group(loaded, "lin01", "wheel")
    assert wheel.last_seen == now - dt.timedelta(hours=2) and wheel.gone_at is None
    assert local_group(loaded, "srv01", "administrators").last_seen == now - dt.timedelta(hours=1)


def test_without_snapshot_vm_part_does_nothing(db_session: Session, app_settings: Any, now: dt.datetime) -> None:
    db_session.add(AssetSettings(data={"sync_after_import": False}))
    db_session.commit()
    load_ad(db_session, Path(app_settings.data_dir), ad_raw(corp_ad(), now - dt.timedelta(hours=3)))
    db_session.add_all(snapshot())  # строки без записи снимка
    db_session.commit()
    got = sync(db_session)
    assert "groups_failed" not in got and "vm_hosts_unmatched" not in got
    assert db_session.execute(select(AssetGroup).where(AssetGroup.local.is_(True))).first() is None
    assert domain_group(db_session, csid(1302)).sources == ["ad"]


def test_domain_group_leaves_ad_but_vm_still_sees_it(loaded: Session, app_settings: Any, now: dt.datetime) -> None:
    """Группа AD и VM: пропала из AD — не пропавшая, источник только vm, состав AD снят; пропала и из VM — gone."""
    sync(loaded)
    da = domain_group(loaded, csid(1302))
    load_ad(loaded, Path(app_settings.data_dir), ad_raw(corp_ad(without=("desktop admins",)), now - dt.timedelta(hours=1)))
    sync(loaded)
    loaded.refresh(da)
    assert (da.gone_at, da.sources, da.in_ad) == (None, ["vm"], False)
    assert members(loaded, da.id) == {}
    assert members(loaded, local_group(loaded, "srv01", "administrators").id)["desktop admins"].member_group_id == da.id
    put_groups(loaded, [r for r in snapshot() if r.member_name != "desktop admins"], now)
    sync(loaded)
    loaded.refresh(da)
    assert da.gone_at is not None and da.sources == []


def test_vm_domain_group_appears_in_ad(loaded: Session, app_settings: Any, now: dt.datetime) -> None:
    sync(loaded)
    rh = domain_group(loaded, csid(1400))
    assert (rh.in_ad, rh.sources) == (False, ["vm"])
    load_ad(loaded, Path(app_settings.data_dir),
            ad_raw(corp_ad(extra=(group("remote helpers", csid(1400), [dn("user01")]),)), now - dt.timedelta(hours=1)))
    sync(loaded)
    loaded.refresh(rh)
    assert (rh.in_ad, rh.sources, rh.gone_at) == (True, ["ad", "vm"], None)
    assert {m.member_name: m.source for m in members(loaded, rh.id).values()} == {"user01": "ad"}
    assert loaded.execute(select(AssetGroup).where(AssetGroup.sid == csid(1400))).scalars().all() == [rh]


def test_vm_only_pass_runs_groups_step(loaded: Session, now: dt.datetime) -> None:
    sync(loaded)
    adm = local_group(loaded, "srv02", "administrators")
    put_groups(loaded, snapshot(without=("srv02",)), now - dt.timedelta(hours=1))
    out: dict[str, int] = {}
    job_id = start_job(loaded, AssetJob, "sync", "tester")
    run_job(AssetJob, job_id, lambda s, h: out.update(run_sync(s, h, ("vm",))))
    loaded.expire_all()
    assert "groups_failed" not in out and "groups" in out
    loaded.refresh(adm)
    assert adm.gone_at is not None
