"""Синхронизация групп (план «Группы как активы», задача 2): доменные группы из выгрузки AD — состав,
участники через primaryGroupID, встроенные субъекты, пропавшие, права по GPO."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from api.modules.ad.services.snapshots import snapshot_path as ad_snapshot_path
from api.modules.assets.models import (
    Asset,
    AssetGroup,
    AssetGroupGpo,
    AssetGroupMember,
    AssetSettings,
    AssetUser,
)
from api.modules.assets.services import groups as groups_service
from api.modules.assets.services import sync as sync_service
from api.modules.assets.services.groups import gpo_notes
from tests.assets.test_users_sync import (
    CORP_DN,
    LAB_DN,
    LAB_SID,
    account,
    ad_raw,
    csid,
    dn,
    fsp,
    load_ad,
    sync,
)

FOREIGN = "S-1-5-21-9999999999-8888888888-7777777777-1105"
GHOST = f"CN=ghost,CN=Users,{CORP_DN}"
BUILTIN_DN = f"CN=Administrators,CN=Builtin,{CORP_DN}"
GPO_DN = f"CN={{22222222-2222-2222-2222-222222222222}},CN=Policies,CN=System,{CORP_DN}"


def grp(name: str, sid: str, members: list[str], **extra: Any) -> dict[str, Any]:
    return {"dn": dn(name), "class": "group", "sid": sid, "sam": name, "name": name, "member": members, **extra}


def host(name: str, rid: int) -> dict[str, Any]:
    return {
        "dn": f"CN={name},CN=Computers,{CORP_DN}", "class": "computer", "sid": csid(rid), "sam": f"{name}$", "name": name,
        "uac": 4096, "dNSHostName": f"{name.lower()}.corp.local", "operatingSystem": "Windows Server 2022", "primaryGroupID": 515,
    }


def corp(*, without: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """helpdesk: user01, вложенная desktop admins, компьютер SRV01, Authenticated Users и учётка чужого леса
    из ForeignSecurityPrincipals, gMSA (не пользователь-актив), DN, которого нет в выгрузке.
    Domain Users пуста по `member`, кроме user01 (он же — по primaryGroupID); Builtin Administrators — helpdesk."""
    helpdesk_members = [dn("user01"), dn("desktop admins"), f"CN=SRV01,CN=Computers,{CORP_DN}", fsp("S-1-5-11"), fsp(FOREIGN),
                        dn("gmsa01"), GHOST]
    objects = [
        account("user01", csid(1101)),
        account("user02", csid(1102)),
        {"dn": dn("gmsa01"), "class": "msDS-GroupManagedServiceAccount", "sid": csid(1150), "sam": "gmsa01$", "name": "gmsa01", "uac": 4096},
        host("SRV01", 1202),
        host("WS01", 1201),
        grp("Domain Users", csid(513), [dn("user01")]),
        grp("Domain Computers", csid(515), []),
        grp("helpdesk", csid(1301), [m for m in helpdesk_members if not any(w in m for w in without)], description="служба поддержки"),
        grp("desktop admins", csid(1302), [dn("user02")]),
        {"dn": BUILTIN_DN, "class": "group", "sid": "S-1-5-32-544", "sam": "Administrators", "name": "Administrators", "member": [dn("helpdesk")]},
    ]
    return [o for o in objects if o.get("sam") not in without]


@pytest.fixture
def now() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(microsecond=0)


@pytest.fixture
def data_dir(app_settings: Any) -> Path:
    return Path(app_settings.data_dir)


@pytest.fixture
def loaded(db_session: Session, data_dir: Path, now: dt.datetime) -> Session:
    db_session.add(AssetSettings(data={"sync_after_import": False}))
    db_session.commit()
    load_ad(db_session, data_dir, ad_raw(corp(), now - dt.timedelta(hours=3)))
    return db_session


def group(db: Session, sid: str, domain: str = "corp.local") -> AssetGroup:
    return db.execute(select(AssetGroup).where(AssetGroup.sid == sid, AssetGroup.domain == domain, AssetGroup.local.is_(False))).scalar_one()


def members(db: Session, group_id: int) -> dict[str, AssetGroupMember]:
    rows = db.execute(select(AssetGroupMember).where(AssetGroupMember.group_id == group_id)).scalars()
    return {m.member_name: m for m in rows}


def counts(db: Session) -> tuple[int, int, int]:
    return tuple(int(db.execute(select(func.count()).select_from(m)).scalar_one()) for m in (AssetGroup, AssetGroupMember, AssetGroupGpo))  # type: ignore[return-value]


def test_domain_and_builtin_groups(loaded: Session) -> None:
    got = sync(loaded)
    assert got["groups"] == 5 and "groups_failed" not in got
    hd = group(loaded, csid(1301))
    assert (hd.name, hd.domain, hd.local, hd.in_ad, hd.sources, hd.description, hd.gone_at) == (
        "helpdesk", "corp.local", False, True, ["ad"], "служба поддержки", None)
    assert hd.group_key == f"d:corp.local:{csid(1301)}"
    assert hd.first_seen is not None and hd.last_seen == hd.first_seen
    builtin = group(loaded, "S-1-5-32-544")
    assert builtin.group_key == "d:corp.local:S-1-5-32-544" and builtin.name == "Administrators"
    assert group(loaded, csid(1302)).description == ""


def test_helpdesk_members(loaded: Session) -> None:
    sync(loaded)
    hd = group(loaded, csid(1301))
    got = members(loaded, hd.id)
    user01 = loaded.execute(select(AssetUser.id).where(AssetUser.sid == csid(1101))).scalar_one()
    srv01 = loaded.execute(select(Asset.id).where(Asset.name_key == "srv01", Asset.merged_into.is_(None))).scalar_one()
    da = group(loaded, csid(1302))
    assert set(got) == {"user01", "desktop admins", "SRV01$", "NT AUTHORITY\\Authenticated Users", FOREIGN, "gmsa01$", GHOST}
    assert (got["user01"].member_kind, got["user01"].user_id, got["user01"].member_sid, got["user01"].primary) == ("user", user01, csid(1101), False)
    assert (got["desktop admins"].member_kind, got["desktop admins"].member_group_id) == ("group", da.id)
    assert (got["SRV01$"].member_kind, got["SRV01$"].asset_id, got["SRV01$"].member_sid) == ("computer", srv01, csid(1202))
    wk = got["NT AUTHORITY\\Authenticated Users"]
    assert (wk.member_kind, wk.member_sid) == ("well_known", "S-1-5-11")
    assert (got[FOREIGN].member_kind, got[FOREIGN].member_sid) == ("unknown", FOREIGN)
    assert (got["gmsa01$"].member_kind, got["gmsa01$"].user_id, got["gmsa01$"].member_sid) == ("user", None, csid(1150))
    assert (got[GHOST].member_kind, got[GHOST].member_sid) == ("unknown", "")
    assert all(m.source == "ad" for m in got.values())
    assert got["user01"].member_domain == "corp.local"
    # Builtin Administrators содержит helpdesk этого домена.
    adm = members(loaded, group(loaded, "S-1-5-32-544").id)
    assert adm["helpdesk"].member_group_id == hd.id


def test_primary_group_members(loaded: Session) -> None:
    sync(loaded)
    du = members(loaded, group(loaded, csid(513)).id)
    # user01 и в `member`, и по primaryGroupID — одна строка с primary.
    assert set(du) == {"user01", "user02"}
    assert all(m.primary and m.member_kind == "user" and m.user_id is not None for m in du.values())
    dc = members(loaded, group(loaded, csid(515)).id)
    assert set(dc) == {"SRV01$", "WS01$"}
    assert all(m.primary and m.member_kind == "computer" and m.asset_id is not None for m in dc.values())


def test_resync_no_duplicates(loaded: Session) -> None:
    sync(loaded)
    first = counts(loaded)
    sync(loaded)
    assert counts(loaded) == first


def test_gone_and_back(loaded: Session, data_dir: Path, now: dt.datetime) -> None:
    sync(loaded)
    da = group(loaded, csid(1302))
    assert members(loaded, da.id)
    load_ad(loaded, data_dir, ad_raw(corp(without=("desktop admins",)), now - dt.timedelta(hours=2)))
    sync(loaded)
    loaded.refresh(da)
    assert da.gone_at is not None
    assert members(loaded, da.id) == {}
    assert "desktop admins" not in members(loaded, group(loaded, csid(1301)).id)
    load_ad(loaded, data_dir, ad_raw(corp(), now - dt.timedelta(hours=1)))
    sync(loaded)
    loaded.refresh(da)
    assert da.gone_at is None and set(members(loaded, da.id)) == {"user02"}
    assert members(loaded, group(loaded, csid(1301)).id)["desktop admins"].member_group_id == da.id


def test_unreadable_domain_file_keeps_groups(loaded: Session, data_dir: Path, now: dt.datetime) -> None:
    lab = ad_raw([account("user09", f"{LAB_SID}-1109", base=LAB_DN),
                  {"dn": f"CN=labstaff,CN=Users,{LAB_DN}", "class": "group", "sid": f"{LAB_SID}-1301", "sam": "labstaff",
                   "name": "labstaff", "member": [dn("user09", LAB_DN)]}],
                 now - dt.timedelta(hours=3), sid=LAB_SID, dns="lab.local", netbios="LAB", base=LAB_DN)
    lab_snap = load_ad(loaded, data_dir, lab)
    sync(loaded)
    labstaff = group(loaded, f"{LAB_SID}-1301", "lab.local")
    assert set(members(loaded, labstaff.id)) == {"user09"}
    ad_snapshot_path(data_dir, lab_snap.id).write_bytes(b"broken")
    load_ad(loaded, data_dir, ad_raw(corp(without=("desktop admins",)), now - dt.timedelta(hours=2)))
    sync(loaded)
    loaded.refresh(labstaff)
    assert labstaff.gone_at is None and set(members(loaded, labstaff.id)) == {"user09"}
    assert group(loaded, csid(1302)).gone_at is not None


def test_gpo_restricted_groups(loaded: Session, data_dir: Path, now: dt.datetime) -> None:
    raw = ad_raw(corp(), now - dt.timedelta(hours=2))
    raw["objects"][0]["gpLink"] = f"[LDAP://{GPO_DN};0]"
    raw["objects"].append({"dn": GPO_DN, "class": "groupPolicyContainer", "cn": "{22222222-2222-2222-2222-222222222222}",
                           "name": "{22222222-2222-2222-2222-222222222222}", "displayName": "Server admins"})
    raw["sysvol"] = {GPO_DN: {"GptTmpl.inf": f"[Group Membership]\n*S-1-5-32-544__Members = *{csid(1301)}\n"}}
    load_ad(loaded, data_dir, raw)
    got = sync(loaded)
    assert "groups_failed" not in got
    [row] = loaded.execute(select(AssetGroupGpo)).scalars().all()
    assert (row.domain, row.group_sid, row.local_group, row.local_group_sid, row.via, row.action, row.gpo_name, row.gpo_dn) == (
        "corp.local", csid(1301), "Administrators", "S-1-5-32-544", "restricted_groups", "member", "Server admins", GPO_DN)
    assert sorted(row.hosts) == ["srv01.corp.local", "ws01.corp.local"] and row.hosts_total == 2
    notes = gpo_notes(loaded)
    assert notes["corp.local"]["links_known"] is True and notes["corp.local"]["files_known"] is True
    assert isinstance(notes["corp.local"]["notes"], list)
    # Повтор — замена, не дубль.
    sync(loaded)
    assert len(loaded.execute(select(AssetGroupGpo)).scalars().all()) == 1


def test_failed_groups_step_keeps_hosts_and_users(loaded: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> dict[str, int]:
        raise RuntimeError("сбой")

    monkeypatch.setattr(sync_service, "sync_groups", boom)
    got = sync(loaded)
    assert got["groups_failed"] == 1 and "groups" not in got
    assert got["ad"] == 2 and got["users"] >= 2
    assert loaded.execute(select(func.count()).select_from(AssetUser)).scalar_one() >= 2
    assert counts(loaded) == (0, 0, 0)


def test_members_diffed_not_rewritten(loaded: Session, data_dir: Path, now: dt.datetime) -> None:
    """Повтор без изменений не трогает строки (id те же); убранный участник удаляется, новый добавляется,
    переименование вложенной группы (тот же SID) правит строку на месте."""
    sync(loaded)
    before = {(m.group_id, m.member_sid, m.member_name): (m.id, m.primary)
              for m in loaded.execute(select(AssetGroupMember)).scalars()}
    sync(loaded)
    after = {(m.group_id, m.member_sid, m.member_name): (m.id, m.primary)
             for m in loaded.execute(select(AssetGroupMember)).scalars()}
    assert after == before
    objs = corp()
    for o in objs:
        if o.get("sam") == "desktop admins":
            o["member"] = [dn("user01")]  # user02 убран, user01 добавлен
            o["sam"] = o["name"] = "desktop admins 2"
        if o.get("sam") == "Domain Users":
            o["member"] = []  # user01 остаётся только по primaryGroupID
    load_ad(loaded, data_dir, ad_raw(objs, now - dt.timedelta(hours=1)))
    sync(loaded)
    da = members(loaded, group(loaded, csid(1302)).id)
    assert set(da) == {"user01"} and da["user01"].primary is False
    du_id = group(loaded, csid(513)).id
    du = members(loaded, du_id)
    assert set(du) == {"user01", "user02"} and du["user01"].primary is True
    assert du["user01"].id == before[(du_id, csid(1101), "user01")][0]
    # Остальные строки не переписаны; строка переименованной группы — та же, с новым именем.
    hd_id = group(loaded, csid(1301)).id
    hd = members(loaded, hd_id)
    assert {m.id for m in hd.values()} == {v[0] for k, v in before.items() if k[0] == hd_id}
    assert hd["desktop admins 2"].id == before[(hd_id, csid(1302), "desktop admins")][0]


def normalized_members(db: Session) -> set[tuple[Any, ...]]:
    """Состав без id строк и групп: группа и группа-участник — по ключу личности."""
    keys = dict(db.execute(select(AssetGroup.id, AssetGroup.group_key)).tuples().all())
    return {(keys[m.group_id], m.source, m.member_kind, m.member_sid, m.member_name, m.member_domain, m.primary, m.user_id,
             m.asset_id, keys.get(m.member_group_id) if m.member_group_id else None)
            for m in db.execute(select(AssetGroupMember)).scalars()}


def test_member_batches_of_one_group_give_same_result(loaded: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    """Сверка состава AD пачками по одной группе (`MEMBER_BATCH_GROUPS=1`) — тот же состав, что одной пачкой;
    повтор пачками не переписывает строки."""
    sync(loaded)
    single = normalized_members(loaded)
    assert len(single) >= 10
    loaded.execute(delete(AssetGroup))
    loaded.commit()
    calls: list[int] = []
    apply = groups_service._apply_members

    def spy(db: Session, batch: dict[int, Any], source: str = "ad") -> None:
        calls.append(len(batch))
        apply(db, batch, source)

    monkeypatch.setattr(groups_service, "MEMBER_BATCH_GROUPS", 1)
    monkeypatch.setattr(groups_service, "_apply_members", spy)
    sync(loaded)
    assert len(calls) == 5 and set(calls) == {1}
    assert normalized_members(loaded) == single
    ids = {m.id for m in loaded.execute(select(AssetGroupMember)).scalars()}
    sync(loaded)
    assert {m.id for m in loaded.execute(select(AssetGroupMember)).scalars()} == ids
