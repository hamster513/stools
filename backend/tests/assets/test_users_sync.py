"""Синхронизация пользователей (план «Пользователи как активы», задача 2): учётки и группы из выгрузки AD,
сеансы и владельцы из `ksc_host.extra_json` (контракт спеки §2.1) с привязкой к активам-хостам."""
from __future__ import annotations

import datetime as dt
import json
import logging
import time
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.jobs import run_job, start_job
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import datetime_to_filetime
from api.modules.ad.models import AdSnapshot
from api.modules.ad.services.snapshots import import_export as import_ad
from api.modules.ad.services.snapshots import snapshot_path as ad_snapshot_path
from api.modules.assets.models import (
    Asset,
    AssetJob,
    AssetObservation,
    AssetSettings,
    AssetUser,
    AssetUserGroup,
    AssetUserHost,
    AssetUserObservation,
)
from api.modules.assets.services.assets import delete_assets
from api.modules.assets.services.sync import run_sync
from api.modules.assets.services.users import ad_domains, sync_users
from api.modules.ksc.models import KscHost, KscSnapshot
from tests.ad.synthetic import build_export as build_ad_export
from tests.assets.synthetic import load_ksc

CORP_SID = "S-1-5-21-1111111111-2222222222-3333333333"
LAB_SID = "S-1-5-21-1111111111-2222222222-4444444444"
CORP_DN = "DC=corp,DC=local"
LAB_DN = "DC=lab,DC=local"
#: Участники групп из ForeignSecurityPrincipals: well-known и учётка чужого домена — не пользователи.
FSP_WELL_KNOWN = "S-1-5-11"
FSP_FOREIGN = "S-1-5-21-9999999999-8888888888-7777777777-1105"
OUTSIDER = "S-1-5-21-5555555555-6666666666-7777777777-500"


def csid(rid: int) -> str:
    return f"{CORP_SID}-{rid}"


def dn(name: str, base: str = CORP_DN) -> str:
    return f"CN={name},CN=Users,{base}"


def fsp(sid: str) -> str:
    return f"CN={sid},CN=ForeignSecurityPrincipals,{CORP_DN}"


# ---- выгрузка AD ----------------------------------------------------------


def account(sam: str, sid: str, *, base: str = CORP_DN, uac: int = 512, last_logon: dt.datetime | None = None, **extra: Any) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "dn": dn(sam, base), "class": "user", "sid": sid, "sam": sam, "name": sam, "uac": uac, "primaryGroupID": 513,
        "lastLogonTimestamp": datetime_to_filetime(last_logon) if last_logon else None,
    }
    obj.update(extra)
    return obj


def group(name: str, sid: str, members: list[str], *, base: str = CORP_DN) -> dict[str, Any]:
    return {"dn": dn(name, base), "class": "group", "sid": sid, "sam": name, "name": name, "member": members}


def computer(name: str, rid: int, os_name: str = "Windows 11 Pro") -> dict[str, Any]:
    return {
        "dn": f"CN={name},CN=Computers,{CORP_DN}", "class": "computer", "sid": csid(rid), "sam": f"{name}$", "name": name,
        "uac": 4096, "dNSHostName": f"{name.lower()}.corp.local", "operatingSystem": os_name, "primaryGroupID": 515,
    }


def corp_objects(now: dt.datetime, *, without: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """user01 — в Staff, Staff вложена в Office; user02 — отключена; admin01 — в Tier0, Tier0 вложена в Domain Admins;
    Administrator (RID 500); gMSA и компьютеры — не пользователи; в Staff — участники из ForeignSecurityPrincipals;
    у Big ровно 1500 участников — заметка «список мог быть обрезан»."""
    users = [
        account("user01", csid(1101), last_logon=now - dt.timedelta(days=1), userPrincipalName="user01@corp.local", displayName="Пользователь 01"),
        account("user02", csid(1102), uac=514),
        account("admin01", csid(1103), uac=512 | 0x10000, adminCount=1),
        account("Administrator", csid(500)),
    ]
    users = [u for u in users if u["sam"] not in without]
    return [
        *users,
        {"dn": dn("gmsa01"), "class": "msDS-GroupManagedServiceAccount", "sid": csid(1150), "sam": "gmsa01$", "name": "gmsa01", "uac": 4096},
        computer("WS01", 1201),
        computer("SRV01", 1202, "Windows Server 2022 Standard"),
        group("Domain Users", csid(513), []),
        group("Domain Admins", csid(512), [dn("Tier0")]),
        group("Tier0", csid(1303), [dn("admin01")]),
        group("Staff", csid(1301), [dn("user01"), fsp(FSP_WELL_KNOWN), fsp(FSP_FOREIGN)]),
        group("Office", csid(1302), [dn("Staff")]),
        group("Big", csid(1304), [f"CN=ghost{i},CN=Users,{CORP_DN}" for i in range(1500)]),
    ]


def ad_raw(objects: list[dict[str, Any]], now: dt.datetime, *, sid: str = CORP_SID, dns: str = "corp.local", netbios: str = "CORP", base: str = CORP_DN) -> dict[str, Any]:
    raw = build_ad_export(now=now)
    raw["domain"].update({"sid": sid, "dns_root": dns, "netbios": netbios, "dn": base})
    raw["objects"] = [{"dn": base, "class": "domainDNS", "sid": sid}, *objects]
    raw["principals"] = {}
    raw.pop("sysvol", None)
    raw.pop("gpo", None)
    return raw


def load_ad(db: Session, data_dir: Path, raw: dict[str, Any]) -> AdSnapshot:
    path = data_dir / "ad-upload.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(raw), encoding="utf-8")
    return import_ad(db, None, path, "file", "ad.json", AdConfig(), data_dir)


# ---- снапшот KSC ----------------------------------------------------------


def rec(sam: str, *, sid: str = "", active: bool = True, domain: str = "corp.local", local: bool = False, group: bool = False,
        upn: str = "", display_name: str = "") -> dict[str, Any]:
    return {"sid": sid, "sam": sam, "upn": upn, "display_name": display_name, "domain": domain, "local": local, "group": group, "active": active}


USER01 = rec("CORP\\user01", sid=csid(1101), upn="user01@corp.local", display_name="Пользователь 01")
OWNER01 = {"sid": csid(1101), "sam": "CORP\\user01", "display_name": "Пользователь 01"}


def ksc_users(**overrides: Any) -> dict[str, dict[str, Any]]:
    """WS01: user01 в системе (по SID), user03 заходил раньше (без SID, в AD нет), группа, локальная admin, владелец user01;
    SRV01: user01 по имени без SID, локальная admin; WS02: user02 заходил раньше, владелец задан вне списка."""
    users: dict[str, dict[str, Any]] = {
        "h-ws01": {"users": [USER01, rec("CORP\\user03", active=False), rec("CORP\\Domain Users", group=True),
                             rec("admin", sid=OUTSIDER, domain="", local=True)],
                   "users_collected": True, "owner": OWNER01},
        "h-srv01": {"users": [rec("CORP\\user01", active=False), rec("admin", domain="", local=True, active=False)],
                    "users_collected": True, "owner": None},
        "h-ws02": {"users": [rec("CORP\\user02", sid=csid(1102), active=False)], "users_collected": True,
                   "owner": {"owner_id": "AAAAAA=="}},
    }
    users.update(overrides)
    return users


HOSTS = [("WS01", "10.10.0.21"), ("SRV01", "10.10.0.11"), ("WS02", "10.10.0.22")]


def load_ksc_users(db: Session, data_dir: Path, collected_at: dt.datetime, users: dict[str, dict[str, Any]],
                   hosts: list[tuple[str, str]] = HOSTS) -> KscSnapshot:
    """Снапшот через импорт KSC, пользователи — прямо в `ksc_host.extra_json` по контракту §2.1."""
    snap = load_ksc(db, data_dir, hosts, collected_at)
    for h in db.execute(select(KscHost).where(KscHost.snapshot_id == snap.id)).scalars():
        extra = json.loads(h.extra_json or "{}")
        extra.update(users.get(h.host_id, {"users": None, "users_collected": True, "owner": None}))
        h.extra_json = json.dumps(extra)
    db.commit()
    return snap


# ---- запуск ---------------------------------------------------------------


def sync(db: Session) -> dict[str, int]:
    out: dict[str, int] = {}
    job_id = start_job(db, AssetJob, "sync", "tester")
    run_job(AssetJob, job_id, lambda s, h: out.update(run_sync(s, h)))
    job = db.get(AssetJob, job_id)
    db.refresh(job)
    assert job is not None and job.status == "done", job.error if job else None
    db.expire_all()
    return out


class Handle:
    id = 0

    def stage(self, *args: Any, **kwargs: Any) -> None:
        pass

    def tick(self, *args: Any, **kwargs: Any) -> None:
        pass


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
    load_ad(db_session, data_dir, ad_raw(corp_objects(now), now - dt.timedelta(hours=3)))
    load_ksc_users(db_session, data_dir, now - dt.timedelta(hours=1), ksc_users())
    return db_session


# ---- выборки --------------------------------------------------------------


def asset_id(db: Session, name: str) -> int:
    return int(db.execute(select(Asset.id).where(Asset.name_key == name, Asset.merged_into.is_(None))).scalar_one())


def users(db: Session) -> list[AssetUser]:
    return list(db.execute(select(AssetUser).where(AssetUser.merged_into.is_(None)).order_by(AssetUser.id)).scalars())


def user(db: Session, **where: Any) -> AssetUser:
    return db.execute(select(AssetUser).filter_by(merged_into=None, **where)).scalar_one()


def links(db: Session, user_id: int) -> dict[tuple[int, str], AssetUserHost]:
    return {(lk.asset_id, lk.kind): lk for lk in db.execute(select(AssetUserHost).where(AssetUserHost.user_id == user_id)).scalars()}


def groups(db: Session, user_id: int) -> dict[str, tuple[str, bool]]:
    rows = db.execute(select(AssetUserGroup).where(AssetUserGroup.user_id == user_id)).scalars()
    return {g.group_sid: (g.group_name, g.direct) for g in rows}


def table_counts(db: Session) -> tuple[int, ...]:
    return tuple(int(db.execute(select(func.count()).select_from(m)).scalar_one())
                 for m in (AssetUser, AssetUserObservation, AssetUserHost, AssetUserGroup))


def ksc_extra(db: Session, host_id: str) -> dict[str, Any]:
    row = db.execute(select(AssetObservation).where(AssetObservation.source == "ksc", AssetObservation.source_key.like(f"%:{host_id}"))).scalar_one()
    return dict(row.extra)


# ---- тесты ----------------------------------------------------------------


def test_sync_counts_users_and_keeps_host_counts(loaded: Session) -> None:
    counts = sync(loaded)
    assert {k: counts[k] for k in ("vm", "ksc", "ad")} == {"vm": 0, "ksc": 3, "ad": 2}
    # AD: user01, user02, admin01, Administrator; KSC сверх них: user03 и две локальные admin.
    assert counts["users"] == 7
    assert len(users(loaded)) == 7


def test_one_user_from_ad_and_ksc_by_sid_and_by_name(loaded: Session) -> None:
    sync(loaded)
    u = user(loaded, sid=csid(1101))
    assert (u.sam, u.upn, u.display_name, u.domain, u.local) == ("user01", "user01@corp.local", "Пользователь 01", "corp.local", False)
    assert u.name_key == "corp.local\\user01" and u.enabled is True and u.privileged is False
    obs = {(o.source, o.source_key) for o in loaded.execute(select(AssetUserObservation).where(AssetUserObservation.user_id == u.id)).scalars()}
    server = {k.split(":", 1)[0] for _, k in obs if _ == "ksc"}
    assert len(server) == 1
    (sid_key,) = server
    # По SID с WS01 и по имени без SID с SRV01 — одна учётка.
    assert obs == {("ad", csid(1101)), ("ksc", f"{sid_key}:{csid(1101)}"), ("ksc", f"{sid_key}:corp\\user01")}
    ws01, srv01 = asset_id(loaded, "ws01"), asset_id(loaded, "srv01")
    got = {key: (lk.active, lk.gone_at) for key, lk in links(loaded, u.id).items()}
    assert got == {(ws01, "session"): (True, None), (srv01, "session"): (False, None), (ws01, "owner"): (False, None)}


def test_ad_fields_flags_and_disabled(loaded: Session, now: dt.datetime) -> None:
    sync(loaded)
    data = loaded.execute(select(AssetUserObservation.data).where(AssetUserObservation.source == "ad", AssetUserObservation.source_key == csid(1101))).scalar_one()
    assert data["uac"] == 512 and data["pwd_never_expires"] is False and data["admin_count"] is None
    assert dt.datetime.fromisoformat(data["last_logon"]) == now - dt.timedelta(days=1)
    admin = loaded.execute(select(AssetUserObservation.data).where(AssetUserObservation.source_key == csid(1103))).scalar_one()
    assert admin["pwd_never_expires"] is True and admin["admin_count"] == 1
    assert user(loaded, sid=csid(1102)).enabled is False


def test_local_account_on_two_hosts_is_two_users(loaded: Session) -> None:
    sync(loaded)
    ws01, srv01 = asset_id(loaded, "ws01"), asset_id(loaded, "srv01")
    local = {u.name_key: u for u in users(loaded) if u.local}
    assert set(local) == {f"local:{ws01}\\admin", f"local:{srv01}\\admin"}
    assert all(u.sid == "" and u.domain == "" and u.enabled is None for u in local.values())
    assert set(links(loaded, local[f"local:{ws01}\\admin"].id)) == {(ws01, "session")}
    assert set(links(loaded, local[f"local:{srv01}\\admin"].id)) == {(srv01, "session")}


def test_group_and_service_records_are_not_users(loaded: Session) -> None:
    sync(loaded)
    sams = {u.sam.lower() for u in users(loaded)}
    assert "domain users" not in sams and "gmsa01$" not in sams and "gmsa01" not in sams and "ws01" not in sams
    sids = {u.sid for u in users(loaded)}
    assert FSP_WELL_KNOWN not in sids and FSP_FOREIGN not in sids
    # Группа с сеансом — только показ при хосте.
    assert ksc_extra(loaded, "h-ws01")["session_groups"] == [{"sid": "", "sam": "CORP\\Domain Users", "active": True}]


def test_users_collected_stored_on_ksc_observation(loaded: Session) -> None:
    sync(loaded)
    assert ksc_extra(loaded, "h-ws01")["users_collected"] is True
    assert ksc_extra(loaded, "h-ws02")["users_collected"] is True


def test_groups_direct_nested_primary(loaded: Session) -> None:
    sync(loaded)
    u = user(loaded, sid=csid(1101))
    assert groups(loaded, u.id) == {
        csid(1301): ("CORP\\Staff", True), csid(513): ("CORP\\Domain Users", True), csid(1302): ("CORP\\Office", False),
    }


def test_privileged_via_nested_group_and_rid_500(loaded: Session) -> None:
    sync(loaded)
    admin = user(loaded, sid=csid(1103))
    assert admin.privileged is True
    assert groups(loaded, admin.id)[csid(512)] == ("CORP\\Domain Admins", False)
    assert user(loaded, sid=csid(500)).privileged is True
    assert user(loaded, sid=csid(1101)).privileged is False
    # KSC привилегированность и включённость не знает.
    u3 = user(loaded, name_key="corp.local\\user03")
    assert u3.enabled is None and u3.privileged is False


def test_group_notes_preserved(loaded: Session) -> None:
    sync(loaded)
    data = loaded.execute(select(AssetUserObservation.data).where(AssetUserObservation.source_key == csid(1101))).scalar_one()
    assert any("Big" in n and "1500" in n for n in data["group_notes"])


def test_resync_makes_no_duplicates(loaded: Session) -> None:
    sync(loaded)
    before = table_counts(loaded)
    sync(loaded)
    assert table_counts(loaded) == before


def test_gone_only_on_collected_hosts(loaded: Session, data_dir: Path, now: dt.datetime) -> None:
    sync(loaded)
    u3, u2 = user(loaded, name_key="corp.local\\user03"), user(loaded, sid=csid(1102))
    ws01, ws02 = asset_id(loaded, "ws01"), asset_id(loaded, "ws02")
    # WS01 собран без user03; у WS02 запрос отказал (users null) — «не собрано», не «пропал».
    later = ksc_users(**{
        "h-ws01": {"users": [USER01], "users_collected": True, "owner": OWNER01},
        "h-ws02": {"users": None, "users_collected": True, "owner": None},
    })
    load_ksc_users(loaded, data_dir, now - dt.timedelta(minutes=10), later)
    sync(loaded)
    assert links(loaded, u3.id)[(ws01, "session")].gone_at is not None
    assert links(loaded, u2.id)[(ws02, "session")].gone_at is None
    assert ksc_extra(loaded, "h-ws02")["users_collected"] is False
    # Учётка KSC без живых связей — наблюдение пропало; user02 видит AD — карточка остаётся.
    obs3 = loaded.execute(select(AssetUserObservation).where(AssetUserObservation.user_id == u3.id)).scalar_one()
    assert obs3.gone_at is not None


def test_section_missing_is_not_collected(loaded: Session, data_dir: Path, now: dt.datetime) -> None:
    sync(loaded)
    u2, ws02 = user(loaded, sid=csid(1102)), asset_id(loaded, "ws02")
    load_ksc_users(loaded, data_dir, now - dt.timedelta(minutes=10),
                   ksc_users(**{"h-ws02": {"users": None, "users_collected": False, "owner": None}}))
    sync(loaded)
    assert links(loaded, u2.id)[(ws02, "session")].gone_at is None
    assert ksc_extra(loaded, "h-ws02")["users_collected"] is False


def test_owner_id_gives_no_link(loaded: Session) -> None:
    sync(loaded)
    ws02 = asset_id(loaded, "ws02")
    owners = loaded.execute(select(AssetUserHost).where(AssetUserHost.asset_id == ws02, AssetUserHost.kind == "owner")).scalars().all()
    assert owners == []


def test_ambiguous_match_is_skipped(loaded: Session, caplog: pytest.LogCaptureFixture, now: dt.datetime) -> None:
    for _ in range(2):
        loaded.add(AssetUser(name_key="corp.local\\user03", sam="user03", domain="corp.local", first_seen=now, last_seen=now))
    loaded.commit()
    with caplog.at_level(logging.WARNING, logger="stools.assets"):
        sync(loaded)
    assert loaded.execute(select(func.count()).select_from(AssetUser).where(AssetUser.name_key == "corp.local\\user03")).scalar_one() == 2
    assert not loaded.execute(select(AssetUserObservation).where(AssetUserObservation.source_key.like("%user03"))).first()
    assert any("неоднознач" in r.getMessage() for r in caplog.records)


def test_merged_host_is_followed(loaded: Session, data_dir: Path, now: dt.datetime) -> None:
    sync(loaded)
    ws01 = asset_id(loaded, "ws01")
    survivor = Asset(name="WS01-NEW", name_key="ws01-new")
    loaded.add(survivor)
    loaded.flush()
    # Актив объединён, а наблюдение KSC ещё указывает на старый: ссылки и ключ локальной — у выжившего.
    loaded.get(Asset, ws01).merged_into = survivor.id  # type: ignore[union-attr]
    loaded.commit()
    sync_users(loaded, Handle(), data_dir, now)  # type: ignore[arg-type]
    loaded.commit()
    loaded.expire_all()
    u = user(loaded, sid=csid(1101))
    assert links(loaded, u.id)[(survivor.id, "session")].active is True
    assert user(loaded, name_key=f"local:{survivor.id}\\admin").local is True


def test_orphan_local_user_removed_after_host_deletion(loaded: Session, data_dir: Path, now: dt.datetime) -> None:
    sync(loaded)
    srv01 = asset_id(loaded, "srv01")
    key = f"local:{srv01}\\admin"
    assert user(loaded, name_key=key)
    delete_assets(loaded, [srv01])
    loaded.commit()
    load_ksc_users(loaded, data_dir, now - dt.timedelta(minutes=10), ksc_users(), hosts=[h for h in HOSTS if h[0] != "SRV01"])
    sync(loaded)
    assert loaded.execute(select(AssetUser).where(AssetUser.name_key == key)).first() is None
    # Доменная учётка с той же машины осталась.
    assert user(loaded, sid=csid(1101))


def test_per_domain_completeness(loaded: Session, data_dir: Path, now: dt.datetime) -> None:
    lab = ad_raw([account("user09", f"{LAB_SID}-1109", base=LAB_DN)], now - dt.timedelta(hours=3), sid=LAB_SID, dns="lab.local", netbios="LAB", base=LAB_DN)
    lab_snap = load_ad(loaded, data_dir, lab)
    sync(loaded)
    assert ad_domains(loaded) == {"corp.local", "lab.local"}
    # Файл lab не читается, в новой выгрузке corp нет user02: пропала только учётка прочитанного домена.
    ad_snapshot_path(data_dir, lab_snap.id).write_bytes(b"broken")
    load_ad(loaded, data_dir, ad_raw(corp_objects(now, without=("user02",)), now - dt.timedelta(hours=2)))
    sync(loaded)
    gone = dict(loaded.execute(select(AssetUserObservation.source_key, AssetUserObservation.gone_at).where(AssetUserObservation.source == "ad")).tuples().all())
    assert gone[csid(1102)] is not None
    assert gone[f"{LAB_SID}-1109"] is None and gone[csid(1101)] is None
    assert ad_domains(loaded) == {"corp.local"}
    u2 = user(loaded, sid=csid(1102))
    assert u2.enabled is None and u2.privileged is False


def test_sync_users_timing_on_larger_case(loaded: Session, data_dir: Path, now: dt.datetime) -> None:
    """Не порог, а замер для отчёта: 2000 учёток AD и по 3 пользователя на 300 хостах KSC."""
    many = [account(f"user{i:04d}", csid(5000 + i)) for i in range(2000)]
    load_ad(loaded, data_dir, ad_raw(corp_objects(now) + many, now - dt.timedelta(hours=2)))
    hosts = [(f"PC{i:03d}", f"10.20.{i // 200}.{i % 200 + 1}") for i in range(300)]
    users_by_host = {
        f"h-pc{i:03d}": {"users": [rec(f"CORP\\user{(i * 3 + j) % 2000:04d}", sid=csid(5000 + (i * 3 + j) % 2000), active=j == 0) for j in range(3)],
                         "users_collected": True, "owner": None}
        for i in range(300)
    }
    load_ksc_users(loaded, data_dir, now - dt.timedelta(minutes=30), users_by_host, hosts=hosts)
    started = time.perf_counter()
    sync(loaded)
    print(f"\nполная синхронизация с первой записью пользователей: {time.perf_counter() - started:.2f} с")
    started = time.perf_counter()
    counts = sync_users(loaded, Handle(), data_dir, now)  # type: ignore[arg-type]
    loaded.commit()
    elapsed = time.perf_counter() - started
    print(f"повторный sync_users: {counts} за {elapsed:.2f} с")
    assert counts["users"] >= 2000
