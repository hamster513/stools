"""Миграция «удаление сканирования» (спека сетей §7): наблюдения `scan` и активы, у которых кроме них
ничего не было, удаляются с теми же каскадами, что удаление актива; расписания и задачи скана — тоже;
столбцы скана сети уходят, откат возвращает их с умолчаниями."""
from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from api.modules.assets.models import (
    Asset,
    AssetGroup,
    AssetGroupMember,
    AssetJob,
    AssetObservation,
    AssetUser,
    AssetUserHost,
)
from api.platform.scheduler import PlatformSchedule
from tests.conftest import BACKEND_DIR

BEFORE = "5e909f11ba53"
NOW = dt.datetime(2026, 10, 20, 12, 0, tzinfo=dt.UTC)
SCAN_COLUMNS = {
    "scan_enabled", "ports", "exclude", "concurrency", "icmp_timeout_ms", "tcp_timeout_ms", "rate_per_s", "schedule_id",
    "last_scan_at", "last_scan_alive", "last_scan_icmp",
}


@pytest.fixture
def scratch(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Engine, Config]]:
    name = f"stools_mig_{uuid.uuid4().hex[:8]}"
    admin = create_engine(postgres_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    url = make_url(postgres_url).set(database=name).render_as_string(hide_password=False)
    monkeypatch.setenv("STOOLS_DATABASE_URL", url)
    engine = create_engine(url)
    try:
        yield engine, Config(str(BACKEND_DIR / "alembic.ini"))
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _obs(asset: Asset, source: str, key: str, ip: str, gone: bool = False) -> AssetObservation:
    return AssetObservation(asset_id=asset.id, source=source, source_key=key, ip=ip, seen_at=NOW, gone_at=NOW if gone else None)


def _seed(engine: Engine) -> dict[str, int]:
    """Сети со сканом и расписаниями, активы с разным составом наблюдений и ссылками на них."""
    with Session(engine) as db:
        # Схема BEFORE ещё не содержит календарные поля текущей ORM-модели.
        scan_sched_id, _, dns_sched_id = [
            db.execute(text(
                "INSERT INTO platform_schedule (module, kind, target_id, interval_hours, enabled) "
                "VALUES ('assets', :kind, :target_id, 24, true) RETURNING id"
            ), {"kind": kind, "target_id": target_id}).scalar_one()
            for kind, target_id in (("scan", 1), ("scan", 999), ("dns", 1))
        ]
        db.execute(text(
            "INSERT INTO network (id, cidr, title, description, zone, site, owner, tags, implicit_tags, scan_enabled, ports, exclude, "
            "concurrency, icmp_timeout_ms, tcp_timeout_ms, rate_per_s, schedule_id, last_scan_at, last_scan_alive, last_scan_icmp, "
            "zone_source, origin, origin_key, created_at, updated_at) VALUES "
            "(1, '10.10.0.0/24', 'офис', '', NULL, '', '', '[]', '[]', true, '[22]', '[\"10.10.0.1\"]', 16, 500, 700, 100, :sched, "
            ":now, 3, false, '', '', '', :now, :now), "
            "(2, '10.20.0.0/24', '', '', NULL, '', '', '[]', '[]', false, '[]', '[]', 64, 1000, 2000, 500, NULL, NULL, NULL, NULL, "
            "'', '', '', :now, :now)"
        ), {"sched": scan_sched_id, "now": NOW})

        only_scan = Asset(name="", ip="10.10.0.9", network_id=1)
        gone_scan = Asset(name="", ip="10.10.0.8", network_id=1)
        scan_and_ksc = Asset(name="srv01", name_key="srv01", ip="10.10.0.5", network_id=1)
        ksc_only = Asset(name="ws01", name_key="ws01", ip="10.20.0.5", network_id=2)
        db.add_all([only_scan, gone_scan, scan_and_ksc, ksc_only])
        db.flush()
        # Слитый актив: наблюдений у него нет (переехали к ws01) — миграция его не трогает.
        merged = Asset(name="ws01-old", name_key="ws01", merged_into=ksc_only.id)
        # Слит в актив «только скан» (и цепочкой — в него): без своих живых наблюдений удаляется вместе с ним.
        merged_into_scan = Asset(name="x", name_key="x", merged_into=only_scan.id)
        db.add_all([merged, merged_into_scan])
        db.flush()
        chained = Asset(name="y", name_key="y", merged_into=merged_into_scan.id)
        # Слит в актив «только скан», но со своим живым наблюдением: остаётся, ссылка обнуляется (SET NULL).
        merged_alive = Asset(name="z", name_key="z", ip="10.20.0.9", merged_into=only_scan.id)
        db.add_all([chained, merged_alive])
        db.flush()
        db.add_all([
            _obs(only_scan, "scan", "10.10.0.9", "10.10.0.9"),
            _obs(gone_scan, "scan", "10.10.0.8", "10.10.0.8", gone=True),
            _obs(scan_and_ksc, "scan", "10.10.0.5", "10.10.0.5"),
            _obs(scan_and_ksc, "ksc", "1:srv01", "10.10.0.5"),
            _obs(ksc_only, "ksc", "1:ws01", "10.20.0.5"),
            _obs(merged_alive, "ksc", "1:z", "10.20.0.9"),
        ])
        user = AssetUser(name_key="corp.local\\user1", sam="user1")
        db.add(user)
        db.flush()
        db.add_all([
            AssetUserHost(user_id=user.id, asset_id=only_scan.id, source="ksc", kind="session", seen_at=NOW),
            AssetUserHost(user_id=user.id, asset_id=ksc_only.id, source="ksc", kind="session", seen_at=NOW),
        ])
        local = AssetGroup(group_key="local:9|administrators", name="Administrators", local=True, host_asset_id=only_scan.id)
        domain = AssetGroup(group_key="corp.local|S-1-5-21-1-512", name="Domain Admins", sid="S-1-5-21-1-512")
        db.add_all([local, domain])
        db.flush()
        db.add(AssetGroupMember(group_id=domain.id, member_kind="computer", asset_id=only_scan.id, member_name="X$", source="ad"))
        db.add_all([AssetJob(kind="scan", status="done", message="сеть 10.10.0.0/24"), AssetJob(kind="dns", status="done")])
        db.commit()
        return {
            "only_scan": only_scan.id, "gone_scan": gone_scan.id, "scan_and_ksc": scan_and_ksc.id, "ksc_only": ksc_only.id,
            "merged": merged.id, "merged_alive": merged_alive.id, "domain": domain.id, "dns_sched": dns_sched_id,
        }


def test_migration_removes_scan_data_and_columns(scratch: tuple[Engine, Config]) -> None:
    engine, cfg = scratch
    command.upgrade(cfg, BEFORE)
    ids = _seed(engine)

    command.upgrade(cfg, "head")
    with Session(engine) as db:
        assert db.execute(select(AssetObservation).where(AssetObservation.source == "scan")).scalars().all() == []
        assets = {a.id: a for a in db.execute(select(Asset)).scalars()}
        # Только скан (живой или пропавший) — актив удалён вместе со слитыми в него (и по цепочке) без живых наблюдений;
        # скан и KSC — остался с KSC; слитый в живой актив и слитый со своим живым наблюдением — на месте.
        assert set(assets) == {ids["scan_and_ksc"], ids["ksc_only"], ids["merged"], ids["merged_alive"]}
        assert [o.source for o in db.execute(select(AssetObservation).where(AssetObservation.asset_id == ids["scan_and_ksc"])).scalars()] == ["ksc"]
        assert assets[ids["merged"]].merged_into == ids["ksc_only"]
        assert assets[ids["merged_alive"]].merged_into is None
        # Каскады удаления актива: связи с пользователями и локальные группы хоста — удалены, участник группы — без актива.
        assert [h.asset_id for h in db.execute(select(AssetUserHost)).scalars()] == [ids["ksc_only"]]
        assert [g.id for g in db.execute(select(AssetGroup)).scalars()] == [ids["domain"]]
        member = db.execute(select(AssetGroupMember)).scalar_one()
        assert member.asset_id is None and member.member_name == "X$"
        # Расписания скана (и осиротевшее) и задачи скана удалены, прочие остались.
        assert [s.id for s in db.execute(select(PlatformSchedule)).scalars()] == [ids["dns_sched"]]
        assert [j.kind for j in db.execute(select(AssetJob)).scalars()] == ["dns"]
    with engine.connect() as conn:
        cols = {r[0] for r in conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name = 'network'"))}
        assert not SCAN_COLUMNS & cols
        assert conn.execute(text("SELECT count(*) FROM network")).scalar() == 2

    command.downgrade(cfg, BEFORE)
    with engine.connect() as conn:
        cols = {r[0] for r in conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name = 'network'"))}
        assert SCAN_COLUMNS <= cols
        rows = conn.execute(text(
            "SELECT scan_enabled, ports, exclude, concurrency, icmp_timeout_ms, tcp_timeout_ms, rate_per_s, schedule_id, last_scan_at "
            "FROM network ORDER BY id"
        )).all()
    assert [tuple(r) for r in rows] == [(False, [22, 80, 135, 139, 443, 445, 3389], [], 64, 1000, 2000, 500, None, None)] * 2
