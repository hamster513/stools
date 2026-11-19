import datetime as dt

import pytest

from api.modules.assets.services import assets
from api.modules.assets.services.list_query import Query
from api.modules.assets.services.read_model import ready_generation, refresh
from api.platform.findings.models import FindingState
from tests.assets.test_asset_read_model import NOW, seed
from tests.assets.test_assets_api import analyst  # noqa: F401

CASES = [{}, {"limit": 1, "offset": 1}, {"limit": 0}, {"q": "SRV"}, {"q": "10."},
    {"source_has": frozenset(("vm", "ksc"))}, {"source_missing": frozenset(("ad", "ksc"))},
    {"network_id": frozenset()}, {"zone": frozenset(("",))}, {"placement": frozenset(("",))},
    {"criticality": frozenset(("none", "High"))}, {"laps": frozenset(("yes", "no"))},
    {"cluster": frozenset(("cluster", "role"))}, {"ad_keys": frozenset()}, {"code": frozenset(("any",))},
    {"code": frozenset(("conflict", "no_av"))}, {"disc_status": "all"}, {"disc_status": "risk_accepted"},
    {"assignee": ["me", "none"], "login": "analyst"}, {"overdue": True},
    {"code": frozenset(("any",)), "disc_status": "new,in_work", "overdue": True}]


@pytest.mark.parametrize("options", CASES)
def test_sql_matches_legacy(analyst, db_session, monkeypatch, options):  # noqa: F811
    db = db_session
    seed(db)
    # A decision remains live even when it is changed after the index is built.
    refresh(db, now=NOW)
    db.commit()
    generation = ready_generation(db, NOW)
    query_options = {k: v for k, v in options.items() if k not in ("limit", "offset")}
    q = Query(db, generation, **query_options)
    ids = q.ids(limit=options.get("limit", 200), offset=options.get("offset", 0))
    actual = (q.page(ids, NOW), *q.facets())
    expected = assets._legacy_list_assets(db, now=NOW, **options)
    assert actual == expected
    assert set(q.ids()) == set(assets._legacy_matching_ids(db, **query_options))


@pytest.mark.parametrize("needle", ["СЕРВЕР", "İ_100%", "i̇_100%", "%", "_", "\x00", "10.2.3"])
def test_literal_unicode_search(db_session, needle):
    db = db_session
    seed(db)
    refresh(db, now=NOW)
    q = Query(db, ready_generation(db, NOW), q=needle)
    assert (q.page(q.ids(), NOW), *q.facets()) == assets._legacy_list_assets(db, now=NOW, q=needle)


def test_live_decisions_and_no_full_registry_reads(db_session, monkeypatch):
    from sqlalchemy import select

    from api.modules.assets.models import AssetReadFinding
    from api.settings import get_settings
    db = db_session
    a = seed(db)
    refresh(db, now=NOW)
    db.commit()
    key = db.scalar(select(AssetReadFinding.key).where(AssetReadFinding.asset_id == a.id).limit(1))
    row = FindingState(module="assets", scope_id=0, key=key, status="in_work", assignee="analyst",
                       due_date=dt.date(2020, 1, 1))
    db.add(row)
    db.commit()
    monkeypatch.setattr(get_settings(), "assets_sql_list_enabled", True)
    for status in ("in_work", "risk_accepted", "resolved", "new"):
        row.status = status
        db.commit()
        for filters in ({}, {"disc_status": "all"}, {"assignee": "me", "login": "analyst"}, {"overdue": True}):
            expected = assets._legacy_list_assets(db, now=NOW, **filters)
            def forbidden(*a, **kw):
                pytest.fail("SQL list attempted to load the whole registry")
            with monkeypatch.context() as m:
                m.setattr(assets, "_pick", forbidden)
                m.setattr(assets, "_states", forbidden)
                assert assets.list_assets(db, now=NOW, **filters) == expected


def test_gone_laps_cluster_tags_and_pinned(db_session):
    from sqlalchemy import select

    from api.modules.assets.models import Asset, AssetObservation
    db = db_session
    a = seed(db)
    a.pinned = {"name": True}
    a.tags = ["tag,with,commas"]
    a.criticality = "High"
    first = db.scalar(select(AssetObservation).where(AssetObservation.asset_id == a.id).limit(1))
    first.extra = {"enabled": True, "cluster": "cluster", "laps": False}
    db.add(AssetObservation(asset_id=a.id, source="ad", source_key="gone-sid", name="old-searchable-name",
                           ips=["192.0.2.15"], seen_at=NOW, gone_at=NOW, extra={"laps": True}))
    merged = Asset(name="hidden", name_key="hidden", merged_into=a.id)
    db.add(merged)
    db.commit()
    refresh(db, now=NOW)
    for options in ({}, {"q": "old-searchable"}, {"q": "192.0.2.15"}, {"ad_keys": frozenset(("gone-sid",))},
                    {"tag": "tag,with,commas"}, {"laps": frozenset(("no",))}, {"cluster": frozenset(("cluster",))}):
        q = Query(db, ready_generation(db, NOW), **options)
        assert (q.page(q.ids(), NOW), *q.facets()) == assets._legacy_list_assets(db, now=NOW, **options)


def test_concurrent_partial_repair_forces_correct_fallback(db_session, monkeypatch):
    from sqlalchemy.orm import Session

    from api.modules.assets.services.read_model import refresh_small
    db = db_session
    a = seed(db)
    refresh(db, now=NOW)
    db.commit()
    original = Query.facets
    def mutate_after_facets(query):
        result = original(query)
        with Session(db.get_bind()) as writer:
            writer.get(type(a), a.id).criticality = "High"
            assert refresh_small(writer, now=NOW)
            writer.commit()
        return result
    monkeypatch.setattr(Query, "facets", mutate_after_facets)
    result = assets.list_assets(db, now=NOW)
    db.expire_all()
    assert result == assets._legacy_list_assets(db, now=NOW)


def test_streaming_export_keeps_snapshot_across_pages(db_session):
    from sqlalchemy import insert
    from sqlalchemy.orm import Session

    from api.modules.assets.models import Asset
    from api.modules.assets.services.list_query import export_items
    from api.timeutil import utcnow
    db = db_session
    db.execute(insert(Asset), [{"id": i, "name": f"host-{i:04}", "name_key": f"host-{i:04}"} for i in range(1, 1002)])
    db.commit()
    refresh(db, now=utcnow())
    db.commit()
    stream = export_items(db)
    first = next(stream)
    assert first["name"] == "host-0001"
    with Session(db.get_bind()) as writer:
        writer.get(Asset, 1001).name = "renamed-during-export"
        writer.commit()
    rows = [first, *stream]
    assert len(rows) == 1001
    assert rows[-1]["name"] == "host-1001"


def test_csv_uses_same_filtered_index(analyst, db_session, monkeypatch):  # noqa: F811
    from api.timeutil import utcnow
    from tests.assets.test_assets_export import ASSETS
    from tests.export_check import check_export
    refresh(db_session, now=utcnow())
    db_session.commit()
    def forbidden(*a, **kw):
        pytest.fail("Ready export fell back to loading the registry")
    monkeypatch.setattr(assets, "_pick", forbidden)
    check_export(analyst, "/api/assets/assets/export", ASSETS, narrow={"source_missing": "ksc"})


def test_network_facets_and_mutations(analyst, assets_admin, db_session):  # noqa: F811
    from api.timeutil import utcnow
    from tests.assets.test_assets_api import by_name
    from tests.assets.test_assets_multi import _with_networks
    networks = _with_networks(analyst, assets_admin)
    now = utcnow()
    refresh(db_session, now=now)
    db_session.commit()
    filters = [{}, {"network_id": frozenset(networks)}, {"zone": frozenset(("DMZ", ""))},
               {"criticality": frozenset(("", "High"))}, {"placement": frozenset(("",))}]
    for options in filters:
        query = Query(db_session, ready_generation(db_session, now), **options)
        assert (query.page(query.ids(), now), *query.facets()) == assets._legacy_list_assets(db_session, now=now, **options)
    id_ = by_name(analyst, "msk1")["id"]
    assert analyst.patch(f"/api/assets/assets/{id_}", json={"criticality": "High", "tags": ["manual"]}).status_code == 200
    db_session.expire_all()
    now = utcnow()
    assert ready_generation(db_session, now)
    assert assets.list_assets(db_session, now=now) == assets._legacy_list_assets(db_session, now=now)


def test_bulk_keys_from_index_keep_existing_finding_keys(db_session, monkeypatch):
    from api.timeutil import utcnow
    db = db_session
    a = seed(db)
    expected = assets.discrepancy_keys(db, [a.id], "no_network")
    refresh(db, now=utcnow())
    db.commit()
    def forbidden(*a, **kw):
        pytest.fail("Bulk decision loaded all observations")
    monkeypatch.setattr(assets, "_pick", forbidden)
    assert assets.discrepancy_keys(db, [a.id], "no_network") == expected


def test_api_response_uses_one_finding_snapshot(analyst, db_session, monkeypatch):  # noqa: F811
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from api.modules.assets.models import AssetReadFinding
    from api.timeutil import utcnow
    db = db_session
    refresh(db, now=utcnow())
    db.commit()
    key = db.scalar(select(AssetReadFinding.key).where(AssetReadFinding.code == "no_network").limit(1))
    db.rollback()
    original = Query.facets
    def close_after_facets(query):
        result = original(query)
        with Session(db.get_bind()) as writer:
            row = writer.scalar(select(FindingState).where(FindingState.module == "assets", FindingState.key == key))
            if row is None:
                row = FindingState(module="assets", scope_id=0, key=key)
                writer.add(row)
            row.status = "resolved"
            writer.commit()
        return result
    monkeypatch.setattr(Query, "facets", close_after_facets)
    result = analyst.get("/api/assets/assets", params={"code": "no_network", "disc_status": "new"}).json()
    assert result["total"] == len(result["items"])


@pytest.mark.parametrize("disabled", [False, True])
def test_fallback_export_is_bounded(db_session, monkeypatch, disabled):
    from sqlalchemy import insert

    from api.modules.assets.models import Asset
    from api.modules.assets.services import read_model
    from api.modules.assets.services.list_query import export_items
    from api.settings import get_settings
    db = db_session
    db.execute(insert(Asset), [{"id": i, "name": f"host-{i:04}", "name_key": f"host-{i:04}"} for i in range(1, 1002)])
    db.commit()
    monkeypatch.setattr(get_settings(), "assets_sql_list_enabled", not disabled)
    sizes = []
    original = read_model._batch
    def batch(db, ids, *args):
        sizes.append(len(ids))
        return original(db, ids, *args)
    monkeypatch.setattr(read_model, "_batch", batch)
    def forbidden(*a, **kw):
        pytest.fail("Fallback export materialized the registry")
    monkeypatch.setattr(assets, "_legacy_list_assets", forbidden)
    assert sum(1 for _ in export_items(db)) == 1001
    assert sizes and max(sizes) <= read_model.BATCH


def test_authenticated_export_with_single_connection(analyst, db_session, monkeypatch):  # noqa: F811
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from api.db import base
    db_session.rollback()
    engine = create_engine(db_session.get_bind().url, pool_size=1, max_overflow=0, pool_timeout=.2)
    monkeypatch.setattr(base, "_SessionLocal", sessionmaker(bind=engine, autoflush=False, expire_on_commit=False))
    try:
        for fmt in ("csv", "xlsx"):
            response = analyst.get("/api/assets/assets/export", params={"format": fmt})
            assert response.status_code == 200
    finally:
        engine.dispose()
