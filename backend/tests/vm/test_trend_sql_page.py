import datetime as dt
from sqlalchemy import select
from api.modules.vm.services.trends import query, analyze
from api.modules.vm.services.trends.ingest import apply_page
from api.modules.vm.trend_models import VmTrendPublication, VmTrendPolicy
from tests.vm.test_trends_api import news_page
from tests.vm.test_trend_list_performance import seed


def test_mentions_reads_bodies_only_for_page(db_session, monkeypatch):
    seed(db_session, 125)
    original = query.evidence_for
    loaded = []

    def capture(db, ids, *args, **kwargs):
        loaded.extend(ids)
        return original(db, ids, *args, **kwargs)

    monkeypatch.setattr(query, "evidence_for", capture)
    result = query.list_cards(db_session, view="mentions", sort="date", limit=10, offset=100)
    assert result["total"] == 125 and len(result["items"]) == 10
    assert len(loaded) <= 10


def test_sql_page_matches_exact_period_and_legacy(db_session):
    now = dt.datetime.now(dt.UTC)
    records = [
        {
            "identifiers": [f"CVE-2026-{40000 + i}"],
            "title": f"Security CVE-2026-{40000 + i}",
            "published_at": (now - dt.timedelta(days=i % 10)).isoformat(),
        }
        for i in range(90)
    ]
    records[0]["published_at"] = (now + dt.timedelta(days=1)).isoformat()
    apply_page(db_session, news_page(records))
    analyze.process_pending(db_session)
    for period in ("24h", "7d", "30d", "all"):
        for sort in ("date", "identifier"):
            options = dict(view="mentions", period=period, sort=sort, offset=8, limit=7, _now=now)
            assert query.list_cards(db_session, **options) == query.list_cards(
                db_session, **options, _fast=False
            )


def test_sql_page_preserves_exclusions_and_publication_decisions(auth_client, db_session):
    seed(db_session, 65)
    for i in range(3):
        identifier = f"CVE-2026-{20000 + i}"
        detail = auth_client.get("/api/vm/trends/" + identifier + "?period=all").json()
        evidence = detail["evidence"][0]
        assert (
            auth_client.patch(
                "/api/vm/trends/" + identifier + "/review",
                json={
                    "version": detail["version"],
                    "publication_key": evidence["publication_key"],
                    "revision": evidence["revision"],
                    "rejected": True,
                },
            ).status_code
            == 200
        )
    db_session.add(
        VmTrendPolicy(
            scope="cve_global",
            target_key="CVE-2026-20003",
            reason="test",
            enabled=True,
            actor="test",
            history=[],
        )
    )
    db_session.commit()
    now = dt.datetime.now(dt.UTC)
    options = dict(view="mentions", sort="date", offset=3, limit=20, _now=now)
    assert query.list_cards(db_session, **options) == query.list_cards(
        db_session, **options, _fast=False
    )


def test_sql_page_filter_and_timezone_parity(db_session):
    from sqlalchemy import text
    from api.modules.vm.trend_models import VmTrendSource, VmTrendCard

    now = dt.datetime.now(dt.UTC)
    records = [
        {
            "identifiers": [f"CVE-2026-{50000 + i}"],
            "title": f"Vulnerability issue CVE-2026-{50000 + i}",
            "published_at": (now - dt.timedelta(hours=i + 1)).isoformat(),
            "offline_archive": i % 2 == 0,
        }
        for i in range(12)
    ]
    apply_page(db_session, news_page(records))
    analyze.process_pending(db_session)
    for source in db_session.scalars(select(VmTrendSource).limit(20)):
        n = int(source.external_id.split("-")[-1])
        source.data = {
            **source.data,
            "region": "RU" if n % 2 == 0 else "EU",
            "language": "ru" if n % 2 == 0 else "en",
        }
    pubs = list(
        db_session.scalars(
            select(VmTrendPublication).order_by(VmTrendPublication.external_id).limit(20)
        )
    )
    pubs[0].data = {**pubs[0].data, "published_at": now.date().isoformat()}
    pubs[1].data = {**pubs[1].data, "published_at": "2026-00-11T12:00:00Z"}
    pubs[2].data = {
        **pubs[2].data,
        "classification": {"category": "background", "identifier_roles": []},
    }
    db_session.get(VmTrendCard, "CVE-2026-50003").status = "rejected"
    db_session.add(
        VmTrendPolicy(
            scope="publication",
            target_key=pubs[4].external_id,
            reason="exclude",
            enabled=True,
            actor="test",
            history=[],
        )
    )
    db_session.commit()
    db_session.execute(text("SET LOCAL TIME ZONE 'America/New_York'"))
    cases = [
        {},
        {"region": "RU"},
        {"language": "en"},
        {"publisher": "publisher-6"},
        {"source_id": "source-7"},
        {"from_archive": True},
        {"status": "rejected"},
        {"q": "50006"},
        {"q": "Vulnerability"},
        {"offset": 1000},
        {
            "period": "custom",
            "date_from": now.date().isoformat(),
            "date_to": now.date().isoformat(),
        },
    ]
    for filters in cases:
        opts = {**dict(view="mentions", sort="date", period="all", limit=4, _now=now), **filters}
        assert query.list_cards(db_session, **opts) == query.list_cards(
            db_session, **opts, _fast=False
        ), filters


def test_pending_edit_without_identifier_uses_exact_evaluation(db_session):
    seed(db_session, 2)
    publication = db_session.scalar(
        select(VmTrendPublication).order_by(VmTrendPublication.id).limit(1)
    )
    publication.data = {
        **publication.data,
        "title": "GeForce sale",
        "text": "Smartphone prices",
        "identifiers": [],
    }
    publication.processing = "pending"
    db_session.commit()
    now = dt.datetime.now(dt.UTC)
    opts = dict(view="mentions", sort="date", _now=now)
    assert query.list_cards(db_session, **opts) == query.list_cards(db_session, **opts, _fast=False)
    assert query.list_cards(db_session, **opts)["total"] == 1


def test_noncanonical_dates_keep_python_semantics(db_session):
    from sqlalchemy import text

    seed(db_session, 9)
    dates = [
        "2026-11-17T12:00:00Z",
        "2026-11-17T24:00:00Z",
        "2026-11-17T23:59:60Z",
        "2026-11-17T12:00:00+03:30:15",
        "2026-11-17T12:00:00.1234569Z",
        "2026-11-17T12:00:00+23:00",
        "2026-11-17",
        "2026-11-17T12:00:00.123456Z",
        "2026-11-17T12:00:00z",
    ]
    pubs = db_session.scalars(
        select(VmTrendPublication).order_by(VmTrendPublication.id).limit(9)
    ).all()
    for pub, value in zip(pubs, dates):
        pub.data = {**pub.data, "published_at": value}
    db_session.commit()
    db_session.execute(text("SET LOCAL TIME ZONE 'America/New_York'"))
    now = dt.datetime(2026, 11, 18, 12, tzinfo=dt.UTC)
    for sort in ("date", "identifier"):
        for offset in (0, 2, 7):
            opts = dict(view="mentions", sort=sort, period="7d", limit=3, offset=offset, _now=now)
            assert query.list_cards(db_session, **opts) == query.list_cards(
                db_session, **opts, _fast=False
            )
