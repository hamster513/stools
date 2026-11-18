"""Local SQL pagination for discussed identifiers; read full articles for the page only.

Publication decisions and pending revisions retain the original evaluator.
They are evaluated as a separate subset, so a handful of reviews cannot disable
SQL pagination for the rest of the catalog. No cross-request cache or network IO.
"""

from sqlalchemy import (
    Boolean,
    DateTime,
    String,
    Text,
    and_,
    case,
    cast,
    column,
    func,
    literal,
    or_,
    select,
    true,
    tuple_,
    union_all,
    values,
)
from sqlalchemy.dialects.postgresql import JSONB

from api.modules.vm.trend_models import (
    VmTrendCard,
    VmTrendEvidence,
    VmTrendPublication,
    VmTrendReview,
    VmTrendSource,
)

from .rules import date, period_bounds

# Restrict SQL casts to the ISO subset parsed identically by Python and PG.
# Other representations (offset seconds, long fractions, 24:00, leap seconds)
# retain the original evaluator, including its rejection of invalid ISO values.
CANONICAL_DATE = (
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}"
    r"([T ]([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(\.[0-9]{1,6})?(Z|[+-](0[0-9]|1[0-4]):[0-5][0-9])?)?$"
)


def published_timestamp(raw):
    # PostgreSQL 16 validates before casting, including malformed legacy dates.
    # Python's date() treats naive ISO values as UTC, regardless of the DB timezone.
    aware = raw.op("~")(r"(Z|[+-][0-9]{2}:[0-9]{2})$")
    parsed = case(
        (aware, cast(raw, DateTime(timezone=True))),
        else_=func.timezone("UTC", cast(raw, DateTime(timezone=False))),
    )
    return case(
        (
            and_(
                raw.op("~")(CANONICAL_DATE),
                func.pg_input_is_valid(raw, literal("timestamp with time zone")),
            ),
            parsed,
        )
    )


def mentions_page(db, conditions, generation, now, options, state):
    from . import query as original

    context = original.evidence_context(db, generation)
    publication = VmTrendPublication
    evidence = VmTrendEvidence
    # Decode each JSON document once, before joining it to all mentioned CVEs.
    # Materialization prevents PostgreSQL from re-reading a large TOASTed article
    # for every date/category expression and every identifier in that article.
    fields = (
        func.jsonb_to_record(publication.data)
        .table_valued(
            column("published_at", Text),
            column("classification", JSONB),
            column("exploitation_confirmed", Boolean),
            column("origin_adapter", Text),
            column("evidence_kind", Text),
            column("offline_archive", Boolean),
            column("publisher_id", Text),
        )
        .render_derived(name="article_fields", with_types=True)
        .lateral()
    )
    coarse = [
        publication.generation == generation,
        *original.publication_period_conditions(
            options["period"],
            options["tz"],
            options["date_from"],
            options["date_to"],
            now,
            published_value=fields.c.published_at,
        ),
    ]
    if options["from_archive"]:
        coarse.append(fields.c.offline_archive.is_(True))
    confirmed = and_(
        fields.c.exploitation_confirmed.is_(True),
        fields.c.origin_adapter.in_(["kev", "msrc"]),
        fields.c.evidence_kind.in_(["kev", "vendor"]),
    )
    metadata = (
        select(
            publication.id,
            publication.external_id,
            publication.source_id,
            published_timestamp(fields.c.published_at).label("published"),
            fields.c.classification["category"].astext.label("category"),
            func.coalesce(confirmed, False).label("confirmed"),
            fields.c.publisher_id,
            (
                publication.data.has_key("publisher_id") if options["publisher"] else literal(False)
            ).label("has_publisher"),
        )
        .select_from(publication)
        .join(fields, true())
        .where(*coarse)
        .cte("article_metadata")
        .prefix_with("MATERIALIZED")
    )
    # The initial membership condition is supplied by article_metadata itself;
    # retaining the original subquery would decode the same articles a second time.
    candidate_ids = select(VmTrendCard.id).where(*conditions[1:]).cte("list_candidates")
    candidate = select(candidate_ids.c.id)
    exceptional = set(
        db.scalars(
            select(VmTrendReview.card_id)
            .where(
                VmTrendReview.card_id.in_(candidate),
                VmTrendReview.decision["publication_key"].astext != "",
            )
            .distinct()
        )
    )
    # process_publication creates ordinary identifier evidence only from actual
    # identifiers; classify_publication cannot label such content background.
    # An incoming revision can leave old evidence until its pending analysis runs.
    # Keep the original evaluator for these rows and all publication decisions.
    unusual = (
        select(publication.id)
        .where(
            publication.generation == generation,
            or_(
                publication.processing != "done",
                publication.data["published_at"].astext.op("!~")(CANONICAL_DATE),
            ),
        )
        .cte("unusual_dates")
        .prefix_with("MATERIALIZED")
    )
    exceptional.update(
        db.scalars(
            select(evidence.card_id)
            .join(unusual, unusual.c.id == evidence.publication_id)
            .where(evidence.card_id.in_(candidate))
            .distinct()
        )
    )
    overrides = {}
    if exceptional:
        legacy = original.list_cards(
            db,
            **{**options, "limit": len(exceptional), "offset": 0},
            _fast=False,
            _candidate_ids=exceptional,
            _now=now,
            _context=context,
        )
        overrides = {item["id"]: item for item in legacy["items"]}

    published = metadata.c.published
    start, end = period_bounds(
        options["period"], options["tz"], options["date_from"], options["date_to"], now
    )
    eligible = [
        evidence.card_id.in_(candidate),
        published.is_not(None),
        published <= now,
        func.coalesce(metadata.c.category, "uncertain") != "background",
    ]
    if exceptional:
        eligible.append(evidence.card_id.not_in(exceptional))
    if start is not None:
        eligible.append(published >= start)
    if end is not None:
        eligible.append(published < end)
    excluded_cards = [p.target_key for p in context.policies if p.scope == "cve_global"]
    excluded_publications = [p.target_key for p in context.policies if p.scope == "publication"]
    if excluded_cards:
        eligible.append(evidence.card_id.not_in(excluded_cards))
    if excluded_publications:
        eligible.append(metadata.c.external_id.not_in(excluded_publications))
    grouped = (
        select(
            evidence.card_id.label("id"),
            func.max(published).label("published"),
            func.bool_or(metadata.c.confirmed).label("confirmed"),
        )
        .join(metadata, metadata.c.id == evidence.publication_id)
        .where(*eligible)
        .group_by(evidence.card_id)
    )
    if any(options[key] for key in ("region", "language", "publisher", "source_id")):
        grouped = grouped.outerjoin(
            VmTrendSource,
            and_(
                VmTrendSource.generation == generation,
                VmTrendSource.external_id == metadata.c.source_id,
            ),
        )
        fields = {
            "region": VmTrendSource.data["region"].astext,
            "language": VmTrendSource.data["language"].astext,
            "publisher": case(
                (metadata.c.has_publisher, metadata.c.publisher_id),
                else_=VmTrendSource.data["publisher_id"].astext,
            ),
            "source_id": metadata.c.source_id,
        }
        grouped = grouped.having(
            func.bool_or(and_(*[fields[k] == options[k] for k in fields if options[k]]))
        )
    if overrides:
        override_rows = [
            (item["id"], date(item["last_event_at"]), item["reason"] == "confirmed_exploitation")
            for item in overrides.values()
        ]
        custom = values(
            column("id", String),
            column("published", DateTime(timezone=True)),
            column("confirmed", Boolean),
            name="reviewed_rank",
        ).data(override_rows)
        grouped = union_all(grouped, select(custom.c.id, custom.c.published, custom.c.confirmed))
    ranks = grouped.cte("list_ranks")
    date_order = [ranks.c.published.desc(), ranks.c.confirmed.desc()]
    # group_start keeps complete boundary ties before risk-based ordering.
    group_order = [ranks.c.id] if options["sort"] == "identifier" else date_order
    window = (
        select(
            ranks,
            func.count().over().label("total"),
            func.rank().over(order_by=group_order).label("group_start"),
        )
        .cte("ranked_page")
        .prefix_with("MATERIALIZED")
    )
    order_window = (
        [window.c.id]
        if options["sort"] == "identifier"
        else [window.c.published.desc(), window.c.confirmed.desc(), window.c.id]
    )
    boundary = (
        select(window)
        .order_by(*order_window)
        .offset(options["offset"])
        .limit(options["limit"])
        .cte("page_boundary")
    )
    if options["sort"] == "identifier":
        selected_groups = select(boundary)
    else:
        selected_groups = select(window).where(
            tuple_(window.c.published, window.c.confirmed).in_(
                select(boundary.c.published, boundary.c.confirmed)
            )
        )
    # Both references reuse ranked_page within this one statement. Re-running
    # ranks in a second SELECT would decode all matching publications again.
    group_rows = db.execute(selected_groups).mappings().all()
    if not group_rows:
        total = db.scalar(select(func.count()).select_from(ranks))
        return {
            "items": [],
            "total": total,
            "received_at": state.received_at,
            "period": options["period"],
            "tz": options["tz"],
        }
    total = group_rows[0]["total"]
    ids = [row["id"] for row in group_rows]
    # This joins only boundary groups, rather than all CVEs with local findings.
    hosts, images = original.match_aggregates(ids)
    matched = db.execute(
        select(
            VmTrendCard.id,
            func.coalesce(hosts.c.count, 0),
            func.coalesce(images.c.count, 0),
            func.greatest(func.coalesce(hosts.c.risk, 0), func.coalesce(images.c.risk, 0)),
        )
        .outerjoin(hosts, hosts.c.identifier == VmTrendCard.id)
        .outerjoin(images, images.c.identifier == VmTrendCard.id)
        .where(VmTrendCard.id.in_(ids))
    ).all()
    matches = {identifier: (h, i, r or 0) for identifier, h, i, r in matched}
    ordered = sorted(
        group_rows,
        key=lambda row: (
            (row["id"],)
            if options["sort"] == "identifier"
            else (
                -row["published"].timestamp(),
                -int(row["confirmed"]),
                -matches[row["id"]][2],
                row["id"],
            )
        ),
    )
    relative = options["offset"] - (min(row["group_start"] for row in group_rows) - 1)
    ids = [row["id"] for row in ordered[relative : relative + options["limit"]]]
    cards = {
        card.id: card for card in db.scalars(select(VmTrendCard).where(VmTrendCard.id.in_(ids)))
    }
    ordinary = [identifier for identifier in ids if identifier not in overrides]
    page_evidence = (
        original.evidence_for(
            db,
            ordinary,
            generation,
            options["period"],
            options["tz"],
            options["date_from"],
            options["date_to"],
            now,
            context=context,
        )
        if ordinary
        else {}
    )
    marker_cache = {}
    items = []
    for identifier in ids:
        if identifier in overrides:
            item = dict(overrides[identifier])
        else:
            entries = page_evidence[identifier]
            if options["from_archive"]:
                entries = [e for e in entries if e.get("offline_archive")]
            item, _ = original.period_card_view(
                cards[identifier],
                entries,
                now,
                options["period"],
                options["tz"],
                options["date_from"],
                options["date_to"],
                marker_cache=marker_cache,
            )
        item.update(zip(("hosts", "images", "risk"), matches[identifier]))
        items.append(item)
    severities = original.card_severities(db, ids, generation)
    return {
        "items": [{**item, **severities[item["id"]]} for item in items],
        "total": total,
        "received_at": state.received_at,
        "period": options["period"],
        "tz": options["tz"],
    }
