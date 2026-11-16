import datetime as dt
from typing import Any

from sqlalchemy import Text, and_, case, func, or_, select
from sqlalchemy.orm import Session

from api.modules.vm.models import VmHost, VmHostCve, VmImage, VmImageCve, VmImport
from api.modules.vm.trend_models import (
    VmTrendCard,
    VmTrendEnrichment,
    VmTrendEvidence,
    VmTrendIngestState,
    VmTrendPublication,
    VmTrendReview,
)
from api.platform.findings.models import FindingState

from .analyze import evidence_context, evidence_for, publication_period_conditions, refresh_cards
from .applicability import evaluate_applicability
from .poc import list_pocs
from .policies import visible_match
from .rules import (
    IDENTIFIER,
    date,
    evaluate,
    extract_identifiers,
    is_news,
    period_bounds,
    period_evidence,
    publication_fingerprint,
)
from .severity import card_severities


def match_aggregates(card_ids: Any) -> Any:
    hosts = select(VmHostCve.cve_id.label("identifier"), func.count().label("count"), func.max(VmHostCve.risk).label("risk")).where(VmHostCve.cve_id.in_(card_ids), visible_match(VmHostCve.cve_id, VmHostCve.host_id, "host")).group_by(VmHostCve.cve_id).subquery()
    images = select(func.upper(VmImageCve.cve_id).label("identifier"), func.count(func.distinct(VmImageCve.image_id)).label("count"),
                    func.max(VmImageCve.risk).label("risk")).where(func.upper(VmImageCve.cve_id).in_(card_ids), visible_match(VmImageCve.cve_id, VmImageCve.image_id, "image", VmImageCve.package)).group_by(func.upper(VmImageCve.cve_id)).subquery()
    return hosts, images


def card_view(card: Any, hosts: Any=0, images: Any=0, risk: Any=0) -> Any:
    return {"id": card.id, "title": card.title, "source_name": "", "source_url": "", "status": card.status, "version": card.version,
            "active": card.status != "rejected" and card.active_until is not None and card.active_until > dt.datetime.now(dt.UTC),
            "active_until": card.active_until, "last_event_at": card.last_event_at, "reason": card.reason,
            "independent_sources": card.independent_sources, "hosts": hosts, "images": images, "risk": risk or 0}


def period_card_view(card: Any, evidence: Any, now: Any, period: str, tz: str, date_from: str, date_to: str, archive: bool = False, marker_cache: dict | None = None) -> Any:
    current = period_evidence(evidence, now, period, tz, date_from, date_to, include_excluded=archive)
    result = {**card_view(card), **evaluate(current, now, period, tz, date_from, date_to, marker_cache=marker_cache), "period": period}
    result["active"] = result["active"] and card.status != "rejected"
    news = [entry for entry in current if is_news(entry) and entry.get("title")]
    titled = news or [entry for entry in current if entry.get("title")]
    if titled:
        result["title"] = titled[0]["title"]
        result["source_name"] = titled[0].get("source_name") or titled[0].get("publisher_id") or ""
        result["source_url"] = titled[0].get("url") or ""
    if archive:
        result.update(publication_count=len(current), last_event_at=current[0].get("published_at") if current else None)
    return result, current


def list_cards(db: Session, view: Any="matched", q: Any="", active: Any=True, limit: Any=50, offset: Any=0, region: Any="", language: Any="", reason: Any="", publisher: Any="", status: Any="", sort: Any="priority",
               period: str = "7d", tz: str = "Europe/Moscow", date_from: str = "", date_to: str = "", source_id: str = "", product: str = "", poc_state: str = "", from_archive: bool = False) -> Any:
    now = dt.datetime.now(dt.UTC)
    period_bounds(period, tz, date_from, date_to, now)
    state = db.get(VmTrendIngestState, 1)
    if not state or not state.active_generation:
        return {"items": [], "total": 0, "received_at": None, "period": period, "tz": tz}
    generation = state.active_generation
    publication = select(VmTrendEvidence.card_id).join(VmTrendPublication).where(
        VmTrendPublication.generation == generation, *publication_period_conditions(period, tz, date_from, date_to, now))
    if from_archive:
        publication = publication.where(VmTrendPublication.data["offline_archive"].as_boolean().is_(True))
    conditions = [VmTrendCard.id.in_(publication)]
    if view == "mentions":
        # extract_identifiers returns canonical uppercase IDs. Drop signal cards
        # before reading their publication bodies, retaining CVE/GHSA/BDU IDs.
        pattern = "^" + IDENTIFIER.pattern.replace(r"\b", "").replace("a-z", "A-Z") + "$"
        conditions.append(VmTrendCard.id.op("~")(pattern))
    if source_id:
        # Narrow candidates in SQL; retain all publishers' evidence for each CVE.
        conditions.append(VmTrendCard.id.in_(publication.where(VmTrendPublication.source_id == source_id)))
    if q:
        needle = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        title_match = publication.where(VmTrendPublication.data["title"].astext.ilike(needle))
        conditions.append(or_(VmTrendCard.id.ilike(needle), VmTrendCard.title.ilike(needle), VmTrendCard.id.in_(title_match)))
    if view == "review":
        conditions.append(VmTrendCard.status == "new")
    if status:
        conditions.append(VmTrendCard.status == status)
    if product:
        needle = "%"+product.replace("%", "\\%").replace("_", "\\_")+"%"
        metadata = select(VmTrendEnrichment.external_id).where(VmTrendEnrichment.generation==generation,
            VmTrendEnrichment.data["affected_products"].cast(Text).ilike(needle))
        conditions.append(or_(VmTrendCard.title.ilike(needle),func.concat("cve:",VmTrendCard.id).in_(metadata)))
    cards = list(db.scalars(select(VmTrendCard).where(*conditions)))
    selected = {}
    context = evidence_context(db, generation) if cards else None
    # A month can include tens of thousands of CVEs with full article bodies.
    # Keep only one evidence batch in memory; pagination still uses the full result.
    for start in range(0, len(cards), 100):
        batch = cards[start:start+100]
        evidence = evidence_for(db, [card.id for card in batch], generation, period, tz, date_from, date_to, now, context=context)
        marker_cache: dict = {}
        for card in batch:
            card_evidence = evidence[card.id]
            if from_archive:
                card_evidence = [entry for entry in card_evidence if entry.get("offline_archive")]
            result, current = period_card_view(card, card_evidence, now, period, tz, date_from, date_to, archive=view=="archive", marker_cache=marker_cache)
            if not current or (view in ("all", "matched") and not result["active"]):
                continue
            if view == "review" and result["active"]:
                continue
            if view == "mentions" and extract_identifiers(card.id) != [card.id]:
                continue
            if poc_state and not any(p["effective_state"]==poc_state for p in list_pocs(db,card.id)):
                continue
            if reason and result["reason"] != reason:
                continue
            if not any(all(not value or entry.get(field) == value for field, value in (
                    ("region", region), ("language", language), ("publisher_id", publisher), ("source_id", source_id))) for entry in current):
                continue
            selected[card.id] = result
    def order(item: Any) -> Any:
        timestamp = date(item["last_event_at"]).timestamp() if date(item["last_event_at"]) else 0
        primary = {"date": -timestamp, "identifier": item["id"],
                   "impact": -(item["hosts"] + item["images"])}.get(sort, -int(item["reason"] == "confirmed_exploitation"))
        return primary, -int(item["reason"] == "confirmed_exploitation"), -item["risk"], -timestamp, item["id"]
    matching_ids = list(selected)
    if view != "matched" and sort in ("date", "identifier"):
        ordered = sorted(selected.values(), key=order)
        # Risk only breaks ties after date/reason (or the unique identifier).
        # Include the complete boundary groups before slicing: ranking within
        # those groups still uses every candidate's actual host/image risk.
        heads = {order(item)[:2] for item in ordered[offset:offset+limit]}
        matching_ids = [item["id"] for item in ordered if order(item)[:2] in heads]
    if matching_ids:
        hosts, images = match_aggregates(matching_ids)
        rows = db.execute(select(VmTrendCard.id, func.coalesce(hosts.c.count, 0), func.coalesce(images.c.count, 0),
            func.greatest(func.coalesce(hosts.c.risk, 0), func.coalesce(images.c.risk, 0))).outerjoin(
            hosts, hosts.c.identifier == VmTrendCard.id).outerjoin(images, images.c.identifier == VmTrendCard.id)
            .where(VmTrendCard.id.in_(matching_ids)))
        for card_id, host_count, image_count, risk in rows:
            selected[card_id].update(hosts=host_count, images=image_count, risk=risk or 0)
    items = [item for item in selected.values() if view != "matched" or item["hosts"] or item["images"]]
    items.sort(key=order)
    page = items[offset:offset+limit]
    severities = card_severities(db, [item["id"] for item in page], generation)
    return {"items": [{**item, **severities[item["id"]]} for item in page], "total": len(items), "received_at": state.received_at, "period": period, "tz": tz}


def detail(db: Session, card_id: Any, period: str = "7d", tz: str = "Europe/Moscow", date_from: str = "", date_to: str = "") -> Any:
    now = dt.datetime.now(dt.UTC)
    period_bounds(period, tz, date_from, date_to, now)
    card = db.get(VmTrendCard, card_id)
    if card is None:
        raise KeyError(card_id)
    state = db.get(VmTrendIngestState, 1)
    evidence = evidence_for(db, [card_id], state.active_generation if state else "", period, tz, date_from, date_to, now, include_retracted=True)[card_id]
    result, _ = period_card_view(card, evidence, now, period, tz, date_from, date_to)
    # Audit/restore controls must retain excluded entries within the chosen period.
    evidence = period_evidence(evidence, now, period, tz, date_from, date_to, include_excluded=True)
    result.update(card_severities(db, [card_id], state.active_generation if state else "")[card_id])
    local = matches(db, card_id)
    result.update(hosts=local["host_total"], images=db.scalar(select(func.count(func.distinct(VmImageCve.image_id))).where(
        func.upper(VmImageCve.cve_id) == card_id.upper())) or 0)
    metadata_row = db.get(VmTrendEnrichment, (state.active_generation, "cve:"+card_id)) if state and state.active_generation else None
    metadata = metadata_row.data if metadata_row and not metadata_row.retracted else None
    applicability = []
    if metadata:
        for host in local["hosts"]:
            applicability.append(evaluate_applicability({"local_ref":"host:"+str(host["id"])},metadata,exact_scanner=True))
        for image in local["images"]:
            applicability.append(evaluate_applicability({"local_ref":"image:"+str(image["id"]),"version":image["installed_version"]},metadata,exact_scanner=True))
        products = {r.get("product", "").lower() for r in metadata.get("cpe_matches", []) if r.get("product") not in (None,"","*")}
        if products:
            for image, pair in db.execute(select(VmImage, VmImageCve).join(VmImageCve).where(func.lower(VmImageCve.package).in_(products)).limit(100)):
                if pair.cve_id.upper() == card_id.upper():
                    continue
                # Current Harbor import has no vendor/ecosystem, so keep unknown explicitly.
                item = {"local_ref":"image:"+str(image.id),"product":pair.package,"version":pair.installed_version,"vendor":"","ecosystem":"unknown"}
                applicability.append({**evaluate_applicability(item,metadata),"product":pair.package,"version":pair.installed_version})
    reviews = db.scalars(select(VmTrendReview).where(VmTrendReview.card_id == card_id).order_by(VmTrendReview.id.desc()).limit(100))
    return {**result, "pocs": list_pocs(db, card_id), "enrichment": metadata, "applicability": applicability, "evidence": [{**entry, "text": entry.get("text", "")[:6000]} for entry in evidence[:100]],
            "evidence_total": len(evidence), "matches": local, "candidates": candidates(db, evidence),
            "reviews": [{"actor": row.actor, "at": row.created_at, "decision": row.decision} for row in reviews]}


def candidates(db: Session, evidence: Any) -> Any:
    # Product hints are explicitly weaker than identifier matches. No version
    # comparison across package ecosystems is inferred from a product name.
    products = sorted({e.get("analysis", {}).get("product", "").strip() for e in evidence
                       if not e.get("rejected") and not e.get("retracted")})
    result = []
    for product in products[:20]:
        if len(product) < 4:
            continue
        needle = "%" + product.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        for host in db.scalars(select(VmHost).where(VmHost.os_name.ilike(needle)).limit(20)):
            result.append({"type": "host", "id": host.id, "name": host.hostname, "product": product,
                           "reason": "Название продукта встречается в ОС; версия и наличие уязвимости не подтверждены"})
        rows = db.execute(select(VmImage, VmImageCve.package).join(VmImageCve).where(
            func.lower(VmImageCve.package) == product.lower()).distinct().limit(20))
        for image, package in rows:
            result.append({"type": "image", "id": image.id, "name": image.project + "/" + image.repository,
                           "product": package, "reason": "Совпало имя пакета; экосистема и затронутая версия требуют проверки"})
    return result[:100]


def matches(db: Session, card_id: Any, limit: Any=100, offset: Any=0) -> Any:
    host_query = select(VmHost, VmHostCve.risk, func.coalesce(FindingState.status, "new")).join(VmHostCve).outerjoin(
        FindingState, and_(FindingState.module == "vm", FindingState.scope_id == 0,
                          FindingState.key == func.concat(VmHost.hostname, "|", VmHost.ip, "|", VmHostCve.cve_id)))
    host_query = host_query.where(VmHostCve.cve_id == card_id, visible_match(VmHostCve.cve_id, VmHostCve.host_id, "host"))
    host_total = db.scalar(select(func.count()).select_from(host_query.subquery()))
    host_rows = db.execute(host_query.order_by(case((FindingState.status.in_(["risk_accepted", "resolved", "false_positive"]), 1), else_=0),
        VmHostCve.risk.desc(), VmHost.id).offset(offset).limit(limit)).all()
    image_query = select(VmImage, VmImageCve).join(VmImageCve).where(func.upper(VmImageCve.cve_id) == card_id.upper(), visible_match(VmImageCve.cve_id, VmImageCve.image_id, "image", VmImageCve.package))
    image_total = db.scalar(select(func.count()).select_from(image_query.subquery()))
    image_rows = db.execute(image_query.order_by(VmImageCve.risk.desc().nulls_last(), VmImage.id).offset(offset).limit(limit)).all()
    imported = db.scalar(select(VmImport).order_by(VmImport.id.desc()).limit(1))
    any_images = db.scalar(select(VmImage.id).limit(1))
    return {"host_total": host_total, "image_finding_total": image_total,
        "hosts": [{"id": host.id, "hostname": host.hostname, "ip": host.ip, "os": host.os_name,
                   "risk": risk, "status": status} for host, risk, status in host_rows],
        "images": [{"id": image.id, "name": image.project + "/" + image.repository, "digest": image.digest,
                    "package": pair.package, "installed_version": pair.installed_version, "fixed_version": pair.fixed_version,
                    "risk": pair.risk, "scanned_at": image.scanned_at, "synced_at": image.synced_at,
                    "scan_status": image.scan_status, "sync_error": image.sync_error} for image, pair in image_rows],
        "host_data_at": imported.finished_at if imported else None,
        "coverage": "loaded" if imported or any_images else "insufficient"}


def review(db: Session, card_id: Any, payload: Any, actor: Any) -> Any:
    card = db.get(VmTrendCard, card_id, with_for_update=True)
    if card is None:
        raise KeyError(card_id)
    if card.version != payload.version:
        raise ValueError("карточка изменена другим аналитиком, обновите её")
    if payload.include_background is not None and not payload.note.strip():
        raise ValueError("Укажите причину изменения классификации")
    decision = payload.model_dump(exclude={"version"}, exclude_unset=True)
    state = db.get(VmTrendIngestState, 1)
    if state is None or not state.active_generation:
        raise ValueError("нет принятой истории сборщика")
    if payload.publication_key:
        publication = db.scalar(select(VmTrendPublication).join(VmTrendEvidence).where(
            VmTrendEvidence.card_id == card_id, VmTrendPublication.external_id == payload.publication_key,
            VmTrendPublication.generation == state.active_generation, VmTrendPublication.revision == payload.revision))
        if publication is None:
            raise ValueError("версия публикации изменилась, обновите карточку")
        decision["fingerprint"] = publication_fingerprint(publication.data)
        if payload.linked_identifier:
            linked = db.get(VmTrendCard, payload.linked_identifier)
            if linked is None:
                linked = VmTrendCard(id=payload.linked_identifier, title=publication.data.get("title", payload.linked_identifier))
                db.add(linked)
                db.flush()
            if linked.id != card_id:
                db.add(VmTrendReview(card_id=linked.id, actor=actor, decision=decision))
                linked.version += 1
            if db.get(VmTrendEvidence, (linked.id, publication.id)) is None:
                db.add(VmTrendEvidence(card_id=linked.id, publication_id=publication.id))
    elif payload.confirm_exploitation or payload.independent or payload.linked_identifier:
        raise ValueError("выберите публикацию для подтверждения или связи")
    if payload.status:
        card.status = payload.status
    db.add(VmTrendReview(card_id=card_id, actor=actor, decision=decision))
    card.version += 1
    db.flush()
    refresh_cards(db, [card_id] + ([payload.linked_identifier] if payload.linked_identifier else []), state.active_generation)
    db.commit()
    return detail(db, card_id)


def badges(db: Session, identifiers: Any) -> Any:
    now = dt.datetime.now(dt.UTC)
    state = db.get(VmTrendIngestState, 1)
    if not state or not state.active_generation:
        return {}
    cards = list(db.scalars(select(VmTrendCard).where(VmTrendCard.id.in_([value.upper() for value in identifiers]),
                                                   VmTrendCard.status != "rejected")))
    evidence = evidence_for(db, [card.id for card in cards], state.active_generation, "7d", now=now)
    found = {}
    for card in cards:
        result = evaluate(evidence[card.id], now)
        if result["active"]:
            found[card.id] = {"id": card.id, "reason": result["reason"], "active_until": result["active_until"]}
    return {value: found[value.upper()] for value in identifiers if value.upper() in found}
