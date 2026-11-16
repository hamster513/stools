import datetime as dt
import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

IDENTIFIER = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|BDU[:\-]\d{4}[-:]\d{3,})\b", re.IGNORECASE)


def extract_identifiers(value: Any) -> Any:
    return sorted({match.upper() for match in IDENTIFIER.findall(value)})


def date(value: Any) -> Any:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(value))
        return parsed.replace(tzinfo=dt.UTC) if parsed.tzinfo is None else parsed.astimezone(dt.UTC)
    except ValueError:
        return None


def canonical_url(value: Any) -> Any:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        return value
    query = urlencode(sorted((key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True)
                             if not key.lower().startswith("utm_") and key.lower() not in ("fbclid", "gclid", "mc_cid", "mc_eid")))
    return urlunsplit((parts.scheme, parts.netloc.lower(), parts.path.rstrip("/"), query, ""))


def period_bounds(period: str = "7d", tz: str = "Europe/Moscow", date_from: str = "", date_to: str = "", now: Any = None) -> Any:
    now = now or dt.datetime.now(dt.UTC)
    try:
        zone = ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("неизвестный часовой пояс") from exc
    if period not in ("today", "24h", "3d", "7d", "30d", "90d", "custom", "all"):
        raise ValueError("неизвестный период")
    if period == "custom":
        try:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_from) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_to):
                raise ValueError
            first, last = dt.date.fromisoformat(date_from), dt.date.fromisoformat(date_to)
            if first > last:
                raise ValueError
            start = dt.datetime.combine(first, dt.time(), zone).astimezone(dt.UTC)
            end = dt.datetime.combine(last + dt.timedelta(days=1), dt.time(), zone).astimezone(dt.UTC)
        except (ValueError, OverflowError) as exc:
            raise ValueError("укажите корректные даты начала и окончания YYYY-MM-DD") from exc
        return start, end
    if period == "24h":
        return now - dt.timedelta(hours=24), None
    if period == "today":
        return now.astimezone(zone).replace(hour=0, minute=0, second=0, microsecond=0).astimezone(dt.UTC), None
    return (now - dt.timedelta(days=int(period[:-1])) if period != "all" else None), None


def period_evidence(evidence: Any, now: Any = None, period: str = "7d", tz: str = "Europe/Moscow", date_from: str = "", date_to: str = "", include_excluded: bool = False) -> Any:
    now = now or dt.datetime.now(dt.UTC)
    start, end = period_bounds(period, tz, date_from, date_to, now)
    result = []
    for entry in evidence:
        published = date(entry.get("published_at"))
        if published is None and include_excluded and period == "all":
            result.append(entry)
            continue
        if ((include_excluded or (not entry.get("retracted") and not entry.get("rejected") and not entry.get("suppressed") and (entry.get("included_manually") or entry.get("classification", {}).get("category") != "background"))) and published is not None
                and published <= now and (start is None or published >= start) and (end is None or published < end)):
            result.append(entry)
    return sorted(result, key=lambda entry: date(entry.get("published_at")) or dt.datetime.min.replace(tzinfo=dt.UTC), reverse=True)


def publisher_key(entry: Any) -> str:
    publisher = entry.get("publisher_id")
    return publisher if publisher and publisher != "unknown" else urlsplit(entry.get("url", "")).netloc.lower()


def is_news(entry: Any) -> bool:
    return entry.get("origin_adapter") == "rss" or entry.get("evidence_kind") == "news"


def _reporting_markers(entry: Any) -> tuple[str, set[str], set[str]]:
    """Content-only markers; analyst decisions remain specific to each CVE."""
    url = canonical_url(entry["url"]) if entry.get("url") else ""
    keys = set()
    publisher = publisher_key(entry)
    if publisher:
        keys.add("publisher:" + publisher)
    if url:
        keys.add("url:" + url)
    text = re.sub(r"\s+", " ", entry.get("text", "")).strip().lower()
    if text:
        content = text if len(text) >= 80 else text + " " + entry.get("title", "").strip().lower()
        keys.add("text:" + hashlib.sha256(content.encode()).hexdigest())
    return url, keys, {canonical_url(link) for link in entry.get("links", []) if link}


def evaluate(evidence: Any, now: Any = None, period: str = "7d", tz: str = "Europe/Moscow", date_from: str = "", date_to: str = "",
             *, marker_cache: dict | None = None) -> Any:
    now = now or dt.datetime.now(dt.UTC)
    current = period_evidence(evidence, now, period, tz, date_from, date_to)
    exploited = [e for e in current if e.get("exploitation_verified") or
                 (e.get("exploitation_confirmed") and e.get("evidence_kind") in ("kev", "vendor"))]
    parents = list(range(len(current)))

    def root(index: Any) -> Any:
        while parents[index] != index:
            index = parents[index]
        return index

    # There is nothing to deduplicate for a single publication. For batches,
    # reuse content markers of publications shared by several CVEs; never cache
    # decisions or period results. The caller discards the cache after a batch.
    if len(current) > 1:
        features = []
        for entry in current:
            key = (entry.get("publication_id"), entry.get("revision"))
            value = marker_cache.get(key) if marker_cache is not None and key[0] is not None else None
            if value is None:
                value = _reporting_markers(entry)
                if marker_cache is not None and key[0] is not None:
                    marker_cache[key] = value
            features.append(value)
        # Shared CVE/catalog/vendor references do not imply a reprint.
        article_urls = {feature[0] for entry, feature in zip(current, features)
                        if entry.get("evidence_kind") not in ("kev", "vendor", "advisory")
                        and entry.get("origin_adapter") not in ("kev", "msrc", "github") and feature[0]}
        markers: dict[str, int] = {}
        for index, (_, base_keys, links) in enumerate(features):
            keys = base_keys | {"url:" + url for url in links & article_urls}
            for key in keys:
                if key in markers:
                    parents[root(index)] = root(markers[key])
                else:
                    markers[key] = index
    independent = {root(index) for index, item in enumerate(current) if item.get("independent")}
    active = bool(exploited) or len(independent) >= 2
    reason = "confirmed_exploitation" if exploited else "independent_reports" if active else "needs_review"
    group_dates: dict[int, dt.datetime] = {}
    for index, item in enumerate(current):
        if item.get("independent"):
            key = root(index)
            published = date(item["published_at"])
            group_dates[key] = max(group_dates.get(key, published), published)
    qualifying_dates = [date(e["published_at"]) for e in exploited]
    if len(group_dates) >= 2:
        qualifying_dates.append(sorted(group_dates.values(), reverse=True)[1])
    expires_base = max(qualifying_dates, default=None)
    latest = date(current[0]["published_at"]) if current else None
    return {"active": active, "reason": reason, "independent_sources": len(independent),
            "publication_count": len(current), "publisher_count": len({publisher_key(e) for e in current if publisher_key(e)}),
            "news_count": sum(is_news(e) for e in current),
            "last_event_at": latest.isoformat() if latest else None,
            "active_until": (expires_base + dt.timedelta(days=7)).isoformat() if expires_base else None}


def publication_fingerprint(value: Any) -> Any:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
