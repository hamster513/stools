"""Bounded, account-free Telegram history for the offline news archive."""
import datetime as dt
import time
from http.client import HTTPException
from urllib.error import HTTPError, URLError

from telegram_public import MAX_TEXT, normalize_channel, parse_page

TELEGRAM_PAGE_DELAY = 2


def collect_news(source, transport, mode, since, until, progress, *, lang="ru",
                 maximum=200, max_pages=50, page_delay=TELEGRAM_PAGE_DELAY):
    channel = normalize_channel(source["url"])
    report = {"id": source["id"], "name": source["name"], "kind": "news",
              "url": "https://t.me/" + channel, "status": "ok", "items": 0}
    extra = {"pages": 0, "duplicates": 0, "excluded_undated": 0,
             "excluded_outside_period": 0, "media_only": 0,
             "coverage": {"from": since.isoformat() if since else None,
                          "until": until.isoformat(), "complete": False}}
    rows, seen, errors = [], set(), []
    before = None
    reached_end = False
    for page in range(max_pages):
        if page:
            time.sleep(page_delay)
        label = "страница" if lang == "ru" else "page"
        progress(f"Telegram @{channel}: {label} {page + 1}; {len(rows)} "
                 + ("публикаций" if lang == "ru" else "posts"))
        url = f"https://t.me/s/{channel}" + (f"?before={before}" if before else "")
        try:
            documents, page_before = parse_page(transport.fetch(url, limit=8 * 1024 * 1024, timeout=30), channel)
        except HTTPError as error:
            errors.append(f"HTTP {error.code}")
            break
        except HTTPException:
            errors.append("telegram_incomplete_response")
            break
        except (TimeoutError, URLError, OSError):
            errors.append("telegram_connection_failed")
            break
        except ValueError as error:
            # Transport exposes only these fixed codes; never echo arbitrary payload/errors.
            code = str(error)
            safe = {"timeout", "proxy_error", "transport_error", "native_proxy_transport_failed",
                    "response_too_large", "incomplete_response", "redirect_limit", "unsafe_redirect"}
            errors.append(code if code in safe else "telegram_preview_unavailable_or_invalid")
            break
        extra["pages"] += 1
        if not documents:
            if page == 0:
                errors.append("telegram_no_public_posts")
            else:
                reached_end = True
            break
        if all(doc["external_id"] in seen for doc in documents):
            extra["duplicates"] += len(documents)
            errors.append("telegram_pagination_not_advancing")
            break
        # Prefer Telegram's history cursor: a pinned message can have a very old ID.
        # For previews without a pager, old pins must not hide newer update pages.
        candidates = [doc for doc in documents if doc["external_id"] not in seen
                      and since is not None and doc["published_at"]
                      and dt.datetime.fromisoformat(doc["published_at"]) > since]
        next_before = page_before or min(int(doc["external_id"]) for doc in candidates or documents)
        if page_before is None and next_before == 1:
            # ID 1 may be pinned, not the start of the history page. Verify older pages.
            higher = [int(doc["external_id"]) for doc in candidates or documents
                      if int(doc["external_id"]) > 1]
            if higher:
                next_before = min(higher)
        if before is not None and next_before >= before:
            errors.append("telegram_pagination_not_advancing")
            break
        dates, undated = [], False
        for document in documents:
            identity = document["external_id"]
            if identity in seen:
                extra["duplicates"] += 1
                continue
            seen.add(identity)
            published = (dt.datetime.fromisoformat(document["published_at"])
                         if document["published_at"] else None)
            if published:
                dates.append(published)
                if published > until or (since is not None and published <= since):
                    extra["excluded_outside_period"] += 1
                    continue
            else:
                undated = True
                if mode == "updates":
                    extra["excluded_undated"] += 1
                    continue
            if not document["text"]:
                extra["media_only"] += 1
                continue
            if len(rows) >= maximum:
                errors.append("telegram_post_limit")
                break
            links = [link for link in document["links"] if link not in document["text"]]
            text = document["text"] + ("\n\nLinks:\n" + "\n".join(links) if links else "")
            truncated = document["truncated"] or len(text) > MAX_TEXT
            if truncated:
                errors.append("telegram_post_truncated")
            rows.append({"source_id": source["id"], "external_id": identity, "kind": "news",
                         "title": document["title"], "text": text[:MAX_TEXT], "format": "article",
                         "url": document["url"], "published_at": document["published_at"],
                         "technique_ids": [], "full_text": not truncated})
        if "telegram_post_limit" in errors:
            break
        if next_before <= 1 or (since is not None and dates and not undated and max(dates) <= since):
            reached_end = True
            break
        if len(rows) >= maximum:
            errors.append("telegram_post_limit")
            break
        before = next_before
    if not reached_end and not errors:
        errors.append("telegram_page_limit")
    if extra["excluded_undated"]:
        errors.append("telegram_undated_posts_excluded")
    extra["coverage"]["complete"] = reached_end and not errors
    if errors:
        report["status"] = "partial" if extra["pages"] and "telegram_no_public_posts" not in errors else "error"
        report["error"] = "; ".join(dict.fromkeys(errors))
    report["items"] = len(rows)
    return report, rows, extra
