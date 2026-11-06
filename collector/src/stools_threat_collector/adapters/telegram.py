import asyncio
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from telethon import TelegramClient

from .rss import CVE


def credentials():
    api_id = int(Path(os.environ["COLLECTOR_TELEGRAM_API_ID_FILE"]).read_text().strip())
    api_hash = Path(os.environ["COLLECTOR_TELEGRAM_API_HASH_FILE"]).read_text().strip()
    session = str(Path(os.environ.get("COLLECTOR_DATA_DIR", "/data")) / "telegram")
    return session, api_id, api_hash


async def collect_async(source, checkpoint):
    parts = urlsplit(source["url"])
    if parts.hostname != "t.me" or not re.fullmatch(r"/[A-Za-z][A-Za-z0-9_]{3,}", parts.path):
        raise ValueError("public Telegram channel URL required")
    channel = parts.path.lstrip("/")
    client = TelegramClient(*credentials(), flood_sleep_threshold=0)
    await client.connect()
    try:
        if not await client.is_user_authorized():
            raise ValueError("Telegram login required on collector")
        cutoff = datetime.now(timezone.utc) - timedelta(days=7 if checkpoint else 30)
        documents, seen = [], {}
        previous_id = checkpoint.get("last_id", 0)
        last_id = previous_id
        async for message in client.iter_messages(channel, limit=None):
            if message.date < cutoff and (not checkpoint or message.id <= previous_id):
                break
            if not message.message:
                continue
            text = message.message
            url = f"https://t.me/{channel}/{message.id}"
            last_id = max(last_id, message.id)
            if message.date >= cutoff:
                seen[str(message.id)] = {"url": url, "date": message.date.isoformat()}
            links = re.findall(r"https?://[^\s<>]+", text)[:100]
            if message.fwd_from and message.fwd_from.channel_post and message.fwd_from.from_id:
                links.append(f"telegram-forward:{message.fwd_from.from_id}:{message.fwd_from.channel_post}")
            documents.append({"external_id": str(message.id), "url": url, "title": text.splitlines()[0][:2000],
                              "text": text[:262144], "published_at": message.date.isoformat(),
                              "updated_at": message.edit_date.isoformat() if message.edit_date else None,
                              "identifiers": sorted(set(CVE.findall(text.upper())))[:500],
                              "links": links[:100], "full_text": True, "truncated": len(text) > 262144})
        for id_, previous in checkpoint.get("recent", {}).items():
            if id_ in seen or datetime.fromisoformat(previous["date"]) < cutoff:
                continue
            message = await client.get_messages(channel, ids=int(id_))
            if message is None:
                documents.append({"external_id": id_, "url": previous["url"], "title": "Removed message", "retracted": True})
        return documents, {"recent": seen, "last_id": last_id}
    finally:
        await client.disconnect()


def collect(source, checkpoint, fetcher):
    return asyncio.run(asyncio.wait_for(collect_async(source, checkpoint), timeout=120))
