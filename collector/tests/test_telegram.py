import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from stools_threat_collector.adapters import telegram


def test_catches_up_outage_older_than_rescan_window_and_retractions(monkeypatch):
    now = datetime.now(timezone.utc)
    def message(id, days):
        return SimpleNamespace(id=id, date=now-timedelta(days=days), message='CVE-2026-12345 original',
                               edit_date=None, fwd_from=None)
    class Client:
        def __init__(self, *args, **kwargs):
            pass
        async def connect(self):
            pass
        async def disconnect(self):
            pass
        async def is_user_authorized(self):
            return True
        async def iter_messages(self, channel, limit):
            assert limit is None
            for value in [message(112, 0), message(111, 10), message(110, 11), message(100, 12)]:
                yield value
        async def get_messages(self, channel, ids):
            assert ids == 109
    monkeypatch.setattr(telegram, 'TelegramClient', Client)
    monkeypatch.setattr(telegram, 'credentials', lambda: ('session', 1, 'secret'))
    docs, checkpoint = asyncio.run(telegram.collect_async({'url': 'https://t.me/public_channel'},
        {'last_id': 100, 'recent': {'109': {'url': 'https://t.me/public_channel/109', 'date': (now-timedelta(days=2)).isoformat()}}}))
    assert {item['external_id'] for item in docs} == {'112', '111', '110', '109'}
    assert next(item for item in docs if item['external_id'] == '109')['retracted']
    assert checkpoint['last_id'] == 112
    assert set(checkpoint['recent']) == {'112'}
