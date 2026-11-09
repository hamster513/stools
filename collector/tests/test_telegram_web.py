from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit
import httpx
import pytest
from stools_threat_collector.adapters.telegram_web import collect, normalize_channel, parse_posts
from stools_threat_collector.monitoring_contracts import CollectionWindow

@pytest.mark.parametrize('value',['@SecLabNews','SecLabNews','https://t.me/SecLabNews','https://t.me/s/SecLabNews'])
def test_normalizes_channel_inputs(value):
    assert normalize_channel(value) == 'seclabnews'

def page(ids):
    return '<div class="tgme_channel_history">'+''.join(f'''<div class="tgme_widget_message" data-post="news/{i}">
    <div class="tgme_widget_message_text">CVE-2026-12345 exploited
    <div class="tgme_widget_message_reply">CVE-2000-99999</div></div>
    <a class="tgme_widget_message_date" href="https://t.me/news/{i}"><time datetime="2026-11-06T12:00:00+00:00"></time></a></div>''' for i in ids)+'</div>'

def test_original_date_permalink_no_nested_reply():
    doc = parse_posts(page([3]), 'news')[0]
    assert doc['url'] == 'https://t.me/news/3'
    assert doc['published_at'].startswith('2026-11-06')
    assert doc['identifiers'] == ['CVE-2026-12345']

def test_layout_change_is_not_empty_success():
    with pytest.raises(ValueError): parse_posts('<html>Channel blocked</html>', 'news')
    assert parse_posts('<div class="tgme_channel_history"></div>', 'news') == []

def test_more_than_three_pages_never_skips_middle_posts(monkeypatch):
    monkeypatch.setattr('stools_threat_collector.adapters.telegram_web.time.sleep', lambda _:None)
    class Fetcher:
        def get(self, url):
            before = int(parse_qs(urlsplit(url).query).get('before', ['11'])[0])
            return httpx.Response(200, text=page(list(range(max(1,before-2),before))))
    cp = {'last_id':1}; seen=set(); now=datetime(2026,11,7,tzinfo=timezone.utc)
    first = collect({'url':'https://t.me/news'}, cp, Fetcher(), now=now)
    assert first.continuation and first.checkpoint['last_id'] == 1
    seen.update(d['external_id'] for d in first.documents)
    second = collect({'url':'https://t.me/news'}, first.checkpoint, Fetcher(), now=now)
    seen.update(d['external_id'] for d in second.documents)
    assert not second.continuation and second.checkpoint['last_id'] == 10
    assert seen == {str(i) for i in range(1,11)}
    assert all(not d.get('retracted') for d in second.documents)


def test_first_preview_obeys_cutoff_and_explicit_upper_bound(monkeypatch):
    monkeypatch.setattr('stools_threat_collector.adapters.telegram_web.time.sleep', lambda _:None)
    class Fetcher:
        def __init__(self,body): self.body=body;self.calls=0
        def get(self,url): self.calls+=1; return httpx.Response(200,text=self.body)
    now=datetime(2026,11,7,tzinfo=timezone.utc)
    old=Fetcher(page([400]).replace('2026-11-06','2020-01-01'))
    result=collect({'url':'https://t.me/news'},{},old,now=now)
    assert not result.documents and not result.continuation and old.calls==1
    future=Fetcher(page([1]))
    result=collect({'url':'https://t.me/news'},{},future,CollectionWindow(date_to='2026-10-01T00:00:00Z'),now=now)
    assert not result.documents


def test_edit_url_wins_over_stored_telegram_channel():
    from stools_threat_collector.monitoring_contracts import SourceConfigV2
    source=SourceConfigV2.model_validate({'name':'news','publisher_id':'news','adapter':'telegram',
        'url':'https://t.me/newchannel','telegram_channel':'oldchannel'})
    assert source.telegram_channel=='newchannel' and source.url=='https://t.me/newchannel'
