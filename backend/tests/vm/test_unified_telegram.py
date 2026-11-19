import datetime as dt
import importlib
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest

ROOT = Path(__file__).resolve().parents[3]
NOW = dt.datetime(2026, 11, 17, 12, tzinfo=dt.UTC)
SOURCE = {'id': 'telegram-news', 'name': 'Test Telegram', 'kind': 'telegram', 'url': 'https://t.me/news'}


def page(rows):
    return ('<div class="tgme_channel_history">'+''.join(
        f'<div class="tgme_widget_message" data-post="news/{id}"><div class="tgme_widget_message_text">{text}</div>'
        f'<a class="tgme_widget_message_date"><time datetime="{date or "unknown"}"></time></a></div>'
        for id, date, text in rows)+'</div>').encode()


@pytest.fixture
def sources(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT/'frontend/public/offline'))
    module=importlib.import_module('offline_sources')
    monkeypatch.setattr(module, 'TELEGRAM_PAGE_DELAY', 0, raising=False)
    return module


def transport(pages):
    calls=[]
    def fetch(url, limit, timeout):
        calls.append(url)
        value=pages[len(calls)-1]
        if isinstance(value, Exception):raise value
        return value
    return SimpleNamespace(fetch=fetch), calls


def test_period_pagination_dedup_and_undated_posts(sources):
    fetcher,calls=transport([
        page([(7,'2026-11-18T12:00:00Z','future'),(6,None,'undated'),(5,'2026-11-17T11:00:00Z','CVE-2026-12345')]),
        page([(5,'2026-11-17T11:00:00Z','CVE-2026-12345'),(4,'2026-11-16T12:00:00Z','boundary'),(3,'2026-11-16T11:00:00Z','older')]),
        page([]),
    ])
    report,rows,extra=sources._telegram_news(SOURCE,fetcher,'updates',NOW-dt.timedelta(days=1),NOW,lambda _:None)
    assert [r['external_id'] for r in rows]==['5']
    assert rows[0]['url']=='https://t.me/news/5' and rows[0]['full_text']
    assert calls[1].endswith('?before=5')
    assert extra['excluded_undated']==1 and extra['duplicates']==1
    assert report['status']=='partial' and extra['coverage']['from'].startswith('2026-11-16')


def test_old_pinned_post_does_not_stop_selected_history(sources):
    fetcher,calls=transport([page([(50,'2026-01-01T00:00:00Z','pinned'),(49,'2026-11-17T11:00:00Z','new')]),page([(48,'2026-11-17T10:00:00Z','also new'),(47,'2026-11-15T00:00:00Z','old')]),page([])])
    report,rows,_=sources._telegram_news(SOURCE,fetcher,'updates',NOW-dt.timedelta(days=1),NOW,lambda _:None)
    assert {r['external_id'] for r in rows}=={'49','48'} and len(calls)>=2


@pytest.mark.parametrize('failure', [HTTPError('https://t.me/news?token=private',429,'secret-password',{},None), ValueError('private-parser-detail')])
def test_later_page_failure_keeps_partial_posts_and_safe_diagnostics(sources,failure):
    fetcher,_=transport([page([(9,'2026-11-17T11:00:00Z','post')]),failure])
    messages=[]
    report,rows,extra=sources._telegram_news(SOURCE,fetcher,'full',None,NOW,messages.append)
    assert report['status']=='partial' and len(rows)==1
    assert not extra['coverage']['complete']
    output=json.dumps([report,extra,messages])
    assert 'private' not in output and 'secret-password' not in output


def test_unavailable_preview_is_error(sources):
    fetcher,_=transport([b'<html>Open in Telegram</html>'])
    report,rows,_=sources._telegram_news(SOURCE,fetcher,'full',None,NOW,lambda _:None)
    assert report['status']=='error' and not rows


def test_limits_and_nonadvancing_pages_are_partial(sources):
    body=page([(9,'2026-11-17T11:00:00Z','post')])
    fetcher,_=transport([body,body])
    report,rows,extra=sources._telegram_news(SOURCE,fetcher,'full',None,NOW,lambda _:None)
    assert report['status']=='partial' and len(rows)==1
    assert 'pagination' in report['error']
    fetcher,_=transport([body])
    report,rows,extra=sources._telegram_news(SOURCE,fetcher,'full',None,NOW,lambda _:None,max_pages=1)
    assert report['status']=='partial' and len(rows)==1


def test_news_zip_contains_telegram_posts_and_valid_manifest(sources,tmp_path):
    module=sources.intel_module()
    module.DEFAULT_SOURCES=[SOURCE]
    fetcher,_=transport([page([(1,'2026-11-17T11:00:00Z','Security issue CVE-2026-12345 <a href="https://example.org/GHSA-2345-6789-cfgh">Advisory</a>')])])
    target=tmp_path/'news.zip'
    result=sources.intel_archive('news',target,fetcher,'updates','1d',NOW,tmp_path,lambda _:None,module=module)
    from api.modules.siem.hunting.intel import read_bundle
    manifest,rows=read_bundle(target.read_bytes())
    assert len(rows)==1 and rows[0].url=='https://t.me/news/1'
    assert 'GHSA-2345-6789-cfgh' in rows[0].text
    assert result['status']=='ok' and manifest.sources[0].kind=='news'


def test_requested_channels_share_canonical_catalog_without_duplicates():
    from zipfile import ZipFile
    requested = set('wmxwas cyberok_news cyb3r53cr3t5 intosecurity ralfhackerchannel true_secator poxek unsec cyberyozh_official xor_journal haccking'.split())
    canonical = json.loads((ROOT/'collector/src/stools_threat_collector/sources.json').read_text())
    expected = [{'id': row['catalog_key'], 'name': row['name'], 'kind': 'telegram', 'url': row['url']}
                for row in canonical if row['adapter'] == 'telegram' and row['telegram_mode'] == 'web']
    actual = json.loads((ROOT/'frontend/public/offline/telegram-sources.json').read_text())
    assert actual == expected
    assert len(actual) == len({row['id'] for row in actual}) == len({row['url'].lower() for row in actual})
    assert requested <= {row['url'].rsplit('/',1)[-1].lower() for row in actual}
    with ZipFile(ROOT/'frontend/public/offline/stools-download-kit.zip') as archive:
        assert json.loads(archive.read('telegram-sources.json')) == expected
        assert archive.read('telegram_public.py') == (ROOT/'collector/src/stools_threat_collector/adapters/telegram_public.py').read_bytes()
        assert 'offline_telegram.py' in archive.namelist()


def test_default_news_includes_rss_and_all_telegram_sources(sources, monkeypatch, tmp_path):
    module = sources.intel_module()
    module.DEFAULT_SOURCES = [{'id':'rss-feed','name':'RSS','kind':'rss','url':'https://example.org/feed'}]
    monkeypatch.setattr(sources, 'intel_module', lambda: module)
    seen = []
    def collect(source, *args, **kwargs):
        seen.append(source['id'])
        return {'id':source['id'],'name':source['name'],'kind':'news','url':source['url'],'status':'ok'}, [], {}
    monkeypatch.setattr(sources, '_period_news', collect)
    monkeypatch.setattr(sources, '_telegram_news', collect)
    result = sources.intel_archive('news',tmp_path/'news.zip',None,'updates','1d',NOW,tmp_path,lambda _:None)
    expected = {'rss-feed'} | {s['id'] for s in json.loads((ROOT/'frontend/public/offline/telegram-sources.json').read_text())}
    assert set(seen) == expected and len(seen) == len(expected)
    assert result['status'] == 'ok'


def test_post_limit_preserves_partial_and_full_mode_retains_undated(sources):
    fetcher,_ = transport([page([(3,None,'unknown date'),(2,'2026-01-01T00:00:00Z','old'),(1,'2026-01-01T00:00:00Z','oldest')])])
    report,rows,extra = sources._telegram_news(SOURCE,fetcher,'full',None,NOW,lambda _:None,maximum=2)
    assert [row['external_id'] for row in rows] == ['3','2']
    assert report['status'] == 'partial' and 'post_limit' in report['error']
    assert not extra['coverage']['complete']


def test_empty_first_preview_is_not_success(sources):
    fetcher,_ = transport([page([])])
    report,rows,extra = sources._telegram_news(SOURCE,fetcher,'full',None,NOW,lambda _:None)
    assert report['status'] == 'error' and not extra['coverage']['complete']


def test_incomplete_second_response_retains_collected_posts(sources):
    from http.client import IncompleteRead
    fetcher,_ = transport([page([(9,'2026-11-17T11:00:00Z','post')]),IncompleteRead(b'private payload')])
    report,rows,extra = sources._telegram_news(SOURCE,fetcher,'full',None,NOW,lambda _:None)
    assert report['status'] == 'partial' and len(rows) == 1
    assert 'private' not in json.dumps([report,extra])


@pytest.mark.parametrize('with_pager', [True,False])
def test_old_pinned_id_one_cannot_hide_recent_history(sources,with_pager):
    first = page([(1,'2026-01-01T00:00:00Z','pinned'),(100,'2026-11-17T11:00:00Z','new')])
    if with_pager:
        first += b'<a class="tme_messages_more js-messages_more" href="/s/news?before=100" data-before="100">More</a>'
    fetcher,calls = transport([first,page([(99,'2026-11-17T10:00:00Z','older new'),(98,'2026-11-15T00:00:00Z','old')]),page([])])
    report,rows,extra = sources._telegram_news(SOURCE,fetcher,'updates',NOW-dt.timedelta(days=1),NOW,lambda _:None)
    assert {r['external_id'] for r in rows} == {'100','99'}
    assert calls[1].endswith('?before=100') and report['status'] == 'ok'


def test_repeated_page_with_pinned_id_is_partial(sources):
    body = page([(1,'2026-01-01T00:00:00Z','pinned'),(100,'2026-11-17T11:00:00Z','new')])
    fetcher,_ = transport([body,body])
    report,rows,extra = sources._telegram_news(SOURCE,fetcher,'updates',NOW-dt.timedelta(days=1),NOW,lambda _:None)
    assert report['status'] == 'partial' and not extra['coverage']['complete']
    assert [row['external_id'] for row in rows] == ['100']
    assert 'pagination' in report['error']


def test_full_mode_does_not_stop_on_pinned_id_one_without_pager(sources):
    fetcher,calls = transport([page([(1,'2026-01-01T00:00:00Z','pin'),(100,'2026-11-17T11:00:00Z','new')]),
                              page([(99,'2026-11-17T10:00:00Z','previous')]),page([])])
    report,rows,extra = sources._telegram_news(SOURCE,fetcher,'full',None,NOW,lambda _:None)
    assert {r['external_id'] for r in rows} == {'1','100','99'}
    assert calls[1].endswith('?before=100')
