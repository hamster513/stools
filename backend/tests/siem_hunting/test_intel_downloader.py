import datetime as dt
import hashlib
import importlib.util
import io
import sys
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / 'frontend/public/siem/download-intel.py'


@pytest.fixture
def downloader(monkeypatch):
    monkeypatch.setattr(sys, 'dont_write_bytecode', True)
    spec = importlib.util.spec_from_file_location('th_intel_downloader', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RSS = b'''<rss><channel><item><guid>a</guid><title>Report T1059</title><link>https://example.org/a</link><description>&lt;p&gt;News&lt;/p&gt;&lt;script&gt;evil()&lt;/script&gt;</description><pubDate>Sun, 08 Nov 2026 12:00:00 GMT</pubDate></item></channel></rss>'''
SOURCE = {'id': 'feed', 'name': 'Feed', 'kind': 'rss', 'url': 'https://example.org/feed'}


def test_feed_text_dates_and_techniques(downloader):
    rows, limited = downloader.parse_feed(RSS, SOURCE, dt.datetime(2026, 11, 9, tzinfo=dt.UTC), 30, 200)
    assert len(rows) == 1 and not limited
    assert rows[0]['text'] == 'News'
    assert rows[0]['technique_ids'] == ['T1059']
    assert rows[0]['published_at'].startswith('2026-11-08')
    assert not rows[0]['full_text']


def test_atom_and_unknown_date_preserved(downloader):
    raw = b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>x</id><title>Test</title><link href="https://example.org/x"/><content type="html">&lt;b&gt;Content&lt;/b&gt;</content></entry></feed>'
    rows, _ = downloader.parse_feed(raw, SOURCE, dt.datetime.now(dt.UTC), 30, 200)
    assert rows[0]['text'] == 'Content' and rows[0]['published_at'] is None


def test_cutoff_and_limit_are_explicit(downloader):
    rows, _ = downloader.parse_feed(RSS, SOURCE, dt.datetime(2027, 1, 1, tzinfo=dt.UTC), 30, 200)
    assert rows == []
    rows, _ = downloader.parse_feed(RSS, SOURCE, dt.datetime.now(dt.UTC), 0, 200)
    assert len(rows) == 1


def test_partial_bundle_and_checksums(downloader, tmp_path):
    def fetch(url, limit, timeout):
        if url.endswith('bad'): raise OSError('unavailable')
        return RSS
    out = tmp_path/'intel.zip'
    result = downloader.collect([SOURCE, {**SOURCE, 'id': 'bad', 'url': 'https://example.org/bad'}], out, days=0, fetcher=fetch)
    assert result['items_count'] == 1
    assert {s['status'] for s in result['sources']} == {'ok', 'error'}
    with zipfile.ZipFile(out) as z:
        data = z.read('items.jsonl')
        assert hashlib.sha256(data).hexdigest() == result['items_sha256']
        assert set(z.namelist()) == {'manifest.json', 'items.jsonl'}
    with pytest.raises(FileExistsError): downloader.collect([SOURCE], out, days=0, fetcher=fetch)


def test_rules_keep_raw_text_and_skip_other_files(downloader):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as z:
        z.writestr('repo/rules/a.yml', 'title: Rule\ntags:\n  - attack.t1059.001\ndetection:\n  condition: selection\n')
        z.writestr('repo/LICENSE', 'Upstream license')
        z.writestr('repo/tools/run.py', 'do not run')
    source = {'id': 'rules', 'name': 'Rules', 'kind': 'github', 'repository': 'Example/Rules',
              'ref': 'main', 'prefixes': ['rules/'], 'format': 'sigma'}
    rows, license_text = downloader.parse_rules(output.getvalue(), source, 'a'*40)
    assert len(rows) == 1 and rows[0]['format'] == 'sigma'
    assert rows[0]['technique_ids'] == ['T1059.001']
    assert '/'+('a'*40)+'/' in rows[0]['url']
    assert 'condition: selection' in rows[0]['text']
    assert 'Upstream license' in license_text


def test_default_sources_match_existing_catalog(downloader):
    defaults = downloader.DEFAULT_SOURCES
    assert len({s['id'] for s in defaults}) == len(defaults)
    assert sum(s['kind']=='rss' for s in defaults) >= 100
    assert {'SigmaHQ/sigma', 'elastic/detection-rules'} <= {s.get('repository') for s in defaults}


def test_empty_or_bad_sources_do_not_create_archive(downloader, tmp_path):
    out = tmp_path/'no.zip'
    def fail(*_): raise OSError('network unavailable')
    with pytest.raises(ValueError): downloader.collect([SOURCE], out, fetcher=fail)
    assert not out.exists()


def test_xml_entities_are_rejected(downloader):
    raw = b'<!DOCTYPE rss [<!ENTITY x "secret">]><rss><channel/></rss>'
    with pytest.raises(ValueError): downloader.parse_feed(raw, SOURCE, dt.datetime.now(dt.UTC), 0, 200)


def test_atom_limit_is_reported(downloader):
    entry = '<entry><id>{}</id><title>Test</title><link href="https://example.org/{}"/></entry>'
    raw = ('<feed>'+''.join(entry.format(i, i) for i in range(3))+'</feed>').encode()
    rows, limited = downloader.parse_feed(raw, SOURCE, dt.datetime.now(dt.UTC), 0, 2)
    assert len(rows) == 2 and limited


def test_bundle_is_importer_compatible(downloader, tmp_path):
    from api.modules.siem.hunting.intel import read_bundle
    out = tmp_path/'compatible.zip'
    downloader.collect([SOURCE], out, days=0, fetcher=lambda *_: RSS)
    manifest, rows = read_bundle(out.read_bytes())
    assert manifest.items_count == 1 and rows[0].kind == 'news'


def test_shared_budget_is_enforced_before_archive_creation(downloader, tmp_path, monkeypatch):
    monkeypatch.setattr(downloader, 'MAX_DATA', 50)
    out = tmp_path/'too-big.zip'
    with pytest.raises(downloader.CollectionLimit):
        downloader.collect([SOURCE, {**SOURCE, 'id': 'second'}], out, days=0, fetcher=lambda *_: RSS)
    assert not out.exists()


def test_large_upstream_sigma_rule_is_kept(downloader):
    output = io.BytesIO()
    raw = 'title: Large upstream rule\ndetection:\n  values:\n' + ''.join(f'    - name{i:06d}.sys\n' for i in range(16000))
    assert len(raw) > 262144
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as z: z.writestr('repo/rules/large.yml', raw)
    source = {'id': 'rules', 'name': 'Rules', 'repository': 'Example/Rules', 'format': 'sigma', 'prefixes': ['rules/']}
    rows, _ = downloader.parse_rules(output.getvalue(), source, 'a'*40)
    from api.modules.siem.hunting.intel import Material
    assert Material.model_validate(rows[0]).text == raw
