import pytest

from stools_threat_collector.adapters import telegram_public as public


HTML = '''<section class="tgme_channel_history"><div class="tgme_widget_message" data-post="SomeNews/42">
<div class="tgme_widget_message_text">Issue CVE-2026-12345<br>Details <a href="https://example.org/advisory">here</a>
<div class="tgme_widget_message_reply">CVE-2000-99999</div><script>secret-script</script>
<a href="javascript:alert(1)">unsafe link</a></div>
<a class="tgme_widget_message_forwarded_from" href="https://t.me/origin/2">Forwarded</a>
<a class="tgme_widget_message_date"><time datetime="2026-11-18T12:30:00+03:00">date</time></a>
</div></section>'''


def test_public_parser_preserves_identity_date_and_links_but_excludes_reply():
    rows = public.parse_posts(HTML, 'somenews')
    assert len(rows) == 1
    row = rows[0]
    assert row['external_id'] == '42' and row['url'] == 'https://t.me/somenews/42'
    assert row['published_at'] == '2026-11-18T09:30:00+00:00'
    assert 'CVE-2026-12345' in row['text'] and 'CVE-2000-99999' not in row['text']
    assert 'secret-script' not in row['text']
    assert row['links'] == ['https://example.org/advisory', 'https://t.me/origin/2']


@pytest.mark.parametrize('value', ['@SomeNews', 'SomeNews', 'https://t.me/s/SomeNews', 'https://t.me/SomeNews/'])
def test_normalization(value):
    assert public.normalize_channel(value) == 'somenews'


@pytest.mark.parametrize('value', ['https://user:secret@t.me/somenews', 'https://t.me.evil/somenews', 'https://t.me/+private', 'somenews/42', 'https://t.me/somenews?token=secret'])
def test_only_public_channel_names(value):
    with pytest.raises(ValueError):
        public.normalize_channel(value)


def test_unavailable_preview_is_not_empty_success():
    with pytest.raises(ValueError, match='preview'):
        public.parse_posts('<html>View in Telegram</html>', 'somenews')
    assert public.parse_posts('<section class="tgme_channel_history"></section>', 'somenews') == []


def test_missing_or_naive_date_is_unknown():
    row = public.parse_posts(HTML.replace('2026-11-18T12:30:00+03:00', '2026-11-18T12:30:00'), 'somenews')[0]
    assert row['published_at'] is None


def test_wrong_channel_does_not_become_empty_success():
    with pytest.raises(ValueError):
        public.parse_posts(HTML, 'othernews')


def test_nested_forward_link_and_paragraph_boundaries():
    html = HTML.replace('<a class="tgme_widget_message_forwarded_from" href="https://t.me/origin/2">Forwarded</a>',
                        '<div class="tgme_widget_message_forwarded_from">Forwarded from <a href="https://t.me/origin/2">Origin</a></div>')
    html = html.replace('Issue CVE-2026-12345<br>Details', '<p>Issue CVE-2026-12345</p><p>Details</p>')
    row = public.parse_posts(html, 'somenews')[0]
    assert 'https://t.me/origin/2' in row['links']
    assert 'CVE-2026-12345 Details' in row['text']
