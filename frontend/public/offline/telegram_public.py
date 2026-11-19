"""Public Telegram preview parsing shared with the standalone stdlib downloader."""
from datetime import datetime, timezone
from html.parser import HTMLParser
import re
from urllib.parse import urlsplit, urljoin, parse_qs

MAX_TEXT = 262144
VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}


def normalize_channel(value):
    value = value.strip()
    if value.startswith(('https://', 'http://')):
        parts = urlsplit(value)
        if parts.netloc.lower() != 't.me' or parts.query or parts.fragment:
            raise ValueError('public Telegram channel required')
        value = parts.path.removeprefix('/s/').strip('/')
    value = value.lstrip('@')
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{3,31}', value):
        raise ValueError('public Telegram channel required')
    return value.lower()


def _public_link(value):
    try:
        parts = urlsplit(value)
        return (parts.scheme in ('http', 'https') and bool(parts.hostname)
                and not parts.username and not parts.password
                and not any(ord(c) < 32 for c in value) and len(value) <= 2048)
    except ValueError:
        return False


class _Posts(HTMLParser):
    def __init__(self, channel):
        super().__init__(convert_charrefs=True)
        self.channel = channel
        self.frames = []
        self.current = None
        self.documents = []
        self.history = self.saw_post = False
        self.before = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        classes = (attrs.get('class') or '').split()
        self.history |= 'tgme_channel_history' in classes
        if tag == 'a' and 'js-messages_more' in classes:
            try:
                link = urlsplit(urljoin('https://t.me', attrs.get('href') or ''))
                value = attrs.get('data-before') or ''
                if (link.netloc.lower() == 't.me' and link.path.lower() == '/s/' + self.channel
                        and value.isascii() and value.isdigit() and 0 < len(value) <= 20
                        and int(value) > 0 and parse_qs(link.query).get('before') == [value]):
                    self.before = int(value)
            except ValueError:
                pass
        root = 'tgme_widget_message' in classes and bool(attrs.get('data-post'))
        if root:
            self.saw_post = True
            self.finish()
            self.frames = []
            identity = attrs['data-post'].split('/')
            if (len(identity) == 2 and identity[0].lower() == self.channel
                    and identity[1].isascii() and identity[1].isdigit() and len(identity[1]) <= 20):
                self.current = {'id': identity[1], 'parts': [], 'links': set(), 'date': None}
        parent = self.frames[-1] if self.frames else {}
        ignored = parent.get('ignored', False) or tag in ('script', 'style') or 'tgme_widget_message_reply' in classes
        body = parent.get('body', False) or 'tgme_widget_message_text' in classes
        forwarded = parent.get('forwarded', False) or 'tgme_widget_message_forwarded_from' in classes
        date = parent.get('date', False) or 'tgme_widget_message_date' in classes
        if self.current and not ignored:
            if tag in ('br', 'p', 'div', 'li', 'blockquote') and body:
                self.current['parts'].append('\n')
            if tag == 'a' and (body or forwarded):
                link = attrs.get('href') or ''
                if _public_link(link):
                    self.current['links'].add(link)
            if tag == 'time' and date and attrs.get('datetime'):
                try:
                    parsed = datetime.fromisoformat(attrs['datetime'].replace('Z', '+00:00'))
                    if parsed.tzinfo:
                        self.current['date'] = parsed.astimezone(timezone.utc).isoformat()
                except (ValueError, OverflowError):
                    pass
        if tag not in VOID:
            self.frames.append({'tag': tag, 'ignored': ignored, 'body': body, 'date': date, 'forwarded': forwarded, 'root': root})

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for index in range(len(self.frames)-1, -1, -1):
            if self.frames[index]['tag'] == tag:
                if (self.current and self.frames[-1]['body'] and not self.frames[-1]['ignored']
                        and tag in ('p', 'div', 'li', 'blockquote')):
                    self.current['parts'].append('\n')
                closing = self.frames[index:]
                del self.frames[index:]
                if any(frame['root'] for frame in closing):
                    self.finish()
                break

    def handle_data(self, value):
        if self.current and self.frames and self.frames[-1]['body'] and not self.frames[-1]['ignored']:
            self.current['parts'].append(value.replace('\x00', ''))

    def finish(self):
        if self.current is None:
            return
        current, self.current = self.current, None
        text = re.sub(r'\s+', ' ', ''.join(current['parts'])).strip()
        self.documents.append({'external_id': current['id'], 'url': f'https://t.me/{self.channel}/{current["id"]}',
            'title': text[:2000], 'text': text[:MAX_TEXT], 'published_at': current['date'],
            'date_basis': 'published' if current['date'] else 'unknown',
            'links': sorted(current['links'])[:100], 'full_text': True, 'truncated': len(text) > MAX_TEXT})


def parse_page(html, channel):
    parser = _Posts(normalize_channel(channel))
    if isinstance(html, bytes):
        html = html.decode('utf-8', errors='replace')
    parser.feed(html)
    parser.close()
    parser.finish()
    if (not parser.history and not parser.saw_post) or (parser.saw_post and not parser.documents):
        raise ValueError('Telegram public preview unavailable or layout changed')
    return parser.documents, parser.before


def parse_posts(html, channel):
    return parse_page(html, channel)[0]
