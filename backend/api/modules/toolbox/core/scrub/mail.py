"""Decode MIME before scanning; reconstruct mail without opaque or active payloads."""
from __future__ import annotations

from collections.abc import Callable
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import PurePosixPath

from .documents import DocumentError, output_name


MIME_SUFFIXES = {
    'application/msword': '.doc', 'application/vnd.ms-excel': '.xls', 'application/vnd.ms-powerpoint': '.ppt',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': '.pptx',
    'application/vnd.ms-word.document.macroenabled.12': '.docm',
    'application/vnd.ms-excel.sheet.macroenabled.12': '.xlsm',
    'application/vnd.ms-powerpoint.presentation.macroenabled.12': '.pptm',
    'application/vnd.oasis.opendocument.text': '.odt', 'application/vnd.oasis.opendocument.spreadsheet': '.ods',
    'application/vnd.oasis.opendocument.presentation': '.odp', 'application/vnd.ms-outlook': '.msg',
    'application/rtf': '.rtf', 'text/rtf': '.rtf', 'text/html': '.html',
    'application/zip': '.zip', 'application/gzip': '.gz', 'application/x-gzip': '.gz',
    'application/json': '.json', 'application/xml': '.xml',
}


def _typed_name(name: str | None, suffix: str) -> str:
    name = name or 'attachment'
    return str(PurePosixPath(name).with_suffix(suffix))


def html_text(text: str) -> str:
    parser = _HtmlText()
    parser.feed(text)
    parser.close()
    return ''.join(parser.parts)


class _HtmlText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in {'script', 'style'}:
            self.hidden += 1
        if tag in {'p', 'div', 'br', 'tr', 'li', 'hr'}:
            self.parts.append('\n')
        if tag == 'a':
            target = dict(attrs).get('href')
            if target:
                self.parts.append(' [' + target + '] ')

    def handle_endtag(self, tag):
        if tag in {'script', 'style'}:
            self.hidden = max(0, self.hidden - 1)
        if tag in {'p', 'div', 'tr', 'li'}:
            self.parts.append('\n')

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def email_file(data: bytes, transform: Callable[[str, str], str],
               attachment: Callable[[str, bytes], bytes | None], add: Callable[[int], None],
               omitted: list[str]) -> bytes:
    message = BytesParser(policy=policy.default).parsebytes(data)
    if not message.keys() or message.defects:
        raise DocumentError('повреждённое MIME-письмо')

    def convert(part: EmailMessage, depth: int) -> EmailMessage | None:
        if depth > 20:
            raise DocumentError('слишком много вложенных MIME-частей')
        typ = part.get_content_type()
        if typ in {'application/pkcs7-mime', 'application/x-pkcs7-mime', 'multipart/encrypted'}:
            raise DocumentError('зашифрованное письмо нельзя очистить')
        if part.get_content_maintype() in {'image', 'audio', 'video'}:
            omitted.append('неподдерживаемая MIME-часть')
            return None
        if typ in {'application/pkcs7-signature', 'application/x-pkcs7-signature', 'application/pgp-signature'}:
            omitted.append('цифровая подпись письма')
            return None
        out = EmailMessage(policy=policy.SMTP)
        for key, value in part.items():
            low = key.lower()
            if low.startswith('content-') or low == 'mime-version':
                continue
            if low in {'dkim-signature', 'domainkey-signature', 'arc-seal', 'arc-message-signature'}:
                omitted.append(key)
                continue
            if getattr(value, 'defects', ()):
                raise DocumentError('некорректная кодировка заголовка письма')
            # Decode RFC2047, unfold before transform, then let email encode/fold safely.
            clean = transform('', str(value).replace('\x00', '')).replace('\r', '').replace('\n', ' ')
            if low == 'message-id':
                # Placeholders can break ID syntax; check the serialized header too.
                probe = EmailMessage(policy=policy.SMTP)
                probe[key] = clean
                parsed = BytesParser(policy=policy.default).parsebytes(probe.as_bytes())
                if probe[key].defects or parsed[key].defects:
                    omitted.append('заголовок Message-ID: подстановка нарушила формат идентификатора')
                    continue
            out[key] = clean
        filename = (part.get_filename() or '').replace('\x00', '') or None
        if typ == 'message/rfc822':
            payload = part.get_payload()
            if not isinstance(payload, list) or len(payload) != 1:
                raise DocumentError('повреждённое вложенное письмо')
            raw = payload[0].as_bytes(policy=policy.SMTP)
            name = _typed_name(filename or 'message.eml', '.eml')
            clean = attachment(name, raw)
            if clean is None:
                return None
            out.set_content(clean, maintype='application', subtype='octet-stream', cte='base64')
            out.add_header('Content-Disposition', 'attachment', filename=transform('__name__', output_name(name)))
        elif part.is_multipart():
            if typ == 'multipart/signed':
                omitted.append('подпись multipart/signed')
            subtype = part.get_content_subtype()
            out.set_type('multipart/' + (subtype if subtype in {'mixed', 'alternative', 'related'} else 'mixed'))
            for child in part.iter_parts():
                cleaned = convert(child, depth + 1)
                if cleaned is not None:
                    out.attach(cleaned)
            if not out.get_payload():
                out.set_payload([])
        elif filename or part.get_content_disposition() == 'attachment':
            if not (typ in MIME_SUFFIXES or typ == 'application/octet-stream' or typ.startswith('text/')):
                omitted.append('неподдерживаемое MIME-вложение')
                return None
            raw = part.get_payload(decode=True)
            if raw is None or part.defects:
                raise DocumentError('повреждённая кодировка вложения')
            # Never guess a textual extension for unnamed binary data.
            name = filename or ('attachment.txt' if typ.startswith('text/') else 'attachment.bin')
            if typ in MIME_SUFFIXES:
                name = _typed_name(name, MIME_SUFFIXES[typ])
            if typ == 'text/html':
                try:
                    raw = raw.decode(part.get_content_charset() or 'ascii').replace('\x00', '').encode('utf-8')
                except (UnicodeError, LookupError) as exc:
                    raise DocumentError('неизвестная кодировка HTML-вложения') from exc
            clean = attachment(name, raw)
            if clean is None:
                return None
            out.set_content(clean, maintype='application', subtype='octet-stream', cte='base64')
            out.add_header('Content-Disposition', 'attachment', filename=transform('__name__', output_name(name)))
        elif typ in {'text/plain', 'text/html'}:
            raw = part.get_payload(decode=True)
            if raw is None or part.defects:
                raise DocumentError('повреждённая кодировка текста письма')
            add(len(raw))
            try:
                # MAPI strings may retain terminating NULs after MSG → EML conversion.
                # Drop them before detection: findings/contexts are stored in PostgreSQL text.
                text = raw.decode(part.get_content_charset() or 'ascii').replace('\x00', '')
            except (UnicodeError, LookupError) as exc:
                raise DocumentError('неизвестная кодировка письма') from exc
            if typ == 'text/html':
                text = html_text(text)
                omitted.append('HTML-оформление и активное содержимое письма (сохранён текст)')
            out.set_content(transform('', text), subtype='plain', charset='utf-8')
        else:
            omitted.append('неподдерживаемая MIME-часть')
            return None
        if part.defects:
            raise DocumentError('повреждённое MIME-письмо')
        return out

    result = convert(message, 0)
    if result is None:
        raise DocumentError('в письме нет доступного текста')
    return result.as_bytes(policy=policy.SMTP)
