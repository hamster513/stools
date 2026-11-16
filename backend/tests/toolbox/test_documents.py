"""Synthetic Office/MIME fixtures; no private documents."""
import io
import zipfile
from email.message import EmailMessage
from email import policy
from email.parser import BytesParser

import pytest

from api.modules.toolbox.core.scrub.files import walk, rewrite

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
CT = b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>'


def package(parts):
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w') as z:
        z.writestr('[Content_Types].xml', CT)
        for name, content in parts.items():
            z.writestr(name, content)
    return b.getvalue()


def texts(path):
    return [(e, list(chunks)) for e, chunks in walk(path)]


def replace(key, text):
    return text.replace('host01', 'host-0001').replace('10.20.30.40', '192.0.2.1')


@pytest.mark.parametrize('extension,part,xml', [
    ('docx', 'word/document.xml', f'<w:document xmlns:w="{W}"><w:body><w:p><w:r><w:t>host</w:t></w:r><w:r><w:t>01</w:t></w:r></w:p></w:body></w:document>'),
    ('xlsx', 'xl/sharedStrings.xml', f'<sst xmlns="{S}"><si><r><t>host</t></r><r><t>01</t></r></si></sst>'),
    ('pptx', 'ppt/slides/slide1.xml', f'<a:p xmlns:a="{A}"><a:r><a:t>host</a:t></a:r><a:r><a:t>01</a:t></a:r></a:p>'),
])
def test_office_split_runs(extension, part, xml, tmp_path):
    src = tmp_path / ('source.' + extension)
    original = package({part: xml})
    src.write_bytes(original)
    assert any(t == 'host01' for _, chunks in texts(src) for _, t in chunks)
    out = tmp_path / ('clean.' + extension)
    rewrite(src, out, replace)
    chunks = [t for _, c in texts(out) for _, t in c]
    assert 'host-0001' in chunks
    assert not any('host01' in t for t in chunks)
    assert src.read_bytes() == original


def test_office_metadata_comments_and_binary_exclusions(tmp_path):
    src = tmp_path / 'source.docx'
    src.write_bytes(package({
        'word/document.xml': f'<w:document xmlns:w="{W}"><w:p><w:r><w:t>host01</w:t></w:r></w:p></w:document>',
        'docProps/core.xml': '<core><creator>host01</creator></core>',
        'word/comments.xml': f'<w:comments xmlns:w="{W}"><w:comment w:author="host01"><w:p><w:r><w:t>10.20.30.40</w:t></w:r></w:p></w:comment></w:comments>',
        'word/media/picture.png': b'private-image',
        'word/vbaProject.bin': b'private-macro',
    }))
    out = tmp_path / 'clean.docx'
    entries = rewrite(src, out, replace)
    assert sum(e.kind == 'skipped' for e in entries) == 2
    with zipfile.ZipFile(out) as z:
        assert 'word/media/picture.png' not in z.namelist()
        assert b'host01' not in z.read('docProps/core.xml')
        assert b'host01' not in z.read('word/comments.xml')
    assert all(e.kind != 'skipped' for e, _ in texts(out))


def test_eml_decodes_headers_body_and_cleans_attachments(tmp_path):
    msg = EmailMessage()
    msg['Subject'] = 'Сервер host01'
    msg['From'] = 'user@host01.example'
    msg.set_content('IP 10.20.30.40', cte='base64')
    msg.add_attachment(b'host01', maintype='text', subtype='plain', filename='host01.txt')
    msg.add_attachment(b'\x89PNG\x00private', maintype='image', subtype='png', filename='secret.png')
    src = tmp_path / 'source.eml'
    src.write_bytes(msg.as_bytes(policy=policy.SMTP))
    chunks = [t for _, c in texts(src) for _, t in c]
    assert any('Сервер host01' in t for t in chunks)
    assert any('10.20.30.40' in t for t in chunks)
    out = tmp_path / 'clean.eml'
    entries = rewrite(src, out, replace)
    clean = BytesParser(policy=policy.default).parsebytes(out.read_bytes())
    assert 'host-0001' in str(clean['Subject'])
    assert '192.0.2.1' in clean.get_body().get_content()
    attachments = list(clean.iter_attachments())
    assert len(attachments) == 1
    assert attachments[0].get_filename() == 'host-0001.txt'
    assert attachments[0].get_payload(decode=True) == b'host-0001'
    assert any(e.kind == 'skipped' for e in entries)


def test_eml_html_entities_and_split_tags(tmp_path):
    msg = EmailMessage()
    msg.set_content('<p>ho<b>st</b>01 &amp; 10.20.30.40</p>', subtype='html')
    src = tmp_path / 'source.eml'
    src.write_bytes(msg.as_bytes())
    assert any('host01' in t for _, c in texts(src) for _, t in c)
    out = tmp_path / 'clean.eml'
    rewrite(src, out, replace)
    clean = BytesParser(policy=policy.default).parsebytes(out.read_bytes())
    assert clean.get_content_type() == 'text/plain'
    assert 'host-0001 & 192.0.2.1' in clean.get_content()


@pytest.mark.parametrize('ext,data', [('docx', b'not a zip'), ('eml', b'Content-Type: application/pkcs7-mime\r\n\r\nAAAA')])
def test_unreadable_document_is_not_reported_clean(ext, data, tmp_path):
    src = tmp_path / ('bad.' + ext)
    src.write_bytes(data)
    out = tmp_path / ('clean.' + ext)
    assert any(e.kind == 'broken' for e, _ in texts(src))
    rewrite(src, out, replace)
    assert not out.exists()


def test_engine_scan_apply_verify_for_document_and_mail(tmp_path):
    from api.modules.toolbox.core.scrub import engine
    from tests.toolbox.synthetic import CTX, MemoryAliases
    for name, data in [
        ('note.docx', package({'word/document.xml': f'<w:document xmlns:w="{W}"><w:p><w:r><w:t>host</w:t></w:r><w:r><w:t>01 10.1.2.15</w:t></w:r></w:p></w:document>'})),
        ('note.eml', b'Subject: host01\r\nContent-Type: text/plain\r\n\r\nhost01 10.1.2.15'),
    ]:
        src = tmp_path / name
        src.write_bytes(data)
        aliases = MemoryAliases()
        findings = engine.scan(src, CTX, aliases).findings
        assert any(f.kind == 'host' and f.checked for f in findings)
        out = tmp_path / ('clean-' + name)
        engine.apply(src, out, findings, CTX, aliases)
        assert engine.verify(out, findings, CTX) == []
        assert engine.verify(src, findings, CTX)


def test_legacy_output_names_and_nested_conversion(tmp_path, monkeypatch):
    from api.modules.toolbox.core.scrub import files
    converted = package({'word/document.xml': f'<w:document xmlns:w="{W}"><w:p><w:r><w:t>host01</w:t></w:r></w:p></w:document>'})
    monkeypatch.setattr(files, 'convert', lambda data, suffix: converted)
    src = tmp_path / 'archive.zip'
    src.write_bytes(package({'host01.doc': b'legacy'}))
    out = tmp_path / 'clean.zip'
    files.rewrite(src, out, replace)
    with zipfile.ZipFile(out) as z:
        assert 'host-0001.docx' in z.namelist()
        assert b'host01' not in z.read('host-0001.docx')
    assert files.output_name('input.DOC') == 'input.docx'
    assert files.output_name('input.MSG') == 'input.eml'
    assert files.output_name('input.xls.gz') == 'input.xlsx.gz'


def test_document_dtd_and_duplicate_parts_rejected(tmp_path):
    src = tmp_path / 'bad.docx'
    src.write_bytes(package({'word/document.xml': '<!DOCTYPE x [<!ENTITY x "host01">]><x>&x;</x>'}))
    assert texts(src)[0][0].kind == 'broken'


def test_document_unpacked_budget(tmp_path, monkeypatch):
    from api.modules.toolbox.core.scrub import files
    src = tmp_path / 'large.docx'
    src.write_bytes(package({'word/document.xml': '<x>' + 'a'*2000 + '</x>'}))
    monkeypatch.setattr(files, 'MAX_UNPACKED', 1000)
    with pytest.raises(files.UnpackLimit):
        texts(src)


def test_eml_nested_message_and_office_attachment(tmp_path):
    msg = EmailMessage()
    msg.set_content('host01')
    inner = EmailMessage()
    inner['Subject'] = 'host01'
    inner.set_content('10.20.30.40')
    msg.add_attachment(inner)
    msg.add_attachment(package({'xl/sharedStrings.xml': f'<sst xmlns="{S}"><si><t>host01</t></si></sst>'}),
                       maintype='application', subtype='octet-stream', filename='host01.xlsx')
    src = tmp_path / 'nested.eml'
    src.write_bytes(msg.as_bytes())
    out = tmp_path / 'clean.eml'
    rewrite(src, out, replace)
    chunks = [t for _, c in texts(out) for _, t in c]
    assert any('host-0001' in t for t in chunks)
    assert not any('host01' in t or '10.20.30.40' in t for t in chunks)
    assert not any(e.kind in ('skipped', 'broken') for e, _ in texts(out))


def test_eml_images_are_excluded_even_when_ascii(tmp_path):
    msg = EmailMessage()
    msg.set_content('host01')
    msg.add_attachment(b'<svg>private</svg>', maintype='image', subtype='svg+xml', filename='image.svg')
    src = tmp_path / 'mail.eml'
    src.write_bytes(msg.as_bytes())
    out = tmp_path / 'clean.eml'
    rewrite(src, out, replace)
    clean = BytesParser(policy=policy.default).parsebytes(out.read_bytes())
    assert list(clean.iter_attachments()) == []


def test_converted_archive_name_collision_fails(tmp_path, monkeypatch):
    from api.modules.toolbox.core.scrub import files
    doc = package({'word/document.xml': '<document>host01</document>'})
    monkeypatch.setattr(files, 'convert', lambda data, suffix: doc)
    src = tmp_path / 'source.zip'
    src.write_bytes(package({'note.doc': b'legacy', 'note.docx': doc}))
    with pytest.raises(ValueError, match='имя'):
        rewrite(src, tmp_path / 'clean.zip', replace)


def test_removed_image_does_not_leave_invalid_picture(tmp_path):
    src = tmp_path / 'image.docx'
    rels = '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Target="media/image.png" Type="image"/></Relationships>'
    doc = f'<w:document xmlns:w="{W}" xmlns:a="{A}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:p><w:r><w:drawing><a:blip r:embed="rId1"/></w:drawing><w:t>host01</w:t></w:r></w:p></w:document>'
    src.write_bytes(package({'word/document.xml': doc, 'word/_rels/document.xml.rels': rels, 'word/media/image.png': b'png'}))
    out = tmp_path / 'out.docx'
    rewrite(src, out, replace)
    with zipfile.ZipFile(out) as z:
        assert b'<w:drawing' not in z.read('word/document.xml')


def test_excel_escaped_values_and_surrogates(tmp_path):
    src = tmp_path / 'escaped.xlsx'
    src.write_bytes(package({'xl/sharedStrings.xml': f'<sst xmlns="{S}"><si><t>host_x0030_1 _xD83D__xDE00_</t></si></sst>'}))
    assert any('host01' in t for _, c in texts(src) for _, t in c)
    out = tmp_path / 'clean.xlsx'
    rewrite(src, out, replace)
    assert any('host-0001' in t for _, c in texts(out) for _, t in c)


def test_pivot_cache_attributes_and_connections(tmp_path):
    src = tmp_path / 'pivot.xlsx'
    src.write_bytes(package({
        'xl/pivotCache/pivotCacheRecords1.xml': f'<pivotCacheRecords xmlns="{S}"><r><s v="host01"/></r></pivotCacheRecords>',
        'xl/connections.xml': f'<connections xmlns="{S}"><connection><dbPr connection="SERVER=host01;PWD=secret"/></connection></connections>',
    }))
    assert any('host01' in t for _, c in texts(src) for _, t in c)
    out = tmp_path / 'clean.xlsx'
    rewrite(src, out, replace)
    with zipfile.ZipFile(out) as z:
        assert 'xl/connections.xml' not in z.namelist()
        assert b'host01' not in z.read('xl/pivotCache/pivotCacheRecords1.xml')


def test_strict_ooxml_split_runs(tmp_path):
    strict = 'http://purl.oclc.org/ooxml/wordprocessingml/main'
    src = tmp_path / 'strict.docx'
    src.write_bytes(package({'word/document.xml': f'<w:document xmlns:w="{strict}"><w:p><w:r><w:t>host</w:t></w:r><w:r><w:t>01</w:t></w:r></w:p></w:document>'}))
    assert any(t == 'host01' for _, c in texts(src) for _, t in c)
    out = tmp_path / 'clean.docx'
    rewrite(src, out, replace)
    assert not any('host01' in t for _, c in texts(out) for _, t in c)


def test_mime_type_controls_nested_mail_and_html_attachments(tmp_path):
    msg = EmailMessage()
    msg.set_content('body')
    inner = EmailMessage()
    inner['Subject'] = 'nested'
    inner.set_content('host01', cte='base64')
    msg.add_attachment(inner, filename='forwarded.txt')
    msg.add_attachment(b'<p>ho&#115;t01</p>', maintype='text', subtype='html', filename='report.html')
    src = tmp_path / 'mail.eml'
    src.write_bytes(msg.as_bytes())
    assert sum('host01' in t for _, c in texts(src) for _, t in c) == 2
    out = tmp_path / 'clean.eml'
    rewrite(src, out, replace)
    clean = BytesParser(policy=policy.default).parsebytes(out.read_bytes())
    attachments = list(clean.iter_attachments())
    assert [p.get_filename() for p in attachments] == ['forwarded.eml', 'report.txt']
    assert not any('host01' in t for _, c in texts(out) for _, t in c)


def test_excel_encoded_pivot_attribute(tmp_path):
    src = tmp_path / 'pivot.xlsx'
    src.write_bytes(package({'xl/pivotCache/pivotCacheRecords1.xml': f'<pivotCacheRecords xmlns="{S}"><r><s v="host_x0030_1"/></r></pivotCacheRecords>'}))
    assert any(t == 'host01' for _, c in texts(src) for _, t in c)
    out = tmp_path / 'clean.xlsx'
    rewrite(src, out, replace)
    assert any(t == 'host-0001' for _, c in texts(out) for _, t in c)


def test_ascii_pdf_attachment_is_excluded(tmp_path):
    msg = EmailMessage()
    msg.set_content('body')
    msg.add_attachment(b'%PDF-1.4 <686f73743031>', maintype='application', subtype='pdf', filename='private.pdf')
    src = tmp_path / 'mail.eml'
    src.write_bytes(msg.as_bytes())
    out = tmp_path / 'clean.eml'
    entries = rewrite(src, out, replace)
    assert any(e.kind == 'skipped' for e in entries)
    assert not list(BytesParser(policy=policy.default).parsebytes(out.read_bytes()).iter_attachments())


def test_report_notes_do_not_contain_untrusted_mime_subtype(tmp_path):
    msg = EmailMessage()
    msg.set_content('host01')
    msg.add_attachment(b'private', maintype='application', subtype='x-host01', filename='file.dat')
    src = tmp_path / 'mail.eml'
    src.write_bytes(msg.as_bytes())
    entries = rewrite(src, tmp_path / 'out.eml', replace)
    assert any(e.kind == 'skipped' for e in entries)
    assert not any('host01' in e.note for e in entries)


@pytest.mark.parametrize('suffix', ['.xlsb', '.dotx', '.emlx', '.mbox'])
def test_unsupported_structured_formats_are_not_treated_as_plain_text(suffix, tmp_path):
    src = tmp_path / ('unsupported' + suffix)
    src.write_bytes(package({'part.xml': '<t>ho&#115;t01</t>'}) if suffix in ('.xlsb', '.dotx') else b'Subject: =?UTF-8?B?aG9zdDAx?=\r\n\r\n')
    out = tmp_path / ('clean' + suffix)
    assert texts(src)[0][0].kind == 'skipped'
    rewrite(src, out, replace)
    assert not out.exists()


def test_email_nul_padding_does_not_reach_findings_or_output(tmp_path):
    msg = EmailMessage()
    msg['Subject'] = 'host\x0001'
    msg.set_content('host\x0001\x00', cte='base64')
    msg.add_attachment(b'host01', maintype='text', subtype='plain', filename='note\x00.txt')
    src = tmp_path / 'mail.eml'
    src.write_bytes(msg.as_bytes())
    chunks = [t for _, pieces in texts(src) for _, t in pieces]
    assert all('\x00' not in t for t in chunks)
    assert any('host01' in t for t in chunks)
    out = tmp_path / 'clean.eml'
    rewrite(src, out, replace)
    clean = BytesParser(policy=policy.default).parsebytes(out.read_bytes())
    assert str(clean['Subject']) == 'host-0001'
    assert 'host-0001' in clean.get_body().get_content()
    assert list(clean.iter_attachments())[0].get_filename() == 'note.txt'
