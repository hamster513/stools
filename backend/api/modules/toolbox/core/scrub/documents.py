"""OOXML text projection and rewrite. Binary parts never reach the cleaned copy."""
from __future__ import annotations

import io
import posixpath
import re
import zipfile
from collections.abc import Callable

from lxml import etree

MODERN = {'.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm'}
LEGACY = {'.doc': '.docx', '.xls': '.xlsx', '.ppt': '.pptx', '.rtf': '.docx',
          '.odt': '.docx', '.ods': '.xlsx', '.odp': '.pptx', '.msg': '.eml'}
LIMIT = 64 * 1024 * 1024
MAX_PARTS = 10000
W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
A = 'http://schemas.openxmlformats.org/drawingml/2006/main'
S = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
R = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
P = 'http://schemas.openxmlformats.org/package/2006/relationships'
GROUPS = {f'{{{W}}}p', f'{{{A}}}p', f'{{{S}}}si', f'{{{S}}}is'}
TEXT = {f'{{{W}}}t', f'{{{W}}}delText', f'{{{A}}}t', f'{{{S}}}t'}
# Strict OOXML uses a different namespace with the same paragraph/string semantics.
STRICT = {'http://schemas.openxmlformats.org/wordprocessingml/2006/main': 'http://purl.oclc.org/ooxml/wordprocessingml/main',
          'http://schemas.openxmlformats.org/drawingml/2006/main': 'http://purl.oclc.org/ooxml/drawingml/main',
          'http://schemas.openxmlformats.org/spreadsheetml/2006/main': 'http://purl.oclc.org/ooxml/spreadsheetml/main'}
GROUPS |= {tag.replace(old, new) for tag in tuple(GROUPS) for old, new in STRICT.items() if old in tag}
TEXT |= {tag.replace(old, new) for tag in tuple(TEXT) for old, new in STRICT.items() if old in tag}
REL_NAMESPACES = {R, 'http://purl.oclc.org/ooxml/officeDocument/relationships'}
# References and enumerations, not user text. All other attributes are inspected, including pivot @v.
STRUCTURAL_ATTRS = {'id', 'Id', 'r', 'ref', 's', 't', 'type', 'Type', 'count', 'styleId', 'numFmtId', 'xfId'}
ESCAPE = re.compile(r'_x([0-9a-fA-F]{4})_')


class DocumentError(ValueError):
    """Unsupported, encrypted or damaged structured input; never silently pass through."""


def output_name(name: str) -> str:
    base, dot, ext = name.rpartition('.')
    suffix = '.' + ext.lower()
    if suffix == '.gz':
        return output_name(base) + dot + ext
    new = LEGACY.get(suffix) or {'.html': '.txt', '.htm': '.txt', '.docm': '.docx', '.xlsm': '.xlsx', '.pptm': '.pptx'}.get(suffix)
    return base + new if new else name


def _local(tag: str) -> str:
    return tag.rsplit('}', 1)[-1]


def _excel_decode(value: str) -> str:
    decoded = ESCAPE.sub(lambda m: chr(int(m[1], 16)), value)
    try:
        return decoded.encode('utf-16-le', 'surrogatepass').decode('utf-16-le')
    except UnicodeError as exc:
        raise DocumentError('некорректная строка Excel') from exc


def _excel_encode(value: str) -> str:
    value = re.sub(r'_x[0-9a-fA-F]{4}_', lambda m: '_x005F_' + m[0][1:], value)
    return ''.join(f'_x{ord(c):04X}_' if ord(c) < 32 and c not in '\t\n\r' else c for c in value)


def _value(value: str, transform: Callable[[str, str], str], excel: bool) -> str:
    decoded = _excel_decode(value) if excel else value
    clean = transform('', decoded)
    if clean == decoded:
        return value
    return _excel_encode(clean) if excel else clean


def _text(root, transform: Callable[[str, str], str]) -> None:
    handled = set()
    # Join only text in the same paragraph/cell; nested textboxes have their own paragraphs.
    for group in root.iter():
        if group.tag not in GROUPS:
            continue
        leaves = []
        for node in group.iter():
            if node.tag not in TEXT:
                continue
            ancestor = node.getparent()
            while ancestor is not None and ancestor.tag not in GROUPS:
                ancestor = ancestor.getparent()
            if ancestor is group:
                leaves.append(node)
        if not leaves:
            continue
        original = ''.join(n.text or '' for n in leaves)
        excel = _local(group.tag) in {'si', 'is'}
        decoded = _excel_decode(original) if excel else original
        clean = transform('', decoded)
        if clean != decoded or decoded != original:
            # Preserve unmodified runs. A changed span inherits its first run's formatting.
            if excel:
                clean = _excel_encode(clean)
            leaves[0].text = clean
            leaves[0].set('{http://www.w3.org/XML/1998/namespace}space', 'preserve')
            for node in leaves[1:]:
                node.text = ''
        handled.update(leaves)
    for node in root.iter():
        if not isinstance(node.tag, str):
            continue
        excel = node.tag.startswith(('{' + S + '}', '{' + STRICT[S] + '}'))
        if node not in handled and node.text and node.text.strip():
            node.text = _value(node.text, transform, excel)
        if node.tail and node.tail.strip():
            node.tail = _value(node.tail, transform, excel)
        for key, value in list(node.attrib.items()):
            if (_local(key) not in STRUCTURAL_ATTRS and
                not key.startswith('{http://www.w3.org/XML/1998/namespace}') and
                not any(key.startswith('{' + ns + '}') for ns in REL_NAMESPACES)):
                node.set(key, _value(value, transform, excel))


def office(data: bytes, transform: Callable[[str, str], str], add: Callable[[int], None]) -> tuple[bytes, list[str]]:
    """Return an XML-only package plus the parts/links excluded from the result."""
    omitted: list[str] = []
    roots = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = [i for i in z.infolist() if not i.is_dir()]
            if len(infos) > MAX_PARTS or len({i.filename for i in infos}) != len(infos):
                raise DocumentError('слишком много частей документа или повторяющиеся имена')
            if sum(i.file_size for i in infos) > LIMIT:
                raise DocumentError('распакованный документ больше 64 МБ')
            for info in infos:
                name = info.filename
                if name.startswith('/') or '\\' in name or posixpath.normpath(name) != name:
                    raise DocumentError('некорректное имя части документа')
                add(info.file_size)
                low = name.lower()
                if (not low.endswith(('.xml', '.rels')) or
                    any(s in low for s in ('vbaproject', 'vbadata', 'activex/', 'customui/', 'customxml/', 'embeddings/', '_xmlsignatures/', 'externallinks/', 'connections.xml'))):
                    omitted.append(name)
                    continue
                parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True,
                                         remove_comments=True, remove_pis=True)
                root = etree.fromstring(z.read(info), parser)
                if root.getroottree().docinfo.doctype:
                    raise DocumentError('DTD в документе запрещён')
                roots[name] = root
        if '[Content_Types].xml' not in roots or not any(p.startswith(('word/', 'xl/', 'ppt/')) for p in roots):
            raise DocumentError('не найдено содержимое Office')
        # Remove unsupported links, then their drawing/object references from the owning part.
        for name, root in list(roots.items()):
            if not name.endswith('.rels'):
                continue
            owner = '' if name == '_rels/.rels' else name.replace('/_rels/', '/').removesuffix('.rels')
            removed_ids = set()
            for rel in list(root):
                target = rel.get('Target', '')
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(owner), target)).lstrip('/')
                if rel.get('TargetMode') == 'External' or resolved not in roots:
                    removed_ids.add(rel.get('Id'))
                    root.remove(rel)
                    omitted.append(name + '#' + (rel.get('Id') or 'link'))
            if owner in roots and removed_ids:
                for node in list(roots[owner].iter()):
                    if any(node.get(f'{{{ns}}}{attr}') in removed_ids for ns in REL_NAMESPACES for attr in ('id', 'embed', 'link')):
                        # Remove the whole picture/object, not just a required blip child.
                        container = node
                        for ancestor in node.iterancestors():
                            if _local(ancestor.tag) in {'drawing', 'pict', 'object', 'pic', 'graphicFrame',
                                                       'oneCellAnchor', 'twoCellAnchor', 'absoluteAnchor'}:
                                container = ancestor
                        node = container
                        parent = node.getparent()
                        if parent is not None:
                            if _local(node.tag) == 'hyperlink':
                                at = parent.index(node)
                                for child in list(node):
                                    parent.insert(at, child)
                                    at += 1
                            parent.remove(node)
        content_types = roots['[Content_Types].xml']
        for node in list(content_types):
            part = node.get('PartName', '').lstrip('/')
            if part and part not in roots:
                content_types.remove(node)
                continue
            ct = node.get('ContentType', '')
            types = {'application/vnd.ms-word.document.macroEnabled.main+xml': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml',
                     'application/vnd.ms-excel.sheet.macroEnabled.main+xml': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml',
                     'application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml': 'application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml'}
            if ct in types:
                node.set('ContentType', types[ct])
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
            for name, root in roots.items():
                if name != '[Content_Types].xml' and not name.endswith('.rels'):
                    _text(root, transform)
                z.writestr(name, etree.tostring(root, xml_declaration=True, encoding='UTF-8'))
        return out.getvalue(), omitted
    except (etree.XMLSyntaxError, zipfile.BadZipFile, KeyError, RuntimeError) as exc:
        raise DocumentError('повреждённый или зашифрованный документ Office') from exc
