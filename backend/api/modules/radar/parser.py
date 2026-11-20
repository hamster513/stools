"""Bounded nginx -T reader. Never executes directives, reads includes from disk, or resolves DNS.

This is configuration inventory, not a request-routing or reachability evaluator.
Only allowlisted directive values leave the parser; originals are stored encrypted separately.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import posixpath
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

MAX_BYTES = 2 * 1024 * 1024
MAX_NODES = 20000
MAX_DEPTH = 48
MAX_OUTPUT_ITEMS = 30000
MAX_OUTPUT_CHARS = 8 * 1024 * 1024
SAFE = frozenset(['listen', 'server_name', 'location', 'upstream', 'server', 'proxy_pass', 'fastcgi_pass', 'grpc_pass', 'uwsgi_pass', 'scgi_pass', 'root', 'alias', 'return', 'rewrite', 'allow', 'deny', 'satisfy', 'auth_basic', 'auth_basic_user_file', 'auth_request', 'internal', 'ssl_certificate', 'ssl_certificate_key', 'ssl_protocols', 'ssl_ciphers', 'ssl_verify_client', 'ssl_client_certificate', 'proxy_ssl_verify', 'proxy_ssl_server_name', 'proxy_ssl_name', 'proxy_read_timeout', 'proxy_connect_timeout', 'proxy_send_timeout', 'client_max_body_size', 'proxy_http_version', 'proxy_set_header', 'add_header', 'error_page', 'try_files', 'index', 'resolver', 'real_ip_header', 'set_real_ip_from', 'real_ip_recursive', 'limit_req', 'limit_conn', 'limit_req_zone', 'limit_conn_zone', 'proxy_bind', 'proxy_method', 'proxy_pass_request_headers', 'proxy_pass_request_body', 'proxy_intercept_errors', 'proxy_redirect', 'proxy_next_upstream', 'ip_hash', 'least_conn', 'hash', 'keepalive', 'include'])
# Header values, freeform auth realms, maps, set and embedded code can contain credentials.
HIDDEN = {'proxy_set_header', 'add_header', 'auth_basic', 'ssl_certificate_key'}
PASS = {'proxy_pass', 'fastcgi_pass', 'grpc_pass', 'uwsgi_pass', 'scgi_pass'}
GROUPS = ({'allow', 'deny'}, {'proxy_set_header'}, {'add_header'}, {'root', 'alias'})


class ParseError(ValueError):
    pass


@dataclass
class Node:
    name: str
    args: list[str]
    file: str
    line: int
    children: list[Node] | None = None


@dataclass
class Token:
    value: str
    line: int
    symbol: bool = False


def _tokens(text: str) -> list[Token]:
    out: list[Token] = []
    i, line = 0, 1
    while i < len(text):
        c = text[i]
        if c.isspace():
            line += c == '\n'
            i += 1
            continue
        if c == '#':
            end = text.find('\n', i)
            i = len(text) if end < 0 else end
            continue
        start = line
        if c in '{};':
            out.append(Token(c, line, True))
            i += 1
            continue
        buf: list[str] = []
        quote = ''
        while i < len(text):
            c = text[i]
            if not quote and (c.isspace() or c in '{};#'):
                break
            if c == '\\' and i + 1 < len(text):
                nxt = text[i + 1]
                buf.append(nxt if nxt in '\\"\' \t\n;{}#' else '\\' + nxt)
                line += nxt == '\n'
                i += 2
                continue
            if c in "\"'":
                if quote == c:
                    quote = ''
                elif not quote:
                    quote = c
                else:
                    buf.append(c)
                i += 1
                continue
            if c == '$' and text[i:i+2] == '${':
                end = text.find('}', i+2)
                if end < 0:
                    raise ParseError(f'Строка {line}: незакрытая переменная')
                buf.append(text[i:end+1])
                i = end + 1
                continue
            buf.append(c)
            line += c == '\n'
            i += 1
        if quote:
            raise ParseError(f'Строка {start}: незакрытая кавычка')
        value = ''.join(buf)
        if len(value) > 8192:
            raise ParseError(f'Строка {start}: слишком длинное значение директивы')
        out.append(Token(value, start))
        if len(out) > MAX_NODES * 12:
            raise ParseError('Слишком много токенов конфигурации')
    return out


def _parse(text: str, filename: str) -> list[Node]:
    tokens = _tokens(text)
    pos, count = 0, 0

    def block(depth: int) -> list[Node]:
        nonlocal pos, count
        if depth > MAX_DEPTH:
            raise ParseError('Слишком большая вложенность конфигурации')
        nodes: list[Node] = []
        while pos < len(tokens):
            first = tokens[pos]
            if first.symbol and first.value == '}':
                if not depth:
                    raise ParseError(f'{filename}:{first.line}: лишняя закрывающая скобка')
                pos += 1
                return nodes
            words = []
            while pos < len(tokens) and not tokens[pos].symbol:
                words.append(tokens[pos].value)
                pos += 1
            if not words or pos == len(tokens) or tokens[pos].value == '}':
                raise ParseError(f'{filename}:{first.line}: ожидались директива и ; или блок')
            symbol = tokens[pos].value
            pos += 1
            count += 1
            if count > MAX_NODES:
                raise ParseError('Слишком много директив')
            nodes.append(Node(words[0], words[1:], filename, first.line, block(depth+1) if symbol == '{' else None))
        if depth:
            raise ParseError(f'{filename}: незакрытый блок')
        return nodes

    return block(0)


def _clean_url(value: str) -> str:
    # Strip authority credentials before parsing: nginx allows a variable scheme,
    # which urllib deliberately does not recognise as a URI scheme.
    base = value.split('?', 1)[0].split('#', 1)[0]
    if '://' in base:
        scheme, rest = base.split('://', 1)
        prefix = scheme + '://'
    elif base.startswith('//'):
        prefix, rest = '//', base[2:]
    else:
        return base
    authority, slash, path = rest.partition('/')
    return prefix + authority.rsplit('@', 1)[-1] + slash + path


def _setting(n: Node) -> dict[str, Any]:
    value = ' '.join(n.args)
    if n.name not in SAFE or n.name in HIDDEN:
        value = '[значение скрыто]'
    elif n.name == 'return':
        value = _clean_url(n.args[0]) if n.args else ''
        if len(n.args) > 1:
            value += ' ' + (_clean_url(n.args[1]) if n.args[1].startswith(('http://', 'https://', '$')) else '[тело ответа скрыто]')
    elif n.name in PASS or n.name in {'rewrite', 'proxy_redirect', 'auth_request', 'error_page', 'try_files', 'index'}:
        value = ' '.join(_clean_url(arg) for arg in n.args)
    name = n.name if n.name in SAFE or n.name in {'http', 'events', 'stream', 'mail', 'map', 'geo', 'if', 'set'} else '[директива скрыта]'
    return {'name': name, 'value': value, 'file': n.file, 'line': n.line}


def _effective(parent: list[Node], own: list[Node]) -> list[Node]:
    local = [n for n in own if n.children is None and n.name in SAFE and n.name != 'include']
    replaced = {n.name for n in local}
    for group in GROUPS:
        if replaced & group:
            replaced |= group
    return [n for n in parent if n.name not in replaced] + local


def _endpoint(value: str, hostname: str, scheme: str = 'http') -> dict[str, Any]:
    cleaned = _clean_url(value)
    dynamic = '$' in value
    host, port, local = '', None, False
    try:
        if value.startswith('unix:'):
            host, local = hostname, True
        elif not dynamic:
            u = urlsplit(value if '://' in value else f'{scheme}://{value}')
            host, port = u.hostname or '', u.port
            if port is None and (scheme in {'http', 'https'} or u.scheme in {'http', 'https'}):
                port = 443 if u.scheme == 'https' else 80
            local = host.lower() == 'localhost'
            try:
                local = local or ipaddress.ip_address(host).is_loopback
            except ValueError:
                pass
            if local:
                host = hostname
    except ValueError:
        dynamic = True
    return {'address': cleaned, 'host': host, 'port': port, 'local': local, 'dynamic': dynamic}


def parse_dump(filename: str, text: str) -> dict[str, Any]:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,249}\.conf', filename, re.IGNORECASE):
        raise ParseError('Имя файла: имя сервера.conf, без путей и специальных символов')
    if len(text.encode('utf-8')) > MAX_BYTES or '\x00' in text:
        raise ParseError('Файл больше 2 МиБ или содержит двоичные данные')
    hostname = filename[:-5].lower().rstrip('.')
    text = text.replace('\r\r\n', '\n').replace('\r\n', '\n').replace('\r', '\n').lstrip('\ufeff')
    parts = re.split(r'^# configuration file ([^\n]+):[ \t]*\n', text, flags=re.MULTILINE)
    files: dict[str, list[Node]] = {}
    if len(parts) > 1:
        for i in range(1, len(parts), 2):
            path = posixpath.normpath(parts[i])
            if path in files:
                raise ParseError('Повторный исходный файл в выгрузке')
            files[path] = _parse(parts[i+1], path)
    else:
        files['nginx.conf'] = _parse(text, 'nginx.conf')
    main = next(iter(files))
    prefix = posixpath.dirname(main)
    warnings: list[str] = []
    opaque_files: set[str] = set()
    used_files = {main}
    expanded = 0
    output_items = 0
    output_chars = 0

    def reserve(count: int) -> None:
        nonlocal output_items
        output_items += count
        if output_items > MAX_OUTPUT_ITEMS:
            raise ParseError('Слишком большой результат раскрытия настроек; разделите конфигурацию')

    def checked(item: dict[str, Any]) -> dict[str, Any]:
        nonlocal output_chars
        reserve(1)
        output_chars += len(str(item))
        if output_chars > MAX_OUTPUT_CHARS:
            raise ParseError('Слишком большой результат раскрытия настроек')
        return item

    def present(nodes: list[Node]) -> list[dict[str, Any]]:
        return [checked(_setting(n)) for n in nodes]

    def expand(nodes: list[Node], stack: tuple[str, ...], depth: int = 0, opaque: bool = False) -> list[Node]:
        nonlocal expanded
        if depth > MAX_DEPTH:
            raise ParseError('Превышена вложенность include/блоков')
        result = []
        for n in nodes:
            expanded += 1
            if expanded > MAX_NODES:
                raise ParseError('Слишком много директив после раскрытия include')
            if n.name == 'include':
                if len(n.args) != 1:
                    raise ParseError(f'{n.file}:{n.line}: include требует один путь')
                pattern = posixpath.normpath(posixpath.join(prefix, n.args[0]))
                matches = sorted(f for f in files if len(f.split('/')) == len(pattern.split('/'))
                                 and all(fnmatch.fnmatchcase(part, pat) for part, pat in zip(f.split('/'), pattern.split('/'), strict=True)))
                if not matches:
                    warnings.append(f'{n.file}:{n.line}: include {n.args[0]} отсутствует в выгрузке; полнота не подтверждена')
                for match in matches:
                    if match in stack:
                        raise ParseError(f'{n.file}:{n.line}: цикл include')
                    used_files.add(match)
                    if opaque:
                        opaque_files.add(match)
                    result.extend(expand(files[match], (*stack, match), depth+1, opaque))
            else:
                result.append(Node(n.name, n.args, n.file, n.line, expand(n.children, stack, depth+1, opaque or n.name not in {'http', 'server', 'location', 'upstream', 'events'}) if n.children is not None else None))
        return result

    tree = expand(files[main], (main,))
    servers: list[dict[str, Any]] = []
    for context in tree:
        if context.name in {'stream', 'mail'}:
            warnings.append(f'{context.name}: этот контекст пока не участвует в построении маршрутов')
        if context.name != 'http' or context.children is None:
            continue
        defaults = _effective([], context.children)
        pools: dict[str, list[Node]] = {}
        for n in context.children:
            if n.name == 'upstream' and n.args and n.children is not None:
                pools[n.args[0]] = [c for c in n.children if c.name == 'server']
        for server in context.children:
            if server.name != 'server' or server.children is None:
                continue
            effective = _effective(defaults, server.children)
            routes: list[dict[str, Any]] = []
            server_returns = [n for n in server.children if n.name == 'return']

            def route(node: Node, inherited: list[Node], ancestry: list[str],
                      pools: dict[str, list[Node]] = pools, routes: list[dict[str, Any]] = routes,
                      server_returns: list[Node] = server_returns) -> None:
                own = node.children or []
                settings = _effective(inherited, own)
                match = ' '.join(node.args) if node.name == 'location' else '(server)'
                passes = [n for n in settings if n.name in PASS]
                returns = server_returns or [n for n in settings if n.name == 'return']
                storage = [n for n in settings if n.name in {'root', 'alias'}]
                action = 'return' if returns else 'proxy' if passes else 'static' if storage else 'unknown'
                candidates = passes or storage
                directive: Node | None = returns[0] if returns else candidates[-1] if candidates else None
                targets = []
                reserve(1)
                if passes and not returns:
                    p = passes[-1]
                    if p.args:
                        endpoint = _endpoint(p.args[0], hostname, 'http' if p.name == 'proxy_pass' else 'tcp')
                        pool_name = endpoint['host']
                        if pool_name in pools:
                            reserve(len(pools[pool_name]))
                            for member in pools[pool_name]:
                                if member.args:
                                    targets.append(checked({**_endpoint(member.args[0], hostname, 'http'), 'parameters': ' '.join(member.args[1:]), 'file': member.file, 'line': member.line}))
                        else:
                            targets.append(checked({**endpoint, 'parameters': '', 'file': p.file, 'line': p.line}))
                        if endpoint['dynamic']:
                            warnings.append(f'{p.file}:{p.line}: динамический backend, адрес не вычислен')
                if any(n.name not in SAFE and n.name not in {'location', 'include', 'if'} for n in own):
                    warnings.append(f'{node.file}:{node.line}: есть неподдержанные директивы/обработчики; влияние на маршрут не вычислено')
                if any(n.name in {'if', 'rewrite', 'try_files', 'error_page'} for n in own + settings):
                    warnings.append(f'{node.file}:{node.line}: условные/внутренние переходы требуют проверки, показана конфигурация')
                routes.append(checked({'match': match, 'parents': ancestry, 'action': action,
                               'destination': _setting(directive)['value'] if directive else '', 'targets': targets,
                               'settings': present(settings), 'file': node.file, 'line': node.line}))
                for child in own:
                    if child.name == 'location':
                        route(child, settings, ancestry + ([match] if node.name == 'location' else []))

            route(server, defaults, [])
            servers.append({'id': len(servers), 'names': [v for n in effective if n.name == 'server_name' for v in n.args],
                            'listen': [' '.join(n.args) for n in effective if n.name == 'listen'],
                            'exposure': 'unknown', 'settings': present(effective), 'routes': routes,
                            'file': server.file, 'line': server.line})
    if not servers:
        warnings.append('HTTP server-блоки не найдены; проверьте полноту выгрузки')
    sources = []

    def source_nodes(nodes: list[Node], depth: int = 0, hidden: bool = False) -> list[dict[str, Any]]:
        result = []
        for n in nodes:
            safe_node = Node('[скрыто]', [], n.file, n.line) if hidden else n
            result.append({**present([safe_node])[0], 'depth': depth, 'block': n.children is not None})
            if n.children is not None:
                result.extend(source_nodes(n.children, depth+1, hidden or n.name not in {'http', 'server', 'location', 'upstream', 'events'}))
        return result

    for path, nodes in files.items():
        sources.append({'path': path, 'directives': source_nodes(nodes, hidden=path in opaque_files or path not in used_files)})
    return {'hostname': hostname, 'servers': servers, 'sources': sources, 'warnings': list(dict.fromkeys(warnings)),
            'exposure': 'unknown', 'parser_version': 1}
