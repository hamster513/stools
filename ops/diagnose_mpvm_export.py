#!/usr/bin/env python3
"""Собрать один обезличенный отчёт об экспорте MaxPatrol: python3 diagnose_mpvm_export.py."""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback
from collections import deque
from contextlib import suppress
from email.utils import parsedate_to_datetime
from functools import lru_cache
from itertools import chain, islice
from pathlib import Path
from urllib.parse import quote, urlsplit

VERSION = '1.1'
JSON_LIMIT = 1024 * 1024
CSV_LINE_LIMIT = 1024 * 1024
CSV_COLUMN_LIMIT = 128
PUBLIC_FILES = ('report.json', 'events.jsonl', 'summary.txt')
CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.I)
SAFE_KEYS = frozenset({
    'records', 'data', 'items', 'fields', 'name', 'id', 'type', 'value', 'version',
    'displayName', 'displayTime', 'deviceType', 'isArray', 'origin', 'localizedName',
    'count', 'total', 'totalCount', 'rowCount', 'row_count', 'rowsCount', 'isFinished',
    'isEstimated', 'isApproximate', 'hasMore', 'hasNextPage', 'offset', 'limit',
    'isPotentiallySlow', 'hasTimepointPipe', 'hasTimeseriesPipe', 'status', 'code',
    'error', 'errors', 'message', 'details', 'errorCode', 'errorMessage', 'result',
    '@Host', 'Host.OsName', 'Host.@Groups', 'Host.@Vulners.CVEs',
    'Host.UF_Criticality', 'Host.UF_Zone',
})
COUNT_KEYS = frozenset({'count', 'total', 'totalCount', 'rowCount', 'row_count', 'rowsCount'})


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def atomic_json(path, value):
    temporary = path.with_name(path.name + '.' + secrets.token_hex(4) + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            json.dump(value, out, ensure_ascii=False, indent=2, allow_nan=False)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def file_hash(path, check=None):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            if check:
                check()
            digest.update(chunk)
    return digest.hexdigest()


class Privacy:
    def __init__(self, key, sensitive=()):
        self.key = key
        self.sensitive = set()
        self.register(*sensitive)

    def register(self, *values):
        for value in values:
            if isinstance(value, str) and len(value) >= 4:
                self.sensitive.update((value, quote(value, safe=''), json.dumps(value)[1:-1]))

    def label(self, value, category='value'):
        data = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        return category + '-' + hmac.new(self.key, data.encode(), hashlib.sha256).hexdigest()[:24]

    def hide(self, value):
        text = str(value)
        for secret in sorted(self.sensitive, key=len, reverse=True):
            text = text.replace(secret, '[hidden]')
        text = re.sub(r"https?://[^\s<>\"']+", '[URL]', text)
        text = re.sub(r'(?i)(?:bearer\s+|pat_)[\w.+/=-]+', '[TOKEN]', text)
        text = re.sub(r'eyJ[\w-]*(?:\.[\w-]*){0,2}', '[TOKEN]', text)
        return text

    def clean(self, value):
        if isinstance(value, dict):
            return {str(k): self.clean(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.clean(v) for v in value]
        if isinstance(value, str):
            return self.hide(value)
        return value

    def schema(self, value, depth=0, metadata=False):
        if isinstance(value, dict):
            result = {'type': 'dict', 'length': len(value)}
            if depth < 4:
                fields = {}
                for key, item in islice(value.items(), 32):
                    name = key if key in SAFE_KEYS else self.label(key, 'field')
                    if metadata and (key in COUNT_KEYS or isinstance(item, bool)) and type(item) in (int, bool):
                        fields[name] = item
                    else:
                        fields[name] = self.schema(item, depth + 1, metadata=metadata and key != 'records')
                result['fields'] = fields
            return result
        if isinstance(value, list):
            return {'type': 'list', 'length': len(value),
                    'samples': [self.schema(item, depth + 1) for item in value[:3]] if depth < 4 else []}
        if value is None:
            return {'type': 'null'}
        if metadata and type(value) in (int, bool):
            return {'type': type(value).__name__, 'value': value}
        result = {'type': type(value).__name__, 'ref': self.label(value)}
        if isinstance(value, str):
            result['length'] = len(value)
        return result

    @staticmethod
    def signals(text):
        lower = text.casefold()
        patterns = {
            'timeout': r'timeout|timed out|тайм.?аут',
            'invalid_query': r'pdql.*(?:reject|invalid|отклон)|syntax|синтакс',
            'unknown_field': r'unknown.*(?:field|property|identifier)|неизвестн.*(?:пол|свойств)',
            'token_expired': r'(?:token|токен).*(?:expir|invalid|истек|недейств)',
            'authorization': r'unauthori|forbidden|access denied|доступ.*запрещ',
            'count_mismatch': r'количество строк.*не совпадает',
            'verification_failed': r'проверка полноты экспорта',
            'api_restarted': r'api перезапускался',
            'diagnostic_deadline': r'diagnostic.*deadline',
            'csv_diagnostic_limit': r'diagnostic csv.*limit',
            'csv_field_limit': r'field.*limit|поле.*лимит',
            'json_body_limit': r'json response limit',
            'disk_reserve': r'diagnostic disk reserve',
            'saved_csv_mismatch': r'saved csv integrity|csv without completion',
            'source_changed': r'source configuration changed|query changed',
        }
        return [name for name, pattern in patterns.items() if re.search(pattern, lower)]

    def error(self, exc):
        causes, seen = [], set()
        while exc is not None and id(exc) not in seen and len(causes) < 8:
            seen.add(id(exc))
            item = {'class': type(exc).__module__ + '.' + type(exc).__name__,
                    'signals': self.signals(str(exc)),
                    'frames': [{'file': Path(f.filename).name, 'function': f.name, 'line': f.lineno}
                               for f in traceback.extract_tb(exc.__traceback__)[-8:]]}
            for key in ('errno', 'status', 'lineno', 'colno'):
                if type(getattr(exc, key, None)) is int:
                    item[key] = getattr(exc, key)
            causes.append(item)
            exc = exc.__cause__ or (exc.__context__ if not exc.__suppress_context__ else None)
        return {'chain': causes}


class RunStore:
    def __init__(self, base, run_id, resume=False):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', run_id):
            raise ValueError('invalid run id')
        base = Path(base).resolve()
        base.mkdir(parents=True, exist_ok=True)
        self.path = base / run_id
        if self.path.is_symlink():
            raise ValueError('symlink workspace')
        self.path.mkdir(mode=0o700, exist_ok=resume)
        os.chmod(self.path, 0o700)
        self.private, self.public = self.path / 'private', self.path / 'public'
        for directory in (self.private, self.public):
            if directory.is_symlink():
                raise ValueError('symlink workspace')
            directory.mkdir(mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
        salt = self.private / 'salt'
        if resume:
            for existing in (salt, self.private / 'state.json', self.public / 'report.json'):
                if existing.is_symlink() or not existing.is_file():
                    raise ValueError('invalid resume file')
            key = salt.read_bytes()
            self.state = json.loads((self.private / 'state.json').read_text())
            self.report = json.loads((self.public / 'report.json').read_text())
        else:
            key = secrets.token_bytes(32)
            with os.fdopen(os.open(salt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as out:
                out.write(key)
            self.state = {'schema': 1, 'tokens': {}, 'steps': {}}
            self.report = {'schema': 1, 'collector_version': VERSION, 'run_id': run_id,
                           'started_at': utc_now(), 'stages': {}, 'findings': []}
        self.privacy = Privacy(key)
        self.events = self.public / 'events.jsonl'
        if self.events.is_symlink():
            raise ValueError('symlink events')
        if not self.events.exists():
            os.close(os.open(self.events, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        self.checkpoint()

    def bind_source(self, fingerprint):
        previous = self.state.get('source_fingerprint')
        if previous is not None and previous != fingerprint:
            raise ValueError('source configuration changed; start a new run')
        self.state['source_fingerprint'] = fingerprint
        self.report['source_fingerprint'] = fingerprint
        self.checkpoint()

    def checkpoint(self):
        atomic_json(self.private / 'state.json', self.state)
        atomic_json(self.public / 'report.json', self.privacy.clean(self.report))

    def emit(self, stage, message, **facts):
        event = self.privacy.clean({'at': utc_now(), 'stage': stage, 'message': message, **facts})
        with os.fdopen(os.open(self.events, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW), 'w', encoding='utf-8') as out:
            out.write(json.dumps(event, ensure_ascii=False) + '\n')
        print(f"[{event['at'][11:19]}] {stage}: {event['message']}", flush=True)

    def summary(self):
        lines = ['MaxPatrol — диагностика экспорта', 'Run: ' + self.report['run_id'],
                 'Status: ' + self.report.get('status', 'in_progress'), '']
        for name, stage in self.report['stages'].items():
            lines.append(f"{name}: {stage.get('status', 'unknown')}")
            result = stage.get('result') or {}
            if isinstance(result, dict):
                for field in ('raw_records', 'app_records', 'blank_records', 'bytes', 'records_count', 'within_bound'):
                    if field in result:
                        lines.append(f"  {field}: {result[field]}")
        lines += ['', 'CSV и секреты остаются в private на сервере и не включены в архив.',
                  'Успешный HTTP/CSV не доказывает полноту результата; см. report.json.']
        return '\n'.join(lines) + '\n'

    def bundle(self):
        self.checkpoint()
        summary = self.public / 'summary.txt'
        with os.fdopen(os.open(summary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), 'w', encoding='utf-8') as out:
            out.write(self.privacy.hide(self.summary()))
        archive = self.path / ('report-' + secrets.token_hex(4) + '.tar.gz')
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as out, tarfile.open(fileobj=out, mode='w:gz') as tar:
            for name in PUBLIC_FILES:
                source = self.public / name
                if source.is_symlink() or not source.is_file():
                    raise ValueError('invalid public report file')
                info = tar.gettarinfo(str(source), arcname=name)
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                info.mode = 0o600
                with source.open('rb') as content:
                    tar.addfile(info, content)
        return archive


def cell_text(value):
    if value is None:
        return ''
    if isinstance(value, dict):
        for key in ('name', 'displayName', 'value'):
            if value.get(key) is not None:
                return cell_text(value[key])
        return ''
    if isinstance(value, list):
        return ' '.join(cell_text(item) for item in value)
    return str(value)


def row_signature(row, privacy):
    host = cell_text(row.get('@Host')).strip().casefold()
    os_name = cell_text(row.get('Host.OsName')).strip().casefold()
    cves = sorted(set(c.upper() for c in CVE_RE.findall(cell_text(row.get('Host.@Vulners.CVEs')))))
    return {'host': privacy.label(host, 'host') if host else '',
            'os': privacy.label(os_name, 'os') if os_name else '',
            'cves': privacy.label(cves, 'cves') if cves else '',
            'columns_present': [k for k in ('@Host', 'Host.OsName', 'Host.@Vulners.CVEs') if k in row]}


class BoundedText:
    def __init__(self, stream, deadline=None):
        self.stream, self.deadline, self.lines, self.record_chars = stream, deadline, 0, 0

    def record_done(self):
        self.record_chars = 0

    def readline(self):
        if self.deadline is not None and self.lines % 10_000 == 0 and time.monotonic() >= self.deadline:
            raise TimeoutError('diagnostic deadline')
        line = self.stream.readline(CSV_LINE_LIMIT + 1)
        self.lines += 1
        self.record_chars += len(line)
        if self.record_chars > CSV_LINE_LIMIT:
            raise ValueError('diagnostic CSV limit between yielded records exceeded')
        return line

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if not line:
            raise StopIteration
        return line


def scan_csv(path, privacy, app_iterator, *, cardinality_limit=100_000, progress=None, deadline=None):
    started = time.monotonic()
    result = {'bytes': path.stat().st_size, 'raw_records': 0, 'app_records': 0,
              'blank_records': 0, 'blank_lines': 0, 'malformed_rows': 0,
              'repeated_headers': 0, 'rows_with_cve': 0, 'raw_complete': False,
              'app_complete': False, 'errors': [], 'chars_between_yielded_records_limit': CSV_LINE_LIMIT,
              'header_column_limit': CSV_COLUMN_LIMIT, 'parser_field_limit_chars': csv.field_size_limit()}
    sets = {name: set() for name in ('hosts', 'hosts_with_cve', 'cves')}
    capped = {name: False for name in sets}
    raw_first, raw_last, app_first, app_last = [], deque(maxlen=3), [], deque(maxlen=3)

    @lru_cache(maxsize=2048)
    def host_ref(value):
        return privacy.label(value, 'host')

    def add(name, value):
        if value and value not in sets[name]:
            if len(sets[name]) < cardinality_limit:
                sets[name].add(value)
            else:
                capped[name] = True

    def tick(phase, count):
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError('diagnostic deadline')
        if progress:
            progress(phase, count)

    try:
        tick('csv_raw', 0)
        with path.open(encoding='utf-8-sig', newline='') as stream:
            stream = BoundedText(stream, deadline)
            header = stream.readline()
            delimiter = ';' if header.count(';') >= header.count(',') else ','
            reader = csv.reader(chain([header], stream), delimiter=delimiter, strict=True)
            columns = [c.strip() for c in next(reader)]
            stream.record_done()
            result['header_columns'] = len(columns)
            if len(columns) > CSV_COLUMN_LIMIT:
                raise ValueError('diagnostic CSV column limit exceeded')
            result['columns'] = [c if c in SAFE_KEYS else privacy.label(c, 'column') for c in columns]
            result['header_valid'] = bool(columns) and all(columns) and len(set(columns)) == len(columns)
            result['required_columns_present'] = {'@Host', 'Host.@Vulners.CVEs'}.issubset(columns)
            for index, values in enumerate(reader):
                stream.record_done()
                if index % 10_000 == 0:
                    tick('csv_raw', result['raw_records'])
                if not values:
                    result['blank_lines'] += 1
                    continue
                result['raw_records'] += 1
                blank = all(not v.strip() for v in values)
                result['blank_records'] += int(blank)
                if len(values) != len(columns):
                    result['malformed_rows'] += 1
                    result.setdefault('first_bad_line', reader.line_num)
                else:
                    result['repeated_headers'] += int(values == columns)
                    row = dict(zip(columns, values))
                    if len(raw_first) < 3:
                        raw_first.append(row)
                    raw_last.append(row)
                    host = row.get('@Host', '').strip().casefold()
                    ref = host_ref(host) if len(host) <= 1024 else privacy.label(host, 'host')
                    cves = set(c.upper() for c in CVE_RE.findall(row.get('Host.@Vulners.CVEs', '')))
                    if host:
                        add('hosts', ref)
                        if cves:
                            add('hosts_with_cve', ref)
                    result['rows_with_cve'] += bool(cves)
                    for cve in cves:
                        add('cves', cve)
                if result['raw_records'] % 10_000 == 0:
                    tick('csv_raw', result['raw_records'])
            result['physical_lines'] = reader.line_num
            result['raw_complete'] = True
    except Exception as exc:
        result['errors'].append({'phase': 'independent_csv_reader', **privacy.error(exc)})
    try:
        tick('csv_app', 0)
        with path.open(encoding='utf-8-sig', newline='') as stream:
            if result.get('header_columns', 0) > CSV_COLUMN_LIMIT:
                raise ValueError('diagnostic CSV column limit exceeded')
            bounded = BoundedText(stream, deadline)
            for row in app_iterator(bounded):
                bounded.record_done()
                result['app_records'] += 1
                if len(app_first) < 3:
                    app_first.append(row)
                app_last.append(row)
                if result['app_records'] % 10_000 == 0:
                    tick('csv_app', result['app_records'])
        result['app_complete'] = True
    except Exception as exc:
        result['errors'].append({'phase': 'installed_application_parser', **privacy.error(exc)})
    for name in sets:
        result[name] = {'count': len(sets[name]), 'capped': capped[name]}
    for name, rows in (('raw_first', raw_first), ('raw_last', raw_last), ('app_first', app_first), ('app_last', app_last)):
        result[name] = [row_signature(row, privacy) for row in rows]
    result['seconds'] = round(time.monotonic() - started, 3)
    return result


class Collector:
    def __init__(self, store, conn, http, base, build_query, app_iterator, *,
                 reserve_bytes=1024 ** 3, budget_seconds=3600):
        self.store, self.conn, self.http = store, conn, http
        self.base = base.rstrip('/') + '/api/assets_temporal_readmodel/v1/assets_grid'
        self.build_query, self.app_iterator = build_query, app_iterator
        self.reserve_bytes = reserve_bytes
        self.deadline = time.monotonic() + budget_seconds
        self.last_progress = 0.0
        store.privacy.register(conn.api_token, base, urlsplit(base).hostname)

    def check(self, disk=False):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('diagnostic deadline')
        if disk and shutil.disk_usage(self.store.path).free < self.reserve_bytes + 1024 ** 2:
            raise OSError(28, 'diagnostic disk reserve')
        return min(600.0, remaining)

    def begin(self, name):
        result = {}
        self.store.report['stages'][name] = {'status': 'running', 'started_at': utc_now(), 'result': result}
        self.store.emit(name, 'начато')
        self.store.checkpoint()
        return result, time.monotonic()

    def finish(self, name, result, started, error=None):
        stage = self.store.report['stages'][name]
        stage.update(status='error' if error else 'ok', seconds=round(time.monotonic() - started, 3),
                     finished_at=utc_now(), result=result)
        if error:
            stage['error'] = self.store.privacy.error(error)
        self.store.checkpoint()
        self.store.emit(name, 'ошибка; подробности сохранены' if error else 'завершено')

    def progress(self, stage, **counts):
        if time.monotonic() - self.last_progress >= 20:
            self.last_progress = time.monotonic()
            self.store.report['progress'] = {'stage': stage, **counts, 'at': utc_now()}
            self.store.checkpoint()
            self.store.emit(stage, ', '.join(f'{k}={v}' for k, v in counts.items()))

    @staticmethod
    def response_info(response):
        info = {'http_status': response.status_code}
        for header in ('content-type', 'content-encoding', 'transfer-encoding'):
            value = response.headers.get(header, '').split(';')[0].lower().strip()
            if re.fullmatch(r'[a-z0-9/+.-]{1,80}', value):
                info[header] = value
        length = response.headers.get('content-length', '')
        if length.isdigit() and len(length) < 20:
            info['content_length'] = int(length)
        try:
            info['server_date'] = parsedate_to_datetime(response.headers['date']).isoformat()
        except (ValueError, KeyError, TypeError, OverflowError):
            pass
        return info

    def json_request(self, name, method, suffix, *, params=None, body=None, cache=True):
        result, started = self.begin(name)
        private = self.store.private / (name + '.json')
        signature = self.store.privacy.label([method, suffix, params, body], 'request')
        cached = self.store.state['steps'].get(name)
        try:
            self.check()
            if cache and cached and cached.get('request') == signature and private.is_file():
                data = json.loads(private.read_text())
                result.update(cached['result'], reused=True)
            else:
                headers = {'Authorization': 'Bearer ' + self.conn.api_token.strip()}
                with self.http.stream(method, self.base + ('/' + suffix if suffix else ''),
                                      headers=headers, params=params, json=body, timeout=self.check()) as response:
                    result.update(self.response_info(response))
                    result['headers_seconds'] = round(time.monotonic() - started, 3)
                    buffer = bytearray()
                    for chunk in response.iter_bytes(chunk_size=65536):
                        self.check()
                        if len(buffer) + len(chunk) > JSON_LIMIT:
                            result['body_limit_bytes'] = JSON_LIMIT
                            raise ValueError('JSON response limit exceeded')
                        buffer.extend(chunk)
                    result['bytes'] = len(buffer)
                    result['signals'] = self.store.privacy.signals(buffer.decode('utf-8', errors='replace'))
                    try:
                        data = json.loads(buffer)
                    except ValueError:
                        response.raise_for_status()
                        raise
                    result['body_shape'] = self.store.privacy.schema(data, metadata=True)
                    response.raise_for_status()
                atomic_json(private, data)
                self.store.state['steps'][name] = {'request': signature, 'result': result.copy()}
            self.finish(name, result, started)
            return data
        except Exception as exc:
            self.finish(name, result, started, exc)
            return None

    def query_token(self, name, query):
        fingerprint = self.store.privacy.label(query, 'query')
        saved = self.store.state['tokens'].get(name)
        if saved:
            if saved['query'] != fingerprint:
                raise ValueError('query changed; start a new run')
            self.store.privacy.register(saved['token'])
            return saved['token']
        data = self.json_request(name + '_token', 'POST', '', body={'pdql': query, 'includeNestedGroups': False})
        if not isinstance(data, dict) or not isinstance(data.get('token'), str) or not data['token']:
            stage = self.store.report['stages'][name + '_token']
            if stage['status'] == 'ok':
                stage.update(status='error', error={'reason': 'missing_query_token'})
            self.store.report['findings'].append({'observed': 'query_token_unavailable', 'stage': name})
            self.store.checkpoint()
            return None
        token = data['token']
        self.store.privacy.register(token)
        self.store.state['tokens'][name] = {'token': token, 'query': fingerprint, 'created_at': utc_now()}
        self.store.checkpoint()
        return token

    def download(self, name, token, max_bytes=None):
        result, started = self.begin(name)
        complete = self.store.private / (name + '.csv')
        partial = self.store.private / (name + '.part')
        saved = self.store.state['steps'].get(name)
        token_ref = self.store.privacy.label(token, 'token')
        try:
            self.check(disk=True)
            if saved and saved.get('complete'):
                if (saved['token'] != token_ref or not complete.is_file()
                        or complete.stat().st_size != saved['result']['bytes']
                        or file_hash(complete, self.check) != saved['sha256']):
                    raise ValueError('saved CSV integrity or query token mismatch')
                result.update(saved['result'], reused=True)
                self.finish(name, result, started)
                return complete
            if complete.exists():
                raise ValueError('CSV without completion checkpoint; start a new run')
            if partial.exists():
                partial.rename(partial.with_suffix('.interrupted-' + secrets.token_hex(3)))
            digest, size = hashlib.sha256(), 0
            with self.http.stream('GET', self.base + '/export', params={'pdqlToken': token},
                                  headers={'Authorization': 'Bearer ' + self.conn.api_token.strip()},
                                  timeout=self.check()) as response:
                result.update(self.response_info(response))
                result['headers_seconds'] = round(time.monotonic() - started, 3)
                response.raise_for_status()
                with os.fdopen(os.open(partial, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb') as out:
                    for chunk in response.iter_bytes(chunk_size=65536):
                        self.check(disk=True)
                        if max_bytes is not None and size + len(chunk) > max_bytes:
                            raise ValueError('small CSV exceeded byte limit')
                        out.write(chunk)
                        digest.update(chunk)
                        size += len(chunk)
                        result['bytes'] = size
                        self.progress(name, bytes=size)
                    out.flush()
                    os.fsync(out.fileno())
                result.update(bytes=size, wire_bytes=response.num_bytes_downloaded, http_eof=True)
            partial.rename(complete)
            self.store.state['steps'][name] = {'complete': True, 'token': token_ref,
                                               'sha256': digest.hexdigest(), 'result': result.copy()}
            self.finish(name, result, started)
            return complete
        except Exception as exc:
            result['http_eof'] = False
            self.finish(name, result, started, exc)
            return None

    def analyze(self, name, path):
        result, started = self.begin(name)
        saved = self.store.state['steps'].get(name)
        if saved:
            result.update(saved['result'], reused=True)
        else:
            result.update(scan_csv(path, self.store.privacy, self.app_iterator, deadline=self.deadline,
                                   progress=lambda phase, count: self.progress(name + '/' + phase, rows=count)))
            if result['raw_complete'] and result['app_complete']:
                self.store.state['steps'][name] = {'result': result.copy()}
        self.finish(name, result, started, None if result.get('app_complete') and result.get('raw_complete')
                    else ValueError('CSV parse incomplete'))
        return result

    def page(self, name, token, offset, *, hard_limit=None, cache=True):
        params = {'pdqlToken': token, 'offset': offset, 'limit': 2}
        data = self.json_request(name, 'GET', 'data', params=params, cache=cache)
        stage = self.store.report['stages'][name]
        result = stage['result']
        result.update(offset=offset, requested_limit=2)
        records = data.get('records') if isinstance(data, dict) else None
        if isinstance(records, list):
            result.update(records_count=len(records), records_ref=self.store.privacy.label(records, 'records'),
                          records=[row_signature(row, self.store.privacy) for row in records[:3] if isinstance(row, dict)])
            if hard_limit is not None:
                result['hard_limit'] = hard_limit
                result['within_bound'] = len(records) <= max(0, min(2, hard_limit - offset))
        elif data is not None:
            stage['status'] = 'error'
            stage['error'] = {'reason': 'missing_records_list'}
        self.store.checkpoint()

        return result

    def run(self):
        small = self.query_token('small', self.build_query(limit=3))
        if small:
            path = self.download('small_csv', small, max_bytes=JSON_LIMIT)
            if path:
                self.analyze('small_csv_counts', path)
            for offset in range(5):
                self.page('small_page_' + str(offset), small, offset, hard_limit=3)

        token = self.query_token('full', self.build_query())
        if not token:
            return
        self.json_request('full_count_before', 'GET', 'row_count', params={'pdqlToken': token})
        path = self.download('full_csv', token)
        if not path:
            return
        counts = self.analyze('full_csv_counts', path)
        first = self.page('full_first', token, 0)
        if not counts['app_complete']:
            return
        n = counts['app_records']
        tail = self.page('full_boundary', token, max(0, n - 1))
        after = self.page('full_after', token, n)
        self.json_request('full_count_after', 'GET', 'row_count', params={'pdqlToken': token})
        if counts['raw_complete'] and counts['raw_records'] != n:
            self.page('full_raw_boundary', token, max(0, counts['raw_records'] - 1))
            self.page('full_raw_after', token, counts['raw_records'])
        if n:
            cap = self.query_token('capped', self.build_query(limit=n))
            if cap:
                self.page('capped_at_limit', cap, n, hard_limit=n)
                self.page('capped_before_limit', cap, n - 1, hard_limit=n)
        repeat = self.page('full_boundary_repeat', token, max(0, n - 1), cache=False)
        observed = {'observed': 'export_boundary', 'csv_app_records': n,
                    'expected_boundary_records': 1 if n else 0,
                    'actual_boundary_records': tail.get('records_count'),
                    'records_after_csv': after.get('records_count'),
                    'same_boundary_response': tail.get('records_ref') == repeat.get('records_ref')
                    if tail.get('records_ref') and repeat.get('records_ref') else None,
                    'first_page_equals_boundary': first.get('records_ref') == tail.get('records_ref')
                    if first.get('records_ref') and tail.get('records_ref') else None}
        self.store.report['findings'].append(observed)
        self.store.report['interpretation_limits'] = [
            'row_count is an observation; exactness is not assumed',
            'a query token is not a proven immutable snapshot',
            'two returned records do not mean the mismatch is only one record',
            'record fingerprints compare normalized selected fields, not full CSV and JSON objects',
            'successful HTTP EOF does not establish semantic export completeness',
        ]
        self.store.checkpoint()


def read_database(store, sessionmaker, text):
    """Every observation has its own bounded, read-only transaction."""
    queries = {
        'hosts_exact': 'SELECT count(*) AS count FROM vm_host',
        'pairs_exact': 'SELECT count(*) AS count FROM vm_host_cve',
        'estimates': "SELECT relname, n_live_tup, n_dead_tup, last_analyze, last_autoanalyze "
                     "FROM pg_stat_user_tables WHERE relname IN ('vm_host','vm_host_cve','vm_import','vm_job') LIMIT 4",
        'imports': 'SELECT id, finished_at, source, hosts, pairs, cves FROM vm_import ORDER BY id DESC LIMIT 10',
        'jobs': "SELECT id, kind, stage, status, processed, total, started_at, finished_at, "
                "left(error, 1000) AS error_hint FROM vm_job ORDER BY id DESC LIMIT 15",
        'activity': "SELECT state, wait_event_type, wait_event, count(*) AS count "
                    "FROM pg_stat_activity WHERE datname=current_database() "
                    "GROUP BY state, wait_event_type, wait_event LIMIT 20",
        'schema': 'SELECT version_num FROM alembic_version LIMIT 5',
        'postgres': 'SELECT version() AS version',
    }
    result = {}
    safe_enums = {'vm', 'file', 'harbor', 'ksc', 'vm_host', 'vm_host_cve', 'vm_import', 'vm_job',
                  'import_vm', 'import_file', 'sync_harbor', 'recompute', 'risk', 'scoring', 'writing',
                  'exporting', 'parsing', 'pending', 'done', 'running', 'failed', 'cancelled',
                  'fetching', 'committing', 'active', 'idle', 'idle in transaction'}
    for name, query in queries.items():
        started = time.monotonic()
        try:
            with sessionmaker() as db:
                db.execute(text('SET TRANSACTION READ ONLY'))
                db.execute(text("SET LOCAL statement_timeout = '5s'"))
                rows = db.execute(text(query)).mappings().all()
                cleaned = []
                for row in rows:
                    item = {}
                    for key, value in row.items():
                        if key == 'error_hint':
                            item['error_signals'] = store.privacy.signals(value or '')
                        elif value is None or isinstance(value, (bool, int, float)):
                            item[key] = value
                        elif isinstance(value, (dt.datetime, dt.date)):
                            item[key] = value.isoformat()
                        elif value in safe_enums:
                            item[key] = value
                        elif key == 'version_num' and re.fullmatch(r'[a-f0-9]{8,40}', str(value)):
                            item[key] = value
                        elif key == 'version':
                            match = re.search(r'PostgreSQL (\d+(?:\.\d+){0,2})', str(value))
                            item[key] = match.group(1) if match else 'unknown'
                        elif key in ('wait_event_type', 'wait_event') and re.fullmatch(r'[A-Za-z0-9_]{1,60}', str(value)):
                            item[key] = value
                        else:
                            item[key] = store.privacy.label(value, key)
                    cleaned.append(item)
                db.rollback()
                result[name] = {'rows': cleaned, 'seconds': round(time.monotonic() - started, 3)}
        except Exception as exc:
            result[name] = {'error': store.privacy.error(exc), 'seconds': round(time.monotonic() - started, 3)}
        store.report['database'] = result
        store.checkpoint()
    return result


def worker(args):
    import fcntl
    logging.disable(logging.CRITICAL)
    os.umask(0o077)
    base = Path(os.environ.get('STOOLS_DATA_DIR', '/data')) / 'vm' / 'diagnostics'
    # Hold the run lock before loading or modifying any resumed checkpoints.
    base.mkdir(parents=True, exist_ok=True)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', args.run_id or ''):
        raise ValueError('invalid run id')
    lock = os.open(base / (args.run_id + '.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(lock)
        raise
    store = RunStore(base, args.run_id, resume=bool(args.resume))
    print('STOOLS_DIAG_WORKER ' + json.dumps({'pid': os.getpid(), 'run_id': args.run_id}), flush=True)
    stop = threading.Event()
    started = time.monotonic()

    def heartbeat():
        while not stop.wait(30):
            print(f'[{utc_now()[11:19]}] heartbeat: диагностика работает, {int(time.monotonic() - started)} с', flush=True)

    def interrupted(signum, frame):
        raise KeyboardInterrupt

    def expired(signum, frame):
        raise TimeoutError('diagnostic overall deadline')

    previous_term = signal.signal(signal.SIGTERM, interrupted)
    previous_alarm = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, args.budget_minutes * 60)
    pulse = threading.Thread(target=heartbeat, daemon=True)
    pulse.start()
    code = 0
    try:
        from importlib import metadata
        from sqlalchemy import text
        from api.db.base import get_sessionmaker
        from api.modules.vm.services.settings import load_settings
        from api.modules.vm.core import mpvm, sources

        sm = get_sessionmaker()
        with sm() as db:
            db.execute(text('SET TRANSACTION READ ONLY'))
            db.execute(text("SET LOCAL statement_timeout = '5s'"))
            conn = load_settings(db).connection.unsealed()
            db.rollback()
        values = conn.model_dump()
        store.privacy.register(conn.api_token, conn.host, conn.pdql_extra, *conn.os_exclude)
        store.bind_source(store.privacy.label(values, 'source'))
        runtime = {'python': sys.version.split()[0], 'architecture': os.uname().machine,
                   'collector_sha256': args.source_sha256,
                   'modules': {name: file_hash(Path(module.__file__)) for name, module in (('mpvm', mpvm), ('sources', sources))}}
        for package in ('httpx', 'SQLAlchemy', 'psycopg', 'pydantic'):
            try:
                runtime[package] = metadata.version(package)
            except metadata.PackageNotFoundError:
                pass
        for name in ('memory.current', 'memory.max', 'memory.peak', 'memory.events'):
            path = Path('/sys/fs/cgroup') / name
            if path.is_file():
                value = path.read_text()[:1024]
                if re.fullmatch(r'[a-z0-9_\s]+', value):
                    runtime[name] = value.strip()
        store.report['runtime'] = runtime
        store.report['container'] = json.loads(getattr(args, 'container_info', '{}'))
        store.report['source'] = {'host_ref': store.privacy.label(conn.host, 'host'), 'limit': conn.limit,
                                  'verify_tls': conn.verify_tls, 'os_exclusion_count': len(conn.os_exclude),
                                  'has_extra_filter': bool(conn.pdql_extra.strip()),
                                  'query_ref': store.privacy.label(mpvm.build_pdql(conn), 'query')}
        store.report['budget'] = {'seconds': args.budget_minutes * 60, 'json_bytes': JSON_LIMIT,
                                  'disk_reserve_bytes': args.reserve_gib * 1024 ** 3}
        store.report['disk_at_start'] = dict(zip(('total', 'used', 'free'), shutil.disk_usage(store.path)))
        store.checkpoint()
        store.emit('database', 'версии, количества и история; транзакции только для чтения')
        read_database(store, sm, text)
        if not conn.host.strip() or not conn.api_token.strip():
            raise ValueError('MaxPatrol connection not configured')
        with mpvm.make_client(conn, timeout=600) as http:
            run = Collector(store, conn, http, mpvm.MpVmClient(conn, http).base,
                            lambda limit=None: mpvm.build_pdql(conn, limit=limit), sources.iter_csv_records,
                            reserve_bytes=args.reserve_gib * 1024 ** 3,
                            budget_seconds=max(0, args.budget_minutes * 60 - (time.monotonic() - started)))
            run.run()
        store.report['status'] = 'completed_with_errors' if any(
            stage['status'] == 'error' for stage in store.report['stages'].values()) else 'completed'
    except KeyboardInterrupt as exc:
        code = 130
        store.report.update(status='interrupted', error=store.privacy.error(exc))
    except Exception as exc:
        code = 1
        store.report.update(status='failed', error=store.privacy.error(exc))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGALRM, previous_alarm)
        stop.set()
        pulse.join(timeout=1)
        for stage in store.report['stages'].values():
            if stage['status'] == 'running':
                stage['status'] = 'interrupted'
        store.report['finished_at'] = utc_now()
        store.report['elapsed_seconds'] = round(time.monotonic() - started, 1)
        archive = store.bundle()
        print('STOOLS_DIAG_RESULT ' + json.dumps({'archive': str(archive), 'sha256': file_hash(archive),
                                                'run_id': args.run_id, 'status': store.report['status']}), flush=True)
        os.close(lock)
    return code


def select_container(rows, requested):
    candidates = [row for row in rows if not requested or row.get('Names') == requested or row.get('ID') == requested]
    if len(candidates) != 1:
        raise ValueError('Не найден единственный API-контейнер; укажите --container ИМЯ')
    return candidates[0]['ID']


def docker_run(arguments, **kwargs):
    return subprocess.run(['docker', *arguments], text=True, capture_output=True, timeout=30, check=True, **kwargs)


def stop_worker(container, pid, run_id, launch_id):
    # PID reuse must never cause a signal to the API or another process.
    script = '''import os, signal, sys
from pathlib import Path
paths = [Path('/proc') / sys.argv[1]] if sys.argv[1] != '0' else Path('/proc').iterdir()
for path in paths:
    if not path.name.isdigit():
        continue
    try:
        cmd = (path / 'cmdline').read_bytes().split(b'\\0')
        if b'--worker' in cmd and sys.argv[2].encode() in cmd and sys.argv[3].encode() in cmd:
            os.kill(int(path.name), signal.SIGINT)
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        pass
'''
    docker_run(['exec', container, 'python', '-c', script, str(pid or 0), run_id, launch_id])


def watchdog(proc, stop, state, stop_owned, budget, startup=60, grace=30):
    started = time.monotonic()

    def watch():
        while not stop.wait(0.1):
            elapsed = time.monotonic() - started
            reason = ('cancelled' if state['cancelled'] else
                      'startup_timeout' if state['pid'] is None and elapsed > startup else
                      'overall_timeout' if elapsed > budget + 90 else None)
            if reason:
                state['reason'] = reason
                try:
                    stop_owned(state['pid'])
                except (OSError, subprocess.SubprocessError):
                    pass
                try:
                    proc.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                return
    thread = threading.Thread(target=watch, daemon=True)
    thread.start()
    return thread


def host(args):
    run_id = args.resume or (dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(3))
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    args.run_id = run_id
    flags = [] if args.container else ['--filter', 'label=com.docker.compose.service=api']
    listing = docker_run(['ps', *flags, '--format', '{{json .}}']).stdout
    rows = [json.loads(line) for line in listing.splitlines() if line.strip()]
    container = select_container(rows, args.container)
    inspect_format = ('{"image_id":{{json .Image}},"restart_count":{{json .RestartCount}},'
                      '"oom_killed":{{json .State.OOMKilled}},"started_at":{{json .State.StartedAt}},'
                      '"memory_limit":{{json .HostConfig.Memory}}}')
    container_info = json.loads(docker_run(['inspect', '--format', inspect_format, container]).stdout)
    source = Path(__file__).read_bytes()
    launch_id = secrets.token_hex(16)
    command = ['docker', 'exec', '-i', container, 'python', '-', '--worker', '--run-id', run_id,
               '--launch-id', launch_id,
               '--budget-minutes', str(args.budget_minutes), '--reserve-gib', str(args.reserve_gib),
               '--container-info', json.dumps(container_info),
               '--source-sha256', hashlib.sha256(source).hexdigest()]
    if args.resume:
        command += ['--resume', args.resume]
    print('Диагностика MaxPatrol ' + VERSION + ' (Python ' + sys.version.split()[0] +
          '). БД не изменяется; CSV остаётся на сервере.', flush=True)
    print('Run: ' + run_id + '; при прерывании: python3 diagnose_mpvm_export.py --resume ' + run_id, flush=True)
    print('Полная выгрузка и проверки могут занять десятки минут. Ctrl+C сохраняет частичный отчёт.', flush=True)
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, start_new_session=True)
    result = None
    state, stop = {'pid': None, 'cancelled': False}, threading.Event()
    watcher = watchdog(proc, stop, state, lambda pid: stop_worker(container, pid, run_id, launch_id), args.budget_minutes * 60)
    previous = signal.getsignal(signal.SIGINT)

    def cancel(signum, frame):
        if not state['cancelled']:
            state['cancelled'] = True
            print('Остановка диагностики; ожидаю сохранения отчёта…', flush=True)

    signal.signal(signal.SIGINT, cancel)
    try:
        proc.stdin.write(source.decode('utf-8'))
        proc.stdin.close()
        for line in iter(lambda: proc.stdout.readline(8192), ''):
            if line.startswith('STOOLS_DIAG_WORKER '):
                info = json.loads(line.split(' ', 1)[1])
                if info['run_id'] == run_id:
                    state['pid'] = int(info['pid'])
            elif line.startswith('STOOLS_DIAG_RESULT '):
                result = json.loads(line.split(' ', 1)[1])
            elif line.startswith('STOOLS_DIAG_BOOT_ERROR '):
                args.worker_error = json.loads(line.split(' ', 1)[1])
                if args.worker_error.get('busy'):
                    print('Этот запуск диагностики уже работает; одновременное продолжение запрещено.', flush=True)
            elif re.match(r'^\[\d{2}:\d{2}:\d{2}\] ', line):
                print(line.rstrip()[:400], flush=True)
        returncode = proc.wait(timeout=30)
    finally:
        signal.signal(signal.SIGINT, previous)
        stop.set()
        watcher.join(timeout=0.2)
        if not result and not state.get('reason') and not getattr(args, 'worker_error', None):
            try:
                stop_worker(container, state['pid'], run_id, launch_id)
            except (OSError, subprocess.SubprocessError):
                pass
    if not result or result.get('run_id') != run_id:
        raise RuntimeError('worker ended before archive; exit code ' + str(returncode))
    remote = Path(result['archive'])
    if remote.parent.name != run_id or not re.fullmatch(r'report-[a-f0-9]{8}\.tar\.gz', remote.name):
        raise ValueError('invalid archive path')
    destination = output / ('mpvm-diagnostics-' + run_id + '-' + remote.name[len('report-'):])
    temporary = destination.with_suffix('.partial')
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    try:
        # Read inside the running mount namespace: docker cp cannot see some tmpfs mounts.
        copy_script = ('import shutil,sys; '
                       'f=open(sys.argv[1],"rb"); shutil.copyfileobj(f,sys.stdout.buffer,65536)')
        with temporary.open('wb') as out:
            subprocess.run(['docker', 'exec', container, 'python', '-c', copy_script, str(remote)],
                           stdout=out, stderr=subprocess.PIPE, timeout=30, check=True)
        if file_hash(temporary) != result['sha256']:
            raise ValueError('archive checksum mismatch')
        if destination.exists():
            raise FileExistsError('archive already exists')
        temporary.rename(destination)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()
    print('\nАрхив: ' + str(destination), flush=True)
    print('Результат: ' + result['status'] + '. Передайте этот один архив.', flush=True)
    print('CSV и токены сохранены только в закрытом каталоге контейнера: ' + str(remote.parent / 'private'), flush=True)
    return returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container', help='имя API-контейнера, если запущено несколько')
    parser.add_argument('--output', default='.', help='куда сохранить обезличенный архив')
    parser.add_argument('--resume', metavar='RUN_ID', help='продолжить с сохранёнными CSV и токеном')
    parser.add_argument('--budget-minutes', type=int, default=60, help='общий предел времени (по умолчанию 60 минут)')
    parser.add_argument('--reserve-gib', type=int, default=1, help='не занимать последние N ГиБ на диске (по умолчанию 1)')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--run-id', help=argparse.SUPPRESS)
    parser.add_argument('--launch-id', help=argparse.SUPPRESS)
    parser.add_argument('--source-sha256', help=argparse.SUPPRESS)
    parser.add_argument('--container-info', default='{}', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not 1 <= args.budget_minutes <= 240 or not 0 <= args.reserve_gib <= 1024:
        parser.error('некорректный бюджет времени или резерв диска')
    try:
        return worker(args) if args.worker else host(args)
    except Exception as exc:
        # No raw exception text: Docker/SQL/HTTP failures can contain source data.
        if args.worker:
            print('STOOLS_DIAG_BOOT_ERROR ' + json.dumps({
                'error': Privacy(secrets.token_bytes(32)).error(exc), 'busy': isinstance(exc, BlockingIOError)}), flush=True)
        print('Запуск/получение архива не завершено: ' + type(exc).__name__, file=sys.stderr)
        if isinstance(exc, ValueError) and '--container' in str(exc):
            print('Укажите --container stools-api-1 (или имя нужного API-контейнера).', file=sys.stderr)
        if args.run_id:
            print('Сохранённые этапы: --resume ' + args.run_id, file=sys.stderr)
        if not args.worker:
            try:
                with tempfile.TemporaryDirectory(prefix='mpvm-diagnostics-') as tmp:
                    failed = RunStore(tmp, 'launcher-error')
                    failed.report.update(status='launcher_failed', error=failed.privacy.error(exc),
                                         docker_available=shutil.which('docker') is not None,
                                         returncode=getattr(exc, 'returncode', None), run_id=args.run_id or 'launcher-error',
                                         worker_error=getattr(args, 'worker_error', None))
                    archive = failed.bundle()
                    destination = Path(args.output).resolve() / ('mpvm-launcher-error-' + secrets.token_hex(4) + '.tar.gz')
                    with destination.open('xb') as out, archive.open('rb') as content:
                        os.chmod(destination, 0o600)
                        shutil.copyfileobj(content, out)
                    print('Архив ошибки запуска: ' + str(destination), file=sys.stderr)
            except Exception:
                pass
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
