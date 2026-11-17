from __future__ import annotations

import importlib.util
import json
import stat
import sys
import tarfile
from pathlib import Path

import pytest
import httpx
from types import SimpleNamespace

from api.modules.vm.core.sources import iter_csv_records

SCRIPT = Path(__file__).resolve().parents[3] / 'ops' / 'diagnose_mpvm_export.py'


def test_host_has_no_application_dependencies_and_delivers_archive():
    import subprocess
    probe = Path(__file__).parent / 'fixtures' / 'mpvm_host_compat.py'
    result = subprocess.run([sys.executable, str(probe), str(SCRIPT)], text=True,
                            capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr


@pytest.fixture(scope='module')
def diag():
    assert SCRIPT.is_file(), 'The single diagnostic collector is not implemented yet'
    spec = importlib.util.spec_from_file_location('mpvm_diagnostics_test_module', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_report_schema_and_error_do_not_disclose_values(diag):
    privacy = diag.Privacy(b'test-only-salt', ['pat-secret-canary', 'server-secret.example'])
    payload = {'records': [{'@Host': {'name': 'hidden-host-canary', 'id': 'hidden-id-canary'},
                            'Host.@Vulners.CVEs': {'displayName': 'CVE-2026-12345'}}],
               'unknown-key-canary': 'unknown-value-canary'}
    result = json.dumps(privacy.schema(payload))
    assert 'records' in result and 'length' in result
    assert all(value not in result for value in ('hidden-host-canary', 'hidden-id-canary',
                                                'unknown-key-canary', 'unknown-value-canary', 'CVE-2026-12345'))
    error = ValueError('secret response pat-secret-canary https://server-secret.example/a?pdqlToken=export-canary')
    report = json.dumps(privacy.error(error))
    assert 'ValueError' in report
    assert all(value not in report for value in ('pat-secret-canary', 'server-secret.example', 'export-canary', 'secret response'))


def test_archive_has_only_public_allowlist_and_private_modes(diag, tmp_path):
    store = diag.RunStore(tmp_path, 'test-run')
    (store.private / 'export.csv').write_text('raw-host-canary;pat-private-canary')
    (store.public / 'accidental.txt').write_text('accidental-public-canary')
    store.report['test'] = {'rows': 3}
    archive = store.bundle()
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o700
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    with tarfile.open(archive) as tar:
        assert set(tar.getnames()) == {'report.json', 'events.jsonl', 'summary.txt'}
        contents = b'\n'.join(tar.extractfile(name).read() for name in tar.getnames())
    assert all(value not in contents for value in (b'raw-host-canary', b'pat-private-canary', b'accidental-public-canary', store.privacy.key.hex().encode()))


def test_resume_preserves_salt_and_refuses_changed_source(diag, tmp_path):
    original = diag.RunStore(tmp_path, 'same-run')
    original.bind_source('fingerprint-one')
    original.state['tokens'] = {'query': 'private-token-canary'}
    original.checkpoint()
    resumed = diag.RunStore(tmp_path, 'same-run', resume=True)
    assert resumed.privacy.label('host') == original.privacy.label('host')
    assert resumed.state['tokens']['query'] == 'private-token-canary'
    resumed.bind_source('fingerprint-one')
    with pytest.raises(ValueError, match='source'):
        resumed.bind_source('fingerprint-two')
    with pytest.raises(FileExistsError):
        diag.RunStore(tmp_path, 'same-run')


def test_csv_counts_blank_records_independently_of_application(diag, tmp_path):
    path = tmp_path / 'export.csv'
    path.write_text('\ufeff@Host;Host.OsName;Host.@Vulners.CVEs\n'
                    'private-host (10.20.30.40);"Linux\nserver";CVE-2026-12345\n'
                    ';;\n\n'
                    'private-host-two;Linux;\n', encoding='utf-8')
    report = diag.scan_csv(path, diag.Privacy(b'key'), iter_csv_records)
    assert report['raw_complete'] and report['app_complete']
    assert report['raw_records'] == 3
    assert report['blank_records'] == 1
    assert report['blank_lines'] == 1
    assert report['app_records'] == 2
    assert report['hosts']['count'] == 2
    assert report['hosts_with_cve']['count'] == 1
    assert report['rows_with_cve'] == 1
    encoded = json.dumps(report)
    assert all(value not in encoded for value in ('private-host', '10.20.30.40', 'Linux', 'CVE-2026-12345'))


@pytest.mark.parametrize('tail', ['bad;short\n', 'bad;"unclosed;CVE-2026-12345'])
def test_malformed_csv_keeps_partial_counts_and_parser_error(diag, tmp_path, tail):
    path = tmp_path / 'broken.csv'
    path.write_text('@Host;Host.OsName;Host.@Vulners.CVEs\ngood;Linux;CVE-2026-12345\n' + tail)
    report = diag.scan_csv(path, diag.Privacy(b'key'), iter_csv_records)
    assert not report['app_complete']
    assert report['app_records'] == 1
    assert report['errors']
    assert 'unclosed' not in json.dumps(report)


def test_csv_cardinality_limits_are_explicit(diag, tmp_path):
    path = tmp_path / 'hosts.csv'
    path.write_text('@Host;Host.@Vulners.CVEs\na;CVE-2026-12345\nb;CVE-2026-12346\nc;CVE-2026-12347\n')
    report = diag.scan_csv(path, diag.Privacy(b'key'), iter_csv_records, cardinality_limit=2)
    assert report['raw_records'] == report['app_records'] == 3
    assert report['hosts'] == {'count': 2, 'capped': True}


def test_oversized_physical_csv_line_is_not_read_into_memory(diag, tmp_path):
    import tracemalloc
    path = tmp_path / 'bad.csv'
    with path.open('wb') as stream:
        stream.write(b'@Host;Host.@Vulners.CVEs\n')
        for _ in range(16):
            stream.write(b'x' * 1024 ** 2)
    tracemalloc.start()
    try:
        result = diag.scan_csv(path, diag.Privacy(b'key'), iter_csv_records)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert not result['raw_complete'] and not result['app_complete']
    assert peak < 10 * 1024 ** 2


def test_multiline_record_width_cannot_bypass_memory_bound(diag, tmp_path):
    import tracemalloc
    path = tmp_path / 'wide.csv'
    path.write_bytes(b'@Host;Host.@Vulners.CVEs\n' + b'"a\n";' * 500_000 + b'"z"\n')
    tracemalloc.start()
    try:
        result = diag.scan_csv(path, diag.Privacy(b'key'), iter_csv_records)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert not result['raw_complete'] and not result['app_complete']
    assert peak < 30 * 1024 ** 2


def collector(diag, tmp_path, handler, **kwargs):
    store = diag.RunStore(tmp_path, 'http-test')
    conn = SimpleNamespace(api_token='private-bearer-canary')
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return diag.Collector(store, conn, http, 'https://private-source.example',
                          lambda limit=None: f'private query limit({limit})', iter_csv_records,
                          reserve_bytes=0, **kwargs)


def test_http_large_body_and_error_preserve_bounded_safe_report(diag, tmp_path):
    def respond(request):
        if request.url.path.endswith('/data'):
            return httpx.Response(200, content=b'x' * (diag.JSON_LIMIT + 1))
        return httpx.Response(400, json={'errorMessage': 'invalid PDQL private-bearer-canary'})
    run = collector(diag, tmp_path, respond)
    assert run.json_request('oversized', 'GET', 'data') is None
    assert run.json_request('bad_query', 'POST', '') is None
    stages = run.store.report['stages']
    assert stages['oversized']['status'] == 'error'
    assert stages['bad_query']['result']['http_status'] == 400
    public = json.dumps(run.store.report)
    assert 'private-bearer-canary' not in public
    assert 'private-source.example' not in public


def test_complete_csv_is_reused_with_original_query_and_checksum(diag, tmp_path):
    calls = []
    data = b'@Host;Host.@Vulners.CVEs\nh1;CVE-2026-1234\n'
    def respond(request):
        calls.append(request.url.path)
        if request.method == 'POST':
            return httpx.Response(200, json={'token': 'query-token-secret'})
        return httpx.Response(200, content=data)
    run = collector(diag, tmp_path, respond)
    token = run.query_token('full', 'private-query')
    path = run.download('full_csv', token)
    assert path.read_bytes() == data
    assert run.query_token('full', 'private-query') == token
    assert run.download('full_csv', token) == path
    assert len(calls) == 2
    with pytest.raises(ValueError, match='query'):
        run.query_token('full', 'different-query')
    path.write_bytes(data + b'tampered')
    assert run.download('full_csv', token) is None
    assert len(calls) == 2


def test_interrupted_csv_stays_partial_and_report_survives(diag, tmp_path):
    class Broken(httpx.SyncByteStream):
        def __iter__(self):
            yield b'@Host;Host.@Vulners.CVEs\nh1;'
            raise httpx.ReadTimeout('secret source and token')
    run = collector(diag, tmp_path, lambda request: httpx.Response(200, stream=Broken()))
    assert run.download('full_csv', 'token') is None
    assert (run.store.private / 'full_csv.part').exists()
    assert not (run.store.private / 'full_csv.csv').exists()
    assert run.store.report['stages']['full_csv']['status'] == 'error'
    assert run.store.bundle().is_file()


def test_deadline_and_disk_reserve_stop_before_request(diag, tmp_path, monkeypatch):
    calls = []
    run = collector(diag, tmp_path, lambda request: calls.append(request))
    run.deadline = 0
    assert run.json_request('expired', 'GET', 'data') is None
    run.deadline = float('inf')
    run.reserve_bytes = 1024
    monkeypatch.setattr(diag.shutil, 'disk_usage', lambda path: SimpleNamespace(free=512))
    assert run.download('no_space', 'token') is None
    assert not calls


def test_page_reports_normalized_records_and_hard_limit(diag, tmp_path):
    record = {'@Host': {'name': 'host-secret'}, 'Host.@Vulners.CVEs': ['CVE-2026-1234']}
    def respond(request):
        offset = int(request.url.params['offset'])
        return httpx.Response(200, json={'records': [record] if offset == 2 else []})
    run = collector(diag, tmp_path, respond)
    page = run.page('tail', 'token', 2, hard_limit=3)
    assert page['records_count'] == 1 and page['within_bound'] is True
    assert run.page('after', 'token', 3, hard_limit=3)['records_count'] == 0
    assert 'host-secret' not in json.dumps(run.store.report)


def test_large_cap_violation_and_expired_token_remain_observations(diag, tmp_path):
    posts = []
    def respond(request):
        if request.method == 'POST':
            posts.append(request)
            return httpx.Response(200, json={'token': 'private-original-token'})
        if request.url.params['offset'] == '31351765':
            return httpx.Response(200, json={'records': [{}, {}]})
        return httpx.Response(410, json={'error': 'token expired private-original-token'})
    run = collector(diag, tmp_path, respond)
    token = run.query_token('capped', 'query limit(31351765)')
    result = run.page('cap_ignored', token, 31351765, hard_limit=31351765)
    assert result['within_bound'] is False and result['records_count'] == 2
    run.page('expired', token, 31351764)
    assert run.query_token('capped', 'query limit(31351765)') == token
    assert len(posts) == 1
    assert run.store.report['stages']['expired']['result']['http_status'] == 410


def test_concurrent_resume_is_rejected_before_loading_checkpoints(diag, tmp_path, monkeypatch):
    import fcntl
    import os
    monkeypatch.setenv('STOOLS_DATA_DIR', str(tmp_path))
    base = tmp_path / 'vm' / 'diagnostics'
    base.mkdir(parents=True)
    descriptor = os.open(base / 'busy.lock', os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        args = SimpleNamespace(run_id='busy', resume='busy')
        with pytest.raises(BlockingIOError):
            diag.worker(args)
        assert not (base / 'busy').exists()
    finally:
        os.close(descriptor)


def test_container_selection_never_guesses_between_instances(diag):
    rows = [{'ID': 'a', 'Names': 'stools-api-1'}, {'ID': 'b', 'Names': 'second-api-1'}]
    assert diag.select_container(rows[:1], None) == 'a'
    assert diag.select_container(rows, 'second-api-1') == 'b'
    with pytest.raises(ValueError, match='--container'):
        diag.select_container(rows, None)
    with pytest.raises(ValueError):
        diag.select_container([], None)


def test_launcher_watchdog_stops_hung_docker_before_worker_marker(diag):
    import subprocess
    import threading
    proc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
    stop, state, signals = threading.Event(), {'pid': None, 'cancelled': False}, []
    try:
        thread = diag.watchdog(proc, stop, state, lambda pid: signals.append(pid),
                               budget=1, startup=0.01, grace=0.01)
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert proc.poll() is not None
        assert signals == [None]
        assert state['reason'] == 'startup_timeout'
    finally:
        stop.set()
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=2)


def test_full_run_records_large_boundary_disagreement_without_new_export(diag, tmp_path):
    exports = []
    requests = []
    observed_counts = []
    def respond(request):
        requests.append(request)
        if request.method == 'POST':
            query = json.loads(request.content)['pdql']
            return httpx.Response(200, json={'token': 'small' if '(3)' in query else 'full'})
        token = request.url.params['pdqlToken']
        if request.url.path.endswith('/export'):
            exports.append(token)
            return httpx.Response(200, content=b'@Host;Host.@Vulners.CVEs\na;CVE-2026-1234\nb;\nc;\n')
        if request.url.path.endswith('/row_count'):
            observed_counts.append(5 + len(observed_counts))
            return httpx.Response(200, json={'count': observed_counts[-1]})
        offset = int(request.url.params['offset'])
        records = [{'@Host': x} for x in ('a', 'b', 'c', 'd', 'e')[:3 if token == 'small' else 5]]
        return httpx.Response(200, json={'records': records[offset:offset + 2]})
    run = collector(diag, tmp_path, respond)
    run.run()
    finding = run.store.report['findings'][-1]
    assert finding['actual_boundary_records'] == 2
    assert finding['records_after_csv'] == 2
    assert run.store.report['stages']['full_count_before']['result']['body_shape']['fields']['count'] == 5
    assert run.store.report['stages']['full_count_after']['result']['body_shape']['fields']['count'] == 6
    assert exports == ['small', 'full']
    # Resume reuses the CSV and its tokens, and repeats only the explicit stability observation.
    run.run()
    assert exports == ['small', 'full']
    assert observed_counts == [5, 6]
    assert all(request.method in ('GET', 'POST') for request in requests)


@pytest.mark.parametrize('failure', [None, 'timeout', 'invalid_json', 'interrupted'])
def test_worker_bundles_context_and_partial_failure_without_writing_database(diag, tmp_path, monkeypatch, capsys, failure):
    from api.db import base
    from api.modules.vm.services import settings
    from api.modules.vm.core import mpvm

    queries = []
    class DB:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def execute(self, query):
            queries.append(str(query))
            return SimpleNamespace(mappings=lambda: SimpleNamespace(all=lambda: []))
        def rollback(self):
            pass
    conn = settings.Connection(host='source-canary.example', api_token='pat_secret_canary')
    monkeypatch.setattr(base, 'get_sessionmaker', lambda: DB)
    monkeypatch.setattr(settings, 'load_settings', lambda db: SimpleNamespace(connection=SimpleNamespace(unsealed=lambda: conn)))
    monkeypatch.setenv('STOOLS_DATA_DIR', str(tmp_path))
    def respond(request):
        if request.method == 'POST':
            return httpx.Response(200, json={'token': 'token-canary'})
        if request.url.path.endswith('/export'):
            if failure == 'timeout':
                raise httpx.ReadTimeout('source-canary.example pat_secret_canary')
            if failure == 'interrupted':
                raise KeyboardInterrupt
            return httpx.Response(200, content=b'@Host;Host.@Vulners.CVEs\nhost-canary;CVE-2026-1234\n')
        if failure == 'invalid_json':
            return httpx.Response(200, content=b'<html>host-canary</html>')
        if request.url.path.endswith('/row_count'):
            return httpx.Response(200, json={'count': 1})
        offset = int(request.url.params['offset'])
        return httpx.Response(200, json={'records': [{'@Host': 'host-canary'}] if offset == 0 else []})
    monkeypatch.setattr(mpvm, 'make_client', lambda *args, **kwargs: httpx.Client(transport=httpx.MockTransport(respond)))
    args = SimpleNamespace(run_id='worker-test', resume=None, source_sha256='a' * 64, budget_minutes=1, reserve_gib=0)
    assert diag.worker(args) == (130 if failure == 'interrupted' else 0)
    public = tmp_path / 'vm' / 'diagnostics' / 'worker-test' / 'public'
    report = json.loads((public / 'report.json').read_text())
    assert report['status'] == ('interrupted' if failure == 'interrupted' else 'completed_with_errors' if failure else 'completed')
    assert queries and all(query.startswith(('SET ', 'SELECT ')) for query in queries)
    assert queries.count('SET TRANSACTION READ ONLY') == 9
    stdout = capsys.readouterr().out
    marker = [line for line in stdout.splitlines() if line.startswith('STOOLS_DIAG_RESULT ')][0]
    archive = Path(json.loads(marker.split(' ', 1)[1])['archive'])
    with tarfile.open(archive) as tar:
        text = '\n'.join(tar.extractfile(member).read().decode() for member in tar.getmembers())
    for secret in ('source-canary.example', 'pat_secret_canary', 'token-canary', 'host-canary'):
        assert secret not in text and secret not in stdout
