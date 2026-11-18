"""Benchmark must stay read-only and keep secrets out of reports."""
import importlib.util
from pathlib import Path
import pytest

path = Path(__file__).resolve().parents[3] / 'ops' / 'benchmark_lists.py'
spec = importlib.util.spec_from_file_location('benchmark_lists', path)
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


@pytest.mark.parametrize('url', ['https://user:password@host', 'https://host/?token=x', 'ftp://host', 'https://host/#secret'])
def test_rejects_unsafe_base_urls(url):
    with pytest.raises(ValueError):
        benchmark.validate_base_url(url)


def test_summary_contains_metrics_but_no_request_content():
    rows = [dict(case='assets:first', elapsed_ms=n, status=200, response_bytes=50, sql_ms=2.0, sql_count=3) for n in range(1, 11)]
    report = benchmark.summarize(rows)
    assert report[0]['p95_ms'] == 10
    assert report[0]['requests'] == 10
    assert report[0]['sql_count_max'] == 3
    assert report[0]['response_bytes_mean'] == 50


def test_cookie_file_must_be_private(tmp_path):
    path = tmp_path / 'cookie'
    path.write_text('stools_session=private-cookie')
    path.chmod(0o644)
    with pytest.raises(ValueError, match='0600'):
        benchmark.read_cookie(path)
    path.chmod(0o600)
    assert benchmark.read_cookie(path) == 'stools_session=private-cookie'


@pytest.mark.parametrize('failure', ['timeout', 'incomplete', 'short'])
def test_body_failure_is_not_a_successful_sample(monkeypatch, failure):
    import http.client
    class Response:
        status = 200
        headers = {'Content-Length': '100'}
        calls = 0
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, size):
            self.calls += 1
            if self.calls == 1: return b'part'
            if failure == 'timeout': raise TimeoutError('secret-url')
            if failure == 'incomplete': raise http.client.IncompleteRead(b'private', 96)
            return b''
    class Opener:
        def open(self, *args, **kwargs): return Response()
    monkeypatch.setattr(benchmark.urllib.request, 'build_opener', lambda *args: Opener())
    row = benchmark.measure('http://localhost', 'private-cookie', 'assets:first', 1)
    assert row['status'] == 0
    assert benchmark.summarize([row])[0]['errors'] == 1
