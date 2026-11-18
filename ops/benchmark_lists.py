#!/usr/bin/env python3
"""Read-only list benchmark. Use only an explicitly selected test environment."""
import argparse
import concurrent.futures
import csv
import http.client
import json
import math
import os
from pathlib import Path
import re
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request

# Fixed GET endpoints: labels, never URLs/query strings, enter the report.
CASES = {
    'assets:first': '/api/assets/assets?limit=200&offset=0',
    'assets:filter': '/api/assets/assets?limit=200&offset=0&q=perf-000',
    'assets:deep': '/api/assets/assets?limit=200&offset=3800',
    'vm:first': '/api/vm/vulns?limit=200&offset=0',
    'vm:filter': '/api/vm/vulns?limit=200&offset=0&q=CVE-2026-1000',
    'vm:deep': '/api/vm/vulns?limit=200&offset=3800',
}


def validate_base_url(value):
    url = urllib.parse.urlsplit(value)
    if (url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.path not in ('', '/')):
        raise ValueError('base-url must be an HTTP(S) origin without credentials, path, query or fragment')
    return value.rstrip('/')


def read_cookie(path):
    if path.stat().st_mode & 0o077:
        raise ValueError('cookie file must have mode 0600')
    return path.read_text().strip()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Do not forward a cookie to another origin.


def measure(base, cookie, case, timeout):
    request = urllib.request.Request(base + CASES[case], headers={'Cookie': cookie, 'Accept': 'application/json'}, method='GET')
    start = time.perf_counter()
    result = dict(case=case, status=0, response_bytes=0, sql_ms=None, sql_count=None)
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=timeout) as response:
            result['status'] = response.status
            # Consume the stream without retaining or printing its contents.
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                result['response_bytes'] += len(chunk)
            expected = response.headers.get('Content-Length')
            if expected is not None and (not expected.isdigit() or int(expected) != result['response_bytes']):
                result['status'] = 0
            timing = response.headers.get('Server-Timing', '')
            sql = re.search(r'(?:^|, )sql;dur=([0-9.]+)', timing)
            count = re.search(r'sql_count;desc="([0-9]+)"', timing)
            result['sql_ms'] = float(sql.group(1)) if sql else None
            result['sql_count'] = int(count.group(1)) if count else None
    except urllib.error.HTTPError as error:
        result['status'] = error.code
        error.close()
    except (OSError, urllib.error.URLError, http.client.HTTPException):
        result['status'] = 0  # Never print exception strings containing URLs or credentials.
    result['elapsed_ms'] = round((time.perf_counter() - start) * 1000, 2)
    return result


def summarize(rows):
    report = []
    for case in dict.fromkeys(r['case'] for r in rows):
        group = [r for r in rows if r['case'] == case]
        times = sorted(r['elapsed_ms'] for r in group)
        sql = [r['sql_ms'] for r in group if r['sql_ms'] is not None]
        counts = [r['sql_count'] for r in group if r['sql_count'] is not None]
        report.append(dict(case=case, requests=len(group), errors=sum(r['status'] != 200 for r in group),
                           p50_ms=statistics.median(times), p95_ms=times[math.ceil(len(times) * .95) - 1],
                           response_bytes_mean=round(statistics.mean(r['response_bytes'] for r in group)),
                           sql_ms_mean=round(statistics.mean(sql), 2) if sql else None,
                           sql_count_max=max(counts) if counts else None))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--confirm-test-target', action='store_true', help='confirm this is a test environment, never production')
    parser.add_argument('--cookie-file', type=Path, help='0600 file with the Cookie header, or use STOOLS_BENCH_COOKIE')
    parser.add_argument('--users', type=int, choices=(1, 5, 10), default=1)
    parser.add_argument('--samples', type=int, default=5, help='requests per case; 1..100')
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.confirm_test_target or not 1 <= args.samples <= 100 or not 0 < args.timeout <= 300:
        parser.error('confirm-test-target is required; samples 1..100, timeout 0..300')
    try:
        base = validate_base_url(args.base_url)
        cookie = read_cookie(args.cookie_file) if args.cookie_file else os.environ.get('STOOLS_BENCH_COOKIE', '').strip()
    except (ValueError, OSError):
        parser.error('invalid target or cookie file (must exist with mode 0600)')
    if not cookie or '\n' in cookie or '\r' in cookie:
        parser.error('provide a session cookie via a private file or STOOLS_BENCH_COOKIE')
    rows = []
    # First sample per list is separated from repeated requests; no OS/DB cache flush.
    for case in CASES:
        first = measure(base, cookie, case, args.timeout)
        rows.append(first)
        if first['status'] in (0, 401, 403):
            parser.error('target unavailable or session has no list access; no response content recorded')
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.users) as pool:
            for row in pool.map(lambda _: measure(base, cookie, case, args.timeout), range(args.samples)):
                row['case'] = case + ':warm'
                rows.append(row)
    report = summarize(rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(users=args.users, samples=args.samples, report=report), indent=2) + '\n')
    with args.output.with_suffix('.csv').open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(report[0]))
        writer.writeheader()
        writer.writerows(report)
    print(f'Completed {len(rows)} read-only requests; errors: {sum(r["status"] != 200 for r in rows)}. Reports: {args.output.name}, {args.output.with_suffix(".csv").name}')
    return int(any(r['status'] != 200 for r in rows))


if __name__ == '__main__':
    raise SystemExit(main())
