#!/usr/bin/env python3
"""Diagnose a failed Blindspot mail job locally on its server; print structure, never content.

Usage: python3 diagnose_blindspot.py [--job-id N] [--container stools-api-1]
Without --job-id, examines the latest failed apply job. No DB writes or external requests.
"""
import argparse
import json
import subprocess
import sys

IN_CONTAINER = r'''
import collections
import contextlib
import io
import json
import logging
import tempfile
from pathlib import Path
from email import policy
from email.parser import BytesParser
from sqlalchemy import select, text
from api.db.base import get_sessionmaker
from api.settings import get_settings
from api.modules.toolbox.models import ToolboxJob, ToolboxFinding, ToolboxSettings
from api.modules.toolbox.services.scrub import _input
from api.modules.toolbox.services.dictionaries import build_ctx
from api.modules.toolbox.core.scrub import engine, files
from api.modules.toolbox.core.scrub.types import Finding
from api.modules.toolbox.core.scrub.conversion import convert
from api.modules.toolbox.core.scrub.documents import LIMIT

logging.disable(logging.CRITICAL)
HEADERS = {'date','resent-date','from','to','cc','bcc','sender','reply-to','message-id',
           'in-reply-to','references','subject','content-type','content-disposition','mime-version'}
MIME = {'text/plain','text/html','multipart/mixed','multipart/alternative','multipart/related',
        'multipart/signed','message/rfc822','application/octet-stream'}


def structure(data):
    message = BytesParser(policy=policy.default).parsebytes(data)
    result = []
    for index, part in enumerate(message.walk()):
        defects = []
        for name, value in part.items():
            errors = getattr(value, 'defects', ())
            if errors:
                defects.append({'header': name.lower() if name.lower() in HEADERS else 'other',
                                'errors': sorted({type(e).__name__ for e in errors})})
        typ = part.get_content_type()
        result.append({'part': index, 'mime': typ if typ in MIME else 'other',
                       'mime_errors': sorted({type(e).__name__ for e in part.defects}),
                       'header_errors': defects})
        if index >= 99:
            result.append({'truncated': True})
            break
    return result


class NoWrites:
    def get(self, kind, key):
        return None

    def commit(self, pairs):
        pass


def diagnose(job_id):
    report = {'stage': 'database'}
    try:
        with get_sessionmaker()() as db:
            db.execute(text('SET TRANSACTION READ ONLY'))
            query = select(ToolboxJob)
            query = query.where(ToolboxJob.id == job_id) if job_id is not None else query.where(
                ToolboxJob.kind == 'apply', ToolboxJob.status == 'failed').order_by(ToolboxJob.id.desc())
            job = db.scalar(query.limit(1))
            if job is None:
                return {'error': 'job_not_found'}
            if job.files_deleted:
                return {'job_id': job.id, 'error': 'job_files_deleted'}
            report['job_id'] = job.id
            settings = db.scalar(select(ToolboxSettings).where(ToolboxSettings.id == 1).limit(1))
            if settings is None:
                return {'job_id': job.id, 'error': 'settings_not_found'}
            report['stage'] = 'source'
            data_dir = get_settings().data_dir
            source = _input(data_dir, job.id)
            suffix = source.suffix.lower()
            if suffix not in {'.msg', '.eml'}:
                return {'job_id': job.id, 'error': 'mail_only'}
            if source.stat().st_size > LIMIT:
                return {'job_id': job.id, 'error': 'source_too_large'}
            rows = list(db.scalars(select(ToolboxFinding).where(ToolboxFinding.job_id == job.id)
                                  .order_by(ToolboxFinding.id).limit(10001)))
            if len(rows) > 10000:
                return {'job_id': job.id, 'error': 'too_many_findings'}
            report['findings'] = len(rows)
            report['selected'] = sum(r.checked for r in rows)
            report['stage'] = 'dictionaries'
            ctx = build_ctx(db, settings, users_from_ad=job.users_from_ad, data_dir=data_dir,
                            extra_words={r.value: r.alias for r in rows if r.kind == 'word'})
            findings = [Finding(r.kind, r.value, r.value_key, r.alias, r.count, [], '', r.checked, r.auto)
                        for r in rows]
            report['stage'] = 'conversion'
            data = source.read_bytes()
            if suffix == '.msg':
                data = convert(data, suffix)
            report['source_structure'] = structure(data)
            with tempfile.TemporaryDirectory(prefix='blindspot-diagnose-') as tmp:
                original = Path(tmp) / 'input.eml'
                original.write_bytes(data)
                output = Path(tmp) / 'output.eml'
                report['stage'] = 'apply'
                engine.apply(original, output, findings, ctx, NoWrites())
                if not output.is_file():
                    report['error'] = 'no_output'
                    return report
                report['output_structure'] = structure(output.read_bytes())
                report['stage'] = 'verify'
                try:
                    remaining = engine.verify(output, findings, ctx)
                    report['verification'] = 'leftovers' if remaining else 'passed'
                    report['remaining_count'] = len(remaining)
                except engine.VerifyError:
                    report['verification'] = 'unreadable'
                kinds = collections.Counter()
                for entry, chunks in files.walk(output):
                    kinds[entry.kind] += 1
                    for _ in chunks:
                        pass
                report['output_entry_types'] = dict(kinds)
            db.rollback()
            report['stage'] = 'done'
            return report
    except Exception as exc:
        # Never print SQL exceptions, filenames, header values or traceback: they can contain secrets.
        report['error_type'] = type(exc).__name__
        return report


if __name__ == '__main__':
    # Third-party parsers must not accidentally add source data to stdout/stderr.
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        report = diagnose(JOB_ID)
    print(json.dumps(report, ensure_ascii=False))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--job-id', type=int)
    parser.add_argument('--container', default='stools-api-1')
    args = parser.parse_args()
    if args.job_id is not None and args.job_id <= 0:
        parser.error('--job-id must be positive')
    script = f'JOB_ID = {args.job_id!r}\n' + IN_CONTAINER
    try:
        result = subprocess.run(['docker', 'exec', '-i', args.container, 'python', '-'],
                                input=script, text=True, capture_output=True, timeout=240, check=False)
        if result.returncode:
            print('Диагностика не запустилась. Проверьте имя контейнера, доступ к Docker и версию API.', file=sys.stderr)
            return 1
        report = json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        print('Диагностика не завершилась; содержимое вывода скрыто, чтобы не раскрыть данные письма.', file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
