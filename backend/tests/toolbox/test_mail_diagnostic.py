"""The production diagnostic reveals only structure and does not change a failed job."""
import json
import logging
import runpy
from email.message import EmailMessage
from pathlib import Path

from sqlalchemy import func, select

from api.modules.toolbox.models import ToolboxAlias, ToolboxJob
from api.modules.toolbox.services.scrub import job_dir
from tests.toolbox.test_api import API, apply, seeded, upload  # noqa: F401


def diagnostic():
    path = Path(__file__).resolve().parents[3] / 'ops/diagnose_blindspot.py'
    module = runpy.run_path(str(path), run_name='diagnostic_module')
    namespace = {'__name__': 'diagnostic_core'}
    previous = logging.root.manager.disable
    try:
        exec(module['IN_CONTAINER'], namespace)  # noqa: S102 — execute our own diagnostic for testing
    finally:
        logging.disable(previous)
    return namespace


def test_diagnostic_identifies_header_failure_without_data_or_writes(seeded, auth_client, app_settings):  # noqa: F811 — imported pytest fixture
    msg = EmailMessage()
    msg['Subject'] = 'PrivateSubjectMarker'
    msg['Date'] = 'Fri, 30 Oct 2026 19:45:00 +0300'
    msg['From'] = 'PrivateSender <sender@corp.test>'
    msg.set_content('<table><tr><td>host01 10.1.2.15</td></tr></table>', subtype='html')
    job_id = upload(auth_client, msg.as_bytes(), 'private-mail.eml')
    response = auth_client.patch(f'{API}/jobs/{job_id}/findings', json={'words': ['Oct']})
    assert response.status_code == 200
    job = apply(auth_client, job_id)
    assert job['status'] == 'failed' and 'самопроверка' in job['error']
    source = next((job_dir(app_settings.data_dir, job_id) / 'in').iterdir())
    original = source.read_bytes()
    count = seeded.scalar(select(func.count()).select_from(ToolboxAlias))
    report = diagnostic()['diagnose'](job_id)
    assert report['verification'] == 'unreadable', report
    assert any(h['header'] == 'date' for p in report['output_structure'] for h in p.get('header_errors', []))
    serialized = json.dumps(report)
    for sensitive in ['PrivateSubjectMarker', 'PrivateSender', 'sender@', 'corp.test', 'host01', '10.1.2.15', 'private-mail']:
        assert sensitive not in serialized
    assert source.read_bytes() == original
    assert seeded.scalar(select(func.count()).select_from(ToolboxAlias)) == count
    seeded.expire_all()
    after = seeded.get(ToolboxJob, job_id)
    assert after.status == job['status'] and after.error == job['error']


def test_diagnostic_redacts_untrusted_mime_types():
    data = b'Subject: PrivateSubjectMarker\r\nContent-Type: application/x-PrivateSubtype\r\n\r\nPrivateBody'
    report = diagnostic()['structure'](data)
    assert report[0]['mime'] == 'other'
    assert 'Private' not in json.dumps(report)


def test_diagnostic_does_not_disclose_exception_values():
    namespace = diagnostic()
    def broken():
        raise ValueError('PrivateSQLPayload')
    namespace['get_sessionmaker'] = broken
    report = namespace['diagnose'](1)
    assert report == {'stage': 'database', 'error_type': 'ValueError'}
