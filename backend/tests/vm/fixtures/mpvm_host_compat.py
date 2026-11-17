"""Stdlib-only launcher checks, executable on Python 3.7 without the application."""
import builtins
import contextlib
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT = Path(sys.argv.pop(1)).resolve()


class HostCompatibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original_import = builtins.__import__

        def host_import(name, *args, **kwargs):
            fromlist = args[2] if len(args) > 2 else kwargs.get('fromlist', ())
            if (name == 'importlib.metadata' or name == 'importlib' and 'metadata' in (fromlist or ())
                    or name.startswith(('api.', 'sqlalchemy', 'httpx'))):
                raise ModuleNotFoundError(name)
            return original_import(name, *args, **kwargs)

        spec = importlib.util.spec_from_file_location('mpvm_host_compat', str(SCRIPT))
        cls.diag = importlib.util.module_from_spec(spec)
        with patch('builtins.__import__', host_import):
            spec.loader.exec_module(cls.diag)

    def test_help_without_container_or_application_packages(self):
        completed = subprocess.run([sys.executable, str(SCRIPT), '--help'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn('--resume', completed.stdout)

    def test_completed_host_transfers_and_checks_archive(self):
        diag = self.diag
        with tempfile.TemporaryDirectory() as folder:
            store = diag.RunStore(folder, 'payload')
            payload = store.bundle().read_bytes()
            output = Path(folder) / 'out'
            run_id = 'compat-run'
            marker = {'archive': '/data/vm/diagnostics/' + run_id + '/report-123456ab.tar.gz',
                      'sha256': hashlib.sha256(payload).hexdigest(), 'run_id': run_id, 'status': 'completed'}
            process = SimpleNamespace(stdin=io.StringIO(), stdout=io.StringIO(
                'STOOLS_DIAG_WORKER ' + json.dumps({'pid': 12345, 'run_id': run_id}) + '\n' +
                'STOOLS_DIAG_RESULT ' + json.dumps(marker) + '\n'), wait=lambda timeout: 0)

            def docker_run(args, **kwargs):
                if args[0] == 'ps':
                    return SimpleNamespace(stdout=json.dumps({'ID': 'abc123', 'Names': 'stools-api-1'}))
                self.assertEqual(args[0], 'inspect')
                return SimpleNamespace(stdout=json.dumps({'image_id': 'sha256:test', 'restart_count': 0}))

            def copy(args, **kwargs):
                self.assertEqual(args[:2], ['docker', 'exec'])
                kwargs['stdout'].write(payload)
                return SimpleNamespace(returncode=0)

            args = SimpleNamespace(resume=run_id, output=str(output), container='stools-api-1',
                                   budget_minutes=1, reserve_gib=1)
            with patch.object(diag, 'docker_run', docker_run), patch.object(diag.subprocess, 'Popen', return_value=process), \
                    patch.object(diag.subprocess, 'run', copy), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(diag.host(args), 0)
            archives = list(output.glob('mpvm-diagnostics-*.tar.gz'))
            self.assertEqual(len(archives), 1)
            self.assertEqual(archives[0].read_bytes(), payload)
            self.assertEqual(list(output.glob('*.partial')), [])

    def test_startup_failure_still_creates_archive(self):
        diag = self.diag
        with tempfile.TemporaryDirectory() as folder:
            argv = [str(SCRIPT), '--output', folder]
            with patch.object(sys, 'argv', argv), patch.object(diag, 'host', side_effect=FileNotFoundError()), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(diag.main(), 1)
            archives = list(Path(folder).glob('mpvm-launcher-error-*.tar.gz'))
            self.assertEqual(len(archives), 1)
            with tarfile.open(str(archives[0])) as archive:
                self.assertEqual(sorted(archive.getnames()), ['events.jsonl', 'report.json', 'summary.txt'])
                report = json.load(archive.extractfile('report.json'))
                self.assertEqual(report['status'], 'launcher_failed')


if __name__ == '__main__':
    print('Launcher compatibility: Python ' + sys.version.split()[0], flush=True)
    unittest.main(verbosity=1)
