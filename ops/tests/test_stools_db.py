"""Local tests; Docker tests use only a fresh, networkless PostgreSQL container."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

SCRIPT = Path(__file__).resolve().parents[1] / 'stools_db.py'
spec = importlib.util.spec_from_file_location('stools_db', SCRIPT)
dbtool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dbtool)


class InputTests(unittest.TestCase):
    def test_identifiers_cannot_be_sql_or_cli_options(self):
        for value in ('--help', 'db;DROP DATABASE db', 'db\nother', 'x' * 64, ''):
            with self.subTest(value=value), self.assertRaises(dbtool.BackupError):
                dbtool.database_name(value)

    def test_existing_backup_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'copy'
            path.mkdir()
            marker = path / 'keep'
            marker.write_text('untouched')
            with self.assertRaises(FileExistsError):
                dbtool.backup(None, path, None)
            self.assertEqual(marker.read_text(), 'untouched')

    def test_incomplete_backup_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)
            with self.assertRaises(dbtool.BackupError):
                dbtool.read_manifest(path)
            (path / 'elsewhere').write_text('{}')
            (path / 'manifest.json').symlink_to(path / 'elsewhere')
            with self.assertRaises(dbtool.BackupError):
                dbtool.read_manifest(path)


@unittest.skipUnless(os.environ.get('STOOLS_TEST_DOCKER') == '1', 'set STOOLS_TEST_DOCKER=1 for isolated PostgreSQL tests')
class PostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.container = 'stools-backup-test-' + uuid.uuid4().hex[:12]
        subprocess.run(['docker', 'run', '-d', '--rm', '--network', 'none', '--name', cls.container,
                        '-e', 'POSTGRES_USER=stools', '-e', 'POSTGRES_PASSWORD=synthetic-test-only',
                        '-e', 'POSTGRES_DB=stools_test', 'postgres:16-alpine'],
                       check=True, stdout=subprocess.DEVNULL)
        cls.addClassCleanup(subprocess.run, ['docker', 'rm', '-fv', cls.container],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            r = subprocess.run(['docker', 'exec', cls.container, 'pg_isready', '-h', '127.0.0.1', '-U', 'stools', '-d', 'stools_test'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if r.returncode == 0:
                break
            time.sleep(.1)
        else:
            raise RuntimeError('temporary PostgreSQL did not start')
        cls.pg = dbtool.Postgres(cls.container)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.source = 'source_' + uuid.uuid4().hex[:8]
        self.target = 'target_' + uuid.uuid4().hex[:8]
        self.pg.run('createdb', '--template=template0', self.source)
        self.pg.run('createdb', '--template=template0', self.target)
        self.pg.sql("CREATE TABLE sentinel(value text); INSERT INTO sentinel VALUES ('original target');", self.target)
        self.directory = Path(self.tmp.name) / 'backup with spaces'

    def run_cli(self, *args, success=True):
        r = subprocess.run([sys.executable, str(SCRIPT), *args, '--container', self.container],
                           capture_output=True, text=True)
        if success:
            self.assertEqual(r.returncode, 0, r.stderr)
            return json.loads(r.stdout)
        self.assertNotEqual(r.returncode, 0)
        return r

    def prepare_backup(self):
        self.pg.sql("""CREATE TABLE app_setting(key text PRIMARY KEY, value text);
INSERT INTO app_setting VALUES ('siem_finding_key','synthetic-salt');
CREATE SCHEMA inventory;
CREATE TABLE inventory.host(id serial PRIMARY KEY, name text);
INSERT INTO inventory.host(name) VALUES ('host-one'),('host-two');
CREATE FUNCTION inventory.answer() RETURNS integer LANGUAGE sql AS 'SELECT 42';
SELECT lo_from_bytea(12345, decode('0001ff', 'hex'));
""", self.source)
        return self.run_cli('backup', str(self.directory), '--database', self.source)

    def original_target_is_intact(self):
        self.assertEqual(self.pg.sql('SELECT value FROM sentinel LIMIT 1', self.target).strip(), 'original target')

    def test_complete_roundtrip_keeps_old_database_and_replaces_all_objects(self):
        result = self.prepare_backup()
        self.assertGreater(result['bytes'], 0)
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        for name in ('database.dump', 'manifest.json'):
            self.assertEqual((self.directory / name).stat().st_mode & 0o777, 0o600)
        self.run_cli('verify', str(self.directory))
        result = self.run_cli('restore', str(self.directory), '--database', self.target,
                              '--confirm-database', self.target)
        self.assertEqual(self.pg.sql('SELECT count(*) FROM inventory.host', self.target).strip(), '2')
        self.assertEqual(self.pg.sql("SELECT nextval('inventory.host_id_seq')", self.target).strip(), '3')
        self.assertEqual(self.pg.sql('SELECT inventory.answer()', self.target).strip(), '42')
        self.assertEqual(self.pg.sql("SELECT value FROM app_setting WHERE key='siem_finding_key' LIMIT 1", self.target).strip(), 'synthetic-salt')
        self.assertEqual(self.pg.sql("SELECT encode(lo_get(12345),'hex')", self.target).strip(), '0001ff')
        self.assertEqual(self.pg.sql("SELECT to_regclass('sentinel') IS NULL", self.target).strip(), 't')
        previous = result['previous_database']
        self.assertFalse(self.pg.info(previous)['allow_connections'])
        self.pg.sql(f'ALTER DATABASE "{previous}" ALLOW_CONNECTIONS true')
        self.assertEqual(self.pg.sql('SELECT value FROM sentinel LIMIT 1', previous).strip(), 'original target')

    def test_new_database_can_be_restored_without_existing_target(self):
        self.prepare_backup()
        name = 'fresh_' + uuid.uuid4().hex[:8]
        result = self.run_cli('restore', str(self.directory), '--database', name, '--confirm-database', name)
        self.assertIsNone(result['previous_database'])
        self.assertEqual(self.pg.sql('SELECT count(*) FROM inventory.host', name).strip(), '2')

    def test_damage_and_wrong_confirmation_do_not_touch_target(self):
        self.prepare_backup()
        self.run_cli('restore', str(self.directory), '--database', self.target,
                     '--confirm-database', 'wrong', success=False)
        self.original_target_is_intact()
        with (self.directory / 'database.dump').open('ab') as f:
            f.write(b'corruption')
        self.run_cli('restore', str(self.directory), '--database', self.target,
                     '--confirm-database', self.target, success=False)
        self.original_target_is_intact()

    def test_incompatible_version_is_rejected(self):
        self.prepare_backup()
        path = self.directory / 'manifest.json'
        meta = json.loads(path.read_text())
        meta['server_version_num'] = 150000
        path.write_text(json.dumps(meta))
        self.run_cli('restore', str(self.directory), '--database', self.target,
                     '--confirm-database', self.target, success=False)
        self.original_target_is_intact()

    def test_sql_restore_failure_preserves_original(self):
        self.pg.sql("""CREATE TABLE guarded(value text CHECK (
current_setting('stools.restore_test', true) IS NOT DISTINCT FROM 'allowed'));
SET stools.restore_test='allowed'; INSERT INTO guarded VALUES ('SENSITIVE_SYNTHETIC_VALUE');""", self.source)
        self.run_cli('backup', str(self.directory), '--database', self.source)
        self.run_cli('verify', str(self.directory))
        r = self.run_cli('restore', str(self.directory), '--database', self.target,
                         '--confirm-database', self.target, success=False)
        self.assertNotIn('SENSITIVE_SYNTHETIC_VALUE', r.stdout + r.stderr)
        self.original_target_is_intact()

    def test_active_connection_prevents_replacement(self):
        self.prepare_backup()
        process = subprocess.Popen(self.pg.command('psql', '-X', '-d', self.target, '-c', 'SELECT pg_sleep(30)'),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(process.wait)
        self.addCleanup(process.terminate)
        for _ in range(100):
            if self.pg.connections(self.target):
                break
            time.sleep(.05)
        self.run_cli('restore', str(self.directory), '--database', self.target,
                     '--confirm-database', self.target, success=False)
        self.original_target_is_intact()


if __name__ == '__main__':
    unittest.main()
