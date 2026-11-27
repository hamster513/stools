"""Opt-in real PostgreSQL pipeline checks using synthetic data only."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

OPS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OPS))
import stools_db_anonymize as app
from stools_db import backup, verified_backup
from stools_db_clone import Values, _fernet
from stools_db_masking import MaskError, Rules

CONFIG = {
    "format": "stools-db-anonymize/1",
    "replacements": [
        {"from": "corp.example", "to": "lab.example"},
        {"from": "alice", "to": "person-001"},
        {"from": "bob", "to": "person-002"},
    ],
    "networks": [{"from": "10.10.0.0/16", "to": "10.200.0.0/16"}],
}


def resources():
    return set(
        subprocess.check_output(
            ["docker", "ps", "-aq", "--filter", "label=" + app.LABEL], text=True
        ).split()
    ), set(
        subprocess.check_output(
            ["docker", "volume", "ls", "-q", "--filter", "label=" + app.LABEL],
            text=True,
        ).split()
    )


class CliTests(unittest.TestCase):
    def test_python_37_syntax(self):
        import ast

        for name in (
            "stools_db_anonymize.py",
            "stools_db_clone.py",
            "stools_db_masking.py",
        ):
            ast.parse((OPS / name).read_text(), feature_version=(3, 7))

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = root / "rules.json"
            cfg.write_text(json.dumps(CONFIG))
            source = root / "source.dump"
            source.write_bytes(b"PGDMPoriginal")
            target = root / "out"
            target.mkdir()
            (target / "keep").write_text("keep")
            with self.assertRaises(MaskError):
                app.run(source, cfg, target)
            self.assertEqual((target / "keep").read_text(), "keep")
            self.assertEqual(source.read_bytes(), b"PGDMPoriginal")

    def test_unavailable_docker_is_not_reported_as_missing_resource(self):
        failure = subprocess.CompletedProcess(
            [], 1, b"", b"Cannot connect to the Docker daemon"
        )
        with (
            patch.object(app.subprocess, "run", return_value=failure),
            self.assertRaises(MaskError),
        ):
            app.inspect("container", "stools-anonymize-test")

    def test_dedup_salt_and_policy_controls_are_preserved(self):
        values = Values(Rules(CONFIG))
        source = '{"salt":"synthetic-deduplication-salt"}'
        self.assertEqual(values.setting({"key": "siem_finding_key"}, source), source)
        self.assertFalse(
            json.loads(values.setting({"key": "siem_th"}, '{"nightly_enabled":true}'))[
                "nightly_enabled"
            ]
        )

    def test_empty_json_text_means_unavailable_not_corrupt(self):
        column = {"name": "summary_json", "type": "text", "category": "S"}
        self.assertEqual(Values(Rules(CONFIG)).cell("ad_snapshot", column, "", {}), "")

    def test_ghsa_prose_preserves_external_bounds_and_masks_explicit_values(self):
        values = Values(Rules(CONFIG))
        for name in ("summary", "description"):
            column = {"name": name, "type": "text", "category": "S"}
            for interval in ("10.0.0.1-10.99.255.254", "10.199.0.0 – 10.201.0.0"):
                with self.subTest(name=name, interval=interval):
                    self.assertEqual(
                        values.cell(
                            "vm_ref_ghsa", column, interval, {}, schema="public"
                        ),
                        interval,
                    )
                    self.assertEqual(
                        values.cell(
                            "vm_ref_ghsa",
                            column,
                            f"{interval}, pc.corp.example (10.10.1.7), 10.10.2.0/24",
                            {},
                            schema="public",
                        ),
                        f"{interval}, pc.lab.example (10.200.1.7), 10.200.2.0/24",
                    )

    def test_external_bounds_remain_strict_outside_ghsa_prose(self):
        values = Values(Rules(CONFIG))
        for schema, table, name in (
            (None, "vm_ref_ghsa", "description"),
            ("private", "vm_ref_ghsa", "description"),
            ("public", "policy", "description"),
            ("public", "vm_ref_ghsa", "other"),
        ):
            column = {"name": name, "type": "text", "category": "S"}
            with self.subTest(schema=schema, table=table, name=name):
                with self.assertRaises(MaskError) as caught:
                    values.cell(
                        table, column, "10.0.0.1-10.99.255.254", {}, schema=schema
                    )
                self.assertIn("networks[0].from", str(caught.exception))

    def test_ghsa_prose_keeps_network_and_alias_guards(self):
        values = Values(Rules(CONFIG))
        column = {"name": "description", "type": "text", "category": "S"}
        interval = "10.0.0.1-10.99.255.254"
        for value, rule in (
            (json.dumps({"scope": interval}), "networks[0].from"),
            (f"<scope>{interval}</scope>", "networks[0].from"),
            (interval + ", 10.10.1.7 – 10.99.0.1", "networks[0].from"),
            ("10.199.0.1-10.200.1.7", "networks[0].to"),
            (interval + ", 10.200.1.7", "networks[0].to"),
            (interval + ", 10.0.0.0/9", "networks[0].from"),
            (interval + ", pc.lab.example", "replacements[0].to"),
        ):
            with self.subTest(value=value):
                with self.assertRaises(MaskError) as caught:
                    values.cell("vm_ref_ghsa", column, value, {}, schema="public")
                self.assertIn(rule, str(caught.exception))

    def test_credentials_stored_as_raw_settings_are_cleared(self):
        values = Values(Rules(CONFIG))
        for key in ("llm.openrouter_key", "llm.deepseek_key", "mail.password"):
            self.assertEqual(
                values.setting({"key": key}, "enc:v1:synthetic-credential"), ""
            )

    def test_unknown_sql_types_are_not_exported_unmodified(self):
        for kind, category in (("hstore", "U"), ("record", "C")):
            column = {"name": "payload", "type": kind, "category": category}
            with self.subTest(kind=kind), self.assertRaises(MaskError):
                Values(Rules(CONFIG)).cell("custom_data", column, "corp.example", {})

    def test_publish_never_replaces_existing_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "manifest.json").write_text("{}")
            target = root / "target"
            target.mkdir()
            (target / "keep").write_text("keep")
            with self.assertRaises((FileExistsError, MaskError)):
                app.publish(bundle, target)
            self.assertEqual((target / "keep").read_text(), "keep")
            self.assertFalse((target / "manifest.json").exists())


@unittest.skipUnless(
    os.environ.get("STOOLS_ANONYMIZE_DOCKER_TESTS") == "1",
    "Set STOOLS_ANONYMIZE_DOCKER_TESTS=1 for isolated Docker tests",
)
class DockerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.context = app.postgres("postgres:16-alpine")
        cls.pg = cls.context.__enter__()
        cls.addClassCleanup(cls.context.__exit__, None, None, None)
        cls.pg.run(
            "createdb",
            "--template=template0",
            "--encoding=UTF8",
            "--lc-collate=C",
            "--lc-ctype=C",
            "fixture",
        )
        cls.pg.sql(
            r"""
CREATE TABLE app_user(id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, login text UNIQUE NOT NULL, password_hash text, is_active boolean NOT NULL);
CREATE TABLE groups(id integer PRIMARY KEY, name text NOT NULL);
CREATE TABLE membership(user_id integer REFERENCES app_user, group_id integer REFERENCES groups, PRIMARY KEY(user_id,group_id));
CREATE TABLE policy(id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, owner_id integer REFERENCES app_user, name text UNIQUE, action text, enabled boolean NOT NULL, payload jsonb, raw text, tags text[], precise numeric(32,20), nullable text, literal_null text);
CREATE TABLE platform_schedule(id integer PRIMARY KEY, enabled boolean NOT NULL);
CREATE TABLE toolbox_settings(id integer PRIMARY KEY, key bytea NOT NULL);
CREATE TABLE radar_snapshot(id integer PRIMARY KEY, original_encrypted text, document jsonb, sha256 text);
CREATE TABLE app_setting(key text PRIMARY KEY, value_json text);
CREATE TABLE search_cache(id integer PRIMARY KEY, words tsvector);
CREATE TABLE vm_ref_ghsa(ghsa_id text PRIMARY KEY, description text);
INSERT INTO app_user(login,password_hash,is_active) VALUES ('alice','original-password-hash',true),('bob',NULL,true);
INSERT INTO groups VALUES (1,'corp.example admins');
INSERT INTO membership VALUES (1,1),(2,1);
INSERT INTO policy(owner_id,name,action,enabled,payload,raw,tags,precise,nullable,literal_null) VALUES
 (1,'corp.example policy','allow',true,'{"host":"pc.corp.example","ip":"10.10.1.7","port":443,"action":"allow","enabled":true,"version":"10.10.1.2","n":123456789.123456789123456789}',E'line one\n\\.\nalice on corp.example','[0:2]={alice,NULL,corp.example}',123.12345678912345678912,NULL,E'\\N');
SELECT setval('policy_id_seq',1000,false);
INSERT INTO platform_schedule VALUES(1,true);
INSERT INTO app_setting VALUES('siem_th','{"nightly_enabled":true,"llm_model":"example","min_score":5}'),('mail','{"enabled":true,"password":"sensitive"}');
INSERT INTO search_cache VALUES(1,to_tsvector('simple','alice corp.example'));
INSERT INTO vm_ref_ghsa VALUES('test-advisory','Published range 10.0.0.1-10.99.255.254, pc.corp.example (10.10.1.7)');
INSERT INTO toolbox_settings VALUES(1,decode(repeat('ab',32),'hex'));
""",
            "fixture",
        )
        cls.source_secret = "synthetic-source-secret-for-integration-only"
        value = (
            "enc:v1:"
            + _fernet(cls.source_secret)
            .encrypt(b"server_name corp.example; allow 10.10.1.7;")
            .decode()
        )
        from stools_db import literal

        cls.pg.sql(
            "INSERT INTO radar_snapshot VALUES(1,"
            + literal(value)
            + ',\'{"host":"corp.example"}\','
            + literal("0" * 64)
            + ")",
            "fixture",
        )
        cls.original = cls.root / "original"
        backup(cls.pg, cls.original, "fixture")
        cls.config = cls.root / "rules.json"
        cls.config.write_text(json.dumps(CONFIG))
        cls.hash = hashlib.sha256(
            (cls.original / "database.dump").read_bytes()
        ).hexdigest()
        cls.config_hash = hashlib.sha256(cls.config.read_bytes()).hexdigest()
        os.environ["STOOLS_TEST_ANON_SOURCE_KEY"] = cls.source_secret

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("STOOLS_TEST_ANON_SOURCE_KEY", None)

    def test_full_round_trip_preserves_rows_links_and_policies(self):
        before = resources()
        out = self.root / "clean"
        report = app.run(
            self.original,
            self.config,
            out,
            source_secret_env="STOOLS_TEST_ANON_SOURCE_KEY",
        )
        self.assertEqual(resources(), before)
        self.assertEqual(report["rows"], 13)
        self.assertTrue(report["restore_verified"])
        self.assertEqual(
            hashlib.sha256((self.original / "database.dump").read_bytes()).hexdigest(),
            self.hash,
        )
        self.assertEqual(
            hashlib.sha256(self.config.read_bytes()).hexdigest(), self.config_hash
        )
        self.assertEqual(
            {p.name for p in out.iterdir()},
            {"database.dump", "manifest.json", "anonymization.json", "stand.env"},
        )
        with verified_backup(self.pg, out) as (_, stream):
            self.pg.run("createdb", "checked")
            self.pg.run(
                "pg_restore",
                "--exit-on-error",
                "--no-owner",
                "--no-privileges",
                "--dbname=checked",
                source=stream,
            )
        row = json.loads(
            self.pg.sql(
                "SELECT json_build_object('login',u.login,'name',p.name,'action',p.action,'enabled',p.enabled,'payload',p.payload,'raw',p.raw,'tags',p.tags,'dims',array_dims(p.tags),'precise',p.precise::text,'nullable',p.nullable,'literal_null',p.literal_null) FROM policy p JOIN app_user u ON u.id=p.owner_id LIMIT 1",
                "checked",
            )
        )
        self.assertEqual(row["login"], "person-001")
        self.assertEqual(row["action"], "allow")
        self.assertIs(row["enabled"], True)
        self.assertEqual(row["payload"]["ip"], "10.200.1.7")
        self.assertEqual(row["payload"]["version"], "10.10.1.2")
        self.assertEqual(
            self.pg.sql(
                "SELECT description FROM vm_ref_ghsa WHERE ghsa_id='test-advisory' LIMIT 1",
                "checked",
            ),
            "Published range 10.0.0.1-10.99.255.254, pc.lab.example (10.200.1.7)",
        )
        self.assertEqual(row["precise"], "123.12345678912345678912")
        self.assertEqual(row["raw"], "line one\n\\.\nperson-001 on lab.example")
        self.assertEqual(row["tags"], ["person-001", None, "lab.example"])
        self.assertEqual(row["dims"], "[0:2]")
        self.assertIsNone(row["nullable"])
        self.assertEqual(row["literal_null"], "\\N")
        self.assertEqual(self.pg.sql("SELECT count(*) FROM membership", "checked"), "2")
        self.assertEqual(
            self.pg.sql(
                "SELECT last_value::text || is_called::text FROM policy_id_seq LIMIT 1",
                "checked",
            ),
            "1000false",
        )
        self.assertEqual(
            self.pg.sql(
                "SELECT count(*) FROM app_user WHERE is_active OR password_hash IS NOT NULL",
                "checked",
            ),
            "0",
        )
        self.assertEqual(
            self.pg.sql("SELECT enabled FROM platform_schedule LIMIT 1", "checked"), "f"
        )
        secret = (out / "stand.env").read_text().strip().split("=", 1)[1]
        encrypted = self.pg.sql(
            "SELECT original_encrypted FROM radar_snapshot LIMIT 1", "checked"
        )
        plain = _fernet(secret).decrypt(encrypted[len("enc:v1:") :].encode()).decode()
        self.assertEqual(plain, "server_name lab.example; allow 10.200.1.7;")
        self.assertEqual(
            self.pg.sql("SELECT sha256 FROM radar_snapshot LIMIT 1", "checked"),
            hashlib.sha256(plain.encode()).hexdigest(),
        )
        self.assertEqual(
            self.pg.sql(
                "SELECT value_json::json->>'nightly_enabled' FROM app_setting WHERE key='siem_th' LIMIT 1",
                "checked",
            ),
            "false",
        )
        self.assertNotIn(
            "alice", self.pg.sql("SELECT words FROM search_cache LIMIT 1", "checked")
        )
        self.assertNotIn(
            "corp.example",
            self.pg.sql("SELECT words FROM search_cache LIMIT 1", "checked"),
        )
        self.assertNotIn(self.source_secret, (out / "stand.env").read_text())
        self.assertEqual(out.stat().st_mode & 0o777, 0o700)
        for file in out.iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)

    def test_raw_dump_preserves_source_locale(self):
        before = resources()
        out = self.root / "raw-locale"
        report = app.run(
            self.original / "database.dump",
            self.config,
            out,
            source_secret_env="STOOLS_TEST_ANON_SOURCE_KEY",
        )
        self.assertTrue(report["restore_verified"])
        metadata = json.loads((out / "manifest.json").read_text())["database"]
        self.assertEqual(metadata["collate"], "C")
        self.assertEqual(metadata["ctype"], "C")
        self.assertEqual(resources(), before)

    def test_failure_still_removes_owned_resources_and_output(self):
        before = resources()
        out = self.root / "failed"
        bad = self.root / "bad.json"
        config = dict(CONFIG)
        config["replacements"] = [{"from": "alice", "to": "bob"}]
        bad.write_text(json.dumps(config))
        with self.assertRaises(MaskError):
            app.run(
                self.original / "database.dump",
                bad,
                out,
                source_secret_env="STOOLS_TEST_ANON_SOURCE_KEY",
            )
        self.assertFalse(out.exists())
        self.assertEqual(resources(), before)
        self.assertEqual(
            hashlib.sha256((self.original / "database.dump").read_bytes()).hexdigest(),
            self.hash,
        )

    def test_missing_decryption_key_does_not_export_original_ciphertext(self):
        before = resources()
        out = self.root / "missing-key"
        with self.assertRaises(MaskError):
            app.run(self.original, self.config, out)
        self.assertFalse(out.exists())
        self.assertEqual(resources(), before)

    def test_cli_pinpoints_existing_destination_address_and_cleans_up(self):
        before = resources()
        config = self.root / "network-conflict.json"
        config.write_text(
            json.dumps(
                {
                    "format": CONFIG["format"],
                    "networks": [{"from": "192.0.2.0/24", "to": "10.10.1.0/24"}],
                }
            )
        )
        output = self.root / "network-conflict-out"
        command = [
            sys.executable,
            str(OPS / "stools_db_anonymize.py"),
            str(self.original),
            "--config",
            str(config),
            "--output",
            str(output),
        ]
        for detailed in (False, True):
            with self.subTest(detailed=detailed):
                result = subprocess.run(
                    command + (["--show-conflicting-ips"] if detailed else []),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn('"public"."policy"', result.stdout)
                for expected in (
                    '"public"."policy"',
                    '"payload"',
                    "строка COPY 1",
                    "id=1",
                    "$.ip",
                    "networks[0].to",
                ):
                    self.assertIn(expected, result.stderr)
                combined = result.stdout + result.stderr
                for ip in ("10.10.1.7", "10.10.1.0/24", "192.0.2.0/24"):
                    self.assertEqual(ip in combined, detailed)
                for private in (
                    "pc.corp.example",
                    "original-password-hash",
                    self.source_secret,
                ):
                    self.assertNotIn(private, combined)
                self.assertFalse(output.exists())
                self.assertEqual(resources(), before)

    def test_sigterm_cleans_up_before_exit(self):
        import select
        import time

        before = resources()
        out = self.root / "cancelled"
        command = [
            sys.executable,
            str(OPS / "stools_db_anonymize.py"),
            str(self.original),
            "--config",
            str(self.config),
            "--output",
            str(out),
            "--source-secret-env",
            "STOOLS_TEST_ANON_SOURCE_KEY",
        ]
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        try:
            deadline = time.monotonic() + 45
            ready = False
            while time.monotonic() < deadline and process.poll() is None:
                if select.select([process.stdout], [], [], 0.25)[0]:
                    line = process.stdout.readline().decode("utf-8")
                    if "Временный PostgreSQL запущен" in line:
                        ready = True
                        break
            self.assertTrue(ready, "isolated PostgreSQL did not start")
            process.terminate()
            _stdout, stderr = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 130, stderr.decode("utf-8"))
            self.assertFalse(out.exists())
            self.assertEqual(resources(), before)
            self.assertFalse(list(self.root.glob(".stools-anonymize-*")))
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()
            process.stderr.close()

    def test_corrupt_input_does_not_leave_container_or_volume(self):
        before = resources()
        source = self.root / "broken.dump"
        source.write_bytes(b"PGDMPbroken")
        from stools_db import BackupError

        with self.assertRaises((MaskError, BackupError)):
            app.run(source, self.config, self.root / "broken-out")
        self.assertEqual(resources(), before)
        self.assertFalse((self.root / "broken-out").exists())


if __name__ == "__main__":
    unittest.main()
