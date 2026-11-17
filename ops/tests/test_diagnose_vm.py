"""Run with: python3 -m unittest discover -s ops/tests -p 'test_diagnose_vm.py'."""
import csv
import importlib.util
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("mpvm_diagnostic_ops_test", ROOT / "ops/diagnose_mpvm_export.py")
diagnose = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = diagnose
SPEC.loader.exec_module(diagnose)
# Exercise the installed parser without importing the application or replacing its modules.
SOURCE_SPEC = importlib.util.spec_from_file_location(
    "mpvm_csv_ops_test", ROOT / "backend/api/modules/vm/core/sources.py")
source_module = importlib.util.module_from_spec(SOURCE_SPEC)
sys.modules[SOURCE_SPEC.name] = source_module
SOURCE_SPEC.loader.exec_module(source_module)
KEY = b"test-only-random-key"
HEADER = '"@Host";"Host.OsName";"Host.@Groups";"Host.@Vulners.CVEs"\n'


class DiagnosticsTest(unittest.TestCase):
    def scan(self, path, **options):
        return diagnose.scan_csv(path, diagnose.Privacy(KEY), source_module.iter_csv_records, **options)

    def test_csv_counts_and_malformed_record_are_explicit(self):
        data = HEADER + (
            '"secret-a.corp (10.22.33.44)";"Linux";"group\nline";"CVE-2024-1234, CVE-2024-1235"\n'
            '"secret-a.corp (10.22.33.44)";"Linux";"";"CVE-2024-1234"\n'
            ';"Linux";"";"CVE-2024-7777"\n'
            '"secret-b.corp (10.22.33.45)";"Linux";"";""\n'
            '"short-row";"Linux"\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "export.csv"
            path.write_text(data, encoding="utf-8-sig")
            result = self.scan(path)
        self.assertTrue(result["raw_complete"])
        self.assertFalse(result["app_complete"])
        self.assertEqual(result["raw_records"], 5)
        self.assertEqual(result["app_records"], 4)
        self.assertEqual(result["malformed_rows"], 1)
        self.assertEqual(result["hosts"]["count"], 2)
        self.assertEqual(result["hosts_with_cve"]["count"], 1)
        self.assertEqual(result["cves"]["count"], 3)
        self.assertEqual(result["raw_first"][0]["host"], result["raw_first"][1]["host"])
        for secret in ("secret-a", "10.22.33.44", "group", "CVE-2024-1234"):
            self.assertNotIn(secret, json.dumps(result))

    def test_csv_comma_and_multiline_field(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "export.csv"
            path.write_text('"@Host","Host.@Vulners.CVEs"\n"host","CVE-2024-1234\nCVE-2024-1235"\n')
            result = self.scan(path)
        self.assertTrue(result["raw_complete"] and result["app_complete"])
        self.assertEqual(result["cves"]["count"], 2)
        self.assertEqual(result["app_records"], 1)

    def test_missing_columns_are_not_reported_as_valid_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "export.csv"
            path.write_text('"wrong-host";"wrong-cve"\n"private-token";"secret"\n')
            result = self.scan(path)
        self.assertFalse(result["required_columns_present"])
        self.assertNotIn("private-token", json.dumps(result))
        self.assertNotIn("wrong-host", json.dumps(result))

    def test_missing_bounded_and_time_limited_files_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "export.csv"
            with self.assertRaises(FileNotFoundError):
                self.scan(path)
            path.write_text(HEADER + '"host";"Linux";"";"CVE-2024-1234"\n')
            with patch.object(diagnose, "CSV_LINE_LIMIT", 10):
                limited = self.scan(path)
            expired = self.scan(path, deadline=0)
        for result in (limited, expired):
            self.assertFalse(result["raw_complete"] or result["app_complete"])
            self.assertTrue(result["errors"])
        self.assertIn("diagnostic_deadline", json.dumps(expired["errors"]))

    def test_error_and_log_signals_do_not_disclose_payloads(self):
        private = "password=pat_secret host=private.corp"
        privacy = diagnose.Privacy(KEY)
        result = privacy.error(RuntimeError("statement timeout " + private))
        self.assertIn("timeout", result["chain"][0]["signals"])
        self.assertEqual(privacy.signals("api перезапускался " + private), ["api_restarted"])
        for value in ("pat_secret", "private.corp", "password="):
            self.assertNotIn(value, json.dumps(result))

    def test_csv_field_limit_preserves_partial_result_without_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "export.csv"
            path.write_text(HEADER + '"host";"Linux";"' + "x" * 65 + '";"CVE-2024-1234"\n')
            previous = csv.field_size_limit(64)
            try:
                result = self.scan(path)
            finally:
                csv.field_size_limit(previous)
        self.assertFalse(result["raw_complete"] or result["app_complete"])
        self.assertIn("csv_field_limit", json.dumps(result["errors"]))
        self.assertNotIn("CVE-2024-1234", json.dumps(result))

    def test_pseudonyms_are_stable_only_within_same_report(self):
        value = ["private.corp", "10.22.33.44"]
        first = diagnose.Privacy(KEY).label(value, "host")
        self.assertEqual(first, diagnose.Privacy(KEY).label(value, "host"))
        self.assertNotEqual(first, diagnose.Privacy(b"other-key").label(value, "host"))
        self.assertNotIn("private.corp", first)
        self.assertNotIn("10.22.33.44", first)

    def test_archive_is_private_and_does_not_overwrite_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            store = diagnose.RunStore(directory, "test-run")
            (store.private / "export.csv").write_text("raw-host-canary")
            (store.public / "accidental.txt").write_text("accidental-canary")
            store.report["test"] = True
            with patch.object(diagnose.secrets, "token_hex", return_value="fixed"):
                path = store.bundle()
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                with tarfile.open(path) as archive:
                    self.assertEqual(set(archive.getnames()), {"summary.txt", "report.json", "events.jsonl"})
                    self.assertTrue(json.load(archive.extractfile("report.json"))["test"])
                    contents = b"\n".join(archive.extractfile(name).read() for name in archive.getnames())
                    self.assertNotIn(b"raw-host-canary", contents)
                    self.assertNotIn(b"accidental-canary", contents)
                original = path.read_bytes()
                with self.assertRaises(FileExistsError):
                    store.bundle()
                self.assertEqual(path.read_bytes(), original)

    def test_query_failure_does_not_prevent_following_read_only_queries(self):
        calls = []

        class FakeSession:
            def __enter__(self):
                return self

            def __exit__(self, kind, *args):
                if kind:
                    self.rollback()

            def rollback(self):
                calls.append("ROLLBACK")

            def execute(self, sql):
                calls.append(sql)
                if sql == "SELECT count(*) AS count FROM vm_host":
                    raise RuntimeError("statement timeout password=canary-secret")
                return SimpleNamespace(mappings=lambda: SimpleNamespace(all=lambda: [{"count": 2}]))

        with tempfile.TemporaryDirectory() as directory:
            store = diagnose.RunStore(directory, "database-test")
            result = diagnose.read_database(store, FakeSession, lambda sql: sql)
        self.assertIn("error", result["hosts_exact"])
        self.assertEqual(result["pairs_exact"]["rows"], [{"count": 2}])
        self.assertNotIn("canary-secret", json.dumps(result))
        self.assertEqual(calls.count("SET TRANSACTION READ ONLY"), len(result))
        self.assertEqual(calls.count("SET LOCAL statement_timeout = '5s'"), len(result))
        self.assertEqual(calls.count("ROLLBACK"), len(result))

    def test_structured_and_csv_rows_have_same_private_signature(self):
        privacy = diagnose.Privacy(KEY)
        plain = {"@Host": "private.corp", "Host.OsName": "Linux", "Host.@Vulners.CVEs": "CVE-2024-1234"}
        structured = {key: {"displayName": value} for key, value in plain.items()}
        result = diagnose.row_signature(plain, privacy)
        self.assertEqual(result, diagnose.row_signature(structured, privacy))
        for value in plain.values():
            self.assertNotIn(value, json.dumps(result))


if __name__ == "__main__":
    unittest.main()
