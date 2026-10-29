"""Required-check semantics, including GitHub's skipped/cancelled states."""

import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/check-results.py"
spec = importlib.util.spec_from_file_location("check_results", SCRIPT)
results = importlib.util.module_from_spec(spec)
spec.loader.exec_module(results)


class RequiredResultsTests(unittest.TestCase):
    def test_every_success_is_required(self):
        self.assertEqual(results.check_results({"lint": {"result": "success"}, "go": {"result": "success"}}), [])

    def test_failure_cancellation_skip_and_unknown_are_rejected(self):
        for state in ("failure", "cancelled", "skipped", "pending", "", None):
            with self.subTest(state=state):
                self.assertEqual(results.check_results({"go": {"result": state}}), ["go"])

    def test_missing_result_or_malformed_job_fails(self):
        for value in ({}, None, [], "success"):
            with self.subTest(value=value):
                self.assertEqual(results.check_results({"go": value}), ["go"])

    def test_empty_or_non_object_cannot_pass_vacuously(self):
        for value in ({}, [], None, "success", 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                results.check_results(value)

    def test_cli_exit_codes_and_diagnostics(self):
        for value, code in (({"go": {"result": "success"}}, 0), ({"go": {"result": "skipped"}}, 1), ({}, 1)):
            with self.subTest(value=value):
                run = subprocess.run(
                    [sys.executable, str(SCRIPT)],
                    env={**os.environ, "CI_NEEDS_JSON": json.dumps(value)},
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(run.returncode, code, run.stderr)
                self.assertTrue(run.stdout or run.stderr)

    def test_missing_and_invalid_json_are_failures(self):
        for value in (None, "{", "null", "[]"):
            env = dict(os.environ)
            env.pop("CI_NEEDS_JSON", None)
            if value is not None:
                env["CI_NEEDS_JSON"] = value
            with self.subTest(value=value):
                run = subprocess.run([sys.executable, str(SCRIPT)], env=env, capture_output=True, text=True)
                self.assertEqual(run.returncode, 1)
                self.assertIn("Invalid CI results", run.stderr)

    def test_cli_malformed_job_reports_failure_without_traceback(self):
        run = subprocess.run(
            [sys.executable, str(SCRIPT)],
            env={**os.environ, "CI_NEEDS_JSON": '{"go": null}'},
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 1)
        self.assertIn("go: invalid", run.stdout)
        self.assertNotIn("Traceback", run.stderr)
