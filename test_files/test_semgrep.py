
import json
import subprocess
import unittest
from unittest.mock import patch

from semgrep_function import run_semgrep


class SemgrepFunctionTests(unittest.TestCase):

    @patch("semgrep_function.subprocess.run")
    def test_valid_finding_is_parsed(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["semgrep"],
            returncode=0,
            stdout=json.dumps({
                "errors": [],
                "results": [{
                    "check_id": "python.test.sql-injection",
                    "path": "sample.py",
                    "start": {"line": 12},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Possible SQL injection.",
                        "metadata": {
                            "vulnerability_class": ["SQL Injection"]
                        }
                    }
                }]
            }),
            stderr=""
        )

        findings = run_semgrep("sample.py")

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["rule"],
            "python.test.sql-injection"
        )
        self.assertEqual(findings[0]["line"], 12)
        self.assertEqual(findings[0]["severity"], "ERROR")
        self.assertEqual(findings[0]["category"], "SQL Injection")

    @patch("semgrep_function.subprocess.run")
    def test_no_findings_returns_empty_list(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["semgrep"],
            returncode=0,
            stdout=json.dumps({
                "errors": [],
                "results": []
            }),
            stderr=""
        )

        self.assertEqual(run_semgrep("clean.py"), [])

    @patch("semgrep_function.subprocess.run")
    def test_nonzero_exit_raises_error(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["semgrep"],
            returncode=2,
            stdout=json.dumps({"errors": [], "results": []}),
            stderr="Scanner failed"
        )

        with self.assertRaisesRegex(RuntimeError, "exited with code"):
            run_semgrep("sample.py")

    @patch("semgrep_function.subprocess.run")
    def test_semgrep_reported_errors_raise_error(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["semgrep"],
            returncode=0,
            stdout=json.dumps({
                "errors": [{"message": "Invalid rule configuration"}],
                "results": []
            }),
            stderr=""
        )

        with self.assertRaisesRegex(RuntimeError, "reported errors"):
            run_semgrep("sample.py")

    @patch("semgrep_function.subprocess.run")
    def test_invalid_json_raises_error(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["semgrep"],
            returncode=0,
            stdout="not JSON",
            stderr=""
        )

        with self.assertRaisesRegex(RuntimeError, "invalid response"):
            run_semgrep("sample.py")

    @patch("semgrep_function.subprocess.run")
    def test_timeout_raises_clear_error(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["semgrep"], timeout=120
        )

        with self.assertRaisesRegex(RuntimeError, "timed out"):
            run_semgrep("sample.py")


if __name__ == "__main__":
    unittest.main(verbosity=2)
