
import io
import unittest
from unittest.mock import patch

import front_end


class SecureScanAppTests(unittest.TestCase):

    def setUp(self):
        front_end.app.config["TESTING"] = True
        self.client = front_end.app.test_client()

    def upload(self, filename, content):
        return self.client.post(
            "/",
            data={
                "file": (
                    io.BytesIO(content.encode("utf-8")),
                    filename
                )
            },
            content_type="multipart/form-data"
        )

    def test_01_dashboard_loads(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"Python Security Dashboard",
            response.data
        )

    def test_02_missing_file_is_rejected(self):
        response = self.client.post(
            "/",
            data={},
            content_type="multipart/form-data"
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"Please select a Python file.",
            response.data
        )

    def test_03_invalid_file_type_is_rejected(self):
        response = self.upload(
            "notes.txt",
            "This is not Python source code."
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"Only Python (.py) files are supported.",
            response.data
        )

    @patch("front_end.run_semgrep")
    def test_04_empty_python_file_is_rejected(self, mock_semgrep):
        response = self.upload("empty.py", "   \n")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"The uploaded Python file is empty.",
            response.data
        )
        mock_semgrep.assert_not_called()

    @patch("front_end.analyze_vulnerability")
    @patch("front_end.run_semgrep")
    def test_05_vulnerability_is_displayed(
        self, mock_semgrep, mock_ai
    ):
        mock_semgrep.return_value = [{
            "rule": "python.test.sql-injection",
            "file": "sample.py",
            "line": 8,
            "severity": "HIGH",
            "message": "Possible SQL injection.",
            "category": "SQL Injection"
        }]

        mock_ai.return_value = {
            "assessment": "true_positive",
            "severity": "HIGH",
            "explanation": "User input enters a SQL query.",
            "impact": "An attacker may access unauthorized records.",
            "recommendation": "Use parameterized queries."
        }

        response = self.upload(
            "sample.py",
            'query = "SELECT * FROM users WHERE name = " + name'
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SQL Injection", response.data)
        self.assertIn(b"Possible SQL injection.", response.data)
        self.assertIn(b"Line 8", response.data)
        self.assertIn(b"Semgrep severity", response.data)
        self.assertIn(b"AI assessment", response.data)
        self.assertIn(b"Use parameterized queries.", response.data)

        mock_semgrep.assert_called_once()
        mock_ai.assert_called_once()

    @patch("front_end.analyze_vulnerability")
    @patch("front_end.run_semgrep")
    def test_06_findings_are_sorted_by_assessed_severity(
        self, mock_semgrep, mock_ai
    ):
        mock_semgrep.return_value = [
            {
                "rule": "test.low",
                "file": "sample.py",
                "line": 1,
                "severity": "LOW",
                "message": "Low-risk test finding.",
                "category": "Low Finding"
            },
            {
                "rule": "test.critical",
                "file": "sample.py",
                "line": 2,
                "severity": "CRITICAL",
                "message": "Critical test finding.",
                "category": "Critical Finding"
            },
            {
                "rule": "test.medium",
                "file": "sample.py",
                "line": 3,
                "severity": "MEDIUM",
                "message": "Medium-risk test finding.",
                "category": "Medium Finding"
            }
        ]

        def fake_ai(finding, source_code):
            return {
                "assessment": "uncertain",
                "severity": finding["severity"],
                "explanation": "Test explanation.",
                "impact": "Test impact.",
                "recommendation": "Test fix."
            }

        mock_ai.side_effect = fake_ai

        response = self.upload("sample.py", "print('test')")

        self.assertEqual(response.status_code, 200)

        body = response.data.decode("utf-8")
        critical_pos = body.index("Critical Finding")
        medium_pos = body.index("Medium Finding")
        low_pos = body.index("Low Finding")

        self.assertLess(critical_pos, medium_pos)
        self.assertLess(medium_pos, low_pos)

    @patch("front_end.analyze_vulnerability")
    @patch("front_end.run_semgrep")
    def test_07_ai_failure_preserves_semgrep_finding(
        self, mock_semgrep, mock_ai
    ):
        mock_semgrep.return_value = [{
            "rule": "python.test.rule",
            "file": "sample.py",
            "line": 4,
            "severity": "HIGH",
            "message": "A test finding.",
            "category": "Test Vulnerability"
        }]

        mock_ai.side_effect = RuntimeError("Test AI outage")

        response = self.upload("sample.py", "print('test')")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Test Vulnerability", response.data)
        self.assertIn(b"A test finding.", response.data)
        self.assertIn(b"AI unavailable", response.data)
        self.assertIn(b"Test AI outage", response.data)

    @patch("front_end.run_semgrep")
    def test_08_scanner_failure_is_not_a_clean_scan(
        self, mock_semgrep
    ):
        mock_semgrep.side_effect = RuntimeError(
            "Semgrep is unavailable."
        )

        response = self.upload("sample.py", "print('test')")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Scan could not be completed", response.data)
        self.assertIn(b"Scan failed:", response.data)
        self.assertNotIn(b"No findings returned", response.data)

    @patch("front_end.analyze_vulnerability")
    @patch("front_end.run_semgrep")
    def test_09_no_findings_shows_clean_scan_message(
        self, mock_semgrep, mock_ai
    ):
        mock_semgrep.return_value = []

        response = self.upload(
            "clean_sample.py",
            "def add(a, b):\n    return a + b\n"
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No findings returned", response.data)
        mock_ai.assert_not_called()

    def test_10_oversized_upload_is_rejected(self):
        oversized_content = "x" * (1024 * 1024 + 100)

        response = self.upload(
            "large.py",
            oversized_content
        )

        self.assertEqual(response.status_code, 413)
        self.assertIn(b"maximum upload size is 1 MB", response.data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
