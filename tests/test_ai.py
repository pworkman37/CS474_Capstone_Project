
import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from groq_function import analyze_vulnerability


class GroqAnalysisTests(unittest.TestCase):

    def setUp(self):
        self.finding = {
            "rule": "python.test.sql-injection",
            "category": "SQL Injection",
            "severity": "ERROR",
            "line": 12,
            "message": "Possible SQL injection."
        }

        self.source_code = (
            'query = "SELECT * FROM users WHERE name = " + name'
        )

        self.valid_response = {
            "assessment": "true_positive",
            "severity": "HIGH",
            "explanation": "User input is concatenated into a query.",
            "impact": "An attacker may manipulate the query.",
            "recommendation": "Use parameterized queries."
        }

    @patch.dict(os.environ, {"GROQ_API_KEY": "test-key"})
    @patch("groq_function.Groq")
    def test_valid_ai_response_is_parsed(self, mock_groq):
        mock_groq.return_value.chat.completions.create.return_value = (
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content=json.dumps(self.valid_response)
                        )
                    )
                ]
            )
        )

        result = analyze_vulnerability(
            self.finding,
            self.source_code
        )

        self.assertEqual(result["assessment"], "true_positive")
        self.assertEqual(result["severity"], "HIGH")
        self.assertIn("concatenated", result["explanation"])
        self.assertIn("parameterized", result["recommendation"])

    @patch.dict(os.environ, {"GROQ_API_KEY": "test-key"})
    @patch("groq_function.Groq")
    def test_markdown_wrapped_json_is_parsed(self, mock_groq):
        wrapped_response = (
            "```json\n"
            + json.dumps(self.valid_response)
            + "\n```"
        )

        mock_groq.return_value.chat.completions.create.return_value = (
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(content=wrapped_response)
                    )
                ]
            )
        )

        result = analyze_vulnerability(
            self.finding,
            self.source_code
        )

        self.assertEqual(result["severity"], "HIGH")

    @patch.dict(os.environ, {}, clear=True)
    def test_missing_api_key_raises_clear_error(self):
        with self.assertRaisesRegex(
            RuntimeError, "GROQ_API_KEY is not configured"
        ):
            analyze_vulnerability(
                self.finding,
                self.source_code
            )

    @patch.dict(os.environ, {"GROQ_API_KEY": "test-key"})
    @patch("groq_function.Groq")
    def test_malformed_ai_response_raises_error(self, mock_groq):
        mock_groq.return_value.chat.completions.create.return_value = (
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content="This response is not JSON."
                        )
                    )
                ]
            )
        )

        with self.assertRaisesRegex(
            RuntimeError, "did not contain valid JSON"
        ):
            analyze_vulnerability(
                self.finding,
                self.source_code
            )

    @patch.dict(os.environ, {"GROQ_API_KEY": "test-key"})
    @patch("groq_function.Groq")
    def test_invalid_severity_is_normalized(self, mock_groq):
        response = dict(self.valid_response)
        response["severity"] = "EXTREME"
        response["assessment"] = "not a valid assessment"

        mock_groq.return_value.chat.completions.create.return_value = (
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content=json.dumps(response)
                        )
                    )
                ]
            )
        )

        result = analyze_vulnerability(
            self.finding,
            self.source_code
        )

        self.assertEqual(result["severity"], "UNKNOWN")
        self.assertEqual(result["assessment"], "uncertain")


if __name__ == "__main__":
    unittest.main(verbosity=2)
