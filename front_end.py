
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from semgrep_function import run_semgrep
from groq_function import analyze_vulnerability

import os
import tempfile

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024


SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "ERROR": 4,
    "MEDIUM": 3,
    "WARNING": 3,
    "LOW": 2,
    "INFO": 1,
    "UNKNOWN": 0
}



def normalize_severity(value):
    severity = str(value or "UNKNOWN").upper().strip()

    aliases = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFORMATIONAL": "INFO",
        "INFORMATION": "INFO"
    }

    severity = aliases.get(severity, severity)

    if severity not in SEVERITY_RANK:
        return "UNKNOWN"

    return severity


def risk_rank(vulnerability):
    severity = vulnerability.get("severity", "UNKNOWN")
    return SEVERITY_RANK.get(
        normalize_severity(severity), 0
    )


@app.errorhandler(413)
def file_too_large(_error):
    return render_template(
        "index.html",
        results=[],
        error="File is too large. The maximum upload size is 1 MB.",
        filename=None
    ), 413


@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    error = None
    filename = None

    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if not uploaded_file or not uploaded_file.filename:
            error = "Please select a Python file."

        elif not uploaded_file.filename.lower().endswith(".py"):
            error = "Only Python (.py) files are supported."

        else:
            filename = secure_filename(uploaded_file.filename)

            if not filename:
                error = "The uploaded filename is invalid."

            else:
                try:
                    with tempfile.TemporaryDirectory() as temp_dir:
                        file_path = os.path.join(temp_dir, filename)
                        uploaded_file.save(file_path)

                        with open(
                            file_path,
                            "r",
                            encoding="utf-8"
                        ) as file:
                            source_code = file.read()

                        if not source_code.strip():
                            error = "The uploaded Python file is empty."
                        else:
                            # A scanner failure stops the scan.
                            vulnerabilities = run_semgrep(file_path)

                            for vulnerability in vulnerabilities:
                                semgrep_raw_severity = str(
                                    vulnerability.get("severity", "UNKNOWN")
                                ).upper().strip()
                                semgrep_severity = normalize_severity(semgrep_raw_severity)

                                finding = {
                                    **vulnerability,
                                    "file":os.path.basename(vulnerability.get("file") or filename),
                                    "semgrep_raw_severity": semgrep_severity, 
                                    "semgrep_severity": semgrep_severity,
                                    "severity": semgrep_severity,
                                    "ai_severity": None,
                                    "ai_assessment": None,
                                    "ai_status": "unavailable",
                                    "risk_source": "Semgrep",
                                    "ai_analysis": (
                                        "AI analysis is unavailable."
                                        "Configure GROQ_API_KEY to enable AI-assisted analysis"
                                    )
                                }
                                

                                try:
                                    analysis = analyze_vulnerability(
                                        vulnerability,
                                        source_code
                                    )

                                    ai_severity = normalize_severity(
                                        analysis.get("severity", "UNKNOWN")
                                    )

                                    finding.update({
                                        "ai_severity": ai_severity,
                                        "ai_assessment": analysis.get(
                                            "assessment", "uncertain"
                                        ),
                                        "ai_status": "complete",
                                        "severity": (
                                            ai_severity
                                            if ai_severity != "UNKNOWN"
                                            else semgrep_severity
                                        ),
                                        "risk_source": (
                                            "AI assessment"
                                            if ai_severity != "UNKNOWN"
                                            else "Semgrep fallback"
                                        ),
                                        "ai_analysis": (
                                            "Assessment: "
                                            + analysis.get(
                                                "assessment", "uncertain"
                                            ).replace("_", " ").title()
                                            + "\n\nExplanation: "
                                            + analysis.get(
                                                "explanation",
                                                "No explanation provided."
                                            )
                                            + "\n\nPotential impact: "
                                            + analysis.get(
                                                "impact",
                                                "Impact not determined."
                                            )
                                            + "\n\nRecommended fix: "
                                            + analysis.get(
                                                "recommendation",
                                                "Manual review recommended."
                                            )
                                        )
                                    })

                                except Exception as exc:
                                    # Keep the Semgrep finding visible.
                                    finding["ai_status"] = "unavailable"
                                    finding["ai_analysis"] = (
                                        "AI analysis unavailable. "
                                        "Semgrep's finding is still shown. "
                                        "Details: "
                                        + str(exc).splitlines()[0][:200]
                                    )

                                results.append(finding)

                            # Highest risk first. Stable ordering preserves
                            # scanner order for findings with equal risk.
                            results.sort(
                                key=risk_rank,
                                reverse=True
                            )

                except UnicodeDecodeError:
                    error = (
                        "The uploaded file is not valid UTF-8 text. "
                        "Save it as a UTF-8 encoded Python source file "
                        "and try again."
                    )
                except Exception as exc:
                    error = (
                        "Scan failed: "
                        + str(exc).splitlines()[0][:250]
                    )

    return render_template(
        "index.html",
        results=results,
        error=error,
        filename=filename
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
