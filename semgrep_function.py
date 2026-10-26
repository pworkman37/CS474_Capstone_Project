import subprocess
import json

def run_semgrep(file_path):
    command = [
        "semgrep",
        "scan",
        "--config", "p/security-audit",
        "--json",
        "--metrics=off",
        file_path
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=120
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Semgrep failed: {result.stderr}"
        )

    data = json.loads(result.stdout)

    if data.get("errors"):
        raise RuntimeError(
            f"Semgrep scan errors: {data['errors']}"
        )

    vulnerabilities = []

    for finding in data.get("results", []):
        vulnerability = {
            "rule": finding["check_id"],
            "file": finding["path"],
            "line": finding["start"]["line"],
            "severity": finding["extra"]["severity"],
            "message": finding["extra"]["message"],
            "category": finding["extra"]
                .get("metadata", {})
                .get("vulnerability_class", ["Unknown"])[0]
        }

        vulnerabilities.append(vulnerability)

    return vulnerabilities