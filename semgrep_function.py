import subprocess
import json
import sys

def run_semgrep(file_path):
    command = [
        "semgrep",
        "scan",
        "--config", "p/security-audit",
        "--json",
        "--metrics=off",
        file_path
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding= "utf-8",
            errors= "replace",
            timeout=120,
            check = False
        )

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "Semgrep scan timedout out after 120 seconds"
        )from exc
    except OSError as exc:
        raise RuntimeError(
            "Could not start Semgrep. Check python installation"
        ) from exc
    
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        detail = result.stderr.strip() or "No valid JSON output returned."
        raise RuntimeError(
            f"Semgrep returned an invalid response: {detail[:300]}"
        ) from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or "No additional details."
        raise RuntimeError(
            f"Semgrep exited with code {result.returncode}: "
            f"{detail[:300]}"
        )

    if data.get("errors"):
        details = "; ".join(
            str(item.get("message", item))
            for item in data["errors"]
        )
        raise RuntimeError(f"Semgrep reported errors: {details[:300]}")

    vulnerabilities = []

    for finding in data.get("results", []):
        extra = finding.get("extra", {})
        metadata = extra.get("metadata", {})
        vulnerability_class = metadata.get(
            "vulnerability_class", ["Unknown"]
        )

        if isinstance(vulnerability_class, list):
            category = (
                str(vulnerability_class[0])
                if vulnerability_class
                else "Unknown"
            )
        else:
            category = str(vulnerability_class)

        vulnerabilities.append({
            "rule": finding.get("check_id", "Unknown rule"),
            "file": finding.get("path", file_path),
            "line": finding.get("start", {}).get("line"),
            "severity": str(
                extra.get("severity", "UNKNOWN")
            ).upper(),
            "message": extra.get(
                "message", "No description provided."
            ),
            "category": category
        })

    return vulnerabilities
