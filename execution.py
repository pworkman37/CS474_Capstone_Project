from semgrep_function import run_semgrep
from groq_function import analyze_vulnerability

# File to scan
file_path = "test_files/vulnerable.py"

# Run Semgrep
vulnerabilities = run_semgrep(file_path)

# Read the source code
with open(file_path, "r", encoding="utf-8") as file:
    source_code = file.read()

print("=" * 50)
print("AI + SEMGREP VULNERABILITY DETECTOR")
print("=" * 50)

print(f"\nTotal vulnerabilities found: {len(vulnerabilities)}")

# Analyze each vulnerability
for vulnerability in vulnerabilities:

    print("\n" + "=" * 50)
    print("SEMGREP FINDING")
    print("=" * 50)

    print("Vulnerability:", vulnerability["category"])
    print("Severity:", vulnerability["severity"])
    print("Line:", vulnerability["line"])
    print("Description:", vulnerability["message"])

    print("\n" + "=" * 50)
    print("OPENAI ANALYSIS")
    print("=" * 50)

    try:
        analysis = analyze_vulnerability(
            vulnerability,
            source_code
        )

        print(analysis)

    except Exception as error:
        print("Gemini analysis failed:", error)