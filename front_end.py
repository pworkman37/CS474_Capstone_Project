
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from semgrep_function import run_semgrep
from groq_function import analyze_vulnerability

import os
import tempfile

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024


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

                    vulnerabilities = run_semgrep(file_path)

                    for vulnerability in vulnerabilities:
                        try:
                            ai_analysis = analyze_vulnerability(
                                vulnerability,
                                source_code
                            )
                        except Exception as exc:
                            ai_analysis = (
                                "Gemini analysis unavailable: "
                                + str(exc).splitlines()[0][:200]
                            )

                        results.append({
                            **vulnerability,
                            "ai_analysis": ai_analysis
                        })

            except Exception as exc:
                error = (
                    "Scan failed: "
                    + str(exc).splitlines()[0][:200]
                )

    return render_template(
        "index.html",
        results=results,
        error=error,
        filename=filename
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
