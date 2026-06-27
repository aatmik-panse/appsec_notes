# Secure Code Review Assignment — Deliverable Folder

Secure code review of the **Scaler Support Desk** deliberately-vulnerable Flask application.

## Contents

| File | Description |
|---|---|
| `Secure_Code_Review_Report.md` | The full report (Markdown): executive summary, scope, methodology, findings summary table, **15 confirmed True-Positive findings** (ID, title, severity, CWE, real file:line, vulnerable snippet, impact, remediation), a **4-entry False Negatives** section, and a conclusion. |
| `Secure_Code_Review_Report.docx` | Word version of the same report, formatted to match the provided sample report. |
| `semgrep_output.txt` | Raw Semgrep scan output (human-readable). |
| `semgrep_output.json` | Raw Semgrep scan output (JSON) — 15 raw results. |

## How the review was produced

- **App reviewed:** `supportdesk-app.zip` → Flask 3.0.3 / Python 3, SQLite, Jinja2 templates.
- **SAST tool:** Semgrep **v1.168.0**, run with curated community security packs:
  ```
  semgrep scan --config p/python --config p/flask --config p/secrets \
               --config p/command-injection --config p/sql-injection .
  ```
  (`--config auto` requires Semgrep telemetry to be enabled to reach the rule registry; the curated
  packs above give equivalent coverage for this codebase and were used so the scan could run with
  telemetry off.)
- **Manual review:** every Semgrep result was validated, and a line-by-line manual pass found the
  access-control, IDOR, stored-XSS, path-traversal, upload, and race-condition issues the scanner
  cannot detect.

All file paths and line numbers in the report are taken from the actual extracted source code.
