# Secure Flask REST API — Remediation Report

This repository contains a remediated version of the technology company's
Flask user registration/login API. The original implementation stored
passwords as unsalted MD5 hashes, hardcoded API credentials in source,
built SQL queries via string concatenation, and left `/admin`
unauthenticated. All four weaknesses are fixed below.

## Repository Layout
```
.
├── app.py                          # Flask app: routes, DB access, admin auth
├── crypto_utils.py                 # hash_password / verify_password (Bcrypt)
├── requirements.txt
├── .env.example                    # placeholder env vars — copy to .env
├── .gitignore                      # .env is excluded
└── .github/workflows/security.yml  # CI security gate (Bandit + Semgrep)
```

---

## Task 1 — STRIDE Threat Model

| STRIDE Category | Threat | Targeted Component | Mitigation |
|---|---|---|---|
| **S**poofing | An attacker submits a login request using a stolen or guessed username/password to impersonate a legitimate user | `/login` endpoint | Bcrypt-hashed password verification (`verify_password`) plus rate limiting on repeated failed attempts at the reverse proxy/firewall |
| **T**ampering | Malicious input is injected into the SQL query string to alter its logic (e.g., `' OR '1'='1`) | Database queries built from `username`/`password` fields in `/register` and `/login` | Parameterised queries via sqlite3 placeholders — user input is bound as data, never concatenated into SQL text |
| **R**epudiation | A user denies having registered an account or performed an admin action, and there's no record to prove otherwise | `/register` and `/admin` endpoints | Server-side request logging (timestamp, source IP, endpoint, outcome) written to an append-only log, correlated with the authenticated identity for admin actions |
| **I**nformation Disclosure | An attacker dumps the `users` table via `/admin` (unauthenticated) or via a successful injection, exposing username/password-hash pairs | `/admin` endpoint; the `users` table | API-key/token authentication middleware (`require_admin_auth`) on `/admin`, combined with the SQL injection fix above |
| **D**enial of Service | An attacker submits a very large number of `/register` or `/login` requests to exhaust database connections or CPU (bcrypt is intentionally slow) | `/register`, `/login` endpoints | Per-source rate limiting at the firewall/reverse-proxy layer (see Part 2's hashlimit rules) and a request-size/connection-count cap on the Flask app itself |
| **E**levation of Privilege | A regular authenticated user discovers or guesses the `/admin` route and gains administrative visibility into all accounts | `/admin` endpoint | Same middleware as Information Disclosure — the admin token is a distinct credential never issued to regular users, not merely "security by obscurity" of an unlisted route |

---

## Task 2 — OWASP Top 10 Remediation

### 2a. Injection (SQL Injection)

**Insecure pattern:**
```python
query = f"INSERT INTO users (username, password_hash) VALUES ('{username}', '{password_hash}')"
db.execute(query)
```

**Remediated pattern:**
```python
db.execute(
    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
    (username, password_hash),
)
```

The insecure version is exploitable because the `username` value is interpolated directly into the SQL text, so any user-supplied string containing SQL metacharacters (quotes, `--`, `;`) changes the query's structure rather than staying data — e.g., a crafted username can close the string early and append arbitrary SQL. The parameterised version sends the query template and the values separately to the database driver, which binds them as literal data, so no user input can ever be interpreted as SQL syntax regardless of its content.

### 2b. Broken Access Control

**Insecure pattern:**
```python
@app.route("/admin", methods=["GET"])
def admin():
    return jsonify({"users": get_all_users()})
```

**Remediated pattern:**
```python
@app.route("/admin", methods=["GET"])
@require_admin_auth
def admin():
    db = get_db()
    cursor = db.execute("SELECT id, username FROM users")
    users = [{"id": r[0], "username": r[1]} for r in cursor.fetchall()]
    return jsonify({"users": users}), 200
```

The insecure version performs no identity or authorization check at all — anyone who discovers the `/admin` path, authenticated or not, gets the full user list. The fix adds a decorator that requires a valid `X-Admin-Token` header matching a server-side secret before the route body ever executes, returning `401` otherwise, so access to administrative data now depends on possession of a credential rather than knowledge of a URL.

---

## Task 3 — Secure Password Hashing (Bcrypt)

See `crypto_utils.py` for the full implementation. Core functions:

```python
def hash_password(plain_text: str) -> str:
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(plain_text.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_text: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(plain_text.encode("utf-8"), stored_hash.encode("utf-8"))
```

**Actual output from running `python3 crypto_utils.py`, proving unique salts per call:**
```
Hash #1: $2b$12$XtsXS/vLNLJJBICMIp/SkuNpiX2k4zlJZic97zD3uwbx4Uijz/JJW
Hash #2: $2b$12$V2snqZjOf.Xavvrcv9.y9ekdCp.HYKqk9xfP3HDkFI/qCSV6q2WNK
Hashes are different: True
verify_password(pw, h1): True
verify_password(pw, h2): True
verify_password('wrong-password', h1): False
```

**Why MD5 is unsuitable for password storage, and why Bcrypt fixes each weakness:** MD5 is a general-purpose cryptographic hash designed to be *fast*, and that speed is exactly the wrong property for password storage — an attacker with a stolen hash database can compute billions of MD5 hashes per second on commodity GPU hardware, making brute-force and dictionary attacks cheap. MD5 also has known collision weaknesses (two different inputs producing the same digest), and because a plain MD5 hash of a common password is identical every time, attackers can precompute rainbow tables mapping common passwords to their MD5 hashes and reverse a stolen hash by lookup rather than computation. Bcrypt addresses all three: it is deliberately slow and tunable via its work factor (`BCRYPT_ROUNDS`), so it can be made more expensive as hardware improves; it embeds a unique random salt in every hash (shown above), so identical passwords never produce identical stored hashes and precomputed rainbow tables are useless; and while collision resistance isn't Bcrypt's primary design goal, its output space combined with per-hash salting makes precomputation attacks impractical in the way MD5 rainbow tables are practical.

---

## Task 4 — Secret Management

**Insecure pattern (hardcoded in source):**
```python
API_KEY = "sk_live_9f2a7c3e1b6d4f80"
ADMIN_TOKEN = "admin123"
```

**Refactored pattern (loaded from environment via python-dotenv):**
```python
from dotenv import load_dotenv
load_dotenv()

API_KEY = os.environ.get("API_KEY")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")

if not API_KEY or not ADMIN_TOKEN:
    raise RuntimeError("API_KEY and ADMIN_TOKEN must be set via environment variables.")
```

`.env.example` (placeholders only, real `.env` is never committed):
```
API_KEY=replace-with-a-real-api-key
ADMIN_TOKEN=replace-with-a-strong-random-admin-token
DATABASE_PATH=app.db
```

Relevant `.gitignore` line:
```
.env
```

**Why hardcoding secrets is dangerous even in a private repository:** a private repository is not a security boundary — it is still cloned onto developer laptops, cached in CI runners, included in every historical commit (recoverable from git history even after later removal), and exposed to anyone who gains access through a compromised developer account, a misconfigured repo-visibility change, or a third-party integration with read access. Hardcoded secrets also can't be rotated without a code change and redeploy, which discourages the routine rotation (a 30–90 day rotation window is standard practice for API keys and tokens) that limits how long a leaked credential remains useful to an attacker; externalizing secrets to environment variables/a secrets manager lets them be rotated independently of the application's code and release cycle.

---

## Task 5 — CI/CD Security Gate

`.github/workflows/security.yml`:
```yaml
name: Security Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install bandit

      - name: Run Bandit SAST scan
        run: bandit -r . -ll

      - name: Run Semgrep (python ruleset)
        uses: semgrep/semgrep-action@v1
        with:
          config: p/python
        continue-on-error: false
```

Verified locally — `bandit -r . -ll` against this remediated codebase exits `0` with no Medium/High findings:
```
Run metrics:
        Total issues (by severity):
                Undefined: 0
                Low: 0
                Medium: 0
                High: 0
```
(`-ll` sets Bandit's reporting threshold to Medium-and-above; any Medium or High finding produces a non-zero exit code, which fails the GitHub Actions job and blocks the merge/deploy.)

**Shift Left Security:** "shifting left" means moving security checks earlier in the software development lifecycle — into the developer's own commit/PR workflow — rather than only auditing for vulnerabilities after deployment. This workflow implements that principle directly: Bandit runs automatically on every push and pull request against `main`, so an injection flaw or a reintroduced hardcoded secret is caught and blocks the merge before the code ever reaches production, instead of being discovered later by a penetration test or, worse, an attacker.

---

## Task 6 — Supply Chain Security Statement (≈180 words)

This application depends on three open-source libraries — Flask, Bcrypt, and python-dotenv — each of which pulls in its own transitive dependencies that the development team never directly reviewed. A software supply chain attack occurs when an adversary compromises one of those upstream packages (or a dependency of a dependency) rather than attacking the application directly — for example, by publishing a malicious version under a typosquatted package name, or by compromising a maintainer's publishing credentials and pushing a backdoored release of a legitimately-trusted package. Because `pip install` executes arbitrary setup code and the resulting package runs with the full privileges of the application, a compromised dependency can lead directly to malicious code execution or credential theft (e.g., silently exfiltrating the `API_KEY`/`ADMIN_TOKEN` values this application loads from environment variables). An SBOM (Software Bill of Materials) is a structured, machine-readable inventory of every component and transitive dependency in the application, along with each one's exact version and source. SCA (Software Composition Analysis) tooling consumes that SBOM, cross-references each entry's version against vulnerability databases (e.g., the OSV or NVD feeds), and flags any dependency — including nested, transitive ones the team never explicitly chose — that has a known CVE, enabling remediation before the vulnerable version ships.
