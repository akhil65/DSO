# Module 3 — Dynamic Application Security Testing (DAST)

## Overview

DAST attacks a live running application with real HTTP payloads — confirming runtime exploitability, not just code patterns. Unlike SAST (which reads source code), DAST acts like an attacker and interacts with the application over HTTP.

**Tool:** OWASP ZAP 2.16.1
**Target:** OWASP Juice Shop (http://localhost:3000)

---

## Real-World Context

DAST occupies a different position in the security programme than SAST. Because it requires a live, running application to test against, it cannot run at the code-commit stage — it runs in staging, after a build has been deployed and the application is accessible over HTTP. This makes DAST a later-stage control: it catches what slips through SAST (runtime configuration issues, authentication flaws, business logic vulnerabilities) and confirms that findings are genuinely exploitable, not just theoretical code patterns.

**Who owns this in a real org:** The AppSec team typically owns ZAP configuration and result triage. They maintain authenticated scan contexts (ZAP needs valid session cookies to scan behind a login), define the scope of what gets scanned, and run the active scanner in a controlled way against the staging environment where destructive payloads cannot affect production data. Some organisations embed a ZAP baseline scan directly in the CI/CD pipeline as a post-deploy check in staging — this is covered in Module 5. The results are triaged by AppSec and filed as tickets to the development team, with severity-based SLA expectations (Critical fixed within 24 hours, High within one sprint, and so on).

**Dev → Staging → Production:** Developers generally do not run DAST locally — the tooling is heavy and the payloads can break or corrupt running applications. In staging, automated ZAP baseline scans run after every deployment, with results flowing into the ticketing system (Jira, Linear, GitHub Issues). Before a major release, AppSec or the red team may run a full active scan with authenticated contexts to maximise coverage. Production is not scanned actively — active scanning sends attack payloads that can corrupt data, trigger alerts, and create audit noise. Production security is handled by WAF (Module 4.5), monitoring, and periodic external penetration tests.

**How findings reach stakeholders:** Developers see ZAP findings as tickets in their sprint backlog, categorised by OWASP category and severity. Engineering managers see the trend of open DAST findings across releases — a rising count before a launch is a risk conversation with the CISO. Security engineers use the ZAP report to prioritise which issues need manual verification (some DAST findings are false positives that require a human to confirm exploitability). Confirmed findings that represent data exposure or authentication bypass are escalated immediately outside the normal ticketing flow.

---

## Prerequisites

- Module 1 complete — Juice Shop running on port 3000
- OWASP ZAP installed
- Firefox installed

## Installation

```bash
brew install --cask owasp-zap
brew install --cask firefox
```

## Exercises

| # | Exercise | Tool | Status |
|---|----------|------|--------|
| 3.1 | Baseline passive scan (Docker) | ZAP Docker | ✅ Complete |
| 3.2 | Full active scan (ZAP GUI — macOS native) | ZAP GUI | ✅ Complete |
| 3.3 | Manual SQLi confirmation via curl | curl | ✅ Complete |

## Exercise 3.1 — Baseline Passive Scan (Docker)

Passive scan only — no attack payloads. Safe for any target.

```bash
mkdir -p /tmp/zap-reports

docker run --rm \
  -v /tmp/zap-reports:/zap/wrk:rw \
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t http://host.docker.internal:3000 \
  -r zap-baseline-report.html
```

> **Note:** Use `host.docker.internal:3000` not `localhost:3000` — Docker on macOS cannot reach the host's localhost directly.

## Exercise 3.2 — Full Active Scan (ZAP GUI)

> **Apple Silicon note:** The Docker full scan image crashes on arm64 due to headless Firefox. Use ZAP GUI natively instead.

1. Open ZAP from Applications
2. Quick Start tab → paste `http://localhost:3000` → click **Automated Scan**
3. Select **Standard Scan** (not Ajax — avoids Firefox dependency)
4. Wait ~15 minutes. Watch Alerts tab populate in real time
5. Report → Generate Report → HTML → save to `zap-reports/`

## Exercise 3.3 — Manual SQLi Confirmation

Confirm the SQL injection ZAP found is genuinely exploitable:

```bash
curl -s "http://localhost:3000/rest/products/search?q=%27%28"
```

Expected response — raw SQLite error leaked in response body:

```json
{"error":{"message":"SQLITE_ERROR: near \"(\": syntax error",
"sql":"SELECT * FROM Products WHERE ((name LIKE '%'(%' OR ..."}}
```

## Key Findings

| Severity | Finding | Endpoint |
|----------|---------|----------|
| HIGH | SQL Injection | `/rest/products/search?q='(` |
| MEDIUM | CSP Header Not Set | `/` (main page) |
| MEDIUM | CORS Wildcard (`Access-Control-Allow-Origin: *`) | JS bundle endpoints |
| MEDIUM | Missing Anti-clickjacking Header | socket.io endpoints |
| MEDIUM | Session ID in URL | socket.io GET/POST |

## Key Concepts

- **SAST vs DAST:** Semgrep (Module 2) flagged SQL concatenation as a code pattern. ZAP sent `'(` and got back the raw SQLite error — runtime confirmation. SAST gives root cause. DAST gives proof of exploitability. You need both.
- **Passive vs Active scan:** Passive = spider + observe only. Active = sends attack payloads. Always get permission before running active scans.
- **ZAP baseline** is safe for any target. ZAP full scan is intrusive — only run against lab environments you own.

## Roadblocks & Fixes

| Roadblock | Fix |
|-----------|-----|
| `/zap/wrk` not mounted error | Add `-v /tmp/zap-reports:/zap/wrk:rw` to docker run |
| `localhost:3000` unreachable inside Docker | Use `host.docker.internal:3000` |
| Docker full scan crashes on Apple Silicon | Use ZAP GUI natively — DomXSS requires headless Firefox which fails on arm64 |
| ZAP GUI: "Failed to start/connect to Firefox" | `brew install --cask firefox` or switch to Chrome in ZAP → Tools → Options → Selenium |

## Reports

See `docs/Module-3-ZAP-DAST-Report.docx`
