# Module 3 — Dynamic Application Security Testing (DAST)

## Overview

DAST attacks a live running application with real HTTP payloads — confirming runtime exploitability, not just code patterns. Unlike SAST (which reads source code), DAST acts like an attacker and interacts with the application over HTTP.

**Tool:** OWASP ZAP 2.16.1
**Target:** OWASP Juice Shop (http://localhost:3000)

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
