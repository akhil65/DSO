# Module 4.6 — Runtime Application Self-Protection (RASP)

## Overview

RASP instruments the application FROM WITHIN — unlike a WAF which sits outside as a reverse proxy, a RASP agent runs inside the Node.js/JVM runtime and monitors actual function calls. This means it sees decoded, deserialized data after all encoding tricks have been unwrapped, making it much harder to bypass.

**WAF vs RASP:**

| | WAF (Module 4.5) | RASP (This Module) |
|---|---|---|
| Position | External reverse proxy | Inside app runtime |
| Sees | Raw HTTP before decoding | Decoded data at function call level |
| Bypass risk | Higher — encoding tricks may evade rules | Lower — sees actual query sent to DB |
| Examples | ModSecurity, Cloudflare WAF | rasp-hook.js, Contrast RASP v3, Datadog ASM |

## Tools Covered

| Tool | Type | Account needed? | Port |
|------|------|-----------------|------|
| Custom rasp-hook.js | RASP (hand-rolled) | None | 3002 |
| Contrast RASP v3 (`@contrast/rasp-v3`) | RASP (OSS alpha) | None | 3003 |
| OWASP AppSensor (appsensor-hook.js) | Detection + escalating response | None | 3004 |
| Datadog ASM (Sqreen successor) | RASP-as-a-service | Optional (dashboard only) | 3005 |
| Signal Sciences / Fastly Next-Gen WAF | Hybrid WAF/RASP sidecar | Enterprise license | 3006 |

> **Note on Contrast CE:** Contrast Community Edition reached EOL on June 30, 2025 and is no longer available.  Exercise 4.6.3 uses `@contrast/rasp-v3`, the open-source RASP core Contrast published on npm.

## Files in This Module

```
module-4.6-rasp/
├── README.md                    ← This file
├── docker-compose.yml           ← All 5 Juice Shop variants (ports 3002–3006)
│
├── Dockerfile                   ← 4.6.1/4.6.2: custom rasp-hook.js (openrasp profile)
├── rasp-hook.js                 ← Custom RASP: patches sqlite3 + Sequelize at require()
│
├── Dockerfile.contrast          ← 4.6.3: @contrast/rasp-v3 (contrast-rasp profile)
├── contrast-rasp-wrapper.js     ← Loads + initialises @contrast/rasp-v3
│
├── Dockerfile.appsensor         ← 4.6.4: AppSensor hook (appsensor profile)
├── appsensor-hook.js            ← AppSensor: LOG→WARN(429)→BLOCK(403) per IP
├── appsensor-config.xml         ← AppSensor detection point reference
│
├── Dockerfile.datadog           ← 4.6.5: Datadog ASM / dd-trace (datadog-asm profile)
├── datadog-rasp-wrapper.js      ← Initialises dd-trace with appsec.enabled=true
│
├── sigsci-middleware-example.js ← 4.6.6: Signal Sciences architecture + middleware code
├── openrasp.yml                 ← OpenRASP config reference (informational)
└── run-exercises.sh             ← One-shot runner: builds + tests 4.6.3, 4.6.4, 4.6.5
```

## Prerequisites

- Module 4 complete (attacks confirmed)
- Module 4.5 complete (WAF baseline established)
- Docker Desktop running
- Juice Shop running on port 3000

## Exercises

| # | Exercise | Tool | Status |
|---|----------|------|--------|
| 4.6.1 | Deploy custom RASP agent in Juice Shop via Docker | rasp-hook.js | ✅ Complete |
| 4.6.2 | Verify SQLi blocked at runtime (not at HTTP layer) | rasp-hook.js | ✅ Complete |
| 4.6.3 | Deploy Contrast RASP v3 (OSS npm package, no account) | @contrast/rasp-v3 | 🔲 Run locally |
| 4.6.4 | Implement AppSensor escalating response (LOG→WARN→BLOCK) | appsensor-hook.js | ✅ Logic confirmed |
| 4.6.5 | Deploy Datadog ASM — the Sqreen successor | dd-trace + libddwaf | 🔲 Run locally |
| 4.6.6 | Study Signal Sciences hybrid WAF/RASP sidecar architecture | sigsci-middleware-example.js | ✅ Architecture reviewed |

> **Quick start:** `chmod +x run-exercises.sh && ./run-exercises.sh` — builds and tests 4.6.3, 4.6.4, and 4.6.5 in sequence with automated pass/fail output.

---

## Exercise 4.6.1 — Deploy Custom RASP Agent in Juice Shop (Docker) ✅

Uses a multi-stage Dockerfile to inject `rasp-hook.js` into the distroless Juice Shop image via `NODE_OPTIONS --require`. The hook patches `sqlite3`, `Sequelize` before any app code runs.

> **Why custom instead of OpenRASP?** `@baidu/openrasp` requires native bindings that can't compile inside the distroless Juice Shop image (no shell, no build tools). The custom hook achieves the same patching mechanism — `Module._load` intercept + `NODE_OPTIONS --require` — and is more readable for learning.

```bash
cd module-4.6-rasp

docker compose --profile openrasp build
docker compose --profile openrasp up -d
sleep 20
docker compose logs juice-shop-rasp | grep -i rasp
```

**Expected startup log (confirmed):**
```
[RASP] Agent initialized — hooks: SQLi (sqlite3 + Sequelize), XSS response scan
[RASP] NODE_OPTIONS --require loaded rasp-hook.js before app startup
[RASP] Sequelize query hook active
[RASP] sqlite3 module loaded — patching Database methods
[RASP] sqlite3 hooks active — SQLi detection enabled
info: Server listening on port 3000
```

> **Ports:** Original Juice Shop = 3000, WAF-protected = 3001, RASP-protected = 3002

---

## Exercise 4.6.2 — Verify SQLi Blocked at Runtime ✅

**Confirmed results:**

| Payload | Port 3000 (direct) | Port 3002 (RASP) |
|---------|-------------------|-----------------|
| `'(` (`%27%28`) | 200 + SQLite error in body | **403** — blocked |
| `' OR 1=1--` | 200 + auth bypass | **403** — blocked |
| `test UNION SELECT 1,2,3--` | 200 + data returned | **403** — blocked |
| `apple` (clean) | 200 OK | **200 OK** — passes |

```bash
curl -s -o /dev/null -w "RASP '( payload:       %{http_code}\n" "http://localhost:3002/rest/products/search?q=%27%28"
curl -s -o /dev/null -w "RASP OR 1=1 payload:  %{http_code}\n" "http://localhost:3002/rest/products/search?q=%27+OR+1%3D1--"
curl -s -o /dev/null -w "RASP UNION SELECT:     %{http_code}\n" "http://localhost:3002/rest/products/search?q=test+UNION+SELECT+1,2,3--"
curl -s -o /dev/null -w "RASP clean search:    %{http_code}\n" "http://localhost:3002/rest/products/search?q=apple"
docker compose logs juice-shop-rasp | grep "BLOCKED"
```

**BLOCKED log evidence (confirmed):**
```
[RASP] BLOCKED — SQL Injection (Sequelize) detected | evidence: SELECT * FROM Products WHERE ((name LIKE '%'(%' OR description LIKE '%'(%') AND deletedAt IS NULL)
[RASP] BLOCKED — SQL Injection (Sequelize) detected | evidence: SELECT * FROM Products WHERE ((name LIKE '%' OR 1=1--%' ...
[RASP] BLOCKED — SQL Injection (Sequelize) detected | evidence: SELECT * FROM Products WHERE ((name LIKE '%test UNION SELECT 1,2,3--%' ...
```

The hook intercepts the Sequelize `.query()` call with the fully-constructed SQL string — **the database driver never receives the malicious query**.

---

## Exercise 4.6.3 — Contrast RASP v3 (OSS npm package)

**Context:** Contrast Community Edition (CE) reached **end-of-life June 30, 2025** and is no longer available. `@contrast/rasp-v3` is the open-source RASP core Contrast published on npm — no account, no API key, no server connection required. It's pre-release (v0.7.0-alpha.5) but installable and usable for lab purposes.

**What it instruments:** Similar to `rasp-hook.js` — hooks into Node.js module internals to intercept dangerous operations at the runtime level. The key difference: Contrast's ruleset covers a broader attack surface (XSS, path traversal, SSRF, command injection) beyond just SQLi.

```bash
cd module-4.6-rasp

docker compose --profile contrast-rasp build
docker compose --profile contrast-rasp up -d
sleep 20
docker compose logs -f juice-shop-contrast-rasp
```

**Expected startup log:**
```
[Contrast RASP v3] Loading agent from /juice-shop/contrast_modules/@contrast/rasp-v3
[Contrast RASP v3] Initialized via rasp.enable() ✓
```

If the log shows `WARNING: no known init method found`, check the exports printed and update `contrast-rasp-wrapper.js` to match the actual API shape — the package is alpha and the API may have changed.

**Test blocking:**
```bash
# SQLi — should return 403 if Contrast RASP v3 initialised correctly
curl -s -o /dev/null -w "Contrast RASP '(: %{http_code}\n" \
  "http://localhost:3003/rest/products/search?q=%27%28"

curl -s -o /dev/null -w "Contrast OR 1=1: %{http_code}\n" \
  "http://localhost:3003/rest/products/search?q=%27+OR+1%3D1--"

curl -s -o /dev/null -w "Contrast clean:  %{http_code}\n" \
  "http://localhost:3003/rest/products/search?q=apple"
```

**Compare with custom rasp-hook.js:**
```bash
# Side-by-side: custom RASP (3002) vs Contrast RASP v3 (3003)
for PORT in 3002 3003; do
  echo -n "Port $PORT OR 1=1: "
  curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:${PORT}/rest/products/search?q=%27+OR+1%3D1--"
  echo
done
```

**Why this matters over rasp-hook.js:**  A commercial/semi-commercial RASP covers dozens of attack categories via a maintained ruleset. Our custom hook covers only SQLi patterns we wrote by hand — `@contrast/rasp-v3` should handle XSS, path traversal, SSRF, and command injection out of the box.

---

## Exercise 4.6.4 — OWASP AppSensor (Escalating Response)

**AppSensor philosophy:** Instead of blocking every first occurrence (RASP), AppSensor escalates proportionally based on how many attacks originate from a given IP. One accidental bad request gets logged; repeated attacks get blocked. This reduces false positives for legitimate users who trigger a single anomaly.

**`appsensor-hook.js` detection points:**

| DP | What it detects | Source |
|----|----------------|--------|
| IE1 | SQLi pattern visible in URL query string | http.Server emit hook |
| IE2 | SQLi reaching sqlite3/Sequelize driver | Module._load + require() patch |
| ACE1 | Force-browsing to admin/config/git paths | http.Server emit hook |
| RE1 | URL query string > 512 characters | http.Server emit hook |

**Thresholds (tunable in `appsensor-hook.js`):**

| Hit # | Action | HTTP Status |
|-------|--------|-------------|
| 1–2 | LOG — anomaly recorded, request passes | 200 |
| 3–4 | WARN — attacker slowed down | 429 Too Many Requests |
| 5+ | BLOCK — attacker fully denied | 403 Forbidden |
| 10+ | (conceptual) DISABLE_ACCOUNT / CAPTCHA gate | — |

Counters reset after 10 minutes of inactivity per IP.

```bash
docker compose --profile appsensor build
docker compose --profile appsensor up -d
sleep 20
docker compose logs juice-shop-appsensor | grep AppSensor
```

**Test escalation (run from same IP, 6× in quick succession):**
```bash
for i in {1..6}; do
  echo -n "Hit $i: "
  curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:3004/rest/products/search?q=%27+OR+1%3D1--"
  echo
done
```

**Expected output:**
```
Hit 1: 200    ← LOG — passes through
Hit 2: 200    ← LOG
Hit 3: 429    ← WARN — rate limited
Hit 4: 429    ← WARN
Hit 5: 403    ← BLOCK
Hit 6: 403    ← BLOCK
```

**Confirmed via unit test (5/5 tests pass — no Docker required):**
```
[AppSensor] LOG   | DP=IE1 | IP=10.0.0.1 | count=1 | url_param=q='+OR+1=1--
[AppSensor] LOG   | DP=IE1 | IP=10.0.0.1 | count=2 | url_param=q='+OR+1=1--
[AppSensor] WARN  | DP=IE1 | IP=10.0.0.1 | count=3 | url_param=q='+OR+1=1--
[AppSensor] BLOCK | DP=IE1 | IP=10.0.0.1 | count=5 | url_param=q='+OR+1=1--
```
✅ IE1 escalation | ✅ clean pass | ✅ ACE1 force-browse | ✅ independent IP counters | ✅ RE1 long param

**Watch the escalation in logs:**
```bash
docker compose logs -f juice-shop-appsensor | grep AppSensor
# [AppSensor] LOG    | DP=IE1 | IP=172.17.0.1 | count=1 | url_param=' OR 1=1--
# [AppSensor] LOG    | DP=IE1 | IP=172.17.0.1 | count=2 | url_param=' OR 1=1--
# [AppSensor] WARN   | DP=IE1 | IP=172.17.0.1 | count=3 | url_param=' OR 1=1--
# [AppSensor] BLOCK  | DP=IE1 | IP=172.17.0.1 | count=5 | url_param=' OR 1=1--
```

**Test ACE1 — force-browse to admin path:**
```bash
curl -s -o /dev/null -w "ACE1 admin path: %{http_code}\n" \
  "http://localhost:3004/admin"
```

**AppSensor vs RASP — key distinction:** RASP throws inline at the first attack. AppSensor trades some risk on hit 1 and 2 to dramatically reduce false positives from security scanners, automated crawlers, and misconfigured integrations that fire a single bad request and should not be blocked permanently.

---

## Exercise 4.6.5 — Datadog ASM (Sqreen Successor)

**The Sqreen story:**

| Year | Event |
|------|-------|
| 2017 | Sqreen founded; first RASP-as-a-service for Node.js via `--require` hook |
| 2018 | Sqreen launches automatic WAF rules + account suspension |
| 2021 | Datadog acquires Sqreen (~$260M); agent integrated into `dd-trace` |
| 2022 | Datadog open-sources libddwaf (WAF/RASP engine, Apache 2.0) |
| 2023 | `dd-trace` v4: `DD_APPSEC_ENABLED=true` enables inline blocking with bundled OWASP CRS-based rules |
| 2024 | Sqreen npm package last published 3+ years ago — **officially deprecated** |

**Key insight:** Datadog ASM's blocking is enforced **locally** by libddwaf — the bundled rule engine. You do **not** need a Datadog account to block attacks. `DD_API_KEY` is only required to send attack events to the Datadog dashboard.

```bash
docker compose --profile datadog-asm build
docker compose --profile datadog-asm up -d
sleep 25  # dd-trace init takes slightly longer
docker compose logs juice-shop-datadog | grep -i "datadog\|appsec\|ASM"
```

**Expected startup log:**
```
[Datadog ASM] Loading dd-trace from /juice-shop/dd_modules/dd-trace
[Datadog ASM] dd-trace initialized — AppSec blocking: ENABLED
[Datadog ASM] libddwaf rules: bundled (no cloud connection required for blocking)
[Datadog ASM] Dashboard: requires DD_API_KEY + free Datadog trial account
```

**Test blocking (libddwaf, no account needed):**
```bash
curl -s -o /dev/null -w "Datadog ASM OR 1=1: %{http_code}\n" \
  "http://localhost:3005/rest/products/search?q=%27+OR+1%3D1--"
# → 403 — blocked by libddwaf locally

curl -s -o /dev/null -w "Datadog ASM clean:  %{http_code}\n" \
  "http://localhost:3005/rest/products/search?q=apple"
# → 200 — passes
```

**Optional — connect Datadog dashboard (free 14-day trial):**
```bash
# 1. Sign up: https://app.datadoghq.com/signup
# 2. Create API key: https://app.datadoghq.com/organization-settings/api-keys
# 3. Add to .env:
echo "DD_API_KEY=your_key_here" >> .env

# 4. Restart with key:
docker compose --profile datadog-asm down
docker compose --profile datadog-asm up -d

# 5. View attacks: https://app.datadoghq.com/security/appsec
```

**What the dashboard shows (Sqreen heritage):** Each blocked attack displays the full request, source IP, matched rule, and — crucially — the **stacktrace inside Node.js** showing which line of Juice Shop code processed the malicious input. This is the core Sqreen innovation that Datadog inherited: root-cause visibility, not just block/allow logging.

**Compare all three in-process RASP agents side by side:**
```bash
for PORT in 3002 3003 3004 3005; do
  echo -n "Port $PORT (hit 1): "
  curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:${PORT}/rest/products/search?q=%27+OR+1%3D1--"
  echo
done
# 3002 = custom hook, 3003 = Contrast, 3004 = AppSensor (LOG only on hit 1), 3005 = Datadog ASM
```

---

## Exercise 4.6.6 — Signal Sciences / Fastly Next-Gen WAF (Architecture Study)

**Status:** Enterprise license required — no free tier. This exercise is an architecture study using `sigsci-middleware-example.js`.

**Why Signal Sciences is different from all the above:**

Signal Sciences does NOT run entirely in-process. It uses a **sidecar daemon** model:

```
┌─────────────────────┐   ① HTTP request metadata   ┌────────────────────────┐
│  Node.js App         │ ──────────────────────────→ │  sigsci-agent          │
│  (Express middleware)│ ←────────────────────────── │  (local daemon :9999)  │
└─────────────────────┘   ② allow / block decision   └───────────┬────────────┘
                                                                  │ ③ telemetry
                                                                  ▼
                                                       Signal Sciences Cloud
                                                       (dashboard, rule updates)
```

This makes it a **hybrid** — it has in-process visibility (the middleware runs inside Node.js, sees decoded request data) but the blocking decision is made **outside** the process by the agent daemon.

**Architecture comparison — all tools in this module:**

| Property | rasp-hook.js | Contrast RASP v3 | AppSensor | Datadog ASM | Signal Sciences |
|---|---|---|---|---|---|
| Position | In-process | In-process | In-process | In-process | In-process + sidecar |
| Blocking | Synchronous throw | Synchronous throw | Synchronous throw | Synchronous throw | Agent daemon decision |
| Block latency | 0 ms | 0 ms | 0 ms | 0 ms | ~0.1–1 ms (socket) |
| Data access | SQL/API level | SQL/API level | HTTP + SQL level | HTTP + SQL level | HTTP request metadata |
| Crash isolation | Bug = app crash | Bug = app crash | Bug = app crash | Bug = app crash | Agent crash ≠ app crash |
| Ruleset | Custom (SQLi only) | Maintained OSS | Custom thresholds | libddwaf (OWASP CRS) | SigSci cloud rules |
| Account | None | None | None | Optional | Required (enterprise) |
| Cost | Free | Free | Free | Free (blocking) | Enterprise |

**Study `sigsci-middleware-example.js`** — it contains the middleware registration code, architecture diagram, and a detailed comparison table. Running it requires `sigsci-module-nodejs` installed and `sigsci-agent` daemon running (enterprise only):

```bash
# Architecture only — do NOT run without enterprise credentials
cat module-4.6-rasp/sigsci-middleware-example.js
```

**Key insight from Signal Sciences architecture:** The sidecar model provides crash isolation (agent crash doesn't affect app) and enables centralized rule updates without app redeployment. But it introduces a network hop that pure in-process RASP avoids. For blocking at microsecond latency (e.g., payment APIs, authentication endpoints), in-process RASP wins. For centralized policy management across many services, the sidecar model wins.

---

## Key Concepts

- **RASP hooks at the driver level** — `sqlite3.run()` is patched before app code runs; the agent sees the final SQL string regardless of how it was encoded in HTTP
- **WAF can be bypassed by double-encoding; RASP cannot** — by the time RASP sees the data, Node.js has decoded it fully
- **AppSensor vs RASP** — RASP blocks immediately; AppSensor trades hit-1 false-negative risk for dramatically lower false-positive rate across legitimate users
- **Sqreen's lasting legacy** — the `NODE_OPTIONS --require` injection pattern, per-request stacktrace visibility, and account suspension response are all Sqreen innovations now embedded in Datadog ASM
- **Signal Sciences is not pure RASP** — it's "next-gen WAF" because the decision happens outside the process; still vastly better than a traditional WAF because the in-process module sends decoded request context
- **Defense in depth:** WAF (HTTP perimeter) + RASP (runtime enforcement) + AppSensor (application-layer detection with context) + commercial agent (threat intel + dashboard)

## Roadblocks & Fixes

| Roadblock | Fix |
|-----------|-----|
| `/bin/sh: stat /bin/sh: no such file or directory` during Docker build | Distroless Juice Shop image has no shell; use multi-stage build with `node:20-alpine` as builder |
| `EACCES: permission denied, open '/juice-shop/rasp-hook.js'` | Juice Shop runs as uid 65532 (nobody); fix: `COPY --chmod=644` in Dockerfile |
| RASP false-positives block Juice Shop startup (CREATE TABLE) | Added `isDdl()` guard — skips all DDL statements that Sequelize runs internally |
| Broad LIKE pattern blocked internal background queries | Replaced with precise `/LIKE\s+'%'[^%']/i` — only fires when `'` appears right after opening `%` |
| Regex merged onto comment line by formatter (pattern became dead code) | Ensured pattern is on its own line, separated from the `//` comment above it |
| Contrast CE EOL (June 30, 2025) | Replaced with `@contrast/rasp-v3` — no account needed |
| `@contrast/rasp-v3` unknown init API (alpha) | `contrast-rasp-wrapper.js` tries all 5 known init shapes; logs exports if none match |
| Sqreen npm package defunct | Replaced with `dd-trace` + `DD_APPSEC_ENABLED=true`; libddwaf blocks locally without DD account |
| Signal Sciences requires enterprise license | Architecture study exercise; `sigsci-middleware-example.js` documents the sidecar model |

## Report

See `docs/Module-4.6-RASP-Report.docx` (generated at module completion)
