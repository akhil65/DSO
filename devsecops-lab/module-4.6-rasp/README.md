# Module 4.6 — Runtime Application Self-Protection (RASP)

## Overview

RASP instruments the application FROM WITHIN — unlike a WAF which sits outside as a reverse proxy, a RASP agent runs inside the Node.js/JVM runtime and monitors actual function calls. This means it sees decoded, deserialized data after all encoding tricks have been unwrapped, making it much harder to bypass.

**WAF vs RASP:**

| | WAF (Module 4.5) | RASP (This Module) |
|---|---|---|
| Position | External reverse proxy | Inside app runtime |
| Sees | Raw HTTP before decoding | Decoded data at function call level |
| Bypass risk | Higher — encoding tricks may evade rules | Lower — sees actual query sent to DB |
| Example | ModSecurity, Cloudflare WAF | OpenRASP, Contrast CE |

## Tools Covered

| Tool | Type | Language | Notes |
|------|------|----------|-------|
| OpenRASP (Baidu) | RASP agent | Node.js, Java, PHP | Most mature open-source RASP |
| Contrast Community Edition | RASP agent + dashboard | Node.js, Java | Free tier, best UI for learning |
| OWASP AppSensor | Detection framework | Java | Conceptual — detection + response patterns |

## Files in This Module

```
module-4.6-rasp/
├── README.md              ← This file
├── docker-compose.yml     ← Orchestrates juice-shop-rasp (port 3002) + juice-shop-contrast (port 3003)
├── Dockerfile             ← Multi-stage build: copies rasp-hook.js into distroless Juice Shop image
├── rasp-hook.js           ← Custom RASP agent: patches sqlite3 + Sequelize at require() time
├── openrasp.yml           ← OpenRASP agent configuration reference (block mode, hooks)
├── appsensor-config.xml   ← OWASP AppSensor detection point rules (conceptual)
└── .env.example           ← Contrast CE credentials template
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
| 4.6.3 | Connect Contrast CE agent + view attack dashboard | Contrast CE | 🔲 Pending |
| 4.6.4 | Review OWASP AppSensor detection rules | AppSensor | 🔲 Pending |

## Exercise 4.6.1 — Deploy Custom RASP Agent in Juice Shop (Docker) ✅

Uses a multi-stage Dockerfile to inject `rasp-hook.js` into the distroless Juice Shop image via `NODE_OPTIONS --require`. The hook patches `sqlite3`, `Sequelize`, and `http.ServerResponse` before any app code runs.

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

## Exercise 4.6.3 — Contrast CE Agent + Dashboard

1. Sign up free at [app.contrastsecurity.com](https://app.contrastsecurity.com)
2. After login: **User menu → Your Account → Download Agent → Node.js**
3. Copy your `CONTRAST__API__*` credentials from that page into `.env`:

```bash
cp .env.example .env
# Edit .env and fill in your Contrast CE credentials
nano .env
```

4. Start the Contrast-instrumented Juice Shop:

```bash
docker compose --profile contrast up -d
```

5. Generate traffic to trigger detections:

```bash
# SQLi probe — Contrast will detect and display in dashboard
curl "http://localhost:3003/rest/products/search?q='("

# Auth bypass attempt
curl -s -X POST http://localhost:3003/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"' OR 1=1--","password":"x"}'
```

6. Open [app.contrastsecurity.com](https://app.contrastsecurity.com) → **Applications → juice-shop-lab → Attacks** and observe detected attack events in real time.

> **What you see in Contrast dashboard:** Each attack shows the exact stacktrace — which function call in Juice Shop triggered the detection, the exact SQL string that was about to execute, the source line in `routes/search.js`, and the HTTP request that triggered it. This is the key RASP advantage: you see root cause, not just "403 blocked."

## Exercise 4.6.4 — OWASP AppSensor Detection Rules

AppSensor is a **detection framework** — it defines when application-layer events constitute an attack, then escalates the response proportionally. Unlike OpenRASP (blocks inline) or a WAF (blocks at HTTP layer), AppSensor is typically embedded in the application code itself as a library.

Review `appsensor-config.xml` — key detection points relevant to Juice Shop:

| ID | What it detects | Juice Shop scenario |
|----|----------------|---------------------|
| AE1 | 5+ failed logins in 5 min | Admin login brute force (Module 4) |
| AE2 | SQLi/XSS pattern in login fields | `' OR 1=1--` in email field |
| IE2 | SQLi in any input | `/rest/products/search?q='(` |
| ACE1 | IDOR — accessing resource not owned | `GET /rest/basket/2` when userId=1 |
| SE3 | Tampered session token | Modified JWT signature |

The detection point threshold for IE2 (SQLi) is set to **count=1, interval=1 minute** — a single injection attempt immediately fires the response chain: log → block 60 minutes → alert security team.

This is the key AppSensor insight: **the application itself is the sensor**. It knows context that no external tool can know — who the logged-in user is, what resource they own, what's a valid vs invalid object reference.

## Key Concepts

- **RASP hooks at the driver level** — `sqlite3.run()` is patched before app code runs; the agent sees the final SQL string regardless of how it was encoded in the HTTP request
- **WAF can be bypassed by double-encoding; RASP cannot** — by the time RASP sees the data, Node.js has decoded it fully
- **Contrast CE stacktraces** give root cause: exact source file + line + SQL string — not just "attack blocked"
- **AppSensor is context-aware** — it knows session owner, normal request patterns, and resource ownership; no external tool has this knowledge
- **Three complementary layers:** WAF (HTTP perimeter) + RASP (runtime enforcement) + AppSensor (application-layer detection) = defense in depth

## Roadblocks & Fixes

| Roadblock | Fix |
|-----------|-----|
| `@baidu/openrasp` npm install fails — distroless image has no shell | Replaced with custom `rasp-hook.js` injected via multi-stage Dockerfile + `NODE_OPTIONS --require` |
| `EACCES: permission denied, open '/juice-shop/rasp-hook.js'` | Juice Shop runs as uid 65532 (nobody); fix: `COPY --chmod=644` in Dockerfile |
| RASP false-positives block Juice Shop startup (CREATE TABLE) | Added `isDdl()` guard — skips all DDL statements that Sequelize runs internally |
| Broad `/LIKE\s+'%[^']*'[^%'\\]/i` pattern blocked internal background queries | Replaced with precise `/LIKE\s+'%'[^%']/i` — only fires when `'` appears right after the opening `%` |
| Regex merged onto comment line by formatter (pattern became dead code) | Ensured pattern is on its own line, separated from the `//` comment above it |
| Contrast CE free tier quota exhausted | Free tier allows one application; delete old app in dashboard before re-adding |
| Port 3002 already in use | Change `3002:3000` to `3004:3000` in docker-compose.yml |
| Contrast agent not showing in dashboard | Wait 2–3 minutes; check `docker compose logs juice-shop-contrast` for auth errors |

## Report

See `docs/Module-4.6-RASP-Report.docx` (generated at module completion)
