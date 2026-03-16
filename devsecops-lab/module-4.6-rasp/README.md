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
├── docker-compose.yml     ← Orchestrates juice-shop-rasp + juice-shop-contrast
├── Dockerfile             ← Builds Juice Shop image with OpenRASP agent injected
├── rasp-entrypoint.sh     ← Entrypoint that sets NODE_OPTIONS --require before app start
├── openrasp.yml           ← OpenRASP agent configuration (block mode, hooks enabled)
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
| 4.6.1 | Deploy OpenRASP Node.js agent in Juice Shop | OpenRASP | 🔲 Pending |
| 4.6.2 | Verify SQLi blocked at runtime (not at HTTP layer) | OpenRASP | 🔲 Pending |
| 4.6.3 | Connect Contrast CE agent + view attack dashboard | Contrast CE | 🔲 Pending |
| 4.6.4 | Review OWASP AppSensor detection rules | AppSensor | 🔲 Pending |

## Exercise 4.6.1 — Deploy OpenRASP in Juice Shop (Docker)

Builds a custom Juice Shop image with the OpenRASP Node.js agent injected via `NODE_OPTIONS --require`. The agent patches `sqlite3` and `http` internals before the app starts.

```bash
cd module-4.6-rasp

# Build the RASP-instrumented Juice Shop image
docker compose --profile openrasp build

# Start it (runs on port 3002 to avoid conflicts with original on port 3000)
docker compose --profile openrasp up -d

# Verify it's running
docker compose ps
curl -s http://localhost:3002 | head -5
```

> **Ports:** Original Juice Shop = 3000, WAF-protected = 3001, RASP-protected = 3002

Check that OpenRASP agent loaded in startup logs:

```bash
docker compose logs juice-shop-rasp | grep -i rasp
```

Expected output includes: `[OpenRASP] Agent initialized` and `[OpenRASP] SQL hook active`

## Exercise 4.6.2 — Verify SQLi Blocked at Runtime

First confirm the attack bypasses WAF if URL-encoded (WAF can be evaded by encoding tricks), then confirm RASP catches it anyway since it sees the decoded SQL string.

```bash
# Step 1 — Direct Juice Shop (no WAF, no RASP) — should return SQLite error
curl -s "http://localhost:3000/rest/products/search?q=%27%28"

# Step 2 — Via WAF — should be BLOCKED (403) because CRS detects the payload
curl -s -o /dev/null -w "%{http_code}" "http://localhost:3001/rest/products/search?q=%27%28"

# Step 3 — RASP-protected Juice Shop — also BLOCKED, but for a different reason:
# The WAF never sees it; the RASP agent hooks sqlite3.run() and blocks AFTER decoding
curl -s -o /dev/null -w "%{http_code}" "http://localhost:3002/rest/products/search?q=%27%28"

# Step 4 — Double-encode to try to bypass WAF — WAF may miss it
# %2527%2528 = URL-encoded version of %27%28 = attacker tries to fool WAF
curl -s -o /dev/null -w "%{http_code}" "http://localhost:3001/rest/products/search?q=%2527%2528"
# WAF: might return 200 (bypass!) depending on paranoia level

# Step 5 — Same double-encoded payload against RASP
# RASP sees the final decoded string at sqlite3 level — still blocked
curl -s -o /dev/null -w "%{http_code}" "http://localhost:3002/rest/products/search?q=%2527%2528"
# RASP: 302 or 403 (blocked) — encoding tricks don't help against RASP
```

**What to observe:** RASP blocks at the sqlite3 call site. It doesn't matter how the payload arrived or what encoding was used — by the time RASP sees it, Node.js has decoded it completely.

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
| `@baidu/openrasp` npm install fails | OpenRASP Node.js agent requires native bindings — use the Docker build; don't try `npm install` locally on macOS |
| Contrast CE free tier quota exhausted | Free tier allows one application; delete old app in dashboard before re-adding |
| Port 3002 already in use | Change `3002:3000` to `3004:3000` in docker-compose.yml |
| OpenRASP logs show "hook disabled" | Ensure `OPENRASP_CONFIG` env var points to `openrasp.yml` correctly |
| Contrast agent not showing in dashboard | Wait 2–3 minutes; check `docker compose logs juice-shop-contrast` for auth errors |

## Report

See `docs/Module-4.6-RASP-Report.docx` (generated at module completion)
