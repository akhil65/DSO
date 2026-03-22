# Module 4.6 — Runtime Application Self-Protection (RASP)

## Overview

| | WAF (Module 4.5) | RASP (This Module) |
|---|---|---|
| Position | External reverse proxy | Inside app runtime |
| Sees | Raw HTTP before decoding | Decoded data at function call level |
| Bypass risk | Higher — encoding tricks may evade rules | Lower — sees actual query sent to DB |

---

## Real-World Context

A WAF sees what arrives at the door. RASP sees what actually happens inside the house. Because RASP instruments the application runtime — hooking into database calls, file system operations, and process execution at the code level — it cannot be bypassed with encoding tricks that fool regex-based WAF rules. An attacker who successfully evades the WAF still hits the RASP when their payload reaches the actual database driver. This is why RASP and WAF are complementary rather than competing controls, and why mature security programmes run both.

**Who owns this in a real org:** RASP is deployed by the platform or DevOps team as part of the application container configuration — it is an agent or library loaded at application startup, not something developers install manually. Commercial RASP products (Datadog ASM, Contrast Security, Sqreen/Snyk) are provisioned at the infrastructure level: a sidecar container, an environment variable that activates the agent, or a JVM argument that loads the instrumentation library. Developers may not even know RASP is running — it is transparent to application code when operating correctly. When RASP does block a request, the platform team and AppSec are alerted, and the AppSec team determines whether it was a genuine attack or a false positive requiring a rule exclusion.

**Dev → Staging → Production:** In development, RASP is typically not active — the overhead and configuration complexity are not worthwhile for local testing. In staging, RASP runs in detection (observe-only) mode, logging what it would have blocked without actually blocking anything. This tuning phase is critical: AppSec reviews RASP observations in staging to identify false positives before enabling blocking mode in production. In production, RASP runs in blocking mode. Every blocked event is logged to the SIEM. A spike in RASP blocks — especially across multiple application instances simultaneously — is a strong signal that an active exploitation attempt is underway, which triggers an incident response process.

**How findings reach stakeholders:** Unlike pentest reports, RASP does not produce a one-time findings document. It produces a continuous stream of runtime security events. These feed into the SIEM as structured logs with context (which endpoint was hit, what the payload looked like, which rule triggered, whether the request was blocked). The security operations team (SOC) monitors these in real time. Monthly, the security team reports RASP block rates to engineering leadership as a measure of active attack volume against production. A developer whose feature is consistently triggering RASP rules receives a notification from AppSec — either their code has a genuine vulnerability that an attacker is probing, or the RASP rule needs tuning for their legitimate use case.

---

## Tools Covered

| Tool | Type | Account | Port |
|------|------|---------|------|
| rasp-hook.js | Custom RASP | None | 3002 |
| @contrast/rasp-v3 | OSS alpha RASP | None | 3003 |
| appsensor-hook.js | Escalating response | None | 3004 |
| dd-trace + libddwaf | Commercial RASP-as-a-service | Optional (dashboard only) | 3005 |
| Signal Sciences | Hybrid WAF/RASP sidecar | Enterprise license | 3006 |

## Files

```
module-4.6-rasp/
├── docker-compose.yml           ← All 5 variants (ports 3002–3006)
├── Dockerfile                   ← 4.6.1/4.6.2 (openrasp profile)
├── rasp-hook.js                 ← Custom RASP: patches sqlite3 + Sequelize
├── Dockerfile.contrast          ← 4.6.3 (contrast-rasp profile)
├── contrast-rasp-loader.mjs     ← ESM loader for @contrast/rasp-v3
├── Dockerfile.appsensor         ← 4.6.4 (appsensor profile)
├── appsensor-hook.js            ← AppSensor: LOG→WARN(429)→BLOCK(403) per IP
├── Dockerfile.datadog           ← 4.6.5 (datadog-asm profile)
├── datadog-rasp-wrapper.js      ← dd-trace init with appsec.enabled=true
├── dd-blocking-rules.json       ← Custom WAF rules with on_match:block
├── sigsci-middleware-example.js ← 4.6.6: architecture reference
└── run-exercises.sh             ← Builds + tests 4.6.3, 4.6.4, 4.6.5
```

## Prerequisites

- Docker Desktop running
- Juice Shop on port 3000 (baseline)

## Exercise Status

| # | Exercise | Tool | Status |
|---|----------|------|--------|
| 4.6.1 | Deploy custom RASP in Juice Shop via Docker | rasp-hook.js | ✅ Working |
| 4.6.2 | Verify SQLi blocked at runtime (not HTTP layer) | rasp-hook.js | ✅ Working |
| 4.6.3 | Deploy Contrast RASP v3 | @contrast/rasp-v3 | ❌ Incompatible — see note |
| 4.6.4 | AppSensor escalating response (LOG→WARN→BLOCK) | appsensor-hook.js | ✅ Working |
| 4.6.5 | Deploy Datadog ASM | dd-trace v4 + libddwaf | ✅ Working — 403 confirmed |
| 4.6.6 | Signal Sciences architecture study | sigsci-middleware-example.js | ✅ Architecture reviewed |

---

## 4.6.1 — Deploy Custom RASP (Docker)

```bash
docker compose --profile openrasp build
docker compose --profile openrasp up -d
sleep 20
docker compose logs juice-shop-rasp | grep -i rasp
```

**Expected startup log:**
```
[RASP] Agent initialized — hooks: SQLi (sqlite3 + Sequelize), XSS response scan
[RASP] sqlite3 hooks active — SQLi detection enabled
info: Server listening on port 3000
```

---

## 4.6.2 — Verify SQLi Blocked at Runtime

| Payload | Port 3000 (direct) | Port 3002 (RASP) |
|---------|-------------------|-----------------|
| `' OR 1=1--` | 200 + auth bypass | **403** |
| `test UNION SELECT 1,2,3--` | 200 + data | **403** |
| `apple` | 200 OK | 200 OK |

```bash
curl -s -o /dev/null -w "direct:  %{http_code}\n" "http://localhost:3000/rest/products/search?q=%27+OR+1%3D1--"
curl -s -o /dev/null -w "RASP:    %{http_code}\n" "http://localhost:3002/rest/products/search?q=%27+OR+1%3D1--"
docker compose logs juice-shop-rasp | grep "BLOCKED"
```

**BLOCKED log evidence:**
```
[RASP] BLOCKED — SQL Injection (Sequelize) detected | evidence: SELECT * FROM Products WHERE ((name LIKE '%' OR 1=1--%' ...
```

The hook intercepts at the Sequelize `.query()` call — the DB driver never receives the malicious query.

---

## 4.6.3 — Contrast RASP v3 ❌ INCOMPATIBLE

**Do not run.** `@contrast/rasp-v3@0.7.0-alpha.5` is incompatible with Apple Silicon (ARM64) + Node.js v24.

**Root cause — three failures, one unfixable:**

| # | Error | Fix |
|---|-------|-----|
| 1 | `require() on ESM graph with top-level await` | `--import file:///loader.mjs` instead of `--require` ✅ |
| 2 | `familySync is not a function` (detect-libc v2 removed sync API) | `Module._load` monkey-patch to inject `familySync` shim ✅ |
| 3 | `Cannot find module 'fireball-node.linux-arm64-gnu.node'` | **No fix** — prebuilt binary for ARM64 + Node.js v24 does not exist in this alpha ❌ |

Production alternative: `@contrast/agent` (commercial, full ARM64 support).

---

## 4.6.4 — AppSensor Escalating Response ✅

**Detection points:**

| DP | Detects | Hook |
|----|---------|------|
| IE1 | SQLi in URL query string | http.Server emit |
| IE2 | SQLi reaching sqlite3/Sequelize | Module._load patch |
| ACE1 | Force-browse to admin/config/git paths | http.Server emit |
| RE1 | Query string > 512 chars | http.Server emit |

**Response thresholds (per IP, tunable):**

| Count | Action | Status |
|-------|--------|--------|
| 1–2 | LOG — passes through | 200 |
| 3–4 | WARN | 429 |
| 5+ | BLOCK | 403 |

```bash
docker compose --profile appsensor build
docker compose --profile appsensor up -d
sleep 20

for i in {1..6}; do
  echo -n "Hit $i: "
  curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:3004/rest/products/search?q=%27+OR+1%3D1--"
  echo
done
```

**Confirmed output:** Hit 1: 500 | Hit 2: 429 | Hit 3: 429 | Hit 4: 429 | Hit 5: 403 | Hit 6: 403

- Hit 1 returns 500 (not 200): AppSensor passes the request through correctly; Juice Shop's SQLite throws on the malicious query. Expected.
- WARN starts at hit 2 (not hit 3): Juice Shop's search runs multiple DB queries per HTTP request; IE2 increments the counter for each. Real-world tuning issue.

```bash
docker compose logs -f juice-shop-appsensor | grep AppSensor
```

---

## 4.6.5 — Datadog ASM ✅

**Blocking works locally without a Datadog account.** `DD_API_KEY` is only needed for the cloud dashboard.

```bash
docker compose --profile datadog-asm build
docker compose --profile datadog-asm up -d
sleep 25
```

**Test blocking:**
```bash
curl -s -o /dev/null -w "SQLi:  %{http_code}\n" \
  "http://localhost:3005/rest/products/search?q=%27+OR+1%3D1--"
# → 403

curl -s -o /dev/null -w "XSS:   %{http_code}\n" \
  "http://localhost:3005/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
# → 403

curl -s -o /dev/null -w "LFI:   %{http_code}\n" \
  "http://localhost:3005/rest/products/search?q=..%2F..%2Fetc%2Fpasswd"
# → 403

curl -s -o /dev/null -w "clean: %{http_code}\n" \
  "http://localhost:3005/rest/products/search?q=apple"
# → 200
```

**Optional — connect Datadog dashboard:**
```bash
echo "DD_API_KEY=your_key_here" >> .env
docker compose --profile datadog-asm up -d
# View attacks: https://app.datadoghq.com/security/appsec
```

---

## 4.6.6 — Signal Sciences (Architecture Study)

Enterprise license required — no free tier. Read `sigsci-middleware-example.js` for the architecture.

**Sidecar model:**
```
┌──────────────────────┐   ① request metadata   ┌─────────────────────┐
│  Node.js App          │ ───────────────────→   │  sigsci-agent       │
│  (Express middleware) │ ←───────────────────   │  (local daemon :9999)│
└──────────────────────┘   ② allow / block       └──────────┬──────────┘
                                                             │ ③ telemetry
                                                             ▼
                                                  Signal Sciences Cloud
```

**All tools compared:**

| Property | rasp-hook.js | Contrast RASP v3 | AppSensor | Datadog ASM | Signal Sciences |
|---|---|---|---|---|---|
| Position | In-process | In-process | In-process | In-process | In-process + sidecar |
| Blocking | Synchronous | Synchronous | Synchronous | Synchronous | Agent daemon |
| Block latency | 0 ms | 0 ms | 0 ms | 0 ms | ~0.1–1 ms |
| Data access | SQL level | SQL level | HTTP + SQL | HTTP + SQL | HTTP metadata |
| Crash isolation | No | No | No | No | Yes |
| Ruleset | Custom (SQLi) | OSS alpha | Custom thresholds | libddwaf OWASP CRS | SigSci cloud |
| Account | None | None | None | Optional | Required |
| Cost | Free | Free | Free | Free | Enterprise |

---

## Roadblocks & Fixes

| Error | Root Cause | Fix |
|-------|-----------|-----|
| `exec: "sh": not found` | Distroless has no shell | Multi-stage build |
| `EACCES: permission denied` on wrapper file | Container uid 65532 can't read root-owned files | `COPY --chmod=644` in Dockerfile |
| `docker cp` → `EACCES` | Copies as root into distroless | Rebuild — don't use `docker cp` |
| RASP blocks Juice Shop startup (CREATE TABLE) | Sequelize runs DDL on boot | `isDdl()` guard |
| Broad LIKE pattern blocks internal queries | Pattern too wide | `/LIKE\s+'%'[^%']/i` — only fires when `'` follows opening `%` |
| Contrast: `require() on ESM graph` | `@contrast/rasp-v3` is ESM; `--require` can't load it | `--import file:///loader.mjs` |
| Contrast: `Cannot find module '@contrast/require-hook'` | Only `@contrast/` scope copied | Copy full `node_modules`, add `NODE_PATH` |
| Contrast: `familySync is not a function` | detect-libc v2 removed sync API | `Module._load` patch to inject `familySync` shim |
| Contrast: libc mismatch | Alpine builder = musl; Juice Shop = glibc | Builder: `node:24-slim` (Debian) |
| Contrast: `fireball-node.linux-arm64-gnu.node` missing | No ARM64 + Node.js v24 prebuilt in alpha | No fix — incompatible |
| Datadog: `Cannot find module 'dc-polyfill'` | dd-trace in non-standard path | `NODE_PATH="/juice-shop/dd_modules"` |
| Datadog: v5 returns 500 | v5 rules require connected agent | Pin to `dd-trace@4` |
| Datadog: libddwaf not loading (no `wafVersion`) | `detect-libc` not installed; `node-gyp-build` falls back to `linux-arm64` path, binary is at `linuxglibc-arm64/` | `npm install dd-trace@4 detect-libc@1` |
| Datadog: WAF detects but doesn't block | dd-trace v4 default rules in monitoring mode (`on_match: []`) | `dd-blocking-rules.json` with `on_match: [block]`; `DD_APPSEC_RULES` |
| Signal Sciences | Enterprise license required | Architecture study only |
