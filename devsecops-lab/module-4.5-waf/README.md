# Module 4.5 — Web Application Firewall (WAF)

## Overview

Deploy OWASP ModSecurity CRS as a WAF reverse proxy in front of Juice Shop and verify it blocks the SQL injection and XSS attacks from Module 4.

**Tool:** OWASP ModSecurity CRS v3.3.8 + nginx (Docker)
**Target:** OWASP Juice Shop (localhost:3000)
**WAF port:** localhost:3001

---

## Real-World Context

A WAF is a production defence control, not a development or testing tool. It sits at the network edge — in front of the load balancer, or as a cloud-native service like AWS WAF, Cloudflare WAF, or Azure Front Door — and inspects every inbound HTTP request before it reaches the application. The ModSecurity CRS deployed in this module is the open-source foundation that many commercial WAF products build on top of. In a real organisation, the WAF is deployed and managed by the platform or security engineering team, not by individual application developers.

**Who owns this in a real org:** The security engineering or platform team owns WAF configuration. They maintain the rule set, tune false positive thresholds (blocking a legitimate request is a business impact, not just a security event), and review WAF logs for attack trends. AppSec defines which OWASP CRS rule groups are enabled and at what paranoia level — higher paranoia catches more attacks but also blocks more legitimate traffic. When developers deploy a new API endpoint or change request formats, they test it against the WAF-enabled staging environment to identify false positives before production. A common failure mode in organisations is that developers test against a WAF-bypassed environment and then discover in production that their legitimate request is being blocked.

**Dev → Staging → Production:** Developers are generally unaware of the WAF in development — they test directly against the application. In staging, the WAF is active and mirrors the production rule set exactly. Any new feature that involves unusual HTTP patterns (large request bodies, non-standard headers, binary payloads) must be validated against the staging WAF before release. In production, the WAF runs in blocking mode with real-time logging to the SIEM. WAF block events feed into the SOC's threat detection workflow — a spike in blocked SQLi attempts from a single IP may be automated scanning or a targeted attack, and the SOC decides whether to escalate.

**How tools integrate with the developer pipeline:** The WAF itself is not wired into the developer's commit pipeline — it is infrastructure. But it has two important integration points: the staging environment gate (developers must test against the WAF before releasing) and the false-positive tuning workflow (developers and AppSec collaborate to ensure legitimate traffic isn't blocked). Here is what the WAF lifecycle looks like in a real org:

```bash
# Platform team: deploy WAF in front of staging (mirrors prod rule set exactly)
# In docker-compose.yml or Kubernetes ingress — WAF sits on :443/:80,
# proxies to the application on its internal port

# ModSecurity CRS paranoia levels (set in modsecurity.conf):
#   PL1 = default, low false positives, catches most common attacks
#   PL2 = more rules, may block some unusual-but-legitimate requests
#   PL3 = aggressive, requires significant false-positive tuning
#   PL4 = maximum, typically only used for high-value targets with dedicated tuning

# Before a release: run regression tests against WAF-enabled staging
# Any test that passes without WAF but fails with it = potential false positive
pytest tests/integration/ --base-url=https://staging-waf.yourapp.com -v

# Validate that known attacks are blocked (security smoke test)
# These should all return HTTP 403:
curl -si "https://staging-waf.yourapp.com/search?q=<script>alert(1)</script>" | head -1
curl -si "https://staging-waf.yourapp.com/api/users?id=1%20UNION%20SELECT%201--" | head -1

# Read ModSecurity audit log to diagnose a false positive
tail -100 /var/log/nginx/modsec_audit.log | grep "id\|uri\|msg"
# Output shows which rule ID triggered — AppSec then decides to tune PL or add exclusion

# Add a rule exclusion for a false positive (modsecurity.conf or .conf.d/exclusions.conf):
# SecRuleRemoveById 942100   ← disable SQLi detection rule for a specific endpoint
# SecRuleUpdateTargetById 942100 "!ARGS:search_query"  ← exclude one parameter
```

The CRS paranoia level is the key tuning decision: start at PL1 in detection mode, run for two weeks in staging watching for false positives, raise to PL2 if the false positive rate is acceptable. Moving straight to PL3 in production on day one is a reliable way to block real users and get the WAF turned off by the product team. The tuning workflow — not the initial deployment — is where most of the AppSec time is spent.

**How findings reach stakeholders:** The WAF is a production control, so its primary output is operational rather than a findings report in the pentest sense. WAF logs are aggregated in the SIEM (Splunk, Datadog, Elastic Security) and dashboards show attack volume, blocked vs. passed requests, and top attack categories by month. The security team presents these trends to the CISO as evidence that the perimeter defence is functioning. When a WAF bypass is discovered — either by the red team or through a production incident — the response is a rule update and a root-cause analysis of why the existing rule set didn't catch it.

**Lab vs real world:** In this module you stand up the WAF with a single Docker command and immediately test it with attack payloads. In a real org the initial deploy is the easy part — the hard part is two to four weeks of false-positive tuning before you can switch from detection to blocking mode without affecting real users. The paranoia level, exclusion rules, and detection-vs-blocking mode switch are the decisions that take time; the Docker configuration itself is nearly identical to what you do here.

---

## Architecture

```
Browser → localhost:3001 (ModSecurity WAF) → localhost:3000 (Juice Shop)
```

## Prerequisites

- Module 4 complete (attacks confirmed working on port 3000)
- Docker Desktop running
- Juice Shop container running on port 3000

## Setup

```bash
cd module-4.5-waf
docker compose up -d
docker compose ps
```

Verify WAF is proxying Juice Shop:

```bash
curl -s http://localhost:3001 | head -5
```

## Exercises

| # | Exercise | Status |
|---|----------|--------|
| 4.5.1 | Deploy ModSecurity WAF via Docker | ✅ Complete |
| 4.5.2 | Test SQLi blocking (UNION SELECT) | ✅ Complete |
| 4.5.3 | Test XSS blocking (<script> + URL-encoded) | ✅ Complete |
| 4.5.4 | Read and interpret WAF block logs | ✅ Complete |

## Key Results

| Attack | Direct (3000) | Via WAF (3001) | CRS Rules |
|--------|--------------|----------------|-----------|
| SQLi UNION SELECT | 200 OK | **403 Blocked** | 942100, 942190, 942270 (score: 15) |
| XSS `<script>` | 201 OK | **403 Blocked** | 941100, 941160 |
| XSS URL-encoded | 201 OK | **403 Blocked** | 941100 (decoded then matched) |
| IDOR basket access | 200 OK | 200 OK | Not blocked — logic flaw, not payload |

## Key Concepts

- **WAF** sits outside the app as a reverse proxy — inspects raw HTTP traffic
- **Anomaly scoring** — each matched rule adds points; block when total >= threshold (default: 5)
- **Paranoia level 1** — balanced false positive/negative rate; catches known patterns
- **IDOR cannot be blocked by WAF** — it is a business logic flaw requiring server-side auth checks
- **WAF ≠ RASP** — see Module 4.6 for runtime protection from inside the app

## Read WAF Logs

```bash
docker compose logs waf --tail=20
```

## Report

See `docs/Module-4.5-WAF-RASP-Report.docx`
