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

**How findings reach stakeholders:** The WAF is a production control, so its primary output is operational rather than a findings report in the pentest sense. WAF logs are aggregated in the SIEM (Splunk, Datadog, Elastic Security) and dashboards show attack volume, blocked vs. passed requests, and top attack categories by month. The security team presents these trends to the CISO as evidence that the perimeter defence is functioning. When a WAF bypass is discovered — either by the red team or through a production incident — the response is a rule update and a root-cause analysis of why the existing rule set didn't catch it.

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
