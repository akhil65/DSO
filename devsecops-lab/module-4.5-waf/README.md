# Module 4.5 — Web Application Firewall (WAF)

## Overview

Deploy OWASP ModSecurity CRS as a WAF reverse proxy in front of Juice Shop and verify it blocks the SQL injection and XSS attacks from Module 4.

**Tool:** OWASP ModSecurity CRS v3.3.8 + nginx (Docker)
**Target:** OWASP Juice Shop (localhost:3000)
**WAF port:** localhost:3001

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
