# Module 3.5 — API Security

> **OWASP API Security Top 10** — hands-on testing against crAPI (Completely Ridiculous API), a purpose-built vulnerable REST/GraphQL target.

---

## Objectives

- Understand the OWASP API Security Top 10 (2023 edition) and how it differs from the Web Top 10
- Set up and attack crAPI — a realistic e-commerce API with intentional vulnerabilities
- Use ZAP with an OpenAPI spec for automated API scanning
- Use kiterunner for API endpoint discovery / route brute-forcing
- Manually exploit Broken Object Level Authorisation (BOLA/IDOR), Mass Assignment, and Excessive Data Exposure
- Produce a structured API security findings report

---

## Tools

| Tool | Role | Install |
|------|------|---------|
| **crAPI** | Vulnerable target — REST + GraphQL API | `docker compose up` |
| **OWASP ZAP** | Automated API scan with OpenAPI spec | Already installed |
| **kiterunner** | API route discovery / endpoint enumeration | `brew install kiterunner` |
| **Burp Suite CE** | Manual request manipulation, BOLA testing | Already installed |
| **jwt_tool** | JWT decode, algorithm confusion, none-attack | `pip install jwt_tool` |

---

## Target: crAPI

crAPI (Completely Ridiculous API) is an OWASP-maintained intentionally vulnerable vehicle management API. It has:
- REST API (JSON)
- GraphQL endpoint
- SMTP mailhog for email flows
- Broken Object Level Auth, Mass Assignment, SSRF, JWT issues, and more

**Start crAPI:**
```bash
cd module-3.5-api-security
curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml
docker compose up -d
# crAPI UI:      http://localhost:8888
# crAPI API:     http://localhost:8888/identity/api/
# Mailhog:       http://localhost:8025
```

---

## OWASP API Security Top 10 (2023)

| # | Category | crAPI Exercise |
|---|----------|---------------|
| API1 | Broken Object Level Authorisation (BOLA) | Access other users' vehicle data by changing IDs |
| API2 | Broken Authentication | JWT none-algorithm attack; weak token validation |
| API3 | Broken Object Property Level Auth | Mass assignment — set `isAdmin: true` on registration |
| API4 | Unrestricted Resource Consumption | No rate limiting — brute-force OTP endpoint |
| API5 | Broken Function Level Authorisation | Access admin-only endpoints without admin role |
| API6 | Unrestricted Access to Sensitive Business Flows | Exploit coupon re-use; negative balance abuse |
| API7 | Server Side Request Forgery (SSRF) | Video upload URL parameter triggers internal request |
| API8 | Security Misconfiguration | Exposed Swagger UI, stack traces, verbose errors |
| API9 | Improper Inventory Management | Shadow/undocumented endpoints exposed |
| API10 | Unsafe Consumption of APIs | Third-party API data not validated before use |

---

## Progress

- [ ] crAPI running locally
- [ ] ZAP API scan with OpenAPI spec
- [ ] kiterunner endpoint discovery
- [ ] BOLA: access other users' vehicle/mechanic data
- [ ] Mass assignment: privilege escalation via registration payload
- [ ] OTP brute-force: no rate limiting
- [ ] JWT manipulation: algorithm confusion / none attack
- [ ] SSRF: video upload endpoint
- [ ] API security report generated
