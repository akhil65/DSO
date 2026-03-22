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

## Real-World Context

APIs are the dominant attack surface in modern applications — the OWASP API Security Top 10 exists separately from the Web Top 10 precisely because APIs fail in distinctive ways that general web scanners miss. Object-level authorisation issues (BOLA/IDOR), mass assignment, and excessive data exposure are architectural problems in API design, not code bugs, which means they often survive SAST and DAST scans entirely. Catching them requires understanding the API's intended behaviour and testing whether enforcement holds up under manipulation.

**Who owns this in a real org:** API security testing is a shared responsibility between AppSec and backend engineering. During design, AppSec participates in API threat modelling — reviewing the OpenAPI spec for endpoints that expose sensitive object IDs, operations that accept more fields than they should, or responses that return more data than the client needs. In testing, AppSec or a red team runs authenticated scanning with the OpenAPI spec in ZAP and performs manual BOLA testing using Burp Suite, verifying whether user A can access user B's resources by manipulating object IDs. Shadow API discovery (kiterunner) is used to find endpoints the team doesn't know they're exposing — undocumented routes that bypass authentication are a consistent finding in mature organisations.

**Dev → Staging → Production:** API security gates in CI/CD focus on spec compliance — automated checks verify that the implementation matches the OpenAPI spec and flag undocumented endpoints. In staging, the full authenticated API scan runs after each deployment. In production, an API gateway (Kong, AWS API Gateway, Apigee) enforces authentication, rate limiting, and request validation as a first line of defence — but gateway-level enforcement does not replace application-level authorisation logic, which is the more common failure point. Bug bounty programmes consistently surface BOLA issues because they require authenticated, human-driven testing at a depth that automated tools rarely reach.

**How findings reach stakeholders:** A confirmed BOLA finding — where user A can read user B's data by changing a number in a URL — is not a sprint backlog ticket. It triggers an incident response decision: is data already exfiltrated, does the product need to be taken offline while a fix is deployed, and is there a breach notification obligation? Less severe findings (excessive data exposure, missing rate limits, mass assignment) feed into the normal security backlog. The structured findings report produced in this module is the format AppSec teams use to brief engineering and product leadership on API risk posture ahead of a launch or after a penetration test.

---

## Tools

| Tool | Role | Install |
|------|------|---------|
| **crAPI** | Vulnerable target — REST + GraphQL API | `docker compose up` |
| **OWASP ZAP (GUI)** | Spider/crawl scan — Phase 1 manual testing | Already installed |
| **OWASP ZAP (API scan)** | OpenAPI spec-driven automated scan — Phase 2 | Docker: `ghcr.io/zaproxy/zaproxy:stable` |
| **kiterunner** | API route discovery / endpoint enumeration | Build from source: `go build ./cmd/kiterunner/` |
| **Burp Suite CE** | Manual request manipulation, BOLA testing | Already installed |
| **jwt_tool** | JWT decode, algorithm confusion, none-attack | Clone: `github.com/ticarpi/jwt_tool` |
| **vAPI** | Additional vulnerable API target (bonus) | `git clone github.com/roottusk/vapi` |

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

## Results

### Phase 1 — Manual Testing (crAPI, curl + ZAP GUI)

| Exercise | Finding | Status |
|----------|---------|--------|
| crAPI deployed | 10 containers running — REST, community, workshop, mailhog | ✅ Confirmed |
| BOLA | User 2 token accessed User 1 vehicle GPS via UUID swap | ✅ Confirmed |
| OTP brute-force | Account takeover via unprotected `/v2/` endpoint — no rate limit | ✅ Confirmed |
| JWT alg:none bypass | Forged unsigned token accepted — user profile data returned | ✅ Confirmed |
| Excessive data exposure | Community posts leak email + vehicleid for all users | ✅ Confirmed |
| Attack chain | Data exposure → BOLA → JWT forgery → account takeover | ✅ Confirmed |
| ZAP GUI spider scan | Crawl-based scan against crAPI REST surface | ✅ Confirmed |

### Phase 2 — Tool Revisit (2026-03-17)

| Tool | Exercise | Finding | Status |
|------|----------|---------|--------|
| jwt_tool | RS256 token decode | Token uses RS256; claims: `sub`, `iat`, `exp`, `role:user` | ✅ Confirmed |
| jwt_tool | alg:none attack | **CRITICAL** — unsigned forged token accepted, HTTP 200 + full user profile returned | ✅ Confirmed |
| kiterunner | Endpoint discovery — crAPI root | 0 endpoints discovered (wordlist: 7,615 routes) | ✅ Run — 0 hits |
| kiterunner | Endpoint discovery — `/identity` | 0 endpoints discovered (91,380 probes) | ✅ Run — 0 hits |
| kiterunner | Endpoint discovery — `/community` | 0 endpoints discovered (91,380 probes) | ✅ Run — 0 hits |
| ZAP API scan | OpenAPI spec-driven scan | Blocked — crAPI does not expose spec via HTTP (all common endpoints return 404/401) | ⚠️ Not completed |
| vAPI | Additional vulnerable target | Started on port 8000; upstream migration bug (PHP 7.4/MySQL 8 incompatibility in flags seeder) — excluded from testing | ⚠️ Setup failed |

### Key Phase 2 Finding: kiterunner 0-hit Analysis

kiterunner found 0 endpoints across all three scans. **This does not mean crAPI has no vulnerabilities** — Phase 1 and jwt_tool confirmed multiple critical issues. It means:

- crAPI's paths (`/identity/api/v2/user/dashboard`, `/community/api/v2/community/posts/{id}`) do not match generic wordlist patterns
- Wordlist-based endpoint discovery fails against non-standard path hierarchies
- Real vulnerabilities (alg:none, BOLA, OTP brute-force) require logic testing, not path enumeration
- Non-standard paths are security through obscurity — not a genuine defence

### Reports

- Phase 1 report: `docs/Module-3.5-API-Security-Report.docx` — manual curl findings
- Phase 2 findings: captured in this README and lab walkthrough
