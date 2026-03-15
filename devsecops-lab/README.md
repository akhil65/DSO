# DevSecOps & AI Security Lab

> A hands-on, end-to-end DevSecOps pipeline and vulnerable lab environment built entirely with free and open-source tools. Every module is tracked here as we build it.

---

## Curriculum

| Module | Topic | Status |
|--------|-------|--------|
| [Module 1](./module-1-infrastructure/) | Infrastructure & Lab Setup (Docker, Juice Shop, DVWA) | ✅ Complete |
| [Module 2](./module-2-sast/) | Static Analysis — SAST & SCA (Bandit, Semgrep, Trivy, OSV Scanner) | ✅ Complete |
| [Module 3](./module-3-dast/) | Dynamic Analysis — DAST (OWASP ZAP, headless CI) | ✅ Complete |
| [Module 3.5](./module-3.5-api-security/) | API Security — OWASP API Top 10 (crAPI, ZAP, kiterunner) | ✅ Complete |
| [Module 4](./module-4-pentesting/) | Manual Pentesting (Burp Suite, SQLi, XSS, CSRF) | ✅ In Progress |
| [Module 4.5](./module-4.5-rasp/) | RASP — Runtime Application Self-Protection (OpenRASP on Juice Shop) | 🔒 Locked |
| [Module 5](./module-5-pipeline/) | CI/CD Pipeline Automation (GitHub Actions / GitLab CI) | 🔒 Locked |
| [Module 6](./module-6-ai-security/) | AI Application Security & MLSecOps (Prompt Injection, STRIDE-GPT) | 🔒 Locked |
| [Module 7](./module-7-mobile/) | Mobile AppSec — Android Static & Dynamic Analysis (MobSF, Frida, DIVA) | 🔒 Locked |

---

## Tech Stack

**Vulnerable Targets:** OWASP Juice Shop · DVWA · crAPI · DIVA (Android) · OWASP LLM Goat
**Environment:** Docker · VirtualBox/VMware · Android Studio Emulator
**SAST:** CodeQL · Semgrep · Bandit · MobSF (mobile static)
**SCA:** OWASP Dependency-Check · Trivy · OSV Scanner
**DAST:** OWASP ZAP · Burp Suite CE · Kiterunner · Nmap · Metasploit
**API Security:** ZAP + OpenAPI · crAPI · OWASP API Top 10
**RASP:** OpenRASP (Node.js agent on Juice Shop)
**Mobile:** MobSF · Frida · Objection · OWASP MASTG
**AI Security:** STRIDE-GPT · Prompt Injection · OWASP LLM Top 10

---

## Getting Started

```bash
git clone https://github.com/akhil65/DSO.git
cd DSO/module-1-infrastructure
docker compose up -d
```

See [Module 1 README](./module-1-infrastructure/README.md) for full setup instructions.

---

## Docs & Walkthroughs

Detailed guides for each module live in the [`docs/`](./docs/) folder.

---

## Progress Log

| Date | Module | Milestone |
|------|--------|-----------|
| 2026-03-13 | Module 1 | Lab infrastructure provisioned — Juice Shop + DVWA |
| 2026-03-13 | Module 1 | First SQL injection executed — bypassed Juice Shop admin login |
| 2026-03-13 | Module 1 | DVWA configured at Low security, Portainer dashboard live |
| 2026-03-13 | Module 2 | Vulnerable Python app created — 10 deliberate vulnerabilities |
| 2026-03-13 | Module 2 | Bandit, Semgrep, Trivy, OSV Scanner added to CI pipeline |
| 2026-03-14 | Module 2 | Bandit scan — 29 Python findings across 9 vulnerability categories |
| 2026-03-14 | Module 2 | Semgrep scan — 43 findings (Python + JS), SSRF and XSS taint tracking |
| 2026-03-14 | Module 2 | Trivy scan — 136 CVEs + 4 secrets in requirements.txt and Juice Shop image |
| 2026-03-14 | Module 2 | OSV scan — 50 CVEs, 7 unique vs Trivy (wider PYSEC database coverage) |
| 2026-03-14 | Module 2 | 4 vulnerability reports generated: Bandit, Semgrep, Trivy, OSV |
| 2026-03-14 | Module 3 | DAST with OWASP ZAP — baseline + active scan against Juice Shop |
| 2026-03-14 | Module 3 | ZAP: 10 alerts — 1 HIGH (SQL Injection confirmed live), 4 Medium, 3 Low, 2 Info |
| 2026-03-14 | Module 3 | SQL Injection confirmed: HTTP 500 + SQLITE_ERROR on /rest/products/search |
| 2026-03-14 | Module 3 | ZAP DAST report generated — 7 sections, SAST+DAST comparison, remediation roadmap |
| 2026-03-15 | Module 3.5 | crAPI deployed — 10 containers, REST + community + workshop services |
| 2026-03-15 | Module 3.5 | BOLA confirmed: User 2 token accessed User 1 vehicle GPS via UUID swap |
| 2026-03-15 | Module 3.5 | OTP brute force: account takeover via unprotected v2 endpoint (no rate limit) |
| 2026-03-15 | Module 3.5 | JWT alg:none bypass: forged unsigned token accepted — admin@admin.com data returned |
| 2026-03-15 | Module 3.5 | Excessive data exposure: community posts leak email + vehicleid for all users |
| 2026-03-15 | Module 3.5 | Attack chain documented: data exposure → BOLA → JWT forgery → account takeover |

---

## License

MIT — for educational use only. Do not deploy vulnerable targets on public networks.
