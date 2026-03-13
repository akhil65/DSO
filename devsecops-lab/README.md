# DevSecOps & AI Security Lab

> A hands-on, end-to-end DevSecOps pipeline and vulnerable lab environment built entirely with free and open-source tools. Every module is tracked here as we build it.

---

## Curriculum

| Module | Topic | Status |
|--------|-------|--------|
| [Module 1](./module-1-infrastructure/) | Infrastructure & Lab Setup (Docker, Juice Shop, DVWA) | ✅ In Progress |
| [Module 2](./module-2-sast/) | Static Analysis — SAST & SCA (Bandit, Semgrep, Trivy) | 🔒 Locked |
| [Module 3](./module-3-dast/) | Dynamic Analysis — DAST (OWASP ZAP, headless CI) | 🔒 Locked |
| [Module 4](./module-4-pentesting/) | Manual Pentesting (Burp Suite, SQLi, XSS, CSRF) | 🔒 Locked |
| [Module 5](./module-5-pipeline/) | CI/CD Pipeline Automation (GitHub Actions / GitLab CI) | 🔒 Locked |
| [Module 6](./module-6-ai-security/) | AI Application Security & MLSecOps (Prompt Injection, STRIDE-GPT) | 🔒 Locked |

---

## Tech Stack

**Vulnerable Targets:** OWASP Juice Shop · DVWA · OWASP LLM Goat
**Environment:** Docker · VirtualBox/VMware
**SAST:** CodeQL · Semgrep · Bandit
**SCA:** OWASP Dependency-Check · Trivy
**DAST:** OWASP ZAP · Burp Suite CE · Nmap · Metasploit
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

---

## License

MIT — for educational use only. Do not deploy vulnerable targets on public networks.
