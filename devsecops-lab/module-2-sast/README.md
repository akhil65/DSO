# Module 2 — Static Analysis (SAST & SCA)

## Overview
In this module you manually run four security scanning tools against a
deliberately vulnerable Python application, learn to read their output,
then wire them into the CI/CD pipeline.

---

## Real-World Context

SAST and SCA are the first security controls most organisations deploy because they require no running infrastructure — they analyse source code and dependency manifests directly. In practice, developers rarely run these tools manually. They are wired into the CI/CD pipeline so that every pull request automatically triggers a scan, and findings surface as PR annotations or a failed check before the code is even reviewed by a human. The manual runs in this module teach you what the tools actually do; the pipeline integration in Module 5 is how they are used day-to-day.

**Who owns this in a real org:** The AppSec team defines which rules are enabled, what severity threshold blocks a merge (typically Critical and High), and maintains the rule configuration in version control alongside the pipeline definition. Developers own remediation — they receive a finding on their PR, fix the code, and re-push. The AppSec team triages false positives, suppresses specific findings with justification, and reviews the overall trend across the codebase using dashboards like SonarCloud or the GitHub Security tab. SCA findings (vulnerable dependencies) are often handled separately by a platform or dependencies team that tracks CVEs across the entire organisation's software bill of materials (SBOM).

**Dev → Staging → Production:** In development, engineers can run Bandit or Semgrep locally via IDE plugins (VS Code has native Semgrep and Bandit extensions) to catch issues before they commit. In the CI pipeline (staging gate), SAST runs on every push and PR — a Critical finding blocks the merge. Production deployments inherit the clean bill of health from CI; nothing that failed a security gate reaches production. SCA tooling like Trivy and OSV Scanner also run continuously in production environments to catch newly disclosed CVEs in dependencies that were safe at build time.

**How findings reach stakeholders:** A developer sees a Bandit `B608: SQL injection` finding as a failed GitHub check with a direct link to the vulnerable line. An engineering manager sees a SonarCloud quality gate dashboard showing the team's security debt trend over sprints. A CISO sees a monthly report on critical vulnerability count, mean time to remediation, and which teams are consistently introducing security issues. The tooling is the same at every level — what changes is the aggregation and the audience.

---

## Tools

| Tool | Type | Install |
|------|------|---------|
| Bandit | SAST — Python | `pip install bandit` |
| Semgrep | SAST — multi-language | `brew install semgrep` |
| Trivy | SCA — containers + deps | `brew install aquasecurity/trivy/trivy` |
| OSV Scanner | SCA — Google CVE DB | `brew install osv-scanner` |

---

## Step 1 — Install tools

```bash
pip install bandit
brew install semgrep
brew install aquasecurity/trivy/trivy
brew install osv-scanner
```

---

## Step 2 — Run Bandit (Python SAST)

```bash
cd module-2-sast/sample-vulnerable-app

# Basic scan — see findings immediately
bandit app.py

# Full recursive scan — save report
bandit -r . -f txt -o bandit-report.txt
```

---

## Step 3 — Run Semgrep (multi-language SAST)

```bash
cd module-2-sast/sample-vulnerable-app

# Scan with OWASP Top 10 rules
semgrep --config p/owasp-top-ten .

# Scan with Python-specific rules
semgrep --config p/python .
```

---

## Step 4 — Run Trivy (container + dependency SCA)

```bash
# Scan our vulnerable requirements.txt
trivy fs --scanners vuln module-2-sast/sample-vulnerable-app/

# Scan the live Juice Shop Docker image
trivy image bkimminich/juice-shop:latest
```

---

## Step 5 — Run OSV Scanner (Google)

```bash
osv-scanner --lockfile module-2-sast/sample-vulnerable-app/requirements.txt
```

---

## Step 6 — Commit and push

```bash
git add module-2-sast/
git commit -m "feat(module-2): add vulnerable sample app and SAST/SCA scan reports"
git push origin main
```
