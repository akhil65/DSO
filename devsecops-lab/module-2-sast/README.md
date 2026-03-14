# Module 2 — Static Analysis (SAST & SCA)

## Overview
In this module you manually run four security scanning tools against a
deliberately vulnerable Python application, learn to read their output,
then wire them into the CI/CD pipeline.

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
