# Module 5 — CI/CD Pipeline Security (GitHub Actions)

## Overview

Secure the software supply chain by embedding security gates directly into the GitHub Actions CI/CD pipeline. Every pull request and push automatically triggers SAST, dependency scanning, container image scanning, and secrets detection — shifting security left so vulnerabilities are caught before they reach production.

**Platform:** GitHub Actions (free tier)
**Target repo:** `devsecops-lab` (your fork)

## Architecture

```
Developer push / PR
        │
        ▼
┌─────────────────────────────────┐
│        GitHub Actions CI        │
│                                 │
│  ① Secrets scan  (Gitleaks)    │
│  ② SAST         (Semgrep)      │
│  ③ Dependency   (Trivy SCA)    │
│  ④ Container    (Trivy image)  │
│  ⑤ DAST smoke   (ZAP baseline) │
└─────────────────────────────────┘
        │
        ▼ Fail-fast on HIGH+CRITICAL
   PR blocked / merge allowed
```

## Prerequisites

- Modules 1–4 complete
- GitHub repo with Actions enabled
- Docker Hub or GHCR account (for container image push step)

## Tools Used

| Tool | Purpose | Free? |
|------|---------|-------|
| Gitleaks | Secrets detection in git history and staged files | ✅ Open source |
| Semgrep (OSS) | SAST — same rules as Module 2 | ✅ Open source |
| Trivy | SCA (dependencies) + container image scanning | ✅ Open source |
| OWASP ZAP baseline | DAST passive scan in pipeline | ✅ Open source |
| GitHub Actions | CI/CD orchestration | ✅ Free tier |

## Exercises

| # | Exercise | Tool | Status |
|---|----------|------|--------|
| 5.1 | Add Gitleaks secrets-scan job to CI workflow | Gitleaks | 🔲 Pending |
| 5.2 | Add Semgrep SAST job — fail on HIGH+ findings | Semgrep | 🔲 Pending |
| 5.3 | Add Trivy SCA job — scan package.json dependencies | Trivy | 🔲 Pending |
| 5.4 | Add Trivy container image scan after docker build | Trivy | 🔲 Pending |
| 5.5 | Add ZAP baseline DAST job against staging | ZAP | 🔲 Pending |
| 5.6 | Gate merge on all security jobs passing | Actions branch protection | 🔲 Pending |

## Exercise 5.1 — Gitleaks Secrets Scan

Create `.github/workflows/security.yml`:

```yaml
name: Security Pipeline

on:
  push:
    branches: [main, dev]
  pull_request:
    branches: [main]

jobs:
  secrets-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history for Gitleaks
      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Exercise 5.2 — Semgrep SAST

```yaml
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Semgrep SAST
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/javascript
            p/nodejs
            p/owasp-top-ten
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}
```

> **Note:** Create a free account at semgrep.dev to get an app token. The OSS rules run without a token but won't upload results to the dashboard.

## Exercise 5.3 — Trivy SCA (Dependencies)

```yaml
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Trivy SCA — package.json
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          scan-ref: .
          severity: HIGH,CRITICAL
          exit-code: 1
```

## Exercise 5.4 — Trivy Container Image Scan

```yaml
  image-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t juice-shop:ci .
      - name: Trivy image scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: juice-shop:ci
          severity: CRITICAL
          exit-code: 1
```

## Exercise 5.5 — ZAP Baseline DAST

```yaml
  dast-baseline:
    runs-on: ubuntu-latest
    steps:
      - name: Start Juice Shop
        run: docker run -d -p 3000:3000 bkimminich/juice-shop
      - name: Wait for app
        run: sleep 15
      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.10.0
        with:
          target: http://localhost:3000
          fail_action: false   # passive scan only — don't fail pipeline
```

## Exercise 5.6 — Branch Protection Gate

In GitHub: **Settings → Branches → Add rule → main**

- ✅ Require status checks to pass before merging
- Add: `secrets-scan`, `sast`, `dependency-scan`, `image-scan`
- ✅ Require branches to be up to date

## Key Concepts

- **Shift-left security** — finding vulnerabilities at PR time is far cheaper to fix than post-production
- **Fail-fast on CRITICAL** — `exit-code: 1` causes the job to fail and blocks the merge; HIGH severity is configurable
- **Secrets in git history** — Gitleaks `fetch-depth: 0` scans all commits, not just the latest push
- **SCA vs image scan** — SCA scans declared dependencies (package.json); image scan also catches OS-level packages inside the Docker layer
- **Passive ZAP in CI** — Active scan takes 15+ minutes and sends attack payloads; passive baseline is safe for any target and completes in ~2 minutes

## Roadblocks & Fixes

| Roadblock | Fix |
|-----------|-----|
| Semgrep action rate-limits without token | Create free semgrep.dev account, add `SEMGREP_APP_TOKEN` to repo secrets |
| Trivy `exit-code: 1` blocks all PRs on day 1 | Start with `exit-code: 0` (audit mode); tighten to 1 once backlog is triaged |
| ZAP action fails with "no rules file" | Use `zaproxy/action-baseline@v0.10.0` not the raw Docker run command |
| Docker layer cache misses slow CI | Add `cache-from: type=gha` to docker/build-push-action |

## Reports

Report generated at module completion — `docs/Module-5-Pipeline-Report.docx`
