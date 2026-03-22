# Module 5 — CI/CD Pipeline Security (GitHub Actions)

> Embed security gates directly into the CI/CD pipeline. Every push and PR automatically triggers secrets detection, SAST, SCA, IaC scanning, and Dockerfile linting — shifting security left so vulnerabilities are caught before they reach production.

---

## Objectives

- Understand the role of each security gate in a real CI/CD pipeline
- Add Gitleaks to detect secrets committed to git history
- Enable CodeQL for GitHub-native SAST across JavaScript and Python
- Configure SonarCloud for continuous code quality and vulnerability gates
- Add Checkov to scan Dockerfiles and docker-compose for misconfigurations
- Add Hadolint to enforce Dockerfile best practices
- Trigger a ZAP DAST baseline scan against Juice Shop on-demand

---

## Real-World Context

Module 5 is the connective tissue of the entire lab — it is where all the individual tools from Modules 2, 3, and 4 stop being things you run manually and become automated gates that run on every commit without anyone having to remember to invoke them. This is what "shifting security left" actually means in practice: the security check happens at the earliest possible point where it can catch the problem — on the developer's PR, before a human reviewer even looks at the code, and certainly before it reaches production.

**Who owns this in a real org:** The AppSec team owns the pipeline security configuration in collaboration with the DevOps or platform engineering team. AppSec defines which tools run, which rule sets are active, and what threshold constitutes a blocking failure (typically: any Critical severity finding blocks the merge; High findings may warn or block depending on the organisation's risk tolerance). The platform team owns the GitHub Actions infrastructure, manages secrets (API keys for SonarCloud, Snyk tokens), and ensures the pipeline runs efficiently. Developers interact with the output — they see failing checks on their PR and are responsible for resolving them before merging.

**Dev → Staging → Production:** In development, engineers use IDE plugins (Semgrep, SonarLint, Gitleaks pre-commit hooks) to catch issues before they even commit. The CI pipeline is the enforcement layer — it catches what local tooling misses and provides a consistent, auditable record. In staging, additional pipeline jobs run that require the full deployed application: DAST scans, integration tests, load tests with security assertions. Production deployments are gated behind all of these checks passing. Some organisations add a separate deployment approval step for production — a human sign-off from AppSec or a change management process — on top of the automated gates.

**How findings reach stakeholders:** Developers see pipeline failures as red checks on their PR with links to the specific finding. Engineering managers see pipeline pass rates and security debt trends in dashboards — a team with a consistently high rate of security gate failures is a risk signal that feeds into quarterly planning. The CISO sees compliance evidence: the pipeline configuration itself is auditable proof that security checks are embedded in every deployment. When a critical vulnerability is published (a new CVE in a widely-used library), the SCA tools in the pipeline will flag every affected repository automatically on the next push, giving the security team a prioritised list of which teams need to update before an attacker can exploit the gap.

---

## Tools

| Tool | Category | Role | Free? |
|------|----------|------|-------|
| **Gitleaks** | Secrets | Scans full git history for API keys, tokens, passwords | ✅ Open source |
| **Semgrep** | SAST | Multi-language static analysis — OWASP Top 10 rules | ✅ Open source |
| **CodeQL** | SAST | GitHub-native deep analysis — JS and Python | ✅ Free for public repos |
| **SonarCloud** | SAST + Quality | Continuous code inspection + quality gate | ✅ Free for public repos |
| **Trivy** | SCA | Dependency and container CVE scan | ✅ Open source |
| **OSV Scanner** | SCA | Google vulnerability DB — broader PYSEC coverage | ✅ Open source |
| **Checkov** | IaC | Dockerfile + docker-compose misconfiguration scan | ✅ Open source |
| **Hadolint** | Lint | Dockerfile best-practice linter (CIS Docker Benchmark) | ✅ Open source |
| **OWASP ZAP** | DAST | Passive baseline scan against Juice Shop (manual trigger) | ✅ Open source |

---

## Pipeline Architecture

```
Developer push / PR
        │
        ▼
┌──────────────────────────────────────────┐
│          GitHub Actions CI/CD            │
│                                          │
│  ① Secrets scan    (Gitleaks)           │
│  ② SAST            (Semgrep)            │
│  ③ SAST            (CodeQL — JS/Python) │
│  ④ SAST + Quality  (SonarCloud)         │
│  ⑤ SCA             (Trivy)              │
│  ⑥ SCA             (OSV Scanner)        │
│  ⑦ IaC scan        (Checkov)            │
│  ⑧ Dockerfile lint (Hadolint)           │
│  ⑨ DAST            (ZAP — manual only)  │
└──────────────────────────────────────────┘
        │
        ▼
 Results → GitHub Security tab (SARIF)
 Results → SonarCloud dashboard
 Artifacts → GitHub Actions summary
```

---

## Workflow File

`.github/workflows/devsecops-pipeline.yml` — at the repo root.

Triggers:
- **push** to `main` or `develop`
- **pull_request** to `main`
- **schedule** — every Monday at 01:30 UTC
- **workflow_dispatch** — manual trigger (also activates ZAP DAST)

---

## Exercises

| # | Exercise | Tool | Status |
|---|----------|------|--------|
| 5.1 | Add Gitleaks secrets scan — full history (`fetch-depth: 0`) | Gitleaks | ✅ Complete |
| 5.2 | Enable CodeQL for JavaScript and Python (matrix strategy) | CodeQL | ✅ Complete |
| 5.3 | Configure SonarCloud with org + project key, SONAR_TOKEN | SonarCloud | ✅ Complete |
| 5.4 | Add Checkov IaC scan — Dockerfile + docker-compose | Checkov | ✅ Complete |
| 5.5 | Add Hadolint Dockerfile linter | Hadolint | ✅ Complete |
| 5.6 | Add ZAP DAST job gated to workflow_dispatch only | ZAP | ✅ Complete |

---

## Exercise Notes

### 5.1 — Gitleaks

`fetch-depth: 0` is the critical setting. Without it, GitHub Actions only checks out a shallow clone of the latest commit. Gitleaks needs the full history to catch secrets that were committed and later "deleted" — they remain in git history forever.

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### 5.2 — CodeQL

Uses a matrix strategy to run two parallel jobs (JS + Python) from a single job definition. Results appear in GitHub Security → Code scanning alerts.

```yaml
strategy:
  matrix:
    language: [javascript, python]
```

No token required — CodeQL is free for public repositories and uses `GITHUB_TOKEN` implicitly.

### 5.3 — SonarCloud

SonarCloud requires three things: the `SONAR_TOKEN` secret, the org key, and the project key. The `fetch-depth: 0` ensures full blame data for accurate code smell attribution.

```yaml
-Dsonar.organization=akhil65
-Dsonar.projectKey=akhil65_DSO
-Dsonar.sources=devsecops-lab
```

Dashboard: https://sonarcloud.io/project/overview?id=akhil65_DSO

### 5.4 — Checkov

Checkov scans IaC files against the CIS Docker Benchmark and Checkov's own policies. `soft_fail: true` means the job always exits 0 (findings are reported but don't block the pipeline on day one). Tighten to `soft_fail: false` once misconfigurations are triaged.

Results upload to the GitHub Security tab via SARIF, alongside Trivy and CodeQL findings.

### 5.5 — Hadolint

Hadolint parses the Dockerfile AST and checks rules like: pinned base image tags, `COPY` over `ADD`, `--no-install-recommends` on `apt-get`, `pipefail` set for piped `RUN` commands.

`failure-threshold: error` means warnings are reported but only errors fail the job. This is a good default for a new codebase.

### 5.6 — ZAP DAST (manual only)

ZAP is gated behind `if: github.event_name == 'workflow_dispatch'`. It should not run on every push because:
- It spins up Juice Shop (a vulnerable intentional app) on the runner
- A passive baseline scan takes 2–5 minutes
- An active scan would take 15+ minutes and would be inappropriate for a shared CI runner

To run ZAP: **GitHub Actions tab → DevSecOps Pipeline → Run workflow**.

---

## Key Concepts

**Shift-left security** — finding a vulnerability at PR time costs minutes to fix. Finding it in production costs days plus potential breach response.

**SARIF** (Static Analysis Results Interchange Format) — the common output format that all these tools (CodeQL, Trivy, Checkov) use to push findings into GitHub Security → Code scanning alerts. One pane of glass for all scan results.

**Quality gate vs. security gate** — SonarCloud's quality gate blocks a PR if new code introduces too many bugs or smells, regardless of severity. Security gates (Trivy `exit-code: 1`, Gitleaks) block specifically on security findings.

**IaC security** — misconfigurations in Dockerfiles and compose files are infrastructure vulnerabilities: containers running as root, `--privileged` mode, exposed ports without justification, `latest` tags (unpinned = unpredictable).

**Secrets in git history** — deleting a file or rotating a key does not remove it from git history. Anyone who clones the repo can read the old commit. Gitleaks with `fetch-depth: 0` catches this at PR time before it ever reaches main.

---

## Roadblocks & Fixes

| Roadblock | Fix |
|-----------|-----|
| SonarCloud "project not found" | Ensure `sonar.organization` and `sonar.projectKey` match exactly what SonarCloud shows — both lowercase |
| Gitleaks flags test credentials in lab files | Add a `.gitleaks.toml` allowlist for known test strings (e.g. `Password1!` in crAPI exercises) |
| Checkov fails on intentionally insecure lab configs | Use `soft_fail: true` during lab — these misconfigurations are intentional for learning |
| Hadolint fails on `FROM` with `:latest` tag | Either pin the tag in the Dockerfile or add `# hadolint ignore=DL3007` above the offending line |
| ZAP times out waiting for Juice Shop | The health-check loop retries 30 times at 5s intervals — increase if runner is slow |
| CodeQL autobuild fails on Python | Python doesn't need building; CodeQL autobuild is a no-op for interpreted languages — that's expected |

---

## Reports

Report generated at module completion — `docs/Module-5-Pipeline-Report.docx`
