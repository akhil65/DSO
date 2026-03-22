# Module 1 — Infrastructure & Lab Setup

## Overview
This module provisions your local vulnerable lab using Docker Compose.
Three containers are launched: **OWASP Juice Shop**, **DVWA**, and **Portainer** (optional GUI).

---

## Real-World Context

In a production organisation, infrastructure is never provisioned by hand. Platform and infrastructure engineering teams define every environment — development, staging, and production — as code using tools like Terraform, Pulumi, or AWS CloudFormation. Docker Compose is the local development analogue of that practice: a declarative manifest that describes what services run, how they connect, and what configuration they receive. The same principle applies at every scale.

**Who owns this in a real org:** The platform engineering team owns the infrastructure manifests and the CI/CD pipelines that deploy them. Developers consume environments; they rarely provision them. A security engineer or AppSec team member reviews the infrastructure definitions during design — checking for overly permissive network policies, containers running as root, secrets baked into environment variables, and misconfigurations against benchmarks like CIS Docker or CIS Kubernetes. Tools like Checkov and tfsec (covered in Module 5) automate that review as a pipeline gate.

**Dev → Staging → Production:** In development, engineers spin up local environments like this one to validate their application changes in isolation. In staging, the same Compose or Kubernetes manifests are deployed to a shared environment that mirrors production — this is where integration testing and security scanning happen before anything reaches users. In production, infrastructure changes go through a pull request process with peer review and automated policy checks; nothing deploys manually. The Portainer GUI used here for visibility has a production equivalent in tools like Grafana, Datadog, or the native console of whichever cloud platform the org uses.

**How tools integrate with the developer pipeline:** Infrastructure-as-code security scanning is wired into CI/CD as a pre-merge gate on any change to infrastructure manifests. The tools inspect Dockerfiles, docker-compose.yml, Terraform, and Kubernetes YAML for misconfigurations rather than code logic. In a real org this looks like:

```bash
# Pre-commit: catch hardcoded secrets before they ever hit the repo
gitleaks detect --source=. --verbose
# (added to .pre-commit-config.yaml — fires automatically on every git commit)

# CI pipeline: scan IaC manifests for misconfigurations on every PR
checkov -d . --framework dockerfile,docker_compose --hard-fail-on HIGH
tfsec . --minimum-severity HIGH --no-colour

# CI pipeline: scan the built container image for known CVEs before pushing
trivy image myapp:latest --severity HIGH,CRITICAL --exit-code 1

# Periodic/scheduled: benchmark a running host against CIS Docker controls
docker run --net host --pid host --userns host --cap-add audit_control \
  -v /var/lib:/var/lib -v /var/run/docker.sock:/var/run/docker.sock \
  docker/docker-bench-security
```

Checkov and tfsec flag things like `user: root` in a Dockerfile, `privileged: true` in a Compose service, unnecessary port exposure, or Terraform resources creating public S3 buckets. Trivy catches CVEs in base images. Gitleaks catches `AWS_SECRET_ACCESS_KEY=...` committed by accident. All three run headlessly in 10–30 seconds on any CI platform (GitHub Actions, GitLab CI, Jenkins) — they are not manual tools, they are pipeline gates that run on every infrastructure PR without anyone having to remember to invoke them.

**The security conversation:** When a security team reviews infrastructure, the questions they ask are: which ports are exposed and to whom, what user does each container run as, where are secrets coming from (never hardcoded — they should come from a secrets manager like HashiCorp Vault or AWS Secrets Manager), and what happens if one container is compromised — can it reach the database directly? This module establishes the baseline environment all other security testing in the lab depends on, mirroring how a real org's secure baseline infrastructure underpins every application that runs on top of it.

**Lab vs real world:** In this lab you stand up the environment manually with `docker compose up`. In a real org nobody touches infrastructure manually — a PR to `docker-compose.yml` triggers Checkov and Trivy in CI, a human review, then an automated deploy. The lab collapses that to make the environment visible and approachable; the principle is the same: infrastructure that hasn't been reviewed and scanned doesn't get deployed.

---

## Prerequisites

```bash
# macOS — install Docker Desktop
brew install --cask docker

# Verify installation
docker --version
docker compose version
```

---

## Spin Up the Lab

```bash
# From this directory
docker compose up -d

# Check all containers are healthy
docker compose ps
```

### Access Points

| Target       | URL                        | Credentials         |
|--------------|----------------------------|---------------------|
| Juice Shop   | http://localhost:3000      | Register any user   |
| DVWA         | http://localhost:8080      | admin / password    |
| Portainer    | http://localhost:9000      | Set on first login  |

---

## DVWA First-Time Setup

1. Navigate to `http://localhost:8080`
2. Login: `admin` / `password`
3. Click **Create / Reset Database**
4. Re-login and set **Security Level → Low** (for initial lab work)

---

## Tear Down

```bash
# Stop containers (data preserved)
docker compose stop

# Remove containers + networks (data preserved in volumes)
docker compose down

# Full clean (removes volumes/data too — USE WITH CAUTION)
docker compose down -v
```

---

## Commit This to GitHub

```bash
cd <your-repo-root>
git add module-1-infrastructure/
git commit -m "feat(module-1): add lab infrastructure docker-compose"
git push origin main
```

---

## What's Next?
Module 2 introduces **SAST** — static code analysis with Bandit and Semgrep.
Type **"Next Module"** when you're ready.
