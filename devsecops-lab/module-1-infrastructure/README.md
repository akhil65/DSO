# Module 1 — Infrastructure & Lab Setup

## Overview
This module provisions your local vulnerable lab using Docker Compose.
Three containers are launched: **OWASP Juice Shop**, **DVWA**, and **Portainer** (optional GUI).

---

## Real-World Context

In a production organisation, infrastructure is never provisioned by hand. Platform and infrastructure engineering teams define every environment — development, staging, and production — as code using tools like Terraform, Pulumi, or AWS CloudFormation. Docker Compose is the local development analogue of that practice: a declarative manifest that describes what services run, how they connect, and what configuration they receive. The same principle applies at every scale.

**Who owns this in a real org:** The platform engineering team owns the infrastructure manifests and the CI/CD pipelines that deploy them. Developers consume environments; they rarely provision them. A security engineer or AppSec team member reviews the infrastructure definitions during design — checking for overly permissive network policies, containers running as root, secrets baked into environment variables, and misconfigurations against benchmarks like CIS Docker or CIS Kubernetes. Tools like Checkov and tfsec (covered in Module 5) automate that review as a pipeline gate.

**Dev → Staging → Production:** In development, engineers spin up local environments like this one to validate their application changes in isolation. In staging, the same Compose or Kubernetes manifests are deployed to a shared environment that mirrors production — this is where integration testing and security scanning happen before anything reaches users. In production, infrastructure changes go through a pull request process with peer review and automated policy checks; nothing deploys manually. The Portainer GUI used here for visibility has a production equivalent in tools like Grafana, Datadog, or the native console of whichever cloud platform the org uses.

**The security conversation:** When a security team reviews infrastructure, the questions they ask are: which ports are exposed and to whom, what user does each container run as, where are secrets coming from (never hardcoded — they should come from a secrets manager like HashiCorp Vault or AWS Secrets Manager), and what happens if one container is compromised — can it reach the database directly? This module establishes the baseline environment all other security testing in the lab depends on, mirroring how a real org's secure baseline infrastructure underpins every application that runs on top of it.

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
