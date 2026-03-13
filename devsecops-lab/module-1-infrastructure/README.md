# Module 1 — Infrastructure & Lab Setup

## Overview
This module provisions your local vulnerable lab using Docker Compose.
Three containers are launched: **OWASP Juice Shop**, **DVWA**, and **Portainer** (optional GUI).

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
