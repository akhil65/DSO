#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# Module 4.6 RASP — Exercise runner (4.6.3 → 4.6.5)
#
# Run from: DSO essentials/devsecops-lab/module-4.6-rasp/
#
# Prerequisites: Docker Desktop running, ports 3002–3005 free
# Usage:
#   chmod +x run-exercises.sh
#   ./run-exercises.sh          ← run all exercises
#   ./run-exercises.sh 4.6.4    ← run one exercise only
#   ./run-exercises.sh clean    ← stop and remove all lab containers
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail
EXERCISE=${1:-all}
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

pass() { echo -e "${GREEN}  ✅ $1${NC}"; }
fail() { echo -e "${RED}  ❌ $1${NC}"; }
info() { echo -e "${CYAN}  ℹ  $1${NC}"; }
head() { echo -e "\n${YELLOW}══ $1 ══${NC}"; }

# ── Helpers ───────────────────────────────────────────────────────────────────

wait_for_port() {
  local PORT=$1 NAME=$2 MAX=60 COUNT=0
  echo -n "  Waiting for $NAME on :$PORT "
  until curl -s -o /dev/null "http://localhost:$PORT/rest/products/search?q=health" 2>/dev/null; do
    sleep 2; COUNT=$((COUNT+2)); echo -n "."
    if [ $COUNT -ge $MAX ]; then echo " TIMEOUT"; return 1; fi
  done
  echo " ready (${COUNT}s)"
}

test_rasp() {
  local PORT=$1 LABEL=$2
  local RESULTS=()
  local PASS=true

  echo ""
  for TEST in \
    "%27%28:sqli_paren:403" \
    "%27+OR+1%3D1--:sqli_or1=1:403" \
    "test+UNION+SELECT+1,2,3--:sqli_union:403" \
    "apple:clean_search:200"; do
    local Q="${TEST%%:*}"
    local NAME="${TEST#*:}"; NAME="${NAME%:*}"
    local EXPECT="${TEST##*:}"
    local STATUS
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "http://localhost:${PORT}/rest/products/search?q=${Q}")
    RESULTS+=("$NAME=$STATUS")
    if [ "$STATUS" = "$EXPECT" ]; then
      pass "$LABEL | $NAME: HTTP $STATUS (expected $EXPECT)"
    else
      fail "$LABEL | $NAME: HTTP $STATUS (expected $EXPECT)"
      PASS=false
    fi
  done

  $PASS && pass "$LABEL: all 4 tests passed" || fail "$LABEL: one or more tests failed"
}

test_appsensor_escalation() {
  local PORT=$1
  echo ""
  info "AppSensor escalation test — 6 SQLi hits from same IP"
  local EXPECTED=(200 200 429 429 403 403)
  local ALL_PASS=true
  for i in 1 2 3 4 5 6; do
    local STATUS
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "http://localhost:${PORT}/rest/products/search?q=%27+OR+1%3D1--")
    local EXP="${EXPECTED[$((i-1))]}"
    if [ "$STATUS" = "$EXP" ]; then
      pass "Hit $i: HTTP $STATUS (LOG→WARN→BLOCK escalation)"
    else
      fail "Hit $i: HTTP $STATUS (expected $EXP)"
      ALL_PASS=false
    fi
    sleep 0.3  # slight pause to avoid localhost batching
  done
  $ALL_PASS && pass "AppSensor escalation: LOG×2 → WARN(429)×2 → BLOCK(403)×2 ✓"

  echo ""
  info "AppSensor ACE1 force-browse test (5 hits to /admin)"
  for i in 1 2 3 4 5; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "http://localhost:${PORT}/admin" 2>/dev/null || echo "000")
    echo -e "  ACE1 hit $i: HTTP $STATUS"
    sleep 0.2
  done
}

clean_up() {
  head "Stopping all lab containers"
  docker compose --profile openrasp     stop 2>/dev/null || true
  docker compose --profile contrast-rasp stop 2>/dev/null || true
  docker compose --profile appsensor    stop 2>/dev/null || true
  docker compose --profile datadog-asm  stop 2>/dev/null || true
  docker compose down --remove-orphans 2>/dev/null || true
  pass "All lab containers stopped"
  exit 0
}

# ── Main ──────────────────────────────────────────────────────────────────────

cd "$DIR"

if [ "$EXERCISE" = "clean" ]; then clean_up; fi

# ═══════════════════════════════════════════════════════════════════════════════
if [ "$EXERCISE" = "all" ] || [ "$EXERCISE" = "4.6.4" ]; then
head "Exercise 4.6.4 — AppSensor (escalating response)"

  info "Building AppSensor image (pure Node.js, no npm deps)..."
  docker compose --profile appsensor build --quiet
  pass "Build complete"

  info "Starting AppSensor container on port 3004..."
  docker compose --profile appsensor up -d
  wait_for_port 3004 "AppSensor"

  info "Startup log:"
  docker compose logs juice-shop-appsensor 2>&1 | grep -i "appsensor\|ready\|listening" | head -6

  test_appsensor_escalation 3004

  info "AppSensor log (detection events):"
  docker compose logs juice-shop-appsensor 2>&1 | grep "\[AppSensor\]" | tail -12
fi

# ═══════════════════════════════════════════════════════════════════════════════
if [ "$EXERCISE" = "all" ] || [ "$EXERCISE" = "4.6.3" ]; then
head "Exercise 4.6.3 — @contrast/rasp-v3 (installs from npm)"

  info "Building Contrast RASP v3 image (npm install @contrast/rasp-v3)..."
  info "This takes 60–90s on first run (npm download + multi-stage copy)"
  docker compose --profile contrast-rasp build 2>&1 | tail -8
  pass "Build complete"

  info "Starting Contrast RASP container on port 3003..."
  docker compose --profile contrast-rasp up -d
  wait_for_port 3003 "Contrast RASP v3"

  info "Startup log (check for Contrast init message):"
  docker compose logs juice-shop-contrast-rasp 2>&1 | grep -i "contrast\|rasp\|warning\|error" | head -8

  echo ""
  info "Testing SQLi blocking..."
  test_rasp 3003 "Contrast RASP v3"

  info "Contrast RASP v3 log:"
  docker compose logs juice-shop-contrast-rasp 2>&1 | grep -i "contrast\|blocked\|attack" | tail -6
fi

# ═══════════════════════════════════════════════════════════════════════════════
if [ "$EXERCISE" = "all" ] || [ "$EXERCISE" = "4.6.5" ]; then
head "Exercise 4.6.5 — Datadog ASM / dd-trace (Sqreen successor)"

  info "Building Datadog ASM image (npm install dd-trace, ~5–8 min first run)..."
  info "dd-trace includes prebuilt libddwaf binaries — larger download"
  docker compose --profile datadog-asm build 2>&1 | tail -8
  pass "Build complete"

  info "Starting Datadog ASM container on port 3005..."
  docker compose --profile datadog-asm up -d
  wait_for_port 3005 "Datadog ASM"

  info "Startup log (check for dd-trace + appsec init):"
  docker compose logs juice-shop-datadog 2>&1 | grep -i "datadog\|appsec\|dd-trace\|libddwaf" | head -8

  echo ""
  info "Testing SQLi blocking (libddwaf — no DD account needed)..."
  test_rasp 3005 "Datadog ASM"

  info "Datadog ASM log:"
  docker compose logs juice-shop-datadog 2>&1 | grep -i "appsec\|blocked\|waf\|attack" | tail -6
fi

# ═══════════════════════════════════════════════════════════════════════════════
if [ "$EXERCISE" = "all" ] || [ "$EXERCISE" = "4.6.6" ]; then
head "Exercise 4.6.6 — Signal Sciences / Fastly (architecture review)"

  echo ""
  echo "  Signal Sciences uses a HYBRID sidecar model — NOT pure in-process RASP."
  echo ""
  echo "  ┌─────────────────────┐   ① request data   ┌────────────────────────┐"
  echo "  │  Node.js App        │ ──────────────────→ │  sigsci-agent daemon   │"
  echo "  │  (Express module)   │ ←────────────────── │  localhost:9999        │"
  echo "  └─────────────────────┘   ② allow/block     └──────────┬─────────────┘"
  echo "                                                           │ telemetry"
  echo "                                                           ▼"
  echo "                                                 Signal Sciences Cloud"
  echo ""
  echo "  Key architectural differences vs all in-process agents:"
  echo "    - Blocking decision is made OUTSIDE the process (agent daemon)"
  echo "    - Agent crash does NOT crash the app (fault isolation)"
  echo "    - Cloud rule updates without app redeployment"
  echo "    - Add ~0.1–1ms latency per request (unix socket round-trip)"
  echo "    - Requires enterprise license; no free tier available"
  echo ""
  echo "  To explore the middleware registration and full comparison table:"
  echo "    cat module-4.6-rasp/sigsci-middleware-example.js"
  echo ""
  info "sigsci profile is defined in docker-compose.yml but requires enterprise credentials."
  info "Set SIGSCI_ACCESSKEYID + SIGSCI_SECRETACCESSKEY in .env to run."
fi

# ═══════════════════════════════════════════════════════════════════════════════
if [ "$EXERCISE" = "all" ]; then
head "Final — Side-by-side comparison"
  echo ""
  echo "  All 5 Juice Shop variants:"
  echo "    Port 3002 = custom rasp-hook.js     (exercises 4.6.1 / 4.6.2)"
  echo "    Port 3003 = @contrast/rasp-v3       (exercise 4.6.3)"
  echo "    Port 3004 = AppSensor               (exercise 4.6.4, hit 1 = LOG = 200)"
  echo "    Port 3005 = Datadog ASM (Sqreen)    (exercise 4.6.5)"
  echo "    Port 3006 = Signal Sciences          (exercise 4.6.6, enterprise only)"
  echo ""
  info "Running SQLi OR-1=1 across all running ports..."
  for PORT in 3002 3003 3004 3005; do
    local_status=$(curl -s -o /dev/null -w "%{http_code}" \
      "http://localhost:${PORT}/rest/products/search?q=%27+OR+1%3D1--" 2>/dev/null || echo "000")
    echo "    Port $PORT: HTTP $local_status"
  done
  echo ""
  info "AppSensor (3004) returns 200 on hit 1 by design — LOG phase, not immediate block."
  info "Run 5 times total to see it escalate to 403."
fi

echo ""
pass "Exercise run complete. To stop all containers: ./run-exercises.sh clean"
