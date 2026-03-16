#!/bin/sh
# rasp-entrypoint.sh — Injects OpenRASP agent before Juice Shop starts
#
# NODE_OPTIONS=--require tells Node.js to load the RASP agent before ANY other
# code — including the app's own require() calls. This is how RASP hooks work:
# it patches Node's built-in modules (e.g., sqlite3, http) at the lowest level
# before the app can call them, giving RASP visibility into every DB query.

set -e

echo "[RASP] Starting Juice Shop with OpenRASP agent..."
echo "[RASP] NODE_OPTIONS: $NODE_OPTIONS"

# Set RASP agent injection via NODE_OPTIONS --require flag
# This is equivalent to adding 'require("@baidu/openrasp")' as the very first
# line of the application — but without modifying app source code at all.
export NODE_OPTIONS="--require /usr/local/lib/node_modules/@baidu/openrasp/lib/index.js $NODE_OPTIONS"
export OPENRASP_CONFIG="/juice-shop/openrasp.yml"

# Start Juice Shop (its default CMD)
cd /juice-shop
exec node app.js
