'use strict';
/**
 * Datadog Application Security Management (ASM) — startup wrapper
 *
 * This is the spiritual successor to Sqreen (acquired by Datadog in 2021 for
 * ~$260M).  Sqreen pioneered RASP-as-a-service for Node.js in 2017 and was
 * the first product to offer:
 *   - Zero-instrumentation injection via NODE_OPTIONS --require
 *   - Per-request attack context (IP, user, stacktrace)
 *   - Proportional response (in-app WAF rules + account suspension)
 *
 * Datadog rebuilt Sqreen's agent on top of dd-trace (the official Datadog
 * APM tracer) and open-sourced the WAF engine as libddwaf (Apache 2.0).
 *
 * Key difference from Sqreen:
 *   - Sqreen had a standalone agent; dd-trace ASM is bundled into the APM tracer
 *   - libddwaf rules ship with the package — no cloud connection needed for blocking
 *   - Dashboard/triage/threat-intel features require a free Datadog account
 *
 * Blocking WITHOUT Datadog account: ✅ works — libddwaf rules are local
 * Dashboard visibility:              ❌ requires DD_API_KEY + free Datadog trial
 *
 * Loaded via NODE_OPTIONS="--require /juice-shop/datadog-rasp-wrapper.js"
 */

const path = require('path');

// dd-trace installed to dd_modules (separate from Juice Shop's node_modules)
const DD_PATH = '/juice-shop/dd_modules/dd-trace';

console.log('[Datadog ASM] Loading dd-trace from', DD_PATH);

try {
  const ddTrace = require(DD_PATH);

  ddTrace.init({
    // ── AppSec (RASP) configuration ──────────────────────────────────────────
    appsec: {
      enabled: true,
      // blockingResponse: { statusCode: 403, type: 'json' }  // default
    },

    // ── Service metadata ─────────────────────────────────────────────────────
    service:     'juice-shop',
    env:         process.env.DD_ENV || 'lab',
    version:     '1.0.0',

    // ── APM / tracing ────────────────────────────────────────────────────────
    // These are no-ops when DD_API_KEY is not set; blocking still works locally.
    hostname:    process.env.DD_AGENT_HOST || 'localhost',
    port:        parseInt(process.env.DD_TRACE_AGENT_PORT || '8126', 10),

    // Disable noisy features irrelevant for local lab
    runtimeMetrics: false,
    logInjection:   false,
    profiling:      false,

    // Suppress "failed to connect to agent" stderr spam when running without DD_API_KEY
    startupLogs: false,
  });

  console.log('[Datadog ASM] dd-trace initialized — AppSec blocking: ENABLED');
  console.log('[Datadog ASM] libddwaf rules: bundled (no cloud connection required for blocking)');
  console.log('[Datadog ASM] Dashboard: requires DD_API_KEY + free Datadog trial account');
  console.log('[Datadog ASM] Sign up: https://app.datadoghq.com/signup (14-day free trial)');

} catch (err) {
  console.error('[Datadog ASM] Failed to initialize dd-trace:', err.message);
  console.error('[Datadog ASM] App will start WITHOUT Datadog ASM protection.');
  if (err.code === 'MODULE_NOT_FOUND') {
    console.error('[Datadog ASM] Check that Dockerfile.datadog copied dd_modules correctly.');
    console.error('[Datadog ASM] Run: docker exec <container> ls /juice-shop/dd_modules/dd-trace/');
  }
}
