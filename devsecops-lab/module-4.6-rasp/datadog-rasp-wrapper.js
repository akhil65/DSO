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

const DD_PATH = '/juice-shop/dd_modules/dd-trace';

// ── detect-libc v2 compatibility shim ────────────────────────────────────────
// node-gyp-build (used by @datadog/native-appsec to load libddwaf) calls
// detect-libc.familySync() to build the prebuilt binary path, e.g.
// "linuxglibc-arm64".  detect-libc v2 removed familySync() (sync API).
// Without the shim: familySync = undefined → path = "linuxundefined-arm64"
//   → fs.existsSync(undefined) → DEP0187 warning → binary not found
//   → wafVersion absent from startup log → no blocking.
// The prebuilt binary EXISTS at linuxglibc-arm64/node-napi.node; we just need
// familySync() to return 'glibc' so node-gyp-build constructs the right path.
const Module = require('module');
const _originalLoad = Module._load;
Module._load = function patchedLoad(request, parent, isMain) {
  const mod = _originalLoad.call(this, request, parent, isMain);
  if (request === 'detect-libc' && mod && typeof mod.familySync !== 'function') {
    mod.familySync        = () => 'glibc';
    mod.versionSync       = () => null;
    mod.isNonGlibcLinux   = () => false;
    console.log('[Datadog ASM] detect-libc patched: familySync() shim installed');
  }
  return mod;
};

console.log('[Datadog ASM] Loading dd-trace from', DD_PATH);

// Log version for diagnosing whether blocking works in this release.
try {
  const pkg = require(DD_PATH + '/package.json');
  console.log('[Datadog ASM] dd-trace version:', pkg.version);
} catch (_) {}

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
    // DD_TRACE_ENABLED=false disables APM span collection but keeps AppSec active.
    // This prevents dd-trace from trying (and timing out connecting) to an agent,
    // which in some versions delays or degrades AppSec blocking decisions.
    hostname:    process.env.DD_AGENT_HOST || 'localhost',
    port:        parseInt(process.env.DD_TRACE_AGENT_PORT || '8126', 10),

    // Disable noisy features irrelevant for local lab
    runtimeMetrics: false,
    logInjection:   false,
    profiling:      false,

    // startupLogs: dd-trace prints a summary of its configuration at startup,
    // including whether libddwaf loaded successfully and WAF rules version.
    // Essential for diagnosing "AppSec enabled but not blocking" issues.
    // Example output:
    //   DATADOG TRACER CONFIGURATION - { ... "appsec":{"enabled":true} ... }
    //   DATADOG TRACER DIAGNOSTIC - Agent Error: connect ECONNREFUSED (expected, no agent)
    //   If libddwaf failed: AppSec would show wafVersion: null or similar
    startupLogs: true,
  });

  console.log('[Datadog ASM] dd-trace initialized — AppSec blocking: ENABLED');
  console.log('[Datadog ASM] Check startup logs above for libddwaf load status.');

} catch (err) {
  console.error('[Datadog ASM] Failed to initialize dd-trace:', err.message);
  console.error('[Datadog ASM] App will start WITHOUT Datadog ASM protection.');
  if (err.code === 'MODULE_NOT_FOUND') {
    console.error('[Datadog ASM] Check that Dockerfile.datadog copied dd_modules correctly.');
    console.error('[Datadog ASM] Run: docker exec <container> ls /juice-shop/dd_modules/dd-trace/');
  }
}
