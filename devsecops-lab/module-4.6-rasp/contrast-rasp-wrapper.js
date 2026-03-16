'use strict';
/**
 * Contrast RASP v3 — startup wrapper
 *
 * Loaded via NODE_OPTIONS="--require /juice-shop/contrast-rasp-wrapper.js"
 * before any Juice Shop module runs.
 *
 * @contrast/rasp-v3 (v0.7.0-alpha.5) is the open-source RASP core published
 * by Contrast Security.  No Contrast server, API key, or account is needed —
 * all detection and blocking is performed locally inside the Node.js process.
 *
 * The package is pre-release (alpha); the public API is still evolving.
 * This wrapper tries each known initialisation shape and falls back gracefully
 * if the API changes in a future release.
 */

const path = require('path');

// @contrast/rasp-v3 is installed to contrast_modules (separate from app's
// node_modules to avoid version conflicts with Juice Shop dependencies).
const RASP_PATH = path.join('/juice-shop/contrast_modules/@contrast/rasp-v3');

console.log('[Contrast RASP v3] Loading agent from', RASP_PATH);

try {
  const rasp = require(RASP_PATH);

  // ── Try the various init shapes the alpha API exposes ──────────────────────
  //
  //  Shape A  rasp.enable({ blocking: true })          — most likely
  //  Shape B  rasp({ blocking: true })                 — default-export function
  //  Shape C  rasp.default.enable({ blocking: true })  — ES-module re-export
  //  Shape D  rasp.init(...)                           — init() style
  //  Shape E  new rasp.Agent().start()                 — class-based

  const opts = {
    blocking: true,          // Enforce blocking mode (vs observe-only)
    reportingEnabled: false, // No cloud reporting — local lab only
    appName: 'juice-shop-lab',
  };

  if (typeof rasp.enable === 'function') {
    rasp.enable(opts);
    console.log('[Contrast RASP v3] Initialized via rasp.enable() ✓');

  } else if (typeof rasp === 'function') {
    rasp(opts);
    console.log('[Contrast RASP v3] Initialized via rasp() default export ✓');

  } else if (rasp.default && typeof rasp.default.enable === 'function') {
    rasp.default.enable(opts);
    console.log('[Contrast RASP v3] Initialized via rasp.default.enable() ✓');

  } else if (typeof rasp.init === 'function') {
    rasp.init(opts);
    console.log('[Contrast RASP v3] Initialized via rasp.init() ✓');

  } else if (rasp.Agent && typeof rasp.Agent === 'function') {
    const agent = new rasp.Agent(opts);
    if (typeof agent.start === 'function') agent.start();
    console.log('[Contrast RASP v3] Initialized via new rasp.Agent().start() ✓');

  } else {
    // Unknown API shape — log exports so you can inspect and adapt the wrapper.
    console.warn('[Contrast RASP v3] WARNING: Loaded but no known init method found.');
    console.warn('[Contrast RASP v3] Package exports:', Object.keys(rasp));
    console.warn('[Contrast RASP v3] App will start WITHOUT Contrast RASP protection.');
    console.warn('[Contrast RASP v3] Check https://www.npmjs.com/package/@contrast/rasp-v3 for updated API.');
  }

} catch (err) {
  // Non-fatal — Juice Shop will start but without Contrast RASP.
  // Check that Dockerfile.contrast copied contrast_modules correctly.
  console.error('[Contrast RASP v3] Failed to load agent:', err.message);
  console.error('[Contrast RASP v3] App will start WITHOUT Contrast RASP protection.');
  if (err.code === 'MODULE_NOT_FOUND') {
    console.error('[Contrast RASP v3] MODULE_NOT_FOUND — expected path:', RASP_PATH);
    console.error('[Contrast RASP v3] Verify: docker exec <container> ls /juice-shop/contrast_modules/@contrast/');
  }
}
