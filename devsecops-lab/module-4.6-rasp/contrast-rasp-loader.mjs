/**
 * Contrast RASP v3 — ESM startup loader
 *
 * Why .mjs and not .js?
 *   @contrast/rasp-v3 is an ES module that uses top-level `await`.
 *   In Node.js, you cannot `require()` a module that has top-level await —
 *   require() is synchronous and top-level await is asynchronous by nature.
 *   The error: "require() cannot be used on an ESM graph with top-level await"
 *
 *   The fix: load via NODE_OPTIONS="--import file:///path/to/loader.mjs"
 *   --import (unlike --require) runs an ES module asynchronously and waits
 *   for all top-level awaits to complete before the main app starts.
 *
 * detect-libc monkey-patch (why this is needed):
 *   @contrast/agent-lib calls detect-libc.familySync() (a v1 synchronous API).
 *   detect-libc v2 removed familySync entirely (async-only API).
 *   npm v10 resolves detect-libc to v2 for the entire tree, including nested
 *   copies inside @contrast packages that npm overrides cannot always reach.
 *
 *   Fix: intercept Module._load for every CJS require() in the process.
 *   When ANY call to require('detect-libc') lands (from any package, any path),
 *   if the returned module is missing familySync, we add it as a shim.
 *   This works because Node.js caches the patched module object — the same
 *   object reference is returned to all subsequent callers, so the patch is
 *   seen process-wide regardless of which detect-libc file was resolved.
 *
 * Loaded via: NODE_OPTIONS="--import file:///juice-shop/contrast-rasp-loader.mjs"
 */

import { createRequire, Module } from 'module';
import { pathToFileURL } from 'url';

const require = createRequire(import.meta.url);

// ── Patch detect-libc BEFORE loading @contrast/rasp-v3 ───────────────────────
// Intercept every CJS require() call in the process.
// When detect-libc is required and is missing familySync (v2 behaviour),
// add the shim synchronously before the caller receives the module object.
const _originalLoad = Module._load;
Module._load = function patchedLoad(request, parent, isMain) {
  const mod = _originalLoad.call(this, request, parent, isMain);
  if (request === 'detect-libc' && mod && typeof mod.familySync !== 'function') {
    // detect-libc v2: GLIBC and MUSL are string constants exported directly.
    // familySync() should return the libc family or null on non-Linux.
    mod.familySync       = () => mod.GLIBC || 'glibc';
    mod.versionSync      = () => null;
    mod.isNonGlibcLinux  = () => false;
    console.log('[Contrast RASP v3] detect-libc patched: familySync() shim installed');
  }
  return mod;
};

// ── Load the RASP agent ───────────────────────────────────────────────────────
const MODULE_PATH = '/juice-shop/contrast_modules/@contrast/rasp-v3/dist/esm-loader.mjs';

console.log('[Contrast RASP v3] Loading agent (ESM) from', MODULE_PATH);

try {
  // Dynamic import() handles ESM + top-level await correctly
  const rasp = await import(pathToFileURL(MODULE_PATH).href);

  const opts = {
    blocking: true,
    reportingEnabled: false,
    appName: 'juice-shop-lab',
  };

  if (typeof rasp.enable === 'function') {
    rasp.enable(opts);
    console.log('[Contrast RASP v3] Initialized via rasp.enable() ✓');
  } else if (typeof rasp.default?.enable === 'function') {
    rasp.default.enable(opts);
    console.log('[Contrast RASP v3] Initialized via rasp.default.enable() ✓');
  } else if (typeof rasp.default === 'function') {
    rasp.default(opts);
    console.log('[Contrast RASP v3] Initialized via rasp.default() ✓');
  } else {
    console.warn('[Contrast RASP v3] Loaded but no known init method found.');
    console.warn('[Contrast RASP v3] Exports:', Object.keys(rasp));
    console.warn('[Contrast RASP v3] App starts WITHOUT Contrast RASP protection.');
  }

} catch (err) {
  console.error('[Contrast RASP v3] Failed to load:', err.message);
  console.error('[Contrast RASP v3] App starts WITHOUT Contrast RASP protection.');
}
