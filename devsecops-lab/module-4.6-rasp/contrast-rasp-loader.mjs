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
 * Loaded via: NODE_OPTIONS="--import file:///juice-shop/contrast-rasp-loader.mjs"
 */

import { pathToFileURL } from 'url';

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
