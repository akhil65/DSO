/**
 * rasp-hook.js — Custom RASP Agent for Juice Shop (Node.js)
 *
 * HOW IT WORKS:
 * Loaded via NODE_OPTIONS="--require /juice-shop/rasp-hook.js" — this means
 * Node.js runs this file BEFORE any application code. We use Module._resolveFilename
 * to intercept the moment Juice Shop calls require('sqlite3'), and replace the
 * sqlite3.Database.prototype.run/get/all methods with our own wrappers that
 * inspect every SQL string before it reaches the database.
 *
 * This is RASP (Runtime Application Self-Protection) in its purest form:
 *   - No network hop (unlike a WAF)
 *   - Sees the FINAL decoded SQL string — encoding tricks cannot bypass it
 *   - Runs inside the Node.js process — zero deployment changes needed
 */

'use strict';

const Module = require('module');
const originalLoad = Module._load;

// ── SQL Injection detection patterns ────────────────────────────────────────
// Rules are applied ONLY to non-DDL queries via the isDdl() guard below.
//
// BROKEN-LIKE DETECTION — root cause analysis:
//
//   Normal LIKE:   LIKE '%apple%'       → '%' immediately after opening quote
//   Injected LIKE: LIKE '%'(%'          → quote appears right after '%' opening
//
//   The precise pattern /LIKE\s+'%'[^%']/i only matches when a single quote
//   appears immediately after the opening '%' — exactly the '( injection case.
//   This avoids false-positives on normal internal queries like:
//     LIKE '%sanitize-html%' AND ...    ← '%s' — quote not right after %
//     LIKE '%epilogue-js%';             ← '%e' — same
//
//   A second pattern catches injection in the MIDDLE of the LIKE value:
//   /LIKE\s+'%[^']*'--/i catches: LIKE '%test'-- (classic comment injection)
const SQLI_PATTERNS = [
  /'\s*(or|and)\s+['"\d]/i,            // ' OR '1' / ' AND 1
  /'\s*(or|and)\s+\d+\s*=\s*\d+/i,    // ' OR 1=1
  /union\s+(all\s+)?select/i,           // UNION SELECT
  /--(\s|$)/m,                          // SQL line comment (--)
  /\/\*[\s\S]*?\*\//,                   // block comment /* */
  /'[^']*'\s*=\s*'[^']*'/,             // 'x'='x' tautology
  /\bexec(\s|\()+/i,                   // exec() call
  /benchmark\s*\(/i,                    // time-based blind
  /sleep\s*\(\s*\d/i,                  // sleep() injection
  // Broken-LIKE (start): quote right after the opening '%' — catches '%'( injection
  /LIKE\s+'%'[^%']/i,
  // Broken-LIKE (mid): quote in the LIKE value followed by SQL comment
  /LIKE\s+'%[^']*'--/i,
];

// ── Guard: skip DDL and internal ORM statements ──────────────────────────────
// CREATE TABLE, ALTER TABLE, DROP TABLE, and bulk INSERT/UPDATE statements
// are generated internally by Sequelize at startup/seeding and are never
// influenced by user input. Checking them only produces false positives.
function isDdl(sql) {
  return /^\s*(CREATE|ALTER|DROP|PRAGMA|ATTACH|DETACH|VACUUM|REINDEX)\s/i.test(sql);
}

// ── XSS detection patterns (for http response hooks) ───────────────────────
const XSS_PATTERNS = [
  /<script[\s>]/i,
  /javascript\s*:/i,
  /on\w+\s*=/i,       // onload=, onerror=, etc.
];

// ── Path traversal patterns ─────────────────────────────────────────────────
const PATH_TRAVERSAL_PATTERNS = [
  /\.\.[\/\\]/,       // ../
  /%2e%2e[%2f%5c]/i, // URL-encoded ../
];

function isSquli(sql) {
  if (!sql || isDdl(sql)) return false;   // skip DDL — never user-influenced
  return SQLI_PATTERNS.some(p => p.test(sql));
}

function blockRequest(type, evidence) {
  const msg = `[RASP] BLOCKED — ${type} detected | evidence: ${evidence.substring(0, 120)}`;
  console.error(msg);
  // Throw an error that will propagate up through Juice Shop's route handler
  // and be caught as a 500, but more importantly — the DB query never executes.
  const err = new Error(`RASP: ${type} attempt blocked`);
  err.status = 403;
  err.rasp = true;
  throw err;
}

// ── Intercept sqlite3 require ────────────────────────────────────────────────
// We hook Module._load so when Juice Shop calls require('sqlite3') we return
// a patched version instead of the real one.
Module._load = function (request, parent, isMain) {
  const result = originalLoad.apply(this, arguments);

  if (request === 'sqlite3' || request === 'better-sqlite3') {
    console.log('[RASP] sqlite3 module loaded — patching Database methods');

    // Patch all query methods: run, get, all, each, exec
    const methods = ['run', 'get', 'all', 'each', 'exec', 'prepare'];
    const proto = result.Database ? result.Database.prototype : result.prototype;

    if (proto) {
      methods.forEach(method => {
        if (!proto[method]) return;
        const original = proto[method];
        proto[method] = function (sql, ...args) {
          if (typeof sql === 'string' && isSquli(sql)) {
            blockRequest('SQL Injection', sql);
          }
          return original.apply(this, [sql, ...args]);
        };
      });
      console.log('[RASP] sqlite3 hooks active — SQLi detection enabled');
    }
  }

  return result;
};

// ── Intercept sequelize / sequelize-pool (Juice Shop uses Sequelize ORM) ────
const originalRequire = Module.prototype.require;
Module.prototype.require = function (id) {
  const mod = originalRequire.apply(this, arguments);

  // Hook Sequelize query method if this is the sequelize module
  if ((id === 'sequelize' || id === 'Sequelize') && mod && mod.prototype && mod.prototype.query) {
    if (!mod.prototype.__raspPatched) {
      const origQuery = mod.prototype.query;
      mod.prototype.query = function (sql, options) {
        const sqlStr = typeof sql === 'string' ? sql : (sql && sql.query) || '';
        if (sqlStr && isSquli(sqlStr)) {
          blockRequest('SQL Injection (Sequelize)', sqlStr);
        }
        return origQuery.apply(this, arguments);
      };
      mod.prototype.__raspPatched = true;
      console.log('[RASP] Sequelize query hook active');
    }
  }

  return mod;
};

// ── HTTP response hook — catch XSS in outbound responses ────────────────────
// We patch http.ServerResponse.write to inspect response bodies for reflected
// XSS payloads. This catches cases where user input is echoed back unsanitized.
const http = require('http');
const origWrite = http.ServerResponse.prototype.write;
const origEnd = http.ServerResponse.prototype.end;

function checkForXss(chunk) {
  if (!chunk) return;
  const body = chunk.toString('utf8', 0, 2000); // only check first 2KB
  if (XSS_PATTERNS.some(p => p.test(body))) {
    console.warn('[RASP] WARNING — possible XSS in response body (logging only, not blocking)');
    // Note: we log rather than block here — blocking response writes causes
    // partial responses. In production RASP you'd sanitize instead.
  }
}

http.ServerResponse.prototype.write = function (chunk, ...args) {
  checkForXss(chunk);
  return origWrite.apply(this, [chunk, ...args]);
};

console.log('[RASP] Agent initialized — hooks: SQLi (sqlite3 + Sequelize), XSS response scan');
console.log('[RASP] NODE_OPTIONS --require loaded rasp-hook.js before app startup');
