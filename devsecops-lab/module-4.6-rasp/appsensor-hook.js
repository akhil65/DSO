'use strict';
/**
 * OWASP AppSensor — Node.js in-process implementation
 *
 * AppSensor (https://owasp.org/www-project-appsensor/) defines Detection Points
 * and Response Actions. Unlike a pure RASP (immediate block), AppSensor
 * escalates the response proportionally to the number of attacks observed
 * from a given IP:
 *
 *   1st attack  →  LOG    (request passes through; anomaly recorded)
 *   3rd attack  →  WARN   (HTTP 429 Too Many Requests; slow attacker down)
 *   5th attack  →  BLOCK  (HTTP 403; attacker fully denied)
 *   10th attack →  (conceptual) DISABLE_ACCOUNT / CAPTCHA gate
 *
 * Detection Points implemented:
 *   IE1  — Injection: SQL injection pattern in query parameter
 *   IE2  — Injection: SQLi detected at sqlite3/Sequelize driver level
 *   ACE1 — Access Control: force-browsing to admin/config paths
 *   RE1  — Input Validation: abnormally long URL parameter value (>512 chars)
 *
 * Loaded via NODE_OPTIONS="--require /juice-shop/appsensor-hook.js"
 *
 * Reference: OWASP AppSensor Guide v2 (detection-point catalogue)
 * https://owasp.org/www-project-appsensor/
 */

const http       = require('http');
const Module     = require('module');
const { AsyncLocalStorage } = require('async_hooks');

// ── Per-request context (IP tracking across async hops) ───────────────────────
const requestCtx = new AsyncLocalStorage();

function currentIp() {
  return requestCtx.getStore()?.ip ?? '0.0.0.0';
}

function getClientIp(req) {
  return ((req.headers && req.headers['x-forwarded-for']) || req.socket?.remoteAddress || 'unknown')
    .split(',')[0].trim();
}

// ── AppSensor state store ─────────────────────────────────────────────────────
//   key: `${ip}::${detectionPoint}`  →  { count, firstSeen, lastSeen }
const store = new Map();

// Thresholds (tune to taste)
const THRESHOLDS = {
  LOG:   1,   // Emit warning log from the very first hit
  WARN:  3,   // Return HTTP 429 from the 3rd hit
  BLOCK: 5,   // Return HTTP 403 from the 5th hit
};
const STALE_AFTER_MS = 10 * 60 * 1000; // Reset per-IP counters after 10 min of silence

function getState(ip, dp) {
  const key = `${ip}::${dp}`;
  const now  = Date.now();
  let s = store.get(key);

  if (!s || (now - s.lastSeen) > STALE_AFTER_MS) {
    s = { count: 0, firstSeen: now, lastSeen: now };
    store.set(key, s);
  }
  return { key, s, now };
}

/**
 * Record a detection point hit and take the proportional AppSensor response.
 *
 * @param {string} dp       Detection point code (e.g. 'IE1', 'ACE1')
 * @param {string} evidence Short description / evidence string (truncated to 120 chars)
 * @throws Error with .status=403 (BLOCK) or .status=429 (WARN)
 */
function detect(dp, evidence) {
  const ip = currentIp();
  const { key, s, now } = getState(ip, dp);

  s.count++;
  s.lastSeen = now;
  store.set(key, s);

  const ev = String(evidence).substring(0, 120);

  if (s.count >= THRESHOLDS.BLOCK) {
    console.error(`[AppSensor] BLOCK  | DP=${dp} | IP=${ip} | count=${s.count} | ${ev}`);
    const err = new Error(`AppSensor BLOCK: ${dp} threshold exceeded (${s.count} detections)`);
    err.status     = 403;
    err.appsensor  = true;
    err.dp         = dp;
    throw err;
  }

  if (s.count >= THRESHOLDS.WARN) {
    console.warn(`[AppSensor] WARN   | DP=${dp} | IP=${ip} | count=${s.count} | ${ev}`);
    const err = new Error(`AppSensor WARN: ${dp} warning threshold (${s.count} detections)`);
    err.status     = 429;
    err.appsensor  = true;
    err.dp         = dp;
    throw err;
  }

  // LOG — request passes through; anomaly recorded
  console.warn(`[AppSensor] LOG    | DP=${dp} | IP=${ip} | count=${s.count} | ${ev}`);
}

// ── SQLi patterns (shared with rasp-hook.js; kept in sync manually) ──────────
const SQLI_PATTERNS = [
  /'\s*(or|and)\s+['"\d]/i,
  /'\s*(or|and)\s+\d+\s*=\s*\d+/i,
  /union\s+(all\s+)?select/i,
  /--(\s|$)/m,
  /\/\*[\s\S]*?\*\//,
  /'[^']*'\s*=\s*'[^']*'/,
  /\bexec(\s|\()+/i,
  /benchmark\s*\(/i,
  /sleep\s*\(\s*\d/i,
  /LIKE\s+'%'[^%']/i,
  /LIKE\s+'%[^']*'--/i,
];

function isDdl(sql) {
  return /^\s*(CREATE|ALTER|DROP|PRAGMA|ATTACH|DETACH|VACUUM|REINDEX)\s/i.test(sql);
}

function isSquli(sql) {
  if (!sql || isDdl(sql)) return false;
  return SQLI_PATTERNS.some(p => p.test(sql));
}

// ── RE1 / IE1 — HTTP-level detection (URL + query params) ────────────────────
//   Wrap http.Server.prototype.emit to intercept every incoming request,
//   store the client IP in AsyncLocalStorage, and run HTTP-level detections.
const origEmit = http.Server.prototype.emit;
http.Server.prototype.emit = function (event, req, res) {
  if (event !== 'request') {
    return origEmit.apply(this, arguments);
  }

  const ip  = getClientIp(req);
  const url = req.url || '';

  // Run within async context so sqlite3/Sequelize hooks (below) can read the IP.
  return requestCtx.run({ ip }, () => {

    // ACE1 — force-browsing to sensitive paths
    if (/\/(admin|manage|config|\.git|\.env|backup|wp-admin|phpMyAdmin)/i.test(url)) {
      try {
        detect('ACE1', `url=${url}`);
      } catch (e) {
        if (e.appsensor) {
          res.writeHead(e.status, { 'Content-Type': 'application/json', 'X-AppSensor-DP': e.dp });
          res.end(JSON.stringify({ status: e.status, error: e.message }));
          return true;
        }
        throw e;
      }
    }

    // RE1 — abnormally long parameter value (possible buffer overflow / fuzzing probe)
    const qs = url.includes('?') ? url.slice(url.indexOf('?') + 1) : '';
    if (qs.length > 512) {
      try {
        detect('RE1', `querystring length=${qs.length}`);
      } catch (e) {
        if (e.appsensor) {
          res.writeHead(e.status, { 'Content-Type': 'application/json', 'X-AppSensor-DP': e.dp });
          res.end(JSON.stringify({ status: e.status, error: e.message }));
          return true;
        }
        throw e;
      }
    }

    // IE1 — SQLi pattern visible directly in the URL (before reaching DB layer)
    const decoded = (() => { try { return decodeURIComponent(qs); } catch { return qs; } })();
    if (isSquli(decoded)) {
      try {
        detect('IE1', `url_param=${decoded.substring(0, 80)}`);
      } catch (e) {
        if (e.appsensor) {
          res.writeHead(e.status, { 'Content-Type': 'application/json', 'X-AppSensor-DP': e.dp });
          res.end(JSON.stringify({ status: e.status, error: e.message }));
          return true;
        }
        throw e;
      }
    }

    return origEmit.apply(this, arguments);
  });
};

// ── IE2 — sqlite3 / Sequelize level detection ─────────────────────────────────
//   By the time we reach the DB driver, the IP is available via AsyncLocalStorage.
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  const result = origLoad.apply(this, arguments);

  if (request === 'sqlite3' || request === 'better-sqlite3') {
    const methods = ['run', 'get', 'all', 'each', 'exec', 'prepare'];
    const proto   = result.Database ? result.Database.prototype : result.prototype;
    if (proto) {
      methods.forEach(method => {
        if (!proto[method]) return;
        const original = proto[method];
        proto[method] = function (sql, ...args) {
          if (typeof sql === 'string' && isSquli(sql)) {
            try {
              detect('IE2', `sql=${sql.substring(0, 100)}`);
            } catch (e) {
              if (e.appsensor) {
                // Re-throw — Juice Shop's error handler will surface a 500 unless
                // the error middleware maps it to e.status.
                throw e;
              }
              throw e;
            }
          }
          return original.apply(this, [sql, ...args]);
        };
      });
    }
  }
  return result;
};

// Sequelize hook
const origRequire = Module.prototype.require;
Module.prototype.require = function (id) {
  const mod = origRequire.apply(this, arguments);
  if ((id === 'sequelize' || id === 'Sequelize') && mod?.prototype?.query && !mod.prototype.__appsensorPatched) {
    const origQuery = mod.prototype.query;
    mod.prototype.query = function (sql, options) {
      const sqlStr = typeof sql === 'string' ? sql : (sql && sql.query) || '';
      if (sqlStr && isSquli(sqlStr)) {
        try {
          detect('IE2', `sequelize=${sqlStr.substring(0, 100)}`);
        } catch (e) {
          if (e.appsensor) throw e;
          throw e;
        }
      }
      return origQuery.apply(this, arguments);
    };
    mod.prototype.__appsensorPatched = true;
  }
  return mod;
};

console.log('[AppSensor] Agent initialized');
console.log('[AppSensor] Detection points: IE1 (URL SQLi), IE2 (DB SQLi), ACE1 (force-browse), RE1 (long param)');
console.log(`[AppSensor] Thresholds: LOG@${THRESHOLDS.LOG}, WARN(429)@${THRESHOLDS.WARN}, BLOCK(403)@${THRESHOLDS.BLOCK} | Stale after: 10 min`);
