'use strict';
/**
 * Signal Sciences / Fastly Next-Gen WAF — Node.js module example
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  ARCHITECTURE NOTE — This is NOT a standalone RASP agent.               ║
 * ║                                                                          ║
 * ║  Signal Sciences uses a HYBRID sidecar model:                           ║
 * ║                                                                          ║
 * ║   ┌─────────────────┐   ① request data   ┌──────────────────────────┐  ║
 * ║   │  Node.js App    │ ─────────────────→ │  sigsci-agent (sidecar)  │  ║
 * ║   │  (this module)  │ ←───────────────── │  local daemon :9999      │  ║
 * ║   └─────────────────┘   ② allow/block    └──────────┬───────────────┘  ║
 * ║                                                      │ ③ telemetry      ║
 * ║                                                      ▼                  ║
 * ║                                           Signal Sciences Cloud         ║
 * ║                                           (dashboard, threat intel)     ║
 * ║                                                                          ║
 * ║  The middleware itself is open-source (Apache 2.0), but the agent       ║
 * ║  daemon and cloud backend require an enterprise license.                ║
 * ║  https://github.com/signalsciences/sigsci-module-nodejs                 ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * Comparison with in-process RASP (rasp-hook.js, contrast-rasp-wrapper.js):
 *
 * ┌─────────────────────┬───────────────────────┬───────────────────────────┐
 * │ Property            │ In-process RASP        │ Signal Sciences           │
 * ├─────────────────────┼───────────────────────┼───────────────────────────┤
 * │ Position            │ Inside Node.js process │ Sidecar daemon + cloud    │
 * │ Data access         │ Decoded SQL / API calls│ Raw HTTP request metadata │
 * │ Blocking latency    │ 0ms (in-process throw) │ ~0.1-1ms (unix socket)    │
 * │ Bypass risk         │ Very low (at DB layer) │ Low (encoding-aware)      │
 * │ Crash isolation     │ Bug in hook = app crash│ Agent crash ≠ app crash   │
 * │ Deployment          │ NODE_OPTIONS --require │ npm install + sidecar     │
 * │ Visibility          │ console.error logs     │ Full dashboard + alerts   │
 * │ Cost                │ Free                   │ Enterprise license        │
 * └─────────────────────┴───────────────────────┴───────────────────────────┘
 *
 * Why Signal Sciences is "Next-Gen WAF" and not pure RASP:
 *   - A WAF sees raw HTTP at the network layer (before app decodes it)
 *   - Signal Sciences agent receives request context FROM the app module,
 *     meaning it sees decoded data — much closer to RASP visibility
 *   - But blocking decision is made OUTSIDE the process (in the agent daemon),
 *     unlike true RASP which throws synchronously inside the function call
 *
 * Installation (when you have a Signal Sciences account):
 *   npm install sigsci-module-nodejs
 *   # Start sidecar: docker run signalsciences/sigsci-agent --apikey <key>
 */

// ─────────────────────────────────────────────────────────────────────────────
//  EXAMPLE ONLY — will not run without sigsci-agent daemon on port 9999
// ─────────────────────────────────────────────────────────────────────────────

const express  = require('express');
const SigSciModule = require('sigsci-module-nodejs');   // npm install sigsci-module-nodejs

const app = express();

// Signal Sciences middleware must be registered BEFORE other routes.
// It adds ~0.1-1ms per request (unix socket round-trip to local agent daemon).
app.use(SigSciModule({
  // Agent daemon address (default: localhost:9999)
  // Can also be a unix socket path for lower latency: '/var/run/sigsci.sock'
  agentHost:      process.env.SIGSCI_AGENT_HOST || 'localhost',
  agentPort:      parseInt(process.env.SIGSCI_AGENT_PORT || '9999', 10),

  // Blocking mode: 'block' enforces decisions from cloud rules
  //                'passive' logs only — safe for initial deployment
  blockingMode:   process.env.SIGSCI_BLOCKING_MODE || 'block',

  // Pass custom request metadata to Signal Sciences dashboard
  anomalySize:    512,    // Flag requests with body > 512 bytes as anomalous
  maxBodySize:    300000, // Do not inspect bodies larger than 300KB
}));

// ─── Rest of your Express routes ─────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Export for use as middleware in an existing Express app:
module.exports = SigSciModule;

/*
 * Docker Compose sidecar setup (see comments in docker-compose.yml):
 *
 *   juice-shop-sigsci:
 *     image: bkimminich/juice-shop:latest
 *     depends_on: [sigsci-agent]
 *     environment:
 *       SIGSCI_AGENT_HOST: sigsci-agent
 *       SIGSCI_AGENT_PORT: "9999"
 *     profiles: [sigsci]
 *
 *   sigsci-agent:
 *     image: signalsciences/sigsci-agent:latest
 *     environment:
 *       SIGSCI_ACCESSKEYID:     ${SIGSCI_ACCESSKEYID}
 *       SIGSCI_SECRETACCESSKEY: ${SIGSCI_SECRETACCESSKEY}
 *     ports: ["9999:9999"]
 *     profiles: [sigsci]
 */
