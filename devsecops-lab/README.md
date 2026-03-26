# DevSecOps & AI Security Lab

> A hands-on, end-to-end DevSecOps pipeline and vulnerable lab environment built entirely with free and open-source tools. Every module is tracked here as we build it.

---

## Curriculum

| Module | Topic | Status |
|--------|-------|--------|
| [Module 1](./module-1-infrastructure/) | Infrastructure & Lab Setup (Docker, Juice Shop, DVWA) | ✅ Complete |
| [Module 2](./module-2-sast/) | Static Analysis — SAST & SCA (Bandit, Semgrep, Trivy, OSV Scanner) | ✅ Complete |
| [Module 3](./module-3-dast/) | Dynamic Analysis — DAST (OWASP ZAP, headless CI) | ✅ Complete |
| [Module 3.5](./module-3.5-api-security/) | API Security — OWASP API Top 10 (crAPI, ZAP, kiterunner, jwt_tool) | ✅ Complete |
| [Module 4](./module-4-pentesting/) | Manual Pentesting (Burp Suite, SQLi, XSS, CSRF, IDOR) | ✅ Complete |
| [Module 4.5](./module-4.5-waf/) | WAF — ModSecurity CRS reverse proxy in front of Juice Shop | ✅ Complete |
| [Module 4.6](./module-4.6-rasp/) | RASP — Runtime Application Self-Protection (dd-trace, AppSensor, Contrast) | ✅ Complete |
| [Module 5](./module-5-pipeline/) | CI/CD Pipeline Security (GitHub Actions — Gitleaks, Semgrep, CodeQL, SonarCloud, Trivy, OSV, Checkov, Hadolint, ZAP) | ✅ Complete |
| [Module 6](./module-6-ai-security/) | AI Application Security (OWASP LLM Top 10, Prompt Injection, Garak, LLM Guard, SecLists) | ✅ Complete |
| [Module 7](./module-7-mobile/) | Mobile AppSec — Android & iOS Static/Dynamic Analysis + AI Mobile Security (MobSF, Frida, DIVA, iGoat, mitmproxy) | ✅ Complete |

---

## Tech Stack

**Vulnerable Targets:** OWASP Juice Shop · DVWA · crAPI · DIVA (Android) · OWASP LLM Goat
**Environment:** Docker · VirtualBox/VMware · Android Studio Emulator
**SAST:** CodeQL · Semgrep · Bandit · MobSF (mobile static)
**SCA:** OWASP Dependency-Check · Trivy · OSV Scanner
**DAST:** OWASP ZAP · Burp Suite CE · Kiterunner · Nmap · Metasploit
**API Security:** ZAP (GUI + OpenAPI scan) · crAPI · kiterunner · jwt_tool · OWASP API Top 10
**WAF:** OWASP ModSecurity CRS v3 + nginx (Docker)
**RASP:** rasp-hook.js (custom) · AppSensor · dd-trace v4 + libddwaf · @contrast/rasp-v3 (documented, incompatible)
**CI/CD Pipeline:** GitHub Actions · Gitleaks · CodeQL · SonarCloud · Checkov · Hadolint · OSSF Scorecard
**Mobile:** MobSF · Frida · Objection · jadx · ADB · mitmproxy · OWASP MASTG · MASVS · DIVA (Android) · iGoat-Swift (iOS)
**AI Security:** Ollama (llama3.2:1b) · Garak · LLM Guard · SecLists LLM · OWASP LLM Top 10 · Prompt Injection (direct + indirect)

---

## Getting Started

```bash
git clone https://github.com/akhil65/DSO.git
cd DSO/module-1-infrastructure
docker compose up -d
```

See [Module 1 README](./module-1-infrastructure/README.md) for full setup instructions.

---

## Docs & Walkthroughs

Detailed guides and scan reports for each module live in the [`docs/`](./docs/) folder.

---

## Progress Log

| Module | Milestone |
|--------|-----------|
| Module 1 | Lab infrastructure provisioned — Juice Shop + DVWA |
| Module 1 | First SQL injection executed — bypassed Juice Shop admin login |
| Module 1 | DVWA configured at Low security, Portainer dashboard live |
| Module 2 | Vulnerable Python app created — 10 deliberate vulnerabilities |
| Module 2 | Bandit, Semgrep, Trivy, OSV Scanner added to CI pipeline |
| Module 2 | Bandit scan — 29 Python findings across 9 vulnerability categories |
| Module 2 | Semgrep scan — 43 findings (Python + JS), SSRF and XSS taint tracking |
| Module 2 | Trivy scan — 136 CVEs + 4 secrets in requirements.txt and Juice Shop image |
| Module 2 | OSV scan — 50 CVEs, 7 unique vs Trivy (wider PYSEC database coverage) |
| Module 2 | 4 vulnerability reports generated: Bandit, Semgrep, Trivy, OSV |
| Module 3 | DAST with OWASP ZAP — baseline + active scan against Juice Shop |
| Module 3 | ZAP: 10 alerts — 1 HIGH (SQL Injection confirmed live), 4 Medium, 3 Low, 2 Info |
| Module 3 | SQL Injection confirmed: HTTP 500 + SQLITE_ERROR on /rest/products/search |
| Module 3 | ZAP DAST report generated — 7 sections, SAST+DAST comparison, remediation roadmap |
| Module 3.5 | crAPI deployed — 10 containers, REST + community + workshop services |
| Module 3.5 | BOLA confirmed: User 2 token accessed User 1 vehicle GPS via UUID swap |
| Module 3.5 | OTP brute force: account takeover via unprotected v2 endpoint (no rate limit) |
| Module 3.5 | JWT alg:none bypass (Phase 1): forged unsigned token accepted — user profile data returned |
| Module 3.5 | Excessive data exposure: community posts leak email + vehicleid for all users |
| Module 3.5 | Attack chain documented: data exposure → BOLA → JWT forgery → account takeover |
| Module 3.5 | Phase 2 — jwt_tool: RS256 decoded; alg:none attack confirmed critical via automated tooling |
| Module 3.5 | Phase 2 — kiterunner: 0 endpoints discovered (3 scans, 91k probes each) — non-standard path structure evades wordlists |
| Module 3.5 | Phase 2 — ZAP OpenAPI scan blocked (spec not exposed via HTTP); vAPI excluded (upstream migration bug) |
| Module 4 | Burp Suite proxy configured, all traffic intercepted |
| Module 4 | SQLi admin login bypass and UNION data extraction via Repeater |
| Module 4 | Stored XSS confirmed in product review form |
| Module 4 | IDOR: accessed other users' baskets by incrementing basket ID |
| Module 4.5 | ModSecurity CRS WAF deployed — SQLi and XSS blocked with 403 on port 3001 |
| Module 4.5 | WAF anomaly scoring validated: CRS rules 942100/941100 firing correctly |
| Module 4.5 | IDOR confirmed unblocked by WAF — logic flaw, not a payload pattern |
| Module 4.6 | Custom RASP (rasp-hook.js) deployed — SQLi blocked at Sequelize hook level |
| Module 4.6 | AppSensor escalating response confirmed: LOG→429→403 per IP |
| Module 4.6 | Contrast RASP v3 incompatible on ARM64 + Node 24 — documented with root cause |
| Module 4.6 | Datadog ASM: libddwaf loaded, custom blocking rules deployed — 403 confirmed for SQLi/XSS/LFI |
| Module 5 | 9-tool security pipeline live — Gitleaks, Semgrep, CodeQL, SonarCloud, Trivy, OSV, Checkov, Hadolint, ZAP |
| Module 5 | SonarCloud connected: org=akhil65, project=akhil65_DSO, SONAR_TOKEN configured |
| Module 5 | ZAP DAST gated to workflow_dispatch — passive baseline scan against Juice Shop |
| Module 5 | Checkov IaC scan: Dockerfiles and docker-compose scanned against CIS Docker Benchmark |
| Module 5 | Hadolint: Dockerfile best-practice linting added to pipeline |
| Module 5 | CodeQL enabled for JS + Python via matrix strategy — results in GitHub Security tab |
| Module 6 | Vulnerable LLM app deployed — 5 endpoints covering LLM01/02/06/08/09 |
| Module 6 | Direct prompt injection confirmed: system prompt + secrets leaked via /api/chat |
| Module 6 | Indirect injection confirmed: malicious document content hijacks LLM response |
| Module 6 | Overreliance: LLM used as auth gate — DENY flipped to ALLOW via injection |
| Module 6 | Excessive agency: LLM triggered delete_file + send_email without confirmation |
| Module 6 | Garak + SecLists LLM wordlist automated sweep integrated |
| Module 6 | LLM Guard input scanner deployed as defense layer |
| Module 7 | Module scaffolding complete — 10 exercises, Frida scripts, docker-compose, README (not yet run) |
| Module 7 | 7.1 — MobSF static analysis: DIVA scored 36/100, 5 HIGH (debuggable, Janus, debug cert, minSdk=15), 7 WARNING (exported APICredsActivity/APICreds2Activity/NotesProvider, raw SQL, external storage write), 0 trackers |
| Module 7 | 7.2 — jadx decompilation: 651 Java files extracted; HardcodeActivity exposes "vendorsecretkey" in plain Java; APICredsActivity hardcodes API Key/user/pass in TextView onCreate(); Hardcode2Activity delegates to native libdivajni.so (credential not in Java — requires strings on .so); pkey/notespin SharedPreferences key confirmed in AccessControl3Activity |
| Module 7 | 7.3 — ADB exploitation: APICredsActivity + APICreds2Activity launched without auth; SharedPrefs XML pulled (user=diva, password=123 in plaintext); SQLite DBs confirmed (divanotes.db, ids2); credit card logged in plaintext via diva-log tag (MSTG-STORAGE-3) |
| Module 7 | 7.4 — Frida dynamic hooks (CLI): storage-interceptor confirmed SharedPreferences.putString fired with key=password/value in real time (MSTG-STORAGE-1); root-detection-bypass spoofed Build.TAGS test-keys→release-keys and Build.FINGERPRINT on load (MSTG-RESILIENCE-1); Python create_script API incompatible with Frida 17 — hooks run via frida -l CLI instead |
| Module 7 | 7.5 — SSL pinning bypass: mitmproxy (native) intercepted HTTPS traffic; DIVA has no OkHttp3 pinning (ClassNotFoundException expected); universal TrustManager bypass loaded via Frida; mitmproxy CA cert installed on emulator; full HTTPS request/response decrypted and confirmed in mitmdump (MSTG-NETWORK-4) |
| Module 7 | 7.6 — MobSF iOS static analysis: iGoat-Swift v1.0 scanned (hash e73a7bf48e); NSAllowsArbitraryLoads=true confirmed (ATS fully disabled, MSTG-NETWORK-2 critical); iGoat:// URL scheme unverified hijack surface (MSTG-PLATFORM-1); Realm.framework embedded; min iOS 10.0; binary protections parsed via MobSF |
| Module 7 | 7.8 — AI API key extraction: 3-phase scan (ZIP resources, DEX string table, jadx source) run against DIVA; 160 text files + 11,413 DEX strings + 651 Java files scanned; 0 keys found (expected — DIVA has no LLM integration); technique proven — same tool finds sk-/sk-ant-/AIza keys in real AI apps instantly |
| Module 7 | 7.9 — On-device ML model extraction: TFLite FlatBuffer detected and extracted from APK ZIP without auth; CONV_2D + DEPTHWISE_CONV_2D + FULLY_CONNECTED layers identified (MobileNet-style CV model); INT8 quantisation confirmed; class labels leaked from metadata; Phase 4 live inference skipped (TF/NumPy 2.x incompatibility — env issue, not exercise issue) |
| Module 7 | 7.10 — Prompt injection via mobile API interception: 5 injection payloads demonstrated (direct override, system prompt extraction, role escalation, data exfiltration, multi-turn anchor); complete mobile AI attack chain documented: key extraction (7.8) + model theft (7.9) + traffic intercept + injection (7.10); no server-side barrier when mobile client is sole enforcement layer (LLM01/02/06, MSTG-ARCH-6) |
| Module 7 | ✅ MODULE COMPLETE — 10 exercises, 16 confirmed findings, DIVA + iGoat-Swift + tflite-demo targets, MobSF + jadx + ADB + Frida + mitmproxy toolchain |

---

## License

MIT — for educational use only. Do not deploy vulnerable targets on public networks.
