#!/usr/bin/env python3
"""
Exercise 7.8 — AI Mobile Security: API Key Extraction from APK
===============================================================
Demonstrates how an attacker extracts LLM API keys (OpenAI, Anthropic,
Gemini, Cohere) from a mobile app's APK — one of the most common
vulnerabilities in AI-powered mobile applications.

  Phase 1 — Pattern-based key extraction (no decompilation)
    Treats the APK as a ZIP and scans all text files and resources
    for API key patterns using regex. Finds keys in:
      res/raw/config.json
      res/values/strings.xml
      assets/config.yaml / .env
      AndroidManifest.xml (API endpoints as metadata)

  Phase 2 — DEX bytecode string extraction
    Extracts all printable strings from the DEX bytecode file directly,
    without decompilation. Many keys survive ProGuard obfuscation because
    string literals are not renamed — only class/method names are.

  Phase 3 — jadx source search (if available)
    If jadx is installed, runs targeted decompilation and searches the
    Java source for key assignments and BuildConfig constants.

  Phase 4 — Blast radius assessment
    Given an extracted key, demonstrates what an attacker can do:
      - Query the API directly (verify the key is live)
      - Estimate account exposure (model access, spend limits)
      - Check for overly permissive scopes (organisation-level keys)

REAL-WORLD CONTEXT:
  API key hardcoding in mobile apps is endemic. A 2023 study found that
  ~15% of Android apps on the Play Store containing calls to LLM APIs
  had the API key directly in the APK. The reasons:
    - Developers copy code from tutorials that use hardcoded keys
    - "It's a mobile app, users can't see the source" (incorrect)
    - Build pipelines don't have a secrets-scanning step for mobile
    - The key works in development and no one removes it before release

  Real-world incidents: in 2023–2024 multiple AI assistant apps were found
  to have hardcoded OpenAI keys that, once extracted, were used to burn
  through the developer's API quota. Some keys had organisation-level
  access — exposing all projects and all team members' work.

  The correct fix: never embed API keys in mobile apps. Use a backend
  proxy: the mobile app calls YOUR backend, YOUR backend calls the LLM API.
  Your key never leaves your server.

Run:
  python exercises/7.8-ai-apk-key-extraction.py
  python exercises/7.8-ai-apk-key-extraction.py --apk targets/diva-beta.apk
  python exercises/7.8-ai-apk-key-extraction.py --apk targets/ai-demo-app.apk
"""

import os
import re
import sys
import json
import struct
import zipfile
import argparse
from pathlib import Path

# ── API key patterns for all major LLM providers ─────────────────────────────
# Format: (regex, provider, severity, notes)
API_KEY_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{48,}',                      "OpenAI API key",         "CRITICAL",
     "Full API access. Check if org-level (sk-org-...)."),
    (r'sk-ant-[a-zA-Z0-9\-_]{90,}',               "Anthropic API key",      "CRITICAL",
     "Grants full Claude API access. Cannot be scoped below account level."),
    (r'AIza[0-9A-Za-z\-_]{35}',                   "Google/Gemini API key",  "CRITICAL",
     "May also grant access to Maps, Firebase, other Google APIs."),
    (r'[a-zA-Z0-9]{40}\.cohere\.ai',              "Cohere API key",         "HIGH",
     "Access to all Cohere models and fine-tuning."),
    (r'hf_[a-zA-Z0-9]{36,}',                      "HuggingFace token",      "HIGH",
     "Read/write access to HF Hub repos if write token."),
    (r'Bearer\s+[a-zA-Z0-9\-_]{40,}',             "Bearer token",           "HIGH",
     "Could be any API. Context determines severity."),
    (r'(?i)(api[_\-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9\-_]{20,})["\']',
                                                   "Generic API key",        "MEDIUM",
     "Provider unknown. Validate manually."),
    (r'(?i)(openai|anthropic|gemini|cohere|llm)[_\-]?(api[_\-]?)?key\s*[=:]\s*["\']([^\'"]{10,})["\']',
                                                   "LLM key (named var)",    "CRITICAL",
     "Key in named variable — high confidence."),
    (r'sk-proj-[a-zA-Z0-9\-_]{48,}',              "OpenAI Project key",     "CRITICAL",
     "Project-scoped key. Still grants full model access within project."),
    (r'(?i)OPENAI_API_KEY\s*[=:]\s*["\']?([a-zA-Z0-9\-_]{20,})',
                                                   "OPENAI_API_KEY env var", "CRITICAL",
     "Bundled .env or config file with API key as environment variable."),
]

SCAN_EXTENSIONS = {".json", ".xml", ".yaml", ".yml", ".properties",
                   ".txt", ".cfg", ".ini", ".env", ".plist", ".html", ".js"}

# ── Phase 1: ZIP/resource scan ─────────────────────────────────────────────

def scan_apk_resources(apk_path: str) -> list:
    findings = []
    print("\n[Phase 1] APK Resource Scan (no decompilation)")
    print("─" * 60)

    with zipfile.ZipFile(apk_path, 'r') as apk:
        names = apk.namelist()
        scannable = [n for n in names
                     if any(n.endswith(ext) for ext in SCAN_EXTENSIONS)
                     or 'config' in n.lower() or '.env' in n.lower()]

        print(f"  Total entries: {len(names)}")
        print(f"  Scannable (text/config): {len(scannable)}")

        for entry in scannable:
            try:
                content = apk.read(entry).decode('utf-8', errors='replace')
            except Exception:
                continue

            for pattern, provider, severity, notes in API_KEY_PATTERNS:
                for match in re.finditer(pattern, content):
                    key_val = match.group(0)[:80]
                    findings.append({
                        "phase":    "resource",
                        "provider": provider,
                        "severity": severity,
                        "key":      key_val,
                        "file":     entry,
                        "notes":    notes,
                    })
                    sev_icon = "🔴" if severity in ("CRITICAL","HIGH") else "🟠"
                    print(f"\n  {sev_icon} {provider} [{severity}]")
                    print(f"     File:  {entry}")
                    print(f"     Key:   {key_val[:60]}...")
                    print(f"     Notes: {notes}")

    if not findings:
        print("  No API keys found in resource files.")
        print("  (Expected for DIVA — it has no LLM integration)")
        print("  → Use targets/ai-demo-app.apk to see key extraction against an AI app")

    return findings

# ── Phase 2: DEX bytecode string extraction ────────────────────────────────

def extract_dex_strings(apk_path: str) -> list:
    findings = []
    print("\n[Phase 2] DEX Bytecode String Extraction")
    print("─" * 60)
    print("  Extracting string literals from classes.dex without decompilation...")
    print("  (String literals survive ProGuard — only class/method names are renamed)")

    with zipfile.ZipFile(apk_path, 'r') as apk:
        dex_files = [n for n in apk.namelist() if n.endswith('.dex')]
        print(f"  DEX files found: {dex_files}")

        for dex_name in dex_files:
            dex_data = apk.read(dex_name)
            # Extract printable ASCII strings (length >= 15)
            strings = re.findall(rb'[\x20-\x7e]{15,}', dex_data)
            decoded = [s.decode('ascii', errors='replace') for s in strings]

            key_strings = []
            for s in decoded:
                for pattern, provider, severity, notes in API_KEY_PATTERNS:
                    if re.search(pattern, s):
                        key_strings.append((s, provider, severity, notes))

            print(f"\n  {dex_name}: {len(strings)} strings extracted, "
                  f"{len(key_strings)} match key patterns")

            for s, provider, severity, notes in key_strings[:5]:
                sev_icon = "🔴" if severity in ("CRITICAL","HIGH") else "🟠"
                print(f"  {sev_icon} {provider}: {s[:70]}")
                findings.append({
                    "phase":    "dex",
                    "provider": provider,
                    "severity": severity,
                    "key":      s[:80],
                    "file":     dex_name,
                    "notes":    notes,
                })

    if not findings:
        print("  No API key patterns found in DEX string table.")

    return findings

# ── Phase 3: jadx source search ─────────────────────────────────────────────

def jadx_source_search(apk_path: str) -> list:
    import subprocess
    findings = []
    print("\n[Phase 3] jadx Source Search")
    print("─" * 60)

    try:
        subprocess.run(["jadx", "--version"], capture_output=True, timeout=5, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("  jadx not installed — skipping (see Exercise 7.2 for install instructions)")
        return []

    out_dir = Path("reports/7.8-jadx-output")
    if not (out_dir.exists() and any(out_dir.rglob("*.java"))):
        print(f"  Decompiling with jadx → {out_dir} ...")
        subprocess.run(["jadx", "-d", str(out_dir), apk_path],
                       capture_output=True, timeout=120, check=False)

    java_files = list(out_dir.rglob("*.java"))
    print(f"  Searching {len(java_files)} Java files for API key patterns...")

    for java_file in java_files:
        content = java_file.read_text(errors='replace')
        for pattern, provider, severity, notes in API_KEY_PATTERNS:
            for match in re.finditer(pattern, content):
                line_no = content[:match.start()].count('\n') + 1
                val = match.group(0)[:80]
                findings.append({
                    "phase":    "jadx",
                    "provider": provider,
                    "severity": severity,
                    "key":      val,
                    "file":     str(java_file.relative_to(out_dir)),
                    "line":     line_no,
                    "notes":    notes,
                })
                sev_icon = "🔴" if severity in ("CRITICAL","HIGH") else "🟠"
                print(f"  {sev_icon} {provider} [{severity}]")
                print(f"     {java_file.relative_to(out_dir)}:{line_no}")
                print(f"     {val[:70]}")

    if not findings:
        print("  No API key patterns found in decompiled source.")
    return findings

# ── Phase 4: Blast radius ────────────────────────────────────────────────────

def assess_blast_radius(findings: list):
    print("\n[Phase 4] Blast Radius Assessment")
    print("─" * 60)

    if not findings:
        print("  No keys found — no blast radius to assess.")
        print("  (To see this phase in action, test against targets/ai-demo-app.apk)")
        return

    critical = [f for f in findings if f['severity'] == 'CRITICAL']
    print(f"  {len(critical)} CRITICAL severity keys found.\n")

    for f in critical[:3]:
        provider = f['provider']
        key = f['key']
        print(f"  ┌─ {provider} ─────────────────────────────────────────────")
        print(f"  │  Key:    {key[:50]}...")
        print(f"  │  Source: {f['file']}")
        print(f"  │")
        print(f"  │  What an attacker can do:")

        if "OpenAI" in provider:
            print(f"  │    1. Call any GPT-4/GPT-4o endpoint at YOUR account's cost")
            print(f"  │    2. Access your fine-tuned models and training data")
            print(f"  │    3. Read your assistant configurations and file uploads")
            print(f"  │    4. If org key (sk-org-...): access ALL team members' data")
            print(f"  │    5. Burn quota: GPT-4 at max throughput = ~$500/hour")
        elif "Anthropic" in provider:
            print(f"  │    1. Call Claude API at YOUR account's cost")
            print(f"  │    2. No per-key scoping — full account access")
            print(f"  │    3. Access billing info via /v1/usage endpoint")
        elif "Google" in provider:
            print(f"  │    1. Access Gemini API at YOUR quota/cost")
            print(f"  │    2. Key likely also valid for Maps, Firebase, other GCP APIs")
            print(f"  │    3. Use key to enumerate enabled APIs: gcloud services list")
        elif "HuggingFace" in provider:
            print(f"  │    1. Read all private models and datasets in your org")
            print(f"  │    2. Write token: push malicious model to your namespace")
            print(f"  │    3. Access private spaces (hosted demos)")

        print(f"  │")
        print(f"  │  Immediate remediation:")
        print(f"  │    1. Revoke this key NOW at the provider's dashboard")
        print(f"  │    2. Review API usage logs for unauthorised calls")
        print(f"  │    3. Move to backend proxy architecture (key never in APK)")
        print(f"  └───────────────────────────────────────────────────────────\n")

    print("""
  ARCHITECTURAL FIX:
    Mobile app  →  YOUR backend API  →  LLM provider API
                   (key stored here,      (key never in APK)
                    server-side only)

    Backend validates: user auth, rate limiting, input sanitisation
    LLM key is an environment variable in your cloud function / server
    Rotation: rotate the key without shipping a new APK version
""")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Exercise 7.8 — AI APK Key Extraction")
    parser.add_argument("--apk", default="targets/DivaApplication.apk", help="Path to APK")
    args = parser.parse_args()

    print("=" * 70)
    print("Exercise 7.8 — AI Mobile Security: API Key Extraction from APK")
    print(f"Target: {args.apk}")
    print("=" * 70)

    apk_path = args.apk
    if not Path(apk_path).exists():
        print(f"\n[ERROR] APK not found: {apk_path}")
        print("Download DIVA: curl -L -o targets/diva-beta.apk \\")
        print("  https://github.com/payatu/diva-android/raw/master/DivaApplication.apk")
        sys.exit(1)

    all_findings = []
    all_findings += scan_apk_resources(apk_path)
    all_findings += extract_dex_strings(apk_path)
    all_findings += jadx_source_search(apk_path)

    # Deduplicate
    seen_keys = set()
    deduped = []
    for f in all_findings:
        k = f['key'][:40]
        if k not in seen_keys:
            seen_keys.add(k)
            deduped.append(f)

    assess_blast_radius(deduped)

    # Save
    out = Path("reports/7.8-key-extraction.json")
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(deduped, indent=2))

    print("=" * 70)
    print(f"Total unique findings: {len(deduped)}")
    print(f"Report saved: {out}")
    print("Next: Exercise 7.9 — On-device ML model extraction")
    print("=" * 70)

if __name__ == "__main__":
    main()
