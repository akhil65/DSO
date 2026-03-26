#!/usr/bin/env python3
"""
Exercise 7.1 — MobSF Static Analysis: Android APK
===================================================
Uploads the DIVA APK to MobSF via its REST API, triggers a static scan,
and prints a structured summary of:
  - App metadata (package name, SDK versions, permissions)
  - Security score and grade
  - High/Critical findings by category
  - MASVS control mapping for each finding
  - Hardcoded secrets detected

PIPELINE:
  APK file → MobSF /api/v1/upload → scan hash
  scan hash → MobSF /api/v1/scan    → trigger analysis
  scan hash → MobSF /api/v1/report_json → structured results

LEARNING OBJECTIVES:
  - Understand what MobSF static analysis covers and what it misses
  - Read MASVS control IDs and map them to real-world risk
  - Identify the difference between static findings that require dynamic
    confirmation vs those that are definitive from decompiled code alone

REAL-WORLD CONTEXT:
  Mobile AppSec teams run MobSF (or equivalent: Apktool + custom rules,
  Semgrep mobile rulesets, or commercial tools like NowSecure) as the
  first gate in mobile CI/CD. Every APK submitted to the internal app
  store is scanned before distribution. The MobSF REST API integrates
  directly into Jenkins/GitHub Actions — the same pattern as Trivy for
  containers and Semgrep for source code.

Run:
  docker compose up -d mobsf
  # Wait ~30s for MobSF to start
  python exercises/7.1-mobsf-static-android.py

Requirements:
  pip install requests rich
"""

import os
import sys
import json
import hashlib
import requests
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

MOBSF_URL   = os.getenv("MOBSF_URL", "http://localhost:8000")
MOBSF_KEY   = os.getenv("MOBSF_API_KEY", "mobsfapikey1234567890")
APK_PATH    = os.getenv("APK_PATH", "targets/DivaApplication.apk")

HEADERS = {"Authorization": MOBSF_KEY}

# MASVS category labels for display
MASVS_LABELS = {
    "MSTG-STORAGE": "Data Storage",
    "MSTG-CRYPTO":  "Cryptography",
    "MSTG-AUTH":    "Authentication",
    "MSTG-NETWORK": "Network Communication",
    "MSTG-PLATFORM":"Platform Interaction",
    "MSTG-CODE":    "Code Quality",
    "MSTG-RESILIENCE": "Anti-Reversing",
}

SEV_ICON = {"high": "🔴", "warning": "🟠", "info": "🔵", "secure": "✅"}

# ── Helpers ───────────────────────────────────────────────────────────────────

def check_mobsf():
    """Verify MobSF is reachable before uploading."""
    try:
        r = requests.get(f"{MOBSF_URL}", timeout=5)
        if r.status_code == 200:
            print(f"MobSF: {MOBSF_URL}  ✅")
            return True
    except requests.exceptions.ConnectionError:
        pass
    print(f"""
[ERROR] Cannot reach MobSF at {MOBSF_URL}

  Start MobSF first:
    docker compose up -d mobsf
    # Wait ~30 seconds, then re-run this script
""")
    return False

def upload_apk(apk_path: str) -> dict:
    """Upload APK to MobSF. Returns upload response with hash."""
    path = Path(apk_path)
    if not path.exists():
        print(f"""
[ERROR] APK not found: {apk_path}

  Download DIVA APK:
    curl -L -o targets/diva-beta.apk \\
      https://github.com/payatu/diva-android/raw/master/DivaApplication.apk
""")
        sys.exit(1)

    print(f"\nUploading {path.name} ({path.stat().st_size / 1024:.1f} KB) ...")
    with open(path, "rb") as f:
        r = requests.post(
            f"{MOBSF_URL}/api/v1/upload",
            headers=HEADERS,
            files={"file": (path.name, f, "application/octet-stream")}
        )
    r.raise_for_status()
    result = r.json()
    print(f"Upload complete — scan hash: {result.get('hash', 'n/a')}")
    return result

def run_scan(file_hash: str, file_name: str) -> bool:
    """Trigger static analysis scan for the uploaded file."""
    print(f"Starting static analysis ...")
    r = requests.post(
        f"{MOBSF_URL}/api/v1/scan",
        headers=HEADERS,
        data={"hash": file_hash, "file_name": file_name, "re_scan": 0}
    )
    r.raise_for_status()
    print("Scan complete ✅")
    return True

def get_report(file_hash: str) -> dict:
    """Fetch the JSON report for a completed scan."""
    r = requests.post(
        f"{MOBSF_URL}/api/v1/report_json",
        headers=HEADERS,
        data={"hash": file_hash}
    )
    r.raise_for_status()
    return r.json()

def get_scorecard(file_hash: str) -> dict:
    """Fetch security scorecard."""
    r = requests.post(
        f"{MOBSF_URL}/api/v1/scorecard",
        headers=HEADERS,
        data={"hash": file_hash}
    )
    r.raise_for_status()
    return r.json()

# ── Display ───────────────────────────────────────────────────────────────────

def print_separator(title=""):
    width = 70
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'─' * pad} {title} {'─' * pad}")
    else:
        print(f"\n{'─' * width}")

def print_app_metadata(report: dict):
    print_separator("APP METADATA")
    info = {
        "Package":        report.get("package_name", "n/a"),
        "App Name":       report.get("app_name", "n/a"),
        "Version":        report.get("version_name", "n/a"),
        "Min SDK":        report.get("min_sdk", "n/a"),
        "Target SDK":     report.get("target_sdk", "n/a"),
        "File Size":      report.get("size", "n/a"),
        "SHA256":         report.get("sha256", "n/a")[:16] + "...",
    }
    for k, v in info.items():
        print(f"  {k:<14} {v}")

def print_permissions(report: dict):
    print_separator("PERMISSIONS")
    perms = report.get("permissions", {})
    dangerous = [(p, v) for p, v in perms.items()
                 if isinstance(v, dict) and v.get("status") == "dangerous"]
    normal     = [(p, v) for p, v in perms.items()
                 if isinstance(v, dict) and v.get("status") != "dangerous"]

    print(f"  Total permissions:     {len(perms)}")
    print(f"  Dangerous permissions: {len(dangerous)}")
    if dangerous:
        print(f"\n  🔴 Dangerous:")
        for p, v in dangerous[:10]:
            desc = v.get("description", "")[:60] if isinstance(v, dict) else ""
            print(f"     {p}")
            if desc:
                print(f"       ↳ {desc}")

def print_security_findings(report: dict):
    print_separator("SECURITY FINDINGS")

    # MobSF stores findings under multiple keys depending on version
    finding_keys = ["android_api", "code_analysis", "manifest_analysis",
                    "binary_analysis", "network_security"]

    total_high = 0
    total_warn = 0

    for key in finding_keys:
        section = report.get(key, {})
        if not section:
            continue

        # Findings can be a dict of {id: {title, severity, ...}}
        if isinstance(section, dict):
            items = section.items()
        elif isinstance(section, list):
            items = enumerate(section)
        else:
            continue

        section_findings = []
        for _, finding in items:
            if not isinstance(finding, dict):
                continue
            sev = finding.get("severity", finding.get("level", "")).lower()
            if sev in ("high", "warning"):
                section_findings.append((sev, finding))
                if sev == "high":
                    total_high += 1
                else:
                    total_warn += 1

        if section_findings:
            print(f"\n  [{key.replace('_', ' ').upper()}]")
            for sev, f in section_findings[:5]:
                icon = SEV_ICON.get(sev, "•")
                title = f.get("title", f.get("issue", str(f)))[:70]
                print(f"  {icon} {title}")
                masvs = f.get("masvs", "")
                if masvs:
                    label = next((v for k, v in MASVS_LABELS.items()
                                  if k in masvs), masvs)
                    print(f"      MASVS: {masvs}  ({label})")

    print(f"\n  Summary: 🔴 {total_high} HIGH   🟠 {total_warn} WARNING")

def print_secrets(report: dict):
    print_separator("HARDCODED SECRETS / STRINGS OF INTEREST")
    secrets = report.get("secrets", [])
    if not secrets:
        # Also check strings section
        strings = report.get("strings", {})
        secrets = strings.get("secrets", []) if isinstance(strings, dict) else []

    if secrets:
        for s in secrets[:10]:
            print(f"  ⚠  {s}")
    else:
        print("  No hardcoded secrets detected by pattern matching.")
        print("  Note: Exercise 7.2 performs manual jadx decompilation to find")
        print("  secrets that pattern matching misses (e.g. obfuscated strings).")

def print_network_security(report: dict):
    print_separator("NETWORK SECURITY")
    net = report.get("network_security", {})
    if not net:
        cert_pinning = report.get("certificate_analysis", {})
        print(f"  Certificate analysis: {cert_pinning.get('summary', 'see full report')}")
        return

    findings = net if isinstance(net, list) else net.get("findings", [])
    for f in findings[:5]:
        if isinstance(f, dict):
            sev = f.get("severity", "").lower()
            print(f"  {SEV_ICON.get(sev,'•')} {f.get('issue', str(f))[:70]}")

def print_masvs_summary(report: dict):
    print_separator("MASVS CONTROL COVERAGE")
    print("""
  Controls exercised by DIVA's static findings:

  MSTG-STORAGE-1    SharedPreferences in plain text — insecure data storage Ch.3
  MSTG-STORAGE-2    SQLite database unencrypted — insecure data storage Ch.4
  MSTG-STORAGE-3    Sensitive data in logs — logging challenge Ch.1
  MSTG-STORAGE-14   Hardcoded credentials in source — hardcoding Ch.2 and Ch.12
  MSTG-NETWORK-3    Certificate validation disabled / cleartext traffic
  MSTG-PLATFORM-1   Exported activity without permission — access control Ch.9–11
  MSTG-CODE-2       App debuggable in release manifest

  Dynamic analysis (Exercises 7.3–7.5) validates runtime behaviour for:
  MSTG-AUTH-1       Access control bypass via exported activity
  MSTG-NETWORK-4    SSL pinning bypass via Frida hook
  MSTG-RESILIENCE-1 Root detection bypass
""")

def print_key_finding(report: dict):
    print_separator("KEY FINDING")
    score = report.get("appsec", {})
    # security_score is 0-100; total_trackers is MobSF's signature DB size, not findings count
    grade = f"{score.get('security_score', '?')}/100" if isinstance(score, dict) else "?"
    total = score.get("trackers", 0) if isinstance(score, dict) else 0  # actual trackers found
    print(f"""
  Static analysis with MobSF gives a security grade based on:
    Manifest configuration (exported components, debuggable flag,
    cleartext traffic permission, backup allowed)
    Code patterns (hardcoded keys, weak crypto, SQL construction)
    Permission audit (dangerous permissions without justification)
    Binary protections (PIE, stack canary, NX bit, RPATH)

  Grade: {grade}   Trackers detected: {total}

  What static analysis CANNOT tell you:
    ✗ Whether a hardcoded key is actually used in the running app
    ✗ Whether root detection can be bypassed at runtime
    ✗ Whether SSL pinning is implemented and bypassable
    ✗ What data actually gets written to disk during normal use
    → These require Exercises 7.3–7.5 (dynamic analysis with Frida + adb)

  NEXT: Run Exercise 7.2 for manual APK decompilation with jadx.
""")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("Exercise 7.1 — MobSF Static Analysis: Android APK")
    print("Target: DIVA (Damn Insecure and Vulnerable App for Android)")
    print("=" * 70)

    if not check_mobsf():
        sys.exit(1)

    # Upload
    upload_result = upload_apk(APK_PATH)
    file_hash = upload_result.get("hash")
    file_name = upload_result.get("file_name", Path(APK_PATH).name)

    if not file_hash:
        print("[ERROR] Upload did not return a scan hash.")
        sys.exit(1)

    # Scan
    run_scan(file_hash, file_name)

    # Report
    report = get_report(file_hash)

    # Display
    print_app_metadata(report)
    print_permissions(report)
    print_security_findings(report)
    print_secrets(report)
    print_network_security(report)
    print_masvs_summary(report)
    print_key_finding(report)

    # Save raw report
    out = Path("reports/7.1-mobsf-android-report.json")
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"  Full JSON report saved: {out}")
    print(f"  MobSF UI:               {MOBSF_URL}/static_analyzer/?type=apk&checksum={file_hash}")

if __name__ == "__main__":
    main()
