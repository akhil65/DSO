#!/usr/bin/env python3
"""
Exercise 7.6 — MobSF Static Analysis: iOS IPA
==============================================
Uploads the iGoat IPA to MobSF and performs iOS-specific static analysis.
No Apple device, Xcode, or developer account required — MobSF decompiles
the IPA and runs its rule engine purely from the binary and metadata.

  Phase 1 — IPA structure inspection
    An IPA is a ZIP archive containing:
      Payload/<AppName>.app/  — the app bundle
        <AppName>            — the Mach-O binary (compiled Swift/ObjC)
        Info.plist           — app metadata, URL schemes, permissions
        embedded.mobileprovision — signing profile
        *.nib / *.storyboardc — compiled UI files
        *.lproj/             — localisation strings

  Phase 2 — MobSF iOS static scan
    MobSF decompiles the Mach-O binary (class-dump for ObjC, otool for all),
    parses Info.plist, checks entitlements, and runs static rules for:
      - Insecure API usage (strcpy, sprintf, gets — memory unsafety)
      - Keychain usage and storage mode (kSecAttrAccessibleAlways = bad)
      - NSUserDefaults sensitive storage
      - ATS (App Transport Security) exceptions
      - URL scheme hijacking surface
      - Binary protection flags (PIE, stack canary, ARC)

  Phase 3 — iOS vs Android comparison
    Side-by-side comparison of what static analysis finds on each platform
    and what each platform's runtime security model protects by default.

REAL-WORLD CONTEXT:
  iOS static analysis from IPA is harder than Android from APK because:
    - Swift code is compiled to native ARM Mach-O (not DEX bytecode)
    - Decompilation produces pseudocode, not source-quality output
    - ObjC runtime still exposes method names (class-dump works)
    - Info.plist and entitlements are human-readable XML → goldmine

  In a real iOS pentest:
    The tester receives an IPA from the client (enterprise distribution,
    TestFlight build, or extracted from a jailbroken device).
    MobSF static scan is the first step — same as APK analysis.
    Runtime analysis (Exercises 7.7) requires a jailbroken device or
    a debug build signed for a specific UDID.

Run:
  docker compose up -d mobsf
  python exercises/7.6-mobsf-static-ios.py
"""

import os
import sys
import json
import zipfile
import plistlib
from pathlib import Path

import requests

MOBSF_URL  = os.getenv("MOBSF_URL", "http://localhost:8000")
MOBSF_KEY  = os.getenv("MOBSF_API_KEY", "mobsfapikey1234567890")
IPA_PATH   = os.getenv("IPA_PATH", "targets/igoat.ipa")
HEADERS    = {"Authorization": MOBSF_KEY}

# iOS-specific MASVS controls
IOS_MASVS = {
    "MSTG-STORAGE-1":   "No sensitive data in NSUserDefaults",
    "MSTG-STORAGE-2":   "No sensitive data in app container (plist, sqlite)",
    "MSTG-STORAGE-6":   "No sensitive data via iOS pasteboard",
    "MSTG-CRYPTO-1":    "No hardcoded cryptographic keys",
    "MSTG-NETWORK-2":   "TLS 1.2+ enforced (ATS not disabled)",
    "MSTG-PLATFORM-1":  "No sensitive data exposed via URL schemes",
    "MSTG-PLATFORM-6":  "WebView JavaScript disabled unless required",
    "MSTG-CODE-1":      "IPA signed with valid certificate",
    "MSTG-CODE-8":      "Binary protections: PIE + stack canary + ARC",
    "MSTG-RESILIENCE-2":"Debugger detection enabled",
}

# ── IPA structure inspection ──────────────────────────────────────────────────

def inspect_ipa_structure(ipa_path: str):
    print("\n[Phase 1] IPA Structure Inspection")
    print("─" * 60)

    path = Path(ipa_path)
    if not path.exists():
        print(f"""
  [ERROR] IPA not found: {ipa_path}

  Download iGoat IPA:
    curl -L -o targets/igoat.ipa \\
      https://github.com/OWASP/iGoat-Swift/releases/download/v1.0/iGoat-Swift.ipa

  Or build from source (Xcode required):
    git clone https://github.com/OWASP/iGoat-Swift.git
    cd iGoat-Swift && xcodebuild -scheme iGoat-Swift -sdk iphonesimulator
""")
        return False

    print(f"  File: {path.name}  ({path.stat().st_size / 1024:.1f} KB)")

    with zipfile.ZipFile(path, 'r') as ipa:
        names = ipa.namelist()
        print(f"  Total entries: {len(names)}")

        # Find Info.plist
        plist_files = [n for n in names if n.endswith("Info.plist")
                       and "Payload" in n and n.count('/') == 2]
        if plist_files:
            raw_plist = ipa.read(plist_files[0])
            try:
                plist = plistlib.loads(raw_plist)
                print(f"\n  Info.plist:")
                print(f"    Bundle ID:    {plist.get('CFBundleIdentifier', 'n/a')}")
                print(f"    App Name:     {plist.get('CFBundleDisplayName', plist.get('CFBundleName','n/a'))}")
                print(f"    Version:      {plist.get('CFBundleShortVersionString','n/a')}")
                print(f"    Min iOS:      {plist.get('MinimumOSVersion','n/a')}")

                # URL schemes
                url_types = plist.get('CFBundleURLTypes', [])
                if url_types:
                    print(f"\n    URL Schemes (potential hijack surface):")
                    for ut in url_types:
                        schemes = ut.get('CFBundleURLSchemes', [])
                        for s in schemes:
                            print(f"      {s}://  ← any app can register this scheme")

                # ATS
                ats = plist.get('NSAppTransportSecurity', {})
                if ats:
                    print(f"\n    App Transport Security:")
                    if ats.get('NSAllowsArbitraryLoads'):
                        print(f"    🔴 NSAllowsArbitraryLoads = true  (all HTTPS validation disabled)")
                    exceptions = ats.get('NSExceptionDomains', {})
                    for domain, config in list(exceptions.items())[:3]:
                        print(f"    🟠 Exception: {domain}")
                        if config.get('NSExceptionAllowsInsecureHTTPLoads'):
                            print(f"       HTTP allowed (MSTG-NETWORK-2)")

                # Permissions
                perm_keys = [k for k in plist if k.startswith("NS") and k.endswith("UsageDescription")]
                if perm_keys:
                    print(f"\n    Permission usage descriptions ({len(perm_keys)}):")
                    for k in perm_keys[:5]:
                        print(f"    {k.replace('NS','').replace('UsageDescription','')}: {plist[k][:50]}")

            except Exception as e:
                print(f"    [WARN] Could not parse Info.plist: {e}")

        # Find embedded mobile provision
        provisions = [n for n in names if n.endswith(".mobileprovision")]
        if provisions:
            print(f"\n  Provisioning profile: {Path(provisions[0]).name}")
            print(f"    (Contains signing identity, UDIDs, entitlements)")

        # Mach-O binary
        app_dirs = [n for n in names if n.startswith("Payload/") and n.count('/') == 2
                    and not n.endswith('/') and '.' not in Path(n).name]
        if app_dirs:
            print(f"\n  Mach-O binary: {app_dirs[0]}")
            print(f"    Static analysis: class-dump / otool (MobSF handles this)")
            print(f"    Dynamic analysis: Frida on jailbroken device (Exercise 7.7)")

        # Embedded frameworks
        frameworks = [n for n in names if '.framework/' in n
                      and n.endswith('.framework/')]
        print(f"\n  Embedded frameworks: {len(frameworks)}")
        for fw in frameworks[:5]:
            print(f"    {Path(fw).name}")

    return True

# ── MobSF iOS scan ────────────────────────────────────────────────────────────

def run_mobsf_ios_scan(ipa_path: str):
    print("\n[Phase 2] MobSF iOS Static Analysis")
    print("─" * 60)

    try:
        r = requests.get(MOBSF_URL, timeout=5)
        if r.status_code != 200:
            raise ConnectionError
        print(f"  MobSF: {MOBSF_URL}  ✅")
    except Exception:
        print(f"""
  [ERROR] MobSF not reachable.
  Start it: docker compose up -d mobsf
""")
        return None

    # Upload
    path = Path(ipa_path)
    print(f"  Uploading {path.name} ...")
    with open(path, "rb") as f:
        r = requests.post(
            f"{MOBSF_URL}/api/v1/upload",
            headers=HEADERS,
            files={"file": (path.name, f, "application/octet-stream")}
        )
    r.raise_for_status()
    upload = r.json()
    file_hash = upload.get("hash")
    print(f"  Hash: {file_hash}")

    # Scan
    print("  Running static analysis ...")
    r = requests.post(f"{MOBSF_URL}/api/v1/scan", headers=HEADERS,
                      data={"hash": file_hash, "file_name": path.name, "re_scan": 0})
    r.raise_for_status()
    print("  Scan complete ✅")

    # Report
    r = requests.post(f"{MOBSF_URL}/api/v1/report_json", headers=HEADERS,
                      data={"hash": file_hash})
    r.raise_for_status()
    report = r.json()

    # Save
    out = Path("reports/7.6-mobsf-ios-report.json")
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"  Full report saved: {out}")
    print(f"  MobSF UI: {MOBSF_URL}/static_analyzer/?type=ipa&checksum={file_hash}")
    return report

def print_ios_findings(report: dict):
    if not report:
        return
    print("\n[Phase 2a] iOS Security Findings")
    print("─" * 60)

    score = report.get("appsec", {})
    if isinstance(score, dict):
        print(f"  Security grade: {score.get('grade','?')}")

    # Binary protection
    binary = report.get("binary_analysis", {})
    if binary:
        print("\n  Binary protections:")
        for check, val in binary.items():
            if isinstance(val, dict):
                status = val.get("status", "")
                icon = "✅" if status == "secure" else "🔴"
                print(f"    {icon} {check}: {val.get('description','')[:60]}")

    # ATS findings
    ats = report.get("ats_analysis", {})
    if ats:
        print("\n  App Transport Security:")
        for item in (ats if isinstance(ats, list) else []):
            if isinstance(item, dict):
                sev = item.get("severity","").lower()
                icon = "🔴" if sev == "high" else "🟠"
                print(f"    {icon} {item.get('issue','')[:70]}")

    # Code findings
    for key in ["code_analysis", "ios_api"]:
        section = report.get(key, {})
        if not section:
            continue
        high = [(k, v) for k, v in section.items()
                if isinstance(v, dict) and v.get("severity","").lower() == "high"]
        if high:
            print(f"\n  [{key.replace('_',' ').upper()}] — HIGH severity:")
            for _, v in high[:5]:
                print(f"    🔴 {v.get('title','')[:70]}")
                print(f"       MASVS: {v.get('masvs','')}")

def print_ios_android_comparison():
    print("\n[Phase 3] iOS vs Android Platform Security Comparison")
    print("─" * 60)
    print("""
  ┌─────────────────────────┬──────────────────────────┬──────────────────────────┐
  │ Feature                 │ Android                  │ iOS                      │
  ├─────────────────────────┼──────────────────────────┼──────────────────────────┤
  │ App sandbox             │ Linux DAC + SELinux       │ iOS sandbox + entitlements│
  │ Storage encryption      │ File-based encryption     │ Data Protection classes  │
  │ Key storage             │ Android Keystore          │ Secure Enclave / Keychain│
  │ Inter-app comms         │ Intents (can be exported) │ URL schemes + App Groups │
  │ Decompilation ease      │ DEX → Java (near source)  │ Mach-O → pseudocode only │
  │ Runtime instrumentation │ Frida (any emulator)      │ Frida (jailbreak needed) │
  │ SSL pinning bypass      │ Frida script (emulator)   │ Frida iOS + jailbreak    │
  │ Static analysis quality │ High (readable Java)      │ Medium (ObjC class names)│
  │ Rooting/jailbreak freq  │ Common (AVD = rooted)     │ iOS 16+ very rare        │
  └─────────────────────────┴──────────────────────────┴──────────────────────────┘

  KEY INSIGHT:
    iOS is harder to test dynamically (jailbreak barrier) but has the same
    class of vulnerabilities: insecure Keychain accessibility, ATS disabled,
    URL scheme hijacking, data in NSUserDefaults, NSLog sensitive output.
    The attack surface is narrower at the OS level but the application layer
    makes the same mistakes as Android apps.

    MobSF static analysis is equally powerful for both platforms — it reads
    the binary, plist, and entitlements without needing a device.
""")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("Exercise 7.6 — MobSF Static Analysis: iOS IPA")
    print(f"Target: {IPA_PATH}")
    print("=" * 70)

    if not inspect_ipa_structure(IPA_PATH):
        sys.exit(0)

    report = run_mobsf_ios_scan(IPA_PATH)
    print_ios_findings(report)
    print_ios_android_comparison()

    print("\nNext: Exercise 7.7 — iOS dynamic analysis (architecture study)")

if __name__ == "__main__":
    main()
