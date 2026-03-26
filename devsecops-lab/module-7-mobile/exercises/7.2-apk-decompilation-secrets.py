#!/usr/bin/env python3
"""
Exercise 7.2 — Manual APK Decompilation: jadx + Secrets Extraction
====================================================================
Decompiles the DIVA APK using jadx, then performs targeted source-code
analysis to find what MobSF's pattern matcher misses:

  Phase 1 — APK structure inspection (without jadx)
    Unpack the APK as a ZIP, list all files, read AndroidManifest.xml
    (binary XML decoded), identify exported components and dangerous flags.

  Phase 2 — jadx decompilation
    Run jadx to produce readable Java source. Search for:
      - Hardcoded strings (passwords, keys, tokens, URLs)
      - SQLite query construction (SQL injection surface)
      - Logging of sensitive data (Log.d/Log.v with sensitive params)
      - Insecure SharedPreferences usage (MODE_WORLD_READABLE)
      - WebView settings (setJavaScriptEnabled, addJavascriptInterface)

  Phase 3 — Findings summary mapped to MASVS controls

REAL-WORLD CONTEXT:
  Every mobile penetration test starts with APK decompilation. jadx produces
  Java source that is close to the original (for unobfuscated apps). For
  obfuscated apps (ProGuard / R8 / DexGuard), automated analysis fails and
  testers fall back to smali (Dalvik bytecode) analysis. DIVA is unobfuscated,
  making it a good baseline for understanding what decompilation reveals.

  In a real assessment: the client ships the .apk from their app store listing
  or from their CI/CD pipeline. The tester runs jadx locally — no device needed.
  Findings from this phase inform which runtime hooks (Exercise 7.4) are most
  valuable to instrument.

Run:
  # Install jadx: brew install jadx  (or download from github.com/skylot/jadx)
  python exercises/7.2-apk-decompilation-secrets.py

Requirements:
  jadx installed and on PATH
  pip install rich
"""

import os
import sys
import re
import subprocess
import zipfile
import struct
from pathlib import Path

APK_PATH    = os.getenv("APK_PATH", "targets/DivaApplication.apk")
JADX_OUT    = Path("reports/7.2-jadx-output")
REPORT_OUT  = Path("reports/7.2-decompilation-findings.txt")

# Patterns to search in decompiled source
SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*=\s*["\']([^"\']{4,})["\']',  "Hardcoded password",     "MSTG-STORAGE-14"),
    (r'(?i)(api[_-]?key|apikey)\s*=\s*["\']([^"\']{8,})["\']',   "Hardcoded API key",       "MSTG-STORAGE-14"),
    (r'(?i)(secret|token)\s*=\s*["\']([^"\']{8,})["\']',          "Hardcoded secret/token",  "MSTG-STORAGE-14"),
    (r'(?i)Log\.(d|v|i|e|w)\s*\([^,]+,\s*["\'][^"\']*(?:pass|key|token|pin)[^"\']*["\']',
                                                                    "Sensitive data in log",   "MSTG-STORAGE-3"),
    (r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE',                   "World-readable SharedPrefs","MSTG-STORAGE-1"),
    (r'(?i)rawQuery\s*\(\s*["\'][^"\']*\+',                        "SQLi risk: string concat", "MSTG-ARCH-6"),
    (r'setJavaScriptEnabled\s*\(\s*true\s*\)',                      "WebView JS enabled",      "MSTG-PLATFORM-5"),
    (r'addJavascriptInterface\s*\(',                                "WebView JS interface",    "MSTG-PLATFORM-7"),
    (r'(?i)http://(?!localhost)[^\s"\']{5,}',                       "Cleartext HTTP URL",      "MSTG-NETWORK-1"),
    (r'(?i)(trust all|trustallhosts|x509trustmanager)',             "Disabled TLS validation", "MSTG-NETWORK-3"),
]

MANIFEST_CHECKS = [
    ("android:debuggable=\"true\"",    "🔴 App is debuggable in release build",     "MSTG-CODE-2"),
    ("android:allowBackup=\"true\"",   "🟠 App data backup enabled",                "MSTG-STORAGE-8"),
    ("android:exported=\"true\"",      "🟠 Exported component (check if protected)","MSTG-PLATFORM-1"),
    ("android:usesCleartextTraffic",   "🟠 Cleartext traffic (HTTP) permitted",     "MSTG-NETWORK-2"),
    ("android:networkSecurityConfig",  "🔵 Network security config present",        "MSTG-NETWORK-2"),
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def check_jadx() -> bool:
    try:
        result = subprocess.run(["jadx", "--version"], capture_output=True, text=True, timeout=10)
        ver = result.stdout.strip() or result.stderr.strip()
        print(f"jadx: {ver}  ✅")
        return True
    except FileNotFoundError:
        print("""
[ERROR] jadx not found. Install it first:

  macOS:   brew install jadx
  Linux:   https://github.com/skylot/jadx/releases (download jadx-x.y.z.zip)
  Windows: https://github.com/skylot/jadx/releases

  Then re-run this exercise.
""")
        return False

def inspect_apk_structure(apk_path: str):
    """Phase 1 — inspect APK as a ZIP without decompiling."""
    print("\n[Phase 1] APK structure inspection")
    print("─" * 60)

    path = Path(apk_path)
    if not path.exists():
        print(f"  [ERROR] APK not found: {apk_path}")
        print("  Download: curl -L -o targets/diva-beta.apk \\")
        print("    https://github.com/payatu/diva-android/raw/master/DivaApplication.apk")
        sys.exit(1)

    print(f"  File: {path.name}  ({path.stat().st_size / 1024:.1f} KB)")

    with zipfile.ZipFile(path, 'r') as apk:
        names = apk.namelist()

    # Categorise entries
    categories = {
        "DEX (bytecode)":      [n for n in names if n.endswith(".dex")],
        "Resources (res/)":    [n for n in names if n.startswith("res/")],
        "Assets":              [n for n in names if n.startswith("assets/")],
        "Native libs (.so)":   [n for n in names if n.endswith(".so")],
        "Certificates":        [n for n in names if n.startswith("META-INF/")],
    }

    for cat, files in categories.items():
        if files:
            print(f"  {cat}: {len(files)} file(s)")
            if cat == "Native libs (.so)":
                for f in files:
                    print(f"    → {f}  (ABI: {f.split('/')[1]})")
            elif cat == "Assets":
                for f in files:
                    print(f"    → {f}")

    # ML models in assets?
    ml_files = [n for n in names if any(n.endswith(ext) for ext in
                [".tflite", ".onnx", ".mlmodel", ".pb", ".pt"])]
    if ml_files:
        print(f"\n  ⚠  ML model files detected in APK:")
        for f in ml_files:
            print(f"    → {f}  ← extractable with unzip (see Exercise 7.9)")

def decompile_with_jadx(apk_path: str) -> bool:
    """Phase 2 — run jadx to produce Java source."""
    print("\n[Phase 2] jadx decompilation")
    print("─" * 60)

    if JADX_OUT.exists() and any(JADX_OUT.rglob("*.java")):
        print(f"  Using cached decompilation: {JADX_OUT}")
        java_count = len(list(JADX_OUT.rglob("*.java")))
        print(f"  {java_count} Java source files")
        return True

    print(f"  Running: jadx -d {JADX_OUT} {apk_path}")
    result = subprocess.run(
        ["jadx", "-d", str(JADX_OUT), apk_path],
        capture_output=True, text=True, timeout=120
    )

    if result.returncode != 0:
        print(f"  [WARN] jadx exited {result.returncode}")
        print(f"  stderr: {result.stderr[:300]}")

    java_files = list(JADX_OUT.rglob("*.java"))
    print(f"  Decompiled {len(java_files)} Java source files  ✅")
    return len(java_files) > 0

def search_source_for_secrets() -> list:
    """Search decompiled Java source for secret patterns."""
    print("\n[Phase 2a] Source code secret search")
    print("─" * 60)

    java_files = list(JADX_OUT.rglob("*.java"))
    findings = []

    for pattern, label, masvs in SECRET_PATTERNS:
        regex = re.compile(pattern, re.MULTILINE)
        for java_file in java_files:
            try:
                content = java_file.read_text(errors="replace")
            except Exception:
                continue
            for match in regex.finditer(content):
                line_no = content[:match.start()].count('\n') + 1
                rel_path = java_file.relative_to(JADX_OUT)
                value = match.group(0)[:100].replace('\n', ' ')
                findings.append({
                    "severity": "HIGH" if "STORAGE-14" in masvs or "SQL" in label else "MEDIUM",
                    "label":    label,
                    "masvs":    masvs,
                    "file":     str(rel_path),
                    "line":     line_no,
                    "snippet":  value.strip(),
                })

    # Deduplicate by snippet
    seen = set()
    deduped = []
    for f in findings:
        key = f["snippet"][:50]
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    print(f"  Patterns searched: {len(SECRET_PATTERNS)}")
    print(f"  Files scanned:     {len(java_files)}")
    print(f"  Findings:          {len(deduped)}")
    return deduped

def check_manifest() -> list:
    """Read AndroidManifest.xml and flag dangerous settings."""
    print("\n[Phase 2b] AndroidManifest.xml analysis")
    print("─" * 60)

    # jadx writes decoded manifest to output/resources/AndroidManifest.xml
    manifest_paths = list(JADX_OUT.rglob("AndroidManifest.xml"))
    if not manifest_paths:
        # Fallback: read raw binary from APK (simplified check)
        print("  Manifest not found in jadx output — using raw APK check")
        with zipfile.ZipFile(APK_PATH, 'r') as apk:
            try:
                raw = apk.read("AndroidManifest.xml").decode("utf-8", errors="replace")
            except Exception:
                raw = ""
        manifest_text = raw
    else:
        manifest_text = manifest_paths[0].read_text(errors="replace")
        print(f"  Reading: {manifest_paths[0].relative_to(JADX_OUT)}")

    findings = []
    for check, label, masvs in MANIFEST_CHECKS:
        if check.lower() in manifest_text.lower():
            findings.append({"label": label, "masvs": masvs, "check": check})

    for f in findings:
        print(f"  {f['label']}")
        print(f"    MASVS: {f['masvs']}  |  trigger: {f['check']}")

    # Count exported activities
    exported = manifest_text.lower().count('android:exported="true"')
    print(f"\n  Exported components: {exported}")
    if exported > 0:
        print("""
  ⚠  Exported activities can be launched by any app on the device:
       adb shell am start -n <package>/<activity>
     Exercise 7.3 demonstrates this with DIVA's access control challenges.
""")

    return findings

def print_findings_summary(source_findings, manifest_findings):
    print("\n" + "=" * 70)
    print("FINDINGS SUMMARY")
    print("=" * 70)

    high   = [f for f in source_findings if f["severity"] == "HIGH"]
    medium = [f for f in source_findings if f["severity"] == "MEDIUM"]

    print(f"\n  🔴 HIGH:   {len(high)}")
    for f in high:
        print(f"    [{f['masvs']}] {f['label']}")
        print(f"      File:    {f['file']}")
        print(f"      Snippet: {f['snippet'][:80]}")

    print(f"\n  🟠 MEDIUM: {len(medium)}")
    for f in medium[:5]:
        print(f"    [{f['masvs']}] {f['label']}")
        print(f"      File:    {f['file']}")

    print(f"\n  📋 MANIFEST: {len(manifest_findings)} flags")
    for f in manifest_findings:
        print(f"    [{f['masvs']}] {f['label']}")

    print(f"""
  KEY FINDING:
  Static decompilation with jadx reveals hardcoded credentials, SQLi
  construction patterns, and insecure component exposure — without
  running the app. This is why obfuscation (ProGuard/R8/DexGuard)
  is a MSTG-RESILIENCE control, not a data-storage one: it makes
  reverse engineering harder, but does not fix the underlying flaws.

  What jadx CANNOT tell you:
    ✗ Runtime value of variables (only literal string assignments)
    ✗ Whether an exported activity actually performs sensitive operations
    ✗ Network traffic content (see Exercises 7.5 / 7.10)
    → Exercise 7.3 (adb) and 7.4 (Frida) cover the runtime gaps.
""")

def save_report(source_findings, manifest_findings):
    REPORT_OUT.parent.mkdir(exist_ok=True)
    lines = ["Exercise 7.2 — APK Decompilation Findings", "=" * 60, ""]
    lines.append("SOURCE CODE FINDINGS")
    for f in source_findings:
        lines += [f"  [{f['severity']}] {f['label']} ({f['masvs']})",
                  f"  File: {f['file']} line {f['line']}",
                  f"  Snippet: {f['snippet']}", ""]
    lines.append("MANIFEST FINDINGS")
    for f in manifest_findings:
        lines += [f"  {f['label']} ({f['masvs']})", ""]
    REPORT_OUT.write_text('\n'.join(lines))
    print(f"\n  Report saved: {REPORT_OUT}")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("Exercise 7.2 — Manual APK Decompilation: jadx + Secrets Extraction")
    print(f"Target: {APK_PATH}")
    print("=" * 70)

    inspect_apk_structure(APK_PATH)

    if not check_jadx():
        print("\n[Skipping Phases 2a/2b — jadx not installed]")
        print("Install jadx and re-run to get full source analysis.")
        sys.exit(0)

    if not decompile_with_jadx(APK_PATH):
        print("[ERROR] jadx decompilation produced no Java files.")
        sys.exit(1)

    source_findings   = search_source_for_secrets()
    manifest_findings = check_manifest()

    print_findings_summary(source_findings, manifest_findings)
    save_report(source_findings, manifest_findings)

if __name__ == "__main__":
    main()
