#!/usr/bin/env python3
"""
Exercise 7.4 — Frida Dynamic Instrumentation
=============================================
Attaches Frida to the running DIVA process and injects JavaScript hooks
that intercept method calls at runtime:

  Hook 1 — Insecure storage intercept (MSTG-STORAGE-1/2)
    Hooks SharedPreferences.edit().putString() and SQLiteDatabase.execSQL()
    to log every key-value pair written to persistent storage in real time.

  Hook 2 — Root detection bypass (MSTG-RESILIENCE-1)
    DIVA checks for root by looking for su binary and test-keys in the
    build fingerprint. Frida hooks the check methods and forces them to
    return "not rooted" so the app continues running on a rooted emulator.

  Hook 3 — Cryptographic key intercept (MSTG-CRYPTO-1)
    Hooks javax.crypto.spec.SecretKeySpec to capture the raw key material
    when DIVA constructs an encryption key — even if the key is computed
    at runtime (not hardcoded).

  Hook 4 — Activity lifecycle intercept (MSTG-AUTH-1)
    Hooks Activity.onResume() for DIVA's access control activities to log
    when they are entered and what authentication checks (if any) they run.

REAL-WORLD CONTEXT:
  Frida is the industry-standard tool for mobile runtime analysis. Every
  mobile penetration test uses Frida for: SSL pinning bypass (Exercise 7.5),
  root detection bypass, biometric bypass, hardcoded key extraction, and
  API call interception. It is language-agnostic — the same JavaScript hook
  works against Java, Kotlin, Flutter (Dart), React Native, and Cordova apps.
  The hook runs in-process, meaning it has access to the same memory space
  as the app — no network interception required.

  The critical distinction vs static analysis:
    Static: "SharedPreferences.putString() is called with a hardcoded key."
    Dynamic (Frida): "At 14:32:03, putString('user_pin', '1234') was called
    from jakhar.aseem.diva.InsecureDataStorage1Activity.onSaveClick()"

Prerequisites:
  - Frida installed: pip install frida-tools
  - frida-server running on emulator (see setup instructions below)
  - DIVA running on emulator

Run:
  python exercises/7.4-frida-dynamic-instrumentation.py

frida-server setup (do once per emulator):
  # 1. Find emulator ABI
  adb shell getprop ro.product.cpu.abi   # usually x86_64

  # 2. Download matching frida-server from:
  #    https://github.com/frida/frida/releases
  #    frida-server-XX.X.X-android-x86_64.xz

  # 3. Push and start
  adb push frida-server-XX.X.X-android-x86_64 /data/local/tmp/frida-server
  adb shell chmod 755 /data/local/tmp/frida-server
  adb shell /data/local/tmp/frida-server &
"""

import os
import sys
import time
import subprocess

DIVA_PACKAGE = "jakhar.aseem.diva"

# ── Frida hook scripts (inlined) ──────────────────────────────────────────────

HOOK_STORAGE = """
// Hook 1: Intercept SharedPreferences and SQLite writes
// Logs every key-value pair written to persistent storage

Java.perform(function() {

    // SharedPreferences.Editor.putString
    var SharedPrefsEditor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
    SharedPrefsEditor.putString.overload('java.lang.String', 'java.lang.String')
    .implementation = function(key, value) {
        send({
            type: "SharedPreferences.putString",
            key: key,
            value: value,
            severity: "HIGH",
            masvs: "MSTG-STORAGE-1"
        });
        return this.putString(key, value);
    };

    // SharedPreferences.Editor.putInt (PIN storage)
    SharedPrefsEditor.putInt.overload('java.lang.String', 'int')
    .implementation = function(key, value) {
        send({
            type: "SharedPreferences.putInt",
            key: key,
            value: value.toString(),
            severity: "HIGH",
            masvs: "MSTG-STORAGE-1"
        });
        return this.putInt(key, value);
    };

    // SQLiteDatabase.execSQL (raw SQL — possible injection + plaintext storage)
    var SQLiteDb = Java.use("android.database.sqlite.SQLiteDatabase");
    SQLiteDb.execSQL.overload('java.lang.String').implementation = function(sql) {
        send({
            type: "SQLiteDatabase.execSQL",
            key: "raw SQL",
            value: sql,
            severity: "MEDIUM",
            masvs: "MSTG-STORAGE-2"
        });
        return this.execSQL(sql);
    };

    send({type: "hook_loaded", value: "Storage intercept hooks active"});
});
"""

HOOK_ROOT_BYPASS = """
// Hook 2: Root detection bypass
// Forces all root check methods to return "not rooted"

Java.perform(function() {

    // DIVA checks for su binary via Runtime.exec
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
            send({
                type: "root_check_intercepted",
                value: "Blocked: " + cmd + " → returning empty process"
            });
            // Return exec of a harmless command instead
            return this.exec("echo not_rooted");
        }
        return this.exec(cmd);
    };

    // Build.TAGS check ("test-keys" indicates rooted build)
    var Build = Java.use("android.os.Build");
    var tags = Build.TAGS.value;
    if (tags && tags.indexOf("test-keys") !== -1) {
        Build.TAGS.value = "release-keys";
        send({
            type: "root_check_intercepted",
            value: "Build.TAGS spoofed: test-keys → release-keys"
        });
    }

    send({type: "hook_loaded", value: "Root detection bypass active"});
});
"""

HOOK_CRYPTO = """
// Hook 3: Cryptographic key intercept
// Captures SecretKeySpec construction — extracts raw key material

Java.perform(function() {

    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    SecretKeySpec.$init.overload('[B', 'java.lang.String')
    .implementation = function(keyBytes, algorithm) {
        var hexKey = Array.from(keyBytes)
            .map(b => ('0' + (b & 0xFF).toString(16)).slice(-2))
            .join('');
        send({
            type: "SecretKeySpec",
            key: algorithm + " key",
            value: hexKey,
            severity: "CRITICAL",
            masvs: "MSTG-CRYPTO-1",
            note: "Raw key extracted at construction time — regardless of how it was derived"
        });
        return this.$init(keyBytes, algorithm);
    };

    // IvParameterSpec — capture IV alongside key
    var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
    IvParameterSpec.$init.overload('[B').implementation = function(ivBytes) {
        var hexIv = Array.from(ivBytes)
            .map(b => ('0' + (b & 0xFF).toString(16)).slice(-2))
            .join('');
        send({
            type: "IvParameterSpec",
            key: "IV",
            value: hexIv,
            severity: "INFO",
            masvs: "MSTG-CRYPTO-3"
        });
        return this.$init(ivBytes);
    };

    send({type: "hook_loaded", value: "Crypto key intercept active"});
});
"""

HOOK_ACTIVITY_LIFECYCLE = """
// Hook 4: Activity lifecycle — log when access-control activities are entered
// Demonstrates that onResume() fires even when launched externally via adb/am start

Java.perform(function() {

    var Activity = Java.use("android.app.Activity");
    Activity.onResume.implementation = function() {
        var className = this.$className;
        if (className.indexOf("jakhar.aseem.diva") !== -1) {
            send({
                type: "activity_resumed",
                value: className,
                note: "Activity entered — check if auth was verified before this point"
            });
        }
        return this.onResume();
    };

    send({type: "hook_loaded", value: "Activity lifecycle intercept active"});
});
"""

# ── Frida runner ─────────────────────────────────────────────────────────────

def check_frida():
    try:
        import frida
        print(f"  frida: {frida.__version__}  ✅")
        return frida
    except ImportError:
        print("""
[ERROR] frida not installed.

  pip install frida-tools
  # or: pip install frida

  Then set up frida-server on your emulator (see script header).
""")
        return None

def list_processes(frida_module):
    """Show DIVA process in frida device process list."""
    try:
        device = frida_module.get_usb_device(timeout=5)
        processes = device.enumerate_processes()
        diva = [p for p in processes if DIVA_PACKAGE in p.name]
        if diva:
            print(f"  DIVA process: PID {diva[0].pid}  ✅")
            return device, diva[0].pid
        else:
            print(f"  DIVA not running — launch it on the emulator first.")
            return device, None
    except Exception as e:
        print(f"  [ERROR] Frida device connection failed: {e}")
        print("  Make sure frida-server is running on the emulator:")
        print("    adb shell /data/local/tmp/frida-server &")
        return None, None

def run_hook(device, pid, hook_name: str, script_code: str, duration: int = 10):
    """Attach Frida to DIVA and run a hook for `duration` seconds."""
    import frida
    print(f"\n  ▶  Running: {hook_name} ({duration}s)")
    print(f"     Interact with the relevant DIVA challenge on the emulator now.")

    findings = []

    def on_message(message, data):
        if message['type'] == 'send':
            payload = message['payload']
            if isinstance(payload, dict):
                if payload.get('type') == 'hook_loaded':
                    print(f"     Hook loaded: {payload.get('value')}")
                else:
                    sev = payload.get('severity', 'INFO')
                    icon = {"CRITICAL": "🔴", "HIGH": "🔴", "MEDIUM": "🟠",
                            "INFO": "🔵"}.get(sev, "•")
                    print(f"     {icon} [{payload.get('type')}]")
                    print(f"        {payload.get('key', '')} = {str(payload.get('value',''))[:80]}")
                    if payload.get('masvs'):
                        print(f"        MASVS: {payload['masvs']}")
                    if payload.get('note'):
                        print(f"        Note:  {payload['note']}")
                    findings.append(payload)
        elif message['type'] == 'error':
            print(f"     [frida error] {message.get('description','')[:100]}")

    try:
        session = device.attach(pid)
        script  = session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        time.sleep(duration)
        script.unload()
        session.detach()
    except frida.ProcessNotFoundError:
        print(f"     [ERROR] DIVA process {pid} not found. Is it still running?")
    except Exception as e:
        print(f"     [ERROR] {e}")

    return findings

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("Exercise 7.4 — Frida Dynamic Instrumentation")
    print(f"Target: DIVA ({DIVA_PACKAGE})")
    print("=" * 70)

    frida = check_frida()
    if not frida:
        sys.exit(1)

    device, pid = list_processes(frida)
    if not device:
        sys.exit(1)

    if not pid:
        print("""
  Launch DIVA on the emulator:
    adb shell am start -n jakhar.aseem.diva/.MainActivity

  Then re-run this exercise.
""")
        sys.exit(1)

    all_findings = []

    print("\n[Hook 1] SharedPreferences + SQLite intercept")
    print("  → Open DIVA → Insecure Data Storage (Challenges 3–4)")
    print("  → Enter credentials and tap Save")
    all_findings += run_hook(device, pid, "Storage Intercept", HOOK_STORAGE, duration=15)

    print("\n[Hook 2] Root detection bypass")
    all_findings += run_hook(device, pid, "Root Detection Bypass", HOOK_ROOT_BYPASS, duration=5)

    print("\n[Hook 3] Cryptographic key intercept")
    print("  → Open DIVA → Hardcoding Issues Part 2 (Challenge 12)")
    all_findings += run_hook(device, pid, "Crypto Key Intercept", HOOK_CRYPTO, duration=10)

    print("\n[Hook 4] Activity lifecycle monitoring")
    print("  → adb shell am start -n jakhar.aseem.diva/.APICreds2Activity")
    all_findings += run_hook(device, pid, "Activity Lifecycle", HOOK_ACTIVITY_LIFECYCLE, duration=8)

    # Summary
    print("\n" + "=" * 70)
    print("EXERCISE 7.4 FINDINGS SUMMARY")
    print("=" * 70)
    by_masvs = {}
    for f in all_findings:
        m = f.get('masvs', 'N/A')
        by_masvs.setdefault(m, []).append(f)

    for masvs, findings in sorted(by_masvs.items()):
        print(f"\n  {masvs}:")
        for f in findings[:3]:
            print(f"    {f.get('type')}: {str(f.get('value',''))[:60]}")

    print(f"""
  KEY FINDING:
  Frida intercepts method calls INSIDE the running process — it does not
  need network access, a jailbreak-equivalent, or SSL decryption.
  It captures data BEFORE it is encrypted (Hook 3 captures the raw key
  before the cipher is initialised), BEFORE it is written to disk
  (Hook 1 captures putString before flush), and BEFORE auth is checked
  (Hook 4 logs activity entry before any onCreate auth gate).

  This is why application-level encryption of on-device data does not
  provide security against a Frida-equipped attacker on the same device.
  The defence is: never store sensitive data on-device if avoidable;
  use Android Keystore for keys (keys never leave the secure element);
  implement MSTG-RESILIENCE-1/2/3 anti-tampering checks.

  NEXT: Exercise 7.5 — SSL pinning bypass (intercept HTTPS traffic)
""")

if __name__ == "__main__":
    main()
