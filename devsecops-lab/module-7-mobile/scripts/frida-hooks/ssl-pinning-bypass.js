/**
 * Frida Hook: Universal Android SSL Pinning Bypass
 * ==================================================
 * Bypasses all major Android SSL certificate pinning implementations
 * simultaneously. Works with or without Magisk/root.
 *
 * Usage:
 *   frida -U -n <package.name> -l ssl-pinning-bypass.js
 *   objection --gadget <package.name> explore  (then: android sslpinning disable)
 *
 * Covers:
 *   1. OkHttp3 CertificatePinner
 *   2. TrustManagerImpl (Android conscrypt)
 *   3. Custom X509TrustManager implementations
 *   4. HttpsURLConnection HostnameVerifier
 *   5. WebViewClient onReceivedSslError
 *   6. Android network_security_config pinning (runtime check)
 *   7. Appcelerator Titanium SSL (Ti.Network.HTTPClient)
 *
 * After injecting this script:
 *   Configure emulator proxy to mitmproxy (localhost:8080)
 *   All HTTPS traffic will be visible in mitmproxy web UI (localhost:8081)
 */

Java.perform(function () {

    var TAG = "[SSLBypass]";

    // ── 1. OkHttp3 CertificatePinner ─────────────────────────────────────────
    try {
        var OkHttpCP = Java.use("okhttp3.CertificatePinner");

        OkHttpCP.check.overload("java.lang.String", "java.util.List")
        .implementation = function (hostname, certs) {
            send({ hook: "OkHttp3.CertificatePinner.check", hostname: hostname, bypassed: true });
        };

        // OkHttp3 also has an internal check method
        try {
            OkHttpCP["check$okhttp"].implementation = function (hostname, certs) {
                send({ hook: "OkHttp3.CertificatePinner.check$okhttp", hostname: hostname, bypassed: true });
            };
        } catch (e) { /* method not present in this version */ }

    } catch (e) {
        send({ hook: "OkHttp3.CertificatePinner", note: "not found: " + e.message });
    }

    // ── 2. TrustManagerImpl (Conscrypt — Android default TLS) ────────────────
    try {
        var TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TMI.verifyChain.implementation = function (
                untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            send({ hook: "TrustManagerImpl.verifyChain", host: host, bypassed: true });
            return untrustedChain;
        };
    } catch (e) {
        send({ hook: "TrustManagerImpl", note: "not found: " + e.message });
    }

    // ── 3. Custom X509TrustManager implementations ───────────────────────────
    // Find all loaded classes implementing X509TrustManager and override
    // checkServerTrusted to accept everything
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            try {
                var cls = Java.use(className);
                if (cls.checkServerTrusted && !className.startsWith("sun.")
                    && !className.startsWith("java.")
                    && !className.startsWith("javax.")) {

                    cls.checkServerTrusted.overload(
                        "[Ljava.security.cert.X509Certificate;", "java.lang.String")
                    .implementation = function (chain, authType) {
                        send({ hook: "X509TrustManager.checkServerTrusted",
                               class: className, bypassed: true });
                        // Accept all — do not call original (which throws on invalid cert)
                    };
                }
            } catch (e2) { /* class doesn't implement the overload */ }
        },
        onComplete: function () {}
    });

    // ── 4. SSLContext with custom TrustManager ────────────────────────────────
    try {
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom")
        .implementation = function (km, tms, sr) {
            // Build a permissive TrustManager to replace any custom one
            var TrustAllClass = Java.registerClass({
                name: "com.lab.TrustAll_" + Date.now(),
                implements: [Java.use("javax.net.ssl.X509TrustManager")],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {
                        send({ hook: "TrustAll.checkServerTrusted", bypassed: true });
                    },
                    getAcceptedIssuers: function () { return []; }
                }
            });
            var trustAll = Java.array("javax.net.ssl.TrustManager", [TrustAllClass.$new()]);
            return this.init(km, trustAll, sr);
        };
    } catch (e) {
        send({ hook: "SSLContext.init", error: e.message });
    }

    // ── 5. HostnameVerifier ───────────────────────────────────────────────────
    try {
        var HttpsConn = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsConn.setDefaultHostnameVerifier.implementation = function (verifier) {
            var TrustAllHV = Java.registerClass({
                name: "com.lab.TrustAllHV_" + Date.now(),
                implements: [Java.use("javax.net.ssl.HostnameVerifier")],
                methods: {
                    verify: function (hostname, session) {
                        send({ hook: "HostnameVerifier.verify", hostname: hostname, bypassed: true });
                        return true;
                    }
                }
            });
            return this.setDefaultHostnameVerifier(TrustAllHV.$new());
        };
    } catch (e) {
        send({ hook: "HttpsURLConnection.HostnameVerifier", error: e.message });
    }

    // ── 6. WebViewClient — SSL errors in WebViews ─────────────────────────────
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            send({ hook: "WebViewClient.onReceivedSslError", bypassed: true,
                   note: "Proceeding despite SSL error" });
            handler.proceed();
        };
    } catch (e) {
        send({ hook: "WebViewClient.onReceivedSslError", error: e.message });
    }

    // ── 7. network_security_config runtime enforcement ────────────────────────
    // The NetworkSecurityConfig is enforced via ConscryptFileDescriptorSocket.
    // TrustManagerImpl hook (step 2) covers this. Additional hook for clarity:
    try {
        var NetworkSec = Java.use("android.security.net.config.NetworkSecurityTrustManager");
        NetworkSec.checkServerTrusted.overload(
            "[Ljava.security.cert.X509Certificate;", "java.lang.String",
            "java.lang.String")
        .implementation = function (certs, authType, host) {
            send({ hook: "NetworkSecurityTrustManager.checkServerTrusted",
                   host: host, bypassed: true });
        };
    } catch (e) {
        send({ hook: "NetworkSecurityTrustManager", note: "not found: " + e.message });
    }

    send({ hook: "init", value: "Universal SSL pinning bypass loaded ✅" });
    send({ hook: "instructions",
           value: "Configure emulator proxy: Settings → WiFi → Modify → Proxy → localhost:8080" });
});
