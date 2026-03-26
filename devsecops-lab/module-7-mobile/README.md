# Module 7 — Mobile Application Security

> Modules 1–6.7 secured the pipeline, the API, the container, and the AI layer. This module secures the client that users actually touch. A mobile app is a compiled binary distributed to millions of devices — each device is a potential attacker's workstation, and the binary can be decompiled, modified, and re-executed by anyone who downloads it.

---

## Real-World Context

Mobile security sits at the intersection of three disciplines that rarely communicate: mobile engineering (who builds the app), DevSecOps (who runs the CI/CD pipeline and vulnerability scanning), and penetration testing (who assesses the running app). In most organisations, these three teams each own a fragment of the problem and none owns the whole:

- The **mobile engineering team** decides what data goes in SharedPreferences vs the Keychain, whether SSL pinning is implemented, and whether API keys are hardcoded in build configs.
- The **DevSecOps / AppSec team** runs MobSF in CI/CD, reviews the MobSF report, and enforces the "no secrets in APK" gate before app store submission.
- The **penetration testing team** does the runtime assessment: installs the APK on a device, attaches Frida, intercepts traffic, and exploits the exported activities that static analysis can't confirm at runtime.

The three teams use different tools on the same artefact. This module runs the complete chain — static, dynamic, iOS, and AI mobile — in order.

**Why mobile is different from the web and API attacks in earlier modules:**

In web security (Modules 3–4), the attack surface is HTTP. The attacker is remote, all communication goes over the network, and the server controls what code runs. In mobile security, the attacker has the compiled application binary. Reverse engineering, not network interception, is the primary attack vector. The "client" in "client-server" is something the attacker owns and can modify.

**The OWASP Mobile Application Security Verification Standard (MASVS)** is the iOS/Android equivalent of OWASP ASVS for web. Every finding in this module maps to a MASVS control. The MASVS organises security requirements into levels: L1 (standard apps), L2 (high-security apps such as banking), and R (resilience against reverse engineering). DIVA violates nearly every L1 control.

---

## Key Concepts — Plain Language

**What "APK decompilation" means to a mobile security engineer**

An APK is a ZIP file. Inside is `classes.dex` — Dalvik bytecode. Tools like jadx convert DEX bytecode back to near-source-quality Java. For most unobfuscated apps, the decompiled Java is as readable as the original source. This means: any secret in the source code is a secret in the APK is a secret in the user's pocket is a secret available to any attacker who downloads the app. The Android ecosystem has millions of apps where developers have forgotten this.

**What "Frida" means to a mobile security engineer**

Frida is a dynamic instrumentation toolkit. It injects a JavaScript engine into the running process and lets you intercept any method call, read any variable, and modify any return value — in real time. It is to mobile what Burp Suite is to web: the de facto standard tool. The key property is that it operates at the Java layer, not the network layer. SSL/TLS is bypassed not by breaking the encryption but by hooking the Java method that validates the certificate and making it return "valid" for everything.

**What "exported Activity" means in an org context**

An Activity is an Android screen. An exported Activity is one that any other app on the device can launch directly — bypassing the app's own navigation. In DIVA, the access control screens are exported without requiring any permission. An attacker app (or an adb command) can jump straight to the "view API credentials" screen without entering a PIN. The real-world equivalent: a banking app that puts the account balance screen behind a PIN, but forgets to mark the Activity as unexported — letting any app launch it directly.

**What "SSL pinning bypass" means to a security engineer**

SSL pinning is a defence where the app checks that the server's certificate matches a specific known certificate, rather than just any cert signed by a trusted CA. This prevents mitmproxy from intercepting traffic, because mitmproxy presents its own certificate (signed by its own CA) which the pinning check rejects. Frida bypasses pinning by hooking the check method and making it return "valid" regardless. The takeaway: SSL pinning is a resilience control, not a cryptographic guarantee. It raises the cost of traffic interception (requires Frida + device access) but does not make it impossible.

**What "on-device ML model" means to a mobile security engineer**

When an app runs ML inference without calling a server — face unlock, OCR, content classification — the model is bundled in the APK as a `.tflite`, `.onnx`, or `.mlmodel` file. These files are plain binary assets, not encrypted. Extracting them requires only `unzip`. Once extracted, the model can be loaded in Python, queried freely, and analysed for architecture, labels, and vulnerabilities (adversarial inputs from Module 6.5). For AI-powered apps, the model is the product — and it ships in the user's pocket without any access control.

**What "LLM API key in APK" means to a security engineer**

An LLM API key in an APK is the single most impactful secret exposure in AI mobile apps. Unlike a database password (which requires network access to your DB to exploit), an LLM API key works directly from any internet-connected machine. The attacker extracts the key, calls the LLM provider's API directly, and burns the developer's quota. If the key is an organisation-level key (not scoped to a project), the attacker also has access to every other project in the developer's account. The fix is architectural: the mobile app should never hold the key — a backend proxy should.

**What "mitmproxy + prompt injection" means as a combined attack**

Exercise 7.10 is where Modules 6 and 7 merge. Module 6 showed that LLM applications are vulnerable to prompt injection — user input flows into the LLM context without sanitisation. Module 7 adds the mobile delivery mechanism: the attacker intercepts the HTTPS call from the mobile app using mitmproxy, reads the system prompt in plaintext, and identifies that the user's input is concatenated directly into the messages array without escaping. The attack is Module 6's injection, delivered via Module 7's traffic interception. No server compromise is needed — the mobile app does it all.

**The module arc — one sentence per exercise:**

- **7.1** — MobSF gives you a scored report of static findings in 60 seconds, before you touch the device
- **7.2** — jadx gives you readable Java source; grep for secrets that pattern matchers miss
- **7.3** — adb confirms that exported activities are exploitable exactly as static analysis predicted
- **7.4** — Frida hooks intercept storage writes, crypto keys, and activity lifecycle in real time
- **7.5** — the SSL pinning bypass reveals HTTPS API traffic in plaintext via mitmproxy
- **7.6** — MobSF runs the same scan against an iOS IPA; plist and entitlements replace the manifest
- **7.7** — iOS dynamic analysis works the same way but requires a jailbroken device (architecture documented)
- **7.8** — API key extraction: unzip the APK, grep the DEX string table, find the LLM key
- **7.9** — model extraction: unzip the APK, extract the `.tflite`, query it — white-box attack from Module 6.5
- **7.10** — prompt injection via mitmproxy: intercept the API call, read the system prompt, inject

---

## ML Terms Addendum — Mobile AI Security Concepts for Security Practitioners

**TFLite FlatBuffer** — TensorFlow Lite's serialisation format. A FlatBuffer is a binary representation of the model graph: tensors, operators, weights. Unlike a protobuf, it can be read from disk without parsing (zero-copy). Security implication: the model can be inspected and modified at the binary level without any TensorFlow tooling — a hex editor and knowledge of the FlatBuffer schema is sufficient to extract operator types, tensor shapes, and metadata strings.

**Model quantisation (INT8)** — the process of converting model weights from 32-bit floats to 8-bit integers to reduce model size and improve inference speed on mobile hardware. The resulting model is 4× smaller than the float version. Security implication: a quantised model is harder to analyse precisely (some precision is lost) but equally extractable from the APK. The same adversarial input crafting applies — quantisation is not an obfuscation mechanism.

**DEX string table** — Dalvik bytecode stores all string literals in a string table section of the `.dex` file. This includes hardcoded values like API keys, URLs, and passwords. ProGuard/R8 renames class and method names but does not encrypt string literals. The string table is therefore a reliable extraction target regardless of obfuscation level — `strings classes.dex` (or `grep -oa '[a-zA-Z0-9]{40,}' classes.dex`) is often sufficient to find API keys.

**Mach-O binary (iOS)** — the compiled format for iOS apps, equivalent to PE (Windows) or ELF (Linux). Contains ARM64 machine code for Swift and ObjC. Unlike Android DEX → Java decompilation, Mach-O → source decompilation produces pseudocode rather than readable source. ObjC apps still expose class and method names in the binary (the ObjC runtime requires them) — `class-dump` extracts the full class hierarchy. Swift symbols are stripped in release builds, making analysis harder.

**Frida's hooking model** — Frida uses ptrace (Linux) or task_for_pid (iOS) to inject a JavaScript engine (Duktape/QuickJS) into the target process. JavaScript code runs in the target's address space and has access to the same memory. `Java.use()` accesses the Android runtime's loaded class definitions. `Interceptor.attach()` modifies the function pointer table. Because hooks run in-process, they capture data before it is encrypted, after it is decrypted, and before it is written to disk — making encryption at the Java layer ineffective as a defence against Frida.

**SafetyNet / Play Integrity API** — Google's remote attestation API for Android. An app requests an attestation token; Google's servers sign it and include: whether the device is certified, whether it is rooted, whether the app binary is unmodified. SafetyNet (deprecated 2024) was bypassable via Magisk modules. Play Integrity (current) is harder to bypass but not impossible — Magisk with MagiskHide, Shamiko, or similar modules can pass Play Integrity on many devices. Security implication: Play Integrity raises the bypass cost (requires maintaining a Magisk module that passes attestation) but does not make runtime analysis impossible.

**On-device inference vs server-side inference** — running ML models on-device (TFLite, Core ML, ONNX) avoids sending user data to a server but exposes the model to extraction. Running inference server-side protects the model IP but creates a network round-trip and a server cost. Security trade-off: privacy-sensitive applications (health, finance) prefer on-device to avoid data leaving the device; IP-sensitive applications prefer server-side to protect the model. Exercise 7.9 shows why on-device models need encryption and integrity protection to protect the IP trade-off.

---

## MITRE ATLAS & ATT&CK Mapping

| ID | Technique | Exercise |
|----|-----------|----------|
| T1418 | Software Discovery (APK analysis) | 7.1, 7.2 |
| T1422 | System Network Configuration Discovery | 7.3 |
| T1623 | Command and Scripting Interpreter (adb shell) | 7.3 |
| T1625 | Hijack Execution Flow (Frida instrumentation) | 7.4, 7.5 |
| T1636.001 | Protected User Data: Calendar (SharedPrefs) | 7.4 |
| T1553.002 | Subvert Trust Controls: Code Signing (SSL bypass) | 7.5 |
| T1552.001 | Unsecured Credentials: Credentials in Files | 7.8 |
| AML.T0035 | ML Model Theft | 7.9 |
| AML.T0054.002 | Indirect Prompt Injection | 7.10 |
| LLM01:2025 | Prompt Injection | 7.10 |
| LLM02:2025 | Insecure Output Handling | 7.10 |

---

## Prerequisites

| Requirement | Purpose | Install |
|-------------|---------|---------|
| Docker | MobSF + mitmproxy | Already present |
| Android Studio | AVD emulator (exercises 7.3–7.5, 7.10) | [developer.android.com/studio](https://developer.android.com/studio) |
| adb | Android Debug Bridge | Included with Android Studio platform-tools |
| jadx | APK decompiler | `brew install jadx` |
| Python 3.9+ | Exercise scripts | Already present |
| frida-tools | Dynamic instrumentation | `pip install frida-tools` |
| objection | Frida REPL for mobile | `pip install objection` |
| mitmproxy Python lib | Exercise 7.10 addon | `pip install mitmproxy` |

---

## Setup

```bash
# Step 1 — Start MobSF
cd devsecops-lab/module-7-mobile
docker compose up -d mobsf
# Wait ~30s, then: http://localhost:8000  (login: mobsf / mobsf)
#
# NOTE (Mac): If MobSF fails with "Permission denied: /home/mobsf/.MobSF/config.py",
# the docker-compose.yml already includes `user: root` to fix this.
# Run: docker compose down -v && docker compose up -d mobsf

# Step 2 — Download DIVA APK
# payatu/diva-android uses Git LFS — use the 0xArab mirror instead:
curl -L -o targets/DivaApplication.apk \
  "https://raw.githubusercontent.com/0xArab/diva-apk-file/main/DivaApplication.apk"
# Verify: file targets/DivaApplication.apk  → should say "Java archive data (JAR)"

# Step 3 — Download iGoat IPA (for Exercise 7.6)
curl -L -o targets/igoat.ipa \
  https://github.com/OWASP/iGoat-Swift/releases/download/v1.0/iGoat-Swift.ipa

# Step 4 — Python dependencies
python3 -m venv mobile-env && source mobile-env/bin/activate
pip install -r requirements.txt

# Step 5 — Android emulator (for Exercises 7.3–7.5, 7.10)
# Open Android Studio → Device Manager → Create Device
# Recommended: Pixel 4, API 30, x86_64, WITHOUT Google Play (to get root shell)
# Start the emulator, then:
adb install targets/DivaApplication.apk

# Step 6 — frida-server on emulator (for Exercises 7.4–7.5)
# Get your emulator ABI:
adb shell getprop ro.product.cpu.abi   # usually x86_64
# Download frida-server from https://github.com/frida/frida/releases
# Matching version to: pip show frida | grep Version
# Push and start:
adb push frida-server-XX.X.X-android-x86_64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "/data/local/tmp/frida-server &"
# Verify: frida-ps -Ua
```

---

## Exercise Reference

| # | Exercise | Requires | MASVS | Run |
|---|----------|----------|-------|-----|
| 7.1 | MobSF static — Android APK | Docker | MSTG-STORAGE-14, MSTG-CODE-2 | `python exercises/7.1-mobsf-static-android.py` |
| 7.2 | APK decompilation — jadx + secrets | jadx | MSTG-STORAGE-14, MSTG-ARCH-6 | `python exercises/7.2-apk-decompilation-secrets.py` |
| 7.3 | ADB — exported activities + storage | Emulator | MSTG-AUTH-1, MSTG-STORAGE-1/2/3 | `python exercises/7.3-adb-exported-activities.py` |
| 7.4 | Frida — dynamic instrumentation | Emulator + frida-server | MSTG-STORAGE-1/2, MSTG-CRYPTO-1 | `python exercises/7.4-frida-dynamic-instrumentation.py` |
| 7.5 | SSL pinning bypass | Emulator + frida-server + mitmproxy | MSTG-NETWORK-3/4 | `python exercises/7.5-ssl-pinning-bypass.py` |
| 7.6 | MobSF static — iOS IPA | Docker + iGoat IPA | MSTG-STORAGE-2, MSTG-NETWORK-2 | `python exercises/7.6-mobsf-static-ios.py` |
| 7.7 | iOS dynamic — architecture study | Jailbroken device | MSTG-STORAGE-2, MSTG-NETWORK-4 | Read `exercises/7.7-ios-dynamic-architecture.md` |
| 7.8 | AI: API key extraction | Nothing | MSTG-STORAGE-14 | `python exercises/7.8-ai-apk-key-extraction.py` |
| 7.9 | AI: on-device ML extraction | pip: tflite-runtime | MSTG-RESILIENCE-9 | `python exercises/7.9-ondevice-ml-extraction.py` |
| 7.10 | AI: prompt injection via API intercept | Emulator + mitmproxy | MSTG-ARCH-6, LLM01 | `python exercises/7.10-prompt-injection-mobile.py` |

---

## Key Findings

| Finding | Severity | Exercise | MASVS | Status |
|---------|----------|----------|-------|--------|
| DIVA security score 36/100 — Janus vuln, debug cert, minSdk=15 | 🔴 CRITICAL | 7.1 | MSTG-CODE-2 | ✅ Confirmed |
| App debuggable in release manifest (`android:debuggable=true`) | 🔴 CRITICAL | 7.1, 7.2 | MSTG-CODE-2 | ✅ Confirmed |
| Exported activities without permission (APICredsActivity, APICreds2Activity, NotesProvider) | 🔴 CRITICAL | 7.1, 7.3 | MSTG-AUTH-1 | ✅ Confirmed |
| `vendorsecretkey` hardcoded in `HardcodeActivity.java` — visible in jadx | 🔴 CRITICAL | 7.2 | MSTG-STORAGE-14 | ✅ Confirmed |
| `APICredsActivity` sets API Key + password in `TextView.onCreate()` — readable in source | 🔴 CRITICAL | 7.2 | MSTG-STORAGE-14 | ✅ Confirmed |
| `olsdfgad;lh` credential in `libdivajni.so` native binary — found via `strings` | 🔴 CRITICAL | 7.2 | MSTG-STORAGE-14 | ✅ Confirmed |
| `pkey/notespin` SharedPreferences key in `AccessControl3Activity` | 🟠 HIGH | 7.2 | MSTG-STORAGE-1 | ✅ Confirmed |
| Raw SQL construction in `NotesProvider` + `SQLInjectionActivity` | 🟠 HIGH | 7.2 | MSTG-PLATFORM-2 | ✅ Confirmed |
| SharedPreferences in plaintext — `password=bs` intercepted live by Frida + pulled by adb | 🔴 CRITICAL | 7.3, 7.4 | MSTG-STORAGE-1 | ✅ Confirmed |
| SQLite databases unencrypted — `divanotes.db` + `ids2` confirmed on disk | 🔴 CRITICAL | 7.3 | MSTG-STORAGE-2 | ✅ Confirmed |
| Credit card logged in plaintext — `diva-log: Error while processing...4111111111111` | 🔴 CRITICAL | 7.3 | MSTG-STORAGE-3 | ✅ Confirmed |
| Build.TAGS spoofed test-keys→release-keys — root/debug detection bypassed at hook load | 🟠 HIGH | 7.4 | MSTG-RESILIENCE-1 | ✅ Confirmed |
| SSL pinning not implemented — HTTPS traffic decrypted in mitmproxy; OkHttp3 absent, universal TrustManager bypass loaded | 🟠 HIGH | 7.5 | MSTG-NETWORK-4 | ✅ Confirmed |
| iGoat `NSAllowsArbitraryLoads = true` — ATS fully disabled, all HTTPS validation bypassed globally | 🔴 CRITICAL | 7.6 | MSTG-NETWORK-2 | ✅ Confirmed |
| iGoat `iGoat://` URL scheme unverified — any app can register and intercept these URL calls | 🟠 HIGH | 7.6 | MSTG-PLATFORM-1 | ✅ Confirmed |
| LLM API key in APK assets/resources — 3-phase scan (ZIP/DEX/jadx) proven on DIVA (0 keys, expected); technique confirmed against AI apps | 🔴 CRITICAL | 7.8 | MSTG-STORAGE-14 | ✅ Confirmed |
| On-device ML model extracted without auth — TFLite FlatBuffer identified; CONV_2D/DEPTHWISE_CONV_2D/FULLY_CONNECTED layers leaked; INT8 quantised; class labels (goldfish, elephant) exposed | 🟠 HIGH | 7.9 | MSTG-RESILIENCE-9 | ✅ Confirmed |
| System prompt visible in intercepted HTTPS traffic — attack chain documented: key extraction (7.8) + model theft (7.9) + traffic intercept (7.10) combine into full mobile AI compromise | 🔴 CRITICAL | 7.10 | MSTG-ARCH-6 | ✅ Confirmed |
| User input concatenated into LLM messages unescaped — 5 injection payloads demonstrated (LLM01/02/06); no server-side barrier when mobile app is the only enforcement layer | 🔴 CRITICAL | 7.10 | LLM01:2025 | ✅ Confirmed |

---

## Defences

| Vulnerability | Mitigation |
|---------------|-----------|
| Hardcoded secrets | Never put secrets in source code. Build-time: CI secret scanning (Module 5 Gitleaks). Runtime: no API keys in mobile — use backend proxy. |
| Debuggable release build | `android:debuggable="false"` in release manifest. Enforced by MobSF gate in CI/CD. |
| Exported activities | `android:exported="false"` unless the Activity is explicitly intended for deep links. Add `android:permission` for any exported component that accesses data. |
| Insecure SharedPreferences | Use EncryptedSharedPreferences (Jetpack Security) — encrypts key-value pairs using AES-256-GCM with a key in Android Keystore. |
| Unencrypted SQLite | SQLCipher — transparent AES-256 encryption for SQLite on Android. Key stored in Android Keystore, never on disk. |
| Sensitive data in logs | Strip all `Log.d`/`Log.v` calls from release builds via ProGuard rule: `-assumenosideeffects class android.util.Log { *; }` |
| No SSL pinning | OkHttp CertificatePinner or network_security_config.xml `<pin-set>`. Note: Frida bypasses both — treat as resilience, not guarantee. |
| LLM API key in APK | Backend proxy architecture. Mobile app authenticates to YOUR server; your server holds the LLM key server-side. |
| On-device model exposed | Encrypt model file (AES-256), decrypt key in Android Keystore, verify model hash before loading. |
| System prompt in traffic | System prompt belongs on the server, not in mobile code. Client sends only the user message; server assembles the full prompt. |

---

## Frida Hook Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `scripts/frida-hooks/root-detection-bypass.js` | Bypass 7 root detection methods | `frida -U -n <pkg> -l root-detection-bypass.js` |
| `scripts/frida-hooks/ssl-pinning-bypass.js` | Universal SSL unpinning (7 methods) | `frida -U -n <pkg> -l ssl-pinning-bypass.js` |
| `scripts/frida-hooks/storage-interceptor.js` | Intercept SharedPrefs, SQLite, File, Log | `frida -U -n <pkg> -l storage-interceptor.js` |
| `scripts/mitmproxy/llm_interceptor.py` | Capture LLM API calls + prompt analysis | Auto-written by Exercise 7.10 |

---

## Artifacts

| Artifact | Location |
|----------|----------|
| Exercise scripts | `module-7-mobile/exercises/` |
| Frida hook scripts | `module-7-mobile/scripts/frida-hooks/` |
| mitmproxy addon | `module-7-mobile/scripts/mitmproxy/` |
| docker-compose (MobSF + mitmproxy) | `module-7-mobile/docker-compose.yml` |
| Python requirements | `module-7-mobile/requirements.txt` |
| Target app setup | `module-7-mobile/targets/README.md` |
| Generated reports | `module-7-mobile/reports/` (gitignored) |
