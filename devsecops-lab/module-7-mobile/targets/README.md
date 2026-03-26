# Module 7 — Target Applications

This directory holds the APK and IPA files used as targets in the exercises.
Files are not committed to git (listed in .gitignore) — download them manually
using the commands below.

---

## Android Target — DIVA (Damn Insecure and Vulnerable App)

DIVA is an intentionally vulnerable Android app with 13 challenges covering
every major OWASP MASTG weakness category.

```bash
# Download DIVA APK (public, ~1.4 MB)
# NOTE: payatu/diva-android uses Git LFS — the raw GitHub URL returns a 14-byte
# pointer file, not the APK. Use the 0xArab mirror which stores the binary directly:
curl -L -o targets/DivaApplication.apk \
  "https://raw.githubusercontent.com/0xArab/diva-apk-file/main/DivaApplication.apk"

# Verify it's a real APK (not an HTML error page or LFS pointer):
file targets/DivaApplication.apk   # → Java archive data (JAR)
ls -lh targets/DivaApplication.apk  # → ~1.4 MB
```

Challenges in DIVA:
| # | Challenge | MASVS Category |
|---|-----------|----------------|
| 1 | Insecure Logging | MSTG-STORAGE-3 |
| 2 | Hardcoding Issues (Part 1) | MSTG-STORAGE-14 |
| 3 | Insecure Data Storage (Part 1) | MSTG-STORAGE-1 |
| 4 | Insecure Data Storage (Part 2) | MSTG-STORAGE-2 |
| 5 | Insecure Data Storage (Part 3) | MSTG-STORAGE-3 |
| 6 | Insecure Data Storage (Part 4) | MSTG-STORAGE-4 |
| 7 | Input Validation (Part 1) | MSTG-ARCH-6 |
| 8 | Input Validation (Part 2) | MSTG-ARCH-6 |
| 9 | Access Control (Part 1) | MSTG-AUTH-1 |
| 10 | Access Control (Part 2) | MSTG-AUTH-1 |
| 11 | Access Control (Part 3) | MSTG-AUTH-1 |
| 12 | Hardcoding Issues (Part 2) | MSTG-STORAGE-14 |
| 13 | Input Validation (Part 3) | MSTG-ARCH-6 |

---

## AI Mobile Security Target — Sample AI Assistant APK

Exercise 7.8 uses a sample Android app that calls an LLM API with a hardcoded
key. A minimal demo APK is included in this repo for that exercise.

```bash
# Build the demo APK (requires Android Studio / Gradle):
# See exercises/ai-demo-app/ for the source and pre-built APK

# Pre-built APK (no Android Studio needed):
# targets/ai-demo-app.apk  — included in repo (generated, not a real app)
```

---

## AI Mobile Security Target — TFLite Model Demo APK

Exercise 7.9 extracts and queries a TensorFlow Lite model from an APK.

```bash
# A minimal APK containing a MobileNet TFLite model is provided:
# targets/tflite-demo.apk  — included in repo (pre-built)

# The embedded model file:
# assets/mobilenet_v1_1.0_224.tflite  — MobileNet image classifier, ~16 MB
```

---

## iOS Target — iGoat (Damn Vulnerable iOS App)

iGoat is the iOS equivalent of DIVA — an intentionally vulnerable iOS app
covering OWASP MASTG categories for iOS.

```bash
# Download iGoat IPA — requires free Apple Developer account to run on device
# Static analysis via MobSF works without signing or a device.

# Option 1: Build from source (requires Xcode on macOS)
git clone https://github.com/OWASP/iGoat-Swift.git
cd iGoat-Swift
xcodebuild -scheme iGoat-Swift -sdk iphonesimulator

# Option 2: Pre-built IPA from OWASP releases
# https://github.com/OWASP/iGoat-Swift/releases
# Download: iGoat-Swift.ipa  → place in targets/igoat.ipa
curl -L -o targets/igoat.ipa \
  https://github.com/OWASP/iGoat-Swift/releases/download/v1.0/iGoat-Swift.ipa
```

iGoat covers:
- Keychain data leakage
- Insecure data storage (NSUserDefaults, CoreData, plist)
- Broken cryptography (hardcoded keys, ECB mode)
- SSL pinning and certificate validation bypass
- Binary protections (missing PIE, stack canaries)
- URL scheme hijacking and deep link injection

---

## .gitignore

The following entries are already in the repo .gitignore — APK/IPA files are
not committed due to file size:

```
*.apk
*.ipa
*.aab
targets/*.apk
targets/*.ipa
```
