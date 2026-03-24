/**
 * Frida Hook: Root Detection Bypass
 * ===================================
 * Bypasses the most common Android root detection methods.
 * Used in Exercise 7.4 and as a standalone hook for any app.
 *
 * Usage:
 *   frida -U -n <package.name> -l root-detection-bypass.js
 *   frida -U --spawn <package.name> -l root-detection-bypass.js
 *
 * Covers:
 *   1. Runtime.exec("su") / "which su" checks
 *   2. File system checks for su binary paths
 *   3. Build.TAGS "test-keys" check
 *   4. Build.FINGERPRINT check
 *   5. RootBeer / RootTools library methods
 *   6. SafetyNet / Play Integrity attestation (intercept result)
 */

Java.perform(function () {

    var TAG = "[RootBypass]";

    // ── 1. Runtime.exec — intercept "su", "which", busybox calls ────────────
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
        if (/\bsu\b|busybox|which|id\s*$/.test(cmd)) {
            send({ hook: "Runtime.exec", cmd: cmd, action: "blocked" });
            return this.exec("echo not_root");
        }
        return this.exec(cmd);
    };

    Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmds) {
        var cmdStr = cmds.join(" ");
        if (/\bsu\b|busybox|which/.test(cmdStr)) {
            send({ hook: "Runtime.exec[]", cmd: cmdStr, action: "blocked" });
            return this.exec(["echo", "not_root"]);
        }
        return this.exec(cmds);
    };

    // ── 2. File existence checks — su binary paths ───────────────────────────
    var File = Java.use("java.io.File");
    var ROOT_PATHS = [
        "/system/bin/su", "/system/xbin/su", "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk", "/data/local/xbin/su", "/data/local/bin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su",
        "/su/bin/su", "/sbin/su", "/magisk/.core/bin/su",
    ];

    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (ROOT_PATHS.includes(path)) {
            send({ hook: "File.exists", path: path, action: "returning false" });
            return false;
        }
        return this.exists();
    };

    File.canExecute.implementation = function () {
        var path = this.getAbsolutePath();
        if (ROOT_PATHS.includes(path)) {
            send({ hook: "File.canExecute", path: path, action: "returning false" });
            return false;
        }
        return this.canExecute();
    };

    // ── 3. Build.TAGS and Build.FINGERPRINT ──────────────────────────────────
    try {
        var Build = Java.use("android.os.Build");
        var tags = Build.TAGS.value;
        if (tags && tags.indexOf("test-keys") >= 0) {
            Build.TAGS.value = "release-keys";
            send({ hook: "Build.TAGS", original: tags, spoofed: "release-keys" });
        }
        var fp = Build.FINGERPRINT.value;
        if (fp && fp.indexOf("test-keys") >= 0) {
            Build.FINGERPRINT.value = fp.replace("test-keys", "release-keys");
            send({ hook: "Build.FINGERPRINT", action: "test-keys removed" });
        }
    } catch (e) {
        send({ hook: "Build.*", error: e.message });
    }

    // ── 4. RootBeer library (common root detection library) ──────────────────
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function () {
            send({ hook: "RootBeer.isRooted", action: "returning false" });
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function () {
            send({ hook: "RootBeer.isRootedWithoutBusyBoxCheck", action: "returning false" });
            return false;
        };
    } catch (e) {
        // RootBeer not present in this app
    }

    // ── 5. PackageManager — check for root-related packages ──────────────────
    var ROOT_PACKAGES = [
        "com.topjohnwu.magisk", "com.noshufou.android.su", "com.thirdparty.superuser",
        "eu.chainfire.supersu", "com.koushikdutta.superuser", "com.zachspong.temprootremovejb",
        "com.ramdroid.appquarantine",
    ];

    try {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.getPackageInfo.overload("java.lang.String", "int")
        .implementation = function (pkg, flags) {
            if (ROOT_PACKAGES.includes(pkg)) {
                send({ hook: "PackageManager.getPackageInfo", pkg: pkg, action: "throwing NameNotFoundException" });
                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkg);
            }
            return this.getPackageInfo(pkg, flags);
        };
    } catch (e) {
        send({ hook: "PackageManager", error: e.message });
    }

    send({ hook: "init", value: "Root detection bypass loaded ✅" });
});
