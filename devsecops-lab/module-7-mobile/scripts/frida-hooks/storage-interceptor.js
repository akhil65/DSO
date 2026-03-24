/**
 * Frida Hook: Storage Interceptor
 * =================================
 * Intercepts ALL Android storage writes in real time:
 *   SharedPreferences, SQLite, File I/O, external storage
 *
 * Usage:
 *   frida -U -n <package.name> -l storage-interceptor.js
 *
 * Output: sends messages for every storage write with key, value, and MASVS ID.
 * Run alongside the target app and interact with it to see data being written.
 */

Java.perform(function () {

    // ── 1. SharedPreferences ──────────────────────────────────────────────────
    var EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

    ["putString", "putInt", "putLong", "putFloat", "putBoolean", "putStringSet"]
    .forEach(function(method) {
        try {
            // Overload that takes key + value
            var overloads = EditorImpl[method].overloads;
            overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var key   = arguments[0] ? arguments[0].toString() : "";
                    var value = arguments[1] !== undefined ? arguments[1].toString() : "";
                    var isSensitive = /pass|pin|secret|token|key|credit|ssn|dob/i.test(key + value);
                    send({
                        type:      "SharedPreferences." + method,
                        key:       key,
                        value:     value.substring(0, 100),
                        sensitive: isSensitive,
                        masvs:    "MSTG-STORAGE-1",
                        severity:  isSensitive ? "HIGH" : "INFO",
                        note:      "Stored in plaintext XML at /data/data/<pkg>/shared_prefs/"
                    });
                    return overload.call(this, ...arguments);
                };
            });
        } catch(e) {}
    });

    // ── 2. SQLiteDatabase ─────────────────────────────────────────────────────
    var SQLiteDb = Java.use("android.database.sqlite.SQLiteDatabase");

    // execSQL — raw SQL (INSERT, CREATE TABLE, etc.)
    SQLiteDb.execSQL.overload("java.lang.String").implementation = function(sql) {
        send({
            type:     "SQLiteDatabase.execSQL",
            key:      "raw SQL",
            value:    sql.substring(0, 200),
            masvs:    "MSTG-STORAGE-2",
            severity: "MEDIUM",
            note:     "Database at /data/data/<pkg>/databases/ — readable on rooted device"
        });
        return this.execSQL(sql);
    };

    // insert — ContentValues insertion
    try {
        SQLiteDb.insert.implementation = function(table, nullCol, values) {
            send({
                type:     "SQLiteDatabase.insert",
                key:      "table=" + table,
                value:    values ? values.toString().substring(0, 150) : "",
                masvs:    "MSTG-STORAGE-2",
                severity: "MEDIUM",
            });
            return this.insert(table, nullCol, values);
        };
    } catch(e) {}

    // ── 3. File writes ────────────────────────────────────────────────────────
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    FileOutputStream.$init.overload("java.lang.String").implementation = function(path) {
        var isExternal = path.startsWith("/sdcard") || path.startsWith("/storage");
        var isSensitive = /pass|pin|secret|token|key|cred/i.test(path);
        send({
            type:     "FileOutputStream",
            key:      "path",
            value:    path,
            masvs:    isExternal ? "MSTG-STORAGE-5" : "MSTG-STORAGE-4",
            severity: (isSensitive || isExternal) ? "HIGH" : "INFO",
            note:     isExternal
                      ? "External storage is world-readable (no permission needed)"
                      : "Internal file storage — readable on rooted device"
        });
        return this.$init(path);
    };

    // ── 4. Log.* — sensitive data in logcat ───────────────────────────────────
    var Log = Java.use("android.util.Log");
    ["d", "v", "i", "w", "e"].forEach(function(level) {
        try {
            Log[level].overload("java.lang.String", "java.lang.String")
            .implementation = function(tag, msg) {
                if (/pass|pin|secret|token|key|credit|ssn|auth/i.test(tag + msg)) {
                    send({
                        type:     "Log." + level,
                        key:      tag,
                        value:    msg.substring(0, 150),
                        masvs:    "MSTG-STORAGE-3",
                        severity: "HIGH",
                        note:     "Sensitive data in logcat — readable by any app with READ_LOGS"
                    });
                }
                return this[level](tag, msg);
            };
        } catch(e) {}
    });

    // ── 5. Clipboard (PasteBoard) ─────────────────────────────────────────────
    try {
        var ClipboardManager = Java.use("android.content.ClipboardManager");
        ClipboardManager.setPrimaryClip.implementation = function(clip) {
            if (clip) {
                var text = clip.getItemAt(0) ? clip.getItemAt(0).getText() : "";
                send({
                    type:     "Clipboard.setPrimaryClip",
                    key:      "clipboard content",
                    value:    text ? text.toString().substring(0, 100) : "",
                    masvs:    "MSTG-STORAGE-9",
                    severity: "MEDIUM",
                    note:     "Clipboard readable by all apps without permission on Android < 10"
                });
            }
            return this.setPrimaryClip(clip);
        };
    } catch(e) {}

    send({ hook: "init", value: "Storage interceptor loaded ✅" });
    send({ hook: "coverage", value: "SharedPreferences | SQLite | File | Log | Clipboard" });
});
