<?php
/* LinkVault – Datenverzeichnis, Schutz, Benutzerordner */
defined('LV_VERSION') || exit;

/* ---------- Datenverzeichnis + Schutz (Apache & Nginx) ---------- */

function lvEnsureDataDir(): void {
    static $done = false;
    if ($done) return;
    $done = true;

    if (!is_dir(LV_DATA_DIR)) {
        @mkdir(LV_DATA_DIR, 0700, true);
    }

    // Migration: alte Dateien aus dem App-Root nach data/ verschieben (einmalig)
    $legacy = [
        LV_ROOT . '/lv_auth.json' => LV_DATA_DIR . '/lv_auth.json',
        LV_ROOT . '/bookmarks.json' => LV_DATA_DIR . '/bookmarks.json',
        LV_ROOT . '/bookmarks.lock' => LV_DATA_DIR . '/bookmarks.lock',
    ];
    foreach ($legacy as $from => $to) {
        if (is_file($from) && !is_file($to)) {
            @rename($from, $to) || @copy($from, $to);
            if (is_file($to) && is_file($from)) @unlink($from);
        }
    }
    if (is_dir(LV_ROOT . '/backups') && !is_dir(LV_DATA_DIR . '/backups')) {
        @rename(LV_ROOT . '/backups', LV_DATA_DIR . '/backups');
    }

    // Apache: Zugriff auf data/ komplett sperren
    $ht = LV_DATA_DIR . '/.htaccess';
    if (!is_file($ht)) {
        @file_put_contents($ht,
            "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n" .
            "<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n" .
            "Options -Indexes\n"
        );
    }
    $idx = LV_DATA_DIR . '/index.html';
    if (!is_file($idx)) {
        @file_put_contents($idx, '');
    }

    // Nginx: fertige Location-Regel (muss in die Server-Config übernommen werden)
    // Der Pfad muss zum Ordner passen, in dem LinkVault liegt (z. B. /linkvault/data/), sonst greift die Regel nicht.
    $ngx = LV_DATA_DIR . '/nginx-deny.conf';
    $base = '';
    if (PHP_SAPI !== 'cli' && !empty($_SERVER['SCRIPT_NAME'])) {
        $base = rtrim(str_replace('\\', '/', dirname((string)$_SERVER['SCRIPT_NAME'])), '/');
        if (!preg_match('~^(/[A-Za-z0-9._\-]+)*$~', $base)) $base = '';
    }
    $old = is_file($ngx) ? (string)@file_get_contents($ngx) : '';
    // Ältere Versionen schrieben immer "/data/", das passt nur im Hauptverzeichnis der Domain
    if ($old === '' || ($base !== '' && strpos($old, "location ^~ /data/ {") !== false)) {
        @file_put_contents($ngx,
            "# LinkVault – diesen Block in die nginx server { }-Sektion übernehmen.\n" .
            "# Der Pfad muss zum Ordner passen, in dem LinkVault liegt.\n" .
            "location ^~ {$base}/data/ {\n" .
            "    deny all;\n" .
            "    return 404;\n" .
            "}\n"
        );
    }

    // Root-.htaccess nur anlegen, wenn es noch keine gibt
    $rootHt = LV_ROOT . '/.htaccess';
    if (!is_file($rootHt)) {
        @file_put_contents($rootHt,
            "Options -Indexes\n" .
            "<FilesMatch \"\\.(json|lock|tmp|log|lvbak)$\">\n" .
            "  <IfModule mod_authz_core.c>\n    Require all denied\n  </IfModule>\n" .
            "  <IfModule !mod_authz_core.c>\n    Deny from all\n  </IfModule>\n" .
            "</FilesMatch>\n"
        );
    }
}

lvEnsureDataDir();

/* ---------- Benutzer und ihre Ordner ---------- */

/**
 * Das erste Konto ist der Administrator. Seine Dateien liegen direkt in data/ (genau wie vor
 * Version 3.1), seine Kennung ist die leere Zeichenkette. Jeder weitere Benutzer bekommt einen
 * eigenen Ordner data/users/<Kennung>/ mit eigenem Schlüssel, eigenen Links und eigenen Backups.
 */
function lvUidOk($uid): bool {
    return is_string($uid) && ($uid === '' || preg_match('/^u[a-f0-9]{16}$/', $uid) === 1);
}

function lvUserDir(?string $uid = null): string {
    global $LV_UID;
    if ($uid === null) $uid = $LV_UID;
    return $uid === '' ? LV_DATA_DIR : USERS_DIR . '/' . $uid;
}

function lvAuthFile(?string $uid = null): string {
    global $LV_UID;
    if ($uid === null) $uid = $LV_UID;
    return $uid === '' ? LV_DATA_DIR . '/lv_auth.json' : USERS_DIR . '/' . $uid . '/auth.json';
}

function lvDataFile(): string { return lvUserDir() . '/bookmarks.json'; }
function lvLockFile(): string { return lvUserDir() . '/bookmarks.lock'; }
function lvFaviconDir(): string { return lvUserDir() . '/favicon_cache'; }
function lvBackupDir(?string $uid = null): string { return lvUserDir($uid) . '/backups'; }

function lvAttemptsFile(string $uid): string {
    return $uid === '' ? THROTTLE_DIR . '/attempts.log' : USERS_DIR . '/' . $uid . '/attempts.log';
}

function lvLower(string $s): string {
    return function_exists('mb_strtolower') ? mb_strtolower($s, 'UTF-8') : strtolower($s);
}

/**
 * Stand eines weiteren Benutzers (wartet / aktiv / gesperrt). Liegt bewusst in einer eigenen Datei:
 * Die schreibt nur die Registrierung und der Administrator, nie der Benutzer selbst.
 */
function lvLoadState(string $uid): array {
    if ($uid === '' || !lvUidOk($uid)) return [];
    $data = json_decode((string)@file_get_contents(USERS_DIR . '/' . $uid . '/state.json'), true);
    return is_array($data) ? $data : [];
}

function lvSaveState(string $uid, array $state): bool {
    if ($uid === '' || !lvUidOk($uid)) return false;
    $file = USERS_DIR . '/' . $uid . '/state.json';
    $json = json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    if ($json === false) return false;
    $tmp = $file . '.tmp.' . bin2hex(random_bytes(4));
    if (@file_put_contents($tmp, $json, LOCK_EX) === false) { @unlink($tmp); return false; }
    if (!@rename($tmp, $file)) {
        $ok = @copy($tmp, $file);
        @unlink($tmp);
        return $ok;
    }
    return true;
}
