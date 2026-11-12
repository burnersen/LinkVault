<?php
/**
 * LinkVault – Lesezeichen-Verwaltung in einer einzigen PHP-Datei
 *
 * Keine Datenbank, keine Abhängigkeiten, nichts wird von fremden Servern nachgeladen.
 * Alle Links liegen AES-256-GCM-verschlüsselt in data/. Der Schlüssel dazu ist mit
 * deinem Passwort geschützt und steht nirgends im Klartext auf dem Server.
 *
 * Mehrere Benutzer: Das erste Konto ist der Administrator. Wer danach dazukommen will,
 * stellt eine Anfrage, die der Administrator freigeben muss. Jeder Benutzer hat einen
 * eigenen Schlüssel und einen eigenen Bereich, niemand sieht die Links der anderen,
 * auch der Administrator nicht.
 *
 * Diese Datei enthält KEINE Zugangsdaten, Schlüssel oder persönlichen Angaben.
 * Alles Geheime entsteht erst beim ersten Aufruf (Einrichtungs-Assistent) und liegt
 * dann im Ordner data/. Den Ordner data/ niemals veröffentlichen oder ins Git legen.
 *
 * Lizenz: GNU General Public License v3.0, siehe Datei LICENSE.
 * Schrift: Inter (SIL Open Font License 1.1, https://github.com/rsms/inter), eingebettet.
 */

error_reporting(E_ALL);
ini_set('display_errors', 0);
date_default_timezone_set('Europe/Berlin');

define('LV_VERSION', '3.1.0');
define('LV_DATA_DIR', __DIR__ . '/data');
define('USERS_DIR', LV_DATA_DIR . '/users');       // weitere Benutzer: jeder hat hier seinen eigenen Ordner
define('SESSION_DIR', LV_DATA_DIR . '/sessions');
define('THROTTLE_DIR', LV_DATA_DIR . '/throttle'); // Fehlversuche + Anmelde-Protokoll
define('LV_MAX_PENDING', 20);    // so viele Zugangsanfragen dürfen gleichzeitig auf Freigabe warten
define('LV_MAX_USERS', 50);      // Obergrenze für weitere Benutzer
define('BACKUP_KEEP_DAILY', 14); // ein Stand pro Tag, 14 Tage
define('BACKUP_KEEP_PRE', 10);   // Stände vor großen Aktionen
define('LV_TRASH_DAYS', 30);     // so lange bleiben gelöschte Links im Papierkorb
// false = Tailwind ist fest eingebaut. true = per CDN laden (nur zum Basteln, lockert die Sicherheitsregeln).
define('LV_TAILWIND_CDN', false);
define('LV_UA', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36');

define('LV_AUTH_ENABLED', true);
define('LV_SESSION_NAME', 'LVSESSID');
define('LV_KEY_COOKIE', 'LVKEY');
define('LV_KDF_ITERS', 600000);   // PBKDF2-Runden für neue/aktualisierte Schlüssel
define('LV_IDLE_DEFAULT', 480);   // Minuten ohne Aktivität bis zur automatischen Abmeldung
define('LV_SESSION_MAX_DAYS', 30);

$LV_CORRUPT = false;   // true = bookmarks.json existiert, ist aber nicht lesbar
$LV_AUTH_CACHE = [];
$LV_UID = '';          // wer gerade angemeldet ist: '' = Administrator (erstes Konto), sonst Ordnername unter data/users/
$LV_DEK = null;        // Datenschlüssel dieser Anfrage (nur im Arbeitsspeicher)
$LV_LOGGED = null;
$LV_NONCE = rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '=');

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
        __DIR__ . '/lv_auth.json' => LV_DATA_DIR . '/lv_auth.json',
        __DIR__ . '/bookmarks.json' => LV_DATA_DIR . '/bookmarks.json',
        __DIR__ . '/bookmarks.lock' => LV_DATA_DIR . '/bookmarks.lock',
    ];
    foreach ($legacy as $from => $to) {
        if (is_file($from) && !is_file($to)) {
            @rename($from, $to) || @copy($from, $to);
            if (is_file($to) && is_file($from)) @unlink($from);
        }
    }
    if (is_dir(__DIR__ . '/backups') && !is_dir(LV_DATA_DIR . '/backups')) {
        @rename(__DIR__ . '/backups', LV_DATA_DIR . '/backups');
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
    $ngx = LV_DATA_DIR . '/nginx-deny.conf';
    if (!is_file($ngx)) {
        @file_put_contents($ngx,
            "# LinkVault – diesen Block in die nginx server { }-Sektion übernehmen:\n" .
            "location ^~ /data/ {\n" .
            "    deny all;\n" .
            "    return 404;\n" .
            "}\n"
        );
    }

    // Root-.htaccess nur anlegen, wenn es noch keine gibt
    $rootHt = __DIR__ . '/.htaccess';
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

/* ---------- Auth-Config ---------- */

/** Zugangsdaten eines Benutzers. Ohne Angabe: der gerade angemeldete. */
function lvLoadAuthConfig(bool $fresh = false, ?string $uid = null): ?array {
    global $LV_AUTH_CACHE, $LV_UID;
    if ($uid === null) $uid = $LV_UID;
    if (!lvUidOk($uid)) return null;
    if (!$fresh && array_key_exists($uid, $LV_AUTH_CACHE)) return $LV_AUTH_CACHE[$uid];
    $LV_AUTH_CACHE[$uid] = null;
    $file = lvAuthFile($uid);
    if (!is_file($file)) return null;
    $raw = @file_get_contents($file);
    if ($raw === false) return null;
    $data = json_decode($raw, true);
    if (!is_array($data)) return null;
    foreach (['username', 'password_hash', 'kdf_salt', 'wrapped_key'] as $k) {
        if (!isset($data[$k]) || !is_string($data[$k]) || trim($data[$k]) === '') return null;
    }
    $data['username'] = trim($data['username']);
    $data['kdf_iters'] = (int)($data['kdf_iters'] ?? 120000);
    $data['epoch'] = (int)($data['epoch'] ?? 0);
    $data['idle_minutes'] = (int)($data['idle_minutes'] ?? LV_IDLE_DEFAULT);
    if ($data['idle_minutes'] < 5) $data['idle_minutes'] = LV_IDLE_DEFAULT;
    // Diese Angaben stehen nicht in der Datei, sie ergeben sich aus dem Ort bzw. aus state.json
    $data['_uid'] = $uid;
    if ($uid === '') {
        $data['role'] = 'admin';
        $data['status'] = 'active';
    } else {
        $st = lvLoadState($uid);
        $data['role'] = 'user';
        // Fehlt die Datei oder ist sie kaputt, gilt das Konto als nicht freigegeben
        $data['status'] = in_array($st['status'] ?? '', ['active', 'blocked'], true) ? $st['status'] : 'pending';
        $data['created'] = (int)($st['created'] ?? 0);
        $data['approved'] = (int)($st['approved'] ?? 0);
        $data['req'] = (string)($st['req'] ?? '');
    }
    return $LV_AUTH_CACHE[$uid] = $data;
}

function lvIsSetupDone(): bool {
    return lvLoadAuthConfig(false, '') !== null;
}

/** Schreibt die Zugangsdaten sicher (erst Kopie des alten Stands, dann temporäre Datei + Umbenennen). */
function lvSaveAuthConfigFull(array $cfg): bool {
    global $LV_AUTH_CACHE;
    $uid = (string)($cfg['_uid'] ?? '');
    if (!lvUidOk($uid)) return false;
    unset($cfg['_uid'], $cfg['role'], $cfg['status'], $cfg['created'], $cfg['approved'], $cfg['req']);
    $json = json_encode($cfg, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    if ($json === false) return false;
    lvEnsureDataDir();
    $file = lvAuthFile($uid);
    if (is_file($file) && ensureBackupDir($uid)) {
        // Ohne diese Datei wären alle Daten verloren, deshalb vor jeder Änderung eine Kopie
        if (@copy($file, lvBackupDir($uid) . '/auth_' . date('Ymd_His') . '.json')) pruneBackups('auth_', 10, $uid);
    }
    $tmp = $file . '.tmp.' . bin2hex(random_bytes(4));
    if (@file_put_contents($tmp, $json, LOCK_EX) === false || filesize($tmp) !== strlen($json)) {
        @unlink($tmp);
        return false;
    }
    if (!@rename($tmp, $file)) {
        $ok = @copy($tmp, $file);
        @unlink($tmp);
        if (!$ok) return false;
    }
    unset($LV_AUTH_CACHE[$uid]);
    return true;
}

/** Alle weiteren Benutzer (ohne den Administrator), auch wartende und gesperrte. */
function lvListUsers(bool $fresh = false): array {
    $out = [];
    foreach (glob(USERS_DIR . '/*/auth.json') ?: [] as $f) {
        $uid = basename(dirname($f));
        if ($uid === '' || !lvUidOk($uid)) continue;
        $cfg = lvLoadAuthConfig($fresh, $uid);
        if ($cfg !== null) $out[] = $cfg;
    }
    return $out;
}

/** Sucht ein Konto über den Namen. $exact = false: Groß/Klein egal (für „Name schon vergeben?“). */
function lvFindUser(string $username, bool $exact = true, bool $fresh = false): ?array {
    $all = lvListUsers($fresh);
    $admin = lvLoadAuthConfig($fresh, '');
    if ($admin !== null) array_unshift($all, $admin);
    foreach ($all as $cfg) {
        if ($exact ? hash_equals($cfg['username'], $username) : lvLower($cfg['username']) === lvLower($username)) return $cfg;
    }
    return null;
}

function lvUserByUid($uid): array {
    if (!is_string($uid) || $uid === '' || !lvUidOk($uid)) throw new Exception('Benutzer nicht gefunden.');
    $u = lvLoadAuthConfig(true, $uid);
    if ($u === null) throw new Exception('Benutzer nicht gefunden.');
    return $u;
}

/** Nur der Administrator darf Benutzer verwalten. Liefert seine Zugangsdaten. */
function lvRequireAdmin(): array {
    $cfg = lvLoadAuthConfig(true);
    if ($cfg === null || $cfg['role'] !== 'admin') throw new Exception('Das darf nur der Administrator.');
    return $cfg;
}

/** Nimmt LinkVault gerade neue Zugangsanfragen an? (Standard: ja) */
function lvRegisterOpen(?array $adminCfg): bool {
    if ($adminCfg === null) return false;
    return !array_key_exists('allow_register', $adminCfg) || !empty($adminCfg['allow_register']);
}

function lvPendingCount(): int {
    $n = 0;
    foreach (lvListUsers() as $u) if ($u['status'] === 'pending') $n++;
    return $n;
}

function lvSetUserStatus(array $user, string $status): bool {
    $st = lvLoadState($user['_uid']);
    if ($status === 'active' && ($st['status'] ?? 'pending') === 'pending') {
        $st['approved'] = time();
        unset($st['req']); // Nachricht und Adresse der Anfrage werden nicht mehr gebraucht
    }
    $st['status'] = $status;
    return lvSaveState($user['_uid'], $st);
}

/** Löscht einen Ordner samt Inhalt (nur für Benutzer-Ordner gedacht). */
function lvRemoveDir(string $dir): bool {
    if (!is_dir($dir) || is_link($dir)) return false;
    foreach (scandir($dir) ?: [] as $f) {
        if ($f === '.' || $f === '..') continue;
        $path = $dir . '/' . $f;
        if (is_dir($path) && !is_link($path)) lvRemoveDir($path);
        else @unlink($path);
    }
    return @rmdir($dir);
}

function lvDeleteUser(string $uid): bool {
    if ($uid === '' || !lvUidOk($uid)) return false;
    global $LV_AUTH_CACHE;
    unset($LV_AUTH_CACHE[$uid]);
    return lvRemoveDir(USERS_DIR . '/' . $uid);
}

/** Nachricht und Adresse einer Zugangsanfrage. Lesen kann sie nur der angemeldete Administrator. */
function lvReadRequest(array $user, array $admin, ?string $adminDek): array {
    $raw = (string)($user['req'] ?? '');
    if (strlen($raw) < 2) return [];
    $bin = base64_decode(substr($raw, 1), true);
    if ($bin === false) return [];
    $json = null;
    if ($raw[0] === 'P') $json = $bin;
    elseif ($raw[0] === 'S' && $adminDek !== null && !empty($admin['log_sec']) && function_exists('sodium_crypto_box_seal_open')) {
        $kp = lvDecryptWith($adminDek, (string)$admin['log_sec']);
        if ($kp !== null) {
            try { $json = sodium_crypto_box_seal_open($bin, $kp); } catch (Throwable $e) { $json = false; }
            if ($json === false) $json = null;
        }
    }
    $rec = $json !== null ? json_decode($json, true) : null;
    if (!is_array($rec)) return [];
    return ['note' => cleanText($rec['note'] ?? '', 300), 'ip' => cleanText($rec['ip'] ?? '', 64)];
}

/** Liste für das Fenster „Benutzer verwalten“. */
function lvUsersPayload(array $admin): array {
    $dek = lvDataKey();
    $list = [];
    $pending = 0;
    foreach (lvListUsers(true) as $u) {
        $req = $u['status'] === 'pending' ? lvReadRequest($u, $admin, $dek) : [];
        if ($u['status'] === 'pending') $pending++;
        $list[] = [
            'uid' => $u['_uid'], 'username' => $u['username'], 'status' => $u['status'],
            'created' => $u['created'], 'approved' => $u['approved'], 'totp' => !empty($u['totp']),
            'note' => $req['note'] ?? '', 'ip' => $req['ip'] ?? '',
        ];
    }
    usort($list, fn($a, $b) => strcasecmp($a['username'], $b['username']));
    return ['users' => $list, 'pending' => $pending, 'admin' => $admin['username'], 'allow_register' => lvRegisterOpen($admin)];
}

/* ---------- Schlüssel aus Passwort wickeln ---------- */

function lvDeriveKek(string $password, string $saltBin, int $iters): string {
    return hash_pbkdf2('sha256', $password, $saltBin, max(10000, $iters), 32, true);
}

function lvWrapKey(string $dek, string $password): array {
    $salt = random_bytes(16);
    $iters = LV_KDF_ITERS;
    $kek = lvDeriveKek($password, $salt, $iters);
    $iv = random_bytes(12);
    $tag = '';
    $ct = openssl_encrypt($dek, 'aes-256-gcm', $kek, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ct === false) throw new Exception('Schlüssel konnte nicht geschützt werden.');
    return [
        'kdf_salt' => base64_encode($salt),
        'wrapped_key' => base64_encode($iv . $tag . $ct),
        'kdf_iters' => $iters,
    ];
}

function lvUnwrapKey(string $password, array $cfg): ?string {
    $salt = base64_decode((string)$cfg['kdf_salt'], true);
    $blob = base64_decode((string)$cfg['wrapped_key'], true);
    if ($salt === false || $blob === false || strlen($blob) < 28) return null;
    $iters = (int)($cfg['kdf_iters'] ?? LV_KDF_ITERS);
    $kek = lvDeriveKek($password, $salt, $iters);
    $iv = substr($blob, 0, 12);
    $tag = substr($blob, 12, 16);
    $ct = substr($blob, 28);
    $dek = openssl_decrypt($ct, 'aes-256-gcm', $kek, OPENSSL_RAW_DATA, $iv, $tag);
    if ($dek === false || strlen($dek) !== 32) return null;
    return $dek;
}

/* ---------- Verschlüsselung (AES-256-GCM) ---------- */

function lvEncryptWith(string $key, string $plain): string {
    $iv = random_bytes(12);
    $tag = '';
    $ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ct === false) throw new Exception('Verschlüsselung fehlgeschlagen.');
    return 'LVENC1' . base64_encode($iv . $tag . $ct);
}

function lvDecryptWith(string $key, string $data): ?string {
    if (strncmp($data, 'LVENC1', 6) !== 0) return null;
    $raw = base64_decode(substr($data, 6), true);
    if ($raw === false || strlen($raw) < 28) return null;
    $plain = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));
    return $plain === false ? null : $plain;
}

/* ---------- Session / Auth ---------- */

function lvIsHttps(): bool {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || ((int)($_SERVER['SERVER_PORT'] ?? 0) === 443)
        || (strtolower($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
}

function lvCookieOpts(int $expires = 0): array {
    return ['expires' => $expires, 'path' => '/', 'secure' => lvIsHttps(), 'httponly' => true, 'samesite' => 'Lax'];
}

function lvStartSession(): void {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    // Eigener Session-Ordner: nicht im gemeinsamen /tmp des Hosters, und die Laufzeit bestimmen wir selbst
    if (ini_get('session.save_handler') === 'files') {
        if (!is_dir(SESSION_DIR)) @mkdir(SESSION_DIR, 0700, true);
        if (is_dir(SESSION_DIR) && is_writable(SESSION_DIR)) {
            @ini_set('session.save_path', SESSION_DIR);
            @ini_set('session.gc_probability', '1');
            @ini_set('session.gc_divisor', '50');
        }
    }
    @ini_set('session.gc_maxlifetime', (string)(LV_SESSION_MAX_DAYS * 86400));
    @ini_set('session.use_strict_mode', '1');
    @ini_set('session.use_only_cookies', '1');
    @ini_set('session.use_trans_sid', '0');
    session_name(LV_SESSION_NAME);
    session_set_cookie_params([
        'lifetime' => 0, 'path' => '/', 'secure' => lvIsHttps(), 'httponly' => true, 'samesite' => 'Lax',
    ]);
    @session_start();
}

/**
 * Datenschlüssel der laufenden Sitzung.
 * In der Session-Datei liegt er nur verschlüsselt. Der Schlüssel dazu steckt in einem
 * Cookie im Browser. Wer nur die Dateien auf dem Server hat, kommt damit nicht weiter.
 */
function lvDataKey(): ?string {
    global $LV_DEK;
    if (!LV_AUTH_ENABLED) return null;
    if (is_string($LV_DEK)) return $LV_DEK;
    lvStartSession();
    $enc = $_SESSION['lv_dek_enc'] ?? null;
    $ck = $_COOKIE[LV_KEY_COOKIE] ?? '';
    if (!is_string($enc) || !is_string($ck) || !preg_match('/^[a-f0-9]{64}$/', $ck)) return null;
    $dek = lvDecryptWith(hex2bin($ck), $enc);
    if ($dek === null || strlen($dek) !== 32) return null;
    return $LV_DEK = $dek;
}

function lvIsLoggedIn(): bool {
    global $LV_LOGGED, $LV_UID;
    if (!LV_AUTH_ENABLED) return true;
    if ($LV_LOGGED !== null) return $LV_LOGGED;
    lvStartSession();
    $ok = !empty($_SESSION['lv_auth']) && $_SESSION['lv_auth'] === true;
    // Sitzungen von vor Version 3.1 haben keine Kennung: das ist der Administrator
    $uid = $_SESSION['lv_uid'] ?? '';
    if ($ok && !lvUidOk($uid)) $ok = false;
    $LV_UID = $ok ? $uid : '';
    $cfg = $ok ? lvLoadAuthConfig() : null;
    // Nach Passwortwechsel (epoch) fliegen alle anderen Geräte raus
    if ($ok && (!$cfg || (int)($_SESSION['lv_epoch'] ?? -1) !== $cfg['epoch'])) $ok = false;
    // Gesperrt, gelöscht oder noch nicht freigegeben: sofort draußen
    if ($ok && $cfg['status'] !== 'active') $ok = false;
    if ($ok && time() - (int)($_SESSION['lv_seen'] ?? 0) > $cfg['idle_minutes'] * 60) $ok = false;
    if ($ok && lvDataKey() === null) $ok = false;
    if ($ok) {
        $_SESSION['lv_seen'] = time();
    } else {
        $LV_UID = '';
        if (!empty($_SESSION['lv_auth'])) {
            unset($_SESSION['lv_auth'], $_SESSION['lv_uid'], $_SESSION['lv_dek_enc'], $_SESSION['lv_dek'], $_SESSION['lv_notice']);
        }
    }
    return $LV_LOGGED = $ok;
}

function lvEstablishSession(array $cfg, string $dek): void {
    global $LV_DEK, $LV_LOGGED, $LV_UID;
    lvStartSession();
    session_regenerate_id(true);
    $ck = random_bytes(32);
    unset($_SESSION['lv_dek'], $_SESSION['lv_totp_pending'], $_SESSION['lv_pwfail']);
    $LV_UID = (string)($cfg['_uid'] ?? '');
    $_SESSION['lv_auth'] = true;
    $_SESSION['lv_uid'] = $LV_UID;
    $_SESSION['lv_user'] = $cfg['username'];
    $_SESSION['lv_login_at'] = time();
    $_SESSION['lv_seen'] = time();
    $_SESSION['lv_epoch'] = (int)($cfg['epoch'] ?? 0);
    $_SESSION['lv_dek_enc'] = lvEncryptWith($ck, $dek);
    $_SESSION['lv_csrf'] = bin2hex(random_bytes(32));
    $idle = (int)($cfg['idle_minutes'] ?? LV_IDLE_DEFAULT);
    $exp = $idle > 480 ? time() + $idle * 60 : 0; // lange Laufzeit = Cookie überlebt den Browser-Neustart
    setcookie(LV_KEY_COOKIE, bin2hex($ck), lvCookieOpts($exp));
    $_COOKIE[LV_KEY_COOKIE] = bin2hex($ck);
    if ($exp) setcookie(session_name(), session_id(), lvCookieOpts($exp));
    $LV_DEK = $dek;
    $LV_LOGGED = true;
}

function lvLogout(): void {
    global $LV_DEK, $LV_LOGGED, $LV_UID;
    lvStartSession();
    $LV_UID = '';
    $_SESSION = [];
    setcookie(session_name(), '', lvCookieOpts(time() - 42000));
    setcookie(LV_KEY_COOKIE, '', lvCookieOpts(time() - 42000));
    @session_destroy();
    $LV_DEK = null;
    $LV_LOGGED = false;
}

function lvCheckNewPassword(string $password): void {
    if (strlen($password) < 12) throw new Exception('Passwort: mindestens 12 Zeichen.');
    if (!preg_match('/[A-Za-z]/', $password) || !preg_match('/[0-9]/', $password)) {
        throw new Exception('Passwort muss Buchstaben und Zahlen enthalten.');
    }
}

/**
 * Anmeldung. Ergebnis: 'ok', 'bad' (Name/Passwort falsch), 'totp' (2FA-Code falsch/fehlt),
 * 'pending' (wartet noch auf Freigabe) oder 'blocked' (vom Administrator gesperrt).
 */
function lvLogin(string $user, string $pass, string $code = ''): string {
    if (!LV_AUTH_ENABLED) return 'ok';
    if (lvLoadAuthConfig(true, '') === null) return 'bad';
    $cfg = lvFindUser($user, true, true);
    // Immer rechnen, auch bei unbekanntem Namen: die Antwortzeit soll nichts verraten
    if ($cfg === null) { password_hash($pass, PASSWORD_DEFAULT); return 'bad'; }
    if (!password_verify($pass, $cfg['password_hash'])) return 'bad';
    // Erst nach richtigem Passwort sagen, woran es liegt
    if ($cfg['status'] === 'pending') return 'pending';
    if ($cfg['status'] !== 'active') return 'blocked';
    $dek = lvUnwrapKey($pass, $cfg);
    if ($dek === null) return 'bad';
    $changed = false;
    if (!empty($cfg['totp'])) {
        $secret = lvDecryptWith($dek, (string)$cfg['totp']);
        $counter = $secret !== null ? lvTotpVerify($secret, $code, (int)($cfg['totp_last'] ?? 0)) : 0;
        if ($counter === 0) return 'totp';
        $cfg['totp_last'] = $counter; // jeder Code gilt nur einmal
        $changed = true;
    }
    // Ältere Schlüssel-Verpackung beim Login unauffällig auf den aktuellen Stand heben
    if ($cfg['kdf_iters'] < LV_KDF_ITERS) {
        try {
            $w = lvWrapKey($dek, $pass);
            $cfg['kdf_salt'] = $w['kdf_salt']; $cfg['wrapped_key'] = $w['wrapped_key']; $cfg['kdf_iters'] = $w['kdf_iters'];
            $changed = true;
        } catch (Throwable $e) { /* alter Stand bleibt gültig */ }
    }
    if (password_needs_rehash($cfg['password_hash'], PASSWORD_DEFAULT)) {
        $h = password_hash($pass, PASSWORD_DEFAULT);
        if ($h) { $cfg['password_hash'] = $h; $changed = true; }
    }
    if (lvEnsureLogKeys($cfg, $dek)) $changed = true;
    if ($changed) lvSaveAuthConfigFull($cfg);
    lvFinishLogin($cfg, $dek);
    return 'ok';
}

/** Gemeinsamer Abschluss für Login, Einrichtung und Wiederherstellung */
function lvFinishLogin(array $cfg, string $dek): void {
    $notice = lvLoginNotice($cfg, $dek);
    lvEstablishSession($cfg, $dek);
    $_SESSION['lv_notice'] = $notice;
    lvLogAttempt('ok', $cfg['username'], (string)($cfg['_uid'] ?? ''));
    // Alte Favicon-Dateien (Domain im Dateinamen) entsorgen
    foreach (glob(lvFaviconDir() . '/*.png') ?: [] as $f) @unlink($f);
}

/** Ersteinrichtung: Benutzer + Passwort, erzeugt Datenschlüssel. Dieses erste Konto ist der Administrator. */
function lvRunSetup(string $username, string $password): void {
    $username = trim($username);
    if (strlen($username) < 2 || strlen($username) > 64) {
        throw new Exception('Benutzername: 2–64 Zeichen.');
    }
    lvCheckNewPassword($password);
    if (lvIsSetupDone()) {
        throw new Exception('Setup war schon erledigt. Bitte anmelden.');
    }
    $hash = password_hash($password, PASSWORD_DEFAULT);
    if ($hash === false) throw new Exception('Passwort-Hash fehlgeschlagen.');
    $dek = random_bytes(32);
    $wrapped = lvWrapKey($dek, $password);
    $cfg = [
        'username' => $username,
        'password_hash' => $hash,
        'kdf_salt' => $wrapped['kdf_salt'],
        'wrapped_key' => $wrapped['wrapped_key'],
        'kdf_iters' => $wrapped['kdf_iters'],
        'epoch' => 0,
        'idle_minutes' => LV_IDLE_DEFAULT,
    ];
    lvEnsureLogKeys($cfg, $dek);
    if (!lvSaveAuthConfigFull($cfg)) throw new Exception('Speichern von lv_auth.json fehlgeschlagen (Schreibrechte?).');
    lvFinishLogin($cfg, $dek);
}

/**
 * Zugangsanfrage eines weiteren Benutzers. Das Konto wird fertig angelegt (eigener Schlüssel,
 * mit dem eigenen Passwort geschützt), bleibt aber zu, bis der Administrator es freigibt.
 */
function lvRegister(string $username, string $password, string $note): void {
    $username = trim($username);
    if (strlen($username) < 2 || strlen($username) > 64) throw new Exception('Benutzername: 2–64 Zeichen.');
    if (cleanText($username, 64) !== $username) throw new Exception('Der Benutzername enthält unzulässige Zeichen.');
    lvCheckNewPassword($password);
    $admin = lvLoadAuthConfig(true, '');
    if ($admin === null) throw new Exception('LinkVault ist noch nicht eingerichtet.');
    if (!lvRegisterOpen($admin)) throw new Exception('Neue Anfragen sind im Moment geschlossen.');
    if (!is_dir(USERS_DIR) && !@mkdir(USERS_DIR, 0700, true)) {
        throw new Exception('Der Ordner für Benutzer konnte nicht angelegt werden (Schreibrechte?).');
    }
    // Zwei Anfragen gleichzeitig mit demselben Namen: nacheinander abarbeiten
    $lock = @fopen(USERS_DIR . '/.lock', 'c');
    if ($lock) flock($lock, LOCK_EX);
    try {
        if (lvFindUser($username, false, true) !== null) {
            lvLoginThrottleFail(); // wer hier Namen durchprobiert, wird ausgebremst
            throw new Exception('Dieser Benutzername ist schon vergeben.');
        }
        $users = lvListUsers();
        if (lvPendingCount() >= LV_MAX_PENDING || count($users) >= LV_MAX_USERS) {
            throw new Exception('Im Moment werden keine weiteren Anfragen angenommen. Bitte später noch einmal versuchen.');
        }
        $hash = password_hash($password, PASSWORD_DEFAULT);
        if ($hash === false) throw new Exception('Passwort-Hash fehlgeschlagen.');
        $dek = random_bytes(32);
        $wrapped = lvWrapKey($dek, $password);
        $uid = 'u' . bin2hex(random_bytes(8));
        $cfg = [
            'username' => $username,
            'password_hash' => $hash,
            'kdf_salt' => $wrapped['kdf_salt'],
            'wrapped_key' => $wrapped['wrapped_key'],
            'kdf_iters' => $wrapped['kdf_iters'],
            'epoch' => 0,
            'idle_minutes' => LV_IDLE_DEFAULT,
            '_uid' => $uid,
        ];
        lvEnsureLogKeys($cfg, $dek);
        // Nachricht und Adresse verschließen: lesen kann sie nur der angemeldete Administrator
        $req = ['note' => cleanText($note, 300), 'ip' => lvRealIp()];
        $sealed = null;
        if (!empty($admin['log_pub']) && function_exists('sodium_crypto_box_seal')) {
            $pk = base64_decode((string)$admin['log_pub'], true);
            if ($pk !== false && strlen($pk) === SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
                try { $sealed = 'S' . base64_encode(sodium_crypto_box_seal((string)json_encode($req, JSON_INVALID_UTF8_SUBSTITUTE), $pk)); }
                catch (Throwable $e) { $sealed = null; }
            }
        }
        if ($sealed === null) $sealed = 'P' . base64_encode((string)json_encode(['note' => $req['note']], JSON_INVALID_UTF8_SUBSTITUTE));
        $dir = USERS_DIR . '/' . $uid;
        if (!@mkdir($dir, 0700, true)) throw new Exception('Das Konto konnte nicht angelegt werden (Schreibrechte?).');
        if (!lvSaveAuthConfigFull($cfg) || !lvSaveState($uid, ['status' => 'pending', 'created' => time(), 'req' => $sealed])) {
            lvDeleteUser($uid);
            throw new Exception('Das Konto konnte nicht gespeichert werden (Schreibrechte?).');
        }
    } finally {
        if ($lock) { flock($lock, LOCK_UN); fclose($lock); }
    }
}

/** Höchstens 3 Zugangsanfragen pro Anschluss und Tag. */
function lvRegThrottlePath(): string {
    return lvThrottleDir() . '/reg_' . hash('sha256', lvClientIp()) . '.json';
}

function lvRegThrottleTimes(): array {
    $data = json_decode((string)@file_get_contents(lvRegThrottlePath()), true);
    $limit = time() - 86400;
    return array_values(array_filter((array)($data['times'] ?? []), fn($t) => (int)$t > $limit));
}

function lvRegThrottleOk(): bool {
    return count(lvRegThrottleTimes()) < 3;
}

function lvRegThrottleHit(): void {
    $times = lvRegThrottleTimes();
    $times[] = time();
    @file_put_contents(lvRegThrottlePath(), (string)json_encode(['times' => $times]), LOCK_EX);
}

/* ---------- Zwei-Faktor (TOTP, z. B. Aegis, Google Authenticator, 2FAS) ---------- */

function lvBase32Encode(string $bin): string {
    $abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split($bin) as $c) $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
    $out = '';
    foreach (str_split($bits, 5) as $chunk) $out .= $abc[bindec(str_pad($chunk, 5, '0'))];
    return $out;
}

function lvBase32Decode(string $s): string {
    $abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $s = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', $s) ?? '');
    $bits = '';
    foreach (str_split($s) as $c) {
        $p = strpos($abc, $c);
        if ($p === false) continue;
        $bits .= str_pad(decbin($p), 5, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 8) as $chunk) if (strlen($chunk) === 8) $out .= chr(bindec($chunk));
    return $out;
}

function lvTotpAt(string $secretBin, int $counter): string {
    $h = hash_hmac('sha1', pack('J', $counter), $secretBin, true);
    $o = ord($h[19]) & 0x0f;
    $n = (unpack('N', substr($h, $o, 4))[1] & 0x7fffffff) % 1000000;
    return str_pad((string)$n, 6, '0', STR_PAD_LEFT);
}

/** Prüft einen 6-stelligen Code (±30 s Toleranz). Ergebnis: verwendeter Zähler oder 0. */
function lvTotpVerify(string $secretB32, string $code, int $lastCounter): int {
    $code = preg_replace('/\D/', '', $code) ?? '';
    $bin = lvBase32Decode($secretB32);
    if (strlen($code) !== 6 || strlen($bin) < 10) return 0;
    $now = intdiv(time(), 30);
    $hit = 0;
    for ($c = $now - 1; $c <= $now + 1; $c++) {
        if (hash_equals(lvTotpAt($bin, $c), $code) && $c > $lastCounter) $hit = $c;
    }
    return $hit;
}

/* ---------- Wiederherstellungscode ---------- */

function lvNormalizeRecovery(string $code): string {
    return strtoupper(preg_replace('/[^A-Za-z0-9]/', '', $code) ?? '');
}

/**
 * Passwort vergessen: mit dem Wiederherstellungscode ein neues Passwort setzen.
 * Ohne Benutzernamen ist der Administrator gemeint (so war es, als es nur ein Konto gab).
 */
function lvRecover(string $code, string $newPass, string $user = ''): bool {
    $cfg = $user === '' ? lvLoadAuthConfig(true, '') : lvFindUser($user, true, true);
    $code = lvNormalizeRecovery($code);
    if ($cfg !== null && $cfg['status'] !== 'active') return false;
    if ($cfg === null || empty($cfg['rec_wrapped']) || empty($cfg['rec_salt']) || strlen($code) < 16) return false;
    $dek = lvUnwrapKey($code, ['kdf_salt' => $cfg['rec_salt'], 'wrapped_key' => $cfg['rec_wrapped'], 'kdf_iters' => (int)($cfg['rec_iters'] ?? LV_KDF_ITERS)]);
    if ($dek === null) return false;
    $hash = password_hash($newPass, PASSWORD_DEFAULT);
    if (!$hash) return false;
    $w = lvWrapKey($dek, $newPass);
    $cfg['password_hash'] = $hash;
    $cfg['kdf_salt'] = $w['kdf_salt']; $cfg['wrapped_key'] = $w['wrapped_key']; $cfg['kdf_iters'] = $w['kdf_iters'];
    $cfg['epoch'] = (int)$cfg['epoch'] + 1;
    // Der Code ist verbraucht, 2FA wird abgeschaltet (Handy weg ist der häufigste Grund)
    unset($cfg['rec_wrapped'], $cfg['rec_salt'], $cfg['rec_iters'], $cfg['totp'], $cfg['totp_last']);
    lvEnsureLogKeys($cfg, $dek);
    if (!lvSaveAuthConfigFull($cfg)) return false;
    lvFinishLogin($cfg, $dek);
    return true;
}

/* ---------- Lesezeichen laden / speichern ---------- */

function lvEncryptPayload(string $plain): string {
    if (!LV_AUTH_ENABLED) return $plain;
    $key = lvDataKey();
    // Niemals unverschlüsselt speichern, lieber gar nicht
    if ($key === null) throw new Exception('Kein Schlüssel vorhanden, bitte neu anmelden.');
    return lvEncryptWith($key, $plain);
}

function lvDecodeStored(string $raw): ?string {
    $raw = trim($raw);
    if ($raw === '') return '[]';
    if (strncmp($raw, 'LVENC1', 6) === 0) {
        $key = lvDataKey();
        return $key === null ? null : lvDecryptWith($key, $raw);
    }
    // Klartext-JSON (Migration von sehr alter Version)
    return ($raw[0] === '[' || $raw[0] === '{') ? $raw : null;
}

function loadBookmarks(): array {
    global $LV_CORRUPT;
    if (!file_exists(lvDataFile())) return [];
    $raw = file_get_contents(lvDataFile());
    if ($raw === false) { $LV_CORRUPT = true; return []; }
    $json = lvDecodeStored($raw);
    if ($json === null) { $LV_CORRUPT = true; return []; }
    if (trim($json) === '') return [];
    $data = json_decode($json, true);
    if (!is_array($data)) { $LV_CORRUPT = true; return []; }
    return array_values(array_filter($data, 'is_array'));
}

function saveBookmarks(array $bookmarks): bool {
    usort($bookmarks, function ($a, $b) {
        if (($a['favorite'] ?? false) !== ($b['favorite'] ?? false)) {
            return ($b['favorite'] ?? false) <=> ($a['favorite'] ?? false);
        }
        return strcasecmp($a['title'] ?? '', $b['title'] ?? '');
    });
    $json = json_encode($bookmarks, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    if ($json === false) {
        return false;
    }
    $payload = lvEncryptPayload($json);
    $dataFile = lvDataFile();
    $dir = dirname($dataFile);
    if (!is_dir($dir) || !is_writable($dir)) {
        return false;
    }
    // Atomic write: temp file + rename (avoids partial/corrupt JSON)
    $tmp = $dataFile . '.tmp.' . bin2hex(random_bytes(4));
    $fp = @fopen($tmp, 'cb');
    if ($fp === false) {
        if (@file_put_contents($dataFile, $payload, LOCK_EX) === false) {
            return false;
        }
        return true;
    }
    if (!flock($fp, LOCK_EX)) {
        fclose($fp);
        @unlink($tmp);
        return false;
    }
    ftruncate($fp, 0);
    $written = fwrite($fp, $payload);
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    if ($written === false || $written < strlen($payload)) {
        @unlink($tmp);
        return false;
    }
    if (!@rename($tmp, $dataFile)) {
        if (@copy($tmp, $dataFile)) {
            @unlink($tmp);
            return true;
        }
        @unlink($tmp);
        return false;
    }
    return true;
}

/* ---------- Backups ---------- */

function ensureBackupDir(?string $uid = null): bool {
    $dir = lvBackupDir($uid);
    if (!is_dir($dir) && !@mkdir($dir, 0755, true)) return false;
    $ht = $dir . '/.htaccess';
    if (!is_file($ht)) {
        @file_put_contents($ht,
            "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n" .
            "<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
    }
    return is_writable($dir);
}

function backupCopy(string $name): bool {
    if (!is_file(lvDataFile()) || filesize(lvDataFile()) < 3) return false; // leer = nichts zu sichern
    if (!ensureBackupDir()) return false;
    return @copy(lvDataFile(), lvBackupDir() . '/' . $name);
}

function pruneBackups(string $prefix, int $keep, ?string $uid = null): void {
    $files = glob(lvBackupDir($uid) . '/' . $prefix . '*.json') ?: [];
    sort($files); // Namen sind zeitlich sortierbar
    while (count($files) > $keep) {
        @unlink(array_shift($files));
    }
}

// Ein Stand pro Tag: Zustand vor der ersten Änderung des Tages
function backupDaily(): void {
    global $LV_CORRUPT;
    if ($LV_CORRUPT) return;
    $name = 'tag_' . date('Y-m-d') . '.json';
    if (is_file(lvBackupDir() . '/' . $name)) return;
    if (backupCopy($name)) pruneBackups('tag_', BACKUP_KEEP_DAILY);
}

// Stand direkt vor einer großen Aktion
function backupBefore(string $label): void {
    global $LV_CORRUPT;
    $prefix = $LV_CORRUPT ? 'defekt_' : 'vor_';
    $name = $prefix . date('Ymd_His') . '_' . preg_replace('/[^a-z_]/', '', $label) . '.json';
    if (backupCopy($name)) pruneBackups($prefix, BACKUP_KEEP_PRE);
}

function listBackups(): array {
    $labels = [
        'bulk_delete' => 'vor Mehrfach-Löschen', 'dedupe' => 'vor Duplikate entfernen',
        'import' => 'vor Import', 'restore' => 'vor Wiederherstellung',
        'delete_category' => 'vor Ordner löschen',
    ];
    $out = [];
    foreach (glob(lvBackupDir() . '/*.json') ?: [] as $file) {
        $name = basename($file);
        if (!preg_match('/^(tag|vor)_/', $name, $m)) continue;
        $raw = (string)@file_get_contents($file);
        $json = lvDecodeStored($raw);
        $data = $json !== null ? json_decode($json, true) : null;
        if (!is_array($data)) continue;
        $label = 'Tagesstand';
        if ($m[1] === 'vor') {
            $key = preg_replace('/^vor_\d{8}_\d{6}_|\.json$/', '', $name);
            $label = $labels[$key] ?? 'vor Änderung';
        }
        $out[] = ['name' => $name, 'time' => filemtime($file), 'count' => count($data), 'label' => $label];
    }
    usort($out, fn($a, $b) => $b['time'] <=> $a['time']);
    return $out;
}

function requireSave(array &$bookmarks): void {
    // Papierkorb: nach LV_TRASH_DAYS endgültig weg
    $limit = time() - LV_TRASH_DAYS * 86400;
    $bookmarks = array_values(array_filter($bookmarks, fn($b) => empty($b['deleted']) || (int)$b['deleted'] > $limit));
    backupDaily();
    $ok = false;
    try { $ok = saveBookmarks($bookmarks); }
    catch (Exception $e) { throw new Exception('Speichern fehlgeschlagen. ' . $e->getMessage()); }
    if (!$ok) {
        $dir = dirname(lvDataFile());
        $hint = !is_writable($dir)
            ? ' Verzeichnis nicht beschreibbar.'
            : (file_exists(lvDataFile()) && !is_writable(lvDataFile())
                ? ' bookmarks.json nicht beschreibbar.'
                : ' Schreibvorgang fehlgeschlagen.');
        throw new Exception('Speichern fehlgeschlagen.' . $hint . ' Bitte Schreibrechte für den Ordner data/ prüfen.');
    }
}

/* ---------- Helfer ---------- */

function generateId(): string {
    return bin2hex(random_bytes(8));
}

function parseIds($raw): array {
    if (is_array($raw)) return array_filter(array_map('strval', $raw));
    if (is_string($raw) && $raw !== '') {
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) return array_filter(array_map('strval', $decoded));
        return array_filter(array_map('trim', explode(',', $raw)));
    }
    return [];
}

function jsonOut(array $data): void {
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function cleanText($s, int $max): string {
    $s = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', (string)$s) ?? '';
    $s = trim($s);
    if (function_exists('mb_substr')) return mb_substr($s, 0, $max, 'UTF-8');
    return substr($s, 0, $max);
}

// Prüft eine eingegebene URL, ergänzt https:// und lässt nur http/https zu
function cleanUrl($url): string {
    $url = trim((string)$url);
    if ($url === '') throw new Exception('URL fehlt.');
    if (!preg_match('~^https?://~i', $url)) {
        if (strpos($url, '://') !== false || preg_match('~^(javascript|data|vbscript|file|mailto|tel|about|blob):~i', $url)) {
            throw new Exception('Nur http- und https-Links sind erlaubt.');
        }
        $url = 'https://' . $url;
    }
    if (preg_match('/[\s<>"\x00-\x1F]/', $url)) throw new Exception('Ungültige URL.');
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        // Umlaut-Domains u. ä. fallen bei filter_var durch – Host muss trotzdem da sein
        $p = parse_url($url);
        if (!$p || empty($p['host'])) throw new Exception('Ungültige URL.');
    }
    return $url;
}

// Ordner dürfen verschachtelt sein: „Technik > Go“ (höchstens 4 Ebenen)
function cleanCategory($s): string {
    $parts = [];
    foreach (explode('>', (string)$s) as $p) {
        $p = cleanText($p, 60);
        if ($p !== '') $parts[] = $p;
    }
    $parts = array_slice($parts, 0, 4);
    return $parts ? implode(' > ', $parts) : 'Allgemein';
}

// Schlagwörter: aus JSON-Liste oder „a, b, c“. Höchstens 12, je 40 Zeichen, ohne #
function cleanTags($raw): array {
    if (is_string($raw)) {
        $dec = json_decode($raw, true);
        $raw = is_array($dec) ? $dec : preg_split('/[,;\n]+/', $raw);
    }
    if (!is_array($raw)) return [];
    $out = [];
    $seen = [];
    foreach ($raw as $t) {
        if (!is_string($t) && !is_numeric($t)) continue;
        $t = cleanText(ltrim(trim((string)$t), '#'), 40);
        $t = preg_replace('/\s+/u', '-', $t) ?? $t;
        $key = function_exists('mb_strtolower') ? mb_strtolower($t, 'UTF-8') : strtolower($t);
        if ($t === '' || isset($seen[$key])) continue;
        $seen[$key] = true;
        $out[] = $t;
        if (count($out) >= 12) break;
    }
    return $out;
}

// Macht aus fremden Daten (Import, Backup) einen sauberen Eintrag
function sanitizeItem($in, bool $full = false): ?array {
    if (!is_array($in)) return null;
    $url = trim((string)($in['url'] ?? ''));
    if ($url === '' || !preg_match('~^https?://~i', $url) || preg_match('/[\s<>"\x00-\x1F]/', $url)) return null;
    $title = cleanText($in['title'] ?? '', 300);
    if ($title === '') $title = (string)(parse_url($url, PHP_URL_HOST) ?: $url);
    $id = (string)($in['id'] ?? '');
    if (!preg_match('/^[A-Za-z0-9_\-]{6,40}$/', $id)) $id = generateId();
    $created = (int)($in['created'] ?? 0);
    if ($created <= 0) $created = time();
    $item = [
        'id' => $id, 'title' => $title, 'url' => $url,
        'category' => cleanCategory($in['category'] ?? ''),
        'description' => cleanText($in['description'] ?? '', 2000),
        'favorite' => !empty($in['favorite']), 'created' => $created,
    ];
    $tags = cleanTags($in['tags'] ?? []);
    if ($tags) $item['tags'] = $tags;
    if ($full) {
        // Komplett-Backup: auch Zähler und Papierkorb-Status übernehmen
        if (!empty($in['clicks'])) $item['clicks'] = max(0, (int)$in['clicks']);
        if (!empty($in['opened'])) $item['opened'] = max(0, (int)$in['opened']);
        if (!empty($in['deleted'])) $item['deleted'] = max(0, (int)$in['deleted']);
    }
    return $item;
}

/* ---------- CSRF-Token (Session-basiert) ---------- */

function lvCsrfToken(): string {
    lvStartSession();
    if (empty($_SESSION['lv_csrf']) || !is_string($_SESSION['lv_csrf']) || strlen($_SESSION['lv_csrf']) < 32) {
        $_SESSION['lv_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['lv_csrf'];
}

function lvCsrfCheck(): bool {
    lvStartSession();
    $session = $_SESSION['lv_csrf'] ?? '';
    if (!is_string($session) || $session === '') return false;
    $token = $_POST['csrf'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!is_string($token) || $token === '') return false;
    return hash_equals($session, $token);
}

/** Prüft CSRF; bei Fehler JSON-Antwort und Exit (für API-Aktionen) */
function lvRequireCsrf(): void {
    if (lvCsrfCheck()) return;
    http_response_code(403);
    jsonOut(['success' => false, 'message' => 'Sicherheits-Token ungültig oder fehlt. Seite neu laden.']);
}

/** Security-Header. Skripte laufen nur mit dem Einmal-Kennzeichen (Nonce) dieser Seite. */
function lvSecurityHeaders(bool $html = false): void {
    global $LV_NONCE;
    if (headers_sent()) return;
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    if (lvIsHttps()) {
        header('Strict-Transport-Security: max-age=31536000');
    }
    if ($html) {
        $script = LV_TAILWIND_CDN ? "'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com" : "'nonce-{$LV_NONCE}'";
        header("Content-Security-Policy: default-src 'none'; "
            . "script-src {$script}; "
            . "style-src 'self' 'unsafe-inline'; "
            . "font-src 'self'; "
            . "img-src 'self' data:; "
            . "connect-src 'self'; "
            . "manifest-src 'self'; "
            . "worker-src 'self'; "
            . "frame-ancestors 'none'; "
            . "base-uri 'none'; "
            . "form-action 'self'");
    } else {
        header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'");
    }
}

/* ---------- Login-Bremse + Anmelde-Protokoll (alles in data/throttle/) ---------- */

function lvThrottleDir(): string {
    lvEnsureDataDir();
    if (!is_dir(THROTTLE_DIR)) @mkdir(THROTTLE_DIR, 0700, true);
    return THROTTLE_DIR;
}

function lvRealIp(): string {
    // Nur REMOTE_ADDR – X-Forwarded-For o. Ä. kann jeder fälschen
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '0');
    return ($ip !== '0' && filter_var($ip, FILTER_VALIDATE_IP)) ? $ip : '0';
}

/** Für die Bremse: IPv6 wird auf das /64-Netz gekürzt, sonst hätte ein Angreifer Milliarden Adressen frei. */
function lvClientIp(): string {
    $ip = lvRealIp();
    if (strpos($ip, ':') !== false) {
        $bin = @inet_pton($ip);
        if ($bin !== false && strlen($bin) === 16) return bin2hex(substr($bin, 0, 8)) . '/64';
    }
    return $ip;
}

function lvThrottlePath(): string {
    return lvThrottleDir() . '/ip_' . hash('sha256', lvClientIp()) . '.json';
}

/**
 * Sperrzeiten in Sekunden nach Anzahl Fehlversuche (spürbar, Worker bleibt frei).
 * 1. Fehler: noch frei · 2.: 3s · 3.: 10s · 4.: 30s · 5.: 60s · danach steiler bis max. 15 Min.
 */
function lvThrottleLockSeconds(int $fails): int {
    if ($fails <= 1) return 0;
    if ($fails === 2) return 3;
    if ($fails === 3) return 10;
    if ($fails === 4) return 30;
    if ($fails === 5) return 60;
    return min(900, 60 * (int)pow(2, min($fails - 5, 4))); // 6→120, 7→240, 8→480, 9+→900
}

/** Throttle-Datei unter exklusivem Lock lesen (JSON-Array oder leeres Array). */
function lvThrottleReadLocked($fp): array {
    rewind($fp);
    $raw = stream_get_contents($fp);
    if ($raw === false || $raw === '') return [];
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

/** Throttle-Daten unter bestehendem Lock atomar zurückschreiben. */
function lvThrottleWriteLocked($fp, array $data): void {
    $json = json_encode($data, JSON_UNESCAPED_UNICODE);
    if ($json === false) return;
    rewind($fp);
    ftruncate($fp, 0);
    fwrite($fp, $json);
    fflush($fp);
}

function lvThrottleUntil(string $file): int {
    if (!is_file($file)) return 0;
    $fp = @fopen($file, 'c+');
    if ($fp === false) return 0;
    if (!flock($fp, LOCK_SH)) { fclose($fp); return 0; }
    $data = lvThrottleReadLocked($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return (int)($data['until'] ?? 0);
}

/**
 * Prüft, ob gerade ein Anmeldeversuch erlaubt ist (pro Adresse und insgesamt).
 * @return string|null Fehlermeldung wenn gesperrt, sonst null
 */
function lvLoginThrottleCheck(): ?string {
    $until = max(lvThrottleUntil(lvThrottlePath()), lvThrottleUntil(lvThrottleDir() . '/global.json'));
    $wait = $until - time();
    if ($wait <= 0) return null;
    if ($wait >= 60) {
        $m = (int)ceil($wait / 60);
        return "Zu viele Fehlversuche. Bitte in ca. {$m} Minute(n) erneut versuchen.";
    }
    return "Zu viele Fehlversuche. Bitte in {$wait} Sekunde(n) erneut versuchen.";
}

function lvLoginThrottleFail(): void {
    $now = time();
    // 1) pro Adresse: steigende Sperrzeit
    $fp = @fopen(lvThrottlePath(), 'c+');
    if ($fp !== false) {
        if (flock($fp, LOCK_EX)) {
            $data = lvThrottleReadLocked($fp);
            $fails = (int)($data['fails'] ?? 0) + 1;
            lvThrottleWriteLocked($fp, ['fails' => $fails, 'until' => $now + lvThrottleLockSeconds($fails), 'last' => $now]);
            flock($fp, LOCK_UN);
        }
        fclose($fp);
    }
    // 2) insgesamt: ab 15 Fehlversuchen in 15 Minuten kurze Pause für alle (gegen verteilte Angriffe)
    $fp = @fopen(lvThrottleDir() . '/global.json', 'c+');
    if ($fp !== false) {
        if (flock($fp, LOCK_EX)) {
            $data = lvThrottleReadLocked($fp);
            $times = array_values(array_filter((array)($data['times'] ?? []), fn($t) => (int)$t > $now - 900));
            $times[] = $now;
            $times = array_slice($times, -200);
            $n = count($times);
            $until = $n >= 15 ? $now + min(120, 5 * ($n - 14)) : 0;
            lvThrottleWriteLocked($fp, ['times' => $times, 'until' => $until, 'last' => $now]);
            flock($fp, LOCK_UN);
        }
        fclose($fp);
    }
    if (random_int(1, 5) === 1) lvLoginThrottlePrune();
}

/** Nach erfolgreichem Login: eigene Sperre weg + Altlasten löschen */
function lvLoginThrottleClear(): void {
    @unlink(lvThrottlePath());
    lvLoginThrottlePrune();
}

/** Löscht abgelaufene Sperr-Dateien, auch die der alten Version direkt in data/. */
function lvLoginThrottlePrune(): void {
    $now = time();
    foreach (glob(LV_DATA_DIR . '/login_*.throttle') ?: [] as $f) @unlink($f);
    foreach (glob(lvThrottleDir() . '/ip_*.json') ?: [] as $f) {
        if (!preg_match('~/ip_[a-f0-9]{64}\.json$~', $f)) continue;
        $data = json_decode((string)@file_get_contents($f), true);
        $last = (int)($data['last'] ?? 0);
        $until = (int)($data['until'] ?? 0);
        if (!is_array($data) || $last < $now - 86400 || ($until <= $now && $last < $now - 3600)) @unlink($f);
    }
    foreach (glob(lvThrottleDir() . '/reg_*.json') ?: [] as $f) {
        if ((int)@filemtime($f) < $now - 86400) @unlink($f);
    }
}

/** Sitzungen von Besuchern, die sich nie angemeldet haben (Bots auf der Login-Seite), nach 2 Stunden wegräumen. */
function lvSessionCleanup(): void {
    $now = time();
    foreach (glob(SESSION_DIR . '/sess_*') ?: [] as $f) {
        $age = $now - (int)@filemtime($f);
        if ($age < 7200) continue;
        if ($age > LV_SESSION_MAX_DAYS * 86400 || strpos((string)@file_get_contents($f, false, null, 0, 4000), 'lv_auth|b:1') === false) @unlink($f);
    }
}

/**
 * Anmelde-Protokoll. Die Einträge (Zeit, Adresse, versuchter Name) werden mit einem
 * öffentlichen Schlüssel verschlossen. Lesen kann sie nur, wer angemeldet ist.
 * Ohne die PHP-Erweiterung sodium wird nur Zeit und Art notiert.
 */
function lvEnsureLogKeys(array &$cfg, string $dek): bool {
    if (!empty($cfg['log_pub']) && !empty($cfg['log_sec'])) return false;
    if (!function_exists('sodium_crypto_box_keypair')) return false;
    try {
        $kp = sodium_crypto_box_keypair();
        $cfg['log_pub'] = base64_encode(sodium_crypto_box_publickey($kp));
        $cfg['log_sec'] = lvEncryptWith($dek, $kp);
        return true;
    } catch (Throwable $e) { return false; }
}

/**
 * Jeder Benutzer hat sein eigenes Protokoll. Versuche mit einem Namen, den es gibt, landen bei
 * diesem Benutzer. Alles andere (unbekannte Namen, Sperren) sieht der Administrator.
 */
function lvLogAttempt(string $kind, string $user = '', ?string $uid = null): void {
    if ($uid === null) {
        $hit = $user !== '' ? lvFindUser($user) : null;
        $uid = $hit !== null ? $hit['_uid'] : '';
    }
    if (!lvUidOk($uid)) $uid = '';
    lvThrottleDir();
    $file = lvAttemptsFile($uid);
    $rec = ['t' => time(), 'k' => $kind, 'ip' => lvRealIp(), 'u' => cleanText($user, 64)];
    $line = null;
    $cfg = lvLoadAuthConfig(false, $uid);
    if ($cfg && !empty($cfg['log_pub']) && function_exists('sodium_crypto_box_seal')) {
        $pk = base64_decode((string)$cfg['log_pub'], true);
        if ($pk !== false && strlen($pk) === SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            try { $line = 'S' . base64_encode(sodium_crypto_box_seal((string)json_encode($rec, JSON_INVALID_UTF8_SUBSTITUTE), $pk)); }
            catch (Throwable $e) { $line = null; }
        }
    }
    if ($line === null) $line = 'P' . base64_encode((string)json_encode(['t' => $rec['t'], 'k' => $kind]));
    @file_put_contents($file, $line . "\n", FILE_APPEND | LOCK_EX);
    // Nicht endlos wachsen lassen: die letzten 500 Einträge reichen
    if (@filesize($file) > 400000) {
        $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        @file_put_contents($file, implode("\n", array_slice($lines, -500)) . "\n", LOCK_EX);
    }
}

/** Protokoll lesen, neueste zuerst. */
function lvReadAttempts(array $cfg, string $dek, int $max = 500): array {
    $file = lvAttemptsFile((string)($cfg['_uid'] ?? ''));
    if (!is_file($file)) return [];
    $kp = null;
    if (!empty($cfg['log_sec']) && function_exists('sodium_crypto_box_seal_open')) {
        $kp = lvDecryptWith($dek, (string)$cfg['log_sec']);
    }
    $out = [];
    $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    foreach (array_reverse(array_slice($lines, -$max)) as $line) {
        $bin = base64_decode(substr($line, 1), true);
        if ($bin === false) continue;
        $json = null;
        if ($line[0] === 'P') $json = $bin;
        elseif ($line[0] === 'S' && $kp !== null) {
            try { $json = sodium_crypto_box_seal_open($bin, $kp); } catch (Throwable $e) { $json = false; }
            if ($json === false) $json = null;
        }
        $rec = $json !== null ? json_decode($json, true) : null;
        if (!is_array($rec) || empty($rec['t'])) continue;
        $out[] = ['t' => (int)$rec['t'], 'k' => (string)($rec['k'] ?? ''), 'ip' => (string)($rec['ip'] ?? ''), 'u' => (string)($rec['u'] ?? '')];
    }
    return $out;
}

/** Was ist seit der letzten erfolgreichen Anmeldung passiert? */
function lvLoginNotice(array $cfg, string $dek): array {
    $fails = 0; $ips = []; $last = 0; $lastIp = '';
    foreach (lvReadAttempts($cfg, $dek) as $r) {
        if ($r['k'] === 'ok') { $last = $r['t']; $lastIp = $r['ip']; break; }
        $fails++;
        if ($r['ip'] !== '') $ips[$r['ip']] = true;
    }
    return ['fails' => $fails, 'ips' => count($ips), 'last' => $last, 'last_ip' => $lastIp];
}

/* ---------- Abrufe nach draußen (Titel, Favicons, Link-Check), geschützt gegen Umwege ins interne Netz ---------- */

function lvIpIsPublic(string $ip): bool {
    if (stripos($ip, '::ffff:') === 0 && strpos($ip, '.') !== false) $ip = substr($ip, 7);
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return false;
    if (strpos($ip, ':') === false) {
        $n = ip2long($ip);
        if ($n !== false && ($n & 0xFFC00000) === 0x64400000) return false; // 100.64.0.0/10
    }
    return true;
}

/** Ergebnis: ['state' => ok|private|nx, 'ip' => geprüfte Adresse] */
function lvResolveHost(string $host): array {
    $h = trim($host, '[]');
    if (filter_var($h, FILTER_VALIDATE_IP)) {
        return lvIpIsPublic($h) ? ['state' => 'ok', 'ip' => $h] : ['state' => 'private', 'ip' => ''];
    }
    if ($h === '' || strtolower($h) === 'localhost' || strpos($h, '.') === false) return ['state' => 'private', 'ip' => ''];
    if (preg_match('/[^\x20-\x7e]/', $h) && function_exists('idn_to_ascii')) {
        $a = @idn_to_ascii($h, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        if (is_string($a) && $a !== '') $h = $a;
    }
    $all = @gethostbynamel($h) ?: [];
    if (!$all && function_exists('dns_get_record')) {
        foreach ((@dns_get_record($h, DNS_AAAA) ?: []) as $r) {
            if (!empty($r['ipv6'])) $all[] = $r['ipv6'];
        }
    }
    if (!$all) return ['state' => 'nx', 'ip' => ''];
    foreach ($all as $ip) {
        if (!lvIpIsPublic($ip)) return ['state' => 'private', 'ip' => ''];
    }
    return ['state' => 'ok', 'ip' => $all[0]];
}

function lvAbsUrl(string $base, string $loc): string {
    $loc = trim($loc);
    if (preg_match('~^[a-z][a-z0-9+.\-]*:~i', $loc)) return $loc;
    $b = parse_url($base);
    $scheme = strtolower($b['scheme'] ?? 'https');
    $origin = $scheme . '://' . ($b['host'] ?? '') . (isset($b['port']) ? ':' . $b['port'] : '');
    if (strncmp($loc, '//', 2) === 0) return $scheme . ':' . $loc;
    if ($loc !== '' && $loc[0] === '/') return $origin . $loc;
    $path = $b['path'] ?? '/';
    $dir = substr($path, 0, (int)strrpos($path, '/') + 1) ?: '/';
    return $origin . $dir . $loc;
}

/** cURL-Handle, fest auf die vorher geprüfte IP-Adresse genagelt. $state sammelt body + Weiterleitungsziel. */
function lvCurlMake(string $url, array $p, string $ip, bool $head, int $limit, int $timeout, string $accept, array &$state) {
    $state = ['body' => '', 'loc' => ''];
    $ch = curl_init($url);
    $port = (int)($p['port'] ?? (strtolower($p['scheme'] ?? '') === 'http' ? 80 : 443));
    curl_setopt_array($ch, [
        CURLOPT_NOBODY => $head,
        CURLOPT_FOLLOWLOCATION => false, // Weiterleitungen prüfen wir selbst, Schritt für Schritt
        CURLOPT_CONNECTTIMEOUT => min(5, $timeout),
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => LV_UA,
        CURLOPT_ENCODING => '',
        CURLOPT_HTTPHEADER => ['Accept: ' . $accept, 'Accept-Language: de,en;q=0.8'],
        CURLOPT_RESOLVE => [trim($p['host'], '[]') . ':' . $port . ':' . $ip],
        CURLOPT_HEADERFUNCTION => function ($c, $line) use (&$state) {
            if (stripos($line, 'location:') === 0) $state['loc'] = trim(substr($line, 9));
            return strlen($line);
        },
        CURLOPT_WRITEFUNCTION => function ($c, $data) use (&$state, $limit) {
            $state['body'] .= $data;
            return strlen($state['body']) > $limit ? 0 : strlen($data);
        },
    ]);
    if (defined('CURLOPT_PROTOCOLS') && defined('CURLPROTO_HTTP')) {
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    }
    return $ch;
}

/**
 * Holt eine Adresse. Jede Station (auch nach Weiterleitungen) muss eine öffentliche Adresse sein.
 * Ergebnis: code, body, ctype, url (Endadresse), errno (6 = Domain gibt es nicht, 28 = Zeit), blocked
 */
function lvSafeFetch(string $url, array $o = []): array {
    $limit = (int)($o['limit'] ?? 200000);
    $timeout = (int)($o['timeout'] ?? 8);
    $head = !empty($o['head']);
    $accept = (string)($o['accept'] ?? 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5');
    $res = ['code' => 0, 'body' => '', 'ctype' => '', 'url' => $url, 'errno' => 0, 'blocked' => false];
    for ($hop = 0; $hop <= 5; $hop++) {
        $p = parse_url($url);
        if (!$p || empty($p['host']) || !in_array(strtolower($p['scheme'] ?? ''), ['http', 'https'], true)) {
            $res['blocked'] = true;
            return $res;
        }
        $r = lvResolveHost($p['host']);
        if ($r['state'] === 'private') { $res['blocked'] = true; return $res; }
        if ($r['state'] === 'nx') { $res['errno'] = 6; return $res; }
        $res['url'] = $url;
        $loc = '';
        if (function_exists('curl_init')) {
            $state = [];
            $ch = lvCurlMake($url, $p, $r['ip'], $head, $limit, $timeout, $accept, $state);
            curl_exec($ch);
            $res['code'] = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $res['ctype'] = (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
            $res['errno'] = $res['code'] > 0 ? 0 : (int)curl_errno($ch);
            $res['body'] = $state['body'];
            $loc = $state['loc'];
            curl_close($ch);
        } else {
            $ctx = stream_context_create([
                'http' => ['method' => $head ? 'HEAD' : 'GET', 'timeout' => $timeout, 'ignore_errors' => true, 'follow_location' => 0,
                           'header' => "User-Agent: " . LV_UA . "\r\nAccept: {$accept}\r\nAccept-Language: de,en;q=0.8\r\n"],
                'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
            ]);
            $body = @file_get_contents($url, false, $ctx, 0, $limit);
            $res['body'] = $body === false ? '' : $body;
            $res['code'] = 0;
            foreach (($http_response_header ?? []) as $h) {
                if (preg_match('~^HTTP/\S+\s+(\d+)~', $h, $m)) $res['code'] = (int)$m[1];
                elseif (stripos($h, 'content-type:') === 0) $res['ctype'] = trim(substr($h, 13));
                elseif (stripos($h, 'location:') === 0) $loc = trim(substr($h, 9));
            }
        }
        if ($res['code'] >= 300 && $res['code'] < 400 && $loc !== '') {
            $url = lvAbsUrl($url, $loc);
            continue;
        }
        return $res;
    }
    $res['code'] = 0;
    $res['errno'] = 47; // zu viele Weiterleitungen
    return $res;
}

function sniffImageType(string $bin): string {
    if (strncmp($bin, "\x89PNG", 4) === 0) return 'image/png';
    if (strncmp($bin, "\x00\x00\x01\x00", 4) === 0) return 'image/x-icon';
    if (strncmp($bin, 'GIF8', 4) === 0) return 'image/gif';
    if (strncmp($bin, "\xFF\xD8\xFF", 3) === 0) return 'image/jpeg';
    if (strncmp($bin, 'RIFF', 4) === 0 && substr($bin, 8, 4) === 'WEBP') return 'image/webp';
    return '';
}

function lvIconType(string $bin): string {
    $t = sniffImageType($bin);
    if ($t !== '') return $t;
    $head = ltrim(substr($bin, 0, 1000));
    if (stripos($head, '<svg') !== false && preg_match('~^(<\?xml|<svg|<!--|<!DOCTYPE)~i', $head)) return 'image/svg+xml';
    return '';
}

/** Sucht das Icon direkt bei der Seite selbst (kein Google, kein DuckDuckGo). Ergebnis: Bilddaten oder null */
function lvFindFavicon(string $domain): ?string {
    $deadline = microtime(true) + 14;
    foreach ([$domain, 'www.' . $domain] as $host) {
        $page = lvSafeFetch('https://' . $host . '/', ['limit' => 150000, 'timeout' => 5]);
        if ($page['blocked']) return null;
        if ($page['code'] === 0 && $page['body'] === '') continue;
        $cands = [];
        if ($page['body'] !== '' && preg_match_all('~<link\b[^>]*>~i', $page['body'], $m)) {
            foreach ($m[0] as $tag) {
                if (!preg_match('~\brel\s*=\s*["\']?([^"\'>]+)~i', $tag, $r)) continue;
                if (stripos($r[1], 'icon') === false || stripos($r[1], 'mask-icon') !== false) continue;
                if (!preg_match('~\bhref\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))~i', $tag, $h)) continue;
                $href = '';
                foreach ([1, 2, 3] as $i) if (isset($h[$i]) && $h[$i] !== '') { $href = $h[$i]; break; }
                $href = html_entity_decode(trim($href), ENT_QUOTES | ENT_HTML5, 'UTF-8');
                if ($href === '' || stripos($href, 'data:') === 0) continue;
                $score = 50;
                if (preg_match('~\bsizes\s*=\s*["\']?(\d+)~i', $tag, $s)) {
                    $n = (int)$s[1];
                    $score = ($n >= 32 && $n <= 192) ? 100 - (int)(abs(64 - $n) / 4) : ($n < 32 ? 30 : 40);
                }
                if (stripos($r[1], 'apple') !== false) $score -= 5;
                $cands[] = [$score, lvAbsUrl($page['url'], $href)];
            }
        }
        usort($cands, fn($a, $b) => $b[0] <=> $a[0]);
        $urls = array_slice(array_column($cands, 1), 0, 3);
        $urls[] = lvAbsUrl($page['url'], '/favicon.ico');
        foreach (array_unique($urls) as $u) {
            if (microtime(true) > $deadline) return null;
            $img = lvSafeFetch($u, ['limit' => 400000, 'timeout' => 5, 'accept' => 'image/*,*/*;q=0.5']);
            $len = strlen($img['body']);
            if ($img['code'] >= 200 && $img['code'] < 300 && $len > 20 && $len <= 400000 && lvIconType($img['body']) !== '') {
                return $img['body'];
            }
        }
        return null;
    }
    return null;
}

/* ---------- Link-Check ---------- */

/** Prüft mehrere Adressen gleichzeitig, folgt Weiterleitungen selbst. Ergebnis je Schlüssel: code, errno (-1 = lokale Adresse) */
function lvMultiProbe(array $urls, bool $head): array {
    $out = [];
    $pending = $urls;
    for ($round = 0; $round <= 5 && $pending; $round++) {
        $mh = curl_multi_init();
        $hs = [];
        $states = [];
        foreach ($pending as $k => $u) {
            $p = parse_url($u);
            $ok = $p && !empty($p['host']) && in_array(strtolower($p['scheme'] ?? ''), ['http', 'https'], true);
            $r = $ok ? lvResolveHost($p['host']) : ['state' => 'private', 'ip' => ''];
            if ($r['state'] !== 'ok') {
                $out[$k] = ['code' => 0, 'errno' => $r['state'] === 'nx' ? 6 : -1];
                continue;
            }
            $states[$k] = [];
            $hs[$k] = lvCurlMake($u, $p, $r['ip'], $head, 4096, 8, 'text/html,application/xhtml+xml,*/*;q=0.8', $states[$k]);
            curl_multi_add_handle($mh, $hs[$k]);
        }
        $errnos = [];
        do {
            $status = curl_multi_exec($mh, $running);
            while ($info = curl_multi_info_read($mh)) $errnos[spl_object_id($info['handle'])] = $info['result'];
            if ($running) curl_multi_select($mh, 1.0);
        } while ($running && $status === CURLM_OK);
        while ($info = curl_multi_info_read($mh)) $errnos[spl_object_id($info['handle'])] = $info['result'];
        $next = [];
        foreach ($hs as $k => $ch) {
            $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $errno = $code > 0 ? 0 : (int)($errnos[spl_object_id($ch)] ?? 0);
            if ($code >= 300 && $code < 400 && $states[$k]['loc'] !== '') $next[$k] = lvAbsUrl($pending[$k], $states[$k]['loc']);
            else $out[$k] = ['code' => $code, 'errno' => $errno];
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
        }
        curl_multi_close($mh);
        $pending = $next;
    }
    foreach ($pending as $k => $u) $out[$k] = ['code' => 0, 'errno' => 47];
    return $out;
}

/**
 * Prüft URLs. Ergebnis je Schlüssel: ['status' => ok|dead|unclear, 'code' => int, 'note' => string]
 * dead    = sicher weg (404/410 oder Domain existiert nicht)
 * unclear = Seite blockt Abfragen, Serverfehler, Zeitüberschreitung – bitte selbst ansehen
 */
function lvCheckUrls(array $urls): array {
    $res = [];
    $todo = [];
    foreach ($urls as $k => $u) {
        if (!preg_match('~^https?://~i', $u) || (string)parse_url($u, PHP_URL_HOST) === '') {
            $res[$k] = ['status' => 'unclear', 'code' => 0, 'note' => 'keine prüfbare Adresse'];
        } else {
            $todo[$k] = $u;
        }
    }
    $raw = [];
    if ($todo && function_exists('curl_multi_init')) {
        $raw = lvMultiProbe($todo, true);
        // Zweiter Versuch mit GET für alles, was auf HEAD nicht sauber geantwortet hat
        $retry = [];
        foreach ($raw as $k => $r) {
            $ok = $r['code'] >= 200 && $r['code'] < 400;
            if (!$ok && !in_array($r['errno'], [6, 28, -1], true)) $retry[$k] = $todo[$k];
        }
        if ($retry) {
            foreach (lvMultiProbe($retry, false) as $k => $r) {
                if ($r['code'] > 0) $raw[$k] = ['code' => $r['code'], 'errno' => 0];
                elseif ($raw[$k]['code'] === 0) $raw[$k] = $r;
            }
        }
    } else {
        foreach ($todo as $k => $u) {
            $r = lvSafeFetch($u, ['head' => true, 'timeout' => 6]);
            if ($r['code'] === 0 || $r['code'] >= 400) {
                $g = lvSafeFetch($u, ['limit' => 4096, 'timeout' => 6]);
                if ($g['code'] > 0) $r = $g;
            }
            $raw[$k] = ['code' => $r['code'], 'errno' => $r['blocked'] ? -1 : $r['errno']];
        }
    }
    $dnsWorks = null;
    foreach ($raw as $k => $r) {
        $code = $r['code'];
        if ($code >= 200 && $code < 400) {
            $res[$k] = ['status' => 'ok', 'code' => $code, 'note' => ''];
        } elseif ($code === 404 || $code === 410) {
            $res[$k] = ['status' => 'dead', 'code' => $code, 'note' => 'Seite nicht gefunden'];
        } elseif ($code === 0 && $r['errno'] === -1) {
            $res[$k] = ['status' => 'unclear', 'code' => 0, 'note' => 'lokale Adresse, vom Server aus nicht prüfbar'];
        } elseif ($code === 0 && $r['errno'] === 6) {
            // Sicherheitsnetz: Klappt die Namensauflösung auf dem Server gerade gar nicht, sähe sonst jede Seite „tot“ aus
            if ($dnsWorks === null) {
                $dnsWorks = (bool)@gethostbynamel('www.wikipedia.org') || (bool)@gethostbynamel('one.one.one.one');
            }
            $res[$k] = $dnsWorks
                ? ['status' => 'dead', 'code' => 0, 'note' => 'Domain existiert nicht mehr']
                : ['status' => 'unclear', 'code' => 0, 'note' => 'Server kann gerade keine Adressen auflösen'];
        } elseif ($code === 0) {
            $res[$k] = ['status' => 'unclear', 'code' => 0, 'note' => $r['errno'] === 28 ? 'Zeitüberschreitung' : 'keine Antwort'];
        } elseif ($code === 401 || $code === 403 || $code === 429) {
            $res[$k] = ['status' => 'unclear', 'code' => $code, 'note' => 'Seite blockt automatische Abfragen'];
        } elseif ($code >= 500) {
            $res[$k] = ['status' => 'unclear', 'code' => $code, 'note' => 'Serverfehler, evtl. nur vorübergehend'];
        } else {
            $res[$k] = ['status' => 'unclear', 'code' => $code, 'note' => 'unerwartete Antwort'];
        }
    }
    return $res;
}

/* ---------- Titel einer Seite holen ---------- */

function lvExtractMeta(string $html, string $ctype): array {
    // Ist der Text schon gültiges UTF-8, bleibt er so. Sonst nach Angabe der Seite umwandeln
    // (Server-Angabe zuerst, dann Meta-Tag), ohne brauchbare Angabe als westeuropäisch behandeln.
    if (function_exists('mb_check_encoding') && !mb_check_encoding($html, 'UTF-8')) {
        $candidates = [];
        if (preg_match('~charset=["\']?([\w\-]+)~i', $ctype, $m)) $candidates[] = $m[1];
        if (preg_match('~<meta[^>]+charset=["\']?([\w\-]+)~i', $html, $m)) $candidates[] = $m[1];
        $candidates[] = 'Windows-1252';
        foreach ($candidates as $cs) {
            if (preg_match('~^utf-?8$~i', $cs)) continue;
            if (preg_match('~^iso-8859-1$~i', $cs)) $cs = 'Windows-1252'; // Browser machen das genauso
            try {
                $conv = mb_convert_encoding($html, 'UTF-8', $cs);
                if (is_string($conv) && $conv !== '') { $html = $conv; break; }
            } catch (Throwable $e) { /* unbekannter Zeichensatz: nächsten versuchen */ }
        }
    }
    $tidy = function (string $s, int $max): string {
        $s = html_entity_decode($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $s = preg_replace('/\s+/u', ' ', $s) ?? $s;
        return cleanText($s, $max);
    };
    $meta = function (string $name) use ($html): string {
        if (preg_match_all('~<meta\b[^>]*>~i', $html, $mm)) {
            foreach ($mm[0] as $tag) {
                if (preg_match('~\b(?:name|property)\s*=\s*["\']?' . preg_quote($name, '~') . '(?=["\'\s>/])~i', $tag)
                    && preg_match('~\bcontent\s*=\s*(?:"([^"]*)"|\'([^\']*)\')~i', $tag, $c)) {
                    return ($c[1] ?? '') !== '' ? $c[1] : ($c[2] ?? '');
                }
            }
        }
        return '';
    };
    $title = '';
    if (preg_match('~<title\b[^>]*>(.*?)</title>~is', $html, $m)) $title = $tidy($m[1], 200);
    if ($title === '') $title = $tidy($meta('og:title'), 200);
    $desc = $tidy($meta('description'), 300);
    if ($desc === '') $desc = $tidy($meta('og:description'), 300);
    return ['title' => $title, 'description' => $desc];
}

/* ---------- Import ---------- */

// Ordnerpfad zu einem Link aus einer Browser-Lesezeichen-Datei, z. B. „Technik > Go“
function lvFolderFor(DOMNode $a): string {
    $h3Of = function (DOMNode $n): ?string {
        if (strtolower($n->nodeName) === 'h3') return trim($n->textContent);
        if ($n instanceof DOMElement) {
            // Der Parser verschachtelt die Einträge, die Überschrift kann tiefer liegen: die letzte zählt
            $hs = $n->getElementsByTagName('h3');
            if ($hs->length) return trim($hs->item($hs->length - 1)->textContent);
        }
        return null;
    };
    $names = [];
    for ($n = $a->parentNode; $n; $n = $n->parentNode) {
        if (strtolower($n->nodeName) !== 'dl') continue;
        $found = null;
        // Ordner-Überschrift steht direkt vor der Liste …
        for ($p = $n->previousSibling; $p; $p = $p->previousSibling) {
            $name = strtolower($p->nodeName);
            if ($name === 'h3' || $name === 'dt') { $found = (string)$h3Of($p); break; }
            if ($name === 'dl') break;
        }
        // … oder die Liste liegt im Eintrag der Überschrift
        if ($found === null) {
            $par = $n->parentNode;
            if ($par && strtolower($par->nodeName) === 'dt') $found = (string)$h3Of($par);
        }
        if ($found !== null && $found !== '') $names[] = $found;
    }
    $names = array_reverse($names);
    // Die Sammelordner der Browser selbst weglassen, wenn darunter echte Ordner liegen
    $roots = ['lesezeichen-symbolleiste', 'lesezeichenleiste', 'lesezeichen-menü', 'lesezeichenmenü', 'weitere lesezeichen',
              'bookmarks bar', 'bookmarks toolbar', 'bookmarks menu', 'other bookmarks', 'mobile lesezeichen', 'mobile bookmarks',
              'favoritenleiste', 'favorites bar'];
    $lower = fn($s) => function_exists('mb_strtolower') ? mb_strtolower($s, 'UTF-8') : strtolower($s);
    if (count($names) > 1 && in_array($lower($names[0]), $roots, true)) array_shift($names);
    return implode(' > ', array_slice($names, -4));
}

/** Liest eine Import-Datei (Browser-HTML oder JSON) und liefert [neue Einträge, übersprungen] */
function lvParseImport(string $html, array $bookmarks): array {
    if (strncmp($html, "\xEF\xBB\xBF", 3) === 0) $html = substr($html, 3);
    $skipped = 0;
    $new = [];
    $existingUrls = [];
    $haveIds = [];
    foreach ($bookmarks as $b) {
        $haveIds[(string)($b['id'] ?? '')] = true;
        if (empty($b['deleted'])) $existingUrls[(string)($b['url'] ?? '')] = true;
    }
    $first = substr(ltrim($html), 0, 1);
    if ($first === '[' || $first === '{') {
        $data = json_decode($html, true);
        if (!is_array($data)) throw new Exception('JSON-Datei ist ungültig.');
        if (($data['format'] ?? '') === 'LVBACKUP1') throw new Exception('Das ist ein Komplett-Backup. Bitte unter Werkzeuge → Backups einspielen.');
        if (isset($data['bookmarks']) && is_array($data['bookmarks'])) $data = $data['bookmarks'];
        foreach ($data as $raw) {
            $item = sanitizeItem($raw);
            if (!$item) continue;
            if (isset($existingUrls[$item['url']])) { $skipped++; continue; }
            if (isset($haveIds[$item['id']])) $item['id'] = generateId();
            $new[] = $item;
            $existingUrls[$item['url']] = true;
            $haveIds[$item['id']] = true;
        }
    } else {
        if (!class_exists('DOMDocument')) throw new Exception('PHP-Erweiterung DOM fehlt auf dem Server.');
        $dom = new DOMDocument();
        // Ohne Zeichensatz-Angabe in der Datei würden Umlaute sonst kaputtgehen
        $hasCharset = (bool)preg_match('~<meta[^>]+charset~i', substr($html, 0, 2000));
        @$dom->loadHTML(($hasCharset ? '' : '<?xml encoding="UTF-8">') . $html, LIBXML_NOERROR | LIBXML_NOWARNING);
        foreach ($dom->getElementsByTagName('a') as $a) {
            $href = trim($a->getAttribute('href'));
            $title = cleanText($a->textContent, 300);
            if (!$href || !$title || !preg_match('~^https?://~i', $href) || preg_match('/[\s<>"\x00-\x1F]/', $href)) continue;
            if (isset($existingUrls[$href])) { $skipped++; continue; }
            $folder = lvFolderFor($a);
            $added = (int)$a->getAttribute('add_date');
            $item = [
                'id' => generateId(), 'title' => $title, 'url' => $href,
                'category' => $folder !== '' ? cleanCategory($folder) : 'Importiert', 'description' => '',
                'favorite' => false, 'created' => $added > 0 ? $added : time(),
            ];
            $tags = cleanTags((string)$a->getAttribute('tags'));
            if ($tags) $item['tags'] = $tags;
            $new[] = $item;
            $existingUrls[$href] = true;
        }
    }
    return [$new, $skipped];
}

function lvUploadedFile(string $field, int $maxBytes = 20000000): string {
    if (!isset($_FILES[$field]) || $_FILES[$field]['error'] !== UPLOAD_ERR_OK || !is_uploaded_file($_FILES[$field]['tmp_name'])) {
        throw new Exception('Datei-Upload fehlgeschlagen.');
    }
    if ((int)$_FILES[$field]['size'] > $maxBytes) throw new Exception('Datei ist zu groß.');
    $raw = file_get_contents($_FILES[$field]['tmp_name']);
    if ($raw === false) throw new Exception('Datei konnte nicht gelesen werden.');
    return $raw;
}

/** Bestätigung mit dem aktuellen Passwort für heikle Aktionen. Liefert den Datenschlüssel. */
function lvRequirePassword(array $cfg, string $current): string {
    $fails = (int)($_SESSION['lv_pwfail'] ?? 0);
    if ($current === '' || !password_verify($current, $cfg['password_hash'])) {
        $_SESSION['lv_pwfail'] = $fails + 1;
        if ($fails + 1 >= 5) { lvLogAttempt('fail', $cfg['username'], (string)($cfg['_uid'] ?? '')); lvLogout(); throw new Exception('Zu viele falsche Eingaben, du wurdest abgemeldet.'); }
        throw new Exception('Aktuelles Passwort ist falsch.');
    }
    $_SESSION['lv_pwfail'] = 0;
    $dek = lvUnwrapKey($current, $cfg);
    if ($dek === null) throw new Exception('Datenschlüssel konnte nicht gelesen werden.');
    return $dek;
}

function lvFontData(): string {
    return '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';
}

/* ================================================================== */

$action = $_POST['action'] ?? $_GET['action'] ?? null;
if (!is_string($action) || $action === '') $action = null;
$isPost = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';

/* ---------- Öffentliche Kleinigkeiten: Schrift, App-Icon, Web-App-Angaben ---------- */

if ($action === 'font') {
    lvSecurityHeaders(false);
    header('Content-Type: font/woff2');
    header('Cache-Control: public, max-age=31536000, immutable');
    echo base64_decode(lvFontData());
    exit;
}

if ($action === 'icon') {
    lvSecurityHeaders(false);
    header('Cache-Control: public, max-age=604800');
    $s = (int)($_GET['s'] ?? 0);
    if ($s > 0) {
        // App-Icon (fertig eingebettet, braucht keine Grafik-Erweiterung)
        header('Content-Type: image/png');
        echo base64_decode($s >= 512 ? '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' : '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');
        exit;
    }
    header('Content-Type: image/svg+xml');
    echo '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#7c3aed"/><path fill="#fff" d="M7.5 5.5h9V19L12 16.6 7.5 19z"/></svg>';
    exit;
}

if ($action === 'manifest') {
    lvSecurityHeaders(false);
    header('Content-Type: application/manifest+json; charset=utf-8');
    header('Cache-Control: public, max-age=3600');
    echo json_encode([
        'name' => 'LinkVault', 'short_name' => 'LinkVault', 'description' => 'Deine Lesezeichen, verschlüsselt auf dem eigenen Server',
        'id' => './', 'start_url' => './', 'scope' => './',
        'display' => 'standalone', 'background_color' => '#0b1120', 'theme_color' => '#0b1120', 'lang' => 'de',
        'categories' => ['productivity', 'utilities'],
        'icons' => [
            ['src' => './?action=icon&s=192', 'sizes' => '192x192', 'type' => 'image/png', 'purpose' => 'any'],
            ['src' => './?action=icon&s=512', 'sizes' => '512x512', 'type' => 'image/png', 'purpose' => 'any'],
            ['src' => './?action=icon&s=192', 'sizes' => '192x192', 'type' => 'image/png', 'purpose' => 'maskable'],
            ['src' => './?action=icon&s=512', 'sizes' => '512x512', 'type' => 'image/png', 'purpose' => 'maskable'],
        ],
        // Langer Druck auf das App-Icon
        'shortcuts' => [
            ['name' => 'Neuer Link', 'short_name' => 'Neu', 'url' => './?new=1', 'icons' => [['src' => './?action=icon&s=192', 'sizes' => '192x192', 'type' => 'image/png']]],
        ],
        // „Teilen“ am Handy: LinkVault taucht in der Teilen-Liste auf
        'share_target' => ['action' => './', 'method' => 'GET', 'enctype' => 'application/x-www-form-urlencoded', 'params' => ['title' => 'title', 'text' => 'text', 'url' => 'url']],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

// Kleiner Helfer im Hintergrund der App: zeigt ohne Netz eine freundliche Seite statt des Browser-Fehlers.
// Er speichert bewusst NICHTS zwischen, deine Links bleiben nur auf dem Server.
if ($action === 'sw') {
    header('Content-Type: application/javascript; charset=utf-8');
    header('Cache-Control: no-cache');
    header('X-Content-Type-Options: nosniff');
    header("Content-Security-Policy: default-src 'none'; connect-src 'self'");
    $offline = '<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">'
        . '<meta name="theme-color" content="#0b1120"><title>LinkVault – offline</title><style>'
        . 'body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem;font-family:system-ui,-apple-system,sans-serif;'
        . 'color:#f1f5f9;background:linear-gradient(165deg,#0b1120 0%,#0f172a 45%,#1e1b4b 100%);text-align:center}'
        . '.l{width:3rem;height:3rem;border-radius:.8rem;background:linear-gradient(135deg,#8b5cf6,#7c3aed);margin:0 auto 1rem;display:flex;align-items:center;justify-content:center}'
        . 'h1{font-size:1.15rem;margin:0 0 .4rem}p{color:#94a3b8;font-size:.9rem;line-height:1.5;margin:0 0 1.25rem}'
        . 'a{display:inline-block;padding:.75rem 1.5rem;border-radius:.7rem;background:linear-gradient(135deg,#8b5cf6,#7c3aed);color:#fff;font-weight:600;text-decoration:none}'
        . '</style></head><body><div><div class="l"><svg width="22" height="22" fill="none" stroke="#fff" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 5a2 2 0 012-2h10a2 2 0 012 2v16l-7-3.5L5 21V5z"/></svg></div>'
        . '<h1>Keine Verbindung</h1><p>LinkVault erreicht den Server gerade nicht.<br>Deine Links liegen sicher dort und sind gleich wieder da.</p><a href="./">Erneut versuchen</a></div></body></html>';
    echo 'const OFFLINE = ' . json_encode($offline, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . ";\n"
        . "self.addEventListener('install', () => self.skipWaiting());\n"
        . "self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));\n"
        . "self.addEventListener('fetch', e => {\n"
        . "    const r = e.request;\n"
        . "    if (r.mode !== 'navigate' || r.method !== 'GET') return;\n"
        . "    e.respondWith(fetch(r).catch(() => new Response(OFFLINE, { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8' } })));\n"
        . "});\n";
    exit;
}

/* ---------- Favicons: nur angemeldet, direkt von der Seite, verschlüsselt und ohne Klarnamen gespeichert ---------- */

if ($action === 'favicon') {
    lvSecurityHeaders(false);
    if (!lvIsLoggedIn()) { http_response_code(401); exit; }
    $key = lvDataKey();
    session_write_close(); // viele Icons laden gleichzeitig, die Session darf das nicht ausbremsen
    $domain = strtolower(trim((string)($_GET['domain'] ?? '')));
    $domain = preg_replace('/^www\./', '', $domain);
    $domain = preg_replace('/[^a-z0-9.\-]/', '', $domain ?? '');
    if ($domain === '' || strlen($domain) > 200 || strpos($domain, '.') === false || $key === null) {
        http_response_code(400);
        exit;
    }
    $favDir = lvFaviconDir();
    if (!is_dir($favDir)) @mkdir($favDir, 0700, true);
    // Dateiname = Prüfsumme mit deinem Schlüssel. Aus dem Namen lässt sich die Domain nicht ablesen.
    $cacheFile = $favDir . '/' . hash_hmac('sha256', 'favicon|' . $domain, $key) . '.bin';
    $maxAge = 60 * 60 * 24 * 30;
    $retryAge = 60 * 60 * 24 * 3;
    $bin = null;
    $known = false;
    if (is_file($cacheFile)) {
        $raw = (string)@file_get_contents($cacheFile);
        $age = time() - (int)filemtime($cacheFile);
        if ($raw === 'NONE') {
            if ($age < $retryAge) $known = true;
        } else {
            $dec = lvDecryptWith($key, $raw);
            if ($dec !== null && $age < $maxAge) { $bin = $dec; $known = true; }
            elseif ($dec !== null) $old = $dec;
        }
    }
    if (!$known) {
        @set_time_limit(30);
        $bin = lvFindFavicon($domain);
        if ($bin === null && isset($old)) { $bin = $old; @touch($cacheFile, time() - $maxAge + $retryAge); }
        elseif ($bin === null) @file_put_contents($cacheFile, 'NONE', LOCK_EX);
        else @file_put_contents($cacheFile, lvEncryptWith($key, $bin), LOCK_EX);
    }
    if ($bin === null) {
        header('Cache-Control: private, max-age=' . $retryAge);
        http_response_code(404);
        exit;
    }
    header('Content-Type: ' . (lvIconType($bin) ?: 'image/png'));
    header('Cache-Control: private, max-age=' . $maxAge);
    echo $bin;
    exit;
}

if ($action) {
    lvSecurityHeaders(false);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');

    if ($action === 'logout') {
        if (!$isPost) {
            http_response_code(405);
            jsonOut(['success' => false, 'message' => 'Logout nur per POST.']);
        }
        lvRequireCsrf();
        lvLogout();
        jsonOut(['success' => true, 'message' => 'Abgemeldet.']);
    }

    if ($action === 'auth_status') {
        jsonOut(['success' => true, 'logged_in' => lvIsLoggedIn(), 'setup_done' => lvIsSetupDone()]);
    }

    // Alles hier geht nur per POST mit gültigem Sicherheits-Token und angemeldet
    if (!$isPost) {
        http_response_code(405);
        jsonOut(['success' => false, 'message' => 'Diese Aktion geht nur per POST.']);
    }
    lvRequireCsrf();
    if (LV_AUTH_ENABLED && !lvIsLoggedIn()) {
        http_response_code(401);
        jsonOut(['success' => false, 'message' => 'Nicht angemeldet.', 'auth_required' => true]);
    }
    lvDataKey();
    $sessionWriters = ['change_password', 'totp_begin', 'totp_enable', 'totp_disable', 'recovery_create', 'settings_save', 'backup_import', 'login_log', 'user_delete'];
    if (!in_array($action, $sessionWriters, true)) session_write_close();

    // Schreibende Aktionen nacheinander ausführen (zwei Geräte gleichzeitig überschreiben sich sonst)
    $mutating = ['add', 'update', 'delete', 'bulk_delete', 'bulk_move', 'bulk_favorite', 'dedupe', 'toggle_favorite',
                 'import', 'rename_category', 'delete_category', 'backup_restore', 'backup_import', 'visit', 'set_status',
                 'trash_restore', 'trash_purge', 'change_password', 'totp_enable', 'totp_disable', 'recovery_create', 'settings_save',
                 'user_approve', 'user_reject', 'user_block', 'user_unblock', 'user_delete', 'register_toggle'];
    $isMutating = in_array($action, $mutating, true);
    $lockFp = null;
    if ($isMutating) {
        $lockFp = @fopen(lvLockFile(), 'c');
        if ($lockFp) flock($lockFp, LOCK_EX);
    }

    $bookmarks = loadBookmarks();
    $isLive = fn($b) => empty($b['deleted']);
    $lower = fn($s) => function_exists('mb_strtolower') ? mb_strtolower((string)$s, 'UTF-8') : strtolower((string)$s);

    try {
        $dataActions = ['add', 'update', 'delete', 'bulk_delete', 'bulk_move', 'bulk_favorite', 'dedupe', 'toggle_favorite',
                        'import', 'rename_category', 'delete_category', 'visit', 'set_status', 'trash_restore', 'trash_purge'];
        if ($LV_CORRUPT && in_array($action, $dataActions, true)) {
            throw new Exception('bookmarks.json ist beschädigt und wird nicht überschrieben. Bitte unter Werkzeuge → Backups einen Stand wiederherstellen.');
        }

        switch ($action) {
            case 'list':
                $out = ['success' => true, 'bookmarks' => $bookmarks, 'corrupt' => $LV_CORRUPT];
                $cfg = lvLoadAuthConfig();
                // Der Administrator erfährt nebenbei, ob neue Zugangsanfragen warten
                if ($cfg !== null && $cfg['role'] === 'admin') $out['pending'] = lvPendingCount();
                jsonOut($out);

            /* ----- Konto & Sicherheit ----- */

            case 'account_info':
                $cfg = lvLoadAuthConfig(true);
                if ($cfg === null) throw new Exception('Kein Konto eingerichtet.');
                jsonOut(['success' => true, 'username' => $cfg['username'], 'role' => $cfg['role'], 'totp' => !empty($cfg['totp']),
                         'recovery' => !empty($cfg['rec_wrapped']), 'idle_minutes' => $cfg['idle_minutes'],
                         'log_details' => !empty($cfg['log_pub'])]);

            case 'settings_save':
                $cfg = lvLoadAuthConfig(true);
                if ($cfg === null) throw new Exception('Kein Konto eingerichtet.');
                $idle = (int)($_POST['idle_minutes'] ?? 0);
                if (!in_array($idle, [15, 60, 480, 1440, 10080, 43200], true)) throw new Exception('Ungültige Zeitangabe.');
                $cfg['idle_minutes'] = $idle;
                if (!lvSaveAuthConfigFull($cfg)) throw new Exception('Speichern fehlgeschlagen (Schreibrechte?).');
                // Cookies an die neue Laufzeit anpassen
                $exp = $idle > 480 ? time() + $idle * 60 : 0;
                setcookie(LV_KEY_COOKIE, (string)($_COOKIE[LV_KEY_COOKIE] ?? ''), lvCookieOpts($exp));
                setcookie(session_name(), session_id(), lvCookieOpts($exp));
                jsonOut(['success' => true, 'message' => 'Gespeichert.']);

            case 'change_password':
                $newUser = trim((string)($_POST['new_username'] ?? ''));
                $newPass = (string)($_POST['new_password'] ?? '');
                $newPass2 = (string)($_POST['new_password2'] ?? '');
                $cfg = lvLoadAuthConfig(true);
                if ($cfg === null) throw new Exception('Kein Konto eingerichtet.');
                $dek = lvRequirePassword($cfg, (string)($_POST['current_password'] ?? ''));
                if ($newUser === '') $newUser = $cfg['username'];
                if (strlen($newUser) < 2 || strlen($newUser) > 64) {
                    throw new Exception('Benutzername: 2–64 Zeichen.');
                }
                if ($newUser !== $cfg['username']) {
                    if (cleanText($newUser, 64) !== $newUser) throw new Exception('Der Benutzername enthält unzulässige Zeichen.');
                    $other = lvFindUser($newUser, false, true);
                    if ($other !== null && $other['_uid'] !== $cfg['_uid']) throw new Exception('Dieser Benutzername ist schon vergeben.');
                }
                if ($newPass === '') {
                    if ($newUser === $cfg['username']) throw new Exception('Keine Änderung.');
                    $cfg['username'] = $newUser;
                    if (!lvSaveAuthConfigFull($cfg)) throw new Exception('Speichern der Zugangsdaten fehlgeschlagen (Schreibrechte?).');
                    $_SESSION['lv_user'] = $newUser;
                    jsonOut(['success' => true, 'message' => 'Benutzername geändert.', 'username' => $newUser]);
                }
                lvCheckNewPassword($newPass);
                if ($newPass !== $newPass2) throw new Exception('Neue Passwörter stimmen nicht überein.');
                $hash = password_hash($newPass, PASSWORD_DEFAULT);
                if ($hash === false) throw new Exception('Passwort-Hash fehlgeschlagen.');
                $wrapped = lvWrapKey($dek, $newPass);
                $cfg['username'] = $newUser;
                $cfg['password_hash'] = $hash;
                $cfg['kdf_salt'] = $wrapped['kdf_salt'];
                $cfg['wrapped_key'] = $wrapped['wrapped_key'];
                $cfg['kdf_iters'] = $wrapped['kdf_iters'];
                $cfg['epoch'] = (int)$cfg['epoch'] + 1; // alle anderen Geräte werden abgemeldet
                if (!lvSaveAuthConfigFull($cfg)) throw new Exception('Speichern der Zugangsdaten fehlgeschlagen (Schreibrechte?).');
                lvEstablishSession($cfg, $dek);
                jsonOut(['success' => true, 'message' => 'Zugangsdaten gespeichert. Andere Geräte wurden abgemeldet.', 'username' => $newUser, 'csrf' => lvCsrfToken()]);

            case 'totp_begin':
                $cfg = lvLoadAuthConfig(true);
                if ($cfg === null) throw new Exception('Kein Konto eingerichtet.');
                $secret = lvBase32Encode(random_bytes(20));
                $_SESSION['lv_totp_pending'] = $secret;
                $label = rawurlencode('LinkVault:' . $cfg['username']);
                jsonOut(['success' => true, 'secret' => $secret,
                         'uri' => "otpauth://totp/{$label}?secret={$secret}&issuer=LinkVault&algorithm=SHA1&digits=6&period=30"]);

            case 'totp_enable':
                $cfg = lvLoadAuthConfig(true);
                if ($cfg === null) throw new Exception('Kein Konto eingerichtet.');
                $dek = lvRequirePassword($cfg, (string)($_POST['current_password'] ?? ''));
                $secret = (string)($_SESSION['lv_totp_pending'] ?? '');
                if ($secret === '') throw new Exception('Bitte die Einrichtung noch einmal starten.');
                $counter = lvTotpVerify($secret, (string)($_POST['code'] ?? ''), 0);
                if ($counter === 0) throw new Exception('Der Code stimmt nicht. Uhrzeit am Handy prüfen und neuen Code eingeben.');
                $cfg['totp'] = lvEncryptWith($dek, $secret);
                $cfg['totp_last'] = $counter;
                if (!lvSaveAuthConfigFull($cfg)) throw new Exception('Speichern fehlgeschlagen (Schreibrechte?).');
                unset($_SESSION['lv_totp_pending']);
                jsonOut(['success' => true, 'message' => 'Zwei-Faktor-Anmeldung ist jetzt aktiv.']);

            case 'totp_disable':
                $cfg = lvLoadAuthConfig(true);
                if ($cfg === null) throw new Exception('Kein Konto eingerichtet.');
                lvRequirePassword($cfg, (string)($_POST['current_password'] ?? ''));
                unset($cfg['totp'], $cfg['totp_last']);
                if (!lvSaveAuthConfigFull($cfg)) throw new Exception('Speichern fehlgeschlagen (Schreibrechte?).');
                jsonOut(['success' => true, 'message' => 'Zwei-Faktor-Anmeldung ist abgeschaltet.']);

            case 'recovery_create':
                $cfg = lvLoadAuthConfig(true);
                if ($cfg === null) throw new Exception('Kein Konto eingerichtet.');
                $dek = lvRequirePassword($cfg, (string)($_POST['current_password'] ?? ''));
                $abc = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // ohne 0/O und 1/I
                $code = '';
                for ($i = 0; $i < 24; $i++) $code .= $abc[random_int(0, 31)];
                $w = lvWrapKey($dek, $code);
                $cfg['rec_salt'] = $w['kdf_salt'];
                $cfg['rec_wrapped'] = $w['wrapped_key'];
                $cfg['rec_iters'] = $w['kdf_iters'];
                if (!lvSaveAuthConfigFull($cfg)) throw new Exception('Speichern fehlgeschlagen (Schreibrechte?).');
                jsonOut(['success' => true, 'code' => implode('-', str_split($code, 4)),
                         'message' => 'Neuer Wiederherstellungscode erzeugt. Ein älterer Code gilt nicht mehr.']);

            case 'login_log':
                $cfg = lvLoadAuthConfig();
                $dek = lvDataKey();
                if ($cfg === null || $dek === null) throw new Exception('Nicht angemeldet.');
                if (!empty($_POST['clear'])) {
                    @unlink(lvAttemptsFile($cfg['_uid']));
                    lvLogAttempt('ok', $cfg['username'], $cfg['_uid']);
                }
                jsonOut(['success' => true, 'entries' => lvReadAttempts($cfg, $dek, 300), 'details' => !empty($cfg['log_pub'])]);

            /* ----- Benutzer verwalten (nur Administrator) ----- */

            case 'users_list':
                $cfg = lvRequireAdmin();
                jsonOut(['success' => true] + lvUsersPayload($cfg));

            case 'user_approve':
            case 'user_block':
            case 'user_unblock':
                $cfg = lvRequireAdmin();
                $u = lvUserByUid($_POST['uid'] ?? '');
                $name = $u['username'];
                if ($action === 'user_approve') {
                    if ($u['status'] !== 'pending') throw new Exception('Diese Anfrage ist schon erledigt.');
                    $ok = lvSetUserStatus($u, 'active');
                    $msg = "„{$name}“ ist freigeschaltet und kann sich jetzt anmelden.";
                } elseif ($action === 'user_block') {
                    if ($u['status'] !== 'active') throw new Exception('Dieser Benutzer ist nicht aktiv.');
                    $ok = lvSetUserStatus($u, 'blocked');
                    $msg = "„{$name}“ ist gesperrt und überall abgemeldet. Die Links bleiben erhalten.";
                } else {
                    if ($u['status'] !== 'blocked') throw new Exception('Dieser Benutzer ist nicht gesperrt.');
                    $ok = lvSetUserStatus($u, 'active');
                    $msg = "„{$name}“ darf sich wieder anmelden.";
                }
                if (!$ok) throw new Exception('Speichern fehlgeschlagen (Schreibrechte?).');
                jsonOut(['success' => true, 'message' => $msg] + lvUsersPayload($cfg));

            case 'user_reject':
                $cfg = lvRequireAdmin();
                $u = lvUserByUid($_POST['uid'] ?? '');
                if ($u['status'] !== 'pending') throw new Exception('Diese Anfrage ist schon erledigt.');
                if (!lvDeleteUser($u['_uid'])) throw new Exception('Löschen fehlgeschlagen (Schreibrechte?).');
                jsonOut(['success' => true, 'message' => "Anfrage von „{$u['username']}“ abgelehnt."] + lvUsersPayload($cfg));

            case 'user_delete':
                // Löscht das Konto samt aller Links und Backups, das lässt sich nicht zurückholen
                $cfg = lvRequireAdmin();
                lvRequirePassword($cfg, (string)($_POST['current_password'] ?? ''));
                $u = lvUserByUid($_POST['uid'] ?? '');
                if (!lvDeleteUser($u['_uid'])) throw new Exception('Löschen fehlgeschlagen (Schreibrechte?).');
                jsonOut(['success' => true, 'message' => "„{$u['username']}“ wurde samt allen Links gelöscht."] + lvUsersPayload($cfg));

            case 'register_toggle':
                $cfg = lvRequireAdmin();
                $cfg['allow_register'] = ($_POST['open'] ?? '') === '1';
                if (!lvSaveAuthConfigFull($cfg)) throw new Exception('Speichern fehlgeschlagen (Schreibrechte?).');
                jsonOut(['success' => true, 'allow_register' => $cfg['allow_register'],
                         'message' => $cfg['allow_register'] ? 'Neue Zugangsanfragen sind wieder möglich.' : 'Es werden keine neuen Zugangsanfragen mehr angenommen.']);

            /* ----- Links ----- */

            case 'add':
                $title = cleanText($_POST['title'] ?? '', 300);
                $url   = trim((string)($_POST['url'] ?? ''));
                if ($title === '' || $url === '') throw new Exception('Titel und URL sind erforderlich.');
                $url = cleanUrl($url);
                $item = [
                    'id' => generateId(), 'title' => $title, 'url' => $url,
                    'category' => cleanCategory($_POST['category'] ?? ''),
                    'description' => cleanText($_POST['description'] ?? '', 2000),
                    'favorite' => ($_POST['favorite'] ?? '') === '1', 'created' => time(),
                ];
                $tags = cleanTags($_POST['tags'] ?? []);
                if ($tags) $item['tags'] = $tags;
                $bookmarks[] = $item;
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => 'Link hinzugefügt.', 'bookmarks' => $bookmarks]);

            case 'update':
                $id = (string)($_POST['id'] ?? '');
                $found = false;
                foreach ($bookmarks as &$bm) {
                    if (($bm['id'] ?? null) === $id) {
                        $title = cleanText($_POST['title'] ?? ($bm['title'] ?? ''), 300);
                        if ($title === '') throw new Exception('Titel darf nicht leer sein.');
                        $url = trim((string)($_POST['url'] ?? ($bm['url'] ?? '')));
                        // Unveränderte URL nicht erneut prüfen (alte Importe bleiben bearbeitbar)
                        if ($url !== ($bm['url'] ?? '')) { $url = cleanUrl($url); unset($bm['check']); }
                        $bm['title']       = $title;
                        $bm['url']         = $url;
                        $bm['category']    = cleanCategory($_POST['category'] ?? ($bm['category'] ?? ''));
                        $bm['description'] = cleanText($_POST['description'] ?? ($bm['description'] ?? ''), 2000);
                        $bm['favorite']    = ($_POST['favorite'] ?? '') === '1';
                        if (isset($_POST['tags'])) {
                            $tags = cleanTags($_POST['tags']);
                            if ($tags) $bm['tags'] = $tags; else unset($bm['tags']);
                        }
                        $found = true;
                        break;
                    }
                }
                unset($bm);
                if (!$found) throw new Exception('Link nicht gefunden.');
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => 'Link aktualisiert.', 'bookmarks' => $bookmarks]);

            case 'delete':
            case 'bulk_delete':
                // Löschen heißt: ab in den Papierkorb
                $ids = $action === 'delete' ? [(string)($_POST['id'] ?? '')] : parseIds($_POST['ids'] ?? []);
                $ids = array_flip(array_filter($ids, fn($i) => $i !== ''));
                if (!$ids) throw new Exception('Keine Links ausgewählt.');
                $n = 0;
                foreach ($bookmarks as &$bm) {
                    if (isset($ids[$bm['id'] ?? '']) && empty($bm['deleted'])) { $bm['deleted'] = time(); $n++; }
                }
                unset($bm);
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => $n === 1 ? 'Link in den Papierkorb gelegt.' : "$n Links in den Papierkorb gelegt.", 'bookmarks' => $bookmarks]);

            case 'trash_restore':
                $ids = array_flip(parseIds($_POST['ids'] ?? []));
                $n = 0;
                foreach ($bookmarks as &$bm) {
                    if (!empty($bm['deleted']) && (!$ids || isset($ids[$bm['id'] ?? '']))) { unset($bm['deleted']); $n++; }
                }
                unset($bm);
                if ($n === 0) throw new Exception('Nichts zum Wiederherstellen.');
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => "$n Link(s) wiederhergestellt.", 'bookmarks' => $bookmarks]);

            case 'trash_purge':
                $ids = array_flip(parseIds($_POST['ids'] ?? []));
                $before = count($bookmarks);
                $bookmarks = array_values(array_filter($bookmarks, fn($b) => empty($b['deleted']) || ($ids && !isset($ids[$b['id'] ?? '']))));
                $n = $before - count($bookmarks);
                if ($n > 0) { backupBefore('purge'); requireSave($bookmarks); }
                jsonOut(['success' => true, 'message' => "$n Link(s) endgültig gelöscht.", 'bookmarks' => $bookmarks]);

            case 'bulk_move':
                $ids = array_flip(parseIds($_POST['ids'] ?? []));
                if (!$ids) throw new Exception('Keine Links ausgewählt.');
                if (trim((string)($_POST['category'] ?? '')) === '') throw new Exception('Ordner fehlt.');
                $cat = cleanCategory($_POST['category']);
                $moved = 0;
                foreach ($bookmarks as &$bm) {
                    if (isset($ids[$bm['id'] ?? '']) && $isLive($bm)) { $bm['category'] = $cat; $moved++; }
                }
                unset($bm);
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => "$moved Link(s) nach „{$cat}“ verschoben.", 'bookmarks' => $bookmarks]);

            case 'bulk_favorite':
                $ids = array_flip(parseIds($_POST['ids'] ?? []));
                $fav = ($_POST['favorite'] ?? '') === '1';
                if (!$ids) throw new Exception('Keine Links ausgewählt.');
                foreach ($bookmarks as &$bm) {
                    if (isset($ids[$bm['id'] ?? ''])) $bm['favorite'] = $fav;
                }
                unset($bm);
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => $fav ? 'Als Favorit markiert.' : 'Aus Favoriten entfernt.', 'bookmarks' => $bookmarks]);

            case 'rename_category':
                $old = trim((string)($_POST['old'] ?? ''));
                if ($old === '' || trim((string)($_POST['new'] ?? '')) === '') throw new Exception('Ordnername fehlt.');
                $new = cleanCategory($_POST['new']);
                $n = 0;
                foreach ($bookmarks as &$bm) {
                    $c = (string)($bm['category'] ?? '');
                    if ($c === $old) { $bm['category'] = $new; $n++; }
                    elseif (strncmp($c, $old . ' > ', strlen($old) + 3) === 0) {
                        // Unterordner ziehen mit um
                        $bm['category'] = cleanCategory($new . ' > ' . substr($c, strlen($old) + 3));
                        $n++;
                    }
                }
                unset($bm);
                if ($n === 0) throw new Exception('Ordner nicht gefunden.');
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => "Ordner umbenannt ($n Links).", 'bookmarks' => $bookmarks, 'new' => $new]);

            case 'delete_category':
                // Ordner auflösen: Links wandern eine Ebene höher (oder nach „Allgemein“), gelöscht wird nichts
                $old = trim((string)($_POST['category'] ?? ''));
                if ($old === '') throw new Exception('Ordnername fehlt.');
                if ($old === 'Allgemein') throw new Exception('„Allgemein“ ist der Standard-Ordner.');
                $pos = strrpos($old, ' > ');
                $parent = $pos !== false ? substr($old, 0, $pos) : '';
                $n = 0;
                foreach ($bookmarks as &$bm) {
                    $c = (string)($bm['category'] ?? '');
                    if ($c === $old) { $bm['category'] = $parent !== '' ? $parent : 'Allgemein'; $n++; }
                    elseif (strncmp($c, $old . ' > ', strlen($old) + 3) === 0) {
                        $rest = substr($c, strlen($old) + 3);
                        $bm['category'] = cleanCategory($parent !== '' ? $parent . ' > ' . $rest : $rest);
                        $n++;
                    }
                }
                unset($bm);
                if ($n === 0) throw new Exception('Ordner nicht gefunden.');
                backupBefore('delete_category');
                requireSave($bookmarks);
                $target = $parent !== '' ? $parent : 'Allgemein';
                jsonOut(['success' => true, 'message' => "Ordner aufgelöst, $n Link(s) liegen jetzt in „{$target}“.", 'bookmarks' => $bookmarks]);

            case 'dedupe':
                // Pro Adresse bleibt der beste Eintrag, die anderen wandern in den Papierkorb
                $keepIds = parseIds($_POST['keep_ids'] ?? []);
                $norm = function ($url) {
                    $url = trim((string)$url);
                    $p = parse_url($url);
                    if (!$p || empty($p['host'])) return strtolower($url);
                    $host = strtolower($p['host']);
                    if (strncmp($host, 'www.', 4) === 0) $host = substr($host, 4);
                    $path = rtrim($p['path'] ?? '/', '/') ?: '/';
                    return $host . $path . (isset($p['query']) ? '?' . $p['query'] : '');
                };
                $groups = [];
                foreach ($bookmarks as $i => $bm) {
                    if ($isLive($bm)) $groups[$norm($bm['url'] ?? '')][] = $i;
                }
                $removed = 0;
                foreach ($groups as $idxs) {
                    if (count($idxs) < 2) continue;
                    usort($idxs, function ($x, $y) use ($bookmarks, $keepIds) {
                        $a = $bookmarks[$x]; $b = $bookmarks[$y];
                        $ak = in_array($a['id'] ?? '', $keepIds, true) ? 1 : 0;
                        $bk = in_array($b['id'] ?? '', $keepIds, true) ? 1 : 0;
                        if ($ak !== $bk) return $bk <=> $ak;
                        $af = !empty($a['favorite']) ? 1 : 0; $bf = !empty($b['favorite']) ? 1 : 0;
                        if ($af !== $bf) return $bf <=> $af;
                        $ad = trim($a['description'] ?? '') !== '' ? 1 : 0; $bd = trim($b['description'] ?? '') !== '' ? 1 : 0;
                        if ($ad !== $bd) return $bd <=> $ad;
                        return ($a['created'] ?? 0) <=> ($b['created'] ?? 0);
                    });
                    foreach (array_slice($idxs, 1) as $i) { $bookmarks[$i]['deleted'] = time(); $removed++; }
                }
                if ($removed > 0) {
                    backupBefore('dedupe');
                    requireSave($bookmarks);
                }
                jsonOut([
                    'success' => true,
                    'message' => $removed > 0 ? "$removed Duplikat(e) in den Papierkorb gelegt." : 'Keine Duplikate gefunden.',
                    'removed' => $removed,
                    'bookmarks' => $bookmarks
                ]);

            case 'toggle_favorite':
                $id = (string)($_POST['id'] ?? '');
                foreach ($bookmarks as &$bm) {
                    if (($bm['id'] ?? null) === $id) {
                        $bm['favorite'] = !($bm['favorite'] ?? false);
                        break;
                    }
                }
                unset($bm);
                requireSave($bookmarks);
                jsonOut(['success' => true, 'bookmarks' => $bookmarks]);

            case 'visit':
                // Zählt, wie oft ein Link geöffnet wurde (für „Oft benutzt“ / „Zuletzt geöffnet“)
                $id = (string)($_POST['id'] ?? '');
                $hit = false;
                foreach ($bookmarks as &$bm) {
                    if (($bm['id'] ?? null) === $id) {
                        $bm['clicks'] = (int)($bm['clicks'] ?? 0) + 1;
                        $bm['opened'] = time();
                        $hit = true;
                        break;
                    }
                }
                unset($bm);
                if ($hit) requireSave($bookmarks);
                jsonOut(['success' => true]);

            case 'set_status':
                // Ergebnis des Link-Checks an den Links merken
                $results = json_decode((string)($_POST['results'] ?? ''), true);
                if (!is_array($results)) throw new Exception('Keine Ergebnisse.');
                foreach ($bookmarks as &$bm) {
                    $r = $results[$bm['id'] ?? ''] ?? null;
                    if (!is_array($r)) continue;
                    $s = (string)($r['s'] ?? '');
                    if ($s === 'dead' || $s === 'unclear') $bm['check'] = ['s' => $s, 'c' => (int)($r['c'] ?? 0), 't' => time()];
                    else unset($bm['check']);
                }
                unset($bm);
                requireSave($bookmarks);
                jsonOut(['success' => true, 'bookmarks' => $bookmarks]);

            case 'check_urls':
                // Die Seite schickt die Links in kleinen Häppchen, so gibt es keine Zeitüberschreitung
                @set_time_limit(90);
                $ids = array_flip(parseIds($_POST['ids'] ?? []));
                $toCheck = array_values(array_filter($bookmarks, fn($b) => $isLive($b) && isset($ids[$b['id'] ?? ''])));
                $toCheck = array_slice($toCheck, 0, 20);
                $urls = [];
                foreach ($toCheck as $i => $bm) $urls[$i] = (string)($bm['url'] ?? '');
                $checked = lvCheckUrls($urls);
                $results = [];
                foreach ($toCheck as $i => $bm) {
                    $r = $checked[$i] ?? ['status' => 'unclear', 'code' => 0, 'note' => 'nicht geprüft'];
                    $results[] = [
                        'id' => $bm['id'], 'url' => $bm['url'] ?? '', 'title' => $bm['title'] ?? '',
                        'status' => $r['status'], 'code' => $r['code'], 'note' => $r['note'],
                    ];
                }
                jsonOut(['success' => true, 'results' => $results]);

            case 'fetch_title':
                $url = cleanUrl($_POST['url'] ?? '');
                $page = lvSafeFetch($url);
                if ($page['blocked']) throw new Exception('Diese Adresse kann der Server nicht abrufen.');
                if ($page['body'] === '') throw new Exception('Seite antwortet nicht.');
                $meta = lvExtractMeta($page['body'], $page['ctype']);
                if ($meta['title'] === '') throw new Exception('Kein Titel gefunden.');
                jsonOut(['success' => true, 'title' => $meta['title'], 'description' => $meta['description']]);

            /* ----- Backups ----- */

            case 'backups_list':
                jsonOut(['success' => true, 'backups' => listBackups()]);

            case 'backup_restore':
                $name = basename((string)($_POST['name'] ?? ''));
                if (!preg_match('/^(tag|vor)_[A-Za-z0-9_\-]+\.json$/', $name) || !is_file(lvBackupDir() . '/' . $name)) {
                    throw new Exception('Backup nicht gefunden.');
                }
                $jsonBackup = lvDecodeStored((string)file_get_contents(lvBackupDir() . '/' . $name));
                if ($jsonBackup === null) throw new Exception('Backup ist nicht lesbar (Entschlüsselung fehlgeschlagen).');
                $data = json_decode($jsonBackup, true);
                if (!is_array($data)) throw new Exception('Backup ist nicht lesbar.');
                backupBefore('restore');
                $LV_CORRUPT = false;
                $bookmarks = array_values(array_filter($data, 'is_array'));
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => 'Stand wiederhergestellt (' . count(array_filter($bookmarks, $isLive)) . ' Links).', 'bookmarks' => $bookmarks]);

            case 'export_full':
                // Komplett-Backup: verschlüsselte Daten + der passwortgeschützte Schlüssel in EINER Datei.
                // Ohne das Passwort von heute ist die Datei wertlos.
                $cfg = lvLoadAuthConfig();
                if ($cfg === null || !is_file(lvDataFile())) throw new Exception('Nichts zu sichern.');
                $raw = trim((string)file_get_contents(lvDataFile()));
                if (strncmp($raw, 'LVENC1', 6) !== 0) $raw = lvEncryptPayload($raw === '' ? '[]' : $raw);
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="linkvault_backup_' . date('Y-m-d') . '.lvbak"');
                echo json_encode([
                    'format' => 'LVBACKUP1', 'version' => LV_VERSION, 'created' => time(),
                    'kdf_salt' => $cfg['kdf_salt'], 'wrapped_key' => $cfg['wrapped_key'], 'kdf_iters' => $cfg['kdf_iters'],
                    'data' => $raw,
                ], JSON_PRETTY_PRINT);
                exit;

            case 'backup_import':
                $pack = json_decode(lvUploadedFile('backup_file'), true);
                if (!is_array($pack) || ($pack['format'] ?? '') !== 'LVBACKUP1' || empty($pack['data'])) {
                    throw new Exception('Das ist keine LinkVault-Backup-Datei (.lvbak).');
                }
                $oldKey = lvUnwrapKey((string)($_POST['backup_password'] ?? ''), [
                    'kdf_salt' => (string)($pack['kdf_salt'] ?? ''), 'wrapped_key' => (string)($pack['wrapped_key'] ?? ''),
                    'kdf_iters' => (int)($pack['kdf_iters'] ?? 120000),
                ]);
                if ($oldKey === null) throw new Exception('Passwort passt nicht zu diesem Backup. Gemeint ist das Passwort von damals.');
                $json = lvDecryptWith($oldKey, (string)$pack['data']);
                $data = $json !== null ? json_decode($json, true) : null;
                if (!is_array($data)) throw new Exception('Backup ist beschädigt.');
                $items = [];
                $seen = [];
                foreach ($data as $raw) {
                    $item = sanitizeItem($raw, true);
                    if (!$item || isset($seen[$item['id']])) continue;
                    $seen[$item['id']] = true;
                    $items[] = $item;
                }
                backupBefore('restore');
                if (($_POST['mode'] ?? 'merge') === 'replace') {
                    $LV_CORRUPT = false;
                    $bookmarks = $items;
                    $msg = 'Backup eingespielt (' . count($items) . ' Einträge), der alte Stand liegt bei den Backups.';
                } else {
                    if ($LV_CORRUPT) throw new Exception('Die aktuellen Daten sind beschädigt. Bitte „Alles ersetzen“ wählen.');
                    $haveUrl = [];
                    $haveId = [];
                    foreach ($bookmarks as $b) { $haveUrl[(string)($b['url'] ?? '')] = true; $haveId[(string)($b['id'] ?? '')] = true; }
                    $n = 0;
                    foreach ($items as $item) {
                        if (!empty($item['deleted']) || isset($haveUrl[$item['url']])) continue;
                        if (isset($haveId[$item['id']])) $item['id'] = generateId();
                        $bookmarks[] = $item;
                        $haveUrl[$item['url']] = true;
                        $n++;
                    }
                    $msg = "$n neue Link(s) aus dem Backup übernommen.";
                }
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => $msg, 'bookmarks' => $bookmarks]);

            /* ----- Import / Export ----- */

            case 'import':
                [$new, $skipped] = lvParseImport(lvUploadedFile('bookmark_file'), $bookmarks);
                $imported = count($new);
                if (!empty($_POST['dry'])) {
                    $folders = [];
                    foreach ($new as $n) $folders[$n['category']] = ($folders[$n['category']] ?? 0) + 1;
                    arsort($folders);
                    jsonOut(['success' => true, 'dry' => true, 'imported' => $imported, 'skipped' => $skipped,
                             'folders' => array_slice($folders, 0, 40, true), 'folder_count' => count($folders)]);
                }
                if ($imported > 0) {
                    backupBefore('import');
                    $bookmarks = array_merge($bookmarks, $new);
                    requireSave($bookmarks);
                }
                $msg = "$imported Links importiert." . ($skipped > 0 ? " $skipped waren schon da." : '');
                jsonOut(['success' => true, 'message' => $msg, 'bookmarks' => $bookmarks]);

            case 'export_json':
                $clean = [];
                foreach ($bookmarks as $bm) {
                    if (!$isLive($bm)) continue;
                    unset($bm['check'], $bm['deleted']);
                    $clean[] = $bm;
                }
                header('Content-Type: application/json; charset=utf-8');
                header('Content-Disposition: attachment; filename="bookmarks_' . date('Y-m-d') . '.json"');
                echo json_encode($clean, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
                exit;

            case 'export_html':
                header('Content-Type: text/html; charset=utf-8');
                header('Content-Disposition: attachment; filename="bookmarks_' . date('Y-m-d') . '.html"');
                echo '<!DOCTYPE NETSCAPE-Bookmark-file-1>' . "\n";
                echo '<!-- This is an automatically generated file. -->' . "\n";
                echo '<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">' . "\n";
                echo '<TITLE>Bookmarks</TITLE>' . "\n<H1>Bookmarks</H1>\n<DL><p>\n";
                $byCat = [];
                foreach ($bookmarks as $bm) {
                    if (!$isLive($bm)) continue;
                    $byCat[($bm['category'] ?? '') ?: 'Allgemein'][] = $bm;
                }
                ksort($byCat, SORT_NATURAL | SORT_FLAG_CASE);
                foreach ($byCat as $cat => $items) {
                    echo '    <DT><H3>' . htmlspecialchars((string)$cat, ENT_QUOTES, 'UTF-8') . '</H3>' . "\n    <DL><p>\n";
                    foreach ($items as $bm) {
                        $add = (int)($bm['created'] ?? time());
                        $tags = !empty($bm['tags']) && is_array($bm['tags']) ? ' TAGS="' . htmlspecialchars(implode(',', $bm['tags']), ENT_QUOTES, 'UTF-8') . '"' : '';
                        echo '        <DT><A HREF="' . htmlspecialchars($bm['url'] ?? '', ENT_QUOTES, 'UTF-8') . '" ADD_DATE="' . $add . '"' . $tags . '>'
                            . htmlspecialchars($bm['title'] ?? '', ENT_QUOTES, 'UTF-8') . '</A>' . "\n";
                    }
                    echo "    </DL><p>\n";
                }
                echo '</DL><p>';
                exit;

            default:
                throw new Exception('Unbekannte Aktion.');
        }
    } catch (Throwable $e) {
        $msg = get_class($e) === 'Exception' ? $e->getMessage() : 'Interner Fehler.';
        if (get_class($e) !== 'Exception') error_log('LinkVault: ' . $e->getMessage() . ' @' . $e->getLine());
        jsonOut(['success' => false, 'message' => $msg]);
    }
}

lvSecurityHeaders(true);
header('Cache-Control: no-store, no-cache, must-revalidate, private');
header('Pragma: no-cache');

// Vom Schnell-Speichern-Knopf oder „Teilen“ mitgebrachte Adresse über die Anmeldung retten
function lvBackUrl(): string {
    $back = strtok((string)($_SERVER['REQUEST_URI'] ?? '/'), '?') ?: '/';
    $keep = [];
    foreach (['add', 'title', 'url', 'text', 'new'] as $k) {
        if (isset($_GET[$k]) && is_string($_GET[$k]) && $_GET[$k] !== '') $keep[$k] = substr($_GET[$k], 0, 2000);
    }
    return $keep ? $back . '?' . http_build_query($keep) : $back;
}

// Setup-, Login- oder Wiederherstellungs-Seite, wenn nicht angemeldet
if (LV_AUTH_ENABLED && !lvIsLoggedIn()) {
    $formError = '';
    $formOk = '';
    $cfgNow = lvLoadAuthConfig(false, '');
    $needsSetup = $cfgNow === null;
    $others = $needsSetup ? [] : lvListUsers();
    $multi = count($others) > 0;
    $hasTotp = !$needsSetup && !empty($cfgNow['totp']);
    $hasRecovery = !$needsSetup && !empty($cfgNow['rec_wrapped']);
    foreach ($others as $o) {
        if ($o['status'] !== 'active') continue;
        if (!empty($o['totp'])) $hasTotp = true;
        if (!empty($o['rec_wrapped'])) $hasRecovery = true;
    }
    $regOpen = !$needsSetup && lvRegisterOpen($cfgNow);
    $recoverMode = $hasRecovery && (isset($_GET['recover']) || isset($_POST['lv_recover']));
    $registerMode = !$recoverMode && $regOpen && !isset($_POST['lv_login']) && (isset($_GET['register']) || isset($_POST['lv_register']));
    lvStartSession();
    if (random_int(1, 15) === 1) lvSessionCleanup();
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
        if (!lvCsrfCheck()) {
            $formError = 'Sicherheits-Token ungültig. Bitte Seite neu laden und erneut versuchen.';
        } elseif ($needsSetup && isset($_POST['lv_setup'])) {
            try {
                if ((string)($_POST['password'] ?? '') !== (string)($_POST['password2'] ?? '')) throw new Exception('Passwörter stimmen nicht überein.');
                lvRunSetup(trim((string)($_POST['username'] ?? '')), (string)($_POST['password'] ?? ''));
                header('Location: ' . lvBackUrl());
                exit;
            } catch (Throwable $e) {
                $formError = get_class($e) === 'Exception' ? $e->getMessage() : 'Einrichtung fehlgeschlagen.';
            }
        } elseif (!$needsSetup && isset($_POST['lv_register'])) {
            try {
                if (!$regOpen) throw new Exception('Neue Anfragen sind im Moment geschlossen.');
                $throttleMsg = lvLoginThrottleCheck();
                if ($throttleMsg !== null) throw new Exception($throttleMsg);
                if (!lvRegThrottleOk()) throw new Exception('Von deinem Anschluss kamen heute schon mehrere Anfragen. Bitte morgen noch einmal versuchen.');
                if ((string)($_POST['password'] ?? '') !== (string)($_POST['password2'] ?? '')) throw new Exception('Passwörter stimmen nicht überein.');
                lvRegister(trim((string)($_POST['username'] ?? '')), (string)($_POST['password'] ?? ''), (string)($_POST['note'] ?? ''));
                lvRegThrottleHit();
                $formOk = 'Deine Anfrage ist raus. Sobald der Administrator dich freigeschaltet hat, kannst du dich hier mit deinem Namen und Passwort anmelden.';
                $registerMode = false;
            } catch (Throwable $e) {
                $formError = get_class($e) === 'Exception' ? $e->getMessage() : 'Die Anfrage hat nicht geklappt.';
            }
        } elseif (!$needsSetup && (isset($_POST['lv_login']) || isset($_POST['lv_recover']))) {
            $u = trim((string)($_POST['username'] ?? ''));
            $throttleMsg = lvLoginThrottleCheck();
            if ($throttleMsg !== null) {
                lvLogAttempt('locked', $u);
                $formError = $throttleMsg;
            } elseif (isset($_POST['lv_recover'])) {
                try {
                    $p = (string)($_POST['password'] ?? '');
                    if ($p !== (string)($_POST['password2'] ?? '')) throw new Exception('Passwörter stimmen nicht überein.');
                    lvCheckNewPassword($p);
                    if (lvRecover((string)($_POST['recovery_code'] ?? ''), $p, $multi ? $u : '')) {
                        lvLoginThrottleClear();
                        header('Location: ' . lvBackUrl());
                        exit;
                    }
                    lvLoginThrottleFail();
                    lvLogAttempt('recover', '');
                    $formError = $multi ? 'Benutzername oder Wiederherstellungscode stimmt nicht.' : 'Der Wiederherstellungscode stimmt nicht.';
                } catch (Throwable $e) {
                    $formError = get_class($e) === 'Exception' ? $e->getMessage() : 'Wiederherstellung fehlgeschlagen.';
                }
            } else {
                $result = lvLogin($u, (string)($_POST['password'] ?? ''), (string)($_POST['totp'] ?? ''));
                if ($result === 'ok') {
                    lvLoginThrottleClear();
                    header('Location: ' . lvBackUrl());
                    exit;
                }
                if ($result === 'pending') {
                    // Passwort war richtig, also kein Fehlversuch
                    $formError = 'Dein Konto wartet noch auf die Freigabe durch den Administrator.';
                } elseif ($result === 'blocked') {
                    $formError = 'Dein Zugang ist gesperrt. Bitte wende dich an den Administrator.';
                } else {
                    lvLoginThrottleFail();
                    lvLogAttempt($result === 'totp' ? 'totp' : 'fail', $u);
                    $formError = $result === 'totp' ? 'Der 2FA-Code fehlt oder stimmt nicht.' : 'Benutzername oder Passwort falsch.';
                }
            }
        }
    }
    $lvCsrf = lvCsrfToken();
    $e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
    $title = $needsSetup ? 'LinkVault – Einrichtung'
        : ($recoverMode ? 'LinkVault – Passwort vergessen' : ($registerMode ? 'LinkVault – Zugang anfragen' : 'LinkVault – Anmeldung'));
    $sub = $needsSetup
        ? 'Erster Start: Benutzer anlegen. Dein Passwort schützt Login und Verschlüsselung.'
        : ($recoverMode ? 'Mit dem Wiederherstellungscode ein neues Passwort setzen.'
        : ($registerMode ? 'Such dir Namen und Passwort aus. Danach muss dich der Administrator erst freischalten.' : 'Bitte anmelden'));
    $selfUrl = strtok((string)($_SERVER['REQUEST_URI'] ?? '/'), '?') ?: '/';
    ?><!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <meta name="theme-color" content="#0b1120">
    <meta name="robots" content="noindex, nofollow">
    <title><?php echo $e($title); ?></title>
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="LinkVault">
    <link rel="icon" href="?action=icon" type="image/svg+xml">
    <link rel="apple-touch-icon" href="?action=icon&amp;s=192">
    <link rel="manifest" href="?action=manifest" crossorigin="use-credentials">
    <style>
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 100 900; font-display: swap; src: url('?action=font') format('woff2'); }
        * { box-sizing: border-box; }
        body {
            margin: 0; min-height: 100vh; min-height: 100dvh;
            font-family: Inter, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; color: #f1f5f9;
            background: linear-gradient(165deg, #0b1120 0%, #0f172a 45%, #1e1b4b 100%);
            display: flex; align-items: center; justify-content: center;
            padding: max(1rem, env(safe-area-inset-top)) max(1rem, env(safe-area-inset-right)) max(1rem, env(safe-area-inset-bottom)) max(1rem, env(safe-area-inset-left));
        }
        html { background: #0b1120; }
        .card {
            width: 100%; max-width: 22rem;
            background: rgba(15, 23, 42, 0.92);
            border: 1px solid rgba(51, 65, 85, 0.55);
            border-radius: 1rem; padding: 1.5rem;
            box-shadow: 0 20px 40px -12px rgba(0,0,0,0.5);
        }
        .logo {
            width: 2.5rem; height: 2.5rem; border-radius: 0.65rem;
            background: linear-gradient(135deg, #8b5cf6, #7c3aed);
            display: flex; align-items: center; justify-content: center;
            margin: 0 auto 1rem;
            box-shadow: 0 0 14px -3px rgba(139, 92, 246, 0.5);
        }
        h1 { text-align: center; font-size: 1.15rem; margin: 0 0 0.25rem; }
        p.sub { text-align: center; color: #94a3b8; font-size: 0.85rem; margin: 0 0 1.25rem; line-height: 1.45; }
        label { display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.35rem; }
        input {
            width: 100%; padding: 0.7rem 0.85rem; border-radius: 0.7rem;
            background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(71, 85, 105, 0.55);
            color: #f1f5f9; font-size: 1rem; margin-bottom: 0.85rem; font-family: inherit;
        }
        input:focus { outline: none; border-color: rgba(139, 92, 246, 0.55); box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.2); }
        button {
            width: 100%; padding: 0.75rem; border: none; border-radius: 0.7rem;
            background: linear-gradient(135deg, #8b5cf6, #7c3aed); color: #fff;
            font-weight: 600; font-size: 0.9rem; cursor: pointer; font-family: inherit;
            box-shadow: 0 4px 14px -3px rgba(139, 92, 246, 0.45);
        }
        button:hover { background: linear-gradient(135deg, #a78bfa, #8b5cf6); }
        .err {
            background: rgba(127, 29, 29, 0.35); border: 1px solid rgba(185, 28, 28, 0.4);
            color: #fca5a5; font-size: 0.85rem; padding: 0.6rem 0.75rem;
            border-radius: 0.6rem; margin-bottom: 0.85rem; text-align: center;
        }
        .ok {
            background: rgba(6, 78, 59, 0.35); border: 1px solid rgba(16, 185, 129, 0.4);
            color: #6ee7b7; font-size: 0.85rem; padding: 0.6rem 0.75rem; line-height: 1.45;
            border-radius: 0.6rem; margin-bottom: 0.85rem; text-align: center;
        }
        .hint { text-align: center; color: #64748b; font-size: 0.72rem; margin-top: 1rem; line-height: 1.45; }
        .hint a { color: #a78bfa; }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">
            <svg width="18" height="18" fill="none" stroke="#fff" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 5a2 2 0 012-2h10a2 2 0 012 2v16l-7-3.5L5 21V5z"/></svg>
        </div>
        <h1>LinkVault</h1>
        <p class="sub"><?php echo $e($sub); ?></p>
        <?php if ($formError !== ''): ?><div class="err" role="alert"><?php echo $e($formError); ?></div><?php endif; ?>
        <?php if ($formOk !== ''): ?><div class="ok" role="status"><?php echo $e($formOk); ?></div><?php endif; ?>
        <?php if ($needsSetup): ?>
        <form method="post" action="">
            <input type="hidden" name="lv_setup" value="1">
            <input type="hidden" name="csrf" value="<?php echo $e($lvCsrf); ?>">
            <label for="username">Benutzername</label>
            <input type="text" id="username" name="username" required autofocus autocomplete="username" minlength="2" maxlength="64" value="<?php echo $e($_POST['username'] ?? ''); ?>">
            <label for="password">Passwort (min. 12 Zeichen, Buchstaben + Zahlen)</label>
            <input type="password" id="password" name="password" required autocomplete="new-password" minlength="12">
            <label for="password2">Passwort wiederholen</label>
            <input type="password" id="password2" name="password2" required autocomplete="new-password" minlength="12">
            <button type="submit">Konto anlegen</button>
        </form>
        <p class="hint">Es wird ein eigener Verschlüsselungsschlüssel erzeugt und mit deinem Passwort geschützt. Ohne Passwort sind die Daten nicht lesbar. Leg dir danach unter Werkzeuge → Konto &amp; Sicherheit einen Wiederherstellungscode an. Dieses erste Konto ist der Administrator: Wer später dazukommen will, braucht deine Freigabe.</p>
        <?php elseif ($recoverMode): ?>
        <form method="post" action="">
            <input type="hidden" name="lv_recover" value="1">
            <input type="hidden" name="csrf" value="<?php echo $e($lvCsrf); ?>">
            <?php if ($multi): ?>
            <label for="username">Benutzername</label>
            <input type="text" id="username" name="username" required autocomplete="username" autocapitalize="none" value="<?php echo $e($_POST['username'] ?? ''); ?>">
            <?php endif; ?>
            <label for="recovery_code">Wiederherstellungscode</label>
            <input type="text" id="recovery_code" name="recovery_code" required autofocus autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX">
            <label for="password">Neues Passwort (min. 12 Zeichen, Buchstaben + Zahlen)</label>
            <input type="password" id="password" name="password" required autocomplete="new-password" minlength="12">
            <label for="password2">Neues Passwort wiederholen</label>
            <input type="password" id="password2" name="password2" required autocomplete="new-password" minlength="12">
            <button type="submit">Neues Passwort setzen</button>
        </form>
        <p class="hint">Der Code ist danach verbraucht, eine Zwei-Faktor-Anmeldung wird abgeschaltet. <a href="<?php echo $e($selfUrl); ?>">Zurück zur Anmeldung</a></p>
        <?php elseif ($registerMode): ?>
        <form method="post" action="">
            <input type="hidden" name="lv_register" value="1">
            <input type="hidden" name="csrf" value="<?php echo $e($lvCsrf); ?>">
            <label for="username">Benutzername</label>
            <input type="text" id="username" name="username" required autofocus autocomplete="username" autocapitalize="none" minlength="2" maxlength="64" value="<?php echo $e($_POST['username'] ?? ''); ?>">
            <label for="password">Passwort (min. 12 Zeichen, Buchstaben + Zahlen)</label>
            <input type="password" id="password" name="password" required autocomplete="new-password" minlength="12">
            <label for="password2">Passwort wiederholen</label>
            <input type="password" id="password2" name="password2" required autocomplete="new-password" minlength="12">
            <label for="note">Nachricht an den Administrator (freiwillig)</label>
            <input type="text" id="note" name="note" maxlength="300" autocomplete="off" placeholder="z. B. wer du bist" value="<?php echo $e($_POST['note'] ?? ''); ?>">
            <button type="submit">Zugang anfragen</button>
        </form>
        <p class="hint">Du bekommst einen eigenen Bereich mit eigenem Schlüssel, den nur dein Passwort öffnet. Niemand sonst kann deine Links lesen, auch der Administrator nicht. Er kann dein Passwort deshalb auch nicht zurücksetzen. <a href="<?php echo $e($selfUrl); ?>">Zurück zur Anmeldung</a></p>
        <?php else: ?>
        <form method="post" action="">
            <input type="hidden" name="lv_login" value="1">
            <input type="hidden" name="csrf" value="<?php echo $e($lvCsrf); ?>">
            <label for="username">Benutzername</label>
            <input type="text" id="username" name="username" required autofocus autocomplete="username" autocapitalize="none" value="<?php echo $e($_POST['username'] ?? ''); ?>">
            <label for="password">Passwort</label>
            <input type="password" id="password" name="password" required autocomplete="current-password">
            <?php if ($hasTotp): ?>
            <label for="totp"><?php echo $multi ? '2FA-Code (nur wenn du 2FA eingerichtet hast)' : '2FA-Code aus der Authenticator-App'; ?></label>
            <input type="text" id="totp" name="totp" <?php echo $multi ? '' : 'required'; ?> inputmode="numeric" pattern="[0-9 ]*" maxlength="7" autocomplete="one-time-code" placeholder="123456">
            <?php endif; ?>
            <button type="submit">Anmelden</button>
        </form>
        <?php if ($hasRecovery || $regOpen): ?>
        <p class="hint">
            <?php if ($hasRecovery): ?><a href="?recover=1">Passwort vergessen oder Handy weg?</a><?php endif; ?>
            <?php if ($hasRecovery && $regOpen): ?><br><?php endif; ?>
            <?php if ($regOpen): ?><a href="?register=1">Noch kein Konto? Zugang anfragen</a><?php endif; ?>
        </p>
        <?php endif; ?>
        <?php endif; ?>
    </div>
</body>
</html><?php
    exit;
}

$initialBookmarks = loadBookmarks();
$lvJsonFlags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
             | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
// Hinweis „seit der letzten Anmeldung“ nur einmal zeigen
$lvNotice = null;
$lvIsAdmin = false;
$lvUserName = '';
$lvPending = 0;
$lvPendingNames = [];
if (LV_AUTH_ENABLED) {
    $lvNotice = $_SESSION['lv_notice'] ?? null;
    unset($_SESSION['lv_notice']);
    // Bei langer Laufzeit die Cookies bei jedem Seitenaufruf verlängern
    $cfgNow = lvLoadAuthConfig();
    if ($cfgNow && $cfgNow['idle_minutes'] > 480 && isset($_COOKIE[LV_KEY_COOKIE])) {
        $exp = time() + $cfgNow['idle_minutes'] * 60;
        setcookie(LV_KEY_COOKIE, (string)$_COOKIE[LV_KEY_COOKIE], lvCookieOpts($exp));
        setcookie(session_name(), session_id(), lvCookieOpts($exp));
    }
    if ($cfgNow) {
        $lvUserName = $cfgNow['username'];
        $lvIsAdmin = $cfgNow['role'] === 'admin';
    }
    // Der Administrator sieht gleich beim Öffnen, ob jemand auf Freigabe wartet
    if ($lvIsAdmin) {
        foreach (lvListUsers() as $u) {
            if ($u['status'] !== 'pending') continue;
            $lvPending++;
            if (count($lvPendingNames) < 5) $lvPendingNames[] = $u['username'];
        }
    }
}
$lvCsrfPage = LV_AUTH_ENABLED ? lvCsrfToken() : '';
?>

<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <meta name="theme-color" content="#0b1120">
    <meta name="robots" content="noindex, nofollow">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="LinkVault">
    <title>LinkVault – Bookmark Manager</title>
    <link rel="icon" href="?action=icon" type="image/svg+xml">
    <link rel="apple-touch-icon" href="?action=icon&amp;s=192">
    <link rel="manifest" href="?action=manifest" crossorigin="use-credentials">
<?php if (LV_TAILWIND_CDN): ?>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: { slate: { 850: '#1a2332', 950: '#0b1120' } },
                    fontFamily: { sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'] }
                }
            }
        }
    </script>
<?php endif; ?>
    <style>
        /* Schrift liegt in dieser Datei und kommt vom eigenen Server, es wird nichts von außen geladen */
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 100 900; font-display: swap; src: url('?action=font') format('woff2'); }
        *, *::before, *::after { box-sizing: border-box; }
        html {
            width: 100%;
            margin: 0;
            padding: 0;
            /* overflow-x:hidden breaks position:sticky in many browsers – use clip */
            overflow-x: clip;
        }
        body {
            width: 100%;
            max-width: 100%;
            margin: 0;
            padding: 0;
            overflow-x: clip;
            background: linear-gradient(165deg, #0b1120 0%, #0f172a 45%, #1e1b4b 100%);
            min-height: 100vh;
            min-height: 100dvh;
            font-family: 'Inter', system-ui, sans-serif;
            color: #f1f5f9;
        }
        * { -webkit-tap-highlight-color: transparent; }
        ::-webkit-scrollbar { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #475569; border-radius: 3px; }

        .glass {
            background: rgba(30, 41, 59, 0.72);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(51, 65, 85, 0.65);
        }
        .glass-strong {
            background: rgba(15, 23, 42, 0.92);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid rgba(51, 65, 85, 0.55);
        }

        .btn {
            display: inline-flex; align-items: center; justify-content: center; gap: 0.35rem;
            font-weight: 600; font-size: 0.8125rem; line-height: 1;
            border-radius: 0.7rem; transition: all 0.15s ease; cursor: pointer;
            user-select: none; border: none; white-space: nowrap;
        }
        .btn:active { transform: scale(0.96); }
        .btn:disabled { opacity: 0.45; cursor: not-allowed; transform: none; }

        .btn-primary {
            background: linear-gradient(135deg, #8b5cf6, #7c3aed); color: #fff;
            box-shadow: 0 4px 14px -3px rgba(139, 92, 246, 0.45); padding: 0.65rem 1rem;
        }
        .btn-primary:hover:not(:disabled) { background: linear-gradient(135deg, #a78bfa, #8b5cf6); }

        .btn-secondary {
            background: rgba(30, 41, 59, 0.95); color: #e2e8f0;
            border: 1px solid rgba(71, 85, 105, 0.7); padding: 0.65rem 1rem;
        }
        .btn-secondary:hover:not(:disabled) { background: rgba(51, 65, 85, 0.95); color: #fff; }

        .btn-danger {
            background: rgba(127, 29, 29, 0.4); color: #fca5a5;
            border: 1px solid rgba(185, 28, 28, 0.4); padding: 0.65rem 1rem;
        }
        .btn-danger:hover:not(:disabled) { background: rgba(153, 27, 27, 0.55); color: #fecaca; }

        .btn-ghost { background: transparent; color: #94a3b8; padding: 0.5rem; border-radius: 0.6rem; }
        .btn-ghost:hover:not(:disabled) { background: rgba(51, 65, 85, 0.6); color: #f1f5f9; }

        .btn-icon {
            width: 2.35rem; height: 2.35rem; padding: 0; border-radius: 0.7rem;
            background: rgba(30, 41, 59, 0.9); border: 1px solid rgba(71, 85, 105, 0.6);
            color: #cbd5e1; flex-shrink: 0;
        }
        .btn-icon:hover:not(:disabled) { background: rgba(51, 65, 85, 0.95); color: #fff; }
        .btn-icon svg { width: 1.15rem; height: 1.15rem; }
        .btn-icon.active {
            background: rgba(139, 92, 246, 0.25); border-color: rgba(139, 92, 246, 0.45); color: #c4b5fd;
        }

        .card-actions {
            display: flex; flex-wrap: nowrap; align-items: center; gap: 0.25rem;
            margin-top: 0.5rem; padding-top: 0.5rem;
            border-top: 1px solid rgba(51, 65, 85, 0.45);
            min-width: 0;
        }
        .card-btn {
            display: inline-flex; align-items: center; justify-content: center; gap: 0.25rem;
            height: 1.85rem; padding: 0 0.5rem; border-radius: 0.5rem;
            font-size: 0.7rem; font-weight: 600; transition: all 0.15s ease;
            cursor: pointer; border: 1px solid transparent; user-select: none;
            flex-shrink: 0;
        }
        .card-btn:active { transform: scale(0.95); }
        .card-btn-open {
            flex: 1 1 auto; min-width: 0;
            background: linear-gradient(135deg, rgba(139, 92, 246, 0.25), rgba(124, 58, 237, 0.2));
            border-color: rgba(139, 92, 246, 0.35); color: #c4b5fd;
        }
        .card-btn-open:hover {
            background: linear-gradient(135deg, rgba(139, 92, 246, 0.4), rgba(124, 58, 237, 0.35)); color: #e9d5ff;
        }
        .card-btn-open span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .card-btn-icon {
            width: 1.85rem; flex: 0 0 1.85rem; padding: 0;
            background: rgba(30, 41, 59, 0.7); border-color: rgba(71, 85, 105, 0.5); color: #94a3b8;
        }
        .card-btn-icon:hover { background: rgba(51, 65, 85, 0.85); color: #e2e8f0; }
        .card-btn-icon.starred {
            color: #fbbf24; background: rgba(120, 53, 15, 0.25); border-color: rgba(245, 158, 11, 0.3);
        }
        .card-btn-icon.danger:hover {
            background: rgba(127, 29, 29, 0.4); border-color: rgba(185, 28, 28, 0.45); color: #fca5a5;
        }
        .card-btn svg { width: 0.85rem; height: 0.85rem; flex-shrink: 0; }

        .bookmark-card {
            transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease;
            width: 100%; max-width: 100%; min-width: 0;
            padding: 0.65rem 0.75rem !important;
        }
        .bookmark-card:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 16px -6px rgba(0,0,0,0.35);
            border-color: rgba(139, 92, 246, 0.3);
        }
        .bookmark-card.favorite {
            border-color: rgba(251, 191, 36, 0.3);
            background: linear-gradient(155deg, rgba(30, 41, 59, 0.85), rgba(69, 26, 3, 0.12));
        }
        .bookmark-card.selected {
            border-color: rgba(139, 92, 246, 0.65) !important;
            box-shadow: 0 0 0 2px rgba(139, 92, 246, 0.25);
            background: linear-gradient(155deg, rgba(30, 41, 59, 0.9), rgba(76, 29, 149, 0.15));
        }

        .favicon {
            width: 28px; height: 28px; border-radius: 7px; object-fit: contain;
            background: rgba(15, 23, 42, 0.65); padding: 3px; flex-shrink: 0;
        }

        .sel-check {
            width: 1.25rem; height: 1.25rem; border-radius: 0.35rem;
            border: 2px solid #64748b; background: transparent; cursor: pointer;
            display: flex; align-items: center; justify-content: center;
            flex-shrink: 0; transition: all 0.15s ease; padding: 0; color: transparent;
        }
        .sel-check.checked { background: #8b5cf6; border-color: #8b5cf6; color: #fff; }
        .sel-check svg { width: 0.75rem; height: 0.75rem; }

        .cat-btn {
            display: inline-flex; align-items: center; gap: 0.25rem;
            padding: 0.35rem 0.7rem; border-radius: 9999px; font-size: 0.72rem; font-weight: 550;
            border: 1px solid rgba(71, 85, 105, 0.55); background: rgba(30, 41, 59, 0.65);
            color: #cbd5e1; transition: all 0.15s ease; cursor: pointer; white-space: nowrap; flex-shrink: 0;
        }
        .cat-btn:hover { background: rgba(51, 65, 85, 0.8); color: #f1f5f9; }
        .cat-btn.active {
            background: linear-gradient(135deg, #8b5cf6, #7c3aed); border-color: transparent; color: #fff;
            box-shadow: 0 3px 12px -2px rgba(139, 92, 246, 0.45);
        }
        .cat-btn .count { opacity: 0.55; font-weight: 500; font-size: 0.7rem; }
        .cat-btn.active .count { opacity: 0.85; }

        #categoryBar {
            display: flex; gap: 0.35rem; overflow-x: auto; -webkit-overflow-scrolling: touch;
            overscroll-behavior-x: contain; touch-action: pan-x;
            scrollbar-width: thin; scrollbar-color: #475569 transparent;
            padding-bottom: 4px; max-width: 100%; cursor: grab;
        }
        #categoryBar:active { cursor: grabbing; }
        #categoryBar::-webkit-scrollbar { height: 4px; display: block; }
        #categoryBar::-webkit-scrollbar-track { background: transparent; }
        #categoryBar::-webkit-scrollbar-thumb {
            background: #475569; border-radius: 4px;
        }
        #categoryBar::-webkit-scrollbar-thumb:hover { background: #64748b; }

        .modal-panel { animation: modalIn 0.2s ease-out; }
        @keyframes modalIn {
            from { opacity: 0; transform: scale(0.96) translateY(10px); }
            to { opacity: 1; transform: scale(1) translateY(0); }
        }
        .toast { animation: toastIn 0.25s ease-out; }
        @keyframes toastIn {
            from { opacity: 0; transform: translateY(12px) scale(0.96); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }

        .fab {
            position: fixed; right: 1rem; bottom: max(1rem, env(safe-area-inset-bottom));
            z-index: 40; width: 3.25rem; height: 3.25rem; border-radius: 1rem;
            background: linear-gradient(135deg, #8b5cf6, #7c3aed); color: #fff;
            box-shadow: 0 8px 24px -4px rgba(139, 92, 246, 0.55);
            display: none; align-items: center; justify-content: center; border: none; cursor: pointer;
        }
        .fab:active { transform: scale(0.92); }
        @media (max-width: 640px) {
            .fab { display: flex; }
            .btn-add-desktop { display: none !important; }
            body.select-mode .fab { display: none; }
        }

        .bookmarks-grid {
            display: grid; grid-template-columns: 1fr; gap: 0.5rem; width: 100%; max-width: 100%;
        }
        @media (min-width: 480px) {
            .bookmarks-grid { grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 0.55rem; }
        }
        @media (min-width: 900px) {
            .bookmarks-grid { grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 0.65rem; }
        }

        .empty-state {
            background: radial-gradient(ellipse at 50% 30%, rgba(139, 92, 246, 0.07) 0%, transparent 65%);
        }
        input:focus, select:focus, textarea:focus, button:focus-visible {
            outline: none; box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.3);
        }

        .safe-bottom { padding-bottom: max(5.5rem, calc(env(safe-area-inset-bottom) + 5rem)); }
        @media (min-width: 641px) { .safe-bottom { padding-bottom: 2rem; } }
        body.select-mode .safe-bottom { padding-bottom: max(7rem, calc(env(safe-area-inset-bottom) + 6.5rem)); }

        .field {
            width: 100%; max-width: 100%; padding: 0.65rem 0.85rem; border-radius: 0.7rem;
            background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(71, 85, 105, 0.55);
            color: #f1f5f9; font-size: 0.9rem; transition: border-color 0.15s;
        }
        .field::placeholder { color: #64748b; }
        .field:focus { border-color: rgba(139, 92, 246, 0.55); box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.2); }

        .toggle {
            position: relative; width: 2.6rem; height: 1.4rem; background: #334155;
            border-radius: 9999px; transition: background 0.2s; cursor: pointer;
            flex-shrink: 0; border: none; padding: 0;
        }
        .toggle::after {
            content: ''; position: absolute; top: 2px; left: 2px;
            width: 1.15rem; height: 1.15rem; background: #fff; border-radius: 50%; transition: transform 0.2s;
        }
        .toggle.on { background: #f59e0b; }
        .toggle.on::after { transform: translateX(1.2rem); }

        .bulk-bar {
            position: fixed; left: 0; right: 0; bottom: 0; z-index: 45;
            transform: translateY(110%); transition: transform 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            padding: 0.75rem 0.75rem max(0.75rem, env(safe-area-inset-bottom));
        }
        body.select-mode .bulk-bar { transform: translateY(0); }

        .bulk-inner {
            max-width: 42rem; margin: 0 auto;
            background: rgba(15, 23, 42, 0.96); backdrop-filter: blur(20px);
            border: 1px solid rgba(139, 92, 246, 0.35); border-radius: 1rem;
            padding: 0.65rem 0.75rem;
            box-shadow: 0 -8px 32px -4px rgba(0,0,0,0.5), 0 0 24px -8px rgba(139, 92, 246, 0.2);
            display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem;
        }

        .header-row {
            display: flex; align-items: center; gap: 0.5rem; width: 100%; min-width: 0;
        }
        .header-actions { display: flex; align-items: center; gap: 0.35rem; flex-shrink: 0; position: relative; z-index: 40; }
        .search-wrap { flex: 1 1 auto; min-width: 0; position: relative; }
        .truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .min-w-0 { min-width: 0; }

        header, main, .max-w-7xl, .header-row, .search-wrap, .bookmarks-grid, .bookmark-card {
            max-width: 100%;
        }
        .header-top { position: relative; z-index: 40; }
        .header-cats { position: relative; z-index: 10; }
        #exportMenu, #toolsMenu {
            z-index: 100 !important;
            /* fast deckend: im Header greift der Unschärfe-Effekt nicht, sonst scheint der Inhalt durch */
            background: rgba(15, 23, 42, 0.97);
            box-shadow: 0 12px 40px -8px rgba(0,0,0,0.55), 0 0 0 1px rgba(51,65,85,0.5);
        }
        .search-clear {
            position: absolute; right: 0.45rem; top: 50%; transform: translateY(-50%);
            width: 1.5rem; height: 1.5rem; border-radius: 0.4rem;
            display: none; align-items: center; justify-content: center;
            color: #94a3b8; background: transparent; border: none; cursor: pointer;
        }
        .search-clear:hover { color: #f1f5f9; background: rgba(51,65,85,0.6); }
        .search-wrap.has-query .search-clear { display: flex; }
        .search-wrap.has-query input { padding-right: 2rem !important; }

        /* Fixed header = search always visible while scrolling */
        #appHeader {
            position: fixed !important;
            top: 0;
            left: 0;
            right: 0;
            width: 100%;
            z-index: 50;
            background: rgba(11, 17, 32, 0.98) !important;
            backdrop-filter: blur(18px);
            -webkit-backdrop-filter: blur(18px);
            border-bottom: 1px solid rgba(51, 65, 85, 0.5);
        }
        #headerSpacer {
            width: 100%;
            flex-shrink: 0;
        }
        .search-wrap .field {
            background: rgba(15, 23, 42, 0.95) !important;
        }

        .cat-chip {
            display: inline-flex; align-items: center; gap: 0.25rem;
            padding: 0.35rem 0.7rem; border-radius: 9999px;
            font-size: 0.75rem; font-weight: 550;
            border: 1px solid rgba(71, 85, 105, 0.6);
            background: rgba(30, 41, 59, 0.8); color: #cbd5e1;
            cursor: pointer; transition: all 0.15s;
        }
        .cat-chip:hover { border-color: rgba(139, 92, 246, 0.45); color: #e9d5ff; }
        .cat-chip.active {
            background: linear-gradient(135deg, #8b5cf6, #7c3aed);
            border-color: transparent; color: #fff;
        }

        /* Domain group – startet geschlossen */
        .domain-group {
            grid-column: 1 / -1;
            border-radius: 0.75rem;
            border: 1px solid rgba(51, 65, 85, 0.55);
            background: rgba(15, 23, 42, 0.4);
            overflow: hidden;
        }
        .domain-group-header {
            display: flex; align-items: center; gap: 0.5rem;
            padding: 0.5rem 0.75rem; cursor: pointer; user-select: none;
            transition: background 0.15s;
        }
        .domain-group-header:hover { background: rgba(51, 65, 85, 0.35); }
        .domain-group-header .chevron {
            transition: transform 0.2s ease; color: #64748b; flex-shrink: 0;
            width: 0.9rem; height: 0.9rem;
        }
        .domain-group.open .domain-group-header .chevron { transform: rotate(90deg); }
        .domain-group-body {
            display: none;
            padding: 0 0.5rem 0.55rem;
            grid-template-columns: 1fr;
            gap: 0.45rem;
        }
        .domain-group.open .domain-group-body { display: grid; }
        @media (min-width: 480px) {
            .domain-group-body { grid-template-columns: repeat(auto-fill, minmax(210px, 1fr)); }
        }

        /* Tools dropdown */
        .tools-menu {
            position: absolute; right: 0; top: calc(100% + 0.4rem);
            min-width: 13.5rem; z-index: 100;
            max-height: calc(100vh - 5rem); max-height: calc(100dvh - 5rem); overflow-y: auto;
        }

        /* ===== Neu in 3.0 ===== */
        /* App-Modus am Handy: Platz für Statusleiste, Notch und Wischbalken lassen.
           Ohne das liegt die Kopfzeile unter der Uhr und lässt sich nicht antippen. */
        html { background: #0b1120; }
        #appHeader {
            padding-top: env(safe-area-inset-top);
            padding-left: env(safe-area-inset-left);
            padding-right: env(safe-area-inset-right);
        }
        html body main {
            padding-left: max(0.75rem, env(safe-area-inset-left));
            padding-right: max(0.75rem, env(safe-area-inset-right));
        }
        @media (min-width: 640px) {
            html body main { padding-left: max(1.25rem, env(safe-area-inset-left)); padding-right: max(1.25rem, env(safe-area-inset-right)); }
        }
        .fab { right: calc(1rem + env(safe-area-inset-right)); }
        .bulk-bar { padding-left: max(0.75rem, env(safe-area-inset-left)); padding-right: max(0.75rem, env(safe-area-inset-right)); }
        [id$="Overlay"] {
            padding: max(0.75rem, env(safe-area-inset-top)) max(0.75rem, env(safe-area-inset-right)) max(0.75rem, env(safe-area-inset-bottom)) max(0.75rem, env(safe-area-inset-left));
        }
        [id$="Overlay"] > .modal-panel {
            max-height: calc(100vh - 1.5rem);
            max-height: calc(100dvh - env(safe-area-inset-top) - env(safe-area-inset-bottom) - 1.5rem);
        }
        #toastContainer { bottom: calc(5rem + env(safe-area-inset-bottom)); }
        @media (min-width: 640px) { #toastContainer { bottom: calc(1.5rem + env(safe-area-inset-bottom)); } }
        @media (display-mode: standalone) {
            body { overscroll-behavior-y: none; }
            #appHeader, .cat-btn, .btn, .card-btn, .menu-opt { -webkit-user-select: none; user-select: none; }
        }
        /* Fenster liegen über Kopfzeile und Plus-Knopf (die Ebenen fehlten im eingebauten CSS) */
        [id$="Overlay"] { z-index: 75; }
        #confirmOverlay, #dialogOverlay { z-index: 85; }
        #toastContainer { z-index: 90; }
        body { font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; }
        /* iPhone zoomt in Felder mit kleiner Schrift hinein, deshalb am Handy 16px */
        @media (pointer: coarse) {
            html body .field, html body input[type="text"], html body input[type="password"], html body input[type="search"],
            html body select, html body textarea { font-size: 16px !important; }
        }
        .bm-main { display: flex; align-items: flex-start; gap: 0.5rem; min-width: 0; }
        .bm-text { flex: 1 1 auto; min-width: 0; }
        .bm-title {
            display: block; font-weight: 600; font-size: 0.875rem; line-height: 1.375; color: #f1f5f9;
            overflow: hidden; text-overflow: ellipsis; white-space: nowrap; text-decoration: none;
        }
        a.bm-title:hover { color: #ddd6fe; text-decoration: underline; text-underline-offset: 2px; }
        a.bm-title:focus-visible { outline: 2px solid #8b5cf6; outline-offset: 2px; border-radius: 3px; }
        .bm-domain { display: block; font-size: 11px; color: #64748b; margin-top: 0.125rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .bm-desc {
            font-size: 11px; color: #94a3b8; margin: 0.15rem 0 0; line-height: 1.375;
            overflow: hidden; display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 2;
        }
        .bm-meta { display: flex; flex-wrap: wrap; gap: 0.25rem; margin-top: 0.3rem; min-width: 0; }
        .bm-chip {
            display: inline-block; padding: 0.1rem 0.375rem; border-radius: 0.25rem; font-size: 10px; font-weight: 500;
            background: rgba(30, 41, 59, 0.7); color: #94a3b8; border: 1px solid rgba(51, 65, 85, 0.45);
            max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; line-height: 1.5;
        }
        .bm-tag { color: #c4b5fd; border-color: rgba(139, 92, 246, 0.3); background: rgba(139, 92, 246, 0.1); cursor: pointer; }
        .bm-tag:hover { background: rgba(139, 92, 246, 0.25); }
        .bm-warn { color: #fda4af; border-color: rgba(244, 63, 94, 0.35); background: rgba(244, 63, 94, 0.12); }
        .bm-warn.unclear { color: #fcd34d; border-color: rgba(245, 158, 11, 0.35); background: rgba(245, 158, 11, 0.1); }
        .bm-more {
            display: none; align-items: center; justify-content: center; flex: 0 0 1.75rem; width: 1.75rem; height: 1.75rem;
            border-radius: 0.5rem; border: 1px solid transparent; background: transparent; color: #94a3b8; cursor: pointer; padding: 0;
        }
        .bm-more:hover, .bookmark-card.expanded .bm-more { background: rgba(51, 65, 85, 0.7); color: #f1f5f9; }
        .bm-more svg { width: 1rem; height: 1rem; }
        body.select-mode .bm-more { display: none !important; }
        .bookmark-card.dragging { opacity: 0.45; }
        .cat-btn.drop-ok { outline: 2px dashed #a78bfa; outline-offset: 1px; background: rgba(139, 92, 246, 0.25); color: #fff; }
        .cat-btn.warn { border-color: rgba(244, 63, 94, 0.4); color: #fda4af; }
        .cat-btn.warn.active { background: linear-gradient(135deg, #e11d48, #be123c); color: #fff; }

        /* Unterordner-Leiste */
        #subCatBar {
            display: flex; gap: 0.3rem; overflow-x: auto; margin-top: 0.35rem; padding-bottom: 3px;
            scrollbar-width: none; -webkit-overflow-scrolling: touch;
        }
        #subCatBar::-webkit-scrollbar { display: none; }
        #subCatBar:empty { display: none; }
        #subCatBar .cat-btn { padding: 0.25rem 0.6rem; font-size: 0.68rem; }

        /* Ansicht „Liste“: eine Zeile pro Link */
        body.view-list .bookmarks-grid, body.view-list .domain-group-body { grid-template-columns: 1fr !important; gap: 0.3rem; }
        body.view-list .bookmark-card {
            padding: 0.4rem 0.6rem !important; display: flex; flex-wrap: wrap; align-items: center; column-gap: 0.5rem;
        }
        body.view-list .bookmark-card:hover { transform: none; }
        body.view-list .bm-main { flex: 1 1 0; align-items: center; }
        body.view-list .favicon { width: 20px; height: 20px; padding: 2px; border-radius: 5px; }
        body.view-list .bm-text { display: flex; align-items: center; gap: 0.6rem; }
        body.view-list .bm-title { flex: 0 1 auto; min-width: 2rem; }
        body.view-list .bm-domain { flex: 0 2 auto; margin: 0; min-width: 0; }
        body.view-list .bm-desc { display: none; }
        body.view-list .bm-meta { margin: 0 0 0 auto; flex-wrap: nowrap; flex: 0 1 auto; max-width: 45%; overflow: hidden; }
        body.view-list .bm-more { display: inline-flex; }
        body.view-list .card-actions { display: none; flex-basis: 100%; }
        body.view-list .bookmark-card.expanded .card-actions { display: flex; }
        @media (max-width: 640px) {
            body.view-list .bm-domain, body.view-list .bm-meta .bm-tag { display: none; }
            body.view-list .bm-meta { max-width: 38%; }
        }
        @media (hover: hover) and (min-width: 900px) {
            body.view-list .bm-more { display: none; }
            body.view-list .card-actions {
                display: flex; flex-basis: auto; margin: 0; padding: 0; border: 0; opacity: 0.25; transition: opacity 0.12s;
            }
            body.view-list .bookmark-card:hover .card-actions, body.view-list .bookmark-card:focus-within .card-actions { opacity: 1; }
            body.view-list .card-btn-open { display: none; }
            body.view-list .bm-desc {
                display: block; flex: 1 1 0; min-width: 0; margin: 0; white-space: nowrap; text-overflow: ellipsis; -webkit-line-clamp: unset;
            }
        }

        /* Ansicht „Kompakt“: kleine Kacheln, nur Icon + Titel */
        body.view-compact .bookmarks-grid, body.view-compact .domain-group-body {
            grid-template-columns: repeat(2, minmax(0, 1fr)) !important; gap: 0.3rem;
        }
        @media (min-width: 560px) {
            body.view-compact .bookmarks-grid, body.view-compact .domain-group-body {
                grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)) !important;
            }
        }
        body.view-compact .bookmark-card { padding: 0.35rem 0.4rem 0.35rem 0.5rem !important; }
        body.view-compact .bookmark-card:hover { transform: none; }
        body.view-compact .bm-main { align-items: center; gap: 0.4rem; }
        body.view-compact .favicon { width: 18px; height: 18px; padding: 1px; border-radius: 4px; }
        body.view-compact .bm-title { font-size: 0.8rem; }
        body.view-compact .bm-domain, body.view-compact .bm-desc, body.view-compact .bm-meta, body.view-compact .card-actions { display: none; }
        body.view-compact .bm-more { display: inline-flex; flex-basis: 1.5rem; width: 1.5rem; height: 1.5rem; }
        body.view-compact .bookmark-card.expanded { grid-column: 1 / -1; }
        body.view-compact .bookmark-card.expanded .bm-domain { display: block; }
        body.view-compact .bookmark-card.expanded .bm-meta, body.view-compact .bookmark-card.expanded .card-actions { display: flex; }
        body.view-compact .bookmark-card.expanded .bm-desc { display: -webkit-box; }
        body.view-compact .bookmark-card.expanded .bm-title { white-space: normal; }

        /* Menüs */
        #viewMenu { z-index: 100 !important; background: rgba(15, 23, 42, 0.97); box-shadow: 0 12px 40px -8px rgba(0,0,0,0.55), 0 0 0 1px rgba(51,65,85,0.5); }
        .menu-label { padding: 0.5rem 0.75rem 0.25rem; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; }
        .menu-opt {
            display: flex; align-items: center; gap: 0.5rem; width: 100%; text-align: left; padding: 0.5rem 0.75rem;
            font-size: 0.875rem; color: #e2e8f0; background: transparent; border: 0; cursor: pointer;
        }
        .menu-opt:hover { background: rgba(51, 65, 85, 0.7); }
        .menu-opt svg { width: 1rem; height: 1rem; color: #94a3b8; flex-shrink: 0; }
        .menu-opt.on { color: #c4b5fd; }
        .menu-opt.on::after { content: '✓'; margin-left: auto; color: #a78bfa; font-weight: 700; }
        .menu-opt.danger { color: #fda4af; }
        .menu-opt.danger svg { color: #fb7185; }
        .menu-opt .badge { margin-left: auto; font-size: 10px; color: #94a3b8; background: rgba(30, 41, 59, 0.9); padding: 0.05rem 0.4rem; border-radius: 9999px; }
        .menu-sep { border-top: 1px solid rgba(51, 65, 85, 0.5); margin: 0.25rem 0; }

        /* Fenster-Bausteine */
        .box { border: 1px solid rgba(51, 65, 85, 0.5); border-radius: 0.75rem; padding: 0.75rem; background: rgba(15, 23, 42, 0.45); }
        .box h4 { font-size: 0.8rem; font-weight: 600; color: #e2e8f0; margin: 0 0 0.35rem; }
        .box p { font-size: 0.78rem; color: #94a3b8; line-height: 1.5; margin: 0 0 0.5rem; }
        .box .row { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }
        .mono-box {
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85rem; letter-spacing: 0.04em;
            color: #ddd6fe; background: rgba(2, 6, 23, 0.6); border: 1px dashed rgba(139, 92, 246, 0.45);
            border-radius: 0.5rem; padding: 0.5rem 0.6rem; word-break: break-all; user-select: all; margin-bottom: 0.5rem;
        }
        .ok-text { color: #6ee7b7; } .warn-text { color: #fcd34d; } .bad-text { color: #fda4af; }
        .lbl { display: block; font-size: 0.75rem; font-weight: 500; color: #94a3b8; margin-bottom: 0.25rem; }
        .list-row {
            display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0.625rem; border-radius: 0.5rem;
            background: rgba(30, 41, 59, 0.5); border: 1px solid rgba(51, 65, 85, 0.4); min-width: 0;
        }
        .list-row .grow { flex: 1 1 auto; min-width: 0; }
        .list-row .t1 { font-size: 0.85rem; color: #e2e8f0; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .list-row .t2 { font-size: 11px; color: #64748b; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .stack > * + * { margin-top: 0.4rem; }
        .dot { width: 0.5rem; height: 0.5rem; border-radius: 50%; flex-shrink: 0; background: #f43f5e; }
        .dot.ok { background: #10b981; } .dot.mid { background: #f59e0b; }
        .tag-suggest { display: flex; flex-wrap: wrap; gap: 0.25rem; margin-top: 0.4rem; }
        kbd { font-family: inherit; font-size: 10px; padding: 0.05rem 0.3rem; border-radius: 0.25rem; border: 1px solid rgba(71, 85, 105, 0.7); color: #94a3b8; }
        /* ===== Neu in 3.1: mehrere Benutzer ===== */
        .btn-icon { position: relative; }
        .btn-icon.has-note::after {
            content: ''; position: absolute; top: -3px; right: -3px; width: 0.65rem; height: 0.65rem;
            border-radius: 50%; background: #f59e0b; border: 2px solid #0b1120;
        }
        .menu-opt .badge.hot { background: #f59e0b; color: #1e1b4b; font-weight: 700; }
        .user-note { font-size: 11px; color: #cbd5e1; margin-top: 0.15rem; line-height: 1.4; overflow-wrap: anywhere; }
        .toggle.green.on { background: #10b981; }
        @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation: none !important; transition: none !important; } }
    </style>
<?php if (!LV_TAILWIND_CDN): ?>
    <!-- Tailwind fest eingebaut (nur die Klassen, die diese Seite benutzt). Neue Klassen? Oben LV_TAILWIND_CDN auf true stellen. -->
    <style id="tailwind-built">*,:after,:before{--tw-border-spacing-x:0;--tw-border-spacing-y:0;--tw-translate-x:0;--tw-translate-y:0;--tw-rotate:0;--tw-skew-x:0;--tw-skew-y:0;--tw-scale-x:1;--tw-scale-y:1;--tw-pan-x: ;--tw-pan-y: ;--tw-pinch-zoom: ;--tw-scroll-snap-strictness:proximity;--tw-gradient-from-position: ;--tw-gradient-via-position: ;--tw-gradient-to-position: ;--tw-ordinal: ;--tw-slashed-zero: ;--tw-numeric-figure: ;--tw-numeric-spacing: ;--tw-numeric-fraction: ;--tw-ring-inset: ;--tw-ring-offset-width:0px;--tw-ring-offset-color:#fff;--tw-ring-color:rgba(59,130,246,.5);--tw-ring-offset-shadow:0 0 #0000;--tw-ring-shadow:0 0 #0000;--tw-shadow:0 0 #0000;--tw-shadow-colored:0 0 #0000;--tw-blur: ;--tw-brightness: ;--tw-contrast: ;--tw-grayscale: ;--tw-hue-rotate: ;--tw-invert: ;--tw-saturate: ;--tw-sepia: ;--tw-drop-shadow: ;--tw-backdrop-blur: ;--tw-backdrop-brightness: ;--tw-backdrop-contrast: ;--tw-backdrop-grayscale: ;--tw-backdrop-hue-rotate: ;--tw-backdrop-invert: ;--tw-backdrop-opacity: ;--tw-backdrop-saturate: ;--tw-backdrop-sepia: ;--tw-contain-size: ;--tw-contain-layout: ;--tw-contain-paint: ;--tw-contain-style: }::backdrop{--tw-border-spacing-x:0;--tw-border-spacing-y:0;--tw-translate-x:0;--tw-translate-y:0;--tw-rotate:0;--tw-skew-x:0;--tw-skew-y:0;--tw-scale-x:1;--tw-scale-y:1;--tw-pan-x: ;--tw-pan-y: ;--tw-pinch-zoom: ;--tw-scroll-snap-strictness:proximity;--tw-gradient-from-position: ;--tw-gradient-via-position: ;--tw-gradient-to-position: ;--tw-ordinal: ;--tw-slashed-zero: ;--tw-numeric-figure: ;--tw-numeric-spacing: ;--tw-numeric-fraction: ;--tw-ring-inset: ;--tw-ring-offset-width:0px;--tw-ring-offset-color:#fff;--tw-ring-color:rgba(59,130,246,.5);--tw-ring-offset-shadow:0 0 #0000;--tw-ring-shadow:0 0 #0000;--tw-shadow:0 0 #0000;--tw-shadow-colored:0 0 #0000;--tw-blur: ;--tw-brightness: ;--tw-contrast: ;--tw-grayscale: ;--tw-hue-rotate: ;--tw-invert: ;--tw-saturate: ;--tw-sepia: ;--tw-drop-shadow: ;--tw-backdrop-blur: ;--tw-backdrop-brightness: ;--tw-backdrop-contrast: ;--tw-backdrop-grayscale: ;--tw-backdrop-hue-rotate: ;--tw-backdrop-invert: ;--tw-backdrop-opacity: ;--tw-backdrop-saturate: ;--tw-backdrop-sepia: ;--tw-contain-size: ;--tw-contain-layout: ;--tw-contain-paint: ;--tw-contain-style: }/*! tailwindcss v3.4.17 | MIT License | https://tailwindcss.com*/*,:after,:before{box-sizing:border-box;border:0 solid #e5e7eb}:after,:before{--tw-content:""}:host,html{line-height:1.5;-webkit-text-size-adjust:100%;-moz-tab-size:4;-o-tab-size:4;tab-size:4;font-family:Inter,system-ui,-apple-system,sans-serif;font-feature-settings:normal;font-variation-settings:normal;-webkit-tap-highlight-color:transparent}body{margin:0;line-height:inherit}hr{height:0;color:inherit;border-top-width:1px}abbr:where([title]){-webkit-text-decoration:underline dotted;text-decoration:underline dotted}h1,h2,h3,h4,h5,h6{font-size:inherit;font-weight:inherit}a{color:inherit;text-decoration:inherit}b,strong{font-weight:bolder}code,kbd,pre,samp{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,Courier New,monospace;font-feature-settings:normal;font-variation-settings:normal;font-size:1em}small{font-size:80%}sub,sup{font-size:75%;line-height:0;position:relative;vertical-align:baseline}sub{bottom:-.25em}sup{top:-.5em}table{text-indent:0;border-color:inherit;border-collapse:collapse}button,input,optgroup,select,textarea{font-family:inherit;font-feature-settings:inherit;font-variation-settings:inherit;font-size:100%;font-weight:inherit;line-height:inherit;letter-spacing:inherit;color:inherit;margin:0;padding:0}button,select{text-transform:none}button,input:where([type=button]),input:where([type=reset]),input:where([type=submit]){-webkit-appearance:button;background-color:transparent;background-image:none}:-moz-focusring{outline:auto}:-moz-ui-invalid{box-shadow:none}progress{vertical-align:baseline}::-webkit-inner-spin-button,::-webkit-outer-spin-button{height:auto}[type=search]{-webkit-appearance:textfield;outline-offset:-2px}::-webkit-search-decoration{-webkit-appearance:none}::-webkit-file-upload-button{-webkit-appearance:button;font:inherit}summary{display:list-item}blockquote,dd,dl,figure,h1,h2,h3,h4,h5,h6,hr,p,pre{margin:0}fieldset{margin:0}fieldset,legend{padding:0}menu,ol,ul{list-style:none;margin:0;padding:0}dialog{padding:0}textarea{resize:vertical}input::-moz-placeholder,textarea::-moz-placeholder{opacity:1;color:#9ca3af}input::placeholder,textarea::placeholder{opacity:1;color:#9ca3af}[role=button],button{cursor:pointer}:disabled{cursor:default}audio,canvas,embed,iframe,img,object,svg,video{display:block;vertical-align:middle}img,video{max-width:100%;height:auto}[hidden]:where(:not([hidden=until-found])){display:none}.container{width:100%}@media (min-width:640px){.container{max-width:640px}}@media (min-width:768px){.container{max-width:768px}}@media (min-width:1024px){.container{max-width:1024px}}@media (min-width:1280px){.container{max-width:1280px}}@media (min-width:1536px){.container{max-width:1536px}}.pointer-events-none{pointer-events:none}.pointer-events-auto{pointer-events:auto}.visible{visibility:visible}.fixed{position:fixed}.absolute{position:absolute}.relative{position:relative}.sticky{position:sticky}.inset-0{inset:0}.bottom-20{bottom:5rem}.left-1\/2{left:50%}.left-2\.5{left:.625rem}.right-0{right:0}.top-0{top:0}.top-1\/2{top:50%}.z-10{z-index:10}.z-50{z-index:50}.z-\[55\]{z-index:55}.z-\[60\]{z-index:60}.mx-auto{margin-left:auto;margin-right:auto}.my-1{margin-top:.25rem}.mb-1,.my-1{margin-bottom:.25rem}.mb-1\.5{margin-bottom:.375rem}.mb-2{margin-bottom:.5rem}.mb-3{margin-bottom:.75rem}.mb-4{margin-bottom:1rem}.mb-6{margin-bottom:1.5rem}.ml-auto{margin-left:auto}.mt-0\.5{margin-top:.125rem}.mt-1{margin-top:.25rem}.mt-1\.5{margin-top:.375rem}.mt-2{margin-top:.5rem}.mt-2\.5{margin-top:.625rem}.mt-3{margin-top:.75rem}.mt-4{margin-top:1rem}.line-clamp-2{overflow:hidden;display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:2}.block{display:block}.flex{display:flex}.inline-flex{display:inline-flex}.grid{display:grid}.hidden{display:none}.h-1\.5{height:.375rem}.h-10{height:2.5rem}.h-12{height:3rem}.h-28{height:7rem}.h-3\.5{height:.875rem}.h-4{height:1rem}.h-5{height:1.25rem}.h-6{height:1.5rem}.h-8{height:2rem}.h-full{height:100%}.max-h-28{max-height:7rem}.max-h-48{max-height:12rem}.max-h-\[85vh\]{max-height:85vh}.max-h-\[90vh\]{max-height:90vh}.w-10{width:2.5rem}.w-12{width:3rem}.w-3\.5{width:.875rem}.w-4{width:1rem}.w-44{width:11rem}.w-5{width:1.25rem}.w-6{width:1.5rem}.w-8{width:2rem}.w-full{width:100%}.min-w-0{min-width:0}.max-w-7xl{max-width:80rem}.max-w-full{max-width:100%}.max-w-md{max-width:28rem}.max-w-sm{max-width:24rem}.max-w-xs{max-width:20rem}.flex-1{flex:1 1 0%}.flex-shrink{flex-shrink:1}.shrink-0{flex-shrink:0}.-translate-x-1\/2{--tw-translate-x:-50%}.-translate-x-1\/2,.-translate-y-1\/2{transform:translate(var(--tw-translate-x),var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y))}.-translate-y-1\/2{--tw-translate-y:-50%}.transform{transform:translate(var(--tw-translate-x),var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y))}.cursor-pointer{cursor:pointer}.resize-none{resize:none}.resize{resize:both}.flex-col{flex-direction:column}.flex-wrap{flex-wrap:wrap}.items-start{align-items:flex-start}.items-center{align-items:center}.justify-center{justify-content:center}.justify-between{justify-content:space-between}.gap-1\.5{gap:.375rem}.gap-2{gap:.5rem}.gap-2\.5{gap:.625rem}.space-y-1\.5>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-top:calc(.375rem*(1 - var(--tw-space-y-reverse)));margin-bottom:calc(.375rem*var(--tw-space-y-reverse))}.space-y-3>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-top:calc(.75rem*(1 - var(--tw-space-y-reverse)));margin-bottom:calc(.75rem*var(--tw-space-y-reverse))}.space-y-3\.5>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-top:calc(.875rem*(1 - var(--tw-space-y-reverse)));margin-bottom:calc(.875rem*var(--tw-space-y-reverse))}.overflow-hidden{overflow:hidden}.overflow-y-auto{overflow-y:auto}.truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.\!rounded-lg{border-radius:.5rem!important}.rounded{border-radius:.25rem}.rounded-2xl{border-radius:1rem}.rounded-full{border-radius:9999px}.rounded-lg{border-radius:.5rem}.rounded-xl{border-radius:.75rem}.border{border-width:1px}.border-2{border-width:2px}.border-b{border-bottom-width:1px}.border-t{border-top-width:1px}.border-dashed{border-style:dashed}.border-slate-600{--tw-border-opacity:1;border-color:rgb(71 85 105/var(--tw-border-opacity,1))}.border-slate-700\/35{border-color:rgba(51,65,85,.35)}.border-slate-700\/40{border-color:rgba(51,65,85,.4)}.border-slate-700\/45{border-color:rgba(51,65,85,.45)}.border-slate-700\/50{border-color:rgba(51,65,85,.5)}.border-transparent{border-color:transparent}.bg-\[rgba\(15\2c 23\2c 42\2c 0\.95\)\]{background-color:rgba(15,23,42,.95)}.bg-black\/65{background-color:rgba(0,0,0,.65)}.bg-emerald-600\/95{background-color:rgba(5,150,105,.95)}.bg-rose-500\/15{background-color:rgba(244,63,94,.15)}.bg-rose-600\/95{background-color:rgba(225,29,72,.95)}.bg-slate-800{--tw-bg-opacity:1;background-color:rgb(30 41 59/var(--tw-bg-opacity,1))}.bg-slate-800\/50{background-color:rgba(30,41,59,.5)}.bg-slate-800\/70{background-color:rgba(30,41,59,.7)}.bg-slate-800\/80{background-color:rgba(30,41,59,.8)}.bg-violet-500{--tw-bg-opacity:1;background-color:rgb(139 92 246/var(--tw-bg-opacity,1))}.bg-gradient-to-br{background-image:linear-gradient(to bottom right,var(--tw-gradient-stops))}.from-violet-500{--tw-gradient-from:#8b5cf6 var(--tw-gradient-from-position);--tw-gradient-to:rgba(139,92,246,0) var(--tw-gradient-to-position);--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to)}.to-purple-700{--tw-gradient-to:#7e22ce var(--tw-gradient-to-position)}.p-3{padding:.75rem}.p-3\.5{padding:.875rem}.p-4{padding:1rem}.\!px-2{padding-left:.5rem!important;padding-right:.5rem!important}.\!px-2\.5{padding-left:.625rem!important;padding-right:.625rem!important}.\!px-3{padding-left:.75rem!important;padding-right:.75rem!important}.\!py-2{padding-top:.5rem!important;padding-bottom:.5rem!important}.px-1{padding-left:.25rem;padding-right:.25rem}.px-1\.5{padding-left:.375rem;padding-right:.375rem}.px-2\.5{padding-left:.625rem;padding-right:.625rem}.px-3{padding-left:.75rem;padding-right:.75rem}.px-3\.5{padding-left:.875rem;padding-right:.875rem}.px-4{padding-left:1rem;padding-right:1rem}.py-0\.5{padding-top:.125rem;padding-bottom:.125rem}.py-1{padding-top:.25rem;padding-bottom:.25rem}.py-1\.5{padding-top:.375rem;padding-bottom:.375rem}.py-12{padding-top:3rem;padding-bottom:3rem}.py-2{padding-top:.5rem;padding-bottom:.5rem}.py-2\.5{padding-top:.625rem;padding-bottom:.625rem}.py-3{padding-top:.75rem;padding-bottom:.75rem}.py-3\.5{padding-top:.875rem;padding-bottom:.875rem}.\!pl-8{padding-left:2rem!important}.\!pr-2{padding-right:.5rem!important}.pt-0\.5{padding-top:.125rem}.pt-1{padding-top:.25rem}.pt-4{padding-top:1rem}.text-left{text-align:left}.text-center{text-align:center}.\!text-sm{font-size:.875rem!important;line-height:1.25rem!important}.\!text-xs{font-size:.75rem!important;line-height:1rem!important}.text-\[10px\]{font-size:10px}.text-\[11px\]{font-size:11px}.text-base{font-size:1rem;line-height:1.5rem}.text-sm{font-size:.875rem;line-height:1.25rem}.text-xs{font-size:.75rem;line-height:1rem}.font-medium{font-weight:500}.font-semibold{font-weight:600}.uppercase{text-transform:uppercase}.leading-relaxed{line-height:1.625}.leading-snug{line-height:1.375}.tracking-wider{letter-spacing:.05em}.text-amber-300{--tw-text-opacity:1;color:rgb(252 211 77/var(--tw-text-opacity,1))}.text-amber-300\/90{color:rgba(252,211,77,.9)}.text-amber-400{--tw-text-opacity:1;color:rgb(251 191 36/var(--tw-text-opacity,1))}.text-rose-300{--tw-text-opacity:1;color:rgb(253 164 175/var(--tw-text-opacity,1))}.text-rose-400{--tw-text-opacity:1;color:rgb(251 113 133/var(--tw-text-opacity,1))}.text-slate-100{--tw-text-opacity:1;color:rgb(241 245 249/var(--tw-text-opacity,1))}.text-slate-200{--tw-text-opacity:1;color:rgb(226 232 240/var(--tw-text-opacity,1))}.text-slate-300{--tw-text-opacity:1;color:rgb(203 213 225/var(--tw-text-opacity,1))}.text-slate-400{--tw-text-opacity:1;color:rgb(148 163 184/var(--tw-text-opacity,1))}.text-slate-500{--tw-text-opacity:1;color:rgb(100 116 139/var(--tw-text-opacity,1))}.text-slate-600{--tw-text-opacity:1;color:rgb(71 85 105/var(--tw-text-opacity,1))}.text-violet-300{--tw-text-opacity:1;color:rgb(196 181 253/var(--tw-text-opacity,1))}.text-violet-400{--tw-text-opacity:1;color:rgb(167 139 250/var(--tw-text-opacity,1))}.text-white{--tw-text-opacity:1;color:rgb(255 255 255/var(--tw-text-opacity,1))}.underline{text-decoration-line:underline}.underline-offset-2{text-underline-offset:2px}.antialiased{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}.shadow-2xl{--tw-shadow:0 25px 50px -12px rgba(0,0,0,.25);--tw-shadow-colored:0 25px 50px -12px var(--tw-shadow-color)}.shadow-2xl,.shadow-\[0_0_14px_-3px_rgba\(139\2c 92\2c 246\2c 0\.5\)\]{box-shadow:var(--tw-ring-offset-shadow,0 0 #0000),var(--tw-ring-shadow,0 0 #0000),var(--tw-shadow)}.shadow-\[0_0_14px_-3px_rgba\(139\2c 92\2c 246\2c 0\.5\)\]{--tw-shadow:0 0 14px -3px rgba(139,92,246,.5);--tw-shadow-colored:0 0 14px -3px var(--tw-shadow-color)}.shadow-xl{--tw-shadow:0 20px 25px -5px rgba(0,0,0,.1),0 8px 10px -6px rgba(0,0,0,.1);--tw-shadow-colored:0 20px 25px -5px var(--tw-shadow-color),0 8px 10px -6px var(--tw-shadow-color);box-shadow:var(--tw-ring-offset-shadow,0 0 #0000),var(--tw-ring-shadow,0 0 #0000),var(--tw-shadow)}.outline{outline-style:solid}.blur{--tw-blur:blur(8px)}.blur,.filter{filter:var(--tw-blur) var(--tw-brightness) var(--tw-contrast) var(--tw-grayscale) var(--tw-hue-rotate) var(--tw-invert) var(--tw-saturate) var(--tw-sepia) var(--tw-drop-shadow)}.backdrop-blur-sm{--tw-backdrop-blur:blur(4px)}.backdrop-blur-sm,.backdrop-filter{-webkit-backdrop-filter:var(--tw-backdrop-blur) var(--tw-backdrop-brightness) var(--tw-backdrop-contrast) var(--tw-backdrop-grayscale) var(--tw-backdrop-hue-rotate) var(--tw-backdrop-invert) var(--tw-backdrop-opacity) var(--tw-backdrop-saturate) var(--tw-backdrop-sepia);backdrop-filter:var(--tw-backdrop-blur) var(--tw-backdrop-brightness) var(--tw-backdrop-contrast) var(--tw-backdrop-grayscale) var(--tw-backdrop-hue-rotate) var(--tw-backdrop-invert) var(--tw-backdrop-opacity) var(--tw-backdrop-saturate) var(--tw-backdrop-sepia)}.transition{transition-property:color,background-color,border-color,text-decoration-color,fill,stroke,opacity,box-shadow,transform,filter,-webkit-backdrop-filter;transition-property:color,background-color,border-color,text-decoration-color,fill,stroke,opacity,box-shadow,transform,filter,backdrop-filter;transition-property:color,background-color,border-color,text-decoration-color,fill,stroke,opacity,box-shadow,transform,filter,backdrop-filter,-webkit-backdrop-filter;transition-timing-function:cubic-bezier(.4,0,.2,1);transition-duration:.15s}.transition-colors{transition-property:color,background-color,border-color,text-decoration-color,fill,stroke;transition-timing-function:cubic-bezier(.4,0,.2,1);transition-duration:.15s}.hover\:border-violet-500\/30:hover{border-color:rgba(139,92,246,.3)}.hover\:border-violet-500\/50:hover{border-color:rgba(139,92,246,.5)}.hover\:bg-slate-700\/70:hover{background-color:rgba(51,65,85,.7)}.hover\:bg-slate-800\/30:hover{background-color:rgba(30,41,59,.3)}.hover\:bg-violet-600\/20:hover{background-color:rgba(124,58,237,.2)}.hover\:text-violet-200:hover{--tw-text-opacity:1;color:rgb(221 214 254/var(--tw-text-opacity,1))}@media (min-width:640px){.sm\:bottom-6{bottom:1.5rem}.sm\:left-auto{left:auto}.sm\:right-4{right:1rem}.sm\:w-auto{width:auto}.sm\:translate-x-0{--tw-translate-x:0px;transform:translate(var(--tw-translate-x),var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y))}.sm\:items-end{align-items:flex-end}.sm\:px-5{padding-left:1.25rem;padding-right:1.25rem}}@media (min-width:768px){.md\:inline{display:inline}}</style>
<?php endif; ?>
</head>
<body class="antialiased">

<header id="appHeader" class="glass-strong border-b border-slate-700/40">
    <div class="max-w-7xl mx-auto px-3 sm:px-5 py-2.5" style="max-width:100%">
        <div class="header-row header-top">
            <div class="flex items-center gap-2 shrink-0">
                <div class="w-8 h-8 rounded-lg bg-gradient-to-br from-violet-500 to-purple-700 flex items-center justify-center shadow-[0_0_14px_-3px_rgba(139,92,246,0.5)]">
                    <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 5a2 2 0 012-2h10a2 2 0 012 2v16l-7-3.5L5 21V5z"/>
                    </svg>
                </div>
            </div>
            <div class="search-wrap" id="searchWrap">
                <svg class="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 pointer-events-none" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                </svg>
                <input type="search" id="searchInput" placeholder="Suchen… (#tag, URL einfügen = hinzufügen)" aria-label="Links durchsuchen"
                       class="field !py-2 !pl-8 !pr-2 !text-sm !rounded-lg" autocomplete="off">
                <button type="button" id="searchClear" class="search-clear" title="Suche leeren" aria-label="Suche leeren">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                </button>
            </div>
            <div class="header-actions">
                <button type="button" id="btnSelectMode" class="btn btn-icon" title="Mehrfachauswahl" aria-label="Mehrfachauswahl">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>
                    </svg>
                </button>
                <div class="relative">
                    <button type="button" id="btnView" class="btn btn-icon" title="Ansicht und Sortierung" aria-label="Ansicht und Sortierung" aria-haspopup="true">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h7v5H4V6zm9 0h7v5h-7V6zM4 15h16M4 19h16"/>
                        </svg>
                    </button>
                    <div id="viewMenu" class="tools-menu hidden glass rounded-xl shadow-2xl py-1">
                        <div class="menu-label">Darstellung</div>
                        <button type="button" class="menu-opt" data-view="cards">Karten</button>
                        <button type="button" class="menu-opt" data-view="list">Liste</button>
                        <button type="button" class="menu-opt" data-view="compact">Kompakt</button>
                        <div class="menu-sep"></div>
                        <div class="menu-label">Sortierung</div>
                        <button type="button" class="menu-opt" data-sort="title">A → Z</button>
                        <button type="button" class="menu-opt" data-sort="title-desc">Z → A</button>
                        <button type="button" class="menu-opt" data-sort="newest">Neueste zuerst</button>
                        <button type="button" class="menu-opt" data-sort="oldest">Älteste zuerst</button>
                        <button type="button" class="menu-opt" data-sort="clicks">Oft benutzt</button>
                        <button type="button" class="menu-opt" data-sort="opened">Zuletzt geöffnet</button>
                        <button type="button" class="menu-opt" data-sort="domain">Nach Domain</button>
                        <button type="button" class="menu-opt" data-sort="folder">Nach Ordner</button>
                        <button type="button" class="menu-opt" id="optFavTop">Favoriten immer oben</button>
                        <div class="menu-sep"></div>
                        <div class="menu-label">Gruppieren</div>
                        <button type="button" class="menu-opt" data-group="domain">Domains mit vielen Links</button>
                        <button type="button" class="menu-opt" data-group="folder">Nach Ordnern</button>
                        <button type="button" class="menu-opt" data-group="none">Gar nicht</button>
                    </div>
                </div>
                <div class="relative">
                    <button type="button" id="btnTools" class="btn btn-icon" title="Werkzeuge" aria-label="Werkzeuge" aria-haspopup="true">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"/>
                        </svg>
                    </button>
                    <div id="toolsMenu" class="tools-menu hidden glass rounded-xl shadow-2xl py-1">
                        <button type="button" id="btnImport" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg>
                            Importieren
                        </button>
                        <button type="button" data-export="json" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                            Export als JSON
                        </button>
                        <button type="button" data-export="html" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                            Export als HTML (Browser)
                        </button>
                        <div class="menu-sep"></div>
                        <button type="button" id="btnDedupe" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"/></svg>
                            Duplikate entfernen
                        </button>
                        <button type="button" id="btnCheckDead" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                            Tote Links prüfen
                        </button>
                        <button type="button" id="btnFolders" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>
                            Ordner verwalten
                        </button>
                        <button type="button" id="btnTrash" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                            Papierkorb <span class="badge" id="trashCount">0</span>
                        </button>
                        <button type="button" id="btnBackups" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                            Backups
                        </button>
                        <button type="button" id="btnBookmarklet" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 5a2 2 0 012-2h10a2 2 0 012 2v16l-7-3.5L5 21V5z"/></svg>
                            Schnell speichern / App
                        </button>
                        <button type="button" id="btnReload" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                            Neu laden
                        </button>
                        <div class="menu-sep"></div>
                        <button type="button" id="btnAccount" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                            Konto &amp; Sicherheit
                        </button>
                        <button type="button" id="btnLoginLog" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                            Anmeldeversuche
                        </button>
<?php if ($lvIsAdmin): ?>
                        <button type="button" id="btnUsers" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"/></svg>
                            Benutzer verwalten <span class="badge hot hidden" id="usersBadge">0</span>
                        </button>
<?php endif; ?>
                        <button type="button" id="btnLogout" class="menu-opt danger">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/></svg>
                            Abmelden
                        </button>
                        <div class="menu-sep"></div>
                        <div id="toolsStats" class="px-3 py-2 text-[11px] text-slate-500 leading-relaxed"></div>
                    </div>
                </div>
                <button type="button" id="btnAdd" class="btn btn-primary btn-add-desktop !px-3 !py-2">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"/>
                    </svg>
                    <span class="hidden md:inline">Hinzufügen</span>
                </button>
            </div>
        </div>
        <div class="mt-2.5 w-full min-w-0 overflow-hidden header-cats">
            <div id="categoryBar"></div>
            <div id="subCatBar"></div>
        </div>
    </div>
</header>
<div id="headerSpacer" aria-hidden="true"></div>

<main class="max-w-7xl mx-auto px-3 sm:px-5 pt-4 safe-bottom" style="max-width:100%">
    <section id="favoritesSection" class="mb-6 hidden">
        <div class="flex items-center gap-2 mb-3">
            <svg class="w-4 h-4 text-amber-400" fill="currentColor" viewBox="0 0 20 20">
                <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z"/>
            </svg>
            <h2 class="text-xs font-semibold text-amber-300/90 uppercase tracking-wider">Favoriten</h2>
            <span id="favCount" class="text-[10px] text-slate-500 bg-slate-800/70 px-1.5 py-0.5 rounded"></span>
        </div>
        <div id="favoritesGrid" class="bookmarks-grid"></div>
    </section>

    <section id="mainSection">
        <div class="flex items-center gap-2 mb-3" id="sectionHeader">
            <h2 class="text-xs font-semibold text-slate-400 uppercase tracking-wider" id="sectionTitle">Alle Links</h2>
            <span id="totalCount" class="text-[10px] text-slate-500 bg-slate-800/70 px-1.5 py-0.5 rounded"></span>
        </div>
        <div id="bookmarksGrid" class="bookmarks-grid"></div>
    </section>

    <div id="emptyState" class="hidden empty-state rounded-2xl border border-slate-700/35 py-12 px-4 text-center mt-2">
        <div class="w-12 h-12 mx-auto mb-3 rounded-xl bg-slate-800/70 flex items-center justify-center">
            <svg class="w-6 h-6 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M5 5a2 2 0 012-2h10a2 2 0 012 2v16l-7-3.5L5 21V5z"/>
            </svg>
        </div>
        <h3 class="text-base font-semibold text-slate-200 mb-1" id="emptyTitle">Noch keine Links</h3>
        <p class="text-slate-400 text-sm mb-4 max-w-xs mx-auto" id="emptyText">Füge deinen ersten Link hinzu oder importiere Lesezeichen.</p>
        <button type="button" id="btnAddEmpty" class="btn btn-primary">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"/>
            </svg>
            Ersten Link hinzufügen
        </button>
    </div>
</main>

<button type="button" id="fabAdd" class="fab" title="Link hinzufügen" aria-label="Link hinzufügen">
    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"/>
    </svg>
</button>

<!-- BULK BAR -->
<div class="bulk-bar" id="bulkBar">
    <div class="bulk-inner">
        <span id="bulkCount" class="text-xs font-semibold text-violet-300 px-1.5 shrink-0">0</span>
        <button type="button" id="bulkSelectAll" class="btn btn-secondary !py-2 !px-2.5 !text-xs">Alle</button>
        <button type="button" id="bulkMove" class="btn btn-secondary !py-2 !px-2.5 !text-xs">
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>
            Ordner
        </button>
        <button type="button" id="bulkFav" class="btn btn-secondary !py-2 !px-2.5 !text-xs">
            <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20"><path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z"/></svg>
            Favorit
        </button>
        <button type="button" id="bulkDelete" class="btn btn-danger !py-2 !px-2.5 !text-xs">
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
            Löschen
        </button>
        <button type="button" id="bulkCancel" class="btn btn-ghost !py-2 !px-2 ml-auto text-slate-400">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
        </button>
    </div>
</div>

<!-- ADD/EDIT MODAL -->
<div id="modalOverlay" class="fixed inset-0 z-[70] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[90vh] overflow-y-auto">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between sticky top-0 bg-[rgba(15,23,42,0.95)] z-10">
            <h3 id="modalTitle" class="text-base font-semibold text-white">Link hinzufügen</h3>
            <button type="button" id="modalClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </button>
        </div>
        <form id="bookmarkForm" class="p-4 space-y-3.5">
            <input type="hidden" id="formId">
            <div>
                <label class="block text-xs font-medium text-slate-400 mb-1">Titel <span class="text-rose-400">*</span></label>
                <input type="text" id="formTitle" class="field" placeholder="z. B. GitHub" required>
            </div>
            <div>
                <label class="block text-xs font-medium text-slate-400 mb-1">URL <span class="text-rose-400">*</span></label>
                <div class="flex gap-2">
                    <input type="text" inputmode="url" id="formUrl" class="field flex-1 min-w-0" placeholder="https://…" required
                           autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false">
                    <button type="button" id="formFetchTitle" class="btn btn-secondary !px-3 shrink-0" title="Titel und Beschreibung von der Seite holen" aria-label="Titel und Beschreibung von der Seite holen">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                    </button>
                </div>
                <p id="formFetchHint" class="text-[11px] text-slate-500 mt-1 hidden"></p>
            </div>
            <div>
                <label class="block text-xs font-medium text-slate-400 mb-1.5">Ordner</label>
                <div id="formCatChips" class="flex flex-wrap gap-1.5 mb-2 max-h-28 overflow-y-auto"></div>
                <div class="flex gap-2">
                    <select id="formCategorySelect" class="field flex-1">
                        <option value="">— Ordner wählen —</option>
                    </select>
                </div>
                <div class="flex gap-2 mt-2">
                    <input type="text" id="formCategoryNew" class="field flex-1" placeholder="Oder neuen Ordner anlegen…">
                    <button type="button" id="formCatCreate" class="btn btn-secondary !px-3 shrink-0" title="Neuen Ordner übernehmen">+</button>
                </div>
                <input type="hidden" id="formCategory" value="Allgemein">
                <p class="text-[11px] text-slate-500 mt-1.5">Gewählt: <span id="formCatLabel" class="text-violet-300 font-medium">Allgemein</span></p>
                <datalist id="categoryList"></datalist>
            </div>
            <div>
                <label class="block text-xs font-medium text-slate-400 mb-1">Beschreibung <span class="text-slate-600">(optional)</span></label>
                <textarea id="formDescription" rows="2" class="field resize-none" placeholder="Kurze Notiz…"></textarea>
            </div>
            <div>
                <label class="block text-xs font-medium text-slate-400 mb-1" for="formTags">Schlagwörter <span class="text-slate-600">(optional, mit Komma trennen)</span></label>
                <input type="text" id="formTags" class="field" placeholder="z. B. go, tutorial, lesen" autocomplete="off" autocapitalize="off" spellcheck="false">
                <div id="formTagChips" class="tag-suggest"></div>
            </div>
            <div class="flex items-center gap-2.5 pt-0.5">
                <button type="button" id="formFavoriteToggle" class="toggle" role="switch" aria-checked="false"></button>
                <span class="text-sm text-slate-300">Als Favorit</span>
            </div>
            <div class="flex gap-2 pt-1">
                <button type="button" id="modalCancel" class="btn btn-secondary flex-1">Abbrechen</button>
                <button type="submit" id="modalSubmit" class="btn btn-primary flex-1">Speichern</button>
            </div>
        </form>
    </div>
</div>

<!-- MOVE MODAL -->
<div id="moveOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-sm glass-strong rounded-2xl shadow-2xl overflow-hidden">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between">
            <h3 class="text-base font-semibold text-white">In Ordner verschieben</h3>
            <button type="button" id="moveClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </button>
        </div>
        <div class="p-4 space-y-3">
            <p class="text-sm text-slate-400" id="moveHint">Wähle einen Ordner oder lege einen neuen an.</p>
            <div id="moveCatList" class="space-y-1.5 max-h-48 overflow-y-auto"></div>
            <div class="pt-1 border-t border-slate-700/40">
                <label class="block text-xs font-medium text-slate-400 mb-1.5">Neuer Ordner</label>
                <div class="flex gap-2">
                    <input type="text" id="moveNewCat" class="field flex-1" placeholder="Name eingeben…">
                    <button type="button" id="moveCreateBtn" class="btn btn-primary !px-3 shrink-0">Anlegen</button>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- IMPORT MODAL -->
<div id="importOverlay" class="fixed inset-0 z-[70] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between">
            <h3 class="text-base font-semibold text-white">Lesezeichen importieren</h3>
            <button type="button" id="importClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </button>
        </div>
        <div class="p-4">
            <p class="text-sm text-slate-400 mb-3 leading-relaxed">
                HTML-Datei aus <strong class="text-slate-200">Firefox</strong> oder <strong class="text-slate-200">Chrome</strong> hochladen,
                oder ein <strong class="text-slate-200">JSON-Backup</strong> aus dem eigenen Export. Vorhandene Links bleiben, doppelte werden übersprungen.
            </p>
            <form id="importForm" enctype="multipart/form-data">
                <label class="flex flex-col items-center justify-center w-full h-28 border-2 border-dashed border-slate-600 rounded-xl cursor-pointer hover:border-violet-500/50 hover:bg-slate-800/30 transition-colors">
                    <svg class="w-6 h-6 mb-1.5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/>
                    </svg>
                    <p class="text-sm text-slate-400"><span class="font-medium text-violet-400">Datei wählen</span></p>
                    <p class="text-xs text-slate-500 mt-0.5">.html / .htm / .json</p>
                    <input type="file" id="importFile" name="bookmark_file" accept=".html,.htm,.json,text/html,application/json" class="hidden" required>
                </label>
                <p id="importFileName" class="mt-2.5 text-sm text-violet-300 text-center hidden font-medium"></p>
                <div id="importPreview" class="box mt-3 hidden"></div>
                <button type="submit" id="importSubmit" class="btn btn-primary w-full mt-3" disabled>Importieren</button>
            </form>
        </div>
    </div>
</div>

<!-- CONFIRM -->
<div id="confirmOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-sm glass-strong rounded-2xl shadow-2xl overflow-hidden">
        <div class="p-4">
            <div class="w-10 h-10 rounded-xl bg-rose-500/15 flex items-center justify-center mb-3">
                <svg class="w-5 h-5 text-rose-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                </svg>
            </div>
            <h3 class="text-base font-semibold text-white mb-1" id="confirmTitle">Löschen?</h3>
            <p class="text-sm text-slate-400 leading-relaxed" id="confirmText">Dieser Vorgang kann nicht rückgängig gemacht werden.</p>
            <div class="flex gap-2 mt-4">
                <button type="button" id="confirmCancel" class="btn btn-secondary flex-1">Abbrechen</button>
                <button type="button" id="confirmOk" class="btn btn-danger flex-1">Löschen</button>
            </div>
        </div>
    </div>
</div>

<!-- DEAD LINKS MODAL -->
<div id="deadOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between shrink-0">
            <h3 class="text-base font-semibold text-white">Link-Check</h3>
            <button type="button" id="deadClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </button>
        </div>
        <div class="p-4 overflow-y-auto flex-1">
            <p class="text-sm text-slate-400 mb-2" id="deadHint">Prüfung läuft…</p>
            <div class="h-1.5 rounded-full bg-slate-800 overflow-hidden mb-3">
                <div id="deadBar" class="h-full bg-violet-500" style="width:0%;transition:width .3s ease"></div>
            </div>
            <div id="deadList" class="space-y-3"></div>
        </div>
        <div class="px-4 py-3 border-t border-slate-700/45 flex gap-2 shrink-0">
            <button type="button" id="deadCancel" class="btn btn-secondary flex-1">Schließen</button>
            <button type="button" id="deadDeleteBtn" class="btn btn-danger flex-1" disabled>Auswahl löschen</button>
        </div>
    </div>
</div>

<!-- FOLDERS MODAL -->
<div id="foldersOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between shrink-0">
            <h3 class="text-base font-semibold text-white">Ordner verwalten</h3>
            <button type="button" id="foldersClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </button>
        </div>
        <div class="p-4 overflow-y-auto flex-1">
            <p class="text-sm text-slate-400 mb-3 leading-relaxed">Namen ändern und mit Enter oder dem Haken speichern. Beim Auflösen wandern die Links nach „Allgemein“, gelöscht wird nichts.</p>
            <div id="foldersList" class="space-y-1.5"></div>
        </div>
    </div>
</div>

<!-- BACKUPS MODAL -->
<div id="backupsOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between shrink-0">
            <h3 class="text-base font-semibold text-white">Backups</h3>
            <button type="button" id="backupsClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </button>
        </div>
        <div class="p-4 overflow-y-auto flex-1">
            <p class="text-sm text-slate-400 mb-3 leading-relaxed" id="backupsHint">LinkVault sichert automatisch: einen Stand pro Tag und einen vor jeder großen Aktion.</p>
            <div id="backupsList" class="space-y-1.5"></div>
            <div class="box mt-3">
                <h4>Komplett-Backup als Datei</h4>
                <p>Eine einzige Datei mit allen Links, verschlüsselt. Sie lässt sich nur mit deinem Passwort von heute öffnen. Am besten ab und zu herunterladen und woanders aufheben.</p>
                <button type="button" id="btnFullBackup" class="btn btn-primary w-full">Komplett-Backup herunterladen</button>
            </div>
            <div class="box mt-3">
                <h4>Backup-Datei einspielen</h4>
                <p>Eine früher heruntergeladene .lvbak-Datei zurückholen. Gefragt ist das Passwort, das beim Herunterladen galt.</p>
                <input type="file" id="backupFile" accept=".lvbak,application/octet-stream,application/json" class="field mb-2">
                <input type="password" id="backupPass" class="field mb-2" placeholder="Passwort des Backups" autocomplete="off">
                <select id="backupMode" class="field mb-2" aria-label="Art des Einspielens">
                    <option value="merge">Nur fehlende Links ergänzen</option>
                    <option value="replace">Alles ersetzen (jetziger Stand wird vorher gesichert)</option>
                </select>
                <button type="button" id="backupImportBtn" class="btn btn-secondary w-full">Einspielen</button>
            </div>
        </div>
    </div>
</div>

<!-- BOOKMARKLET MODAL -->
<div id="bookmarkletOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between">
            <h3 class="text-base font-semibold text-white">Schnell speichern</h3>
            <button type="button" id="bookmarkletClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </button>
        </div>
        <div class="p-4 space-y-3">
            <p class="text-sm text-slate-400 leading-relaxed">Zieh den Knopf in deine Lesezeichenleiste. Ein Klick darauf öffnet LinkVault, Adresse und Titel der aktuellen Seite sind dann schon eingetragen.</p>
            <div class="flex justify-center py-1">
                <a id="bookmarkletLink" href="#" class="btn btn-primary" draggable="true">+ LinkVault</a>
            </div>
            <div class="box">
                <h4>Als App aufs Handy</h4>
                <p id="installHint">iPhone: in Safari auf „Teilen“ tippen, dann „Zum Home-Bildschirm“. Android: im Browser-Menü „App installieren“ wählen, danach taucht LinkVault auch beim Teilen einer Seite in der Liste auf.</p>
                <button type="button" id="installBtn" class="btn btn-primary w-full hidden">Jetzt als App installieren</button>
            </div>
            <p class="text-xs text-slate-500 leading-relaxed">Ohne App: den Code kopieren und als Adresse eines Lesezeichens einfügen.</p>
            <button type="button" id="bookmarkletCopy" class="btn btn-secondary w-full">Code kopieren</button>
        </div>
    </div>
</div>

<!-- KONTO & SICHERHEIT -->
<div id="accountOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between shrink-0">
            <h3 class="text-base font-semibold text-white">Konto &amp; Sicherheit</h3>
            <button type="button" id="accountClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>
        </div>
        <form id="accountForm" class="p-4 overflow-y-auto flex-1 space-y-3">
            <div>
                <label class="lbl" for="accCurrent">Aktuelles Passwort <span class="text-rose-400">*</span></label>
                <input type="password" id="accCurrent" class="field" autocomplete="current-password">
                <p class="text-[11px] text-slate-500 mt-1">Nötig als Bestätigung für alles in diesem Fenster, außer „Automatisch abmelden“.</p>
            </div>

            <div class="box">
                <h4>Benutzername und Passwort ändern</h4>
                <label class="lbl" for="accUser">Neuer Benutzername</label>
                <input type="text" id="accUser" class="field mb-2" autocomplete="username" maxlength="64" placeholder="leer = unverändert">
                <label class="lbl" for="accNew">Neues Passwort (min. 12 Zeichen, Buchstaben + Zahlen)</label>
                <input type="password" id="accNew" class="field mb-2" autocomplete="new-password" placeholder="leer = nur Name ändern" minlength="12">
                <label class="lbl" for="accNew2">Neues Passwort wiederholen</label>
                <input type="password" id="accNew2" class="field mb-2" autocomplete="new-password">
                <button type="submit" class="btn btn-primary w-full">Zugangsdaten speichern</button>
                <p class="mt-2" style="margin-bottom:0">Nach einem Passwortwechsel werden alle anderen Geräte abgemeldet. Deine Links und Backups bleiben lesbar.</p>
            </div>

            <div class="box">
                <h4>Zwei-Faktor-Anmeldung (2FA)</h4>
                <p id="totpStatus">Lade…</p>
                <div class="row">
                    <button type="button" id="totpStart" class="btn btn-secondary hidden">Einrichten</button>
                    <button type="button" id="totpOff" class="btn btn-danger hidden">Abschalten</button>
                </div>
                <div id="totpSetup" class="hidden mt-3">
                    <p>1. Diesen Schlüssel in deine Authenticator-App eintragen (Aegis, 2FAS, Google Authenticator …). Am Handy reicht der Knopf darunter.</p>
                    <div class="mono-box" id="totpSecret"></div>
                    <div class="row mb-2">
                        <a id="totpLink" href="#" class="btn btn-secondary">In App öffnen</a>
                        <button type="button" id="totpCopy" class="btn btn-secondary">Schlüssel kopieren</button>
                    </div>
                    <p>2. Den 6-stelligen Code aus der App eingeben. Oben muss dein aktuelles Passwort stehen.</p>
                    <div class="row">
                        <input type="text" id="totpCode" class="field" style="flex:1 1 8rem" inputmode="numeric" maxlength="7" placeholder="123456" autocomplete="off">
                        <button type="button" id="totpEnable" class="btn btn-primary">Aktivieren</button>
                    </div>
                </div>
            </div>

            <div class="box">
                <h4>Wiederherstellungscode</h4>
                <p id="recStatus">Lade…</p>
                <div class="mono-box hidden" id="recCode"></div>
                <div class="row">
                    <button type="button" id="recCreate" class="btn btn-secondary">Neuen Code erzeugen</button>
                    <button type="button" id="recCopy" class="btn btn-secondary hidden">Kopieren</button>
                </div>
            </div>

            <div class="box">
                <h4>Automatisch abmelden</h4>
                <p>Nach so langer Pause musst du dich neu anmelden. Bis 8 Stunden endet die Anmeldung zusätzlich, wenn der Browser geschlossen wird.</p>
                <select id="accIdle" class="field" aria-label="Automatisch abmelden nach">
                    <option value="15">nach 15 Minuten</option>
                    <option value="60">nach 1 Stunde</option>
                    <option value="480">nach 8 Stunden</option>
                    <option value="1440">nach 1 Tag (angemeldet bleiben)</option>
                    <option value="10080">nach 7 Tagen (angemeldet bleiben)</option>
                    <option value="43200">nach 30 Tagen (angemeldet bleiben)</option>
                </select>
            </div>
        </form>
    </div>
</div>

<!-- PAPIERKORB -->
<div id="trashOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between shrink-0">
            <h3 class="text-base font-semibold text-white">Papierkorb</h3>
            <button type="button" id="trashClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>
        </div>
        <div class="p-4 overflow-y-auto flex-1">
            <p class="text-sm text-slate-400 mb-3 leading-relaxed">Gelöschte Links bleiben <?php echo (int)LV_TRASH_DAYS; ?> Tage hier liegen und verschwinden danach von selbst.</p>
            <div id="trashList" class="stack"></div>
        </div>
        <div class="px-4 py-3 border-t border-slate-700/45 flex gap-2 shrink-0">
            <button type="button" id="trashRestoreAll" class="btn btn-secondary flex-1">Alle zurückholen</button>
            <button type="button" id="trashEmpty" class="btn btn-danger flex-1">Papierkorb leeren</button>
        </div>
    </div>
</div>

<!-- ANMELDEVERSUCHE -->
<div id="logOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between shrink-0">
            <h3 class="text-base font-semibold text-white">Anmeldeversuche</h3>
            <button type="button" id="logClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>
        </div>
        <div class="p-4 overflow-y-auto flex-1">
            <div id="logSummary" class="box mb-3"></div>
            <div id="logList" class="stack"></div>
        </div>
        <div class="px-4 py-3 border-t border-slate-700/45 flex gap-2 shrink-0">
            <button type="button" id="logClear" class="btn btn-secondary flex-1">Liste leeren</button>
            <button type="button" id="logDone" class="btn btn-primary flex-1">Schließen</button>
        </div>
    </div>
</div>

<!-- BENUTZER VERWALTEN (nur Administrator) -->
<div id="usersOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between shrink-0">
            <h3 class="text-base font-semibold text-white">Benutzer verwalten</h3>
            <button type="button" id="usersClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>
        </div>
        <div class="p-4 overflow-y-auto flex-1">
            <div id="usersPendingBox" class="hidden mb-3">
                <h4 class="text-[11px] font-semibold uppercase tracking-wider text-amber-300 mb-2">Wartet auf deine Freigabe</h4>
                <div id="usersPending" class="stack"></div>
            </div>
            <h4 class="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">Benutzer</h4>
            <div id="usersList" class="stack"></div>
            <div class="box mt-3">
                <h4>Neue Zugangsanfragen</h4>
                <p>Ist das an, steht auf der Anmeldeseite „Zugang anfragen“. Rein kommt trotzdem nur, wen du hier freigibst.</p>
                <div class="row">
                    <button type="button" id="regToggle" class="toggle green" role="switch" aria-checked="false" aria-label="Neue Zugangsanfragen annehmen"></button>
                    <span class="text-sm text-slate-300" id="regToggleLabel">Lade…</span>
                </div>
            </div>
            <div class="box mt-3">
                <h4>Gut zu wissen</h4>
                <p style="margin-bottom:0">Jeder Benutzer hat einen eigenen Bereich mit eigenem Schlüssel. Du siehst hier nur die Namen, nie die Links der anderen, und die anderen sehen deine nicht. Ein vergessenes Passwort kannst du deshalb auch nicht zurücksetzen, dafür hat jeder seinen eigenen Wiederherstellungscode unter Konto &amp; Sicherheit.</p>
            </div>
        </div>
    </div>
</div>

<!-- ALLGEMEINES HINWEIS-FENSTER -->
<div id="dialogOverlay" class="fixed inset-0 z-[80] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-sm glass-strong rounded-2xl shadow-2xl overflow-hidden" role="dialog" aria-modal="true" aria-labelledby="dialogTitle">
        <div class="p-4">
            <h3 class="text-base font-semibold text-white mb-2" id="dialogTitle"></h3>
            <div class="text-sm text-slate-300 leading-relaxed" id="dialogBody"></div>
            <div class="flex gap-2 mt-4" id="dialogActions"></div>
        </div>
    </div>
</div>

<div id="toastContainer" class="fixed bottom-20 left-1/2 -translate-x-1/2 sm:bottom-6 sm:left-auto sm:right-4 sm:translate-x-0 z-[80] flex flex-col gap-2 pointer-events-none items-center sm:items-end px-3 w-full sm:w-auto max-w-sm"></div>

<form id="exportForm" method="POST" class="hidden">
    <input type="hidden" name="action" id="exportAction">
    <input type="hidden" name="csrf" id="exportCsrf" value="<?php echo htmlspecialchars($lvCsrfPage, ENT_QUOTES, 'UTF-8'); ?>">
</form>


<script nonce="<?php echo htmlspecialchars($LV_NONCE, ENT_QUOTES, 'UTF-8'); ?>">
(() => {
    'use strict';
    let bookmarks = <?php echo json_encode($initialBookmarks, $lvJsonFlags) ?: '[]'; ?>;
    const LV_CORRUPT = <?php echo $LV_CORRUPT ? 'true' : 'false'; ?>;
    let LV_CSRF = <?php echo json_encode($lvCsrfPage, $lvJsonFlags); ?>;
    const LV_NOTICE = <?php echo json_encode($lvNotice, $lvJsonFlags) ?: 'null'; ?>;
    const LV_VERSION = <?php echo json_encode(LV_VERSION); ?>;
    const LV_ADMIN = <?php echo $lvIsAdmin ? 'true' : 'false'; ?>;
    const LV_USER = <?php echo json_encode($lvUserName, $lvJsonFlags) ?: '""'; ?>;
    const LV_PENDING_NAMES = <?php echo json_encode($lvPendingNames, $lvJsonFlags) ?: '[]'; ?>;
    let pendingCount = <?php echo (int)$lvPending; ?>;
    const TRASH_DAYS = <?php echo (int)LV_TRASH_DAYS; ?>;

    // Einstellungen dieses Geräts (nur Ansicht, nichts Geheimes)
    const store = {
        get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : v; } catch (_) { return d; } },
        set(k, v) { try { localStorage.setItem(k, v); } catch (_) {} }
    };
    const oneOf = (v, list, d) => list.includes(v) ? v : d;
    let currentCategory = store.get('lv_cat', 'all');
    let searchQuery = '';
    let sortMode = oneOf(store.get('lv_sort', 'title'), ['title', 'title-desc', 'newest', 'oldest', 'clicks', 'opened', 'domain', 'folder'], 'title');
    let viewMode = oneOf(store.get('lv_view', 'cards'), ['cards', 'list', 'compact'], 'cards');
    let groupMode = oneOf(store.get('lv_group', 'domain'), ['domain', 'folder', 'none'], 'domain');
    let favTop = store.get('lv_favtop', '1') === '1';
    let editingId = null;
    let formFavorite = false;
    let selectMode = false;
    let selected = new Set();
    let lastSelected = null;
    let dragIds = null;
    let lastSync = Date.now();
    // Welche Gruppen ausgeklappt sind (bleibt nach render erhalten)
    let openDomains = new Set();
    try {
        const saved = JSON.parse(store.get('lv_open_domains', '[]'));
        if (Array.isArray(saved)) saved.forEach(d => openDomains.add(d));
    } catch (_) {}
    function persistOpenDomains() { store.set('lv_open_domains', JSON.stringify([...openDomains])); }

    const $ = s => document.querySelector(s);
    const $$ = s => document.querySelectorAll(s);

    const searchInput = $('#searchInput');
    const categoryBar = $('#categoryBar');
    const subCatBar = $('#subCatBar');
    const mainEl = document.querySelector('main');
    const favoritesSection = $('#favoritesSection');
    const favoritesGrid = $('#favoritesGrid');
    const bookmarksGrid = $('#bookmarksGrid');
    const emptyState = $('#emptyState');
    const totalCount = $('#totalCount');
    const favCount = $('#favCount');
    const sectionTitle = $('#sectionTitle');
    const sectionHeader = $('#sectionHeader');
    const modalOverlay = $('#modalOverlay');
    const importOverlay = $('#importOverlay');
    const confirmOverlay = $('#confirmOverlay');
    const moveOverlay = $('#moveOverlay');
    const bookmarkForm = $('#bookmarkForm');
    const toastContainer = $('#toastContainer');
    const favToggle = $('#formFavoriteToggle');
    const btnSelectMode = $('#btnSelectMode');
    const bulkCount = $('#bulkCount');
    const canDrag = window.matchMedia && window.matchMedia('(hover: hover) and (pointer: fine)').matches;
    const SEP = ' > ';

    const live = () => bookmarks.filter(b => !b.deleted);
    const trashed = () => bookmarks.filter(b => b.deleted);
    const byId = id => bookmarks.find(b => b.id === id);
    const isWeb = u => /^https?:\/\//i.test(u || '');

    // Auch Anführungszeichen maskieren, die Werte landen teils in HTML-Attributen
    const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
    function escapeHtml(str) {
        if (str === null || str === undefined || str === '') return '';
        return String(str).replace(/[&<>"']/g, c => ESC_MAP[c]);
    }
    function getDomain(url) {
        try { return new URL(url).hostname.replace(/^www\./, ''); }
        catch (_) { return url || ''; }
    }
    // Ersatz-Icon mit dem Anfangsbuchstaben, falls eine Seite kein eigenes Icon hat
    function letterIcon(ch) {
        const c = escapeHtml((ch || '?').toUpperCase());
        return 'data:image/svg+xml,' + encodeURIComponent(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#334155"/>'
            + '<text x="12" y="16.5" text-anchor="middle" font-family="system-ui,sans-serif" font-size="12" font-weight="700" fill="#cbd5e1">' + c + '</text></svg>');
    }
    function faviconSrc(domain) {
        return /^[a-z0-9.-]+\.[a-z0-9-]+$/i.test(domain || '') ? `?action=favicon&domain=${encodeURIComponent(domain)}` : letterIcon((domain || '?')[0]);
    }
    document.addEventListener('error', e => {
        const t = e.target;
        if (t && t.tagName === 'IMG' && t.dataset && t.dataset.letter !== undefined && !t.dataset.fb) {
            t.dataset.fb = '1';
            t.src = letterIcon(t.dataset.letter);
        }
    }, true);

    const topOf = cat => (cat || 'Allgemein').split(SEP)[0];
    const prettyCat = cat => (cat || 'Allgemein').split(SEP).join(' › ');
    function inCat(bmCat, cur) {
        const a = (bmCat || '').toLowerCase(), b = (cur || '').toLowerCase();
        return a === b || a.startsWith(b + SEP);
    }
    function getCategories() {
        const s = new Set();
        live().forEach(b => { if (b.category) s.add(b.category); });
        return Array.from(s).sort((a, b) => a.localeCompare(b, 'de'));
    }
    function allTags() {
        const count = {};
        live().forEach(b => (b.tags || []).forEach(t => { count[t] = (count[t] || 0) + 1; }));
        return Object.keys(count).sort((a, b) => count[b] - count[a] || a.localeCompare(b, 'de'));
    }
    // Für Duplikat-Erkennung: www., Schrägstrich am Ende und Groß/Klein egal
    function normUrl(u) {
        try {
            const p = new URL(u);
            const host = p.hostname.replace(/^www\./, '');
            const path = (p.pathname || '/').replace(/\/$/, '') || '/';
            return (host + path + (p.search || '')).toLowerCase();
        } catch (_) { return (u || '').toLowerCase(); }
    }
    function trackVisit(bm) {
        bm.clicks = (bm.clicks || 0) + 1;
        bm.opened = Math.floor(Date.now() / 1000);
        api('visit', { id: bm.id });
    }
    function openLink(bm) {
        if (!isWeb(bm.url)) { showToast('Das ist kein Web-Link', 'error'); return; }
        window.open(bm.url, '_blank', 'noopener,noreferrer');
        trackVisit(bm);
    }
    function copyText(text, okMsg) {
        const fallback = () => {
            const ta = document.createElement('textarea');
            ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
            document.body.appendChild(ta); ta.select();
            let ok = false;
            try { ok = document.execCommand('copy'); } catch (_) {}
            ta.remove();
            showToast(ok ? okMsg : 'Kopieren fehlgeschlagen', ok ? 'success' : 'error');
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => showToast(okMsg)).catch(fallback);
        } else fallback();
    }
    const fmtDate = ts => new Date(ts * 1000).toLocaleString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });

    // Fuzzy helpers: normalize + token match across all fields
    function normalizeText(str) {
        return (str || '')
            .toLowerCase()
            .normalize('NFD')
            .replace(/[\u0300-\u036f]/g, '')
            .replace(/[^\p{L}\p{N}\s./:_-]+/gu, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    }
    function fuzzyMatch(haystack, query) {
        if (!query) return true;
        const hay = normalizeText(haystack);
        const tokens = normalizeText(query).split(' ').filter(Boolean);
        if (!tokens.length) return true;
        // Every token must appear somewhere (order independent)
        return tokens.every(t => hay.includes(t));
    }
    function bookmarkSearchText(bm) {
        return [bm.title, bm.url, bm.description, bm.category, getDomain(bm.url || ''), (bm.tags || []).join(' ')].filter(Boolean).join(' ');
    }
    // Suche: normale Wörter überall, „#wort“ nur in den Schlagwörtern
    function matchesSearch(bm) {
        if (!searchQuery) return true;
        const tokens = searchQuery.split(/\s+/).filter(Boolean);
        const tagTokens = tokens.filter(t => t.length > 1 && t[0] === '#').map(t => normalizeText(t.slice(1)));
        const rest = tokens.filter(t => !(t.length > 1 && t[0] === '#')).join(' ');
        if (tagTokens.length) {
            const tags = (bm.tags || []).map(normalizeText);
            if (!tagTokens.every(t => tags.some(x => x.startsWith(t)))) return false;
        }
        return fuzzyMatch(bookmarkSearchText(bm), rest);
    }
    // action = { label, fn } zeigt einen Knopf im Hinweis (z. B. „Rückgängig“)
    function showToast(msg, type = 'success', action = null) {
        const t = document.createElement('div');
        t.className = `toast pointer-events-auto flex items-center gap-2 px-3.5 py-2.5 rounded-xl shadow-xl text-sm font-medium max-w-full ${
            type === 'success' ? 'bg-emerald-600/95 text-white' : 'bg-rose-600/95 text-white'
        }`;
        t.innerHTML = `<span class="${type === 'success' ? 'truncate' : 'min-w-0'}">${escapeHtml(msg)}</span>`;
        const close = () => { t.style.opacity = '0'; t.style.transition = 'opacity 0.25s'; setTimeout(() => t.remove(), 250); };
        if (action) {
            const b = document.createElement('button');
            b.type = 'button';
            b.className = 'shrink-0 font-semibold underline underline-offset-2 px-1';
            b.textContent = action.label;
            b.addEventListener('click', () => { close(); action.fn(); });
            t.appendChild(b);
        }
        toastContainer.appendChild(t);
        setTimeout(close, action ? 8000 : (type === 'success' ? 2800 : 6000));
    }
    async function api(action, data = {}, files = null) {
        const fd = new FormData();
        fd.append('action', action);
        fd.append('csrf', LV_CSRF);
        for (const [k, v] of Object.entries(data)) {
            fd.append(k, (v !== null && typeof v === 'object') ? JSON.stringify(v) : v);
        }
        if (files) for (const [k, f] of Object.entries(files)) fd.append(k, f);
        let res, text;
        try {
            res = await fetch('', { method: 'POST', body: fd, credentials: 'same-origin', headers: { 'X-CSRF-Token': LV_CSRF } });
            text = await res.text();
        } catch (e) {
            return { success: false, message: 'Keine Verbindung zum Server.' };
        }
        try {
            const parsed = JSON.parse(text);
            if (parsed && parsed.auth_required) {
                showToast('Sitzung abgelaufen, bitte neu anmelden', 'error');
                setTimeout(() => { location.reload(); }, 1200);
            }
            if (parsed && parsed.csrf) setCsrf(parsed.csrf);
            if (parsed && typeof parsed.pending === 'number') syncPending(parsed.pending, true);
            if (parsed && parsed.success) lastSync = Date.now();
            return parsed;
        } catch (e) {
            if (res.status === 403) return { success: false, message: 'Sicherheits-Token abgelaufen. Bitte Seite neu laden.' };
            return { success: false, message: 'Server-Antwort ungültig (HTTP ' + res.status + '). Schreibrechte oder PHP-Fehler prüfen.' };
        }
    }
    function setCsrf(token) {
        LV_CSRF = token;
        const f = $('#exportCsrf');
        if (f) f.value = token;
    }
    // Antwort übernehmen: neue Liste zeigen, Meldung ausgeben. Ergebnis: hat geklappt?
    function applyRes(res, fallbackMsg, quiet) {
        if (res && res.success) {
            if (Array.isArray(res.bookmarks)) bookmarks = res.bookmarks;
            render();
            if (!quiet) showToast(res.message || fallbackMsg || 'Gespeichert');
            return true;
        }
        showToast((res && res.message) || 'Fehler', 'error');
        return false;
    }

    /* ---------- Fenster ---------- */
    let overlayReturnFocus = null;
    let dialogQueue = [];      // Hinweis-Fenster, die warten, bis das vorige zu ist
    let dialogDismiss = null;
    function showOverlay(el) {
        if (!overlayReturnFocus) overlayReturnFocus = document.activeElement;
        el.classList.remove('hidden'); el.classList.add('flex');
    }
    function hideOverlay(el) {
        el.classList.add('hidden'); el.classList.remove('flex');
        if (!anyOverlayOpen() && overlayReturnFocus) {
            try { overlayReturnFocus.focus({ preventScroll: true }); } catch (_) {}
            overlayReturnFocus = null;
        }
        if (dialogQueue.length) setTimeout(pumpDialogs, 200);
    }
    function pumpDialogs() {
        if (dialogQueue.length && !anyOverlayOpen()) showDialog(dialogQueue.shift());
    }
    function anyOverlayOpen() {
        return Array.from($$('[id$="Overlay"]')).some(o => !o.classList.contains('hidden'));
    }
    // Eigene Rückfrage statt des Browser-Fensters. Ergebnis: Promise<true|false>
    let confirmResolve = null;
    function confirmDialog({ title, text, ok = 'OK', danger = false }) {
        if (confirmResolve) confirmResolve(false);
        $('#confirmTitle').textContent = title;
        $('#confirmText').textContent = text || '';
        const okBtn = $('#confirmOk');
        okBtn.textContent = ok;
        okBtn.className = 'btn flex-1 ' + (danger ? 'btn-danger' : 'btn-primary');
        const icon = confirmOverlay.querySelector('.w-10');
        if (icon) icon.style.display = danger ? '' : 'none';
        showOverlay(confirmOverlay);
        setTimeout(() => okBtn.focus(), 60);
        return new Promise(resolve => { confirmResolve = resolve; });
    }
    function closeConfirm(result) {
        hideOverlay(confirmOverlay);
        if (confirmResolve) { const r = confirmResolve; confirmResolve = null; r(!!result); }
    }
    $('#confirmCancel').addEventListener('click', () => closeConfirm(false));
    $('#confirmOk').addEventListener('click', () => closeConfirm(true));
    confirmOverlay.addEventListener('click', e => { if (e.target === confirmOverlay) closeConfirm(false); });

    const dialogOverlay = $('#dialogOverlay');
    function showDialog(opts) {
        // Ist schon ein Hinweis offen, kommt dieser danach dran
        if (!dialogOverlay.classList.contains('hidden')) { dialogQueue.push(opts); return; }
        const { title, html, buttons, onDismiss } = opts;
        dialogDismiss = onDismiss || null;
        $('#dialogTitle').textContent = title;
        $('#dialogBody').innerHTML = html;
        const box = $('#dialogActions');
        box.innerHTML = '';
        (buttons || [{ label: 'OK', primary: true }]).forEach(b => {
            const el = document.createElement('button');
            el.type = 'button';
            el.className = 'btn flex-1 ' + (b.danger ? 'btn-danger' : (b.primary ? 'btn-primary' : 'btn-secondary'));
            if (b.primary) el.dataset.main = '1';
            el.textContent = b.label;
            el.addEventListener('click', () => closeDialog(b.fn));
            box.appendChild(el);
        });
        showOverlay(dialogOverlay);
    }
    function closeDialog(fn) {
        const dismiss = dialogDismiss;
        dialogDismiss = null;
        hideOverlay(dialogOverlay);
        if (fn) fn(); else if (dismiss) dismiss();
    }
    dialogOverlay.addEventListener('click', e => { if (e.target === dialogOverlay) closeDialog(); });
    // Rückfrage mit Passwort. Ergebnis: Promise<Passwort|null>
    function askPassword({ title, text, ok }) {
        return new Promise(resolve => {
            showDialog({
                title,
                html: `<p>${escapeHtml(text)}</p><input type="password" id="dialogPw" class="field" style="margin-top:0.75rem" placeholder="Dein Passwort" autocomplete="current-password">`,
                buttons: [
                    { label: 'Abbrechen', fn: () => resolve(null) },
                    { label: ok, primary: true, danger: true, fn: () => { const i = $('#dialogPw'); resolve(i ? i.value : null); } }
                ],
                onDismiss: () => resolve(null)
            });
            const input = $('#dialogPw');
            if (!input) return;
            setTimeout(() => input.focus(), 60);
            input.addEventListener('keydown', e => {
                if (e.key !== 'Enter') return;
                e.preventDefault();
                const b = $('#dialogActions [data-main]');
                if (b) b.click();
            });
        });
    }

    /* ---------- Auswahl ---------- */
    function updateBulkUI() {
        bulkCount.textContent = selected.size;
        document.body.classList.toggle('select-mode', selectMode);
        btnSelectMode.classList.toggle('active', selectMode);
    }
    function toggleSelectMode(force) {
        selectMode = typeof force === 'boolean' ? force : !selectMode;
        if (!selectMode) { selected.clear(); lastSelected = null; }
        updateBulkUI();
        render();
    }
    function paintSelection() {
        mainEl.querySelectorAll('.bookmark-card').forEach(card => {
            const on = selected.has(card.dataset.id);
            card.classList.toggle('selected', on);
            const check = card.querySelector('.sel-check');
            if (check) check.classList.toggle('checked', on);
        });
        bulkCount.textContent = selected.size;
    }
    // Mit gedrückter Umschalttaste wird der ganze Bereich bis zum letzten Klick gewählt
    function toggleSelect(id, range) {
        if (range && lastSelected && lastSelected !== id) {
            const order = [];
            mainEl.querySelectorAll('.bookmark-card').forEach(c => { if (!order.includes(c.dataset.id)) order.push(c.dataset.id); });
            const a = order.indexOf(lastSelected), b = order.indexOf(id);
            if (a >= 0 && b >= 0) {
                order.slice(Math.min(a, b), Math.max(a, b) + 1).forEach(x => selected.add(x));
                lastSelected = id;
                paintSelection();
                return;
            }
        }
        if (selected.has(id)) selected.delete(id); else selected.add(id);
        lastSelected = id;
        paintSelection();
    }

    /* ---------- Karten ---------- */
    const SVG = {
        check: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"/></svg>',
        open: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>',
        star: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z"/>',
        copy: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>',
        folder: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>',
        edit: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>',
        trash: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>',
        more: '<svg fill="currentColor" viewBox="0 0 24 24"><circle cx="5" cy="12" r="1.8"/><circle cx="12" cy="12" r="1.8"/><circle cx="19" cy="12" r="1.8"/></svg>',
        undo: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6"/></svg>',
        chevron: '<svg class="chevron" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>'
    };

    function createCard(bm) {
        const card = document.createElement('article');
        const isSelected = selected.has(bm.id);
        const domain = getDomain(bm.url);
        card.className = `bookmark-card glass rounded-xl ${bm.favorite ? 'favorite' : ''} ${isSelected ? 'selected' : ''}`;
        card.dataset.id = bm.id;
        if (canDrag) card.draggable = true;

        const checkHtml = selectMode
            ? `<button type="button" class="sel-check ${isSelected ? 'checked' : ''}" data-action="select" aria-label="Auswählen">${SVG.check}</button>` : '';
        const title = escapeHtml(bm.title);
        // Der Titel ist ein echter Link: Mittelklick, „In neuem Tab öffnen“ und langes Drücken funktionieren
        const titleHtml = (!selectMode && isWeb(bm.url))
            ? `<a class="bm-title" href="${escapeHtml(bm.url)}" target="_blank" rel="noopener noreferrer" title="${title}" draggable="false">${title}</a>`
            : `<span class="bm-title" title="${title}">${title}</span>`;
        const tags = (bm.tags || []).map(t => `<span class="bm-chip bm-tag" data-tag="${escapeHtml(t)}" title="Alle Links mit #${escapeHtml(t)}">#${escapeHtml(t)}</span>`).join('');
        const warn = bm.check
            ? `<span class="bm-chip bm-warn ${bm.check.s === 'dead' ? '' : 'unclear'}" title="Beim letzten Link-Check am ${escapeHtml(fmtDate(bm.check.t || 0))} nicht erreichbar">${bm.check.s === 'dead' ? 'tot?' : 'unklar'}</span>` : '';

        card.innerHTML = `
            <div class="bm-main">
                ${checkHtml}
                <img src="${escapeHtml(faviconSrc(domain))}" data-letter="${escapeHtml((domain || '?')[0])}" alt="" class="favicon" loading="lazy" draggable="false">
                <div class="bm-text">
                    ${titleHtml}
                    <span class="bm-domain">${escapeHtml(domain)}</span>
                    ${bm.description ? `<p class="bm-desc">${escapeHtml(bm.description)}</p>` : ''}
                    <div class="bm-meta"><span class="bm-chip">${escapeHtml(prettyCat(bm.category))}</span>${tags}${warn}</div>
                </div>
                <button type="button" class="bm-more" data-action="more" title="Aktionen" aria-label="Aktionen">${SVG.more}</button>
            </div>
            ${selectMode ? '' : `
            <div class="card-actions">
                <button type="button" class="card-btn card-btn-open" data-action="open" title="${escapeHtml(bm.url)}">${SVG.open}<span>Öffnen</span></button>
                <button type="button" class="card-btn card-btn-icon ${bm.favorite ? 'starred' : ''}" data-action="favorite" title="Favorit" aria-label="Favorit" aria-pressed="${bm.favorite ? 'true' : 'false'}">
                    <svg fill="${bm.favorite ? 'currentColor' : 'none'}" stroke="currentColor" viewBox="0 0 24 24">${SVG.star}</svg>
                </button>
                <button type="button" class="card-btn card-btn-icon" data-action="copy" title="URL kopieren" aria-label="URL kopieren">${SVG.copy}</button>
                <button type="button" class="card-btn card-btn-icon" data-action="folder" title="Ordner wählen" aria-label="Ordner wählen">${SVG.folder}</button>
                <button type="button" class="card-btn card-btn-icon" data-action="edit" title="Bearbeiten" aria-label="Bearbeiten">${SVG.edit}</button>
                <button type="button" class="card-btn card-btn-icon danger" data-action="delete" title="Löschen" aria-label="Löschen">${SVG.trash}</button>
            </div>`}
        `;
        return card;
    }

    // Ein Klick-Empfänger für alle Karten (schneller als einer pro Karte)
    mainEl.addEventListener('click', e => {
        const head = e.target.closest('.domain-group-header');
        if (head) {
            const wrap = head.parentElement;
            const key = wrap.dataset.key;
            wrap.classList.toggle('open');
            if (wrap.classList.contains('open')) openDomains.add(key); else openDomains.delete(key);
            head.setAttribute('aria-expanded', wrap.classList.contains('open') ? 'true' : 'false');
            persistOpenDomains();
            return;
        }
        const card = e.target.closest('.bookmark-card');
        if (!card) return;
        const bm = byId(card.dataset.id);
        if (!bm) return;
        if (selectMode) { e.preventDefault(); toggleSelect(bm.id, e.shiftKey); return; }
        const tag = e.target.closest('[data-tag]');
        if (tag) { e.preventDefault(); setSearch('#' + tag.dataset.tag); return; }
        if (e.target.closest('a.bm-title')) { trackVisit(bm); return; }
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        e.preventDefault();
        const action = btn.dataset.action;
        if (action === 'open') openLink(bm);
        else if (action === 'favorite') toggleFavorite(bm.id);
        else if (action === 'copy') copyText(bm.url, 'URL kopiert');
        else if (action === 'folder') openMoveModal([bm.id]);
        else if (action === 'edit') openEditModal(bm);
        else if (action === 'delete') deleteIds([bm.id]);
        else if (action === 'more') {
            mainEl.querySelectorAll('.bookmark-card.expanded').forEach(c => { if (c !== card) c.classList.remove('expanded'); });
            card.classList.toggle('expanded');
        }
    });
    mainEl.addEventListener('auxclick', e => {
        if (e.button !== 1 || selectMode) return;
        const link = e.target.closest('a.bm-title');
        const card = link && link.closest('.bookmark-card');
        const bm = card && byId(card.dataset.id);
        if (bm) trackVisit(bm);
    });

    // Ziehen und Ablegen: Karte auf einen Ordner in der Leiste ziehen (nur mit Maus)
    mainEl.addEventListener('dragstart', e => {
        const card = e.target.closest && e.target.closest('.bookmark-card');
        if (!card) return;
        const id = card.dataset.id;
        dragIds = (selectMode && selected.has(id)) ? Array.from(selected) : [id];
        const bm = byId(id);
        try {
            e.dataTransfer.effectAllowed = 'move';
            e.dataTransfer.setData('text/plain', bm ? bm.url : '');
        } catch (_) {}
        card.classList.add('dragging');
    });
    mainEl.addEventListener('dragend', () => {
        dragIds = null;
        $$('.dragging').forEach(c => c.classList.remove('dragging'));
        $$('.drop-ok').forEach(c => c.classList.remove('drop-ok'));
    });
    const dropTarget = e => {
        const btn = e.target.closest && e.target.closest('.cat-btn[data-cat]');
        return (btn && !['all', 'favorites', 'dead'].includes(btn.dataset.cat)) ? btn : null;
    };
    const headerEl = $('#appHeader');
    headerEl.addEventListener('dragover', e => {
        const btn = dragIds && dropTarget(e);
        if (!btn) return;
        e.preventDefault();
        btn.classList.add('drop-ok');
    });
    headerEl.addEventListener('dragleave', e => {
        const btn = e.target.closest && e.target.closest('.cat-btn');
        if (btn) btn.classList.remove('drop-ok');
    });
    headerEl.addEventListener('drop', e => {
        const btn = dragIds && dropTarget(e);
        if (!btn) return;
        e.preventDefault();
        const ids = dragIds;
        dragIds = null;
        doMove(btn.dataset.cat, ids);
    });

    /* ---------- Filtern, Sortieren, Gruppieren ---------- */
    function matchesFilter(bm) {
        if (bm.deleted) return false;
        if (currentCategory === 'favorites') { if (!bm.favorite) return false; }
        else if (currentCategory === 'dead') { if (!bm.check) return false; }
        else if (currentCategory !== 'all' && !inCat(bm.category, currentCategory)) return false;
        return matchesSearch(bm);
    }
    function sortList(list) {
        const arr = [...list];
        const byTitle = (a, b) => (a.title || '').localeCompare(b.title || '', 'de', { sensitivity: 'base', numeric: true });
        arr.sort((a, b) => {
            if (favTop && !searchQuery) {
                const af = a.favorite ? 1 : 0, bf = b.favorite ? 1 : 0;
                if (af !== bf) return bf - af;
            }
            let d = 0;
            if (sortMode === 'newest') d = (b.created || 0) - (a.created || 0);
            else if (sortMode === 'oldest') d = (a.created || 0) - (b.created || 0);
            else if (sortMode === 'clicks') d = (b.clicks || 0) - (a.clicks || 0);
            else if (sortMode === 'opened') d = (b.opened || 0) - (a.opened || 0);
            else if (sortMode === 'domain') d = getDomain(a.url || '').localeCompare(getDomain(b.url || ''), 'de');
            else if (sortMode === 'folder') d = (a.category || '').localeCompare(b.category || '', 'de');
            else if (sortMode === 'title-desc') return byTitle(b, a);
            return d || byTitle(a, b);
        });
        return arr;
    }
    // Liefert Gruppen (aufklappbar) und Einzel-Links
    function partition(list) {
        const singles = [];
        const groups = [];
        if (groupMode === 'none') return { singles: sortList(list), groups };
        const buckets = {};
        list.forEach(bm => {
            const k = groupMode === 'folder' ? (bm.category || 'Allgemein') : (getDomain(bm.url || '') || 'andere');
            (buckets[k] = buckets[k] || []).push(bm);
        });
        Object.entries(buckets).forEach(([name, items]) => {
            if (groupMode === 'folder') groups.push({ key: 'f:' + name, label: prettyCat(name), domain: null, items: sortList(items) });
            else if (items.length > 5) groups.push({ key: name, label: name, domain: name, items: sortList(items) });
            else singles.push(...items);
        });
        if (groupMode === 'folder') groups.sort((a, b) => a.label.localeCompare(b.label, 'de'));
        else groups.sort((a, b) => b.items.length - a.items.length);
        return { singles: sortList(singles), groups };
    }
    function createGroup(g) {
        const wrap = document.createElement('div');
        const isOpen = openDomains.has(g.key);
        wrap.className = 'domain-group' + (isOpen ? ' open' : '');
        wrap.dataset.key = g.key;
        const icon = g.domain
            ? `<img src="${escapeHtml(faviconSrc(g.domain))}" data-letter="${escapeHtml(g.domain[0] || '?')}" alt="" class="w-4 h-4 rounded" loading="lazy">`
            : `<span class="w-4 h-4 text-slate-400">${SVG.folder}</span>`;
        wrap.innerHTML = `
            <div class="domain-group-header" role="button" tabindex="0" aria-expanded="${isOpen ? 'true' : 'false'}">
                ${SVG.chevron}
                ${icon}
                <span class="font-semibold text-sm text-slate-100 truncate flex-1">${escapeHtml(g.label)}</span>
                <span class="text-[11px] text-slate-500 bg-slate-800/80 px-1.5 py-0.5 rounded shrink-0">${g.items.length} Links</span>
            </div>
            <div class="domain-group-body"></div>`;
        const body = wrap.querySelector('.domain-group-body');
        g.items.forEach(bm => body.appendChild(createCard(bm)));
        return wrap;
    }
    mainEl.addEventListener('keydown', e => {
        if ((e.key === 'Enter' || e.key === ' ') && e.target.classList && e.target.classList.contains('domain-group-header')) {
            e.preventDefault();
            e.target.click();
        }
    });

    function updateStats() {
        const l = live();
        const favs = l.filter(b => b.favorite).length;
        $('#toolsStats').textContent = `${l.length} Links · ${getCategories().length} Ordner · ${favs} Favoriten · v${LV_VERSION}`
            + (LV_USER ? ` · angemeldet als ${LV_USER}${LV_ADMIN ? ' (Administrator)' : ''}` : '');
        $('#trashCount').textContent = trashed().length;
    }
    function markMenus() {
        $$('#viewMenu [data-view]').forEach(b => b.classList.toggle('on', b.dataset.view === viewMode));
        $$('#viewMenu [data-sort]').forEach(b => b.classList.toggle('on', b.dataset.sort === sortMode));
        $$('#viewMenu [data-group]').forEach(b => b.classList.toggle('on', b.dataset.group === groupMode));
        $('#optFavTop').classList.toggle('on', favTop);
        document.body.classList.toggle('view-list', viewMode === 'list');
        document.body.classList.toggle('view-compact', viewMode === 'compact');
    }

    function render() {
        // Scroll-Position merken, damit die Ansicht nach Löschen/Hinzufügen nicht springt
        const scrollY = window.scrollY || window.pageYOffset || 0;
        const all = live();
        const cats = getCategories();
        const deadTotal = all.filter(b => b.check).length;
        // Gemerkter Ordner existiert nicht mehr (umbenannt, geleert)? Dann zurück auf „Alle“
        const special = ['all', 'favorites', 'dead'].includes(currentCategory);
        if ((currentCategory === 'dead' && !deadTotal) || (!special && !all.some(b => inCat(b.category, currentCategory)))) {
            currentCategory = 'all';
            store.set('lv_cat', 'all');
        }
        const isSpecial = ['all', 'favorites', 'dead'].includes(currentCategory);
        const activeTop = isSpecial ? null : topOf(currentCategory);
        const filtered = bookmarks.filter(matchesFilter);
        const favTotal = all.filter(b => b.favorite).length;
        const countIn = c => all.filter(b => inCat(b.category, c)).length;

        // Ordnerleiste: oberste Ebene, Unterordner in der zweiten Zeile
        const tops = [];
        cats.forEach(c => { const t = topOf(c); if (!tops.some(x => x.toLowerCase() === t.toLowerCase())) tops.push(t); });
        const chip = (cat, label, count, active, extra = '') =>
            `<button type="button" class="cat-btn ${extra} ${active ? 'active' : ''}" data-cat="${escapeHtml(cat)}" aria-pressed="${active ? 'true' : 'false'}">${label} <span class="count">${count}</span></button>`;
        categoryBar.innerHTML =
            chip('all', 'Alle', all.length, currentCategory === 'all')
            + chip('favorites', '⭐ Favoriten', favTotal, currentCategory === 'favorites')
            + (deadTotal ? chip('dead', 'Tote Links', deadTotal, currentCategory === 'dead', 'warn') : '')
            + tops.map(t => chip(t, escapeHtml(t), countIn(t), !!activeTop && activeTop.toLowerCase() === t.toLowerCase())).join('');
        const subs = activeTop ? cats.filter(c => c.toLowerCase().startsWith(activeTop.toLowerCase() + SEP)) : [];
        subCatBar.innerHTML = subs.map(c =>
            chip(c, escapeHtml(prettyCat(c.slice(activeTop.length + SEP.length))), countIn(c), currentCategory.toLowerCase() === c.toLowerCase())).join('');

        $('#categoryList').innerHTML = cats.map(c => `<option value="${escapeHtml(c)}">`).join('');
        fillCategoryPicker(cats);
        updateStats();
        markMenus();

        const { singles, groups } = partition(filtered);
        const groupedIds = new Set();
        groups.forEach(g => g.items.forEach(b => groupedIds.add(b.id)));
        const frontPage = currentCategory === 'all' && !searchQuery;

        // Favoriten-Bereich oben: nur auf der Startansicht und nur, wenn „Favoriten oben“ an ist
        const favSingles = (frontPage && favTop && groupMode !== 'folder') ? singles.filter(b => b.favorite) : [];
        favoritesGrid.innerHTML = '';
        if (favSingles.length > 0) {
            favoritesSection.classList.remove('hidden');
            favCount.textContent = favSingles.length;
            const frag = document.createDocumentFragment();
            favSingles.forEach(bm => frag.appendChild(createCard(bm)));
            favoritesGrid.appendChild(frag);
        } else {
            favoritesSection.classList.add('hidden');
        }

        bookmarksGrid.innerHTML = '';
        const frag = document.createDocumentFragment();
        groups.forEach(g => frag.appendChild(createGroup(g)));
        const rest = favSingles.length ? singles.filter(b => !b.favorite) : singles;
        rest.forEach(bm => frag.appendChild(createCard(bm)));
        bookmarksGrid.appendChild(frag);

        totalCount.textContent = filtered.length;
        sectionTitle.textContent =
            currentCategory === 'all' ? (searchQuery ? 'Suchergebnisse' : (favSingles.length ? 'Weitere Links' : 'Alle Links')) :
            currentCategory === 'favorites' ? 'Favoriten' :
            currentCategory === 'dead' ? 'Beim letzten Check nicht erreichbar' : prettyCat(currentCategory);
        sectionHeader.classList.toggle('hidden', frontPage && rest.length === 0 && groups.length === 0 && favSingles.length > 0);

        if (filtered.length === 0) {
            emptyState.classList.remove('hidden');
            const none = all.length === 0;
            $('#emptyTitle').textContent = none ? 'Noch keine Links' : 'Keine Treffer';
            $('#emptyText').textContent = none ? 'Füge deinen ersten Link hinzu oder importiere Lesezeichen.' : 'Anderen Suchbegriff oder Filter versuchen.';
            $('#btnAddEmpty').classList.toggle('hidden', !none);
        } else {
            emptyState.classList.add('hidden');
        }
        updateBulkUI();
        syncHeaderSpacer();
        requestAnimationFrame(() => { window.scrollTo(0, scrollY); });
    }

    function pickCategory(cat) {
        if (currentCategory === cat && cat !== 'all') {
            // Noch mal auf denselben Ordner: eine Ebene zurück
            const i = cat.lastIndexOf(SEP);
            currentCategory = (i > 0 && !['favorites', 'dead'].includes(cat)) ? cat.slice(0, i) : 'all';
        } else currentCategory = cat;
        store.set('lv_cat', currentCategory);
        window.scrollTo(0, 0);
        render();
    }
    [categoryBar, subCatBar].forEach(bar => bar.addEventListener('click', e => {
        const btn = e.target.closest('[data-cat]');
        if (btn) pickCategory(btn.dataset.cat);
    }));

    /* ---------- Aktionen an Links ---------- */
    async function toggleFavorite(id) {
        applyRes(await api('toggle_favorite', { id }), '', true);
    }
    async function restoreIds(ids) {
        applyRes(await api('trash_restore', { ids }), 'Wiederhergestellt');
    }
    // Löschen = Papierkorb, mit „Rückgängig“
    async function deleteIds(ids) {
        const res = await api(ids.length === 1 ? 'delete' : 'bulk_delete', ids.length === 1 ? { id: ids[0] } : { ids });
        if (!res.success) { showToast(res.message || 'Löschen fehlgeschlagen', 'error'); return false; }
        bookmarks = res.bookmarks;
        selected.clear();
        if (selectMode) toggleSelectMode(false); else render();
        showToast(res.message || 'Gelöscht', 'success', { label: 'Rückgängig', fn: () => restoreIds(ids) });
        return true;
    }
    async function askDeleteBulk() {
        if (selected.size === 0) return;
        const ids = Array.from(selected);
        if (ids.length > 1 && !await confirmDialog({
            title: `${ids.length} Links löschen?`,
            text: `Sie landen im Papierkorb und lassen sich ${TRASH_DAYS} Tage lang zurückholen.`, ok: 'Löschen', danger: true })) return;
        deleteIds(ids);
    }

    let moveIds = [];
    function openMoveModal(ids) {
        moveIds = ids || Array.from(selected);
        if (!moveIds.length) return;
        const cats = getCategories();
        $('#moveHint').textContent = `${moveIds.length} Link(s) verschieben. Unterordner legst du mit „Ordner > Unterordner“ an.`;
        const list = $('#moveCatList');
        list.innerHTML = cats.length ? cats.map(c => `
            <button type="button" class="w-full text-left px-3 py-2.5 rounded-lg text-sm text-slate-200 hover:bg-violet-600/20 hover:text-violet-200 border border-transparent hover:border-violet-500/30 transition-colors flex items-center gap-2" data-movecat="${escapeHtml(c)}">
                <span class="w-4 h-4 text-slate-500 shrink-0">${SVG.folder}</span>
                ${escapeHtml(prettyCat(c))}
            </button>`).join('') : '<p class="text-sm text-slate-500 px-1">Noch keine Ordner. Lege unten einen an.</p>';
        $('#moveNewCat').value = '';
        showOverlay(moveOverlay);
    }
    $('#moveCatList').addEventListener('click', e => {
        const btn = e.target.closest('[data-movecat]');
        if (btn) doMove(btn.dataset.movecat, moveIds);
    });
    async function doMove(category, ids) {
        if (!category || !ids || !ids.length) return;
        const res = await api('bulk_move', { ids, category });
        closeMove();
        if (res.success) {
            bookmarks = res.bookmarks;
            selected.clear();
            if (selectMode) toggleSelectMode(false); else render();
            showToast(res.message || 'Verschoben');
        } else showToast(res.message || 'Fehler', 'error');
    }
    function closeMove() { hideOverlay(moveOverlay); }

    function setFormCategory(name) {
        const cat = (name || '').trim() || 'Allgemein';
        $('#formCategory').value = cat;
        const label = $('#formCatLabel');
        if (label) label.textContent = cat;
        const sel = $('#formCategorySelect');
        if (sel) {
            // ensure option exists
            let found = false;
            for (const opt of sel.options) {
                if (opt.value === cat) { found = true; break; }
            }
            if (!found && cat) {
                const o = document.createElement('option');
                o.value = cat; o.textContent = cat;
                sel.appendChild(o);
            }
            sel.value = cat;
        }
        $$('#formCatChips .cat-chip').forEach(chip => {
            chip.classList.toggle('active', chip.dataset.cat === cat);
        });
        const neu = $('#formCategoryNew');
        if (neu) neu.value = '';
    }

    function fillCategoryPicker(cats) {
        const list = cats && cats.length ? cats : getCategories();
        const chips = $('#formCatChips');
        const sel = $('#formCategorySelect');
        if (!chips || !sel) return;
        const current = $('#formCategory')?.value || 'Allgemein';
        chips.innerHTML = list.map(c =>
            `<button type="button" class="cat-chip ${c === current ? 'active' : ''}" data-cat="${escapeHtml(c)}">${escapeHtml(c)}</button>`
        ).join('') + `<button type="button" class="cat-chip" data-cat="__new" style="border-style:dashed;color:#a78bfa">+ Neu</button>`;
        chips.querySelectorAll('.cat-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                if (chip.dataset.cat === '__new') {
                    $('#formCategoryNew')?.focus();
                    return;
                }
                setFormCategory(chip.dataset.cat);
            });
        });
        sel.innerHTML = `<option value="">— Ordner wählen —</option>` +
            list.map(c => `<option value="${escapeHtml(c)}" ${c === current ? 'selected' : ''}>${escapeHtml(c)}</option>`).join('');
    }

    function fillTagChips() {
        const box = $('#formTagChips');
        const tags = allTags().slice(0, 14);
        box.innerHTML = tags.map(t => `<button type="button" class="bm-chip bm-tag" data-addtag="${escapeHtml(t)}">#${escapeHtml(t)}</button>`).join('');
    }
    const parseTags = v => (v || '').split(/[,;\n]+/).map(t => t.trim().replace(/^#/, '')).filter(Boolean);
    $('#formTagChips').addEventListener('click', e => {
        const btn = e.target.closest('[data-addtag]');
        if (!btn) return;
        const input = $('#formTags');
        const cur = parseTags(input.value);
        const t = btn.dataset.addtag;
        const i = cur.findIndex(x => x.toLowerCase() === t.toLowerCase());
        if (i >= 0) cur.splice(i, 1); else cur.push(t);
        input.value = cur.join(', ');
    });

    function openAddModal() {
        editingId = null; formFavorite = false;
        $('#modalTitle').textContent = 'Link hinzufügen';
        resetFetch();
        bookmarkForm.reset(); $('#formId').value = '';
        favToggle.classList.remove('on'); favToggle.setAttribute('aria-checked', 'false');
        fillCategoryPicker();
        fillTagChips();
        setFormCategory(!['all', 'favorites', 'dead'].includes(currentCategory) ? currentCategory : 'Allgemein');
        showOverlay(modalOverlay);
        setTimeout(() => $('#formUrl').focus(), 80);
    }
    function openEditModal(bm) {
        editingId = bm.id; formFavorite = !!bm.favorite;
        $('#modalTitle').textContent = 'Link bearbeiten';
        resetFetch();
        $('#formId').value = bm.id;
        $('#formTitle').value = bm.title || '';
        $('#formUrl').value = bm.url || '';
        $('#formDescription').value = bm.description || '';
        $('#formTags').value = (bm.tags || []).join(', ');
        favToggle.classList.toggle('on', formFavorite);
        favToggle.setAttribute('aria-checked', formFavorite ? 'true' : 'false');
        fillCategoryPicker();
        fillTagChips();
        setFormCategory(bm.category || 'Allgemein');
        showOverlay(modalOverlay);
        setTimeout(() => $('#formTitle').focus(), 80);
    }
    function closeModal() { hideOverlay(modalOverlay); }

    /* ---------- Suche ---------- */
    function syncSearchClear() {
        $('#searchWrap').classList.toggle('has-query', !!searchInput.value.trim());
    }
    function setSearch(q) {
        searchInput.value = q;
        searchQuery = q.trim();
        syncSearchClear();
        window.scrollTo(0, 0);
        render();
    }
    let searchTimer = null;
    searchInput.addEventListener('input', e => {
        searchQuery = e.target.value.trim();
        syncSearchClear();
        // Kurz warten, damit bei vielen Links nicht jeder Tastendruck alles neu aufbaut
        clearTimeout(searchTimer);
        searchTimer = setTimeout(render, 120);
    });
    // URL in die Suche einfügen → Schnell-Hinzufügen anbieten
    searchInput.addEventListener('paste', () => {
        setTimeout(async () => {
            let url = searchInput.value.trim();
            if (!/^https?:\/\//i.test(url) && /^[\w.-]+\.[a-z]{2,}(\/\S*)?$/i.test(url)) url = 'https://' + url;
            let u;
            try { u = new URL(url); } catch (_) { return; }
            if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
            if (!await confirmDialog({ title: 'Als neuen Link speichern?', text: u.href, ok: 'Hinzufügen' })) return;
            setSearch('');
            startAdd(u.href, '');
        }, 0);
    });
    $('#searchClear').addEventListener('click', () => { setSearch(''); searchInput.focus(); });
    btnSelectMode.addEventListener('click', () => toggleSelectMode());

    // Neuen Link mit vorbelegter Adresse anlegen (Suche, Schnell-Speichern, Teilen)
    function startAdd(url, title) {
        const existing = live().find(b => normUrl(b.url) === normUrl(url));
        if (existing) {
            showToast('Den Link hast du schon gespeichert');
            openEditModal(existing);
            return;
        }
        openAddModal();
        $('#formUrl').value = url;
        if (title) $('#formTitle').value = title;
        else {
            $('#formTitle').value = getDomain(url);
            autoTitle = $('#formTitle').value;
            fetchTitle(false);
        }
        setTimeout(() => $('#formTitle').focus(), 100);
    }

    /* ---------- Menüs ---------- */
    const menus = [['#btnView', '#viewMenu'], ['#btnTools', '#toolsMenu']];
    function closeMenus() { menus.forEach(([, m]) => $(m).classList.add('hidden')); }
    menus.forEach(([b, m]) => {
        $(b).addEventListener('click', e => {
            e.stopPropagation();
            const wasOpen = !$(m).classList.contains('hidden');
            closeMenus();
            if (!wasOpen) $(m).classList.remove('hidden');
        });
    });
    document.addEventListener('click', e => {
        if (!e.target.closest('#viewMenu')) closeMenus();
        // Aufgeklappte Aktionsleiste schließen, wenn woanders hingeklickt wird
        if (!e.target.closest('.bookmark-card')) mainEl.querySelectorAll('.bookmark-card.expanded').forEach(c => c.classList.remove('expanded'));
    });
    $('#toolsMenu').addEventListener('click', e => { if (e.target.closest('button')) closeMenus(); });
    $('#viewMenu').addEventListener('click', e => {
        const b = e.target.closest('button');
        if (!b) return;
        if (b.dataset.view) { viewMode = b.dataset.view; store.set('lv_view', viewMode); }
        else if (b.dataset.sort) { sortMode = b.dataset.sort; store.set('lv_sort', sortMode); }
        else if (b.dataset.group) { groupMode = b.dataset.group; store.set('lv_group', groupMode); }
        else if (b.id === 'optFavTop') { favTop = !favTop; store.set('lv_favtop', favTop ? '1' : '0'); }
        render();
    });

    /* ---------- Sammel-Leiste ---------- */
    $('#bulkCancel').addEventListener('click', () => toggleSelectMode(false));
    $('#bulkSelectAll').addEventListener('click', () => {
        const filtered = bookmarks.filter(matchesFilter);
        if (selected.size >= filtered.length) selected.clear();
        else filtered.forEach(b => selected.add(b.id));
        paintSelection();
    });
    $('#bulkDelete').addEventListener('click', askDeleteBulk);
    $('#bulkMove').addEventListener('click', () => openMoveModal());
    $('#bulkFav').addEventListener('click', async () => {
        if (selected.size === 0) return;
        // Sind schon alle ausgewählten Favoriten, wird der Stern wieder entfernt
        const ids = Array.from(selected);
        const allFav = ids.every(id => bookmarks.some(b => b.id === id && b.favorite));
        const res = await api('bulk_favorite', { ids, favorite: allFav ? '0' : '1' });
        if (res.success) {
            bookmarks = res.bookmarks; selected.clear(); toggleSelectMode(false);
            showToast(res.message || 'Favoriten gesetzt');
        } else showToast(res.message || 'Fehler', 'error');
    });

    $('#moveClose').addEventListener('click', closeMove);
    moveOverlay.addEventListener('click', e => { if (e.target === moveOverlay) closeMove(); });
    const moveNew = () => {
        const name = $('#moveNewCat').value.trim();
        if (!name) { showToast('Name eingeben', 'error'); return; }
        doMove(name, moveIds);
    };
    $('#moveCreateBtn').addEventListener('click', moveNew);
    $('#moveNewCat').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); moveNew(); } });

    /* ---------- Formular Hinzufügen/Bearbeiten ---------- */
    $('#btnAdd').addEventListener('click', openAddModal);
    $('#fabAdd').addEventListener('click', openAddModal);
    $('#btnAddEmpty').addEventListener('click', openAddModal);
    $('#modalClose').addEventListener('click', closeModal);
    $('#modalCancel').addEventListener('click', closeModal);
    modalOverlay.addEventListener('click', e => { if (e.target === modalOverlay) closeModal(); });

    favToggle.addEventListener('click', () => {
        formFavorite = !formFavorite;
        favToggle.classList.toggle('on', formFavorite);
        favToggle.setAttribute('aria-checked', formFavorite ? 'true' : 'false');
    });
    $('#formCategorySelect').addEventListener('change', e => { if (e.target.value) setFormCategory(e.target.value); });
    $('#formCatCreate').addEventListener('click', () => {
        const name = $('#formCategoryNew').value.trim();
        if (!name) { showToast('Ordnername eingeben', 'error'); $('#formCategoryNew').focus(); return; }
        setFormCategory(name);
        fillCategoryPicker();
        setFormCategory(name);
        showToast('Ordner „' + name + '“ gewählt');
    });
    $('#formCategoryNew').addEventListener('keydown', e => {
        if (e.key === 'Enter') { e.preventDefault(); $('#formCatCreate').click(); }
    });
    $('#formCategoryNew').setAttribute('placeholder', 'Neuer Ordner, auch „Ordner > Unterordner“');

    let saving = false;
    bookmarkForm.addEventListener('submit', async e => {
        e.preventDefault();
        if (saving) return;
        const typedNew = $('#formCategoryNew').value.trim();
        if (typedNew) setFormCategory(typedNew);
        const data = {
            title: $('#formTitle').value.trim(), url: $('#formUrl').value.trim(),
            category: ($('#formCategory').value.trim() || typedNew || 'Allgemein'),
            description: $('#formDescription').value.trim(),
            tags: parseTags($('#formTags').value),
            favorite: formFavorite ? '1' : '0'
        };
        if (!editingId) {
            const key = normUrl(/^https?:\/\//i.test(data.url) ? data.url : 'https://' + data.url);
            const dup = live().find(b => normUrl(b.url) === key);
            if (dup && !await confirmDialog({
                title: 'Diesen Link gibt es schon',
                text: `„${dup.title}“ im Ordner ${prettyCat(dup.category)}. Trotzdem noch mal speichern?`, ok: 'Trotzdem speichern' })) return;
        }
        saving = true;
        $('#modalSubmit').disabled = true;
        const res = editingId ? await api('update', { ...data, id: editingId }) : await api('add', data);
        saving = false;
        $('#modalSubmit').disabled = false;
        if (res.success) { bookmarks = res.bookmarks; closeModal(); render(); showToast(res.message || 'Gespeichert'); }
        else showToast(res.message || 'Fehler', 'error');
    });

    /* ---------- Import mit Vorschau ---------- */
    let importReady = false;
    function resetImportStep() {
        importReady = false;
        $('#importPreview').classList.add('hidden');
        $('#importSubmit').textContent = 'Datei prüfen';
    }
    function closeImport() {
        hideOverlay(importOverlay);
        $('#importForm').reset(); $('#importFileName').classList.add('hidden'); $('#importSubmit').disabled = true;
        resetImportStep();
    }
    $('#btnImport').addEventListener('click', () => { resetImportStep(); showOverlay(importOverlay); });
    $('#importClose').addEventListener('click', closeImport);
    importOverlay.addEventListener('click', e => { if (e.target === importOverlay) closeImport(); });
    $('#importFile').addEventListener('change', e => {
        const f = e.target.files[0];
        resetImportStep();
        if (f) { $('#importFileName').textContent = f.name; $('#importFileName').classList.remove('hidden'); $('#importSubmit').disabled = false; }
    });
    $('#importForm').addEventListener('submit', async e => {
        e.preventDefault();
        const file = $('#importFile').files[0];
        if (!file) return;
        const btn = $('#importSubmit');
        btn.disabled = true;
        if (!importReady) {
            btn.textContent = 'Prüfe…';
            const res = await api('import', { dry: '1' }, { bookmark_file: file });
            btn.disabled = false;
            if (!res.success) { btn.textContent = 'Datei prüfen'; showToast(res.message || 'Datei nicht lesbar', 'error'); return; }
            const folders = Object.entries(res.folders || {});
            const box = $('#importPreview');
            box.innerHTML = `<h4>${res.imported} neue Links${res.skipped ? `, ${res.skipped} sind schon da` : ''}</h4>`
                + (folders.length ? `<p style="margin:0">In ${res.folder_count} Ordner(n): ${folders.map(([n, c]) => `${escapeHtml(prettyCat(n))} (${c})`).join(', ')}${res.folder_count > folders.length ? ' …' : ''}</p>` : '');
            box.classList.remove('hidden');
            if (res.imported > 0) { importReady = true; btn.textContent = `${res.imported} Links importieren`; }
            else { btn.textContent = 'Nichts Neues dabei'; btn.disabled = true; }
            return;
        }
        btn.textContent = 'Importiere…';
        const res = await api('import', {}, { bookmark_file: file });
        btn.disabled = false;
        if (res.success) { bookmarks = res.bookmarks; closeImport(); render(); showToast(res.message || 'Import erfolgreich'); }
        else { resetImportStep(); showToast(res.message || 'Import fehlgeschlagen', 'error'); }
    });

    /* ---------- Export ---------- */
    function download(action) {
        $('#exportAction').value = action;
        $('#exportForm').submit();
    }
    $$('[data-export]').forEach(btn => {
        btn.addEventListener('click', async () => {
            if (!await confirmDialog({
                title: 'Unverschlüsselt exportieren?',
                text: 'Diese Datei enthält deine Links im Klartext, zum Beispiel für den Umzug in einen Browser. Für eine Sicherung nimm lieber das Komplett-Backup unter Werkzeuge → Backups.',
                ok: 'Exportieren' })) return;
            download(btn.dataset.export === 'json' ? 'export_json' : 'export_html');
        });
    });

    /* ---------- Duplikate ---------- */
    $('#btnDedupe').addEventListener('click', async () => {
        if (!await confirmDialog({
            title: 'Duplikate entfernen?',
            text: 'Pro Adresse bleibt der beste Eintrag (Favorit und Beschreibung zuerst). Die anderen landen im Papierkorb.', ok: 'Entfernen' })) return;
        applyRes(await api('dedupe', {}), 'Fertig');
    });

    /* ---------- Link-Check: in kleinen Häppchen mit Fortschritt ---------- */
    let deadRun = 0;
    const deadOverlay = $('#deadOverlay');
    const deadDeleteBtn = $('#deadDeleteBtn');
    function syncDeadButton() {
        const n = deadOverlay.querySelectorAll('.dead-check:checked').length;
        deadDeleteBtn.disabled = n === 0;
        deadDeleteBtn.textContent = n ? `Auswahl löschen (${n})` : 'Auswahl löschen';
    }
    function addDeadRow(r) {
        const isDead = r.status === 'dead';
        const group = $(isDead ? '#deadGroupDead' : '#deadGroupUnclear');
        group.classList.remove('hidden');
        const safe = isWeb(r.url) ? r.url : '#';
        const row = document.createElement('label');
        row.className = 'flex items-start gap-2 px-2.5 py-2 rounded-lg bg-slate-800/50 border border-slate-700/40 cursor-pointer';
        row.innerHTML = `
            <input type="checkbox" class="dead-check mt-1 shrink-0" style="accent-color:#8b5cf6" value="${escapeHtml(r.id)}" ${isDead ? 'checked' : ''}>
            <span class="min-w-0 flex-1">
                <span class="block text-sm text-slate-200 truncate font-medium">${escapeHtml(r.title || r.url)}</span>
                <span class="block text-[11px] text-slate-500 truncate">${escapeHtml(r.url)}</span>
                <span class="block text-[11px] ${isDead ? 'text-rose-300' : 'text-amber-300'}">${escapeHtml(r.note || '')}${r.code ? ' · HTTP ' + r.code : ''}
                    · <a href="https://web.archive.org/web/2/${escapeHtml(safe)}" target="_blank" rel="noopener noreferrer" class="underline underline-offset-2">Archiv-Kopie</a></span>
            </span>
            <a href="${escapeHtml(safe)}" target="_blank" rel="noopener noreferrer" class="card-btn card-btn-icon shrink-0" title="Selbst ansehen" aria-label="Selbst ansehen">${SVG.open}</a>`;
        group.appendChild(row);
    }
    async function runDeadCheck() {
        const run = ++deadRun;
        const hint = $('#deadHint');
        const bar = $('#deadBar');
        // Ist ein Ordner oder eine Suche aktiv, wird nur das geprüft, was gerade zu sehen ist
        const scoped = currentCategory !== 'all' || !!searchQuery;
        const ids = (scoped ? bookmarks.filter(matchesFilter) : live()).map(b => b.id);
        const total = ids.length;
        const statusMap = {};
        let done = 0, ok = 0, dead = 0, unclear = 0, failed = 0;

        $('#deadList').innerHTML = `
            <div id="deadGroupDead" class="hidden space-y-1.5">
                <h4 class="text-[11px] font-semibold uppercase tracking-wider text-rose-300">Sicher weg</h4>
            </div>
            <div id="deadGroupUnclear" class="hidden space-y-1.5">
                <h4 class="text-[11px] font-semibold uppercase tracking-wider text-amber-300">Unklar, bitte selbst ansehen</h4>
            </div>`;
        bar.style.width = '0%';
        syncDeadButton();
        showOverlay(deadOverlay);
        if (!total) { hint.textContent = 'Keine Links zum Prüfen.'; return; }
        const where = scoped ? ' in der aktuellen Ansicht' : '';
        hint.textContent = `Prüfe ${total} Link(s)${where}…`;

        const chunks = [];
        for (let i = 0; i < ids.length; i += 10) chunks.push(ids.slice(i, i + 10));
        let next = 0;
        const worker = async () => {
            while (next < chunks.length && run === deadRun) {
                const chunk = chunks[next++];
                const res = await api('check_urls', { ids: chunk });
                if (run !== deadRun) return;
                if (res.success) {
                    (res.results || []).forEach(r => {
                        statusMap[r.id] = { s: r.status, c: r.code || 0 };
                        if (r.status === 'ok') { ok++; return; }
                        if (r.status === 'dead') dead++; else unclear++;
                        addDeadRow(r);
                    });
                } else failed += chunk.length;
                done += chunk.length;
                bar.style.width = Math.round(done / total * 100) + '%';
                hint.textContent = `${done} von ${total} geprüft${where}…`;
                syncDeadButton();
            }
        };
        await Promise.all([worker(), worker()]);
        // Ergebnis an den Links merken, auch wenn das Fenster schon zu ist
        if (Object.keys(statusMap).length) {
            const res = await api('set_status', { results: statusMap });
            if (res.success && Array.isArray(res.bookmarks)) { bookmarks = res.bookmarks; render(); }
        }
        if (run !== deadRun) return;
        bar.style.width = '100%';
        hint.textContent = `Fertig: ${ok} erreichbar, ${dead} sicher weg, ${unclear} unklar.`
            + (failed ? ` ${failed} konnten nicht geprüft werden.` : '')
            + (dead + unclear === 0 && !failed ? ' Alles sauber.' : ' Auffällige Links sind jetzt markiert und oben unter „Tote Links“ zu finden.');
    }
    $('#btnCheckDead').addEventListener('click', runDeadCheck);
    function closeDead() {
        deadRun++; // laufende Prüfung abbrechen
        hideOverlay(deadOverlay);
    }
    $('#deadClose').addEventListener('click', closeDead);
    $('#deadCancel').addEventListener('click', closeDead);
    deadOverlay.addEventListener('click', e => { if (e.target === deadOverlay) closeDead(); });
    $('#deadList').addEventListener('change', syncDeadButton);
    deadDeleteBtn.addEventListener('click', async () => {
        const ids = Array.from(deadOverlay.querySelectorAll('.dead-check:checked')).map(c => c.value);
        if (!ids.length) return;
        closeDead();
        deleteIds(ids);
    });

    /* ---------- Ordner verwalten ---------- */
    const foldersOverlay = $('#foldersOverlay');
    function renderFolders() {
        const cats = getCategories();
        const list = $('#foldersList');
        if (!cats.length) { list.innerHTML = '<p class="text-sm text-slate-500">Noch keine Ordner.</p>'; return; }
        const counts = {};
        live().forEach(b => { if (b.category) counts[b.category] = (counts[b.category] || 0) + 1; });
        list.innerHTML = cats.map(c => `
            <div class="flex items-center gap-1.5" data-folder="${escapeHtml(c)}">
                <input type="text" class="field flex-1 min-w-0 !py-2 !text-sm" value="${escapeHtml(c)}" aria-label="Ordnername" maxlength="150">
                <span class="text-[11px] text-slate-500 bg-slate-800/80 px-1.5 py-0.5 rounded shrink-0">${counts[c] || 0}</span>
                <button type="button" class="card-btn card-btn-icon" data-fact="rename" title="Namen speichern" aria-label="Namen speichern">${SVG.check}</button>
                <button type="button" class="card-btn card-btn-icon danger" data-fact="dissolve" title="Ordner auflösen" aria-label="Ordner auflösen" ${c === 'Allgemein' ? 'disabled style="opacity:.3;cursor:not-allowed"' : ''}>${SVG.trash}</button>
            </div>`).join('');
    }
    async function renameFolder(row) {
        const old = row.dataset.folder;
        const input = row.querySelector('input');
        const neu = input.value.trim();
        if (!neu) { input.value = old; return; }
        if (neu === old) return;
        if (getCategories().includes(neu) && !await confirmDialog({ title: 'Ordner zusammenlegen?', text: `„${neu}“ gibt es schon. Beide Ordner werden zusammengelegt.`, ok: 'Zusammenlegen' })) return;
        const res = await api('rename_category', { old, new: neu });
        if (res.success) {
            bookmarks = res.bookmarks;
            if (inCat(currentCategory, old)) { currentCategory = 'all'; store.set('lv_cat', 'all'); }
            render(); renderFolders();
            showToast(res.message || 'Umbenannt');
        } else showToast(res.message || 'Fehler', 'error');
    }
    $('#foldersList').addEventListener('click', async e => {
        const btn = e.target.closest('[data-fact]');
        const row = btn && btn.closest('[data-folder]');
        if (!row || btn.disabled) return;
        if (btn.dataset.fact === 'rename') { renameFolder(row); return; }
        const old = row.dataset.folder;
        if (!await confirmDialog({ title: 'Ordner auflösen?', text: `Die Links aus „${prettyCat(old)}“ bleiben erhalten und rutschen eine Ebene höher bzw. nach „Allgemein“.`, ok: 'Auflösen', danger: true })) return;
        const res = await api('delete_category', { category: old });
        if (res.success) { bookmarks = res.bookmarks; render(); renderFolders(); showToast(res.message || 'Ordner aufgelöst'); }
        else showToast(res.message || 'Fehler', 'error');
    });
    $('#foldersList').addEventListener('keydown', e => {
        if (e.key === 'Enter' && e.target.tagName === 'INPUT') { e.preventDefault(); renameFolder(e.target.closest('[data-folder]')); }
    });
    function closeFolders() { hideOverlay(foldersOverlay); }
    $('#btnFolders').addEventListener('click', () => { renderFolders(); showOverlay(foldersOverlay); });
    $('#foldersClose').addEventListener('click', closeFolders);
    foldersOverlay.addEventListener('click', e => { if (e.target === foldersOverlay) closeFolders(); });

    /* ---------- Papierkorb ---------- */
    const trashOverlay = $('#trashOverlay');
    function renderTrash() {
        const items = trashed().sort((a, b) => (b.deleted || 0) - (a.deleted || 0));
        const list = $('#trashList');
        $('#trashRestoreAll').disabled = $('#trashEmpty').disabled = !items.length;
        if (!items.length) { list.innerHTML = '<p class="text-sm text-slate-500">Der Papierkorb ist leer.</p>'; return; }
        list.innerHTML = items.map(b => `
            <div class="list-row" data-trash="${escapeHtml(b.id)}">
                <div class="grow">
                    <div class="t1">${escapeHtml(b.title)}</div>
                    <div class="t2">${escapeHtml(getDomain(b.url))} · gelöscht am ${escapeHtml(fmtDate(b.deleted))}</div>
                </div>
                <button type="button" class="card-btn card-btn-icon" data-tact="restore" title="Zurückholen" aria-label="Zurückholen">${SVG.undo}</button>
                <button type="button" class="card-btn card-btn-icon danger" data-tact="purge" title="Endgültig löschen" aria-label="Endgültig löschen">${SVG.trash}</button>
            </div>`).join('');
    }
    $('#trashList').addEventListener('click', async e => {
        const btn = e.target.closest('[data-tact]');
        const row = btn && btn.closest('[data-trash]');
        if (!row) return;
        const res = await api(btn.dataset.tact === 'restore' ? 'trash_restore' : 'trash_purge', { ids: [row.dataset.trash] });
        if (applyRes(res)) renderTrash();
    });
    $('#trashRestoreAll').addEventListener('click', async () => {
        if (applyRes(await api('trash_restore', { ids: trashed().map(b => b.id) }))) renderTrash();
    });
    $('#trashEmpty').addEventListener('click', async () => {
        const n = trashed().length;
        if (!await confirmDialog({ title: 'Papierkorb leeren?', text: `${n} Link(s) werden endgültig gelöscht.`, ok: 'Endgültig löschen', danger: true })) return;
        if (applyRes(await api('trash_purge', { ids: trashed().map(b => b.id) }))) renderTrash();
    });
    function closeTrash() { hideOverlay(trashOverlay); }
    $('#btnTrash').addEventListener('click', () => { renderTrash(); showOverlay(trashOverlay); });
    $('#trashClose').addEventListener('click', closeTrash);
    trashOverlay.addEventListener('click', e => { if (e.target === trashOverlay) closeTrash(); });

    /* ---------- Backups ---------- */
    const backupsOverlay = $('#backupsOverlay');
    async function loadBackups() {
        const list = $('#backupsList');
        list.innerHTML = '<p class="text-sm text-slate-500">Lade…</p>';
        const res = await api('backups_list');
        if (!res.success) { list.innerHTML = `<p class="text-sm text-rose-300">${escapeHtml(res.message || 'Fehler')}</p>`; return; }
        const items = res.backups || [];
        if (!items.length) {
            list.innerHTML = '<p class="text-sm text-slate-500">Noch keine Backups. Das erste entsteht bei der nächsten Änderung.</p>';
            return;
        }
        list.innerHTML = items.map(b => `
            <div class="flex items-center gap-2 px-2.5 py-2 rounded-lg bg-slate-800/50 border border-slate-700/40">
                <div class="min-w-0 flex-1">
                    <div class="text-sm text-slate-200 font-medium truncate">${escapeHtml(fmtDate(b.time))} Uhr</div>
                    <div class="text-[11px] text-slate-500 truncate">${escapeHtml(b.label)} · ${b.count} Einträge</div>
                </div>
                <button type="button" class="btn btn-secondary !py-2 !px-2.5 !text-xs shrink-0" data-backup="${escapeHtml(b.name)}" data-when="${escapeHtml(fmtDate(b.time))}">Zurückholen</button>
            </div>`).join('');
    }
    $('#backupsList').addEventListener('click', async e => {
        const btn = e.target.closest('[data-backup]');
        if (!btn) return;
        if (!await confirmDialog({ title: 'Stand zurückholen?', text: `Stand vom ${btn.dataset.when} Uhr. Der jetzige Stand wird vorher selbst als Backup gesichert.`, ok: 'Zurückholen' })) return;
        btn.disabled = true;
        const r = await api('backup_restore', { name: btn.dataset.backup });
        btn.disabled = false;
        if (applyRes(r, 'Wiederhergestellt')) closeBackups();
    });
    $('#btnFullBackup').addEventListener('click', () => download('export_full'));
    $('#backupImportBtn').addEventListener('click', async () => {
        const file = $('#backupFile').files[0];
        const pass = $('#backupPass').value;
        const mode = $('#backupMode').value;
        if (!file) { showToast('Erst eine .lvbak-Datei wählen', 'error'); return; }
        if (!pass) { showToast('Passwort des Backups eingeben', 'error'); return; }
        if (mode === 'replace' && !await confirmDialog({ title: 'Alles ersetzen?', text: 'Deine jetzigen Links werden durch das Backup ersetzt. Der jetzige Stand wird vorher gesichert.', ok: 'Ersetzen', danger: true })) return;
        const btn = $('#backupImportBtn');
        btn.disabled = true;
        const res = await api('backup_import', { backup_password: pass, mode }, { backup_file: file });
        btn.disabled = false;
        if (applyRes(res)) { $('#backupPass').value = ''; $('#backupFile').value = ''; closeBackups(); }
    });
    function closeBackups() { hideOverlay(backupsOverlay); }
    $('#btnBackups').addEventListener('click', () => { showOverlay(backupsOverlay); loadBackups(); });
    $('#backupsClose').addEventListener('click', closeBackups);
    backupsOverlay.addEventListener('click', e => { if (e.target === backupsOverlay) closeBackups(); });

    /* ---------- Schnell-Speichern-Knopf (Bookmarklet) ---------- */
    const bookmarkletOverlay = $('#bookmarkletOverlay');
    const bookmarkletCode = "javascript:(function(){window.open('" + (location.origin + location.pathname).replace(/'/g, '%27')
        + "?add='+encodeURIComponent(location.href)+'&title='+encodeURIComponent(document.title));})();";
    $('#bookmarkletLink').setAttribute('href', bookmarkletCode);
    $('#bookmarkletLink').addEventListener('click', e => {
        e.preventDefault();
        showToast('Nicht klicken, in die Lesezeichenleiste ziehen');
    });
    $('#bookmarkletCopy').addEventListener('click', () => copyText(bookmarkletCode, 'Code kopiert'));
    function closeBookmarklet() { hideOverlay(bookmarkletOverlay); }
    $('#btnBookmarklet').addEventListener('click', () => showOverlay(bookmarkletOverlay));
    $('#bookmarkletClose').addEventListener('click', closeBookmarklet);
    bookmarkletOverlay.addEventListener('click', e => { if (e.target === bookmarkletOverlay) closeBookmarklet(); });

    /* ---------- Konto & Sicherheit ---------- */
    const accountOverlay = $('#accountOverlay');
    let accInfo = null;
    function needPw() {
        const pw = $('#accCurrent').value;
        if (!pw) { showToast('Oben erst das aktuelle Passwort eingeben', 'error'); $('#accCurrent').focus(); }
        return pw;
    }
    async function loadAccount() {
        const res = await api('account_info');
        if (!res.success) { showToast(res.message || 'Fehler', 'error'); return; }
        accInfo = res;
        $('#accUser').placeholder = `leer = unverändert (${res.username})`;
        $('#accIdle').value = String(res.idle_minutes);
        $('#totpStatus').innerHTML = res.totp
            ? '<span class="ok-text">Aktiv.</span> Beim Anmelden wird zusätzlich ein Code aus deiner App verlangt.'
            : 'Nicht aktiv. Mit 2FA braucht ein Angreifer außer dem Passwort auch dein Handy.';
        $('#totpStart').classList.toggle('hidden', !!res.totp);
        $('#totpOff').classList.toggle('hidden', !res.totp);
        $('#totpSetup').classList.add('hidden');
        $('#recStatus').innerHTML = res.recovery
            ? '<span class="ok-text">Ein Code ist hinterlegt.</span> Damit kommst du wieder rein, wenn du das Passwort vergisst oder das Handy mit der 2FA-App weg ist.'
            : '<span class="warn-text">Noch kein Code.</span> Ohne ihn sind deine Links bei vergessenem Passwort für immer verloren, das ist der Preis der Verschlüsselung.';
    }
    function closeAccount() {
        hideOverlay(accountOverlay);
        $('#accountForm').reset();
        $('#recCode').classList.add('hidden'); $('#recCode').textContent = '';
        $('#recCopy').classList.add('hidden');
        $('#totpSetup').classList.add('hidden'); $('#totpSecret').textContent = '';
    }
    $('#btnAccount').addEventListener('click', () => { showOverlay(accountOverlay); loadAccount(); });
    $('#accountClose').addEventListener('click', closeAccount);
    accountOverlay.addEventListener('click', e => { if (e.target === accountOverlay) closeAccount(); });
    $('#accountForm').addEventListener('submit', async e => {
        e.preventDefault();
        const current_password = needPw();
        if (!current_password) return;
        const new_username = $('#accUser').value.trim();
        const new_password = $('#accNew').value;
        const new_password2 = $('#accNew2').value;
        if (new_password && new_password.length < 12) { showToast('Neues Passwort: mind. 12 Zeichen', 'error'); return; }
        if (new_password && new_password !== new_password2) { showToast('Neue Passwörter stimmen nicht überein', 'error'); return; }
        if (!new_username && !new_password) { showToast('Nichts zu ändern', 'error'); return; }
        const res = await api('change_password', { current_password, new_username, new_password, new_password2 });
        if (res.success) { closeAccount(); showToast(res.message || 'Gespeichert'); }
        else showToast(res.message || 'Fehler', 'error');
    });
    $('#totpStart').addEventListener('click', async () => {
        const res = await api('totp_begin');
        if (!res.success) { showToast(res.message || 'Fehler', 'error'); return; }
        $('#totpSecret').textContent = res.secret.replace(/(.{4})/g, '$1 ').trim();
        $('#totpSecret').dataset.raw = res.secret;
        $('#totpLink').setAttribute('href', res.uri);
        $('#totpCode').value = '';
        $('#totpSetup').classList.remove('hidden');
    });
    $('#totpCopy').addEventListener('click', () => copyText($('#totpSecret').dataset.raw || '', 'Schlüssel kopiert'));
    $('#totpEnable').addEventListener('click', async () => {
        const current_password = needPw();
        if (!current_password) return;
        const res = await api('totp_enable', { current_password, code: $('#totpCode').value });
        if (res.success) {
            showToast(res.message);
            await loadAccount();
            if (accInfo && !accInfo.recovery) showToast('Tipp: jetzt gleich einen Wiederherstellungscode erzeugen', 'success');
        } else showToast(res.message || 'Fehler', 'error');
    });
    $('#totpOff').addEventListener('click', async () => {
        const current_password = needPw();
        if (!current_password) return;
        if (!await confirmDialog({ title: '2FA abschalten?', text: 'Danach reicht wieder das Passwort allein.', ok: 'Abschalten', danger: true })) return;
        const res = await api('totp_disable', { current_password });
        if (res.success) { showToast(res.message); loadAccount(); } else showToast(res.message || 'Fehler', 'error');
    });
    $('#recCreate').addEventListener('click', async () => {
        const current_password = needPw();
        if (!current_password) return;
        if (accInfo && accInfo.recovery && !await confirmDialog({ title: 'Neuen Code erzeugen?', text: 'Der bisherige Wiederherstellungscode wird damit ungültig.', ok: 'Neuen Code erzeugen' })) return;
        const res = await api('recovery_create', { current_password });
        if (!res.success) { showToast(res.message || 'Fehler', 'error'); return; }
        $('#recCode').textContent = res.code;
        $('#recCode').classList.remove('hidden');
        $('#recCopy').classList.remove('hidden');
        $('#recStatus').innerHTML = '<span class="warn-text">Jetzt aufschreiben oder im Passwort-Manager ablegen.</span> Der Code wird nur dieses eine Mal angezeigt und liegt nirgends im Klartext.';
        if (accInfo) accInfo.recovery = true;
    });
    $('#recCopy').addEventListener('click', () => copyText($('#recCode').textContent, 'Code kopiert'));
    $('#accIdle').addEventListener('change', async e => {
        const res = await api('settings_save', { idle_minutes: e.target.value });
        showToast(res.message || (res.success ? 'Gespeichert' : 'Fehler'), res.success ? 'success' : 'error');
    });

    /* ---------- Anmeldeversuche ---------- */
    const logOverlay = $('#logOverlay');
    const LOG_KIND = {
        ok: ['Erfolgreich angemeldet', 'ok'],
        fail: ['Name oder Passwort falsch', ''],
        totp: ['Passwort richtig, 2FA-Code falsch', ''],
        recover: ['Wiederherstellungscode falsch', ''],
        locked: ['Versuch während einer Sperre', 'mid']
    };
    async function loadLog(clear) {
        const list = $('#logList');
        list.innerHTML = '<p class="text-sm text-slate-500">Lade…</p>';
        const res = await api('login_log', clear ? { clear: '1' } : {});
        if (!res.success) { list.innerHTML = `<p class="text-sm text-rose-300">${escapeHtml(res.message || 'Fehler')}</p>`; return; }
        const entries = res.entries || [];
        const now = Date.now() / 1000;
        const fails = entries.filter(r => r.k !== 'ok');
        const f24 = fails.filter(r => r.t > now - 86400).length;
        const f7 = fails.filter(r => r.t > now - 7 * 86400).length;
        const ips = new Set(fails.map(r => r.ip).filter(Boolean)).size;
        $('#logSummary').innerHTML = `<h4>${fails.length ? `<span class="${f24 ? 'bad-text' : 'warn-text'}">${fails.length} Fehlversuch(e) im Protokoll</span>` : '<span class="ok-text">Keine Fehlversuche</span>'}</h4>
            <p style="margin:0">Letzte 24 Stunden: ${f24} · letzte 7 Tage: ${f7}${ips ? ` · von ${ips} Adresse(n)` : ''}.
            ${res.details ? '' : '<br>Dein Server hat die PHP-Erweiterung „sodium“ nicht, deshalb werden nur Zeit und Art notiert.'}
            <br>Viele Versuche von fremden Adressen? Dann lohnt sich zusätzlich der Ordnerschutz deines Hosters oder 2FA.</p>`;
        list.innerHTML = entries.length ? entries.map(r => {
            const [label, cls] = LOG_KIND[r.k] || ['Unbekannt', 'mid'];
            return `<div class="list-row"><span class="dot ${cls}"></span><div class="grow">
                <div class="t1">${escapeHtml(label)}${r.u && r.k !== 'ok' ? ` als „${escapeHtml(r.u)}“` : ''}</div>
                <div class="t2">${escapeHtml(fmtDate(r.t))} Uhr${r.ip ? ' · ' + escapeHtml(r.ip) : ''}</div></div></div>`;
        }).join('') : '<p class="text-sm text-slate-500">Noch nichts protokolliert.</p>';
    }
    function closeLog() { hideOverlay(logOverlay); }
    $('#btnLoginLog').addEventListener('click', () => { showOverlay(logOverlay); loadLog(false); });
    $('#logClose').addEventListener('click', closeLog);
    $('#logDone').addEventListener('click', closeLog);
    $('#logClear').addEventListener('click', async () => {
        if (await confirmDialog({ title: 'Liste leeren?', text: 'Alle protokollierten Anmeldeversuche werden gelöscht.', ok: 'Leeren', danger: true })) loadLog(true);
    });
    logOverlay.addEventListener('click', e => { if (e.target === logOverlay) closeLog(); });

    /* ---------- Benutzer verwalten (nur Administrator) ---------- */
    const usersOverlay = $('#usersOverlay');
    // Zähler am Menü und Punkt am Werkzeug-Knopf: Es warten Zugangsanfragen
    function syncPending(n, announce) {
        const grew = n > pendingCount;
        pendingCount = n;
        const badge = $('#usersBadge');
        if (badge) { badge.textContent = n; badge.classList.toggle('hidden', n === 0); }
        $('#btnTools').classList.toggle('has-note', LV_ADMIN && n > 0);
        if (announce && grew && LV_ADMIN && usersOverlay.classList.contains('hidden')) {
            showToast('Eine neue Zugangsanfrage wartet auf dich', 'success', { label: 'Ansehen', fn: openUsers });
        }
    }
    function paintUsers(res) {
        const users = res.users || [];
        const waiting = users.filter(u => u.status === 'pending');
        const rest = users.filter(u => u.status !== 'pending');
        $('#usersPendingBox').classList.toggle('hidden', !waiting.length);
        $('#usersPending').innerHTML = waiting.map(u => `
            <div class="list-row" data-uid="${escapeHtml(u.uid)}" data-name="${escapeHtml(u.username)}">
                <span class="dot mid"></span>
                <div class="grow">
                    <div class="t1">${escapeHtml(u.username)}</div>
                    <div class="t2">angefragt am ${escapeHtml(fmtDate(u.created))} Uhr</div>
                    ${u.ip ? `<div class="t2">von ${escapeHtml(u.ip)}</div>` : ''}
                    ${u.note ? `<div class="user-note">„${escapeHtml(u.note)}“</div>` : ''}
                </div>
                <button type="button" class="btn btn-primary !py-2 !px-2.5 !text-xs shrink-0" data-uact="approve">Freigeben</button>
                <button type="button" class="card-btn card-btn-icon danger" data-uact="reject" title="Ablehnen" aria-label="Ablehnen">${SVG.trash}</button>
            </div>`).join('');
        const adminRow = `
            <div class="list-row">
                <span class="dot ok"></span>
                <div class="grow">
                    <div class="t1">${escapeHtml(res.admin || LV_USER)}</div>
                    <div class="t2">Administrator, das bist du</div>
                </div>
            </div>`;
        $('#usersList').innerHTML = adminRow + rest.map(u => {
            const blocked = u.status === 'blocked';
            const info = blocked ? 'gesperrt' : `dabei seit ${u.approved ? escapeHtml(fmtDate(u.approved)) + ' Uhr' : 'unbekannt'}${u.totp ? ' · 2FA aktiv' : ''}`;
            return `
            <div class="list-row" data-uid="${escapeHtml(u.uid)}" data-name="${escapeHtml(u.username)}">
                <span class="dot ${blocked ? '' : 'ok'}"></span>
                <div class="grow">
                    <div class="t1">${escapeHtml(u.username)}</div>
                    <div class="t2">${info}</div>
                </div>
                <button type="button" class="btn btn-secondary !py-2 !px-2.5 !text-xs shrink-0" data-uact="${blocked ? 'unblock' : 'block'}">${blocked ? 'Entsperren' : 'Sperren'}</button>
                <button type="button" class="card-btn card-btn-icon danger" data-uact="delete" title="Benutzer löschen" aria-label="Benutzer löschen">${SVG.trash}</button>
            </div>`;
        }).join('');
        paintRegToggle(!!res.allow_register);
    }
    function paintRegToggle(open) {
        const t = $('#regToggle');
        t.classList.toggle('on', open);
        t.setAttribute('aria-checked', open ? 'true' : 'false');
        $('#regToggleLabel').textContent = open ? 'Anfragen sind möglich' : 'Anfragen sind abgeschaltet';
    }
    async function loadUsers() {
        const res = await api('users_list');
        if (!res.success) {
            $('#usersList').innerHTML = `<p class="text-sm text-rose-300">${escapeHtml(res.message || 'Fehler')}</p>`;
            return;
        }
        paintUsers(res);
    }
    function openUsers() {
        $('#usersList').innerHTML = '<p class="text-sm text-slate-500">Lade…</p>';
        showOverlay(usersOverlay);
        loadUsers();
    }
    function closeUsers() { hideOverlay(usersOverlay); }
    if ($('#btnUsers')) $('#btnUsers').addEventListener('click', openUsers);
    $('#usersClose').addEventListener('click', closeUsers);
    usersOverlay.addEventListener('click', async e => {
        if (e.target === usersOverlay) { closeUsers(); return; }
        const btn = e.target.closest('[data-uact]');
        const row = btn && btn.closest('[data-uid]');
        if (!row) return;
        const uid = row.dataset.uid, name = row.dataset.name, act = btn.dataset.uact;
        const data = { uid };
        if (act === 'reject') {
            if (!await confirmDialog({ title: 'Anfrage ablehnen?', text: `Die Anfrage von „${name}“ wird gelöscht.`, ok: 'Ablehnen', danger: true })) return;
        } else if (act === 'block') {
            if (!await confirmDialog({ title: `„${name}“ sperren?`, text: 'Der Benutzer wird sofort überall abgemeldet und kommt nicht mehr rein. Seine Links bleiben erhalten, du kannst die Sperre jederzeit aufheben.', ok: 'Sperren', danger: true })) return;
        } else if (act === 'delete') {
            const pw = await askPassword({
                title: `„${name}“ löschen?`,
                text: 'Das Konto wird mit allen Links und Backups dieses Benutzers endgültig gelöscht. Das lässt sich nicht zurückholen. Zur Bestätigung dein eigenes Passwort:',
                ok: 'Endgültig löschen'
            });
            if (!pw) return;
            data.current_password = pw;
        }
        btn.disabled = true;
        const res = await api('user_' + act, data);
        btn.disabled = false;
        if (res.success) { showToast(res.message || 'Erledigt'); paintUsers(res); }
        else { showToast(res.message || 'Fehler', 'error'); loadUsers(); }
    });
    $('#regToggle').addEventListener('click', async () => {
        const open = !$('#regToggle').classList.contains('on');
        const res = await api('register_toggle', { open: open ? '1' : '0' });
        if (res.success) { paintRegToggle(!!res.allow_register); showToast(res.message || 'Gespeichert'); }
        else showToast(res.message || 'Fehler', 'error');
    });

    $('#btnReload').addEventListener('click', () => location.reload());

    /* ---------- App (PWA) ---------- */
    const isStandalone = (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) || window.navigator.standalone === true;
    if ('serviceWorker' in navigator && (location.protocol === 'https:' || ['localhost', '127.0.0.1'].includes(location.hostname))) {
        navigator.serviceWorker.register('./?action=sw', { scope: './' }).catch(() => {});
    }
    let installEvent = null;
    window.addEventListener('beforeinstallprompt', e => {
        e.preventDefault();
        installEvent = e;
        $('#installBtn').classList.remove('hidden');
    });
    $('#installBtn').addEventListener('click', async () => {
        if (!installEvent) return;
        installEvent.prompt();
        try { await installEvent.userChoice; } catch (_) {}
        installEvent = null;
        $('#installBtn').classList.add('hidden');
    });
    window.addEventListener('appinstalled', () => { $('#installBtn').classList.add('hidden'); showToast('LinkVault ist jetzt als App installiert'); });
    if (isStandalone) $('#installHint').textContent = 'LinkVault läuft gerade als App. Unter Android findest du es jetzt auch beim Teilen einer Seite in der Liste.';

    $('#btnLogout').addEventListener('click', async () => {
        const res = await api('logout', {});
        if (res.success) location.reload();
        else showToast(res.message || 'Abmelden fehlgeschlagen', 'error');
    });

    // Titel (und auf Knopfdruck Beschreibung) von der Seite holen
    let autoTitle = '';
    let fetchRun = 0;
    function resetFetch() {
        autoTitle = '';
        fetchRun++;
        const h = $('#formFetchHint');
        h.textContent = '';
        h.classList.add('hidden');
    }
    async function fetchTitle(manual) {
        const url = $('#formUrl').value.trim();
        const hint = $('#formFetchHint');
        if (!url) { if (manual) showToast('Erst eine URL eingeben', 'error'); return; }
        const titleEl = $('#formTitle');
        const cur = titleEl.value.trim();
        // Automatisch nur, wenn noch kein eigener Titel drinsteht
        if (!manual && cur !== '' && cur !== autoTitle) return;
        const run = ++fetchRun;
        hint.textContent = 'Hole Titel von der Seite…';
        hint.classList.remove('hidden');
        const res = await api('fetch_title', { url });
        if (run !== fetchRun) return;
        if (res.success && res.title) {
            const now = titleEl.value.trim();
            if (manual || now === '' || now === autoTitle) { titleEl.value = res.title; autoTitle = res.title; }
            if (manual && res.description && !$('#formDescription').value.trim()) $('#formDescription').value = res.description;
            hint.textContent = '';
            hint.classList.add('hidden');
        } else if (manual) {
            hint.textContent = res.message || 'Titel konnte nicht geholt werden.';
        } else {
            hint.textContent = '';
            hint.classList.add('hidden');
        }
    }
    $('#formFetchTitle').addEventListener('click', () => fetchTitle(true));
    $('#formUrl').addEventListener('change', () => { if (!editingId) fetchTitle(false); });

    /* ---------- Tastatur ---------- */
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') {
            if (!confirmOverlay.classList.contains('hidden')) { closeConfirm(false); return; }
            if (!dialogOverlay.classList.contains('hidden')) { closeDialog(); return; }
            if (anyOverlayOpen()) {
                closeModal(); closeImport(); closeMove(); closeDead(); closeFolders(); closeBackups();
                closeBookmarklet(); closeAccount(); closeTrash(); closeLog(); closeUsers();
                return;
            }
            closeMenus();
            if (selectMode) toggleSelectMode(false);
            else if (searchQuery) setSearch('');
            return;
        }
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); searchInput.focus(); searchInput.select(); return; }
        const t = e.target;
        const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
        if (typing || e.metaKey || e.ctrlKey || e.altKey || anyOverlayOpen()) return;
        if (e.key === '/') { e.preventDefault(); searchInput.focus(); searchInput.select(); }
        else if (e.key === 'n') { e.preventDefault(); openAddModal(); }
        else if (e.key === 'v') {
            viewMode = { cards: 'list', list: 'compact', compact: 'cards' }[viewMode];
            store.set('lv_view', viewMode);
            render();
            showToast('Ansicht: ' + { cards: 'Karten', list: 'Liste', compact: 'Kompakt' }[viewMode]);
        }
    });

    // Keep content below fixed header
    function syncHeaderSpacer() {
        const h = document.getElementById('appHeader');
        const s = document.getElementById('headerSpacer');
        if (h && s) s.style.height = h.offsetHeight + 'px';
    }
    window.syncHeaderSpacer = syncHeaderSpacer;
    window.addEventListener('resize', syncHeaderSpacer);
    requestAnimationFrame(syncHeaderSpacer);
    setTimeout(syncHeaderSpacer, 120);
    setTimeout(syncHeaderSpacer, 500);

    // Kategorieleiste: Mausrad horizontal, Drag-to-Scroll mit Nachlauf (Momentum)
    (function setupCategoryScroll() {
        const bar = categoryBar;
        if (!bar) return;
        bar.addEventListener('wheel', e => {
            if (Math.abs(e.deltaY) > Math.abs(e.deltaX) && bar.scrollWidth > bar.clientWidth) {
                e.preventDefault();
                bar.scrollLeft += e.deltaY;
            }
        }, { passive: false });

        let dragging = false, startX = 0, startScroll = 0, moved = false;
        let lastX = 0, lastT = 0, velocity = 0; // px pro ms
        let momentumId = 0;

        const stopMomentum = () => {
            if (momentumId) { cancelAnimationFrame(momentumId); momentumId = 0; }
        };

        const runMomentum = () => {
            stopMomentum();
            // Zu langsam → kein Nachlauf
            if (Math.abs(velocity) < 0.05) { velocity = 0; return; }
            const friction = 0.95; // je näher an 1, desto länger der Nachlauf
            const step = () => {
                velocity *= friction;
                if (Math.abs(velocity) < 0.04) {
                    velocity = 0;
                    momentumId = 0;
                    return;
                }
                const max = bar.scrollWidth - bar.clientWidth;
                bar.scrollLeft = Math.max(0, Math.min(max, bar.scrollLeft - velocity * 16));
                // Am Rand abfangen
                if (bar.scrollLeft <= 0 || bar.scrollLeft >= max - 0.5) {
                    velocity = 0;
                    momentumId = 0;
                    return;
                }
                momentumId = requestAnimationFrame(step);
            };
            momentumId = requestAnimationFrame(step);
        };

        const onDown = e => {
            if (e.button != null && e.button !== 0) return;
            stopMomentum();
            dragging = true; moved = false;
            velocity = 0;
            startX = e.pageX ?? (e.touches && e.touches[0].pageX) ?? 0;
            lastX = startX;
            lastT = performance.now();
            startScroll = bar.scrollLeft;
            bar.style.scrollBehavior = 'auto';
        };
        const onMove = e => {
            if (!dragging) return;
            const x = e.pageX ?? (e.touches && e.touches[0].pageX) ?? 0;
            const now = performance.now();
            const dx = x - startX;
            if (Math.abs(dx) > 4) moved = true;
            bar.scrollLeft = startScroll - dx;
            // Geschwindigkeit aus den letzten Bewegungen
            const dt = now - lastT;
            if (dt > 0) {
                const v = (x - lastX) / dt; // positiv = Finger nach rechts
                // glätten
                velocity = velocity * 0.6 + v * 0.4;
            }
            lastX = x;
            lastT = now;
            if (e.cancelable) e.preventDefault();
        };
        const onUp = () => {
            if (!dragging) return;
            dragging = false;
            bar.style.scrollBehavior = '';
            // Wenn die letzte Bewegung schon etwas her ist, Velocity dämpfen
            if (performance.now() - lastT > 80) velocity = 0;
            runMomentum();
        };
        bar.addEventListener('mousedown', onDown);
        window.addEventListener('mousemove', onMove);
        window.addEventListener('mouseup', onUp);
        bar.addEventListener('touchstart', onDown, { passive: true });
        bar.addEventListener('touchmove', onMove, { passive: false });
        bar.addEventListener('touchend', onUp);
        bar.addEventListener('touchcancel', onUp);
        // Klicks auf Buttons nicht auslösen, wenn gerade gescrollt wurde
        bar.addEventListener('click', e => {
            if (moved) { e.preventDefault(); e.stopPropagation(); moved = false; }
        }, true);
    })();

    // Zweites Gerät hat etwas geändert? Beim Zurückkommen auf die Seite still nachladen
    document.addEventListener('visibilitychange', async () => {
        if (document.visibilityState !== 'visible' || Date.now() - lastSync < 60000) return;
        if (anyOverlayOpen() || selectMode) return;
        const res = await api('list');
        if (res.success && Array.isArray(res.bookmarks) && JSON.stringify(res.bookmarks) !== JSON.stringify(bookmarks)) {
            bookmarks = res.bookmarks;
            render();
        }
    });

    render();
    syncHeaderSpacer();

    if (LV_CORRUPT) {
        showToast('bookmarks.json ist beschädigt und wird nicht überschrieben. Unter Werkzeuge → Backups kannst du einen Stand zurückholen.', 'error');
    }

    // Administrator: Wartet jemand auf Freigabe? Pro Sitzung nur einmal melden, der Punkt am Werkzeug-Knopf bleibt.
    syncPending(pendingCount, false);
    if (LV_ADMIN && pendingCount > 0) {
        const sig = pendingCount + '|' + LV_PENDING_NAMES.join('|');
        let seen = '';
        try { seen = sessionStorage.getItem('lv_pending_seen') || ''; } catch (_) {}
        if (seen !== sig) {
            try { sessionStorage.setItem('lv_pending_seen', sig); } catch (_) {}
            const one = pendingCount === 1;
            const names = LV_PENDING_NAMES.map(n => `„${escapeHtml(n)}“`).join(', ') + (pendingCount > LV_PENDING_NAMES.length ? ' und weitere' : '');
            showDialog({
                title: one ? 'Neue Zugangsanfrage' : `${pendingCount} neue Zugangsanfragen`,
                html: `<p>${names} ${one ? 'möchte' : 'möchten'} LinkVault mitbenutzen und ${one ? 'wartet' : 'warten'} auf deine Freigabe. Ohne dein Okay kommt niemand rein.</p>`,
                buttons: [{ label: 'Später' }, { label: 'Ansehen', primary: true, fn: openUsers }]
            });
        }
    }

    // Direkt nach der Anmeldung: Gab es fremde Anmeldeversuche?
    if (LV_NOTICE && typeof LV_NOTICE === 'object') {
        const n = LV_NOTICE;
        const last = n.last ? `Deine letzte Anmeldung war am ${escapeHtml(fmtDate(n.last))} Uhr${n.last_ip ? ' von ' + escapeHtml(n.last_ip) : ''}.` : '';
        if (n.fails > 0) {
            showDialog({
                title: `${n.fails} fehlgeschlagene${n.fails === 1 ? 'r' : ''} Anmeldeversuch${n.fails === 1 ? '' : 'e'}`,
                html: `<p>Seit deiner letzten Anmeldung hat ${n.fails === 1 ? 'jemand einmal' : `jemand ${n.fails} Mal`} versucht, sich hier anzumelden${n.ips > 0 ? `, von ${n.ips} Adresse${n.ips === 1 ? '' : 'n'}` : ''}. Hast du dich selbst vertippt, ist alles gut.</p>${last ? `<p class="mt-2 text-xs text-slate-400">${last}</p>` : ''}`,
                buttons: [{ label: 'Ansehen', fn: () => { showOverlay(logOverlay); loadLog(false); } }, { label: 'OK', primary: true }]
            });
        } else {
            showToast('Keine Fehlversuche seit deinem letzten Login');
        }
    }

    // Aufruf vom Schnell-Speichern-Knopf (?add=…&title=…) oder vom „Teilen“ am Handy (?url=…&text=…&title=…)
    (() => {
        const params = new URLSearchParams(location.search);
        let add = (params.get('add') || params.get('url') || '').trim();
        const text = (params.get('text') || '').trim();
        if (!add && text) { const m = text.match(/https?:\/\/\S+/i); if (m) add = m[0]; }
        if (!params.has('add') && !params.has('url') && !params.has('text') && !params.has('new')) return;
        history.replaceState(null, '', location.pathname);
        if (params.has('new') && !add) { openAddModal(); return; }
        if (!isWeb(add)) return;
        startAdd(add, (params.get('title') || '').trim());
    })();
})();
</script>

</body>
</html>
