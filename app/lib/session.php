<?php
/* LinkVault – Session, Anmeldung, Einrichtung, Zugangsanfragen */
defined('LV_VERSION') || exit;

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
    $len = function_exists('mb_strlen') ? mb_strlen($password, 'UTF-8') : strlen($password);
    if ($len < 12) throw new Exception('Passwort: mindestens 12 Zeichen.');
    if (strlen($password) > 1024) throw new Exception('Passwort: höchstens 1024 Zeichen.');
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
        // Prüfen und Merken unter einer Sperre, sonst könnten zwei gleichzeitige Anfragen denselben Code nutzen
        $uid = (string)($cfg['_uid'] ?? '');
        $lk = @fopen(lvUserDir($uid) . '/bookmarks.lock', 'c');
        if ($lk) flock($lk, LOCK_EX);
        $now = lvLoadAuthConfig(true, $uid);
        $last = max((int)($cfg['totp_last'] ?? 0), (int)($now['totp_last'] ?? 0));
        $counter = $secret !== null ? lvTotpVerify($secret, $code, $last) : 0;
        if ($counter > 0) {
            $cfg['totp_last'] = $counter; // jeder Code gilt nur einmal
            lvSaveAuthConfigFull($cfg);
        }
        if ($lk) { flock($lk, LOCK_UN); fclose($lk); }
        if ($counter === 0) return 'totp';
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
