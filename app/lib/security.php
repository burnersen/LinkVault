<?php
/* LinkVault – CSRF, Security-Header, Login-Bremse, Anmelde-Protokoll */
defined('LV_VERSION') || exit;

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
    $until = lvThrottleUntil(lvThrottlePath());
    // Die Pause für alle gilt nicht für Anschlüsse, von denen sich kürzlich jemand richtig angemeldet hat.
    // Sonst könnte ein Angreifer mit vielen Adressen den Besitzer immer wieder kurz aussperren.
    if (!lvKnownClient()) $until = max($until, lvThrottleUntil(lvThrottleDir() . '/global.json'));
    $wait = $until - time();
    if ($wait <= 0) return null;
    if ($wait >= 60) {
        $m = (int)ceil($wait / 60);
        return "Zu viele Fehlversuche. Bitte in ca. {$m} Minute(n) erneut versuchen.";
    }
    return "Zu viele Fehlversuche. Bitte in {$wait} Sekunde(n) erneut versuchen.";
}

/** Anschlüsse mit einer erfolgreichen Anmeldung in den letzten 30 Tagen (gespeichert wird nur eine Prüfsumme). */
function lvKnownClientPath(): string {
    return lvThrottleDir() . '/ok_' . hash('sha256', lvClientIp()) . '.json';
}

function lvKnownClient(): bool {
    $t = (int)@filemtime(lvKnownClientPath());
    return $t > time() - 30 * 86400;
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
    if (lvRealIp() !== '0') @file_put_contents(lvKnownClientPath(), '1', LOCK_EX);
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
    foreach (glob(lvThrottleDir() . '/ok_*.json') ?: [] as $f) {
        if ((int)@filemtime($f) < $now - 30 * 86400) @unlink($f);
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
