<?php
/* LinkVault – Zwei-Faktor und Wiederherstellungscode */
defined('LV_VERSION') || exit;

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
