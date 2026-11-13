<?php
/* LinkVault – Auth-Config und Benutzerverwaltung */
defined('LV_VERSION') || exit;

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
