<?php
/* LinkVault – Lesezeichen laden/speichern, Backups */
defined('LV_VERSION') || exit;

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
    if (!is_dir($dir) && !@mkdir($dir, 0700, true)) return false;
    if ((@fileperms($dir) & 0077) !== 0) @chmod($dir, 0700); // ältere Installationen: 0755 nachziehen
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

// Stand direkt vor einer großen Aktion. Ergebnis: Dateiname des Backups oder null, wenn nichts gesichert wurde
function backupBefore(string $label): ?string {
    global $LV_CORRUPT;
    $prefix = $LV_CORRUPT ? 'defekt_' : 'vor_';
    $name = $prefix . date('Ymd_His') . '_' . preg_replace('/[^a-z_]/', '', $label) . '.json';
    if (!backupCopy($name)) return null;
    pruneBackups($prefix, BACKUP_KEEP_PRE);
    return $name;
}

function listBackups(): array {
    $labels = [
        'bulk_delete' => 'vor Mehrfach-Löschen', 'dedupe' => 'vor Duplikate entfernen',
        'import' => 'vor Import', 'restore' => 'vor Wiederherstellung',
        'delete_category' => 'vor Ordner löschen', 'autosort' => 'vor automatischem Sortieren',
        'tags' => 'vor Tag-Änderung',
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
