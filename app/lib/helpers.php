<?php
/* LinkVault – Helfer */
defined('LV_VERSION') || exit;

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

/** Pfad dieser Seite ohne Abfrage. Immer genau ein Schrägstrich vorn, sonst läse der Browser „//name“ als fremde Adresse. */
function lvSelfPath(): string {
    $path = strtok((string)($_SERVER['REQUEST_URI'] ?? '/'), '?') ?: '/';
    $path = preg_replace('/[\x00-\x20\x7f\\\\]/', '', $path) ?? '';
    return '/' . ltrim($path, '/');
}

// Vom Schnell-Speichern-Knopf oder „Teilen“ mitgebrachte Adresse über die Anmeldung retten
function lvBackUrl(): string {
    $back = lvSelfPath();
    $keep = [];
    foreach (['add', 'title', 'url', 'text', 'new'] as $k) {
        if (isset($_GET[$k]) && is_string($_GET[$k]) && $_GET[$k] !== '') $keep[$k] = substr($_GET[$k], 0, 2000);
    }
    return $keep ? $back . '?' . http_build_query($keep) : $back;
}
