<?php
/* LinkVault – Import und Datei-Upload */
defined('LV_VERSION') || exit;

/* ---------- Import ---------- */

/** Lesezeichen-Datei in UTF-8 umwandeln, falls sie in einem anderen Zeichensatz kommt (ältere Browser, Windows) */
function lvImportToUtf8(string $s): string {
    if (preg_match('//u', $s)) return $s; // schon gültiges UTF-8
    $cs = '';
    if (preg_match('~<meta[^>]+charset\s*=\s*["\']?\s*([a-z0-9_\-]+)~i', substr($s, 0, 4000), $m)) $cs = strtoupper($m[1]);
    if (function_exists('mb_convert_encoding')) {
        $known = array_map('strtoupper', mb_list_encodings());
        $from = ($cs !== '' && $cs !== 'UTF-8' && in_array($cs, $known, true)) ? $cs : 'Windows-1252';
        $out = @mb_convert_encoding($s, 'UTF-8', $from);
        if (is_string($out) && $out !== '') return $out;
    }
    if (function_exists('iconv')) {
        $out = @iconv($cs !== '' && $cs !== 'UTF-8' ? $cs : 'Windows-1252', 'UTF-8//IGNORE', $s);
        if (is_string($out) && $out !== '') return $out;
    }
    return $s; // ungültige Zeichen ersetzt später json_encode
}

/** Ordnerpfad aus den Namen der offenen Ordner, z. B. „Technik > Go“ (die Sammelordner der Browser fallen weg) */
function lvImportFolderPath(array $names): string {
    // Die Sammelordner der Browser selbst weglassen, wenn darunter echte Ordner liegen
    $roots = ['lesezeichen-symbolleiste', 'lesezeichenleiste', 'lesezeichen-menü', 'lesezeichenmenü', 'weitere lesezeichen',
              'bookmarks bar', 'bookmarks toolbar', 'bookmarks menu', 'other bookmarks', 'mobile lesezeichen', 'mobile bookmarks',
              'favoritenleiste', 'favorites bar'];
    $lower = fn($s) => function_exists('mb_strtolower') ? mb_strtolower($s, 'UTF-8') : strtolower($s);
    if (count($names) > 1 && in_array($lower($names[0]), $roots, true)) array_shift($names);
    return implode(' > ', array_slice($names, -4));
}

/**
 * Liest eine Lesezeichen-Datei der Browser (Netscape-Format: <DT><H3>Ordner</H3><DL> … <DT><A HREF>Titel</A><DD>Notiz … </DL>).
 * Bewusst ohne DOM: Die Dateien schließen ihre <DT> nie. Ein HTML-Parser schachtelt deshalb jeden Eintrag in den vorigen
 * und hört bei ein paar hundert Links in einem Ordner still auf (Tiefengrenze von libxml). Hier wird die Datei einfach
 * der Reihe nach gelesen und die offenen Ordner werden mitgezählt. Das klappt bei jeder Größe und jeder Tiefe.
 * Ergebnis: Liste von ['href', 'title', 'folders' => [...], 'add_date', 'tags', 'desc']
 */
function lvReadBookmarkHtml(string $html): array {
    $html = lvImportToUtf8($html);
    $len = strlen($html);
    $text = function (string $s): string {
        $s = preg_replace('~<[^>]*>~', ' ', $s) ?? $s;
        $s = html_entity_decode($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        return trim(preg_replace('/\s+/u', ' ', $s) ?? $s);
    };
    $attr = function (string $attrs, string $name): string {
        if (!preg_match('~(?:^|\s)' . $name . '\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))~i', $attrs, $m)) return '';
        return trim(html_entity_decode($m[count($m) - 1], ENT_QUOTES | ENT_HTML5, 'UTF-8'));
    };
    // Wo hört ein Text auf, wenn das schließende Tag fehlt? Spätestens beim nächsten Eintrag oder Ordner.
    $nextBlock = function (int $from) use ($html, $len): int {
        return preg_match('~<(?:/?dl|dt|h3)\b~i', $html, $n, PREG_OFFSET_CAPTURE, $from) ? (int)$n[0][1] : $len;
    };
    $out = [];
    $stack = [];     // Namen der offenen Listen, null = Liste ohne Überschrift (die äußerste)
    $pending = null; // zuletzt gelesene Ordner-Überschrift, sie gehört zur nächsten Liste
    $last = null;    // zuletzt gelesener Link, für seine Notiz (<DD>)
    $pos = 0;
    while ($pos < $len && preg_match('~<(/?)(dl|dt|dd|h3|a)\b([^>]*)>~i', $html, $m, PREG_OFFSET_CAPTURE, $pos)) {
        $pos = (int)$m[0][1] + strlen($m[0][0]);
        $close = $m[1][0] === '/';
        $tag = strtolower($m[2][0]);
        if ($tag === 'dl') {
            if ($close) { if ($stack) array_pop($stack); }
            else { $stack[] = $pending; $pending = null; }
            $last = null;
            continue;
        }
        if ($close) continue;
        if ($tag === 'dt') { $last = null; continue; }
        if ($tag === 'dd') {
            if ($last === null) continue; // Notiz zu einem Ordner: gibt es bei uns nicht
            $end = $nextBlock($pos);
            $out[$last]['desc'] = $text(substr($html, $pos, $end - $pos));
            $last = null;
            $pos = $end;
            continue;
        }
        // h3 oder a: Text bis zum schließenden Tag
        $end = stripos($html, '</' . $tag, $pos);
        $block = $nextBlock($pos);
        if ($end === false || $end > $block) $end = $block;
        $inner = $text(substr($html, $pos, $end - $pos));
        $pos = $end;
        if ($tag === 'h3') { $pending = $inner; $last = null; continue; }
        $pending = null; // Überschrift ohne eigene Liste (leerer Ordner)
        $folders = [];
        foreach ($stack as $f) if ($f !== null && $f !== '') $folders[] = $f;
        $out[] = ['href' => $attr($m[3][0], 'href'), 'title' => $inner, 'folders' => $folders,
                  'add_date' => (int)$attr($m[3][0], 'add_date'), 'tags' => $attr($m[3][0], 'tags'), 'desc' => ''];
        $last = count($out) - 1;
    }
    return $out;
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
        foreach (lvReadBookmarkHtml($html) as $e) {
            $href = $e['href'];
            $title = cleanText($e['title'], 300);
            if ($href === '' || $title === '' || !preg_match('~^https?://~i', $href) || preg_match('/[\s<>"\x00-\x1F]/', $href)) continue;
            if (isset($existingUrls[$href])) { $skipped++; continue; }
            $folder = lvImportFolderPath($e['folders']);
            $item = [
                'id' => generateId(), 'title' => $title, 'url' => $href,
                'category' => $folder !== '' ? cleanCategory($folder) : 'Importiert', 'description' => cleanText($e['desc'], 2000),
                'favorite' => false, 'created' => $e['add_date'] > 0 ? $e['add_date'] : time(),
            ];
            $tags = cleanTags($e['tags']);
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
