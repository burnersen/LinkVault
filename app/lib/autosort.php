<?php
/* LinkVault – Automatisch sortieren */
defined('LV_VERSION') || exit;

/* =====================================================================
   Neu in 3.4: Automatisch sortieren
   ---------------------------------------------------------------------
   Ohne KI und ohne fremde Dienste. Die Vorschläge rechnet der Browser
   aus (Gruppen mit Domains und Stichwörtern, deine bisherige Sortierung).
   Hier liegt nur deine Fassung der Gruppen: pro Benutzer eine Datei
   autosort.json, verschlüsselt wie die Links selbst. Gibt es die Datei
   nicht, nimmt der Browser die eingebauten Gruppen.
   ===================================================================== */

function lvAutoSortFile(): string { return lvUserDir() . '/autosort.json'; }

/** Ein Eintrag einer Gruppe: Domain, Wort, „wort*“, „*wortteil*“ … klein geschrieben, ohne Steuerzeichen */
function lvAutoSortEntry($e): string {
    if (!is_string($e) && !is_numeric($e)) return '';
    $e = cleanText((string)$e, 120);
    $e = function_exists('mb_strtolower') ? mb_strtolower($e, 'UTF-8') : strtolower($e);
    return trim(preg_replace('/\s+/u', ' ', $e) ?? $e);
}

/**
 * Seit 3.4: eine gemeinsame Liste von Gruppen, die du komplett bearbeiten kannst.
 * Gruppe: id (nur bei eingebauten, zum Wiedererkennen), n Name, on an/aus, t Tags, f Ordner, e Einträge.
 */
function lvAutoSortCleanGroups($list): array {
    $out = [];
    if (!is_array($list)) return $out;
    foreach ($list as $g) {
        if (!is_array($g)) continue;
        $id = (string)($g['id'] ?? '');
        if (!preg_match('/^[a-z]{2,20}$/', $id)) $id = '';
        $name = cleanText($g['n'] ?? '', 60);
        if ($name === '') $name = 'Gruppe';
        $f = trim((string)($g['f'] ?? ''));
        $f = $f === '' ? '' : cleanCategory($f);
        if ($f === 'Allgemein') $f = '';
        $entries = [];
        $seen = [];
        foreach ((is_array($g['e'] ?? null) ? $g['e'] : []) as $e) {
            $e = lvAutoSortEntry($e);
            if ($e === '' || isset($seen[$e])) continue;
            $seen[$e] = true;
            $entries[] = $e;
            if (count($entries) >= 500) break;
        }
        $out[] = ['id' => $id, 'n' => $name, 'on' => !empty($g['on']), 't' => array_slice(cleanTags($g['t'] ?? []), 0, 5), 'f' => $f, 'e' => $entries];
        if (count($out) >= 150) break;
    }
    return $out;
}

/**
 * groups = null: noch nie gespeichert, der Browser nimmt den Standard.
 * legacy: Regeln aus der ersten Fassung von heute (eigene Regeln + Änderungen an den eingebauten Gruppen),
 * der Browser baut daraus die neue Liste. broken = Datei da, aber nicht lesbar.
 */
function lvAutoSortLoad(): array {
    $file = lvAutoSortFile();
    if (!is_file($file)) return ['groups' => null, 'legacy' => null, 'broken' => false];
    $json = lvDecodeStored((string)@file_get_contents($file));
    $data = $json !== null ? json_decode($json, true) : null;
    if (!is_array($data)) return ['groups' => null, 'legacy' => null, 'broken' => true];
    if (isset($data['groups']) && is_array($data['groups'])) {
        return ['groups' => lvAutoSortCleanGroups($data['groups']), 'legacy' => null, 'broken' => false];
    }
    // Altes Format: {rules: [{m, t, f}], cats: {id: {on, t, f}}}
    $rules = [];
    foreach ((is_array($data['rules'] ?? null) ? $data['rules'] : []) as $r) {
        if (!is_array($r)) continue;
        $m = lvAutoSortEntry($r['m'] ?? '');
        if ($m === '') continue;
        $f = trim((string)($r['f'] ?? ''));
        $rules[] = ['m' => $m, 't' => array_slice(cleanTags($r['t'] ?? []), 0, 5), 'f' => $f === '' ? '' : cleanCategory($f)];
    }
    $cats = [];
    foreach ((is_array($data['cats'] ?? null) ? $data['cats'] : []) as $id => $c) {
        if (!is_string($id) || !preg_match('/^[a-z]{2,20}$/', $id) || !is_array($c)) continue;
        $t = cleanTags([(string)($c['t'] ?? '')]);
        $f = trim((string)($c['f'] ?? ''));
        $cats[$id] = ['on' => !empty($c['on']), 't' => $t ? $t[0] : '', 'f' => $f === '' ? '' : cleanCategory($f)];
    }
    return ['groups' => null, 'legacy' => ['rules' => $rules, 'cats' => (object)$cats], 'broken' => false];
}

function lvAutoSortSave(array $groups): bool {
    $dir = lvUserDir();
    if (!is_dir($dir) || !is_writable($dir)) return false;
    $json = json_encode(['v' => 2, 'groups' => $groups], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false) return false;
    $payload = lvEncryptPayload($json);
    $file = lvAutoSortFile();
    $tmp = $file . '.tmp.' . bin2hex(random_bytes(4));
    if (@file_put_contents($tmp, $payload, LOCK_EX) === false) { @unlink($tmp); return false; }
    @chmod($tmp, 0600);
    if (!@rename($tmp, $file)) { @unlink($tmp); return false; }
    return true;
}
