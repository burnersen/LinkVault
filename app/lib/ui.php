<?php
/* LinkVault – Farbschemata und Sprache */
defined('LV_VERSION') || exit;

/* =====================================================================
   Neu in 3.2: Farbschemata (hell/dunkel, je 3 Farben) und Englisch
   ---------------------------------------------------------------------
   Dieser Block legt sich nur über die Oberfläche, an Daten und Logik
   ändert er nichts:
   - Design: Das ursprüngliche dunkle Violett ("d1") bleibt unangetastet.
     Alle anderen Schemata überschreiben nur Farben (html.lvt …).
   - Sprache: Deutsch bleibt die Grundlage im Code. Für Englisch werden
     die sichtbaren Texte im Browser anhand der Tabelle unten ersetzt.
   Die Wahl wird am Konto gespeichert (ui.json, seit 3.3), der Browser behält eine Kopie.
   ===================================================================== */

/** Für die wenigen Stellen ohne Browser-Skript (App-Manifest): Will der Browser lieber Englisch? */
function lvBrowserEnglish(): bool {
    $al = strtolower(trim((string)($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '')));
    return $al !== '' && strncmp($al, 'de', 2) !== 0;
}

/* ----- Neu in 3.3: Die Einstellungen liegen zusätzlich am Konto -----
   Jeder Benutzer hat in seinem eigenen Ordner eine ui.json (Design, Sprache, Ansicht).
   Bewusst eine eigene Datei: auth.json mit dem Schlüssel wird dafür nie angefasst.
   Der Browser behält eine Kopie, damit auch die Anmeldeseite passend aussieht. */
function lvUiOptions(): array {
    return [
    'mode' => ['auto', 'light', 'dark'], 'light' => ['1', '2', '3'], 'dark' => ['1', '2', '3'], 'lang' => ['', 'de', 'en'],
    'view' => ['cards', 'list', 'tiles'],
    'sort' => ['title', 'title-desc', 'newest', 'oldest', 'clicks', 'opened', 'domain', 'folder'],
    'group' => ['domain', 'folder', 'none'], 'favtop' => ['1', '0'], 'tagbar' => ['1', '0'],
    ];
}

/** Lässt nur bekannte Werte durch, alles andere fällt auf den Standard (erster Eintrag) zurück. */
function lvUiClean($in): array {
    $out = [];
    foreach (lvUiOptions() as $k => $allowed) {
        $v = (is_array($in) && isset($in[$k]) && is_scalar($in[$k])) ? (string)$in[$k] : '';
        if ($k === 'view' && $v === 'compact') $v = 'tiles'; // bis 3.4 hieß die dritte Ansicht „Kompakt“
        $out[$k] = in_array($v, $allowed, true) ? $v : $allowed[0];
    }
    return $out;
}

function lvUiFile(): string { return lvUserDir() . '/ui.json'; }

/** @return array|null null = für dieses Konto ist noch nichts gespeichert */
function lvUiLoad(): ?array {
    $raw = @file_get_contents(lvUiFile());
    $data = is_string($raw) ? json_decode($raw, true) : null;
    return is_array($data) ? lvUiClean($data) : null;
}

function lvUiSave(array $ui): bool {
    $dir = lvUserDir();
    if (!is_dir($dir)) return false;
    $json = json_encode($ui);
    if ($json === false) return false;
    $file = lvUiFile();
    $tmp = $file . '.tmp.' . bin2hex(random_bytes(4));
    if (@file_put_contents($tmp, $json, LOCK_EX) === false) { @unlink($tmp); return false; }
    if (!@rename($tmp, $file)) { @unlink($tmp); return false; }
    return true;
}

/** Gehört in den <head>, nach den eigenen Styles der Seite. */
function lvUiHead(): void {
    global $LV_NONCE;
    // Nur wer angemeldet ist, bekommt seine gespeicherten Einstellungen mit (auf der Anmeldeseite: null)
    $ui = (LV_AUTH_ENABLED && lvIsLoggedIn() && lvLoadAuthConfig() !== null) ? lvUiLoad() : null;
    echo '<script nonce="' . htmlspecialchars((string)$LV_NONCE, ENT_QUOTES, 'UTF-8') . '">';
    echo 'window.LV_UI_SERVER = ' . (json_encode($ui, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?: 'null') . ";\n";
    echo <<<'LVJS'
(function () {
    var d = document.documentElement;
    // Reihenfolge wie in lvUiOptions() (PHP)
    var KEYS = { mode: 'lv_mode', light: 'lv_light', dark: 'lv_dark', lang: 'lv_lang', view: 'lv_view', sort: 'lv_sort', group: 'lv_group', favtop: 'lv_favtop', tagbar: 'lv_tagbar' };
    var mem = {};   // Ersatz, falls der Browser nichts speichern darf
    var get = function (k) {
        if (Object.prototype.hasOwnProperty.call(mem, k)) return mem[k];
        try { return localStorage.getItem(k); } catch (e) { return null; }
    };
    var put = function (k, v) {
        v = String(v);
        mem[k] = v;
        try { if (v === '') localStorage.removeItem(k); else localStorage.setItem(k, v); } catch (e) {}
        if (window.lvUi && window.lvUi.onPut) window.lvUi.onPut(k);
    };
    // Am Konto gespeicherte Einstellungen gelten vor dem, was dieser Browser sich gemerkt hat
    var SRV = (window.LV_UI_SERVER && typeof window.LV_UI_SERVER === 'object') ? window.LV_UI_SERVER : null;
    if (SRV) { for (var sk in KEYS) { if (typeof SRV[sk] === 'string') put(KEYS[sk], SRV[sk]); } }
    var mq = window.matchMedia ? window.matchMedia('(prefers-color-scheme: light)') : null;
    var BAR = { d1: '#0b1120', d2: '#07131f', d3: '#0a0a0a', l1: '#ffffff', l2: '#ffffff', l3: '#fdfcf9' };
    function state() {
        var mode = get('lv_mode');
        if (mode !== 'light' && mode !== 'dark') mode = 'auto';
        var side = mode === 'auto' ? (mq && mq.matches ? 'l' : 'd') : mode.charAt(0);
        var light = get('lv_light'), dark = get('lv_dark');
        if (!/^[123]$/.test(light || '')) light = '1';
        if (!/^[123]$/.test(dark || '')) dark = '1';
        return { mode: mode, side: side, light: light, dark: dark, theme: side + (side === 'l' ? light : dark) };
    }
    function apply() {
        var s = state();
        d.setAttribute('data-lvt', s.theme);
        // "d1" ist das ursprüngliche Design: dafür greift keine einzige Überschreibung
        d.classList.toggle('lvt', s.theme !== 'd1');
        var m = document.querySelector('meta[name="theme-color"]');
        if (m) m.setAttribute('content', BAR[s.theme] || BAR.d1);
        return s;
    }
    var lang = get('lv_lang');
    if (lang !== 'de' && lang !== 'en') lang = /^de/i.test(navigator.language || 'de') ? 'de' : 'en';
    d.lang = lang;
    if (lang === 'en') {
        // Kurz verstecken, bis die Texte ersetzt sind (sonst blitzt Deutsch auf)
        d.classList.add('lv-wait');
        setTimeout(function () { d.classList.remove('lv-wait'); }, 2500);
    }
    window.lvUi = { state: state, apply: apply, lang: lang, get: get, put: put, keys: KEYS, server: SRV };
    apply();
    if (mq) {
        var onChange = function () { apply(); if (window.lvUi.onTheme) window.lvUi.onTheme(); };
        if (mq.addEventListener) mq.addEventListener('change', onChange); else if (mq.addListener) mq.addListener(onChange);
    }
})();
LVJS;
    echo '</script>' . "\n" . '<style id="lv-themes">';
    echo <<<'LVCSS'

/* ---------- Farbwerte ---------- */
html {
    --lv-scheme: dark;
    --lv-bg: #0b1120; --lv-body: linear-gradient(165deg, #0b1120 0%, #0f172a 45%, #1e1b4b 100%);
    --lv-header: rgba(11, 17, 32, 0.98); --lv-panel: rgba(15, 23, 42, 0.92); --lv-panel-solid: #101a2e;
    --lv-card: rgba(30, 41, 59, 0.72); --lv-field: rgba(15, 23, 42, 0.7); --lv-field-solid: rgba(15, 23, 42, 0.95);
    --lv-raised: rgba(30, 41, 59, 0.95); --lv-raised-h: rgba(51, 65, 85, 0.95); --lv-group: rgba(15, 23, 42, 0.4);
    --lv-line: rgba(51, 65, 85, 0.6); --lv-line2: rgba(71, 85, 105, 0.7);
    --lv-t1: #f1f5f9; --lv-t2: #e2e8f0; --lv-t3: #94a3b8; --lv-t4: #64748b;
    --lv-a: #8b5cf6; --lv-a2: #7c3aed; --lv-ah: #a78bfa; --lv-at: #c4b5fd; --lv-ath: #e9d5ff; --lv-ar: 139 92 246; --lv-on-a: #fff;
    --lv-bad-t: #fca5a5; --lv-bad-bg: rgba(127, 29, 29, 0.4); --lv-bad-bg-h: rgba(153, 27, 27, 0.55); --lv-bad-line: rgba(185, 28, 28, 0.5);
    --lv-warn-t: #fcd34d; --lv-warn-bg: rgba(245, 158, 11, 0.1); --lv-warn-line: rgba(245, 158, 11, 0.35);
    --lv-ok-t: #6ee7b7; --lv-ok-bg: rgba(6, 78, 59, 0.35); --lv-ok-line: rgba(16, 185, 129, 0.4);
    --lv-star: #fbbf24; --lv-star-bg: rgba(120, 53, 15, 0.25); --lv-star-line: rgba(245, 158, 11, 0.35);
    --lv-fav: rgba(69, 26, 3, 0.12);
    --lv-shadow: rgba(0, 0, 0, 0.5); --lv-overlay: rgba(0, 0, 0, 0.65);
    --lv-scroll: #475569; --lv-toggle: #334155; --lv-track: #1e293b;
}
html[data-lvt="d2"] {
    --lv-bg: #07131f; --lv-body: linear-gradient(165deg, #07131f 0%, #0b1c2c 45%, #0c2a44 100%);
    --lv-header: rgba(7, 19, 31, 0.98); --lv-panel: rgba(11, 26, 41, 0.96); --lv-panel-solid: #0b1a29;
    --lv-card: rgba(22, 44, 66, 0.78); --lv-field: rgba(6, 16, 27, 0.75); --lv-field-solid: #08141f;
    --lv-raised: rgba(24, 48, 72, 0.96); --lv-raised-h: rgba(36, 66, 98, 0.96); --lv-group: rgba(6, 16, 27, 0.45);
    --lv-line: rgba(58, 92, 126, 0.6); --lv-line2: rgba(84, 120, 156, 0.75);
    --lv-t1: #f1f5f9; --lv-t2: #dbe7f3; --lv-t3: #a3b8cc; --lv-t4: #7c95ad;
    --lv-a: #3b82f6; --lv-a2: #2563eb; --lv-ah: #60a5fa; --lv-at: #93c5fd; --lv-ath: #bfdbfe; --lv-ar: 59 130 246; --lv-on-a: #fff;
    --lv-scroll: #3f5f7f; --lv-toggle: #2c4a68; --lv-track: #14283c;
}
html[data-lvt="d3"] {
    --lv-bg: #0a0a0a; --lv-body: linear-gradient(165deg, #0a0a0a 0%, #111312 45%, #0c2219 100%);
    --lv-header: rgba(10, 10, 10, 0.98); --lv-panel: rgba(22, 22, 22, 0.97); --lv-panel-solid: #161616;
    --lv-card: rgba(38, 38, 38, 0.8); --lv-field: rgba(8, 8, 8, 0.75); --lv-field-solid: #0d0d0d;
    --lv-raised: rgba(42, 42, 42, 0.96); --lv-raised-h: rgba(66, 66, 66, 0.96); --lv-group: rgba(8, 8, 8, 0.45);
    --lv-line: rgba(84, 84, 84, 0.65); --lv-line2: rgba(120, 120, 120, 0.75);
    --lv-t1: #fafafa; --lv-t2: #e5e5e5; --lv-t3: #b0b0b0; --lv-t4: #8c8c8c;
    --lv-a: #34d399; --lv-a2: #10b981; --lv-ah: #6ee7b7; --lv-at: #6ee7b7; --lv-ath: #a7f3d0; --lv-ar: 16 185 129; --lv-on-a: #022c22;
    --lv-scroll: #525252; --lv-toggle: #404040; --lv-track: #262626;
}
html[data-lvt^="l"] {
    --lv-scheme: light;
    --lv-header: rgba(255, 255, 255, 0.98); --lv-panel: rgba(255, 255, 255, 0.98); --lv-panel-solid: #ffffff;
    --lv-card: #ffffff; --lv-field: #ffffff; --lv-field-solid: #ffffff;
    --lv-raised: #f1f5f9; --lv-raised-h: #e2e8f0; --lv-group: #f8fafc;
    --lv-line: #cbd5e1; --lv-line2: #94a3b8;
    --lv-t1: #0f172a; --lv-t2: #1e293b; --lv-t3: #475569; --lv-t4: #5b6b80;
    --lv-on-a: #fff;
    --lv-bad-t: #b91c1c; --lv-bad-bg: #fee2e2; --lv-bad-bg-h: #fecaca; --lv-bad-line: #f87171;
    --lv-warn-t: #92400e; --lv-warn-bg: #fef3c7; --lv-warn-line: #f59e0b;
    --lv-ok-t: #047857; --lv-ok-bg: #d1fae5; --lv-ok-line: #34d399;
    --lv-star: #b45309; --lv-star-bg: #fef3c7; --lv-star-line: #f59e0b;
    --lv-fav: #fffbeb;
    --lv-shadow: rgba(15, 23, 42, 0.2); --lv-overlay: rgba(15, 23, 42, 0.5);
    --lv-scroll: #94a3b8; --lv-toggle: #94a3b8; --lv-track: #e2e8f0;
}
html[data-lvt="l1"] {
    --lv-bg: #f6f5fb; --lv-body: linear-gradient(165deg, #f8fafc 0%, #f5f3ff 50%, #ede9fe 100%);
    --lv-a: #7c3aed; --lv-a2: #6d28d9; --lv-ah: #8b5cf6; --lv-at: #6d28d9; --lv-ath: #4c1d95; --lv-ar: 124 58 237;
}
html[data-lvt="l2"] {
    --lv-bg: #f3f7fc; --lv-body: linear-gradient(165deg, #f8fafc 0%, #eff6ff 50%, #dbeafe 100%);
    --lv-a: #2563eb; --lv-a2: #1d4ed8; --lv-ah: #3b82f6; --lv-at: #1d4ed8; --lv-ath: #1e3a8a; --lv-ar: 37 99 235;
}
html[data-lvt="l3"] {
    --lv-bg: #f7f6f0; --lv-body: linear-gradient(165deg, #fbfaf6 0%, #f4f5ec 50%, #e2eee1 100%);
    --lv-header: rgba(253, 252, 249, 0.98); --lv-panel: rgba(253, 252, 249, 0.98); --lv-panel-solid: #fdfcf9;
    --lv-card: #fffefb; --lv-field: #fffefb; --lv-field-solid: #fffefb;
    --lv-raised: #f2f0ea; --lv-raised-h: #e5e2d9; --lv-group: #f8f6f0;
    --lv-line: #d3cfc6; --lv-line2: #a19c94;
    --lv-t1: #1c1917; --lv-t2: #292524; --lv-t3: #57534e; --lv-t4: #6b6560;
    --lv-a: #047857; --lv-a2: #065f46; --lv-ah: #059669; --lv-at: #047857; --lv-ath: #064e3b; --lv-ar: 4 120 87;
    --lv-scroll: #a19c94; --lv-toggle: #a19c94; --lv-track: #e5e2d9;
}

/* ---------- Überschreibungen (alles außer dem ursprünglichen Design) ---------- */
html.lvt { background: var(--lv-bg); color-scheme: var(--lv-scheme); }
html.lvt body { background: var(--lv-body); color: var(--lv-t1); }
html.lvt ::-webkit-scrollbar-thumb, html.lvt #categoryBar::-webkit-scrollbar-thumb { background: var(--lv-scroll); }
html.lvt #categoryBar { scrollbar-color: var(--lv-scroll) transparent; }

html.lvt .glass { background: var(--lv-card); border-color: var(--lv-line); }
html.lvt .glass-strong { background: var(--lv-panel); border-color: var(--lv-line); }

html.lvt .btn-primary, html.lvt .fab {
    background: linear-gradient(135deg, var(--lv-a), var(--lv-a2)); color: var(--lv-on-a);
    box-shadow: 0 4px 14px -3px rgb(var(--lv-ar) / 0.45);
}
html.lvt .btn-primary:hover:not(:disabled) { background: linear-gradient(135deg, var(--lv-ah), var(--lv-a)); }
html.lvt .btn-secondary { background: var(--lv-raised); color: var(--lv-t2); border-color: var(--lv-line2); }
html.lvt .btn-secondary:hover:not(:disabled) { background: var(--lv-raised-h); color: var(--lv-t1); }
html.lvt .btn-danger { background: var(--lv-bad-bg); color: var(--lv-bad-t); border-color: var(--lv-bad-line); }
html.lvt .btn-danger:hover:not(:disabled) { background: var(--lv-bad-bg-h); color: var(--lv-bad-t); }
html.lvt .btn-ghost { color: var(--lv-t3); }
html.lvt .btn-ghost:hover:not(:disabled) { background: var(--lv-raised-h); color: var(--lv-t1); }
html.lvt .btn-icon { background: var(--lv-raised); border-color: var(--lv-line2); color: var(--lv-t2); }
html.lvt .btn-icon:hover:not(:disabled) { background: var(--lv-raised-h); color: var(--lv-t1); }
html.lvt .btn-icon.active { background: rgb(var(--lv-ar) / 0.2); border-color: rgb(var(--lv-ar) / 0.6); color: var(--lv-at); }
html.lvt .btn-icon.has-note::after { border-color: var(--lv-bg); }

html.lvt .card-actions { border-top-color: var(--lv-line); }
html.lvt .card-btn-open { background: rgb(var(--lv-ar) / 0.14); border-color: rgb(var(--lv-ar) / 0.4); color: var(--lv-at); }
html.lvt .card-btn-open:hover { background: rgb(var(--lv-ar) / 0.26); color: var(--lv-ath); }
html.lvt .card-btn-icon { background: var(--lv-raised); border-color: var(--lv-line2); color: var(--lv-t3); }
html.lvt .card-btn-icon:hover { background: var(--lv-raised-h); color: var(--lv-t1); }
html.lvt .card-btn-icon.starred { color: var(--lv-star); background: var(--lv-star-bg); border-color: var(--lv-star-line); }
html.lvt .card-btn-icon.danger:hover { background: var(--lv-bad-bg); border-color: var(--lv-bad-line); color: var(--lv-bad-t); }

html.lvt .bookmark-card:hover { box-shadow: 0 6px 16px -6px var(--lv-shadow); border-color: rgb(var(--lv-ar) / 0.5); }
html.lvt .bookmark-card.favorite { border-color: var(--lv-star-line); background: linear-gradient(155deg, var(--lv-card), var(--lv-fav)); }
html.lvt .bookmark-card.selected {
    border-color: rgb(var(--lv-ar) / 0.8) !important; box-shadow: 0 0 0 2px rgb(var(--lv-ar) / 0.3);
    background: linear-gradient(155deg, var(--lv-card), rgb(var(--lv-ar) / 0.14));
}
html.lvt .bookmark-card.kb-cursor { outline-color: var(--lv-a); }
html.lvt .bookmark-card.last-opened { outline-color: var(--lv-a); box-shadow: 0 0 14px -2px rgb(var(--lv-ar) / 0.6); }
html[data-lvt^="l"] .bookmark-card { box-shadow: 0 1px 2px rgba(15, 23, 42, 0.06); }
html.lvt .favicon { background: var(--lv-group); }
html.lvt .sel-check { border-color: var(--lv-t4); }
html.lvt .sel-check.checked { background: var(--lv-a); border-color: var(--lv-a); color: var(--lv-on-a); }

html.lvt .cat-btn { border-color: var(--lv-line2); background: var(--lv-raised); color: var(--lv-t2); }
html.lvt .cat-btn:hover { background: var(--lv-raised-h); color: var(--lv-t1); }
html.lvt .cat-btn.active {
    background: linear-gradient(135deg, var(--lv-a), var(--lv-a2)); border-color: transparent; color: var(--lv-on-a);
    box-shadow: 0 3px 12px -2px rgb(var(--lv-ar) / 0.45);
}
html.lvt .cat-btn.drop-ok { outline-color: var(--lv-a); background: rgb(var(--lv-ar) / 0.25); color: var(--lv-t1); }
html.lvt .cat-btn.warn { border-color: var(--lv-bad-line); color: var(--lv-bad-t); }
html.lvt .cat-btn.warn.active { background: linear-gradient(135deg, #e11d48, #be123c); border-color: transparent; color: #fff; box-shadow: none; }
html.lvt .cat-chip { border-color: var(--lv-line2); background: var(--lv-raised); color: var(--lv-t2); }
html.lvt .cat-chip:hover { border-color: rgb(var(--lv-ar) / 0.6); color: var(--lv-at); }
html.lvt .cat-chip.active { background: linear-gradient(135deg, var(--lv-a), var(--lv-a2)); border-color: transparent; color: var(--lv-on-a); }
html.lvt .cat-chip[data-cat="__new"] { color: var(--lv-at) !important; }

html.lvt .empty-state { background: radial-gradient(ellipse at 50% 30%, rgb(var(--lv-ar) / 0.08) 0%, transparent 65%); }
html.lvt input:focus, html.lvt select:focus, html.lvt textarea:focus, html.lvt button:focus-visible { box-shadow: 0 0 0 3px rgb(var(--lv-ar) / 0.35); }
html.lvt .field { background: var(--lv-field); border-color: var(--lv-line2); color: var(--lv-t1); }
html.lvt .field::placeholder { color: var(--lv-t4); }
html.lvt .field:focus { border-color: var(--lv-a); box-shadow: 0 0 0 3px rgb(var(--lv-ar) / 0.25); }
html.lvt .search-wrap .field { background: var(--lv-field-solid) !important; }
html.lvt .toggle:not(.on) { background: var(--lv-toggle); }

html.lvt .bulk-inner {
    background: var(--lv-panel); border-color: rgb(var(--lv-ar) / 0.45);
    box-shadow: 0 -8px 32px -4px var(--lv-shadow), 0 0 24px -8px rgb(var(--lv-ar) / 0.2);
}
html.lvt #exportMenu, html.lvt #toolsMenu, html.lvt #viewMenu {
    background: var(--lv-panel-solid); box-shadow: 0 12px 40px -8px var(--lv-shadow), 0 0 0 1px var(--lv-line);
}
html.lvt .search-clear { color: var(--lv-t3); }
html.lvt .search-clear:hover { color: var(--lv-t1); background: var(--lv-raised-h); }
html.lvt #appHeader { background: var(--lv-header) !important; border-bottom-color: var(--lv-line); }
html.lvt #appHeader .w-8.h-8 { background-image: linear-gradient(to bottom right, var(--lv-a), var(--lv-a2)); box-shadow: 0 0 14px -3px rgb(var(--lv-ar) / 0.5); }
html.lvt #appHeader .w-8.h-8 svg { color: var(--lv-on-a); }

html.lvt .domain-group { border-color: var(--lv-line); background: var(--lv-group); }
html.lvt .domain-group-header:hover { background: var(--lv-raised-h); }
html.lvt .domain-group-header .chevron { color: var(--lv-t4); }

html.lvt .bm-title { color: var(--lv-t1); }
html.lvt a.bm-title:hover { color: var(--lv-at); }
html.lvt a.bm-title:focus-visible { outline-color: var(--lv-a); }
html.lvt .bm-domain { color: var(--lv-t4); }
html.lvt .bm-desc { color: var(--lv-t3); }
html.lvt .bm-chip { background: var(--lv-raised); color: var(--lv-t3); border-color: var(--lv-line); }
html.lvt .bm-chip.bm-tag { color: var(--lv-at); border-color: rgb(var(--lv-ar) / 0.4); background: rgb(var(--lv-ar) / 0.1); }
html.lvt .bm-chip.bm-tag:hover { background: rgb(var(--lv-ar) / 0.22); }
html.lvt .bm-chip.bm-warn { color: var(--lv-bad-t); border-color: var(--lv-bad-line); background: var(--lv-bad-bg); }
html.lvt .bm-chip.bm-warn.unclear { color: var(--lv-warn-t); border-color: var(--lv-warn-line); background: var(--lv-warn-bg); }
html.lvt .bm-more { color: var(--lv-t3); }
html.lvt .bm-more:hover, html.lvt .bookmark-card.expanded .bm-more { background: var(--lv-raised-h); color: var(--lv-t1); }

html.lvt .menu-label { color: var(--lv-t4); }
html.lvt .menu-opt { color: var(--lv-t2); }
html.lvt .menu-opt:hover { background: var(--lv-raised-h); }
html.lvt .menu-opt svg { color: var(--lv-t3); }
html.lvt .menu-opt.on { color: var(--lv-at); }
html.lvt .menu-opt.on::after { color: var(--lv-at); }
html.lvt .menu-opt.danger, html.lvt .menu-opt.danger svg { color: var(--lv-bad-t); }
html.lvt .menu-opt .badge { color: var(--lv-t3); background: var(--lv-raised); }
html.lvt .menu-opt .badge.hot { background: #f59e0b; color: #1e1b4b; }
html.lvt .menu-sep { border-top-color: var(--lv-line); }

html.lvt .box { border-color: var(--lv-line); background: var(--lv-group); }
html.lvt .box h4 { color: var(--lv-t1); }
html.lvt .box p { color: var(--lv-t3); }
html.lvt .mono-box { color: var(--lv-at); background: var(--lv-field); border-color: rgb(var(--lv-ar) / 0.55); }
html.lvt .ok-text { color: var(--lv-ok-t); }
html.lvt .warn-text { color: var(--lv-warn-t); }
html.lvt .bad-text { color: var(--lv-bad-t); }
html.lvt .lbl { color: var(--lv-t3); }
html.lvt .list-row { background: var(--lv-raised); border-color: var(--lv-line); }
html.lvt .list-row .t1 { color: var(--lv-t1); }
html.lvt .list-row .t2 { color: var(--lv-t4); }
html.lvt kbd { border-color: var(--lv-line2); color: var(--lv-t3); }
html.lvt .user-note { color: var(--lv-t2); }

/* Farbklassen aus dem eingebauten Tailwind */
html.lvt .text-slate-100, html.lvt h3.text-white { color: var(--lv-t1); }
html.lvt .text-slate-200, html.lvt .text-slate-300 { color: var(--lv-t2); }
html.lvt .text-slate-400 { color: var(--lv-t3); }
html.lvt .text-slate-500, html.lvt .text-slate-600 { color: var(--lv-t4); }
html.lvt .text-violet-300, html.lvt .text-violet-400 { color: var(--lv-at); }
html.lvt .text-amber-300, html.lvt .text-amber-300\/90 { color: var(--lv-warn-t); }
html.lvt .text-amber-400 { color: var(--lv-star); }
html.lvt .text-rose-300, html.lvt .text-rose-400 { color: var(--lv-bad-t); }
html.lvt .border-slate-600 { border-color: var(--lv-line2); }
html.lvt .border-slate-700\/35, html.lvt .border-slate-700\/40, html.lvt .border-slate-700\/45, html.lvt .border-slate-700\/50 { border-color: var(--lv-line); }
html.lvt .bg-\[rgba\(15\2c 23\2c 42\2c 0\.95\)\] { background-color: var(--lv-panel-solid); }
html.lvt .bg-black\/65 { background-color: var(--lv-overlay); }
html.lvt .bg-slate-800 { background-color: var(--lv-track); }
html.lvt .bg-slate-800\/50, html.lvt .bg-slate-800\/70, html.lvt .bg-slate-800\/80 { background-color: var(--lv-raised); }
html.lvt .bg-violet-500 { background-color: var(--lv-a); }
html.lvt .hover\:border-violet-500\/30:hover, html.lvt .hover\:border-violet-500\/50:hover { border-color: rgb(var(--lv-ar) / 0.6); }
html.lvt .hover\:bg-slate-700\/70:hover { background-color: var(--lv-raised-h); }
html.lvt .hover\:bg-slate-800\/30:hover { background-color: var(--lv-raised); }
html.lvt .hover\:bg-violet-600\/20:hover { background-color: rgb(var(--lv-ar) / 0.14); }
html.lvt .hover\:text-violet-200:hover { color: var(--lv-ath); }

/* Anmeldeseite */
html.lvt .card { background: var(--lv-panel); border-color: var(--lv-line); box-shadow: 0 20px 40px -12px var(--lv-shadow); }
html.lvt .card .logo { background: linear-gradient(135deg, var(--lv-a), var(--lv-a2)); box-shadow: 0 0 14px -3px rgb(var(--lv-ar) / 0.5); }
html.lvt .card .logo svg { stroke: var(--lv-on-a); }
html.lvt .card p.sub, html.lvt .card label { color: var(--lv-t3); }
html.lvt .card input { background: var(--lv-field); border-color: var(--lv-line2); color: var(--lv-t1); }
html.lvt .card input:focus { border-color: var(--lv-a); box-shadow: 0 0 0 3px rgb(var(--lv-ar) / 0.25); }
html.lvt .card form button {
    background: linear-gradient(135deg, var(--lv-a), var(--lv-a2)); color: var(--lv-on-a);
    box-shadow: 0 4px 14px -3px rgb(var(--lv-ar) / 0.45);
}
html.lvt .card form button:hover { background: linear-gradient(135deg, var(--lv-ah), var(--lv-a)); }
html.lvt .card .err { background: var(--lv-bad-bg); border-color: var(--lv-bad-line); color: var(--lv-bad-t); }
html.lvt .card .ok { background: var(--lv-ok-bg); border-color: var(--lv-ok-line); color: var(--lv-ok-t); }
html.lvt .card .hint { color: var(--lv-t4); }
html.lvt .card .hint a { color: var(--lv-at); }

/* ---------- Fenster „Design & Sprache“ (gilt für alle Schemata) ---------- */
html.lv-wait body { visibility: hidden; }
.lvui-ov {
    position: fixed; inset: 0; z-index: 95; display: flex; align-items: center; justify-content: center;
    padding: 0.75rem; background: var(--lv-overlay); -webkit-backdrop-filter: blur(4px); backdrop-filter: blur(4px);
}
.lvui-ov.hidden { display: none; }
.lvui-panel {
    width: 100%; max-width: 23rem; max-height: calc(100vh - 1.5rem); max-height: calc(100dvh - 1.5rem); overflow-y: auto;
    background: var(--lv-panel-solid); color: var(--lv-t1); border: 1px solid var(--lv-line2); border-radius: 1rem;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.45); text-align: left;
}
.lvui-head { display: flex; align-items: center; justify-content: space-between; padding: 0.7rem 0.7rem 0.7rem 1rem; border-bottom: 1px solid var(--lv-line); }
.lvui-head h3 { margin: 0; font-size: 1rem; font-weight: 600; color: var(--lv-t1); text-align: left; }
.lvui-body { padding: 0.9rem 1rem 1rem; }
.lvui-lbl { font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--lv-t3); margin: 0.9rem 0 0.4rem; }
.lvui-lbl:first-child { margin-top: 0; }
.lvui-row { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.4rem; }
.lvui-row.two { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.lvui-ov .lvui-b {
    all: unset; box-sizing: border-box; cursor: pointer; display: flex; flex-direction: column; align-items: center; justify-content: center;
    gap: 0.3rem; min-height: 2.6rem; padding: 0.4rem; border-radius: 0.65rem; border: 2px solid var(--lv-line2);
    background: var(--lv-raised); color: var(--lv-t2); font-size: 0.8rem; font-weight: 600; text-align: center; line-height: 1.2;
    -webkit-user-select: none; user-select: none;
}
.lvui-ov .lvui-b:hover { background: var(--lv-raised-h); color: var(--lv-t1); }
.lvui-ov .lvui-b:focus-visible { outline: 2px solid var(--lv-a); outline-offset: 2px; }
.lvui-ov .lvui-b[aria-pressed="true"] { border-color: var(--lv-a); background: rgb(var(--lv-ar) / 0.16); color: var(--lv-t1); }
.lvui-ov .lvui-b[aria-pressed="true"] .lvui-nm::after { content: ' \2713'; font-weight: 700; color: var(--lv-at); }
.lvui-prev {
    display: flex; align-items: center; justify-content: center; gap: 0.3rem; width: 100%; height: 1.9rem;
    border-radius: 0.4rem; border: 1px solid rgba(128, 128, 128, 0.45);
}
.lvui-prev i { display: block; width: 1.2rem; height: 0.55rem; border-radius: 9999px; }
.lvui-prev b { display: block; width: 1.5rem; height: 0.3rem; border-radius: 2px; }
.lvui-ov .lvui-x {
    all: unset; box-sizing: border-box; cursor: pointer; display: flex; align-items: center; justify-content: center;
    width: 2.1rem; height: 2.1rem; border-radius: 0.6rem; color: var(--lv-t3);
}
.lvui-ov .lvui-x:hover { background: var(--lv-raised-h); color: var(--lv-t1); }
.lvui-ov .lvui-x:focus-visible { outline: 2px solid var(--lv-a); outline-offset: 2px; }
.lvui-note { font-size: 0.72rem; color: var(--lv-t4); margin: 0.8rem 0 0; line-height: 1.45; }
html .lvui-fab {
    all: unset; box-sizing: border-box; cursor: pointer; position: fixed; z-index: 60;
    top: max(0.75rem, env(safe-area-inset-top)); right: max(0.75rem, env(safe-area-inset-right));
    width: 2.6rem; height: 2.6rem; border-radius: 0.75rem; display: flex; align-items: center; justify-content: center;
    background: var(--lv-raised); border: 1px solid var(--lv-line2); color: var(--lv-t2);
}
html .lvui-fab:hover { background: var(--lv-raised-h); color: var(--lv-t1); }
html .lvui-fab:focus-visible { outline: 2px solid var(--lv-a); outline-offset: 2px; }
.btn.lvui-hdr { display: none; }
@media (min-width: 640px) { .btn.lvui-hdr { display: inline-flex; } }
LVCSS;
    echo '</style>' . "\n";
}

/** Gehört ans Ende des <body>, nach dem Skript der Seite. */
function lvUiFoot(): void {
    global $LV_NONCE;
    echo '<script nonce="' . htmlspecialchars((string)$LV_NONCE, ENT_QUOTES, 'UTF-8') . '">';
    echo <<<'LVJS'
(function () {
    'use strict';
    var ui = window.lvUi;
    if (!ui) return;
    var doc = document, root = doc.documentElement;
    var set = ui.put;

    /* ----- Einstellungen am Konto speichern (nur in der App, nicht auf der Anmeldeseite) ----- */
    var csrfEl = doc.getElementById('exportCsrf');
    var DEF = { mode: 'auto', light: '1', dark: '1', lang: '', view: 'cards', sort: 'title', group: 'domain', favtop: '1', tagbar: '1' };
    var snap = function (src) {
        var o = {};
        for (var k in ui.keys) {
            var v = src ? src[k] : ui.get(ui.keys[k]);
            o[k] = (v === null || v === undefined) ? DEF[k] : String(v);
        }
        return JSON.stringify(o);
    };
    var sent = snap(ui.server || DEF);
    // Schickt den Stand nur, wenn er sich vom zuletzt gespeicherten unterscheidet.
    // keep = true: Die Seite wird gerade verlassen, die Anfrage soll trotzdem noch rausgehen.
    var pushTimer = 0;
    function push(keep) {
        clearTimeout(pushTimer);
        if (!csrfEl) return Promise.resolve();
        var now = snap(), before = sent;
        if (now === sent) return Promise.resolve();
        sent = now;
        var fd = new FormData();
        fd.append('action', 'ui_save'); fd.append('csrf', csrfEl.value); fd.append('ui', now);
        if (keep && navigator.sendBeacon) {
            // Der Browser schickt das auch dann noch ab, wenn die Seite schon weg ist
            try { if (navigator.sendBeacon(location.pathname, fd)) return Promise.resolve(); } catch (e) {}
        }
        // keepalive: Die Anfrage läuft zu Ende, auch wenn gleich danach neu geladen oder die Seite geschlossen wird
        var opts = { method: 'POST', body: fd, credentials: 'same-origin', keepalive: true, headers: { 'X-CSRF-Token': csrfEl.value } };
        return fetch('', opts)
            .then(function (r) { return r.json(); })
            .then(function (j) { if (!j || !j.success) sent = before; })
            .catch(function () { sent = before; });
    }
    if (csrfEl) {
        // Jede Änderung an einer der Einstellungen (auch Ansicht, Sortierung, Gruppierung in der App) stößt das Speichern an
        var uiKeys = {};
        for (var uk in ui.keys) uiKeys[ui.keys[uk]] = 1;
        ui.onPut = function (k) {
            // Sofort losschicken, ohne Wartezeit: so ist es auch dann gespeichert, wenn gleich danach neu geladen wird
            if (uiKeys[k]) push();
        };
        // Seite wird geschlossen oder neu geladen, bevor gespeichert wurde: jetzt noch schnell nachholen
        window.addEventListener('pagehide', function () { push(true); });
        doc.addEventListener('visibilitychange', function () { if (doc.visibilityState === 'hidden') push(true); });
        // Konto hatte noch nichts gespeichert, der Browser aber schon: einmalig übernehmen
        push();
    }
    var ICON = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 000 18z" fill="currentColor" stroke="none"/></svg>';
    var CLOSE = '<svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>';
    // Vorschau je Schema: [Hintergrund, Akzent, Textfarbe]
    var THEMES = {
        l1: ['Violett', '#ffffff', '#7c3aed', '#0f172a'], l2: ['Blau', '#ffffff', '#2563eb', '#0f172a'], l3: ['Grün', '#fffefb', '#047857', '#1c1917'],
        d1: ['Violett', '#0f172a', '#8b5cf6', '#f1f5f9'], d2: ['Blau', '#0b1c2c', '#3b82f6', '#f1f5f9'], d3: ['Grün', '#161616', '#34d399', '#fafafa']
    };
    var btn = function (attrs, label, prev) {
        return '<button type="button" class="lvui-b" ' + attrs + ' aria-pressed="false">' + (prev || '') + '<span class="lvui-nm">' + label + '</span></button>';
    };
    var swatches = function (side) {
        return ['1', '2', '3'].map(function (n) {
            var t = THEMES[side + n];
            return btn('data-theme="' + side + n + '"', t[0],
                '<span class="lvui-prev" style="background:' + t[1] + '"><i style="background:' + t[2] + '"></i><b style="background:' + t[3] + '"></b></span>');
        }).join('');
    };

    var ov = doc.createElement('div');
    ov.id = 'lvUiOverlay';
    ov.className = 'lvui-ov hidden';
    ov.innerHTML = '<div class="lvui-panel" role="dialog" aria-modal="true" aria-labelledby="lvUiTitle">'
        + '<div class="lvui-head"><h3 id="lvUiTitle">Design &amp; Sprache</h3><button type="button" class="lvui-x" data-close="1" aria-label="Schließen">' + CLOSE + '</button></div>'
        + '<div class="lvui-body">'
        + '<div class="lvui-lbl">Modus</div><div class="lvui-row">'
        + btn('data-mode="auto"', 'Automatisch') + btn('data-mode="light"', 'Hell') + btn('data-mode="dark"', 'Dunkel') + '</div>'
        + '<div class="lvui-lbl">Helle Farben</div><div class="lvui-row">' + swatches('l') + '</div>'
        + '<div class="lvui-lbl">Dunkle Farben</div><div class="lvui-row">' + swatches('d') + '</div>'
        + '<div class="lvui-lbl">Sprache</div><div class="lvui-row two">'
        + btn('data-lang="de" lang="de"', 'Deutsch') + btn('data-lang="en" lang="en"', 'English') + '</div>'
        + '<p class="lvui-note">„Automatisch“ richtet sich nach der Einstellung deines Geräts. Die Wahl wird an deinem Konto gespeichert.</p>'
        + '</div></div>';
    doc.body.appendChild(ov);

    function paint() {
        var s = ui.state();
        ov.querySelectorAll('[data-mode]').forEach(function (b) { b.setAttribute('aria-pressed', b.getAttribute('data-mode') === s.mode ? 'true' : 'false'); });
        ov.querySelectorAll('[data-theme]').forEach(function (b) {
            var t = b.getAttribute('data-theme');
            b.setAttribute('aria-pressed', t === (t.charAt(0) === 'l' ? 'l' + s.light : 'd' + s.dark) ? 'true' : 'false');
        });
        ov.querySelectorAll('[data-lang]').forEach(function (b) { b.setAttribute('aria-pressed', b.getAttribute('data-lang') === ui.lang ? 'true' : 'false'); });
        if (typeof window.syncHeaderSpacer === 'function') window.syncHeaderSpacer();
    }
    ui.onTheme = paint;
    var returnFocus = null;
    function open() { returnFocus = doc.activeElement; paint(); ov.classList.remove('hidden'); var x = ov.querySelector('.lvui-x'); if (x) x.focus(); }
    function close() {
        ov.classList.add('hidden');
        if (returnFocus && returnFocus.focus) { try { returnFocus.focus({ preventScroll: true }); } catch (e) {} }
        returnFocus = null;
    }
    ov.addEventListener('click', function (e) {
        if (e.target === ov || e.target.closest('[data-close]')) { close(); return; }
        var b = e.target.closest('.lvui-b');
        if (!b) return;
        if (b.hasAttribute('data-mode')) {
            set('lv_mode', b.getAttribute('data-mode'));
        } else if (b.hasAttribute('data-theme')) {
            // Eine Farbe anklicken zeigt sie auch gleich: notfalls von „Automatisch“ auf hell bzw. dunkel umstellen
            var t = b.getAttribute('data-theme'), side = t.charAt(0);
            set(side === 'l' ? 'lv_light' : 'lv_dark', t.charAt(1));
            if (ui.state().side !== side) set('lv_mode', side === 'l' ? 'light' : 'dark');
        } else if (b.hasAttribute('data-lang')) {
            var lang = b.getAttribute('data-lang');
            if (lang === ui.lang) return;
            set('lv_lang', lang);
            // Erst speichern, dann neu laden (per GET, damit ein abgeschicktes Formular nicht noch einmal gesendet wird)
            var go = function () { location.replace(location.href); };
            push().then(go, go);
            return;
        }
        ui.apply();
        paint();
        push();
    });
    doc.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && !ov.classList.contains('hidden')) { e.stopPropagation(); close(); }
    }, true);

    // Knöpfe zum Öffnen: in der App im Werkzeug-Menü und (ab Tablet-Breite) in der Kopfzeile, auf der Anmeldeseite oben rechts
    var tools = doc.getElementById('toolsMenu');
    if (tools) {
        var opt = doc.createElement('button');
        opt.type = 'button'; opt.id = 'btnLvUi'; opt.className = 'menu-opt';
        opt.innerHTML = ICON + ' Design &amp; Sprache';
        var acc = doc.getElementById('btnAccount');
        if (acc && acc.parentNode === tools) tools.insertBefore(opt, acc); else tools.appendChild(opt);
        opt.addEventListener('click', open);
        var add = doc.getElementById('btnAdd');
        if (add && add.parentNode) {
            var hb = doc.createElement('button');
            hb.type = 'button'; hb.id = 'btnLvUiTop'; hb.className = 'btn btn-icon lvui-hdr';
            hb.title = 'Design & Sprache'; hb.setAttribute('aria-label', 'Design & Sprache');
            hb.innerHTML = ICON;
            add.parentNode.insertBefore(hb, add);
            hb.addEventListener('click', open);
        }
    } else {
        var fab = doc.createElement('button');
        fab.type = 'button'; fab.className = 'lvui-fab';
        fab.title = 'Design & Sprache'; fab.setAttribute('aria-label', 'Design & Sprache');
        fab.innerHTML = ICON;
        doc.body.appendChild(fab);
        fab.addEventListener('click', open);
    }
    paint();

    /* ================= Englisch ================= */
    if (ui.lang !== 'en') return;

    // Feste Texte: deutsch → englisch
    var D = {
        // Design & Sprache
        "Design & Sprache": "Appearance & language", "Modus": "Mode", "Automatisch": "Automatic", "Hell": "Light", "Dunkel": "Dark",
        "Helle Farben": "Light colors", "Dunkle Farben": "Dark colors", "Sprache": "Language",
        "Violett": "Violet", "Blau": "Blue", "Grün": "Green",
        "„Automatisch“ richtet sich nach der Einstellung deines Geräts. Die Wahl wird an deinem Konto gespeichert.": "“Automatic” follows your device setting. Your choice is saved with your account.",

        // Anmeldeseite
        "LinkVault – Einrichtung": "LinkVault – Setup", "LinkVault – Passwort vergessen": "LinkVault – Forgot password",
        "LinkVault – Zugang anfragen": "LinkVault – Request access", "LinkVault – Anmeldung": "LinkVault – Sign in",
        "Erster Start: Benutzer anlegen. Dein Passwort schützt Login und Verschlüsselung.": "First start: create a user. Your password protects both sign-in and encryption.",
        "Mit dem Wiederherstellungscode ein neues Passwort setzen.": "Set a new password using your recovery code.",
        "Such dir Namen und Passwort aus. Danach muss dich der Administrator erst freischalten.": "Pick a name and a password. The administrator then has to approve you first.",
        "Bitte anmelden": "Please sign in",
        "Benutzername": "User name", "Passwort": "Password",
        "Passwort (min. 12 Zeichen, Buchstaben + Zahlen)": "Password (min. 12 characters, letters + digits)",
        "Passwort wiederholen": "Repeat password", "Konto anlegen": "Create account",
        "Es wird ein eigener Verschlüsselungsschlüssel erzeugt und mit deinem Passwort geschützt. Ohne Passwort sind die Daten nicht lesbar. Leg dir danach unter Werkzeuge → Konto & Sicherheit einen Wiederherstellungscode an. Dieses erste Konto ist der Administrator: Wer später dazukommen will, braucht deine Freigabe.":
            "A dedicated encryption key is generated and protected with your password. Without the password the data cannot be read. Afterwards, create a recovery code under Tools → Account & security. This first account is the administrator: anyone who wants to join later needs your approval.",
        "Wiederherstellungscode": "Recovery code",
        "Neues Passwort (min. 12 Zeichen, Buchstaben + Zahlen)": "New password (min. 12 characters, letters + digits)",
        "Neues Passwort wiederholen": "Repeat new password", "Neues Passwort setzen": "Set new password",
        "Der Code ist danach verbraucht, eine Zwei-Faktor-Anmeldung wird abgeschaltet.": "The code is used up afterwards, and two-factor sign-in is switched off.",
        "Zurück zur Anmeldung": "Back to sign-in",
        "Nachricht an den Administrator (freiwillig)": "Message to the administrator (optional)", "z. B. wer du bist": "e.g. who you are",
        "Zugang anfragen": "Request access",
        "Du bekommst einen eigenen Bereich mit eigenem Schlüssel, den nur dein Passwort öffnet. Niemand sonst kann deine Links lesen, auch der Administrator nicht. Er kann dein Passwort deshalb auch nicht zurücksetzen.":
            "You get your own area with your own key, which only your password unlocks. Nobody else can read your links, not even the administrator. That is also why the administrator cannot reset your password.",
        "2FA-Code (nur wenn du 2FA eingerichtet hast)": "2FA code (only if you have set up 2FA)",
        "2FA-Code aus der Authenticator-App": "2FA code from your authenticator app",
        "Anmelden": "Sign in", "Passwort vergessen oder Handy weg?": "Forgot your password or lost your phone?",
        "Noch kein Konto? Zugang anfragen": "No account yet? Request access",
        "Dein Konto wartet noch auf die Freigabe durch den Administrator.": "Your account is still waiting for approval by the administrator.",
        "Dein Zugang ist gesperrt. Bitte wende dich an den Administrator.": "Your access is blocked. Please contact the administrator.",
        "Der 2FA-Code fehlt oder stimmt nicht.": "The 2FA code is missing or wrong.",
        "Benutzername oder Passwort falsch.": "Wrong user name or password.",
        "Sicherheits-Token ungültig. Bitte Seite neu laden und erneut versuchen.": "Invalid security token. Please reload the page and try again.",
        "Passwörter stimmen nicht überein.": "The passwords do not match.",
        "Einrichtung fehlgeschlagen.": "Setup failed.", "Die Anfrage hat nicht geklappt.": "The request did not work.",
        "Wiederherstellung fehlgeschlagen.": "Recovery failed.",
        "Von deinem Anschluss kamen heute schon mehrere Anfragen. Bitte morgen noch einmal versuchen.": "Several requests have already come from your connection today. Please try again tomorrow.",
        "Deine Anfrage ist raus. Sobald der Administrator dich freigeschaltet hat, kannst du dich hier mit deinem Namen und Passwort anmelden.":
            "Your request has been sent. As soon as the administrator has approved you, you can sign in here with your name and password.",
        "Benutzername oder Wiederherstellungscode stimmt nicht.": "User name or recovery code is wrong.",
        "Der Wiederherstellungscode stimmt nicht.": "The recovery code is wrong.",

        // Kopfzeile und Menüs
        "Suchen… (#tag, URL einfügen = hinzufügen)": "Search… (#tag, paste a URL to add it)", "Links durchsuchen": "Search links",
        "Suche leeren": "Clear search", "Mehrfachauswahl": "Select multiple", "Ansicht und Sortierung": "View and sorting",
        "Darstellung": "Layout", "Karten": "Cards", "Liste": "List", "Kacheln": "Tiles",
        "Sortierung": "Sort by", "Neueste zuerst": "Newest first", "Älteste zuerst": "Oldest first", "Oft benutzt": "Most used",
        "Zuletzt geöffnet": "Recently opened", "Nach Domain": "By domain", "Nach Ordner": "By folder", "Favoriten immer oben": "Favorites always on top",
        "Gruppieren": "Group", "Domains mit vielen Links": "Domains with many links", "Nach Ordnern": "By folder", "Gar nicht": "No grouping",
        "Werkzeuge": "Tools", "Importieren": "Import", "Export als JSON": "Export as JSON", "Export als HTML (Browser)": "Export as HTML (browser)",
        // Automatisch sortieren, Gruppen, Tags verwalten, Tag-Leiste (3.4)
        "Automatisch sortieren": "Auto-sort", "Übernehmen": "Apply", "Tag": "Tag", "Speichere…": "Saving…",
        "Vorschläge nach Domain, Stichwörtern, deinen Gruppen und deiner bisherigen Sortierung. Geändert wird erst, wenn du auf „Übernehmen“ tippst, vorher wird automatisch ein Backup angelegt.":
            "Suggestions based on domain, keywords, your groups and how you have sorted so far. Nothing changes until you tap “Apply”, and a backup is made automatically first.",
        "Tags vorschlagen (vorhandene Tags bleiben)": "Suggest tags (existing tags are kept)",
        "Ordner vorschlagen für unsortierte Links („Allgemein“)": "Suggest folders for unsorted links (“Allgemein”)",
        "Auch Links umsortieren, die schon in einem Ordner liegen": "Also re-sort links that are already in a folder",
        "Keine Links zum Sortieren.": "No links to sort.",
        "Nichts ausgewählt.": "Nothing selected.", "Zu viele Änderungen auf einmal.": "Too many changes at once.",
        "Nichts geändert, war schon alles so.": "Nothing changed, it was all like that already.", "Sortiert": "Sorted", "Zurückgeholt": "Restored",
        "vor automatischem Sortieren": "before auto-sort", "vor Tag-Änderung": "before tag change",
        "dein Tag steht im Titel oder in der Adresse": "your tag appears in the title or address",
        "Ordnername steht im Titel oder in der Adresse": "the folder name appears in the title or address",
        "Gruppen und Stichwörter bearbeiten": "Edit groups and keywords", "Gruppen und Stichwörter": "Groups and keywords",
        "Passt ein Eintrag einer Gruppe zum Link, schlägt sie ihre Tags und ihren Ordner vor. Alles lässt sich ändern, abschalten oder löschen.":
            "If one of a group's entries matches a link, the group suggests its tags and its folder. Everything can be changed, switched off or deleted.",
        "Neue Gruppe": "New group", "Standard wiederherstellen": "Restore defaults", "Standard wiederherstellen?": "Restore defaults?",
        "Suchen: Name, Tag, Domain oder Stichwort": "Search: name, tag, domain or keyword", "Gruppen durchsuchen": "Search groups",
        "So schreibst du Einträge": "How to write entries",
        "= diese Domain samt Unterseiten": "= this domain including its subdomains",
        "= jede Endung, also amazon.de, amazon.com usw.": "= any ending, so amazon.de, amazon.com and so on",
        "= alle Domains mit dieser Endung": "= all domains with this ending",
        "= ganzes Wort in Titel, Adresse oder Beschreibung": "= whole word in the title, address or description",
        "= Wortanfang, also auch „programmieren“": "= start of a word, so “programming” matches too",
        "= steht irgendwo, auch mitten im Wort": "= appears anywhere, even inside a word",
        "Für den Ordner zählen Treffer über die Domain vor Stichwörtern. Sonst gewinnt die Gruppe weiter oben.":
            "For the folder, domain matches count before keywords. Otherwise the group higher up wins.",
        "Gruppe benutzen": "Use group", "Gruppe löschen": "Delete group", "Name": "Name", "Tags (mit Komma)": "Tags (comma separated)",
        "z. B. video, musik": "e.g. video, music", "leer = keiner": "empty = none",
        "Domains und Stichwörter (mit Komma oder je Zeile)": "Domains and keywords (comma separated or one per line)",
        "Nach oben": "Move up", "Nach unten": "Move down", "1 Eintrag": "1 entry",
        "Keine Gruppen. Leg eine neue an oder hol den Standard zurück.": "No groups. Create a new one or restore the defaults.",
        "Höchstens 150 Gruppen": "150 groups at most", "Wiederherstellen": "Restore",
        "Alle eingebauten Gruppen kommen in der Originalfassung zurück, auch gelöschte. Deine eigenen Gruppen bleiben. Übernommen wird es erst mit „Speichern“.":
            "All built-in groups come back in their original form, deleted ones too. Your own groups are kept. It only takes effect once you tap “Save”.",
        "Standard ist wieder da. Zum Übernehmen „Speichern“ antippen.": "The defaults are back. Tap “Save” to keep them.",
        "Gruppen gespeichert.": "Groups saved.", "Keine Gruppen übergeben.": "No groups were sent.",
        "Gruppen konnten nicht geladen werden": "The groups could not be loaded",
        "Die Datei mit deinen Gruppen ist nicht lesbar, es gilt der Standard. Beim nächsten Speichern wird sie neu angelegt.":
            "The file with your groups cannot be read, the defaults apply. It will be created anew the next time you save.",
        "Erwachsene (NSFW)": "Adult (NSFW)", "Technik & Computer": "Tech & computers", "Programmierung": "Programming",
        "Videos & Streaming": "Videos & streaming", "Musik": "Music", "Nachrichten": "News", "Social Media": "Social media",
        "Job & Karriere": "Jobs & career", "Kochen & Rezepte": "Cooking & recipes", "Reisen": "Travel", "Geld & Finanzen": "Money & finance",
        "Ämter & Behörden": "Public authorities", "Wissen & Lernen": "Knowledge & learning", "Anleitungen": "How-tos",
        "Spiele & Gaming": "Games", "Sport & Fitness": "Sports & fitness", "Gesundheit": "Health", "Wohnen & Garten": "Home & garden",
        "Auto & Verkehr": "Cars & traffic", "Wetter": "Weather", "Bücher": "Books",
        "Werkzeuge & Online-Dienste": "Tools & online services",
        "Tag-Leiste anzeigen": "Show tag bar", "Tags verwalten": "Manage tags", "✕ Tag-Filter aus": "✕ Clear tag filter",
        "Namen ändern und mit „Speichern“ oder Enter übernehmen. Heißt er dann wie ein anderer Tag, werden beide zusammengelegt. „Löschen“ nimmt den Tag von allen Links, die Links selbst bleiben.":
            "Change a name and confirm with “Save” or Enter. If it then matches another tag, both are merged. “Delete” removes the tag from all links, the links themselves stay.",
        "Tags durchsuchen": "Search tags", "Tag-Name": "Tag name", "Links mit diesem Tag": "Links with this tag", "Noch keine Tags.": "No tags yet.",
        "Tags zusammenlegen?": "Merge tags?", "Tag löschen": "Delete tag",
        "Tag fehlt.": "Tag is missing.", "Neuer Name fehlt.": "New name is missing.", "Tag nicht gefunden.": "Tag not found.",
        "Namen ändern und mit „Speichern“ oder Enter übernehmen. „Löschen“ entfernt nur den Ordner, die Links darin bleiben und kommen nach „Allgemein“ (bei Unterordnern eine Ebene höher).":
            "Change a name and confirm with “Save” or Enter. “Delete” only removes the folder, its links stay and move to “Allgemein” (one level up for subfolders).",
        "Links in diesem Ordner": "Links in this folder", "„Allgemein“ ist der Standard-Ordner": "“Allgemein” is the default folder",
        "Ordner löschen": "Delete folder", "Ordner gelöscht": "Folder deleted",
        "Duplikate entfernen": "Remove duplicates", "Tote Links prüfen": "Check for dead links", "Ordner verwalten": "Manage folders",
        "Papierkorb": "Trash", "Schnell speichern / App": "Quick save / app", "Neu laden": "Reload",
        "Konto & Sicherheit": "Account & security", "Anmeldeversuche": "Sign-in attempts", "Benutzer verwalten": "Manage users",
        "Abmelden": "Sign out", "Hinzufügen": "Add",

        // Hauptbereich
        "Favoriten": "Favorites", "⭐ Favoriten": "⭐ Favorites", "Alle": "All", "Tote Links": "Dead links",
        "Alle Links": "All links", "Suchergebnisse": "Search results", "Weitere Links": "More links",
        "Beim letzten Check nicht erreichbar": "Unreachable at the last check",
        "Noch keine Links": "No links yet", "Keine Treffer": "No matches",
        "Füge deinen ersten Link hinzu oder importiere Lesezeichen.": "Add your first link or import bookmarks.",
        "Anderen Suchbegriff oder Filter versuchen.": "Try a different search term or filter.",
        "Ersten Link hinzufügen": "Add first link", "Link hinzufügen": "Add link", "Link bearbeiten": "Edit link",
        "Ordner": "Folder", "Favorit": "Favorite", "Löschen": "Delete",
        "Auswählen": "Select", "Aktionen": "Actions", "Öffnen": "Open", "URL kopieren": "Copy URL", "Ordner wählen": "Choose folder",
        "Bearbeiten": "Edit", "tot?": "dead?", "unklar": "unclear",

        // Fenster Hinzufügen/Bearbeiten
        "Schließen": "Close", "Titel": "Title", "z. B. GitHub": "e.g. GitHub",
        "Titel und Beschreibung von der Seite holen": "Fetch title and description from the page",
        "— Ordner wählen —": "— Choose folder —", "Oder neuen Ordner anlegen…": "Or create a new folder…",
        "Neuer Ordner, auch „Ordner > Unterordner“": "New folder, also “Folder > Subfolder”",
        "Neuen Ordner übernehmen": "Use the new folder", "Gewählt:": "Selected:", "+ Neu": "+ New",
        "Beschreibung": "Description", "Kurze Notiz…": "Short note…", "Schlagwörter": "Tags",
        "(optional, mit Komma trennen)": "(optional, comma-separated)", "z. B. go, tutorial, lesen": "e.g. go, tutorial, read",
        "Als Favorit": "As favorite", "Abbrechen": "Cancel", "Speichern": "Save",
        "Hole Titel von der Seite…": "Fetching the title from the page…", "Titel konnte nicht geholt werden.": "The title could not be fetched.",
        "Erst eine URL eingeben": "Enter a URL first",
        "Als neuen Link speichern?": "Save as a new link?", "Den Link hast du schon gespeichert": "You have already saved this link",
        "Diesen Link gibt es schon": "This link already exists", "Trotzdem speichern": "Save anyway",
        "Ordnername eingeben": "Enter a folder name", "Name eingeben": "Enter a name",

        // Verschieben
        "In Ordner verschieben": "Move to folder", "Wähle einen Ordner oder lege einen neuen an.": "Choose a folder or create a new one.",
        "Neuer Ordner": "New folder", "Name eingeben…": "Enter a name…", "Anlegen": "Create",
        "Noch keine Ordner. Lege unten einen an.": "No folders yet. Create one below.",

        // Import / Export
        "Lesezeichen importieren": "Import bookmarks", "HTML-Datei aus": "Upload an HTML file from", "oder": "or",
        "hochladen, oder ein": "or alternatively a", "JSON-Backup": "JSON backup",
        "aus dem eigenen Export. Vorhandene Links bleiben, doppelte werden übersprungen.": "from LinkVault's own export. Existing links are kept, duplicates are skipped.",
        "Datei wählen": "Choose file", "Datei prüfen": "Check file", "Prüfe…": "Checking…", "Nichts Neues dabei": "Nothing new in it",
        "Importiere…": "Importing…", "Datei nicht lesbar": "The file cannot be read", "Import erfolgreich": "Import successful",
        "Import fehlgeschlagen": "Import failed",
        "Unverschlüsselt exportieren?": "Export unencrypted?",
        "Diese Datei enthält deine Links im Klartext, zum Beispiel für den Umzug in einen Browser. Für eine Sicherung nimm lieber das Komplett-Backup unter Werkzeuge → Backups.":
            "This file contains your links in plain text, for example for moving them into a browser. For a backup, rather use the full backup under Tools → Backups.",
        "Exportieren": "Export",
        "Duplikate entfernen?": "Remove duplicates?",
        "Pro Adresse bleibt der beste Eintrag (Favorit und Beschreibung zuerst). Die anderen landen im Papierkorb.": "For each address the best entry is kept (favorite and description first). The others go to the trash.",
        "Entfernen": "Remove", "Fertig": "Done",

        // Rückfragen und allgemeine Meldungen
        "Löschen?": "Delete?", "Dieser Vorgang kann nicht rückgängig gemacht werden.": "This cannot be undone.",
        "Gespeichert": "Saved", "Gespeichert.": "Saved.", "Fehler": "Error", "Gelöscht": "Deleted", "Rückgängig": "Undo",
        "Löschen fehlgeschlagen": "Deleting failed", "Wiederhergestellt": "Restored", "Verschoben": "Moved",
        "Favoriten gesetzt": "Favorites updated", "Umbenannt": "Renamed", "Ordner aufgelöst": "Folder dissolved", "Erledigt": "Done",
        "Tastenkürzel": "Keyboard shortcuts", "Überall": "Everywhere", "Suchen": "Search", "Neuen Link anlegen": "Add a new link",
        "Ansicht wechseln": "Switch view", "Diese Hilfe": "This help", "Schließen, Suche leeren": "Close, clear search",
        "Eintrag unter Maus oder Rahmen": "Entry under mouse or frame", "Seite öffnen": "Open page", "Eintrag wechseln": "Move between entries", "Markieren an/aus": "Select on/off",
        "Beim Wandern markieren": "Select while moving", "Alle angezeigten markieren": "Select all shown", "Markierte löschen": "Delete selected",
        "Entf": "Del", "Leertaste": "Space",
        "Das ist kein Web-Link": "This is not a web link", "Kopieren fehlgeschlagen": "Copying failed", "URL kopiert": "URL copied",
        "Keine Verbindung zum Server.": "No connection to the server.",
        "Sitzung abgelaufen, bitte neu anmelden": "Session expired, please sign in again",
        "Sicherheits-Token abgelaufen. Bitte Seite neu laden.": "Security token expired. Please reload the page.",
        "Später": "Later", "Ansehen": "View", "Dein Passwort": "Your password",

        // Link-Check
        "Link-Check": "Link check", "Prüfung läuft…": "Check in progress…", "Auswahl löschen": "Delete selection",
        "Sicher weg": "Definitely gone", "Unklar, bitte selbst ansehen": "Unclear, please have a look yourself",
        "Keine Links zum Prüfen.": "No links to check.", "Archiv-Kopie": "Archived copy", "Selbst ansehen": "Have a look yourself",
        "keine prüfbare Adresse": "not a checkable address", "Seite nicht gefunden": "page not found",
        "lokale Adresse, vom Server aus nicht prüfbar": "local address, cannot be checked from the server",
        "Domain existiert nicht mehr": "domain no longer exists", "Server kann gerade keine Adressen auflösen": "the server cannot resolve addresses right now",
        "Zeitüberschreitung": "timeout", "keine Antwort": "no response", "Seite blockt automatische Abfragen": "the site blocks automated requests",
        "Serverfehler, evtl. nur vorübergehend": "server error, possibly only temporary", "unerwartete Antwort": "unexpected response",
        "nicht geprüft": "not checked",

        // Ordner verwalten
        "Namen ändern und mit Enter oder dem Haken speichern. Beim Auflösen wandern die Links nach „Allgemein“, gelöscht wird nichts.":
            "Change names and save with Enter or the check mark. Dissolving a folder moves its links to “Allgemein” (the default folder), nothing is deleted.",
        "Noch keine Ordner.": "No folders yet.", "Ordnername": "Folder name", "Namen speichern": "Save name", "Ordner auflösen": "Dissolve folder",
        "Ordner zusammenlegen?": "Merge folders?", "Zusammenlegen": "Merge", "Ordner auflösen?": "Dissolve folder?", "Auflösen": "Dissolve",

        // Papierkorb
        "Der Papierkorb ist leer.": "The trash is empty.", "Zurückholen": "Restore", "Endgültig löschen": "Delete permanently",
        "Alle zurückholen": "Restore all", "Papierkorb leeren": "Empty trash", "Papierkorb leeren?": "Empty the trash?",

        // Backups
        "LinkVault sichert automatisch: einen Stand pro Tag und einen vor jeder großen Aktion.": "LinkVault backs up automatically: one snapshot per day and one before every major action.",
        "Komplett-Backup als Datei": "Full backup as a file",
        "Eine einzige Datei mit allen Links, verschlüsselt. Sie lässt sich nur mit deinem Passwort von heute öffnen. Am besten ab und zu herunterladen und woanders aufheben.":
            "A single file with all your links, encrypted. It can only be opened with your password as it is today. Best download it now and then and keep it somewhere else.",
        "Komplett-Backup herunterladen": "Download full backup", "Backup-Datei einspielen": "Restore from a backup file",
        "Eine früher heruntergeladene .lvbak-Datei zurückholen. Gefragt ist das Passwort, das beim Herunterladen galt.":
            "Bring back a previously downloaded .lvbak file. You need the password that was valid when it was downloaded.",
        "Passwort des Backups": "Password of the backup", "Art des Einspielens": "How to restore",
        "Nur fehlende Links ergänzen": "Only add missing links",
        "Alles ersetzen (jetziger Stand wird vorher gesichert)": "Replace everything (the current state is backed up first)",
        "Einspielen": "Restore", "Lade…": "Loading…",
        "Noch keine Backups. Das erste entsteht bei der nächsten Änderung.": "No backups yet. The first one is created with your next change.",
        "Stand zurückholen?": "Restore this snapshot?", "Erst eine .lvbak-Datei wählen": "Choose a .lvbak file first",
        "Passwort des Backups eingeben": "Enter the password of the backup", "Alles ersetzen?": "Replace everything?",
        "Deine jetzigen Links werden durch das Backup ersetzt. Der jetzige Stand wird vorher gesichert.": "Your current links will be replaced by the backup. The current state is backed up first.",
        "Ersetzen": "Replace",
        "Tagesstand": "daily snapshot", "vor Änderung": "before a change", "vor Mehrfach-Löschen": "before bulk delete",
        "vor Duplikate entfernen": "before removing duplicates", "vor Import": "before import", "vor Wiederherstellung": "before restore",
        "vor Ordner löschen": "before dissolving a folder",

        // Schnell speichern / App
        "Schnell speichern": "Quick save",
        "Zieh den Knopf in deine Lesezeichenleiste. Ein Klick darauf öffnet LinkVault, Adresse und Titel der aktuellen Seite sind dann schon eingetragen.":
            "Drag the button to your bookmarks bar. Clicking it opens LinkVault with the address and title of the current page already filled in.",
        "Als App aufs Handy": "As an app on your phone",
        "iPhone: in Safari auf „Teilen“ tippen, dann „Zum Home-Bildschirm“. Android: im Browser-Menü „App installieren“ wählen, danach taucht LinkVault auch beim Teilen einer Seite in der Liste auf.":
            "iPhone: tap “Share” in Safari, then “Add to Home Screen”. Android: choose “Install app” in the browser menu, after that LinkVault also shows up in the list when you share a page.",
        "Jetzt als App installieren": "Install as an app now",
        "Ohne App: den Code kopieren und als Adresse eines Lesezeichens einfügen.": "Without the app: copy the code and paste it as the address of a bookmark.",
        "Code kopieren": "Copy code", "Code kopiert": "Code copied",
        "Nicht klicken, in die Lesezeichenleiste ziehen": "Don't click, drag it to the bookmarks bar",
        "LinkVault ist jetzt als App installiert": "LinkVault is now installed as an app",
        "LinkVault läuft gerade als App. Unter Android findest du es jetzt auch beim Teilen einer Seite in der Liste.":
            "LinkVault is currently running as an app. On Android you will now also find it in the list when you share a page.",

        // Konto & Sicherheit
        "Aktuelles Passwort": "Current password",
        "Nötig als Bestätigung für alles in diesem Fenster, außer „Automatisch abmelden“.": "Needed to confirm everything in this window, except “Sign out automatically”.",
        "Benutzername und Passwort ändern": "Change user name and password", "Neuer Benutzername": "New user name",
        "leer = unverändert": "empty = unchanged", "leer = nur Name ändern": "empty = change the name only",
        "Zugangsdaten speichern": "Save credentials",
        "Nach einem Passwortwechsel werden alle anderen Geräte abgemeldet. Deine Links und Backups bleiben lesbar.": "After a password change all other devices are signed out. Your links and backups stay readable.",
        "Zwei-Faktor-Anmeldung (2FA)": "Two-factor sign-in (2FA)", "Einrichten": "Set up", "Abschalten": "Switch off",
        "1. Diesen Schlüssel in deine Authenticator-App eintragen (Aegis, 2FAS, Google Authenticator …). Am Handy reicht der Knopf darunter.":
            "1. Enter this key in your authenticator app (Aegis, 2FAS, Google Authenticator …). On your phone the button below is enough.",
        "In App öffnen": "Open in app", "Schlüssel kopieren": "Copy key", "Schlüssel kopiert": "Key copied",
        "2. Den 6-stelligen Code aus der App eingeben. Oben muss dein aktuelles Passwort stehen.": "2. Enter the 6-digit code from the app. Your current password must be filled in at the top.",
        "Aktivieren": "Activate", "Neuen Code erzeugen": "Create new code", "Kopieren": "Copy",
        "Automatisch abmelden": "Sign out automatically", "Automatisch abmelden nach": "Sign out automatically after",
        "Nach so langer Pause musst du dich neu anmelden. Bis 8 Stunden endet die Anmeldung zusätzlich, wenn der Browser geschlossen wird.":
            "After a break this long you have to sign in again. Up to 8 hours, the session also ends when the browser is closed.",
        "nach 15 Minuten": "after 15 minutes", "nach 1 Stunde": "after 1 hour", "nach 8 Stunden": "after 8 hours",
        "nach 1 Tag (angemeldet bleiben)": "after 1 day (stay signed in)", "nach 7 Tagen (angemeldet bleiben)": "after 7 days (stay signed in)",
        "nach 30 Tagen (angemeldet bleiben)": "after 30 days (stay signed in)",
        "Oben erst das aktuelle Passwort eingeben": "Enter your current password at the top first",
        "Aktiv.": "Active.", "Beim Anmelden wird zusätzlich ein Code aus deiner App verlangt.": "Signing in additionally requires a code from your app.",
        "Nicht aktiv. Mit 2FA braucht ein Angreifer außer dem Passwort auch dein Handy.": "Not active. With 2FA an attacker needs your phone in addition to the password.",
        "Ein Code ist hinterlegt.": "A code is on file.",
        "Damit kommst du wieder rein, wenn du das Passwort vergisst oder das Handy mit der 2FA-App weg ist.": "It gets you back in if you forget the password or lose the phone with the 2FA app.",
        "Noch kein Code.": "No code yet.",
        "Ohne ihn sind deine Links bei vergessenem Passwort für immer verloren, das ist der Preis der Verschlüsselung.": "Without it your links are lost for good if you forget the password, that is the price of encryption.",
        "Jetzt aufschreiben oder im Passwort-Manager ablegen.": "Write it down now or store it in your password manager.",
        "Der Code wird nur dieses eine Mal angezeigt und liegt nirgends im Klartext.": "The code is shown only this once and is not stored anywhere in plain text.",
        "Neues Passwort: mind. 12 Zeichen": "New password: at least 12 characters",
        "Neue Passwörter stimmen nicht überein": "The new passwords do not match", "Nichts zu ändern": "Nothing to change",
        "Tipp: jetzt gleich einen Wiederherstellungscode erzeugen": "Tip: create a recovery code right now",
        "2FA abschalten?": "Switch off 2FA?", "Danach reicht wieder das Passwort allein.": "After that the password alone is enough again.",
        "Neuen Code erzeugen?": "Create a new code?", "Der bisherige Wiederherstellungscode wird damit ungültig.": "This makes the previous recovery code invalid.",
        "Abmelden fehlgeschlagen": "Signing out failed",

        // Anmeldeversuche
        "Liste leeren": "Clear list", "Erfolgreich angemeldet": "Signed in successfully", "Name oder Passwort falsch": "Wrong name or password",
        "Passwort richtig, 2FA-Code falsch": "Password correct, 2FA code wrong", "Wiederherstellungscode falsch": "Wrong recovery code",
        "Versuch während einer Sperre": "Attempt during a lockout", "Unbekannt": "Unknown",
        "Keine Fehlversuche": "No failed attempts",
        "Dein Server hat die PHP-Erweiterung „sodium“ nicht, deshalb werden nur Zeit und Art notiert.": "Your server lacks the PHP extension “sodium”, so only time and type are recorded.",
        "Viele Versuche von fremden Adressen? Dann lohnt sich zusätzlich der Ordnerschutz deines Hosters oder 2FA.": "Many attempts from unknown addresses? Then your host's directory protection or 2FA is worth adding.",
        "Noch nichts protokolliert.": "Nothing logged yet.", "Liste leeren?": "Clear the list?",
        "Alle protokollierten Anmeldeversuche werden gelöscht.": "All logged sign-in attempts will be deleted.", "Leeren": "Clear",
        "Keine Fehlversuche seit deinem letzten Login": "No failed attempts since your last sign-in",
        "Neue Zugangsanfrage": "New access request",
        "Der Ordner data/ ist nicht geschützt": "The data/ folder is not protected", "Verstanden": "Got it",
        "Dein Webserver liefert Dateien aus dem Ordner data/ an jeden aus, der die Adresse kennt. Deine Links sind zwar verschlüsselt, aber dort liegt auch die Datei mit deinem Passwort-Schutz. Das solltest du gleich abstellen.":
            "Your web server hands out files from the data/ folder to anyone who knows the address. Your links are encrypted, but the file with your password protection is stored there too. You should fix this right away.",
        "Den Block aus der Datei data/nginx-deny.conf in die Server-Konfiguration übernehmen und Nginx neu laden.":
            "Copy the block from the file data/nginx-deny.conf into the server configuration and reload Nginx.",
        "Für diesen Ordner „AllowOverride All“ einschalten, dann greifen die mitgelieferten .htaccess-Dateien.":
            "Switch on “AllowOverride All” for this folder, then the bundled .htaccess files take effect.",
        "Die Meldung kommt bei jedem Öffnen, bis der Ordner gesperrt ist. Mehr dazu steht in der README.":
            "This message appears every time you open LinkVault until the folder is locked. The README has the details.",

        // Benutzer verwalten
        "Wartet auf deine Freigabe": "Waiting for your approval", "Benutzer": "Users", "Neue Zugangsanfragen": "New access requests",
        "Ist das an, steht auf der Anmeldeseite „Zugang anfragen“. Rein kommt trotzdem nur, wen du hier freigibst.":
            "When this is on, the sign-in page shows “Request access”. Still, only people you approve here get in.",
        "Neue Zugangsanfragen annehmen": "Accept new access requests", "Gut zu wissen": "Good to know",
        "Jeder Benutzer hat einen eigenen Bereich mit eigenem Schlüssel. Du siehst hier nur die Namen, nie die Links der anderen, und die anderen sehen deine nicht. Ein vergessenes Passwort kannst du deshalb auch nicht zurücksetzen, dafür hat jeder seinen eigenen Wiederherstellungscode unter Konto & Sicherheit.":
            "Every user has their own area with their own key. You only see the names here, never other people's links, and they do not see yours. That is also why you cannot reset a forgotten password; instead everyone has their own recovery code under Account & security.",
        "Freigeben": "Approve", "Ablehnen": "Reject", "Administrator, das bist du": "Administrator, that's you",
        "gesperrt": "blocked", "dabei seit unbekannt": "member since unknown", "2FA aktiv": "2FA on",
        "Entsperren": "Unblock", "Sperren": "Block", "Benutzer löschen": "Delete user",
        "Anfragen sind möglich": "Requests are possible", "Anfragen sind abgeschaltet": "Requests are switched off",
        "Eine neue Zugangsanfrage wartet auf dich": "A new access request is waiting for you",
        "Anfrage ablehnen?": "Reject the request?",
        "Der Benutzer wird sofort überall abgemeldet und kommt nicht mehr rein. Seine Links bleiben erhalten, du kannst die Sperre jederzeit aufheben.":
            "The user is signed out everywhere immediately and cannot get back in. Their links are kept, and you can lift the block at any time.",
        "Das Konto wird mit allen Links und Backups dieses Benutzers endgültig gelöscht. Das lässt sich nicht zurückholen. Zur Bestätigung dein eigenes Passwort:":
            "The account is permanently deleted together with all links and backups of this user. This cannot be undone. To confirm, enter your own password:",

        "bookmarks.json ist beschädigt und wird nicht überschrieben. Unter Werkzeuge → Backups kannst du einen Stand zurückholen.":
            "bookmarks.json is damaged and will not be overwritten. You can restore a snapshot under Tools → Backups.",

        // Meldungen vom Server
        "Benutzer nicht gefunden.": "User not found.", "Das darf nur der Administrator.": "Only the administrator may do that.",
        "Schlüssel konnte nicht geschützt werden.": "The key could not be protected.", "Verschlüsselung fehlgeschlagen.": "Encryption failed.",
        "Passwort: mindestens 12 Zeichen.": "Password: at least 12 characters.",
        "Passwort: höchstens 1024 Zeichen.": "Password: at most 1024 characters.",
        "Passwort muss Buchstaben und Zahlen enthalten.": "The password must contain letters and digits.",
        "Benutzername: 2–64 Zeichen.": "User name: 2–64 characters.", "Setup war schon erledigt. Bitte anmelden.": "Setup was already done. Please sign in.",
        "Passwort-Hash fehlgeschlagen.": "Password hashing failed.",
        "Speichern von lv_auth.json fehlgeschlagen (Schreibrechte?).": "Saving lv_auth.json failed (write permissions?).",
        "Der Benutzername enthält unzulässige Zeichen.": "The user name contains characters that are not allowed.",
        "LinkVault ist noch nicht eingerichtet.": "LinkVault has not been set up yet.",
        "Neue Anfragen sind im Moment geschlossen.": "New requests are closed at the moment.",
        "Der Ordner für Benutzer konnte nicht angelegt werden (Schreibrechte?).": "The folder for users could not be created (write permissions?).",
        "Dieser Benutzername ist schon vergeben.": "This user name is already taken.",
        "Im Moment werden keine weiteren Anfragen angenommen. Bitte später noch einmal versuchen.": "No further requests are being accepted at the moment. Please try again later.",
        "Das Konto konnte nicht angelegt werden (Schreibrechte?).": "The account could not be created (write permissions?).",
        "Das Konto konnte nicht gespeichert werden (Schreibrechte?).": "The account could not be saved (write permissions?).",
        "Kein Schlüssel vorhanden, bitte neu anmelden.": "No key available, please sign in again.",
        "Speichern fehlgeschlagen.": "Saving failed.", "Verzeichnis nicht beschreibbar.": "The directory is not writable.",
        "bookmarks.json nicht beschreibbar.": "bookmarks.json is not writable.", "Schreibvorgang fehlgeschlagen.": "The write operation failed.",
        "Bitte Schreibrechte für den Ordner data/ prüfen.": "Please check the write permissions for the data/ folder.",
        "URL fehlt.": "The URL is missing.", "Nur http- und https-Links sind erlaubt.": "Only http and https links are allowed.",
        "Ungültige URL.": "Invalid URL.",
        "Sicherheits-Token ungültig oder fehlt. Seite neu laden.": "Security token invalid or missing. Reload the page.",
        "JSON-Datei ist ungültig.": "The JSON file is invalid.",
        "Das ist ein Komplett-Backup. Bitte unter Werkzeuge → Backups einspielen.": "This is a full backup. Please restore it under Tools → Backups.",
        "PHP-Erweiterung DOM fehlt auf dem Server.": "The PHP extension DOM is missing on the server.",
        "Datei-Upload fehlgeschlagen.": "File upload failed.", "Datei ist zu groß.": "The file is too large.",
        "Datei konnte nicht gelesen werden.": "The file could not be read.",
        "Zu viele falsche Eingaben, du wurdest abgemeldet.": "Too many wrong entries, you have been signed out.",
        "Aktuelles Passwort ist falsch.": "The current password is wrong.",
        "Datenschlüssel konnte nicht gelesen werden.": "The data key could not be read.",
        "Logout nur per POST.": "Sign-out only via POST.", "Abgemeldet.": "Signed out.", "Diese Aktion geht nur per POST.": "This action only works via POST.",
        "Nicht angemeldet.": "Not signed in.",
        "bookmarks.json ist beschädigt und wird nicht überschrieben. Bitte unter Werkzeuge → Backups einen Stand wiederherstellen.":
            "bookmarks.json is damaged and will not be overwritten. Please restore a snapshot under Tools → Backups.",
        "Kein Konto eingerichtet.": "No account set up.", "Ungültige Zeitangabe.": "Invalid time value.",
        "Speichern fehlgeschlagen (Schreibrechte?).": "Saving failed (write permissions?).", "Keine Änderung.": "No change.",
        "Speichern der Zugangsdaten fehlgeschlagen (Schreibrechte?).": "Saving the credentials failed (write permissions?).",
        "Benutzername geändert.": "User name changed.", "Neue Passwörter stimmen nicht überein.": "The new passwords do not match.",
        "Zugangsdaten gespeichert. Andere Geräte wurden abgemeldet.": "Credentials saved. Other devices have been signed out.",
        "Bitte die Einrichtung noch einmal starten.": "Please start the setup again.",
        "Der Code stimmt nicht. Uhrzeit am Handy prüfen und neuen Code eingeben.": "The code is wrong. Check the time on your phone and enter a new code.",
        "Zwei-Faktor-Anmeldung ist jetzt aktiv.": "Two-factor sign-in is now active.",
        "Zwei-Faktor-Anmeldung ist abgeschaltet.": "Two-factor sign-in is switched off.",
        "Neuer Wiederherstellungscode erzeugt. Ein älterer Code gilt nicht mehr.": "New recovery code created. An older code is no longer valid.",
        "Diese Anfrage ist schon erledigt.": "This request has already been handled.", "Dieser Benutzer ist nicht aktiv.": "This user is not active.",
        "Dieser Benutzer ist nicht gesperrt.": "This user is not blocked.", "Löschen fehlgeschlagen (Schreibrechte?).": "Deleting failed (write permissions?).",
        "Neue Zugangsanfragen sind wieder möglich.": "New access requests are possible again.",
        "Es werden keine neuen Zugangsanfragen mehr angenommen.": "New access requests are no longer accepted.",
        "Titel und URL sind erforderlich.": "Title and URL are required.", "Link hinzugefügt.": "Link added.",
        "Titel darf nicht leer sein.": "The title must not be empty.", "Link nicht gefunden.": "Link not found.", "Link aktualisiert.": "Link updated.",
        "Keine Links ausgewählt.": "No links selected.", "Link in den Papierkorb gelegt.": "Link moved to the trash.",
        "Nichts zum Wiederherstellen.": "Nothing to restore.", "Ordner fehlt.": "The folder is missing.",
        "Als Favorit markiert.": "Marked as favorite.", "Aus Favoriten entfernt.": "Removed from favorites.",
        "Ordnername fehlt.": "The folder name is missing.", "Ordner nicht gefunden.": "Folder not found.",
        "„Allgemein“ ist der Standard-Ordner.": "“Allgemein” is the default folder.",
        "Keine Duplikate gefunden.": "No duplicates found.", "Keine Ergebnisse.": "No results.",
        "Diese Adresse kann der Server nicht abrufen.": "The server cannot fetch this address.", "Seite antwortet nicht.": "The page does not respond.",
        "Kein Titel gefunden.": "No title found.", "Backup nicht gefunden.": "Backup not found.",
        "Backup ist nicht lesbar (Entschlüsselung fehlgeschlagen).": "The backup cannot be read (decryption failed).",
        "Backup ist nicht lesbar.": "The backup cannot be read.", "Nichts zu sichern.": "Nothing to back up.",
        "Das ist keine LinkVault-Backup-Datei (.lvbak).": "This is not a LinkVault backup file (.lvbak).",
        "Passwort passt nicht zu diesem Backup. Gemeint ist das Passwort von damals.": "The password does not match this backup. What is needed is the password from back then.",
        "Backup ist beschädigt.": "The backup is damaged.",
        "Die aktuellen Daten sind beschädigt. Bitte „Alles ersetzen“ wählen.": "The current data is damaged. Please choose “Replace everything”.",
        "Unbekannte Aktion.": "Unknown action.", "Interner Fehler.": "Internal error."
    };

    // Datum 12.11.2026, 18:35 → 2026-11-12 18:35 (eindeutig, egal wo man wohnt)
    var iso = function (s) { return s.replace(/(\d{2})\.(\d{2})\.(\d{4}), (\d{2}:\d{2})/g, '$3-$2-$1 $4'); };
    var sub = function (s) { var t = one(s); return t === null ? s : t; };

    // Texte mit eingesetzten Werten
    var R = [
        [/^Alle Links mit #(.+)$/, 'All links tagged #$1'],
        [/^Beim letzten Link-Check am (.+) nicht erreichbar$/, 'Unreachable at the last link check on $1'],
        [/^(\d+) Links$/, function (m) { return m[1] + (m[1] === '1' ? ' link' : ' links'); }], [/^(\d+) Ordner$/, '$1 folders'], [/^(\d+) Favoriten$/, '$1 favorites'],
        [/^angemeldet als (.+) \(Administrator\)$/, 'signed in as $1 (administrator)'], [/^angemeldet als (.+)$/, 'signed in as $1'],
        [/^(\d+) Links löschen\?$/, 'Delete $1 links?'],
        [/^Sie landen im Papierkorb und lassen sich (\d+) Tage lang zurückholen\.$/, 'They go to the trash and can be restored for $1 days.'],
        [/^Gelöschte Links bleiben (\d+) Tage hier liegen und verschwinden danach von selbst\.$/, 'Deleted links stay here for $1 days and then disappear on their own.'],
        [/^(\d+) Link\(s\) verschieben\. Unterordner legst du mit „Ordner > Unterordner“ an\.$/, 'Move $1 link(s). Create subfolders with “Folder > Subfolder”.'],
        [/^Ordner „(.+)“ gewählt$/, 'Folder “$1” selected'],
        [/^„(.+)“ im Ordner (.+)\. Trotzdem noch mal speichern\?$/, '“$1” in folder $2. Save it again anyway?'],
        [/^(\d+) neue Links, (\d+) sind schon da$/, '$1 new links, $2 already exist'], [/^(\d+) neue Links$/, '$1 new links'],
        [/^In (\d+) Ordner\(n\): (.+)$/, 'In $1 folder(s): $2'],
        [/^(\d+) Links importieren$/, 'Import $1 links'],
        [/^Auswahl löschen \((\d+)\)$/, 'Delete selection ($1)'],
        [/^Prüfe (\d+) Link\(s\) in der aktuellen Ansicht…$/, 'Checking $1 link(s) in the current view…'], [/^Prüfe (\d+) Link\(s\)…$/, 'Checking $1 link(s)…'],
        [/^(\d+) von (\d+) geprüft in der aktuellen Ansicht…$/, '$1 of $2 checked in the current view…'], [/^(\d+) von (\d+) geprüft…$/, '$1 of $2 checked…'],
        [/^Fertig: (\d+) erreichbar, (\d+) sicher weg, (\d+) unklar\.(?: (\d+) konnten nicht geprüft werden\.)?( Alles sauber\.| Auffällige Links sind jetzt markiert und oben unter „Tote Links“ zu finden\.)$/, function (m) {
            return 'Done: ' + m[1] + ' reachable, ' + m[2] + ' definitely gone, ' + m[3] + ' unclear.'
                + (m[4] ? ' ' + m[4] + ' could not be checked.' : '')
                + (m[5] === ' Alles sauber.' ? ' All clean.' : ' Suspicious links are now marked and can be found at the top under “Dead links”.');
        }],
        [/^„(.+)“ gibt es schon\. Beide Ordner werden zusammengelegt\.$/, '“$1” already exists. Both folders will be merged.'],
        [/^Die Links aus „(.+)“ bleiben erhalten und rutschen eine Ebene höher bzw\. nach „Allgemein“\.$/, 'The links from “$1” are kept and move up one level or to “Allgemein”.'],
        [/^gelöscht am (.+)$/, 'deleted on $1'],
        [/^(\d+) Link\(s\) werden endgültig gelöscht\.$/, '$1 link(s) will be deleted permanently.'],
        [/^(\d+) Einträge$/, function (m) { return m[1] + (m[1] === '1' ? ' entry' : ' entries'); }],
        [/^Stand vom (.+) Uhr\. Der jetzige Stand wird vorher selbst als Backup gesichert\.$/, 'Snapshot from $1. The current state is itself saved as a backup first.'],
        [/^leer = unverändert \((.+)\)$/, 'empty = unchanged ($1)'],
        [/^(\d+) Fehlversuch\(e\) im Protokoll$/, '$1 failed attempt(s) in the log'],
        [/^Letzte 24 Stunden: (\d+)(\.?)$/, 'Last 24 hours: $1$2'], [/^letzte 7 Tage: (\d+)(\.?)$/, 'last 7 days: $1$2'],
        [/^von (\d+) Adresse\(n\)(\.?)$/, 'from $1 address(es)$2'],
        [/^(.+) als „(.+)“$/, function (m) { return sub(m[1]) + ' as “' + m[2] + '”'; }],
        [/^angefragt am (.+) Uhr$/, 'requested on $1'], [/^von ([0-9a-fA-F:.]+)$/, 'from $1'],
        [/^dabei seit (.+) Uhr$/, 'member since $1'],
        [/^Die Anfrage von „(.+)“ wird gelöscht\.$/, 'The request from “$1” will be deleted.'],
        [/^„(.+)“ sperren\?$/, 'Block “$1”?'], [/^„(.+)“ löschen\?$/, 'Delete “$1”?'],
        [/^Ansicht: (.+)$/, function (m) { return 'View: ' + sub(m[1]); }],
        [/^(\d+) neue Zugangsanfragen$/, '$1 new access requests'],
        [/^(.+) (möchten?) LinkVault mitbenutzen und warte[tn] auf deine Freigabe\. Ohne dein Okay kommt niemand rein\.$/, function (m) {
            var many = m[2] === 'möchten';
            return m[1].replace(/ und weitere$/, ' and others') + (many ? ' would like to use LinkVault too and are' : ' would like to use LinkVault too and is')
                + ' waiting for your approval. Nobody gets in without your OK.';
        }],
        [/^(\d+) fehlgeschlagener? Anmeldeversuche?$/, function (m) { return m[1] + ' failed sign-in attempt' + (m[1] === '1' ? '' : 's'); }],
        [/^Seit deiner letzten Anmeldung hat jemand (?:einmal|(\d+) Mal) versucht, sich hier anzumelden(?:, von (\d+) Adressen?)?\. Hast du dich selbst vertippt, ist alles gut\.$/, function (m) {
            return 'Since your last sign-in someone has tried to sign in here ' + (m[1] ? m[1] + ' times' : 'once')
                + (m[2] ? ', from ' + m[2] + ' address' + (m[2] === '1' ? '' : 'es') : '') + '. If it was you mistyping, everything is fine.';
        }],
        [/^Deine letzte Anmeldung war am (.+?) Uhr(?: von (.+))?\.$/, function (m) { return 'Your last sign-in was on ' + m[1] + (m[2] ? ' from ' + m[2] : '') + '.'; }],
        [/^Server-Antwort ungültig \(HTTP (\d+)\)\. Schreibrechte oder PHP-Fehler prüfen\.$/, 'Invalid server response (HTTP $1). Check write permissions or PHP errors.'],
        // vom Server
        [/^Zu viele Fehlversuche\. Bitte in ca\. (\d+) Minute\(n\) erneut versuchen\.$/, 'Too many failed attempts. Please try again in about $1 minute(s).'],
        [/^Zu viele Fehlversuche\. Bitte in (\d+) Sekunde\(n\) erneut versuchen\.$/, 'Too many failed attempts. Please try again in $1 second(s).'],
        [/^„(.+)“ ist freigeschaltet und kann sich jetzt anmelden\.$/, '“$1” is approved and can sign in now.'],
        [/^„(.+)“ ist gesperrt und überall abgemeldet\. Die Links bleiben erhalten\.$/, '“$1” is blocked and signed out everywhere. The links are kept.'],
        [/^„(.+)“ darf sich wieder anmelden\.$/, '“$1” may sign in again.'],
        [/^Anfrage von „(.+)“ abgelehnt\.$/, 'Request from “$1” rejected.'],
        [/^„(.+)“ wurde samt allen Links gelöscht\.$/, '“$1” has been deleted together with all links.'],
        [/^(\d+) Links in den Papierkorb gelegt\.$/, '$1 links moved to the trash.'],
        [/^(\d+) Link\(s\) wiederhergestellt\.$/, '$1 link(s) restored.'],
        [/^(\d+) Link\(s\) endgültig gelöscht\.$/, '$1 link(s) deleted permanently.'],
        [/^(\d+) Link\(s\) nach „(.+)“ verschoben\.$/, '$1 link(s) moved to “$2”.'],
        [/^Ordner umbenannt \((\d+) Links\)\.$/, 'Folder renamed ($1 links).'],
        [/^Ordner aufgelöst, (\d+) Link\(s\) liegen jetzt in „(.+)“\.$/, 'Folder dissolved, $1 link(s) are now in “$2”.'],
        [/^(\d+) Duplikat\(e\) in den Papierkorb gelegt\.$/, '$1 duplicate(s) moved to the trash.'],
        [/^Stand wiederhergestellt \((\d+) Links\)\.$/, 'Snapshot restored ($1 links).'],
        [/^Backup eingespielt \((\d+) Einträge\), der alte Stand liegt bei den Backups\.$/, 'Backup restored ($1 entries), the previous state is among the backups.'],
        [/^(\d+) neue Link\(s\) aus dem Backup übernommen\.$/, '$1 new link(s) taken over from the backup.'],
        [/^(\d+) Links importiert\.(?: (\d+) waren schon da\.)?$/, function (m) { return m[1] + ' links imported.' + (m[2] ? ' ' + m[2] + ' already existed.' : ''); }],
        // Automatisch sortieren (3.4)
        [/^Übernehmen \((\d+)\)$/, 'Apply ($1)'],
        [/^Für (\d+) Link\(s\)( in der aktuellen Ansicht)? gibt es keine neuen Vorschläge\.$/, function (m) {
            return 'No new suggestions for ' + m[1] + ' link(s)' + (m[2] ? ' in the current view' : '') + '.';
        }],
        [/^(\d+) von (\d+) Link\(s\)( in der aktuellen Ansicht)? bekommen Vorschläge\. Antippen schaltet einzelne Vorschläge ab\.$/, function (m) {
            return m[1] + ' of ' + m[2] + ' link(s)' + (m[3] ? ' in the current view' : '') + ' get suggestions. Tap a suggestion to switch it off.';
        }],
        [/^Die Liste zeigt die ersten (\d+)\. Übernommen werden alle (\d+), die Schalter oben gelten für alle\.$/,
            'The list shows the first $1. All $2 will be applied, the switches at the top apply to all of them.'],
        [/^Stichwort „([^“]+)“ \(([^·]+)\)$/, function (m) { return 'keyword “' + m[1] + '” (' + sub(m[2]) + ')'; }],
        [/^Domain ([^\s·]+) \(([^·]+)\)$/, function (m) { return 'domain ' + m[1] + ' (' + sub(m[2]) + ')'; }],
        [/^wie deine anderen Links von ([^\s·]+)$/, 'like your other links from $1'],
        [/^Gruppe „(.+)“ gelöscht$/, 'Group “$1” deleted'],
        [/^Ordner „(.+)“ löschen\?$/, 'Delete folder “$1”?'],
        [/^Nur der Ordner verschwindet\. Die (\d+) Link\(s\) darin bleiben erhalten und kommen nach „Allgemein“ \(bei Unterordnern eine Ebene höher\)\.$/,
            'Only the folder disappears. Its $1 link(s) are kept and move to “Allgemein” (one level up for subfolders).'],
        [/^Ordner gelöscht, (\d+) Link\(s\) liegen jetzt in „(.+)“\.$/, 'Folder deleted, $1 link(s) are now in “$2”.'],
        [/^„#(.+)“ gibt es schon\. Alle Links mit „#(.+)“ bekommen stattdessen „#(.+)“\.$/, '“#$1” already exists. All links tagged “#$2” get “#$3” instead.'],
        [/^Tag „#(.+)“ löschen\?$/, 'Delete tag “#$1”?'],
        [/^Er verschwindet von (\d+) Link\(s\)\. Die Links selbst bleiben\.$/, 'It is removed from $1 link(s). The links themselves stay.'],
        [/^Tag „(.+)“ bei (\d+) Link\(s\) entfernt\.$/, 'Tag “$1” removed from $2 link(s).'],
        [/^Tag „(.+)“ heißt jetzt „(.+)“ \((\d+) Links\)\.$/, 'Tag “$1” is now called “$2” ($3 links).'],
        [/^(\d+) Link\(s\) sortiert: (\d+) mit neuen Tags, (\d+) in andere Ordner\.$/, '$1 link(s) sorted: $2 with new tags, $3 moved to other folders.'],
        [/^(.+) Uhr$/, '$1']
    ];

    var has = Object.prototype.hasOwnProperty;
    function one(k) {
        if (has.call(D, k)) return D[k];
        for (var i = 0; i < R.length; i++) {
            var m = k.match(R[i][0]);
            if (m) return iso(typeof R[i][1] === 'function' ? R[i][1](m) : k.replace(R[i][0], R[i][1]));
        }
        return null;
    }
    // Ergebnis: englischer Text oder null (= so lassen)
    function tr(raw) {
        var k = raw.replace(/\s+/g, ' ').trim();
        if (!k || k.length > 600 || !/[A-Za-zÄÖÜäöü]/.test(k) || /^https?:\/\//i.test(k)) return null;
        var v = one(k);
        if (v !== null) return v;
        var hit = false, parts;
        // „a · b · c“: jedes Stück einzeln
        if (k.indexOf('·') >= 0) {
            parts = k.split(/ ?· ?/).map(function (p) { var t = p ? one(p) : null; if (t !== null) { hit = true; return t; } return p; });
            if (hit) return parts.join(' · ');
        }
        // Mehrere Sätze hintereinander: nur wenn jeder einzelne bekannt ist
        parts = k.match(/[^.!?]+[.!?]+(?=\s|$)/g);
        if (parts && parts.length > 1) {
            parts = parts.map(function (p) { return p.trim(); });
            if (parts.join(' ') === k) {
                var out = parts.map(one);
                if (out.every(function (t) { return t !== null; })) return out.join(' ');
            }
        }
        return null;
    }

    // Stellen mit eigenen Inhalten (Titel, Ordner, Schlagwörter, Namen) bleiben unangetastet
    var KEEP = 'script,style,textarea,datalist,.bm-title,.bm-domain,.bm-desc,.bm-tag,.user-note,.mono-box,#importFileName,#formCatLabel,'
        + '[data-movecat],.domain-group-header .truncate,#deadList .truncate,[data-lang],.as-keep';
    var SPECIAL = { all: 1, favorites: 1, dead: 1, __tagmanage: 1, __tagoff: 1 };
    // Namen der Standard-Gruppen beim Anlegen gleich auf Englisch (siehe asDefaultGroups)
    ui.tr = function (s) { var t = tr(String(s)); return t === null ? s : t; };
    function keep(el) {
        if (!el || el.closest(KEEP)) return true;
        var c = el.closest('.bm-chip');
        if (c && !c.classList.contains('bm-warn')) return true;
        c = el.closest('.cat-btn');
        if (c && !SPECIAL[c.getAttribute('data-cat')]) return true;
        c = el.closest('.cat-chip');
        if (c && c.getAttribute('data-cat') !== '__new') return true;
        if (el.tagName === 'OPTION' && el.parentElement && el.parentElement.id === 'formCategorySelect' && el.value !== '') return true;
        c = el.closest('.t1');
        if (c && !c.closest('#logList')) return true;
        return false;
    }
    function fixText(node) {
        var s = node.nodeValue;
        if (!s || keep(node.parentElement)) return;
        var t = tr(s);
        if (t === null) return;
        var out = s.match(/^\s*/)[0] + t + s.match(/\s*$/)[0];
        if (out !== s) node.nodeValue = out;
    }
    var ATTRS = ['placeholder', 'title', 'aria-label'];
    function fixAttrs(el) {
        if (el.classList && el.classList.contains('bm-title')) return;
        for (var i = 0; i < ATTRS.length; i++) {
            var v = el.getAttribute(ATTRS[i]);
            if (!v) continue;
            var t = tr(v);
            if (t !== null && t !== v) el.setAttribute(ATTRS[i], t);
        }
    }
    function walk(node) {
        if (node.nodeType === 3) { fixText(node); return; }
        if (node.nodeType !== 1) return;
        fixAttrs(node);
        var it = doc.createTreeWalker(node, 5 /* Elemente + Text */, null), n;
        while ((n = it.nextNode())) {
            if (n.nodeType === 3) fixText(n); else fixAttrs(n);
        }
    }
    try {
        walk(root);
        new MutationObserver(function (list) {
            for (var i = 0; i < list.length; i++) {
                var m = list[i];
                if (m.type === 'childList') { for (var j = 0; j < m.addedNodes.length; j++) walk(m.addedNodes[j]); }
                else if (m.type === 'characterData') fixText(m.target);
                else if (m.type === 'attributes') fixAttrs(m.target);
            }
        }).observe(root, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ATTRS });
    } catch (e) {}
    root.classList.remove('lv-wait');
    if (typeof window.syncHeaderSpacer === 'function') window.syncHeaderSpacer();
})();
LVJS;
    echo '</script>' . "\n";
}
