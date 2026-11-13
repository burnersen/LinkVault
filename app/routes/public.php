<?php
/* LinkVault – Öffentliche Abrufe: Schrift, Icon, Manifest, Service Worker, Favicons */
defined('LV_VERSION') || exit;

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
        'name' => 'LinkVault', 'short_name' => 'LinkVault', 'description' => lvBrowserEnglish() ? 'Your bookmarks, encrypted on your own server' : 'Deine Lesezeichen, verschlüsselt auf dem eigenen Server',
        'id' => './', 'start_url' => './', 'scope' => './',
        'display' => 'standalone', 'background_color' => '#0b1120', 'theme_color' => '#0b1120', 'lang' => lvBrowserEnglish() ? 'en' : 'de',
        'categories' => ['productivity', 'utilities'],
        'icons' => [
            ['src' => './?action=icon&s=192', 'sizes' => '192x192', 'type' => 'image/png', 'purpose' => 'any'],
            ['src' => './?action=icon&s=512', 'sizes' => '512x512', 'type' => 'image/png', 'purpose' => 'any'],
            ['src' => './?action=icon&s=192', 'sizes' => '192x192', 'type' => 'image/png', 'purpose' => 'maskable'],
            ['src' => './?action=icon&s=512', 'sizes' => '512x512', 'type' => 'image/png', 'purpose' => 'maskable'],
        ],
        // Langer Druck auf das App-Icon
        'shortcuts' => [
            ['name' => lvBrowserEnglish() ? 'New link' : 'Neuer Link', 'short_name' => lvBrowserEnglish() ? 'New' : 'Neu', 'url' => './?new=1', 'icons' => [['src' => './?action=icon&s=192', 'sizes' => '192x192', 'type' => 'image/png']]],
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
        . '<h1>Keine Verbindung</h1><p>LinkVault erreicht den Server gerade nicht.<br>Deine Links liegen sicher dort und sind gleich wieder da.</p><a href="./">Erneut versuchen</a></div>'
        . '<script>try{var l=localStorage.getItem("lv_lang")||(/^de/i.test(navigator.language||"de")?"de":"en");if(l==="en"){document.documentElement.lang="en";'
        . 'document.querySelector("h1").textContent="No connection";document.querySelector("p").innerHTML="LinkVault cannot reach the server right now.<br>Your links are safe there and will be back shortly.";'
        . 'document.querySelector("a").textContent="Try again"}}catch(e){}</script></body></html>';
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
    // Fremde SVG-Icons: beim direkten Aufruf in einen eigenen, leeren Ursprung sperren
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox; frame-ancestors 'none'");
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
