<?php
/* LinkVault – Abrufe nach draußen, Favicons, Link-Check, Seitentitel */
defined('LV_VERSION') || exit;

/* ---------- Abrufe nach draußen (Titel, Favicons, Link-Check), geschützt gegen Umwege ins interne Netz ---------- */

function lvIpIsPublic(string $ip): bool {
    $bin = @inet_pton($ip);
    if ($bin === false) return false;
    if (strlen($bin) === 16) {
        // IPv6-Adressen, in denen eine IPv4-Adresse steckt, in jeder Schreibweise auspacken und als IPv4 prüfen:
        // ::ffff:a.b.c.d (auch hex geschrieben), ::a.b.c.d, NAT64 (64:ff9b::/96 und 64:ff9b:1::/48), 6to4 (2002::/16)
        $v4 = null;
        if (strncmp($bin, str_repeat("\0", 10) . "\xff\xff", 12) === 0 || strncmp($bin, str_repeat("\0", 12), 12) === 0
            || strncmp($bin, "\x00\x64\xff\x9b" . str_repeat("\0", 8), 12) === 0) {
            $v4 = substr($bin, 12, 4);
        } elseif (strncmp($bin, "\x00\x64\xff\x9b\x00\x01", 6) === 0) {
            return false; // lokales NAT64: wohin das führt, lässt sich von hier nicht sagen
        } elseif (strncmp($bin, "\x20\x02", 2) === 0) {
            $v4 = substr($bin, 2, 4);
        }
        if ($v4 !== null) {
            if ($v4 === "\0\0\0\0" || $v4 === "\0\0\0\1") return false; // :: und ::1
            $ip = (string)inet_ntop($v4);
        } else {
            $ip = (string)inet_ntop($bin);
            $b0 = ord($bin[0]); $b1 = ord($bin[1]);
            if (($b0 & 0xFE) === 0xFC) return false;                 // fc00::/7 privat
            if ($b0 === 0xFE && ($b1 & 0xC0) === 0x80) return false; // fe80::/10 link-lokal
            if ($b0 === 0xFE && ($b1 & 0xC0) === 0xC0) return false; // fec0::/10 site-lokal (alt)
            if ($b0 === 0xFF) return false;                          // Multicast
        }
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return false;
    if (strpos($ip, ':') === false) {
        $n = ip2long($ip);
        if ($n === false) return false;
        if (($n & 0xFFC00000) === 0x64400000) return false; // 100.64.0.0/10 (Carrier-NAT)
        if (($n & 0xFFFFFF00) === 0xC0000000) return false; // 192.0.0.0/24 (Protokoll-Zuweisungen)
        if (($n & 0xFFFE0000) === 0xC6120000) return false; // 198.18.0.0/15 (Testnetze)
        if (($n & 0xF0000000) === 0xE0000000) return false; // 224.0.0.0/4 (Multicast)
    }
    return true;
}

/** Ergebnis: ['state' => ok|private|nx, 'ip' => geprüfte Adresse] */
function lvResolveHost(string $host): array {
    $h = trim($host, '[]');
    if (filter_var($h, FILTER_VALIDATE_IP)) {
        return lvIpIsPublic($h) ? ['state' => 'ok', 'ip' => $h] : ['state' => 'private', 'ip' => ''];
    }
    if ($h === '' || strtolower($h) === 'localhost' || strpos($h, '.') === false) return ['state' => 'private', 'ip' => ''];
    if (preg_match('/[^\x20-\x7e]/', $h) && function_exists('idn_to_ascii')) {
        $a = @idn_to_ascii($h, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        if (is_string($a) && $a !== '') $h = $a;
    }
    $all = @gethostbynamel($h) ?: [];
    if (!$all && function_exists('dns_get_record')) {
        foreach ((@dns_get_record($h, DNS_AAAA) ?: []) as $r) {
            if (!empty($r['ipv6'])) $all[] = $r['ipv6'];
        }
    }
    if (!$all) return ['state' => 'nx', 'ip' => ''];
    foreach ($all as $ip) {
        if (!lvIpIsPublic($ip)) return ['state' => 'private', 'ip' => ''];
    }
    return ['state' => 'ok', 'ip' => $all[0]];
}

function lvAbsUrl(string $base, string $loc): string {
    $loc = trim($loc);
    if (preg_match('~^[a-z][a-z0-9+.\-]*:~i', $loc)) return $loc;
    $b = parse_url($base);
    $scheme = strtolower($b['scheme'] ?? 'https');
    $origin = $scheme . '://' . ($b['host'] ?? '') . (isset($b['port']) ? ':' . $b['port'] : '');
    if (strncmp($loc, '//', 2) === 0) return $scheme . ':' . $loc;
    if ($loc !== '' && $loc[0] === '/') return $origin . $loc;
    $path = $b['path'] ?? '/';
    $dir = substr($path, 0, (int)strrpos($path, '/') + 1) ?: '/';
    return $origin . $dir . $loc;
}

/** cURL-Handle, fest auf die vorher geprüfte IP-Adresse genagelt. $state sammelt body + Weiterleitungsziel. */
/** Eindeutige Nummer eines cURL-Handles (bis PHP 7.4 eine Ressource, ab PHP 8 ein Objekt). */
function lvCurlId($ch): int {
    return is_object($ch) ? spl_object_id($ch) : (int)$ch;
}

/** Ab PHP 8 räumt sich ein Handle selbst weg, curl_close() ist dort ohne Wirkung und ab 8.5 veraltet. */
function lvCurlClose($ch): void {
    if (PHP_VERSION_ID < 80000) curl_close($ch);
}

function lvCurlMake(string $url, array $p, string $ip, bool $head, int $limit, int $timeout, string $accept, array &$state) {
    $state = ['body' => '', 'loc' => ''];
    $ch = curl_init($url);
    $port = (int)($p['port'] ?? (strtolower($p['scheme'] ?? '') === 'http' ? 80 : 443));
    curl_setopt_array($ch, [
        CURLOPT_NOBODY => $head,
        CURLOPT_FOLLOWLOCATION => false, // Weiterleitungen prüfen wir selbst, Schritt für Schritt
        CURLOPT_CONNECTTIMEOUT => min(5, $timeout),
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => LV_UA,
        CURLOPT_ENCODING => '',
        CURLOPT_HTTPHEADER => ['Accept: ' . $accept, 'Accept-Language: de,en;q=0.8'],
        CURLOPT_RESOLVE => [trim($p['host'], '[]') . ':' . $port . ':' . $ip],
        CURLOPT_HEADERFUNCTION => function ($c, $line) use (&$state) {
            if (stripos($line, 'location:') === 0) $state['loc'] = trim(substr($line, 9));
            return strlen($line);
        },
        CURLOPT_WRITEFUNCTION => function ($c, $data) use (&$state, $limit) {
            $state['body'] .= $data;
            return strlen($state['body']) > $limit ? 0 : strlen($data);
        },
    ]);
    if (defined('CURLOPT_PROTOCOLS') && defined('CURLPROTO_HTTP')) {
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    }
    return $ch;
}

/**
 * Holt eine Adresse. Jede Station (auch nach Weiterleitungen) muss eine öffentliche Adresse sein.
 * Ergebnis: code, body, ctype, url (Endadresse), errno (6 = Domain gibt es nicht, 28 = Zeit), blocked
 */
function lvSafeFetch(string $url, array $o = []): array {
    $limit = (int)($o['limit'] ?? 200000);
    $timeout = (int)($o['timeout'] ?? 8);
    $head = !empty($o['head']);
    $accept = (string)($o['accept'] ?? 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5');
    $res = ['code' => 0, 'body' => '', 'ctype' => '', 'url' => $url, 'errno' => 0, 'blocked' => false];
    for ($hop = 0; $hop <= 5; $hop++) {
        $p = parse_url($url);
        if (!$p || empty($p['host']) || !in_array(strtolower($p['scheme'] ?? ''), ['http', 'https'], true)) {
            $res['blocked'] = true;
            return $res;
        }
        $r = lvResolveHost($p['host']);
        if ($r['state'] === 'private') { $res['blocked'] = true; return $res; }
        if ($r['state'] === 'nx') { $res['errno'] = 6; return $res; }
        $res['url'] = $url;
        $loc = '';
        if (function_exists('curl_init')) {
            $state = [];
            $ch = lvCurlMake($url, $p, $r['ip'], $head, $limit, $timeout, $accept, $state);
            curl_exec($ch);
            $res['code'] = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $res['ctype'] = (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
            $res['errno'] = $res['code'] > 0 ? 0 : (int)curl_errno($ch);
            $res['body'] = $state['body'];
            $loc = $state['loc'];
            lvCurlClose($ch);
        } else {
            // Ohne cURL: direkt die geprüfte IP ansprechen, damit PHP den Namen nicht ein zweites Mal auflöst
            $host = trim($p['host'], '[]');
            $scheme = strtolower($p['scheme']);
            $ipUrl = $scheme . '://' . (strpos($r['ip'], ':') !== false ? '[' . $r['ip'] . ']' : $r['ip'])
                . (isset($p['port']) ? ':' . (int)$p['port'] : '')
                . ($p['path'] ?? '/') . (isset($p['query']) ? '?' . $p['query'] : '');
            $hostHdr = (strpos($host, ':') !== false ? '[' . $host . ']' : $host) . (isset($p['port']) ? ':' . (int)$p['port'] : '');
            $ctx = stream_context_create([
                'http' => ['method' => $head ? 'HEAD' : 'GET', 'timeout' => $timeout, 'ignore_errors' => true, 'follow_location' => 0,
                           'header' => "Host: {$hostHdr}\r\nUser-Agent: " . LV_UA . "\r\nAccept: {$accept}\r\nAccept-Language: de,en;q=0.8\r\n"],
                'ssl' => ['verify_peer' => true, 'verify_peer_name' => true, 'peer_name' => $host, 'SNI_enabled' => true],
            ]);
            $http_response_header = [];
            $body = @file_get_contents($ipUrl, false, $ctx, 0, $limit);
            $res['body'] = $body === false ? '' : $body;
            $res['code'] = 0;
            foreach (($http_response_header ?? []) as $h) {
                if (preg_match('~^HTTP/\S+\s+(\d+)~', $h, $m)) $res['code'] = (int)$m[1];
                elseif (stripos($h, 'content-type:') === 0) $res['ctype'] = trim(substr($h, 13));
                elseif (stripos($h, 'location:') === 0) $loc = trim(substr($h, 9));
            }
        }
        if ($res['code'] >= 300 && $res['code'] < 400 && $loc !== '') {
            $url = lvAbsUrl($url, $loc);
            continue;
        }
        return $res;
    }
    $res['code'] = 0;
    $res['errno'] = 47; // zu viele Weiterleitungen
    return $res;
}

function sniffImageType(string $bin): string {
    if (strncmp($bin, "\x89PNG", 4) === 0) return 'image/png';
    if (strncmp($bin, "\x00\x00\x01\x00", 4) === 0) return 'image/x-icon';
    if (strncmp($bin, 'GIF8', 4) === 0) return 'image/gif';
    if (strncmp($bin, "\xFF\xD8\xFF", 3) === 0) return 'image/jpeg';
    if (strncmp($bin, 'RIFF', 4) === 0 && substr($bin, 8, 4) === 'WEBP') return 'image/webp';
    return '';
}

function lvIconType(string $bin): string {
    $t = sniffImageType($bin);
    if ($t !== '') return $t;
    $head = ltrim(substr($bin, 0, 1000));
    if (stripos($head, '<svg') !== false && preg_match('~^(<\?xml|<svg|<!--|<!DOCTYPE)~i', $head)) return 'image/svg+xml';
    return '';
}

/** Sucht das Icon direkt bei der Seite selbst (kein Google, kein DuckDuckGo). Ergebnis: Bilddaten oder null */
function lvFindFavicon(string $domain): ?string {
    $deadline = microtime(true) + 14;
    foreach ([$domain, 'www.' . $domain] as $host) {
        $page = lvSafeFetch('https://' . $host . '/', ['limit' => 150000, 'timeout' => 5]);
        if ($page['blocked']) return null;
        if ($page['code'] === 0 && $page['body'] === '') continue;
        $cands = [];
        if ($page['body'] !== '' && preg_match_all('~<link\b[^>]*>~i', $page['body'], $m)) {
            foreach ($m[0] as $tag) {
                if (!preg_match('~\brel\s*=\s*["\']?([^"\'>]+)~i', $tag, $r)) continue;
                if (stripos($r[1], 'icon') === false || stripos($r[1], 'mask-icon') !== false) continue;
                if (!preg_match('~\bhref\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))~i', $tag, $h)) continue;
                $href = '';
                foreach ([1, 2, 3] as $i) if (isset($h[$i]) && $h[$i] !== '') { $href = $h[$i]; break; }
                $href = html_entity_decode(trim($href), ENT_QUOTES | ENT_HTML5, 'UTF-8');
                if ($href === '' || stripos($href, 'data:') === 0) continue;
                $score = 50;
                if (preg_match('~\bsizes\s*=\s*["\']?(\d+)~i', $tag, $s)) {
                    $n = (int)$s[1];
                    $score = ($n >= 32 && $n <= 192) ? 100 - (int)(abs(64 - $n) / 4) : ($n < 32 ? 30 : 40);
                }
                if (stripos($r[1], 'apple') !== false) $score -= 5;
                $cands[] = [$score, lvAbsUrl($page['url'], $href)];
            }
        }
        usort($cands, fn($a, $b) => $b[0] <=> $a[0]);
        $urls = array_slice(array_column($cands, 1), 0, 3);
        $urls[] = lvAbsUrl($page['url'], '/favicon.ico');
        foreach (array_unique($urls) as $u) {
            if (microtime(true) > $deadline) return null;
            $img = lvSafeFetch($u, ['limit' => 400000, 'timeout' => 5, 'accept' => 'image/*,*/*;q=0.5']);
            $len = strlen($img['body']);
            if ($img['code'] >= 200 && $img['code'] < 300 && $len > 20 && $len <= 400000 && lvIconType($img['body']) !== '') {
                return $img['body'];
            }
        }
        return null;
    }
    return null;
}

/* ---------- Link-Check ---------- */

/** Prüft mehrere Adressen gleichzeitig, folgt Weiterleitungen selbst. Ergebnis je Schlüssel: code, errno (-1 = lokale Adresse) */
function lvMultiProbe(array $urls, bool $head): array {
    $out = [];
    $pending = $urls;
    for ($round = 0; $round <= 5 && $pending; $round++) {
        $mh = curl_multi_init();
        $hs = [];
        $states = [];
        foreach ($pending as $k => $u) {
            $p = parse_url($u);
            $ok = $p && !empty($p['host']) && in_array(strtolower($p['scheme'] ?? ''), ['http', 'https'], true);
            $r = $ok ? lvResolveHost($p['host']) : ['state' => 'private', 'ip' => ''];
            if ($r['state'] !== 'ok') {
                $out[$k] = ['code' => 0, 'errno' => $r['state'] === 'nx' ? 6 : -1];
                continue;
            }
            $states[$k] = [];
            $hs[$k] = lvCurlMake($u, $p, $r['ip'], $head, 4096, 8, 'text/html,application/xhtml+xml,*/*;q=0.8', $states[$k]);
            curl_multi_add_handle($mh, $hs[$k]);
        }
        $errnos = [];
        do {
            $status = curl_multi_exec($mh, $running);
            while ($info = curl_multi_info_read($mh)) $errnos[lvCurlId($info['handle'])] = $info['result'];
            if ($running) curl_multi_select($mh, 1.0);
        } while ($running && $status === CURLM_OK);
        while ($info = curl_multi_info_read($mh)) $errnos[lvCurlId($info['handle'])] = $info['result'];
        $next = [];
        foreach ($hs as $k => $ch) {
            $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $errno = $code > 0 ? 0 : (int)($errnos[lvCurlId($ch)] ?? 0);
            if ($code >= 300 && $code < 400 && $states[$k]['loc'] !== '') $next[$k] = lvAbsUrl($pending[$k], $states[$k]['loc']);
            else $out[$k] = ['code' => $code, 'errno' => $errno];
            curl_multi_remove_handle($mh, $ch);
            lvCurlClose($ch);
        }
        curl_multi_close($mh);
        $pending = $next;
    }
    foreach ($pending as $k => $u) $out[$k] = ['code' => 0, 'errno' => 47];
    return $out;
}

/**
 * Prüft URLs. Ergebnis je Schlüssel: ['status' => ok|dead|unclear, 'code' => int, 'note' => string]
 * dead    = sicher weg (404/410 oder Domain existiert nicht)
 * unclear = Seite blockt Abfragen, Serverfehler, Zeitüberschreitung – bitte selbst ansehen
 */
function lvCheckUrls(array $urls): array {
    $res = [];
    $todo = [];
    foreach ($urls as $k => $u) {
        if (!preg_match('~^https?://~i', $u) || (string)parse_url($u, PHP_URL_HOST) === '') {
            $res[$k] = ['status' => 'unclear', 'code' => 0, 'note' => 'keine prüfbare Adresse'];
        } else {
            $todo[$k] = $u;
        }
    }
    $raw = [];
    if ($todo && function_exists('curl_multi_init')) {
        $raw = lvMultiProbe($todo, true);
        // Zweiter Versuch mit GET für alles, was auf HEAD nicht sauber geantwortet hat
        $retry = [];
        foreach ($raw as $k => $r) {
            $ok = $r['code'] >= 200 && $r['code'] < 400;
            if (!$ok && !in_array($r['errno'], [6, 28, -1], true)) $retry[$k] = $todo[$k];
        }
        if ($retry) {
            foreach (lvMultiProbe($retry, false) as $k => $r) {
                if ($r['code'] > 0) $raw[$k] = ['code' => $r['code'], 'errno' => 0];
                elseif ($raw[$k]['code'] === 0) $raw[$k] = $r;
            }
        }
    } else {
        foreach ($todo as $k => $u) {
            $r = lvSafeFetch($u, ['head' => true, 'timeout' => 6]);
            if ($r['code'] === 0 || $r['code'] >= 400) {
                $g = lvSafeFetch($u, ['limit' => 4096, 'timeout' => 6]);
                if ($g['code'] > 0) $r = $g;
            }
            $raw[$k] = ['code' => $r['code'], 'errno' => $r['blocked'] ? -1 : $r['errno']];
        }
    }
    $dnsWorks = null;
    foreach ($raw as $k => $r) {
        $code = $r['code'];
        if ($code >= 200 && $code < 400) {
            $res[$k] = ['status' => 'ok', 'code' => $code, 'note' => ''];
        } elseif ($code === 404 || $code === 410) {
            $res[$k] = ['status' => 'dead', 'code' => $code, 'note' => 'Seite nicht gefunden'];
        } elseif ($code === 0 && $r['errno'] === -1) {
            $res[$k] = ['status' => 'unclear', 'code' => 0, 'note' => 'lokale Adresse, vom Server aus nicht prüfbar'];
        } elseif ($code === 0 && $r['errno'] === 6) {
            // Sicherheitsnetz: Klappt die Namensauflösung auf dem Server gerade gar nicht, sähe sonst jede Seite „tot“ aus
            if ($dnsWorks === null) {
                $dnsWorks = (bool)@gethostbynamel('www.wikipedia.org') || (bool)@gethostbynamel('one.one.one.one');
            }
            $res[$k] = $dnsWorks
                ? ['status' => 'dead', 'code' => 0, 'note' => 'Domain existiert nicht mehr']
                : ['status' => 'unclear', 'code' => 0, 'note' => 'Server kann gerade keine Adressen auflösen'];
        } elseif ($code === 0) {
            $res[$k] = ['status' => 'unclear', 'code' => 0, 'note' => $r['errno'] === 28 ? 'Zeitüberschreitung' : 'keine Antwort'];
        } elseif ($code === 401 || $code === 403 || $code === 429) {
            $res[$k] = ['status' => 'unclear', 'code' => $code, 'note' => 'Seite blockt automatische Abfragen'];
        } elseif ($code >= 500) {
            $res[$k] = ['status' => 'unclear', 'code' => $code, 'note' => 'Serverfehler, evtl. nur vorübergehend'];
        } else {
            $res[$k] = ['status' => 'unclear', 'code' => $code, 'note' => 'unerwartete Antwort'];
        }
    }
    return $res;
}

/* ---------- Titel einer Seite holen ---------- */

function lvExtractMeta(string $html, string $ctype): array {
    // Ist der Text schon gültiges UTF-8, bleibt er so. Sonst nach Angabe der Seite umwandeln
    // (Server-Angabe zuerst, dann Meta-Tag), ohne brauchbare Angabe als westeuropäisch behandeln.
    if (function_exists('mb_check_encoding') && !mb_check_encoding($html, 'UTF-8')) {
        $candidates = [];
        if (preg_match('~charset=["\']?([\w\-]+)~i', $ctype, $m)) $candidates[] = $m[1];
        if (preg_match('~<meta[^>]+charset=["\']?([\w\-]+)~i', $html, $m)) $candidates[] = $m[1];
        $candidates[] = 'Windows-1252';
        foreach ($candidates as $cs) {
            if (preg_match('~^utf-?8$~i', $cs)) continue;
            if (preg_match('~^iso-8859-1$~i', $cs)) $cs = 'Windows-1252'; // Browser machen das genauso
            try {
                $conv = mb_convert_encoding($html, 'UTF-8', $cs);
                if (is_string($conv) && $conv !== '') { $html = $conv; break; }
            } catch (Throwable $e) { /* unbekannter Zeichensatz: nächsten versuchen */ }
        }
    }
    $tidy = function (string $s, int $max): string {
        $s = html_entity_decode($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $s = preg_replace('/\s+/u', ' ', $s) ?? $s;
        return cleanText($s, $max);
    };
    $meta = function (string $name) use ($html): string {
        if (preg_match_all('~<meta\b[^>]*>~i', $html, $mm)) {
            foreach ($mm[0] as $tag) {
                if (preg_match('~\b(?:name|property)\s*=\s*["\']?' . preg_quote($name, '~') . '(?=["\'\s>/])~i', $tag)
                    && preg_match('~\bcontent\s*=\s*(?:"([^"]*)"|\'([^\']*)\')~i', $tag, $c)) {
                    return ($c[1] ?? '') !== '' ? $c[1] : ($c[2] ?? '');
                }
            }
        }
        return '';
    };
    $title = '';
    if (preg_match('~<title\b[^>]*>(.*?)</title>~is', $html, $m)) $title = $tidy($m[1], 200);
    if ($title === '') $title = $tidy($meta('og:title'), 200);
    $desc = $tidy($meta('description'), 300);
    if ($desc === '') $desc = $tidy($meta('og:description'), 300);
    return ['title' => $title, 'description' => $desc];
}
