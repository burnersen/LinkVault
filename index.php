<?php
/**
 * LinkVault – Lesezeichen-Verwaltung
 *
 * Diese Datei ist nur der Einstieg: Einstellungen und Reihenfolge. Der eigentliche Code liegt in app/:
 *   app/lib/     Funktionen (Speicher, Konten, Verschlüsselung, Anmeldung, Abrufe, Import, Oberfläche)
 *   app/routes/  Antworten ohne Seite (Schrift, Icon, Manifest, Favicons, alle JSON-Aktionen)
 *   app/views/   Anmeldeseite und Hauptseite (HTML, CSS, JavaScript)
 *
 * Keine Datenbank, keine Abhängigkeiten, nichts wird von fremden Servern nachgeladen.
 * Alle Links liegen AES-256-GCM-verschlüsselt in data/. Der Schlüssel dazu ist mit
 * deinem Passwort geschützt und steht nirgends im Klartext auf dem Server.
 *
 * Mehrere Benutzer: Das erste Konto ist der Administrator. Wer danach dazukommen will,
 * stellt eine Anfrage, die der Administrator freigeben muss. Jeder Benutzer hat einen
 * eigenen Schlüssel und einen eigenen Bereich, niemand sieht die Links der anderen,
 * auch der Administrator nicht.
 *
 * Der Code enthält KEINE Zugangsdaten, Schlüssel oder persönlichen Angaben.
 * Alles Geheime entsteht erst beim ersten Aufruf (Einrichtungs-Assistent) und liegt
 * dann im Ordner data/. Den Ordner data/ niemals veröffentlichen oder ins Git legen.
 *
 * Lizenz: GNU Affero General Public License v3.0, siehe Datei LICENSE.
 * Schrift: Inter (SIL Open Font License 1.1, https://github.com/rsms/inter), eingebettet.
 */

error_reporting(E_ALL);
ini_set('display_errors', 0);
date_default_timezone_set('Europe/Berlin');

define('LV_VERSION', '3.6.0');
define('LV_ROOT', __DIR__);          // hier liegt die index.php, daneben data/
define('LV_APP', LV_ROOT . '/app');  // Programmteile
define('LV_DATA_DIR', LV_ROOT . '/data');
define('USERS_DIR', LV_DATA_DIR . '/users');       // weitere Benutzer: jeder hat hier seinen eigenen Ordner
define('SESSION_DIR', LV_DATA_DIR . '/sessions');
define('THROTTLE_DIR', LV_DATA_DIR . '/throttle'); // Fehlversuche + Anmelde-Protokoll
define('LV_MAX_PENDING', 20);    // so viele Zugangsanfragen dürfen gleichzeitig auf Freigabe warten
define('LV_MAX_USERS', 50);      // Obergrenze für weitere Benutzer
define('BACKUP_KEEP_DAILY', 14); // ein Stand pro Tag, 14 Tage
define('BACKUP_KEEP_PRE', 10);   // Stände vor großen Aktionen
define('LV_TRASH_DAYS', 30);     // so lange bleiben gelöschte Links im Papierkorb
// false = Tailwind ist fest eingebaut. true = per CDN laden (nur zum Basteln, lockert die Sicherheitsregeln).
define('LV_TAILWIND_CDN', false);
define('LV_UA', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36');

define('LV_AUTH_ENABLED', true);
define('LV_SESSION_NAME', 'LVSESSID');
define('LV_KEY_COOKIE', 'LVKEY');
define('LV_KDF_ITERS', 600000);   // PBKDF2-Runden für neue/aktualisierte Schlüssel
define('LV_IDLE_DEFAULT', 480);   // Minuten ohne Aktivität bis zur automatischen Abmeldung
define('LV_SESSION_MAX_DAYS', 30);

$LV_CORRUPT = false;   // true = bookmarks.json existiert, ist aber nicht lesbar
$LV_AUTH_CACHE = [];
$LV_UID = '';          // wer gerade angemeldet ist: '' = Administrator (erstes Konto), sonst Ordnername unter data/users/
$LV_DEK = null;        // Datenschlüssel dieser Anfrage (nur im Arbeitsspeicher)
$LV_LOGGED = null;
$LV_NONCE = rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '=');


/* ---------- Programmteile laden (alles liegt im Ordner app/) ---------- */

if (!is_file(LV_APP . '/lib/storage.php')) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    exit("LinkVault ist unvollständig: Der Ordner app/ fehlt. Bitte alle Dateien der Version hochladen, nicht nur die index.php.\n"
       . "LinkVault is incomplete: the folder app/ is missing. Please upload all files of the release, not just index.php.\n");
}
foreach (['storage', 'users', 'crypto', 'session', 'totp', 'bookmarks', 'helpers', 'security', 'fetch', 'import', 'font', 'ui', 'autosort'] as $lvPart) {
    require LV_APP . '/lib/' . $lvPart . '.php';
}
unset($lvPart);

/* ================================================================== */

$action = $_POST['action'] ?? $_GET['action'] ?? null;
if (!is_string($action) || $action === '') $action = null;
$isPost = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';

// Schrift, Icon, Manifest, Service Worker, Favicons (antworten und beenden die Anfrage)
require LV_APP . '/routes/public.php';
// Alle JSON-Aktionen (antworten und beenden die Anfrage)
require LV_APP . '/routes/api.php';

lvSecurityHeaders(true);
header('Cache-Control: no-store, no-cache, must-revalidate, private');
header('Pragma: no-cache');

// Nicht angemeldet: Einrichtung, Anmeldung, Wiederherstellung oder Zugangsanfrage (beendet die Anfrage)
require LV_APP . '/views/login.php';
// Angemeldet: die eigentliche Seite
require LV_APP . '/views/app.php';
