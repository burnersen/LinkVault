# LinkVault

Eine Lesezeichen-Verwaltung zum Selbsthosten in **einer einzigen PHP-Datei**. Keine Datenbank, keine Abhängigkeiten, kein Build-Schritt, keine Abrufe bei fremden Servern. Die Lesezeichen jedes Benutzers liegen mit AES-256-GCM verschlüsselt auf dem Server, und der Schlüssel dazu ist mit dem Passwort dieses Benutzers geschützt.

`index.php` hochladen, im Browser öffnen, erstes Konto anlegen. Das ist die ganze Installation.

**English version: [README.en.md](README.en.md)**

## Funktionen

- Lesezeichen mit verschachtelten Ordnern, Schlagwörtern, Favoriten, Notizen und Volltextsuche
- Import aus Lesezeichen-Dateien der Browser (HTML), Export als HTML oder JSON
- Papierkorb mit 30 Tagen Aufbewahrung, Duplikat-Suche, Prüfung auf tote Links
- Automatische Tagesstände und ein Stand vor jeder größeren Aktion
- Verschlüsseltes Komplett-Backup als einzelne Datei zum Herunterladen (`.lvbak`)
- Mehrere Benutzer, jeder mit eigenem Schlüssel und eigenem, getrenntem Bereich
- Zwei-Faktor-Anmeldung (TOTP), Wiederherstellungscode, Anmelde-Protokoll
- Als App installierbar (PWA), läuft ohne CDN (Schrift und CSS sind eingebettet)

## Voraussetzungen

- PHP 7.4 oder neuer (empfohlen 8.x) mit der Erweiterung `openssl`
- Ein Webserver mit PHP (Apache läuft ohne Zutun, Nginx braucht eine zusätzliche Regel, siehe unten)
- **HTTPS.** Ohne HTTPS geht dein Passwort im Klartext durchs Netz, und alles Weitere hier ist hinfällig.
- Optional: `sodium` (verschlossenes Anmelde-Protokoll), `curl` (Titel abrufen, Links prüfen), `dom` (Lesezeichen-Import), `mbstring`, `intl`

## Installation

1. `index.php` in ein Verzeichnis auf deinem Webserver kopieren.
2. PHP muss in dieses Verzeichnis schreiben dürfen (es legt daneben den Ordner `data/` an).
3. Die Seite **sofort** aufrufen und das erste Konto anlegen. Dieses Konto ist der Administrator.
4. Prüfen, dass `data/` von außen nicht erreichbar ist (siehe „Den Datenordner schützen“).
5. Unter *Werkzeuge → Konto & Sicherheit* einen Wiederherstellungscode anlegen und die Zwei-Faktor-Anmeldung einschalten.

> Wer ein frisch hochgeladenes, noch nicht eingerichtetes LinkVault als Erster aufruft, wird Administrator. Schritt 3 also direkt nach dem Hochladen erledigen.

### Den Datenordner schützen

LinkVault legt `.htaccess`-Dateien an, die jeden Zugriff auf `data/` sperren. Das wirkt unter Apache, wenn `AllowOverride` eingeschaltet ist. Nginx beachtet `.htaccess` nicht, dort gehört dieser Block in die `server { }`-Sektion (derselbe Text liegt auch in `data/nginx-deny.conf`):

```nginx
location ^~ /data/ {
    deny all;
    return 404;
}
```

Bitte testen. Hier darf **keine** 200 herauskommen:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://deine-domain.example/linkvault/data/lv_auth.json
```

Alles in `data/` ist verschlüsselt oder gehasht, ein Leck wäre also nicht sofort eine Katastrophe. Ein Angreifer hätte damit aber das Material, um Passwörter in Ruhe offline durchzuprobieren, und genau das soll er nicht bekommen.

## Konten und Rollen

- Das **erste Konto** ist der Administrator.
- Alle anderen können auf der Anmeldeseite **Zugang anfragen** und suchen sich dabei Namen und Passwort selbst aus. Das Konto wird sofort mit eigenem Schlüssel angelegt, bleibt aber zu, bis der Administrator es freigibt.
- Der Administrator kann Anfragen freigeben oder ablehnen, Benutzer sperren, entsperren und löschen und neue Anfragen ganz abschalten.
- Der Administrator **kann die Lesezeichen anderer nicht lesen** und **ihre Passwörter nicht zurücksetzen**. Es gibt keinen Generalschlüssel. Wer Passwort und Wiederherstellungscode verliert, hat seine Daten verloren. Das ist Absicht.
- Grenzen gegen Missbrauch: höchstens 3 Anfragen pro Anschluss und Tag, 20 wartende Anfragen, 50 Benutzer insgesamt.

## So sind deine Daten geschützt

### Schlüssel-Aufbau

```
Passwort ──PBKDF2-SHA256, 600.000 Runden, zufälliges Salt (16 Byte)──▶ Schlüssel-Schlüssel (KEK)
                                                                            │
zufälliger 256-Bit-Datenschlüssel (DEK) ◀──mit AES-256-GCM ausgepackt──────┘
        │
        └──AES-256-GCM, bei jedem Speichern neue zufällige 96-Bit-Nonce──▶ Lesezeichen, Backups, TOTP-Geheimnis
```

- Jeder Benutzer bekommt beim Anlegen einen eigenen zufälligen 256-Bit-Datenschlüssel aus PHPs sicherem Zufallsgenerator (`random_bytes`).
- Der Datenschlüssel liegt nie im Klartext auf der Platte. Gespeichert ist er nur *verpackt* mit einem Schlüssel, der aus dem Passwort abgeleitet wird.
- Beim Passwortwechsel wird derselbe Datenschlüssel neu verpackt. Die Lesezeichen müssen dafür nicht neu verschlüsselt werden.
- AES-GCM verschlüsselt und prüft zugleich die Echtheit. Manipulierte Dateien lassen sich nicht entschlüsseln, statt Datenmüll zu liefern.
- Fehlt der Schlüssel, speichert LinkVault lieber gar nicht als unverschlüsselt.

### Was auf dem Server liegt

| Datei | Inhalt | Ohne Passwort lesbar? |
|---|---|---|
| `data/bookmarks.json`, `data/users/<id>/bookmarks.json` | Lesezeichen | Nein (AES-256-GCM) |
| `…/backups/*.json` | ältere Stände davon | Nein (AES-256-GCM) |
| `data/lv_auth.json`, `…/auth.json` | Benutzername, Passwort-Hash (`password_hash`, bcrypt), Salt, verpackter Datenschlüssel, verschlüsseltes TOTP-Geheimnis, Einstellungen | Benutzername und Einstellungen ja, alles Geheime nein |
| `…/state.json` | Stand des Kontos (wartet / aktiv / gesperrt), Zeitpunkte, verschlossene Nachricht der Anfrage | Stand und Zeitpunkte ja |
| `…/attempts.log` | Anmelde-Protokoll: Zeit, IP-Adresse, versuchter Name | Nein, sofern `sodium` vorhanden ist (siehe unten) |
| `…/favicon_cache/` | Icons der Seiten | Nein (AES-256-GCM). Die Dateinamen sind mit dem Schlüssel gebildete Prüfsummen (HMAC) und verraten die Domain nicht. |
| `data/throttle/` | Zähler für Fehlversuche, Dateinamen sind SHA-256-Prüfsummen der Adresse | Zähler ja, Adressen nein |
| `data/sessions/` | PHP-Sitzungen | Der Datenschlüssel darin ist verschlüsselt (siehe unten) |

Mehr gibt es nicht. Keine Datenbank und keine Protokolldatei, in der deine Adressen oder die gespeicherten Domains stehen.

### Sitzungen

Nach der Anmeldung muss der Datenschlüssel bei jeder Anfrage verfügbar sein. Er liegt dafür **nicht** im Klartext in der Sitzung:

- Es wird ein zufälliger 256-Bit-Sitzungsschlüssel erzeugt und als Cookie an den Browser geschickt (`HttpOnly`, `SameSite=Lax`, bei HTTPS `Secure`).
- In der Sitzungsdatei auf dem Server steht der Datenschlüssel nur verschlüsselt mit diesem Cookie-Schlüssel.
- Wer die Sitzungsdateien vom Server kopiert, kann damit nichts anfangen. Es braucht beide Hälften.
- Die Sitzungen liegen in einem eigenen Ordner von LinkVault, nicht im gemeinsamen `/tmp` des Hosters.
- Bei der Anmeldung gibt es eine neue Sitzungskennung. Die automatische Abmeldung ist einstellbar (15 Minuten bis 30 Tage, Standard 8 Stunden).
- Ein Passwortwechsel meldet alle anderen Geräte ab.

### Schutz der Anmeldung

- Passwörter: mindestens 12 Zeichen mit Buchstaben und Zahlen. Gespeichert wird nur ein Hash aus `password_hash()`.
- Bremse pro Adresse mit wachsenden Sperrzeiten (3 s, 10 s, 30 s, 60 s … bis 15 Minuten). IPv6-Adressen werden als /64-Netz zusammengefasst. Vertraut wird nur `REMOTE_ADDR`, nie `X-Forwarded-For`.
- Eine Gesamtbremse verlangsamt kurz alle, wenn sich Fehlversuche von vielen Adressen häufen.
- Unbekannte Benutzernamen kosten dieselbe Zeit wie falsche Passwörter. Warum eine Anmeldung abgelehnt wird (wartet, gesperrt), erfährt man erst nach dem richtigen Passwort.
- **Zwei-Faktor-Anmeldung (TOTP, RFC 6238)**: läuft mit Aegis, 2FAS, Google Authenticator und ähnlichen. Das TOTP-Geheimnis ist mit dem Datenschlüssel verschlüsselt gespeichert. Jeder Code gilt nur einmal.
- **Wiederherstellungscode**: 24 zufällige Zeichen (120 Bit). Er verpackt eine zweite Kopie des Datenschlüssels. Wer ihn einsetzt, vergibt ein neues Passwort, der Code ist danach verbraucht und TOTP wird abgeschaltet (meist braucht man ihn, weil das Handy weg ist).
- Heikle Aktionen (Passwort ändern, TOTP ein/aus, neuer Wiederherstellungscode, Benutzer löschen) fragen noch einmal nach dem aktuellen Passwort. Nach fünf falschen Eingaben ist die Sitzung beendet.
- **Anmelde-Protokoll**: jeder Versuch wird mit Zeit, Adresse und versuchtem Namen notiert und mit einem öffentlichen Schlüssel verschlossen (`sodium_crypto_box_seal`). Der Server kann Einträge schreiben, lesen kann sie nur der angemeldete Besitzer. Nach der Anmeldung siehst du, was seit dem letzten Mal passiert ist.

### Absicherung im Browser

- Strenge Content Security Policy: `default-src 'none'`, Skripte nur mit dem Einmal-Kennzeichen (Nonce) der jeweiligen Seite, keinerlei fremde Quellen, `frame-ancestors 'none'`, `form-action 'self'`
- `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy` und `Cross-Origin-Resource-Policy: same-origin`, HSTS bei HTTPS, `X-Robots-Tag: noindex`
- CSRF-Token bei jeder ändernden Anfrage, verglichen in konstanter Zeit. Alle Aktionen der Schnittstelle gehen nur per POST.
- Angenommen werden nur Links mit `http://` und `https://`. `javascript:`, `data:` und Ähnliches wird abgelehnt, auch beim Import.

### Privatsphäre

- **Dein Browser ruft nichts bei Dritten ab.** Schrift (Inter) und CSS stecken in der Datei. Kein CDN, keine Statistik, keine Google Fonts, kein fremder Favicon-Dienst.
- Favicons und Seitentitel holt **dein Server direkt bei der gespeicherten Seite**, nicht über Google oder DuckDuckGo.
- Diese Abrufe nach draußen sind gegen Umwege ins interne Netz (SSRF) geschützt: erlaubt sind nur öffentliche IP-Adressen, die Verbindung wird auf die geprüfte Adresse festgenagelt, jede Weiterleitung wird neu geprüft und TLS-Zertifikate werden kontrolliert.
- Der einzige Link nach draußen in der Oberfläche ist ein optionales „im Internet Archive öffnen“ bei toten Lesezeichen. Er tut nichts, solange du ihn nicht anklickst.

## Wogegen das nicht schützt

Die ehrlichen Grenzen, damit du selbst entscheiden kannst:

- **Das ist Verschlüsselung der gespeicherten Daten auf dem Server, keine Ende-zu-Ende-Verschlüsselung.** Dein Passwort geht bei der Anmeldung (über HTTPS) an den Server, und während eine Anfrage läuft, liegt der Datenschlüssel im Arbeitsspeicher des Servers. Wer den Server kontrolliert, *während du ihn benutzt* (ein böswilliger Hoster, ein Angreifer, der `index.php` verändern kann), kann Passwort oder Daten abgreifen. Wogegen der Aufbau schützt: gestohlene oder durchgesickerte Dateien, gestohlene Server-Backups, ein falsch eingestellter Webserver, der `data/` ausliefert, neugierige Mitbenutzer oder Admins, die auf der Platte stöbern.
- **Ein schwaches Passwort bleibt ein schwaches Passwort.** Wer an `auth.json` kommt, kann Passwörter offline durchprobieren. PBKDF2 mit 600.000 Runden und bcrypt machen das langsam, nicht unmöglich. Nimm ein langes, einmaliges Passwort, am besten aus einem Passwort-Manager.
- **TOTP schützt die Anmeldung, nicht die Dateien.** Es hält jemanden auf, der dein Passwort kennt und sich über die Webseite anmelden will. Es hilft nicht gegen jemanden, der dein Passwort *und* eine Kopie der Dateien hat, denn dann lässt sich der Datenschlüssel direkt auspacken.
- **Rahmendaten sind auf dem Server sichtbar:** Benutzernamen, Zahl der Benutzer, Stand der Konten, Dateigrößen und Änderungszeiten.
- **Die gespeicherten Seiten sehen die IP-Adresse deines Servers**, wenn LinkVault Titel oder Icon holt oder einen Link prüft.
- **Der Administrator kann Konten samt Daten löschen**, und wer Dateizugriff auf den Server hat, kann das auch. Heb dir ein eigenes `.lvbak`-Backup auf.
- **Kein Passwort, keine Daten.** Es gibt kein Zurücksetzen per E-Mail und keine Hintertür. Leg den Wiederherstellungscode an und verwahre ihn sicher.
- Das ist ein Hobbyprojekt. Es wurde nicht von einer unabhängigen Sicherheitsfirma geprüft. Der Code ist eine einzige lesbare Datei, schau also gern selbst nach.

## Backups

- Automatisch: ein Stand pro Tag (14 bleiben) und einer vor jeder größeren Aktion (10 bleiben), pro Benutzer, verschlüsselt wie die laufenden Daten.
- Von Hand: *Werkzeuge → Backups* lädt eine `.lvbak`-Datei herunter, mit den verschlüsselten Daten und dem verpackten Schlüssel. Ohne das Passwort, das beim Herunterladen galt, ist sie wertlos. Einspielen lässt sie sich in jedes LinkVault.
- Für eine vollständige Kopie der Installation den ganzen Ordner `data/` sichern.

## Einstellungen

Ein paar Konstanten ganz oben in `index.php`:

| Konstante | Standard | Bedeutung |
|---|---|---|
| `LV_KDF_ITERS` | `600000` | PBKDF2-Runden. Wer den Wert erhöht, hebt vorhandene Schlüssel bei der nächsten Anmeldung auf den neuen Stand. |
| `LV_IDLE_DEFAULT` | `480` | Minuten ohne Aktivität bis zur automatischen Abmeldung (jeder Benutzer kann das in der Oberfläche ändern) |
| `LV_SESSION_MAX_DAYS` | `30` | Längste Laufzeit einer Sitzung |
| `LV_MAX_PENDING` / `LV_MAX_USERS` | `20` / `50` | Grenzen für Zugangsanfragen und Benutzer |
| `BACKUP_KEEP_DAILY` / `BACKUP_KEEP_PRE` | `14` / `10` | So viele Stände bleiben erhalten |
| `LV_TRASH_DAYS` | `30` | So lange bleiben gelöschte Lesezeichen im Papierkorb |
| `LV_TAILWIND_CDN` | `false` | Nur zum Basteln. `true` lädt Tailwind von einem CDN und lockert die CSP. Aus lassen. |
| `LV_AUTH_ENABLED` | `true` | **Auf einem erreichbaren Server niemals auf `false` stellen.** Das schaltet Anmeldung und Verschlüsselung ab. |

## Aktualisieren

`index.php` durch die neue Fassung ersetzen. `data/` bleibt, wie es ist. Ältere Datenformate werden bei der nächsten Anmeldung von selbst umgestellt.

## `data/` niemals veröffentlichen

`index.php` enthält keine Zugangsdaten, Schlüssel oder persönlichen Angaben. Alles Geheime entsteht beim ersten Start und liegt in `data/`. Die `.gitignore` in diesem Repository schließt den Ordner aus. Das soll so bleiben.

## Sicherheitslücken melden

Bitte ein Issue aufmachen. Lässt sich das Problem ausnutzen, beschreib es zuerst ohne fertigen Angriff.

## Lizenz

GNU Affero General Public License v3.0, siehe [LICENSE](LICENSE). Du darfst LinkVault frei benutzen, untersuchen, verändern und weitergeben, privat wie geschäftlich. Wer es weitergibt oder verkauft, verändert oder unverändert, muss das unter derselben Lizenz tun und den Quelltext mitliefern. Das gilt auch für alle, die eine veränderte Fassung anderen als Dienst im Netz anbieten: auch sie müssen ihren Quelltext offenlegen.

## Dank

Schrift: [Inter](https://github.com/rsms/inter) von Rasmus Andersson, SIL Open Font License 1.1, als Auswahl eingebettet.
CSS-Bausteine erzeugt mit [Tailwind CSS](https://tailwindcss.com) (MIT-Lizenz), eingebettet.
