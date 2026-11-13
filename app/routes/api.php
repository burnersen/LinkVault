<?php
/* LinkVault – Alle JSON-Aktionen */
defined('LV_VERSION') || exit;

if ($action) {
    lvSecurityHeaders(false);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');

    if ($action === 'logout') {
        if (!$isPost) {
            http_response_code(405);
            jsonOut(['success' => false, 'message' => 'Logout nur per POST.']);
        }
        lvRequireCsrf();
        lvLogout();
        jsonOut(['success' => true, 'message' => 'Abgemeldet.']);
    }

    if ($action === 'auth_status') {
        jsonOut(['success' => true, 'logged_in' => lvIsLoggedIn(), 'setup_done' => lvIsSetupDone()]);
    }

    // Alles hier geht nur per POST mit gültigem Sicherheits-Token und angemeldet
    if (!$isPost) {
        http_response_code(405);
        jsonOut(['success' => false, 'message' => 'Diese Aktion geht nur per POST.']);
    }
    lvRequireCsrf();
    if (LV_AUTH_ENABLED && !lvIsLoggedIn()) {
        http_response_code(401);
        jsonOut(['success' => false, 'message' => 'Nicht angemeldet.', 'auth_required' => true]);
    }
    lvDataKey();
    $sessionWriters = ['change_password', 'totp_begin', 'totp_enable', 'totp_disable', 'recovery_create', 'settings_save', 'backup_import', 'login_log', 'user_delete'];
    if (!in_array($action, $sessionWriters, true)) session_write_close();

    // Schreibende Aktionen nacheinander ausführen (zwei Geräte gleichzeitig überschreiben sich sonst)
    $mutating = ['add', 'update', 'delete', 'bulk_delete', 'bulk_move', 'bulk_favorite', 'dedupe', 'toggle_favorite',
                 'import', 'rename_category', 'delete_category', 'backup_restore', 'backup_import', 'visit', 'set_status',
                 'trash_restore', 'trash_purge', 'change_password', 'totp_enable', 'totp_disable', 'recovery_create', 'settings_save',
                 'user_approve', 'user_reject', 'user_block', 'user_unblock', 'user_delete', 'register_toggle',
                 'autosort_apply', 'autosort_rules_save', 'tag_rename', 'tag_delete'];
    $isMutating = in_array($action, $mutating, true);
    $lockFp = null;
    if ($isMutating) {
        $lockFp = @fopen(lvLockFile(), 'c');
        if ($lockFp) flock($lockFp, LOCK_EX);
    }

    $bookmarks = loadBookmarks();
    $isLive = fn($b) => empty($b['deleted']);
    $lower = fn($s) => function_exists('mb_strtolower') ? mb_strtolower((string)$s, 'UTF-8') : strtolower((string)$s);

    try {
        $dataActions = ['add', 'update', 'delete', 'bulk_delete', 'bulk_move', 'bulk_favorite', 'dedupe', 'toggle_favorite',
                        'import', 'rename_category', 'delete_category', 'visit', 'set_status', 'trash_restore', 'trash_purge',
                        'autosort_apply', 'tag_rename', 'tag_delete'];
        if ($LV_CORRUPT && in_array($action, $dataActions, true)) {
            throw new Exception('bookmarks.json ist beschädigt und wird nicht überschrieben. Bitte unter Werkzeuge → Backups einen Stand wiederherstellen.');
        }

        switch ($action) {
            case 'list':
                $out = ['success' => true, 'bookmarks' => $bookmarks, 'corrupt' => $LV_CORRUPT];
                $cfg = lvLoadAuthConfig();
                // Der Administrator erfährt nebenbei, ob neue Zugangsanfragen warten
                if ($cfg !== null && $cfg['role'] === 'admin') $out['pending'] = lvPendingCount();
                jsonOut($out);

            /* ----- Konto & Sicherheit ----- */

            case 'account_info':
                $cfg = lvLoadAuthConfig(true);
                if ($cfg === null) throw new Exception('Kein Konto eingerichtet.');
                jsonOut(['success' => true, 'username' => $cfg['username'], 'role' => $cfg['role'], 'totp' => !empty($cfg['totp']),
                         'recovery' => !empty($cfg['rec_wrapped']), 'idle_minutes' => $cfg['idle_minutes'],
                         'log_details' => !empty($cfg['log_pub'])]);

            case 'settings_save':
                $cfg = lvLoadAuthConfig(true);
                if ($cfg === null) throw new Exception('Kein Konto eingerichtet.');
                $idle = (int)($_POST['idle_minutes'] ?? 0);
                if (!in_array($idle, [15, 60, 480, 1440, 10080, 43200], true)) throw new Exception('Ungültige Zeitangabe.');
                $cfg['idle_minutes'] = $idle;
                if (!lvSaveAuthConfigFull($cfg)) throw new Exception('Speichern fehlgeschlagen (Schreibrechte?).');
                // Cookies an die neue Laufzeit anpassen
                $exp = $idle > 480 ? time() + $idle * 60 : 0;
                setcookie(LV_KEY_COOKIE, (string)($_COOKIE[LV_KEY_COOKIE] ?? ''), lvCookieOpts($exp));
                setcookie(session_name(), session_id(), lvCookieOpts($exp));
                jsonOut(['success' => true, 'message' => 'Gespeichert.']);

            // Design, Sprache und Ansicht des angemeldeten Benutzers (siehe Block „Neu in 3.2/3.3“ am Dateiende)
            case 'ui_save':
                $ui = json_decode((string)($_POST['ui'] ?? ''), true);
                if (!is_array($ui) || !lvUiSave(lvUiClean($ui))) throw new Exception('Speichern fehlgeschlagen (Schreibrechte?).');
                jsonOut(['success' => true]);

            case 'change_password':
                $newUser = trim((string)($_POST['new_username'] ?? ''));
                $newPass = (string)($_POST['new_password'] ?? '');
                $newPass2 = (string)($_POST['new_password2'] ?? '');
                $cfg = lvLoadAuthConfig(true);
                if ($cfg === null) throw new Exception('Kein Konto eingerichtet.');
                $dek = lvRequirePassword($cfg, (string)($_POST['current_password'] ?? ''));
                if ($newUser === '') $newUser = $cfg['username'];
                if (strlen($newUser) < 2 || strlen($newUser) > 64) {
                    throw new Exception('Benutzername: 2–64 Zeichen.');
                }
                if ($newUser !== $cfg['username']) {
                    if (cleanText($newUser, 64) !== $newUser) throw new Exception('Der Benutzername enthält unzulässige Zeichen.');
                    $other = lvFindUser($newUser, false, true);
                    if ($other !== null && $other['_uid'] !== $cfg['_uid']) throw new Exception('Dieser Benutzername ist schon vergeben.');
                }
                if ($newPass === '') {
                    if ($newUser === $cfg['username']) throw new Exception('Keine Änderung.');
                    $cfg['username'] = $newUser;
                    if (!lvSaveAuthConfigFull($cfg)) throw new Exception('Speichern der Zugangsdaten fehlgeschlagen (Schreibrechte?).');
                    $_SESSION['lv_user'] = $newUser;
                    jsonOut(['success' => true, 'message' => 'Benutzername geändert.', 'username' => $newUser]);
                }
                lvCheckNewPassword($newPass);
                if ($newPass !== $newPass2) throw new Exception('Neue Passwörter stimmen nicht überein.');
                $hash = password_hash($newPass, PASSWORD_DEFAULT);
                if ($hash === false) throw new Exception('Passwort-Hash fehlgeschlagen.');
                $wrapped = lvWrapKey($dek, $newPass);
                $cfg['username'] = $newUser;
                $cfg['password_hash'] = $hash;
                $cfg['kdf_salt'] = $wrapped['kdf_salt'];
                $cfg['wrapped_key'] = $wrapped['wrapped_key'];
                $cfg['kdf_iters'] = $wrapped['kdf_iters'];
                $cfg['epoch'] = (int)$cfg['epoch'] + 1; // alle anderen Geräte werden abgemeldet
                if (!lvSaveAuthConfigFull($cfg)) throw new Exception('Speichern der Zugangsdaten fehlgeschlagen (Schreibrechte?).');
                lvEstablishSession($cfg, $dek);
                jsonOut(['success' => true, 'message' => 'Zugangsdaten gespeichert. Andere Geräte wurden abgemeldet.', 'username' => $newUser, 'csrf' => lvCsrfToken()]);

            case 'totp_begin':
                $cfg = lvLoadAuthConfig(true);
                if ($cfg === null) throw new Exception('Kein Konto eingerichtet.');
                $secret = lvBase32Encode(random_bytes(20));
                $_SESSION['lv_totp_pending'] = $secret;
                $label = rawurlencode('LinkVault:' . $cfg['username']);
                jsonOut(['success' => true, 'secret' => $secret,
                         'uri' => "otpauth://totp/{$label}?secret={$secret}&issuer=LinkVault&algorithm=SHA1&digits=6&period=30"]);

            case 'totp_enable':
                $cfg = lvLoadAuthConfig(true);
                if ($cfg === null) throw new Exception('Kein Konto eingerichtet.');
                $dek = lvRequirePassword($cfg, (string)($_POST['current_password'] ?? ''));
                $secret = (string)($_SESSION['lv_totp_pending'] ?? '');
                if ($secret === '') throw new Exception('Bitte die Einrichtung noch einmal starten.');
                $counter = lvTotpVerify($secret, (string)($_POST['code'] ?? ''), 0);
                if ($counter === 0) throw new Exception('Der Code stimmt nicht. Uhrzeit am Handy prüfen und neuen Code eingeben.');
                $cfg['totp'] = lvEncryptWith($dek, $secret);
                $cfg['totp_last'] = $counter;
                $cfg['epoch'] = (int)$cfg['epoch'] + 1; // alle anderen Geräte werden abgemeldet
                if (!lvSaveAuthConfigFull($cfg)) throw new Exception('Speichern fehlgeschlagen (Schreibrechte?).');
                $_SESSION['lv_epoch'] = $cfg['epoch']; // dieses Gerät bleibt angemeldet
                unset($_SESSION['lv_totp_pending']);
                jsonOut(['success' => true, 'message' => 'Zwei-Faktor-Anmeldung ist jetzt aktiv.']);

            case 'totp_disable':
                $cfg = lvLoadAuthConfig(true);
                if ($cfg === null) throw new Exception('Kein Konto eingerichtet.');
                lvRequirePassword($cfg, (string)($_POST['current_password'] ?? ''));
                unset($cfg['totp'], $cfg['totp_last']);
                $cfg['epoch'] = (int)$cfg['epoch'] + 1; // alle anderen Geräte werden abgemeldet
                if (!lvSaveAuthConfigFull($cfg)) throw new Exception('Speichern fehlgeschlagen (Schreibrechte?).');
                $_SESSION['lv_epoch'] = $cfg['epoch']; // dieses Gerät bleibt angemeldet
                jsonOut(['success' => true, 'message' => 'Zwei-Faktor-Anmeldung ist abgeschaltet.']);

            case 'recovery_create':
                $cfg = lvLoadAuthConfig(true);
                if ($cfg === null) throw new Exception('Kein Konto eingerichtet.');
                $dek = lvRequirePassword($cfg, (string)($_POST['current_password'] ?? ''));
                $abc = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // ohne 0/O und 1/I
                $code = '';
                for ($i = 0; $i < 24; $i++) $code .= $abc[random_int(0, 31)];
                $w = lvWrapKey($dek, $code);
                $cfg['rec_salt'] = $w['kdf_salt'];
                $cfg['rec_wrapped'] = $w['wrapped_key'];
                $cfg['rec_iters'] = $w['kdf_iters'];
                if (!lvSaveAuthConfigFull($cfg)) throw new Exception('Speichern fehlgeschlagen (Schreibrechte?).');
                jsonOut(['success' => true, 'code' => implode('-', str_split($code, 4)),
                         'message' => 'Neuer Wiederherstellungscode erzeugt. Ein älterer Code gilt nicht mehr.']);

            case 'login_log':
                $cfg = lvLoadAuthConfig();
                $dek = lvDataKey();
                if ($cfg === null || $dek === null) throw new Exception('Nicht angemeldet.');
                if (!empty($_POST['clear'])) {
                    @unlink(lvAttemptsFile($cfg['_uid']));
                    lvLogAttempt('ok', $cfg['username'], $cfg['_uid']);
                }
                jsonOut(['success' => true, 'entries' => lvReadAttempts($cfg, $dek, 300), 'details' => !empty($cfg['log_pub'])]);

            /* ----- Benutzer verwalten (nur Administrator) ----- */

            case 'users_list':
                $cfg = lvRequireAdmin();
                jsonOut(['success' => true] + lvUsersPayload($cfg));

            case 'user_approve':
            case 'user_block':
            case 'user_unblock':
                $cfg = lvRequireAdmin();
                $u = lvUserByUid($_POST['uid'] ?? '');
                $name = $u['username'];
                if ($action === 'user_approve') {
                    if ($u['status'] !== 'pending') throw new Exception('Diese Anfrage ist schon erledigt.');
                    $ok = lvSetUserStatus($u, 'active');
                    $msg = "„{$name}“ ist freigeschaltet und kann sich jetzt anmelden.";
                } elseif ($action === 'user_block') {
                    if ($u['status'] !== 'active') throw new Exception('Dieser Benutzer ist nicht aktiv.');
                    $ok = lvSetUserStatus($u, 'blocked');
                    $msg = "„{$name}“ ist gesperrt und überall abgemeldet. Die Links bleiben erhalten.";
                } else {
                    if ($u['status'] !== 'blocked') throw new Exception('Dieser Benutzer ist nicht gesperrt.');
                    $ok = lvSetUserStatus($u, 'active');
                    $msg = "„{$name}“ darf sich wieder anmelden.";
                }
                if (!$ok) throw new Exception('Speichern fehlgeschlagen (Schreibrechte?).');
                jsonOut(['success' => true, 'message' => $msg] + lvUsersPayload($cfg));

            case 'user_reject':
                $cfg = lvRequireAdmin();
                $u = lvUserByUid($_POST['uid'] ?? '');
                if ($u['status'] !== 'pending') throw new Exception('Diese Anfrage ist schon erledigt.');
                if (!lvDeleteUser($u['_uid'])) throw new Exception('Löschen fehlgeschlagen (Schreibrechte?).');
                jsonOut(['success' => true, 'message' => "Anfrage von „{$u['username']}“ abgelehnt."] + lvUsersPayload($cfg));

            case 'user_delete':
                // Löscht das Konto samt aller Links und Backups, das lässt sich nicht zurückholen
                $cfg = lvRequireAdmin();
                lvRequirePassword($cfg, (string)($_POST['current_password'] ?? ''));
                $u = lvUserByUid($_POST['uid'] ?? '');
                if (!lvDeleteUser($u['_uid'])) throw new Exception('Löschen fehlgeschlagen (Schreibrechte?).');
                jsonOut(['success' => true, 'message' => "„{$u['username']}“ wurde samt allen Links gelöscht."] + lvUsersPayload($cfg));

            case 'register_toggle':
                $cfg = lvRequireAdmin();
                $cfg['allow_register'] = ($_POST['open'] ?? '') === '1';
                if (!lvSaveAuthConfigFull($cfg)) throw new Exception('Speichern fehlgeschlagen (Schreibrechte?).');
                jsonOut(['success' => true, 'allow_register' => $cfg['allow_register'],
                         'message' => $cfg['allow_register'] ? 'Neue Zugangsanfragen sind wieder möglich.' : 'Es werden keine neuen Zugangsanfragen mehr angenommen.']);

            /* ----- Links ----- */

            case 'add':
                $title = cleanText($_POST['title'] ?? '', 300);
                $url   = trim((string)($_POST['url'] ?? ''));
                if ($title === '' || $url === '') throw new Exception('Titel und URL sind erforderlich.');
                $url = cleanUrl($url);
                $item = [
                    'id' => generateId(), 'title' => $title, 'url' => $url,
                    'category' => cleanCategory($_POST['category'] ?? ''),
                    'description' => cleanText($_POST['description'] ?? '', 2000),
                    'favorite' => ($_POST['favorite'] ?? '') === '1', 'created' => time(),
                ];
                $tags = cleanTags($_POST['tags'] ?? []);
                if ($tags) $item['tags'] = $tags;
                $bookmarks[] = $item;
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => 'Link hinzugefügt.', 'bookmarks' => $bookmarks]);

            case 'update':
                $id = (string)($_POST['id'] ?? '');
                $found = false;
                foreach ($bookmarks as &$bm) {
                    if (($bm['id'] ?? null) === $id) {
                        $title = cleanText($_POST['title'] ?? ($bm['title'] ?? ''), 300);
                        if ($title === '') throw new Exception('Titel darf nicht leer sein.');
                        $url = trim((string)($_POST['url'] ?? ($bm['url'] ?? '')));
                        // Unveränderte URL nicht erneut prüfen (alte Importe bleiben bearbeitbar)
                        if ($url !== ($bm['url'] ?? '')) { $url = cleanUrl($url); unset($bm['check']); }
                        $bm['title']       = $title;
                        $bm['url']         = $url;
                        $bm['category']    = cleanCategory($_POST['category'] ?? ($bm['category'] ?? ''));
                        $bm['description'] = cleanText($_POST['description'] ?? ($bm['description'] ?? ''), 2000);
                        $bm['favorite']    = ($_POST['favorite'] ?? '') === '1';
                        if (isset($_POST['tags'])) {
                            $tags = cleanTags($_POST['tags']);
                            if ($tags) $bm['tags'] = $tags; else unset($bm['tags']);
                        }
                        $found = true;
                        break;
                    }
                }
                unset($bm);
                if (!$found) throw new Exception('Link nicht gefunden.');
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => 'Link aktualisiert.', 'bookmarks' => $bookmarks]);

            case 'delete':
            case 'bulk_delete':
                // Löschen heißt: ab in den Papierkorb
                $ids = $action === 'delete' ? [(string)($_POST['id'] ?? '')] : parseIds($_POST['ids'] ?? []);
                $ids = array_flip(array_filter($ids, fn($i) => $i !== ''));
                if (!$ids) throw new Exception('Keine Links ausgewählt.');
                $n = 0;
                foreach ($bookmarks as &$bm) {
                    if (isset($ids[$bm['id'] ?? '']) && empty($bm['deleted'])) { $bm['deleted'] = time(); $n++; }
                }
                unset($bm);
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => $n === 1 ? 'Link in den Papierkorb gelegt.' : "$n Links in den Papierkorb gelegt.", 'bookmarks' => $bookmarks]);

            case 'trash_restore':
                $ids = array_flip(parseIds($_POST['ids'] ?? []));
                $n = 0;
                foreach ($bookmarks as &$bm) {
                    if (!empty($bm['deleted']) && (!$ids || isset($ids[$bm['id'] ?? '']))) { unset($bm['deleted']); $n++; }
                }
                unset($bm);
                if ($n === 0) throw new Exception('Nichts zum Wiederherstellen.');
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => "$n Link(s) wiederhergestellt.", 'bookmarks' => $bookmarks]);

            case 'trash_purge':
                $ids = array_flip(parseIds($_POST['ids'] ?? []));
                $before = count($bookmarks);
                $bookmarks = array_values(array_filter($bookmarks, fn($b) => empty($b['deleted']) || ($ids && !isset($ids[$b['id'] ?? '']))));
                $n = $before - count($bookmarks);
                if ($n > 0) { backupBefore('purge'); requireSave($bookmarks); }
                jsonOut(['success' => true, 'message' => "$n Link(s) endgültig gelöscht.", 'bookmarks' => $bookmarks]);

            case 'bulk_move':
                $ids = array_flip(parseIds($_POST['ids'] ?? []));
                if (!$ids) throw new Exception('Keine Links ausgewählt.');
                if (trim((string)($_POST['category'] ?? '')) === '') throw new Exception('Ordner fehlt.');
                $cat = cleanCategory($_POST['category']);
                $moved = 0;
                foreach ($bookmarks as &$bm) {
                    if (isset($ids[$bm['id'] ?? '']) && $isLive($bm)) { $bm['category'] = $cat; $moved++; }
                }
                unset($bm);
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => "$moved Link(s) nach „{$cat}“ verschoben.", 'bookmarks' => $bookmarks]);

            case 'bulk_favorite':
                $ids = array_flip(parseIds($_POST['ids'] ?? []));
                $fav = ($_POST['favorite'] ?? '') === '1';
                if (!$ids) throw new Exception('Keine Links ausgewählt.');
                foreach ($bookmarks as &$bm) {
                    if (isset($ids[$bm['id'] ?? ''])) $bm['favorite'] = $fav;
                }
                unset($bm);
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => $fav ? 'Als Favorit markiert.' : 'Aus Favoriten entfernt.', 'bookmarks' => $bookmarks]);

            case 'rename_category':
                $old = trim((string)($_POST['old'] ?? ''));
                if ($old === '' || trim((string)($_POST['new'] ?? '')) === '') throw new Exception('Ordnername fehlt.');
                $new = cleanCategory($_POST['new']);
                $n = 0;
                foreach ($bookmarks as &$bm) {
                    $c = (string)($bm['category'] ?? '');
                    if ($c === $old) { $bm['category'] = $new; $n++; }
                    elseif (strncmp($c, $old . ' > ', strlen($old) + 3) === 0) {
                        // Unterordner ziehen mit um
                        $bm['category'] = cleanCategory($new . ' > ' . substr($c, strlen($old) + 3));
                        $n++;
                    }
                }
                unset($bm);
                if ($n === 0) throw new Exception('Ordner nicht gefunden.');
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => "Ordner umbenannt ($n Links).", 'bookmarks' => $bookmarks, 'new' => $new]);

            case 'delete_category':
                // Ordner auflösen: Links wandern eine Ebene höher (oder nach „Allgemein“), gelöscht wird nichts
                $old = trim((string)($_POST['category'] ?? ''));
                if ($old === '') throw new Exception('Ordnername fehlt.');
                if ($old === 'Allgemein') throw new Exception('„Allgemein“ ist der Standard-Ordner.');
                $pos = strrpos($old, ' > ');
                $parent = $pos !== false ? substr($old, 0, $pos) : '';
                $n = 0;
                foreach ($bookmarks as &$bm) {
                    $c = (string)($bm['category'] ?? '');
                    if ($c === $old) { $bm['category'] = $parent !== '' ? $parent : 'Allgemein'; $n++; }
                    elseif (strncmp($c, $old . ' > ', strlen($old) + 3) === 0) {
                        $rest = substr($c, strlen($old) + 3);
                        $bm['category'] = cleanCategory($parent !== '' ? $parent . ' > ' . $rest : $rest);
                        $n++;
                    }
                }
                unset($bm);
                if ($n === 0) throw new Exception('Ordner nicht gefunden.');
                $backup = backupBefore('delete_category');
                requireSave($bookmarks);
                $target = $parent !== '' ? $parent : 'Allgemein';
                jsonOut(['success' => true, 'message' => "Ordner gelöscht, $n Link(s) liegen jetzt in „{$target}“.", 'bookmarks' => $bookmarks, 'backup' => $backup]);

            /* ----- Tags verwalten: umbenennen (gleicher Name = zusammenlegen) und löschen. Die Links bleiben immer. ----- */

            case 'tag_rename':
            case 'tag_delete':
                $old = (string)($_POST['tag'] ?? '');
                if (trim($old) === '') throw new Exception('Tag fehlt.');
                $new = '';
                if ($action === 'tag_rename') {
                    $clean = cleanTags([(string)($_POST['new'] ?? '')]);
                    if (!$clean) throw new Exception('Neuer Name fehlt.');
                    $new = $clean[0];
                    if ($new === $old) throw new Exception('Keine Änderung.');
                }
                $n = 0;
                foreach ($bookmarks as &$bm) {
                    if (empty($bm['tags']) || !is_array($bm['tags']) || !in_array($old, $bm['tags'], true)) continue;
                    $list = [];
                    foreach ($bm['tags'] as $t) {
                        if ($t === $old) { if ($new !== '') $list[] = $new; }
                        else $list[] = $t;
                    }
                    $list = cleanTags($list);
                    if ($list) $bm['tags'] = $list; else unset($bm['tags']);
                    $n++;
                }
                unset($bm);
                if ($n === 0) throw new Exception('Tag nicht gefunden.');
                $backup = backupBefore('tags');
                requireSave($bookmarks);
                jsonOut(['success' => true, 'bookmarks' => $bookmarks, 'backup' => $backup,
                         'message' => $action === 'tag_delete' ? "Tag „{$old}“ bei $n Link(s) entfernt." : "Tag „{$old}“ heißt jetzt „{$new}“ ($n Links)."]);

            /* ----- Automatisch sortieren (Block „Neu in 3.4“ am Dateiende) ----- */

            case 'autosort_rules':
                jsonOut(['success' => true] + lvAutoSortLoad());

            case 'autosort_rules_save':
                $groups = json_decode((string)($_POST['groups'] ?? ''), true);
                if (!is_array($groups)) throw new Exception('Keine Gruppen übergeben.');
                $groups = lvAutoSortCleanGroups($groups);
                if (!lvAutoSortSave($groups)) throw new Exception('Speichern fehlgeschlagen (Schreibrechte?).');
                jsonOut(['success' => true, 'message' => 'Gruppen gespeichert.', 'groups' => $groups]);

            case 'autosort_apply':
                // Die Vorschläge rechnet der Browser aus, hier wird nur übernommen, was angehakt war.
                // Schlagwörter kommen nur dazu (nie weg), der Ordner wird nur gesetzt, wenn einer mitkommt.
                $changes = json_decode((string)($_POST['changes'] ?? ''), true);
                if (!is_array($changes) || !$changes) throw new Exception('Nichts ausgewählt.');
                if (count($changes) > 50000) throw new Exception('Zu viele Änderungen auf einmal.');
                $nTag = 0; $nFolder = 0; $touched = 0;
                foreach ($bookmarks as &$bm) {
                    $c = $changes[$bm['id'] ?? ''] ?? null;
                    if (!is_array($c) || !$isLive($bm)) continue;
                    $hit = false;
                    $add = isset($c['t']) ? cleanTags($c['t']) : [];
                    if ($add) {
                        $old = isset($bm['tags']) && is_array($bm['tags']) ? $bm['tags'] : [];
                        $merged = cleanTags(array_merge($old, $add));
                        if (count($merged) > count(cleanTags($old))) { $bm['tags'] = $merged; $nTag++; $hit = true; }
                    }
                    if (isset($c['f']) && is_string($c['f']) && trim($c['f']) !== '') {
                        $cat = cleanCategory($c['f']);
                        if ($cat !== ($bm['category'] ?? '')) { $bm['category'] = $cat; $nFolder++; $hit = true; }
                    }
                    if ($hit) $touched++;
                }
                unset($bm);
                if ($touched === 0) jsonOut(['success' => true, 'message' => 'Nichts geändert, war schon alles so.', 'bookmarks' => $bookmarks]);
                $backup = backupBefore('autosort');
                requireSave($bookmarks);
                jsonOut(['success' => true, 'bookmarks' => $bookmarks, 'backup' => $backup,
                         'message' => "$touched Link(s) sortiert: $nTag mit neuen Tags, $nFolder in andere Ordner."]);

            case 'dedupe':
                // Pro Adresse bleibt der beste Eintrag, die anderen wandern in den Papierkorb
                $keepIds = parseIds($_POST['keep_ids'] ?? []);
                $norm = function ($url) {
                    $url = trim((string)$url);
                    $p = parse_url($url);
                    if (!$p || empty($p['host'])) return strtolower($url);
                    $host = strtolower($p['host']);
                    if (strncmp($host, 'www.', 4) === 0) $host = substr($host, 4);
                    $path = rtrim($p['path'] ?? '/', '/') ?: '/';
                    return $host . $path . (isset($p['query']) ? '?' . $p['query'] : '');
                };
                $groups = [];
                foreach ($bookmarks as $i => $bm) {
                    if ($isLive($bm)) $groups[$norm($bm['url'] ?? '')][] = $i;
                }
                $removed = 0;
                foreach ($groups as $idxs) {
                    if (count($idxs) < 2) continue;
                    usort($idxs, function ($x, $y) use ($bookmarks, $keepIds) {
                        $a = $bookmarks[$x]; $b = $bookmarks[$y];
                        $ak = in_array($a['id'] ?? '', $keepIds, true) ? 1 : 0;
                        $bk = in_array($b['id'] ?? '', $keepIds, true) ? 1 : 0;
                        if ($ak !== $bk) return $bk <=> $ak;
                        $af = !empty($a['favorite']) ? 1 : 0; $bf = !empty($b['favorite']) ? 1 : 0;
                        if ($af !== $bf) return $bf <=> $af;
                        $ad = trim($a['description'] ?? '') !== '' ? 1 : 0; $bd = trim($b['description'] ?? '') !== '' ? 1 : 0;
                        if ($ad !== $bd) return $bd <=> $ad;
                        return ($a['created'] ?? 0) <=> ($b['created'] ?? 0);
                    });
                    foreach (array_slice($idxs, 1) as $i) { $bookmarks[$i]['deleted'] = time(); $removed++; }
                }
                if ($removed > 0) {
                    backupBefore('dedupe');
                    requireSave($bookmarks);
                }
                jsonOut([
                    'success' => true,
                    'message' => $removed > 0 ? "$removed Duplikat(e) in den Papierkorb gelegt." : 'Keine Duplikate gefunden.',
                    'removed' => $removed,
                    'bookmarks' => $bookmarks
                ]);

            case 'toggle_favorite':
                $id = (string)($_POST['id'] ?? '');
                foreach ($bookmarks as &$bm) {
                    if (($bm['id'] ?? null) === $id) {
                        $bm['favorite'] = !($bm['favorite'] ?? false);
                        break;
                    }
                }
                unset($bm);
                requireSave($bookmarks);
                jsonOut(['success' => true, 'bookmarks' => $bookmarks]);

            case 'visit':
                // Zählt, wie oft ein Link geöffnet wurde (für „Oft benutzt“ / „Zuletzt geöffnet“)
                $id = (string)($_POST['id'] ?? '');
                $hit = false;
                foreach ($bookmarks as &$bm) {
                    if (($bm['id'] ?? null) === $id) {
                        $bm['clicks'] = (int)($bm['clicks'] ?? 0) + 1;
                        $bm['opened'] = time();
                        $hit = true;
                        break;
                    }
                }
                unset($bm);
                if ($hit) requireSave($bookmarks);
                jsonOut(['success' => true]);

            case 'set_status':
                // Ergebnis des Link-Checks an den Links merken
                $results = json_decode((string)($_POST['results'] ?? ''), true);
                if (!is_array($results)) throw new Exception('Keine Ergebnisse.');
                foreach ($bookmarks as &$bm) {
                    $r = $results[$bm['id'] ?? ''] ?? null;
                    if (!is_array($r)) continue;
                    $s = (string)($r['s'] ?? '');
                    if ($s === 'dead' || $s === 'unclear') $bm['check'] = ['s' => $s, 'c' => (int)($r['c'] ?? 0), 't' => time()];
                    else unset($bm['check']);
                }
                unset($bm);
                requireSave($bookmarks);
                jsonOut(['success' => true, 'bookmarks' => $bookmarks]);

            case 'check_urls':
                // Die Seite schickt die Links in kleinen Häppchen, so gibt es keine Zeitüberschreitung
                @set_time_limit(90);
                $ids = array_flip(parseIds($_POST['ids'] ?? []));
                $toCheck = array_values(array_filter($bookmarks, fn($b) => $isLive($b) && isset($ids[$b['id'] ?? ''])));
                $toCheck = array_slice($toCheck, 0, 20);
                $urls = [];
                foreach ($toCheck as $i => $bm) $urls[$i] = (string)($bm['url'] ?? '');
                $checked = lvCheckUrls($urls);
                $results = [];
                foreach ($toCheck as $i => $bm) {
                    $r = $checked[$i] ?? ['status' => 'unclear', 'code' => 0, 'note' => 'nicht geprüft'];
                    $results[] = [
                        'id' => $bm['id'], 'url' => $bm['url'] ?? '', 'title' => $bm['title'] ?? '',
                        'status' => $r['status'], 'code' => $r['code'], 'note' => $r['note'],
                    ];
                }
                jsonOut(['success' => true, 'results' => $results]);

            case 'fetch_title':
                $url = cleanUrl($_POST['url'] ?? '');
                $page = lvSafeFetch($url);
                if ($page['blocked']) throw new Exception('Diese Adresse kann der Server nicht abrufen.');
                if ($page['body'] === '') throw new Exception('Seite antwortet nicht.');
                $meta = lvExtractMeta($page['body'], $page['ctype']);
                if ($meta['title'] === '') throw new Exception('Kein Titel gefunden.');
                jsonOut(['success' => true, 'title' => $meta['title'], 'description' => $meta['description']]);

            /* ----- Backups ----- */

            case 'backups_list':
                jsonOut(['success' => true, 'backups' => listBackups()]);

            case 'backup_restore':
                $name = basename((string)($_POST['name'] ?? ''));
                if (!preg_match('/^(tag|vor)_[A-Za-z0-9_\-]+\.json$/', $name) || !is_file(lvBackupDir() . '/' . $name)) {
                    throw new Exception('Backup nicht gefunden.');
                }
                $jsonBackup = lvDecodeStored((string)file_get_contents(lvBackupDir() . '/' . $name));
                if ($jsonBackup === null) throw new Exception('Backup ist nicht lesbar (Entschlüsselung fehlgeschlagen).');
                $data = json_decode($jsonBackup, true);
                if (!is_array($data)) throw new Exception('Backup ist nicht lesbar.');
                backupBefore('restore');
                $LV_CORRUPT = false;
                $bookmarks = array_values(array_filter($data, 'is_array'));
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => 'Stand wiederhergestellt (' . count(array_filter($bookmarks, $isLive)) . ' Links).', 'bookmarks' => $bookmarks]);

            case 'export_full':
                // Komplett-Backup: verschlüsselte Daten + der passwortgeschützte Schlüssel in EINER Datei.
                // Ohne das Passwort von heute ist die Datei wertlos.
                $cfg = lvLoadAuthConfig();
                if ($cfg === null || !is_file(lvDataFile())) throw new Exception('Nichts zu sichern.');
                $raw = trim((string)file_get_contents(lvDataFile()));
                if (strncmp($raw, 'LVENC1', 6) !== 0) $raw = lvEncryptPayload($raw === '' ? '[]' : $raw);
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="linkvault_backup_' . date('Y-m-d') . '.lvbak"');
                echo json_encode([
                    'format' => 'LVBACKUP1', 'version' => LV_VERSION, 'created' => time(),
                    'kdf_salt' => $cfg['kdf_salt'], 'wrapped_key' => $cfg['wrapped_key'], 'kdf_iters' => $cfg['kdf_iters'],
                    'data' => $raw,
                ], JSON_PRETTY_PRINT);
                exit;

            case 'backup_import':
                $pack = json_decode(lvUploadedFile('backup_file'), true);
                if (!is_array($pack) || ($pack['format'] ?? '') !== 'LVBACKUP1' || empty($pack['data'])) {
                    throw new Exception('Das ist keine LinkVault-Backup-Datei (.lvbak).');
                }
                $oldKey = lvUnwrapKey((string)($_POST['backup_password'] ?? ''), [
                    'kdf_salt' => (string)($pack['kdf_salt'] ?? ''), 'wrapped_key' => (string)($pack['wrapped_key'] ?? ''),
                    'kdf_iters' => (int)($pack['kdf_iters'] ?? 120000),
                ]);
                if ($oldKey === null) throw new Exception('Passwort passt nicht zu diesem Backup. Gemeint ist das Passwort von damals.');
                $json = lvDecryptWith($oldKey, (string)$pack['data']);
                $data = $json !== null ? json_decode($json, true) : null;
                if (!is_array($data)) throw new Exception('Backup ist beschädigt.');
                $items = [];
                $seen = [];
                foreach ($data as $raw) {
                    $item = sanitizeItem($raw, true);
                    if (!$item || isset($seen[$item['id']])) continue;
                    $seen[$item['id']] = true;
                    $items[] = $item;
                }
                backupBefore('restore');
                if (($_POST['mode'] ?? 'merge') === 'replace') {
                    $LV_CORRUPT = false;
                    $bookmarks = $items;
                    $msg = 'Backup eingespielt (' . count($items) . ' Einträge), der alte Stand liegt bei den Backups.';
                } else {
                    if ($LV_CORRUPT) throw new Exception('Die aktuellen Daten sind beschädigt. Bitte „Alles ersetzen“ wählen.');
                    $haveUrl = [];
                    $haveId = [];
                    foreach ($bookmarks as $b) { $haveUrl[(string)($b['url'] ?? '')] = true; $haveId[(string)($b['id'] ?? '')] = true; }
                    $n = 0;
                    foreach ($items as $item) {
                        if (!empty($item['deleted']) || isset($haveUrl[$item['url']])) continue;
                        if (isset($haveId[$item['id']])) $item['id'] = generateId();
                        $bookmarks[] = $item;
                        $haveUrl[$item['url']] = true;
                        $n++;
                    }
                    $msg = "$n neue Link(s) aus dem Backup übernommen.";
                }
                requireSave($bookmarks);
                jsonOut(['success' => true, 'message' => $msg, 'bookmarks' => $bookmarks]);

            /* ----- Import / Export ----- */

            case 'import':
                [$new, $skipped] = lvParseImport(lvUploadedFile('bookmark_file'), $bookmarks);
                $imported = count($new);
                if (!empty($_POST['dry'])) {
                    $folders = [];
                    foreach ($new as $n) $folders[$n['category']] = ($folders[$n['category']] ?? 0) + 1;
                    arsort($folders);
                    jsonOut(['success' => true, 'dry' => true, 'imported' => $imported, 'skipped' => $skipped,
                             'folders' => array_slice($folders, 0, 40, true), 'folder_count' => count($folders)]);
                }
                if ($imported > 0) {
                    backupBefore('import');
                    $bookmarks = array_merge($bookmarks, $new);
                    requireSave($bookmarks);
                }
                $msg = "$imported Links importiert." . ($skipped > 0 ? " $skipped waren schon da." : '');
                jsonOut(['success' => true, 'message' => $msg, 'bookmarks' => $bookmarks]);

            case 'export_json':
                $clean = [];
                foreach ($bookmarks as $bm) {
                    if (!$isLive($bm)) continue;
                    unset($bm['check'], $bm['deleted']);
                    $clean[] = $bm;
                }
                header('Content-Type: application/json; charset=utf-8');
                header('Content-Disposition: attachment; filename="bookmarks_' . date('Y-m-d') . '.json"');
                echo json_encode($clean, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
                exit;

            case 'export_html':
                header('Content-Type: text/html; charset=utf-8');
                header('Content-Disposition: attachment; filename="bookmarks_' . date('Y-m-d') . '.html"');
                echo '<!DOCTYPE NETSCAPE-Bookmark-file-1>' . "\n";
                echo '<!-- This is an automatically generated file. -->' . "\n";
                echo '<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">' . "\n";
                echo '<TITLE>Bookmarks</TITLE>' . "\n<H1>Bookmarks</H1>\n<DL><p>\n";
                $byCat = [];
                foreach ($bookmarks as $bm) {
                    if (!$isLive($bm)) continue;
                    $byCat[($bm['category'] ?? '') ?: 'Allgemein'][] = $bm;
                }
                ksort($byCat, SORT_NATURAL | SORT_FLAG_CASE);
                foreach ($byCat as $cat => $items) {
                    echo '    <DT><H3>' . htmlspecialchars((string)$cat, ENT_QUOTES, 'UTF-8') . '</H3>' . "\n    <DL><p>\n";
                    foreach ($items as $bm) {
                        $add = (int)($bm['created'] ?? time());
                        $tags = !empty($bm['tags']) && is_array($bm['tags']) ? ' TAGS="' . htmlspecialchars(implode(',', $bm['tags']), ENT_QUOTES, 'UTF-8') . '"' : '';
                        echo '        <DT><A HREF="' . htmlspecialchars($bm['url'] ?? '', ENT_QUOTES, 'UTF-8') . '" ADD_DATE="' . $add . '"' . $tags . '>'
                            . htmlspecialchars($bm['title'] ?? '', ENT_QUOTES, 'UTF-8') . '</A>' . "\n";
                    }
                    echo "    </DL><p>\n";
                }
                echo '</DL><p>';
                exit;

            default:
                throw new Exception('Unbekannte Aktion.');
        }
    } catch (Throwable $e) {
        $msg = get_class($e) === 'Exception' ? $e->getMessage() : 'Interner Fehler.';
        if (get_class($e) !== 'Exception') error_log('LinkVault: ' . $e->getMessage() . ' @' . $e->getLine());
        jsonOut(['success' => false, 'message' => $msg]);
    }
}
