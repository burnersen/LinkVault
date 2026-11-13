<?php
/* LinkVault – Einrichtung, Anmeldung, Wiederherstellung, Zugangsanfrage */
defined('LV_VERSION') || exit;

// Setup-, Login- oder Wiederherstellungs-Seite, wenn nicht angemeldet
if (LV_AUTH_ENABLED && !lvIsLoggedIn()) {
    $formError = '';
    $formOk = '';
    $cfgNow = lvLoadAuthConfig(false, '');
    $needsSetup = $cfgNow === null;
    $others = $needsSetup ? [] : lvListUsers();
    $multi = count($others) > 0;
    $hasTotp = !$needsSetup && !empty($cfgNow['totp']);
    $hasRecovery = !$needsSetup && !empty($cfgNow['rec_wrapped']);
    foreach ($others as $o) {
        if ($o['status'] !== 'active') continue;
        if (!empty($o['totp'])) $hasTotp = true;
        if (!empty($o['rec_wrapped'])) $hasRecovery = true;
    }
    $regOpen = !$needsSetup && lvRegisterOpen($cfgNow);
    $recoverMode = $hasRecovery && (isset($_GET['recover']) || isset($_POST['lv_recover']));
    $registerMode = !$recoverMode && $regOpen && !isset($_POST['lv_login']) && (isset($_GET['register']) || isset($_POST['lv_register']));
    lvStartSession();
    if (random_int(1, 15) === 1) lvSessionCleanup();
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
        if (!lvCsrfCheck()) {
            $formError = 'Sicherheits-Token ungültig. Bitte Seite neu laden und erneut versuchen.';
        } elseif ($needsSetup && isset($_POST['lv_setup'])) {
            try {
                if ((string)($_POST['password'] ?? '') !== (string)($_POST['password2'] ?? '')) throw new Exception('Passwörter stimmen nicht überein.');
                lvRunSetup(trim((string)($_POST['username'] ?? '')), (string)($_POST['password'] ?? ''));
                header('Location: ' . lvBackUrl());
                exit;
            } catch (Throwable $e) {
                $formError = get_class($e) === 'Exception' ? $e->getMessage() : 'Einrichtung fehlgeschlagen.';
            }
        } elseif (!$needsSetup && isset($_POST['lv_register'])) {
            try {
                if (!$regOpen) throw new Exception('Neue Anfragen sind im Moment geschlossen.');
                $throttleMsg = lvLoginThrottleCheck();
                if ($throttleMsg !== null) throw new Exception($throttleMsg);
                if (!lvRegThrottleOk()) throw new Exception('Von deinem Anschluss kamen heute schon mehrere Anfragen. Bitte morgen noch einmal versuchen.');
                if ((string)($_POST['password'] ?? '') !== (string)($_POST['password2'] ?? '')) throw new Exception('Passwörter stimmen nicht überein.');
                lvRegister(trim((string)($_POST['username'] ?? '')), (string)($_POST['password'] ?? ''), (string)($_POST['note'] ?? ''));
                lvRegThrottleHit();
                $formOk = 'Deine Anfrage ist raus. Sobald der Administrator dich freigeschaltet hat, kannst du dich hier mit deinem Namen und Passwort anmelden.';
                $registerMode = false;
            } catch (Throwable $e) {
                $formError = get_class($e) === 'Exception' ? $e->getMessage() : 'Die Anfrage hat nicht geklappt.';
            }
        } elseif (!$needsSetup && (isset($_POST['lv_login']) || isset($_POST['lv_recover']))) {
            $u = trim((string)($_POST['username'] ?? ''));
            $throttleMsg = lvLoginThrottleCheck();
            if ($throttleMsg !== null) {
                lvLogAttempt('locked', $u);
                $formError = $throttleMsg;
            } elseif (isset($_POST['lv_recover'])) {
                try {
                    $p = (string)($_POST['password'] ?? '');
                    if ($p !== (string)($_POST['password2'] ?? '')) throw new Exception('Passwörter stimmen nicht überein.');
                    lvCheckNewPassword($p);
                    if (lvRecover((string)($_POST['recovery_code'] ?? ''), $p, $multi ? $u : '')) {
                        lvLoginThrottleClear();
                        header('Location: ' . lvBackUrl());
                        exit;
                    }
                    lvLoginThrottleFail();
                    lvLogAttempt('recover', '');
                    $formError = $multi ? 'Benutzername oder Wiederherstellungscode stimmt nicht.' : 'Der Wiederherstellungscode stimmt nicht.';
                } catch (Throwable $e) {
                    $formError = get_class($e) === 'Exception' ? $e->getMessage() : 'Wiederherstellung fehlgeschlagen.';
                }
            } else {
                $result = lvLogin($u, (string)($_POST['password'] ?? ''), (string)($_POST['totp'] ?? ''));
                if ($result === 'ok') {
                    lvLoginThrottleClear();
                    header('Location: ' . lvBackUrl());
                    exit;
                }
                if ($result === 'pending') {
                    // Passwort war richtig, also kein Fehlversuch
                    $formError = 'Dein Konto wartet noch auf die Freigabe durch den Administrator.';
                } elseif ($result === 'blocked') {
                    $formError = 'Dein Zugang ist gesperrt. Bitte wende dich an den Administrator.';
                } else {
                    lvLoginThrottleFail();
                    lvLogAttempt($result === 'totp' ? 'totp' : 'fail', $u);
                    $formError = $result === 'totp' ? 'Der 2FA-Code fehlt oder stimmt nicht.' : 'Benutzername oder Passwort falsch.';
                }
            }
        }
    }
    $lvCsrf = lvCsrfToken();
    $e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
    $title = $needsSetup ? 'LinkVault – Einrichtung'
        : ($recoverMode ? 'LinkVault – Passwort vergessen' : ($registerMode ? 'LinkVault – Zugang anfragen' : 'LinkVault – Anmeldung'));
    $sub = $needsSetup
        ? 'Erster Start: Benutzer anlegen. Dein Passwort schützt Login und Verschlüsselung.'
        : ($recoverMode ? 'Mit dem Wiederherstellungscode ein neues Passwort setzen.'
        : ($registerMode ? 'Such dir Namen und Passwort aus. Danach muss dich der Administrator erst freischalten.' : 'Bitte anmelden'));
    $selfUrl = lvSelfPath();
    ?><!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <meta name="theme-color" content="#0b1120">
    <meta name="robots" content="noindex, nofollow">
    <title><?php echo $e($title); ?></title>
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="LinkVault">
    <link rel="icon" href="?action=icon" type="image/svg+xml">
    <link rel="apple-touch-icon" href="?action=icon&amp;s=192">
    <link rel="manifest" href="?action=manifest" crossorigin="use-credentials">
    <style>
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 100 900; font-display: swap; src: url('?action=font') format('woff2'); }
        * { box-sizing: border-box; }
        body {
            margin: 0; min-height: 100vh; min-height: 100dvh;
            font-family: Inter, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; color: #f1f5f9;
            background: linear-gradient(165deg, #0b1120 0%, #0f172a 45%, #1e1b4b 100%);
            display: flex; align-items: center; justify-content: center;
            padding: max(1rem, env(safe-area-inset-top)) max(1rem, env(safe-area-inset-right)) max(1rem, env(safe-area-inset-bottom)) max(1rem, env(safe-area-inset-left));
        }
        html { background: #0b1120; }
        .card {
            width: 100%; max-width: 22rem;
            background: rgba(15, 23, 42, 0.92);
            border: 1px solid rgba(51, 65, 85, 0.55);
            border-radius: 1rem; padding: 1.5rem;
            box-shadow: 0 20px 40px -12px rgba(0,0,0,0.5);
        }
        .logo {
            width: 2.5rem; height: 2.5rem; border-radius: 0.65rem;
            background: linear-gradient(135deg, #8b5cf6, #7c3aed);
            display: flex; align-items: center; justify-content: center;
            margin: 0 auto 1rem;
            box-shadow: 0 0 14px -3px rgba(139, 92, 246, 0.5);
        }
        h1 { text-align: center; font-size: 1.15rem; margin: 0 0 0.25rem; }
        p.sub { text-align: center; color: #94a3b8; font-size: 0.85rem; margin: 0 0 1.25rem; line-height: 1.45; }
        label { display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.35rem; }
        input {
            width: 100%; padding: 0.7rem 0.85rem; border-radius: 0.7rem;
            background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(71, 85, 105, 0.55);
            color: #f1f5f9; font-size: 1rem; margin-bottom: 0.85rem; font-family: inherit;
        }
        input:focus { outline: none; border-color: rgba(139, 92, 246, 0.55); box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.2); }
        button {
            width: 100%; padding: 0.75rem; border: none; border-radius: 0.7rem;
            background: linear-gradient(135deg, #8b5cf6, #7c3aed); color: #fff;
            font-weight: 600; font-size: 0.9rem; cursor: pointer; font-family: inherit;
            box-shadow: 0 4px 14px -3px rgba(139, 92, 246, 0.45);
        }
        button:hover { background: linear-gradient(135deg, #a78bfa, #8b5cf6); }
        .err {
            background: rgba(127, 29, 29, 0.35); border: 1px solid rgba(185, 28, 28, 0.4);
            color: #fca5a5; font-size: 0.85rem; padding: 0.6rem 0.75rem;
            border-radius: 0.6rem; margin-bottom: 0.85rem; text-align: center;
        }
        .ok {
            background: rgba(6, 78, 59, 0.35); border: 1px solid rgba(16, 185, 129, 0.4);
            color: #6ee7b7; font-size: 0.85rem; padding: 0.6rem 0.75rem; line-height: 1.45;
            border-radius: 0.6rem; margin-bottom: 0.85rem; text-align: center;
        }
        .hint { text-align: center; color: #64748b; font-size: 0.72rem; margin-top: 1rem; line-height: 1.45; }
        .hint a { color: #a78bfa; }
    </style>
<?php lvUiHead(); ?>
</head>
<body>
    <div class="card">
        <div class="logo">
            <svg width="18" height="18" fill="none" stroke="#fff" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 5a2 2 0 012-2h10a2 2 0 012 2v16l-7-3.5L5 21V5z"/></svg>
        </div>
        <h1>LinkVault</h1>
        <p class="sub"><?php echo $e($sub); ?></p>
        <?php if ($formError !== ''): ?><div class="err" role="alert"><?php echo $e($formError); ?></div><?php endif; ?>
        <?php if ($formOk !== ''): ?><div class="ok" role="status"><?php echo $e($formOk); ?></div><?php endif; ?>
        <?php if ($needsSetup): ?>
        <form method="post" action="">
            <input type="hidden" name="lv_setup" value="1">
            <input type="hidden" name="csrf" value="<?php echo $e($lvCsrf); ?>">
            <label for="username">Benutzername</label>
            <input type="text" id="username" name="username" required autofocus autocomplete="username" minlength="2" maxlength="64" value="<?php echo $e($_POST['username'] ?? ''); ?>">
            <label for="password">Passwort (min. 12 Zeichen, Buchstaben + Zahlen)</label>
            <input type="password" id="password" name="password" required autocomplete="new-password" minlength="12">
            <label for="password2">Passwort wiederholen</label>
            <input type="password" id="password2" name="password2" required autocomplete="new-password" minlength="12">
            <button type="submit">Konto anlegen</button>
        </form>
        <p class="hint">Es wird ein eigener Verschlüsselungsschlüssel erzeugt und mit deinem Passwort geschützt. Ohne Passwort sind die Daten nicht lesbar. Leg dir danach unter Werkzeuge → Konto &amp; Sicherheit einen Wiederherstellungscode an. Dieses erste Konto ist der Administrator: Wer später dazukommen will, braucht deine Freigabe.</p>
        <?php elseif ($recoverMode): ?>
        <form method="post" action="">
            <input type="hidden" name="lv_recover" value="1">
            <input type="hidden" name="csrf" value="<?php echo $e($lvCsrf); ?>">
            <?php if ($multi): ?>
            <label for="username">Benutzername</label>
            <input type="text" id="username" name="username" required autocomplete="username" autocapitalize="none" value="<?php echo $e($_POST['username'] ?? ''); ?>">
            <?php endif; ?>
            <label for="recovery_code">Wiederherstellungscode</label>
            <input type="text" id="recovery_code" name="recovery_code" required autofocus autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX">
            <label for="password">Neues Passwort (min. 12 Zeichen, Buchstaben + Zahlen)</label>
            <input type="password" id="password" name="password" required autocomplete="new-password" minlength="12">
            <label for="password2">Neues Passwort wiederholen</label>
            <input type="password" id="password2" name="password2" required autocomplete="new-password" minlength="12">
            <button type="submit">Neues Passwort setzen</button>
        </form>
        <p class="hint">Der Code ist danach verbraucht, eine Zwei-Faktor-Anmeldung wird abgeschaltet. <a href="<?php echo $e($selfUrl); ?>">Zurück zur Anmeldung</a></p>
        <?php elseif ($registerMode): ?>
        <form method="post" action="">
            <input type="hidden" name="lv_register" value="1">
            <input type="hidden" name="csrf" value="<?php echo $e($lvCsrf); ?>">
            <label for="username">Benutzername</label>
            <input type="text" id="username" name="username" required autofocus autocomplete="username" autocapitalize="none" minlength="2" maxlength="64" value="<?php echo $e($_POST['username'] ?? ''); ?>">
            <label for="password">Passwort (min. 12 Zeichen, Buchstaben + Zahlen)</label>
            <input type="password" id="password" name="password" required autocomplete="new-password" minlength="12">
            <label for="password2">Passwort wiederholen</label>
            <input type="password" id="password2" name="password2" required autocomplete="new-password" minlength="12">
            <label for="note">Nachricht an den Administrator (freiwillig)</label>
            <input type="text" id="note" name="note" maxlength="300" autocomplete="off" placeholder="z. B. wer du bist" value="<?php echo $e($_POST['note'] ?? ''); ?>">
            <button type="submit">Zugang anfragen</button>
        </form>
        <p class="hint">Du bekommst einen eigenen Bereich mit eigenem Schlüssel, den nur dein Passwort öffnet. Niemand sonst kann deine Links lesen, auch der Administrator nicht. Er kann dein Passwort deshalb auch nicht zurücksetzen. <a href="<?php echo $e($selfUrl); ?>">Zurück zur Anmeldung</a></p>
        <?php else: ?>
        <form method="post" action="">
            <input type="hidden" name="lv_login" value="1">
            <input type="hidden" name="csrf" value="<?php echo $e($lvCsrf); ?>">
            <label for="username">Benutzername</label>
            <input type="text" id="username" name="username" required autofocus autocomplete="username" autocapitalize="none" value="<?php echo $e($_POST['username'] ?? ''); ?>">
            <label for="password">Passwort</label>
            <input type="password" id="password" name="password" required autocomplete="current-password">
            <?php if ($hasTotp): ?>
            <label for="totp"><?php echo $multi ? '2FA-Code (nur wenn du 2FA eingerichtet hast)' : '2FA-Code aus der Authenticator-App'; ?></label>
            <input type="text" id="totp" name="totp" <?php echo $multi ? '' : 'required'; ?> inputmode="numeric" pattern="[0-9 ]*" maxlength="7" autocomplete="one-time-code" placeholder="123456">
            <?php endif; ?>
            <button type="submit">Anmelden</button>
        </form>
        <?php if ($hasRecovery || $regOpen): ?>
        <p class="hint">
            <?php if ($hasRecovery): ?><a href="?recover=1">Passwort vergessen oder Handy weg?</a><?php endif; ?>
            <?php if ($hasRecovery && $regOpen): ?><br><?php endif; ?>
            <?php if ($regOpen): ?><a href="?register=1">Noch kein Konto? Zugang anfragen</a><?php endif; ?>
        </p>
        <?php endif; ?>
        <?php endif; ?>
    </div>
<?php lvUiFoot(); ?>
</body>
</html><?php
    exit;
}
