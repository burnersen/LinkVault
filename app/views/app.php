<?php
/* LinkVault – Hauptseite */
defined('LV_VERSION') || exit;

$initialBookmarks = loadBookmarks();
$lvJsonFlags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
             | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
// Hinweis „seit der letzten Anmeldung“ nur einmal zeigen
$lvNotice = null;
$lvIsAdmin = false;
$lvUserName = '';
$lvPending = 0;
$lvPendingNames = [];
if (LV_AUTH_ENABLED) {
    $lvNotice = $_SESSION['lv_notice'] ?? null;
    unset($_SESSION['lv_notice']);
    // Bei langer Laufzeit die Cookies bei jedem Seitenaufruf verlängern
    $cfgNow = lvLoadAuthConfig();
    if ($cfgNow && $cfgNow['idle_minutes'] > 480 && isset($_COOKIE[LV_KEY_COOKIE])) {
        $exp = time() + $cfgNow['idle_minutes'] * 60;
        setcookie(LV_KEY_COOKIE, (string)$_COOKIE[LV_KEY_COOKIE], lvCookieOpts($exp));
        setcookie(session_name(), session_id(), lvCookieOpts($exp));
    }
    if ($cfgNow) {
        $lvUserName = $cfgNow['username'];
        $lvIsAdmin = $cfgNow['role'] === 'admin';
    }
    // Der Administrator sieht gleich beim Öffnen, ob jemand auf Freigabe wartet
    if ($lvIsAdmin) {
        foreach (lvListUsers() as $u) {
            if ($u['status'] !== 'pending') continue;
            $lvPending++;
            if (count($lvPendingNames) < 5) $lvPendingNames[] = $u['username'];
        }
    }
}
$lvCsrfPage = LV_AUTH_ENABLED ? lvCsrfToken() : '';
?>

<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <meta name="theme-color" content="#0b1120">
    <meta name="robots" content="noindex, nofollow">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="LinkVault">
    <title>LinkVault – Bookmark Manager</title>
    <link rel="icon" href="?action=icon" type="image/svg+xml">
    <link rel="apple-touch-icon" href="?action=icon&amp;s=192">
    <link rel="manifest" href="?action=manifest" crossorigin="use-credentials">
<?php if (LV_TAILWIND_CDN): ?>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: { slate: { 850: '#1a2332', 950: '#0b1120' } },
                    fontFamily: { sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'] }
                }
            }
        }
    </script>
<?php endif; ?>
<?php require LV_APP . '/views/app.css.php'; ?>
<?php lvUiHead(); ?>
</head>
<body class="antialiased">

<header id="appHeader" class="glass-strong border-b border-slate-700/40">
    <div class="max-w-7xl mx-auto px-3 sm:px-5 py-2.5" style="max-width:100%">
        <div class="header-row header-top">
            <div class="flex items-center gap-2 shrink-0">
                <div class="w-8 h-8 rounded-lg bg-gradient-to-br from-violet-500 to-purple-700 flex items-center justify-center shadow-[0_0_14px_-3px_rgba(139,92,246,0.5)]">
                    <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 5a2 2 0 012-2h10a2 2 0 012 2v16l-7-3.5L5 21V5z"/>
                    </svg>
                </div>
            </div>
            <div class="search-wrap" id="searchWrap">
                <svg class="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 pointer-events-none" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                </svg>
                <input type="search" id="searchInput" placeholder="Suchen… (#tag, URL einfügen = hinzufügen)" aria-label="Links durchsuchen"
                       class="field !py-2 !pl-8 !pr-2 !text-sm !rounded-lg" autocomplete="off">
                <button type="button" id="searchClear" class="search-clear" title="Suche leeren" aria-label="Suche leeren">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                </button>
            </div>
            <div class="header-actions">
                <button type="button" id="btnSelectMode" class="btn btn-icon" title="Mehrfachauswahl" aria-label="Mehrfachauswahl">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>
                    </svg>
                </button>
                <div class="relative">
                    <button type="button" id="btnView" class="btn btn-icon" title="Ansicht und Sortierung" aria-label="Ansicht und Sortierung" aria-haspopup="true">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h7v5H4V6zm9 0h7v5h-7V6zM4 15h16M4 19h16"/>
                        </svg>
                    </button>
                    <div id="viewMenu" class="tools-menu hidden glass rounded-xl shadow-2xl py-1">
                        <div class="menu-label">Darstellung</div>
                        <button type="button" class="menu-opt" data-view="cards">Karten</button>
                        <button type="button" class="menu-opt" data-view="list">Liste</button>
                        <button type="button" class="menu-opt" data-view="tiles">Kacheln</button>
                        <div class="menu-sep"></div>
                        <div class="menu-label">Sortierung</div>
                        <button type="button" class="menu-opt" data-sort="title">A → Z</button>
                        <button type="button" class="menu-opt" data-sort="title-desc">Z → A</button>
                        <button type="button" class="menu-opt" data-sort="newest">Neueste zuerst</button>
                        <button type="button" class="menu-opt" data-sort="oldest">Älteste zuerst</button>
                        <button type="button" class="menu-opt" data-sort="clicks">Oft benutzt</button>
                        <button type="button" class="menu-opt" data-sort="opened">Zuletzt geöffnet</button>
                        <button type="button" class="menu-opt" data-sort="domain">Nach Domain</button>
                        <button type="button" class="menu-opt" data-sort="folder">Nach Ordner</button>
                        <button type="button" class="menu-opt" id="optFavTop">Favoriten immer oben</button>
                        <button type="button" class="menu-opt" id="optTagBar">Tag-Leiste anzeigen</button>
                        <div class="menu-sep"></div>
                        <div class="menu-label">Gruppieren</div>
                        <button type="button" class="menu-opt" data-group="domain">Domains mit vielen Links</button>
                        <button type="button" class="menu-opt" data-group="folder">Nach Ordnern</button>
                        <button type="button" class="menu-opt" data-group="none">Gar nicht</button>
                    </div>
                </div>
                <div class="relative">
                    <button type="button" id="btnTools" class="btn btn-icon" title="Werkzeuge" aria-label="Werkzeuge" aria-haspopup="true">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"/>
                        </svg>
                    </button>
                    <div id="toolsMenu" class="tools-menu hidden glass rounded-xl shadow-2xl py-1">
                        <button type="button" id="btnImport" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg>
                            Importieren
                        </button>
                        <button type="button" data-export="json" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                            Export als JSON
                        </button>
                        <button type="button" data-export="html" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                            Export als HTML (Browser)
                        </button>
                        <div class="menu-sep"></div>
                        <button type="button" id="btnDedupe" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"/></svg>
                            Duplikate entfernen
                        </button>
                        <button type="button" id="btnAutoSort" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M7 3h5a1.99 1.99 0 011.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z"/></svg>
                            Automatisch sortieren
                        </button>
                        <button type="button" id="btnCheckDead" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                            Tote Links prüfen
                        </button>
                        <button type="button" id="btnFolders" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>
                            Ordner verwalten
                        </button>
                        <button type="button" id="btnTags" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 20l4-16m2 16l4-16M6 9h14M4 15h14"/></svg>
                            Tags verwalten
                        </button>
                        <button type="button" id="btnTrash" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                            Papierkorb <span class="badge" id="trashCount">0</span>
                        </button>
                        <button type="button" id="btnBackups" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                            Backups
                        </button>
                        <button type="button" id="btnBookmarklet" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 5a2 2 0 012-2h10a2 2 0 012 2v16l-7-3.5L5 21V5z"/></svg>
                            Schnell speichern / App
                        </button>
                        <button type="button" id="btnReload" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                            Neu laden
                        </button>
                        <div class="menu-sep"></div>
                        <button type="button" id="btnAccount" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                            Konto &amp; Sicherheit
                        </button>
                        <button type="button" id="btnLoginLog" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                            Anmeldeversuche
                        </button>
<?php if ($lvIsAdmin): ?>
                        <button type="button" id="btnUsers" class="menu-opt">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"/></svg>
                            Benutzer verwalten <span class="badge hot hidden" id="usersBadge">0</span>
                        </button>
<?php endif; ?>
                        <button type="button" id="btnLogout" class="menu-opt danger">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/></svg>
                            Abmelden
                        </button>
                        <div class="menu-sep"></div>
                        <div id="toolsStats" class="px-3 py-2 text-[11px] text-slate-500 leading-relaxed"></div>
                    </div>
                </div>
                <button type="button" id="btnAdd" class="btn btn-primary btn-add-desktop !px-3 !py-2">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"/>
                    </svg>
                    <span class="hidden md:inline">Hinzufügen</span>
                </button>
            </div>
        </div>
        <div class="mt-2.5 w-full min-w-0 overflow-hidden header-cats">
            <div id="categoryBar"></div>
            <div id="subCatBar"></div>
            <div id="tagBar" aria-label="Tags"></div>
        </div>
    </div>
</header>
<div id="headerSpacer" aria-hidden="true"></div>

<main class="max-w-7xl mx-auto px-3 sm:px-5 pt-4 safe-bottom" style="max-width:100%">
    <section id="favoritesSection" class="mb-6 hidden">
        <div class="flex items-center gap-2 mb-3">
            <svg class="w-4 h-4 text-amber-400" fill="currentColor" viewBox="0 0 20 20">
                <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z"/>
            </svg>
            <h2 class="text-xs font-semibold text-amber-300/90 uppercase tracking-wider">Favoriten</h2>
            <span id="favCount" class="text-[10px] text-slate-500 bg-slate-800/70 px-1.5 py-0.5 rounded"></span>
        </div>
        <div id="favoritesGrid" class="bookmarks-grid"></div>
    </section>

    <section id="mainSection">
        <div class="flex items-center gap-2 mb-3" id="sectionHeader">
            <h2 class="text-xs font-semibold text-slate-400 uppercase tracking-wider" id="sectionTitle">Alle Links</h2>
            <span id="totalCount" class="text-[10px] text-slate-500 bg-slate-800/70 px-1.5 py-0.5 rounded"></span>
        </div>
        <div id="bookmarksGrid" class="bookmarks-grid"></div>
    </section>

    <div id="emptyState" class="hidden empty-state rounded-2xl border border-slate-700/35 py-12 px-4 text-center mt-2">
        <div class="w-12 h-12 mx-auto mb-3 rounded-xl bg-slate-800/70 flex items-center justify-center">
            <svg class="w-6 h-6 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M5 5a2 2 0 012-2h10a2 2 0 012 2v16l-7-3.5L5 21V5z"/>
            </svg>
        </div>
        <h3 class="text-base font-semibold text-slate-200 mb-1" id="emptyTitle">Noch keine Links</h3>
        <p class="text-slate-400 text-sm mb-4 max-w-xs mx-auto" id="emptyText">Füge deinen ersten Link hinzu oder importiere Lesezeichen.</p>
        <button type="button" id="btnAddEmpty" class="btn btn-primary">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"/>
            </svg>
            Ersten Link hinzufügen
        </button>
    </div>
</main>

<button type="button" id="fabAdd" class="fab" title="Link hinzufügen" aria-label="Link hinzufügen">
    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"/>
    </svg>
</button>

<!-- BULK BAR -->
<div class="bulk-bar" id="bulkBar">
    <div class="bulk-inner">
        <span id="bulkCount" class="text-xs font-semibold text-violet-300 px-1.5 shrink-0">0</span>
        <button type="button" id="bulkSelectAll" class="btn btn-secondary !py-2 !px-2.5 !text-xs">Alle</button>
        <button type="button" id="bulkMove" class="btn btn-secondary !py-2 !px-2.5 !text-xs">
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>
            Ordner
        </button>
        <button type="button" id="bulkFav" class="btn btn-secondary !py-2 !px-2.5 !text-xs">
            <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20"><path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z"/></svg>
            Favorit
        </button>
        <button type="button" id="bulkDelete" class="btn btn-danger !py-2 !px-2.5 !text-xs">
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
            Löschen
        </button>
        <button type="button" id="bulkCancel" class="btn btn-ghost !py-2 !px-2 ml-auto text-slate-400">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
        </button>
    </div>
</div>

<!-- ADD/EDIT MODAL -->
<div id="modalOverlay" class="fixed inset-0 z-[70] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[90vh] overflow-y-auto">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between sticky top-0 bg-[rgba(15,23,42,0.95)] z-10">
            <h3 id="modalTitle" class="text-base font-semibold text-white">Link hinzufügen</h3>
            <button type="button" id="modalClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </button>
        </div>
        <form id="bookmarkForm" class="p-4 space-y-3.5">
            <input type="hidden" id="formId">
            <div>
                <label class="block text-xs font-medium text-slate-400 mb-1">Titel <span class="text-rose-400">*</span></label>
                <input type="text" id="formTitle" class="field" placeholder="z. B. GitHub" required>
            </div>
            <div>
                <label class="block text-xs font-medium text-slate-400 mb-1">URL <span class="text-rose-400">*</span></label>
                <div class="flex gap-2">
                    <input type="text" inputmode="url" id="formUrl" class="field flex-1 min-w-0" placeholder="https://…" required
                           autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false">
                    <button type="button" id="formFetchTitle" class="btn btn-secondary !px-3 shrink-0" title="Titel und Beschreibung von der Seite holen" aria-label="Titel und Beschreibung von der Seite holen">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                    </button>
                </div>
                <p id="formFetchHint" class="text-[11px] text-slate-500 mt-1 hidden"></p>
            </div>
            <div>
                <label class="block text-xs font-medium text-slate-400 mb-1.5">Ordner</label>
                <div id="formCatChips" class="flex flex-wrap gap-1.5 mb-2 max-h-28 overflow-y-auto"></div>
                <div class="flex gap-2">
                    <select id="formCategorySelect" class="field flex-1">
                        <option value="">— Ordner wählen —</option>
                    </select>
                </div>
                <div class="flex gap-2 mt-2">
                    <input type="text" id="formCategoryNew" class="field flex-1" placeholder="Oder neuen Ordner anlegen…">
                    <button type="button" id="formCatCreate" class="btn btn-secondary !px-3 shrink-0" title="Neuen Ordner übernehmen">+</button>
                </div>
                <input type="hidden" id="formCategory" value="Allgemein">
                <p class="text-[11px] text-slate-500 mt-1.5">Gewählt: <span id="formCatLabel" class="text-violet-300 font-medium">Allgemein</span></p>
                <datalist id="categoryList"></datalist>
            </div>
            <div>
                <label class="block text-xs font-medium text-slate-400 mb-1">Beschreibung <span class="text-slate-600">(optional)</span></label>
                <textarea id="formDescription" rows="2" class="field resize-none" placeholder="Kurze Notiz…"></textarea>
            </div>
            <div>
                <label class="block text-xs font-medium text-slate-400 mb-1" for="formTags">Schlagwörter <span class="text-slate-600">(optional, mit Komma trennen)</span></label>
                <input type="text" id="formTags" class="field" placeholder="z. B. go, tutorial, lesen" autocomplete="off" autocapitalize="off" spellcheck="false">
                <div id="formTagChips" class="tag-suggest"></div>
            </div>
            <div class="flex items-center gap-2.5 pt-0.5">
                <button type="button" id="formFavoriteToggle" class="toggle" role="switch" aria-checked="false"></button>
                <span class="text-sm text-slate-300">Als Favorit</span>
            </div>
            <div class="flex gap-2 pt-1">
                <button type="button" id="modalCancel" class="btn btn-secondary flex-1">Abbrechen</button>
                <button type="submit" id="modalSubmit" class="btn btn-primary flex-1">Speichern</button>
            </div>
        </form>
    </div>
</div>

<!-- MOVE MODAL -->
<div id="moveOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-sm glass-strong rounded-2xl shadow-2xl overflow-hidden">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between">
            <h3 class="text-base font-semibold text-white">In Ordner verschieben</h3>
            <button type="button" id="moveClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </button>
        </div>
        <div class="p-4 space-y-3">
            <p class="text-sm text-slate-400" id="moveHint">Wähle einen Ordner oder lege einen neuen an.</p>
            <div id="moveCatList" class="space-y-1.5 max-h-48 overflow-y-auto"></div>
            <div class="pt-1 border-t border-slate-700/40">
                <label class="block text-xs font-medium text-slate-400 mb-1.5">Neuer Ordner</label>
                <div class="flex gap-2">
                    <input type="text" id="moveNewCat" class="field flex-1" placeholder="Name eingeben…">
                    <button type="button" id="moveCreateBtn" class="btn btn-primary !px-3 shrink-0">Anlegen</button>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- IMPORT MODAL -->
<div id="importOverlay" class="fixed inset-0 z-[70] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between">
            <h3 class="text-base font-semibold text-white">Lesezeichen importieren</h3>
            <button type="button" id="importClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </button>
        </div>
        <div class="p-4">
            <p class="text-sm text-slate-400 mb-3 leading-relaxed">
                HTML-Datei aus <strong class="text-slate-200">Firefox</strong> oder <strong class="text-slate-200">Chrome</strong> hochladen,
                oder ein <strong class="text-slate-200">JSON-Backup</strong> aus dem eigenen Export. Vorhandene Links bleiben, doppelte werden übersprungen.
            </p>
            <form id="importForm" enctype="multipart/form-data">
                <label class="flex flex-col items-center justify-center w-full h-28 border-2 border-dashed border-slate-600 rounded-xl cursor-pointer hover:border-violet-500/50 hover:bg-slate-800/30 transition-colors">
                    <svg class="w-6 h-6 mb-1.5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/>
                    </svg>
                    <p class="text-sm text-slate-400"><span class="font-medium text-violet-400">Datei wählen</span></p>
                    <p class="text-xs text-slate-500 mt-0.5">.html / .htm / .json</p>
                    <input type="file" id="importFile" name="bookmark_file" accept=".html,.htm,.json,text/html,application/json" class="hidden" required>
                </label>
                <p id="importFileName" class="mt-2.5 text-sm text-violet-300 text-center hidden font-medium"></p>
                <div id="importPreview" class="box mt-3 hidden"></div>
                <button type="submit" id="importSubmit" class="btn btn-primary w-full mt-3" disabled>Importieren</button>
            </form>
        </div>
    </div>
</div>

<!-- CONFIRM -->
<div id="confirmOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-sm glass-strong rounded-2xl shadow-2xl overflow-hidden">
        <div class="p-4">
            <div class="w-10 h-10 rounded-xl bg-rose-500/15 flex items-center justify-center mb-3">
                <svg class="w-5 h-5 text-rose-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                </svg>
            </div>
            <h3 class="text-base font-semibold text-white mb-1" id="confirmTitle">Löschen?</h3>
            <p class="text-sm text-slate-400 leading-relaxed" id="confirmText">Dieser Vorgang kann nicht rückgängig gemacht werden.</p>
            <div class="flex gap-2 mt-4">
                <button type="button" id="confirmCancel" class="btn btn-secondary flex-1">Abbrechen</button>
                <button type="button" id="confirmOk" class="btn btn-danger flex-1">Löschen</button>
            </div>
        </div>
    </div>
</div>

<!-- DEAD LINKS MODAL -->
<div id="deadOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between shrink-0">
            <h3 class="text-base font-semibold text-white">Link-Check</h3>
            <button type="button" id="deadClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </button>
        </div>
        <div class="p-4 overflow-y-auto flex-1">
            <p class="text-sm text-slate-400 mb-2" id="deadHint">Prüfung läuft…</p>
            <div class="h-1.5 rounded-full bg-slate-800 overflow-hidden mb-3">
                <div id="deadBar" class="h-full bg-violet-500" style="width:0%;transition:width .3s ease"></div>
            </div>
            <div id="deadList" class="space-y-3"></div>
        </div>
        <div class="px-4 py-3 border-t border-slate-700/45 flex gap-2 shrink-0">
            <button type="button" id="deadCancel" class="btn btn-secondary flex-1">Schließen</button>
            <button type="button" id="deadDeleteBtn" class="btn btn-danger flex-1" disabled>Auswahl löschen</button>
        </div>
    </div>
</div>

<!-- FOLDERS MODAL -->
<div id="foldersOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between shrink-0">
            <h3 class="text-base font-semibold text-white">Ordner verwalten</h3>
            <button type="button" id="foldersClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </button>
        </div>
        <div class="p-4 overflow-y-auto flex-1">
            <p class="text-sm text-slate-400 mb-3 leading-relaxed">Namen ändern und mit „Speichern“ oder Enter übernehmen. „Löschen“ entfernt nur den Ordner, die Links darin bleiben und kommen nach „Allgemein“ (bei Unterordnern eine Ebene höher).</p>
            <div id="foldersList" class="space-y-1.5"></div>
        </div>
    </div>
</div>

<!-- AUTOMATISCH SORTIEREN -->
<div id="autoOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-lg glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between shrink-0">
            <h3 class="text-base font-semibold text-white">Automatisch sortieren</h3>
            <button type="button" id="autoClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>
        </div>
        <div class="p-4 overflow-y-auto flex-1">
            <p class="text-sm text-slate-400 mb-3 leading-relaxed">Vorschläge nach Domain, Stichwörtern, deinen Gruppen und deiner bisherigen Sortierung. Geändert wird erst, wenn du auf „Übernehmen“ tippst, vorher wird automatisch ein Backup angelegt.</p>
            <div class="box mb-3 as-opts">
                <label class="as-opt"><input type="checkbox" id="autoOptTags" checked> <span>Tags vorschlagen (vorhandene Tags bleiben)</span></label>
                <label class="as-opt"><input type="checkbox" id="autoOptFolders" checked> <span>Ordner vorschlagen für unsortierte Links („Allgemein“)</span></label>
                <label class="as-opt"><input type="checkbox" id="autoOptMove"> <span>Auch Links umsortieren, die schon in einem Ordner liegen</span></label>
                <button type="button" id="autoRulesBtn" class="btn btn-secondary w-full mt-2">Gruppen und Stichwörter bearbeiten</button>
            </div>
            <p class="text-sm text-slate-300 mb-2 font-medium" id="autoHint"></p>
            <div id="autoSummary" class="as-sum"></div>
            <div id="autoList" class="space-y-1.5"></div>
        </div>
        <div class="px-4 py-3 border-t border-slate-700/45 flex gap-2 shrink-0">
            <button type="button" id="autoCancel" class="btn btn-secondary flex-1">Abbrechen</button>
            <button type="button" id="autoApply" class="btn btn-primary flex-1" disabled>Übernehmen</button>
        </div>
    </div>
</div>

<!-- GRUPPEN FÜRS AUTOMATISCHE SORTIEREN -->
<div id="rulesOverlay" class="fixed inset-0 z-[78] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-lg glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between shrink-0">
            <h3 class="text-base font-semibold text-white">Gruppen und Stichwörter</h3>
            <button type="button" id="rulesClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>
        </div>
        <div class="p-4 overflow-y-auto flex-1">
            <p class="text-sm text-slate-400 mb-3 leading-relaxed">Passt ein Eintrag einer Gruppe zum Link, schlägt sie ihre Tags und ihren Ordner vor. Alles lässt sich ändern, abschalten oder löschen.</p>
            <div class="flex gap-2 mb-2">
                <button type="button" id="grpNew" class="btn btn-primary flex-1">Neue Gruppe</button>
                <button type="button" id="grpReset" class="btn btn-secondary flex-1">Standard wiederherstellen</button>
            </div>
            <input type="search" id="grpFilter" class="field mb-2" placeholder="Suchen: Name, Tag, Domain oder Stichwort" aria-label="Gruppen durchsuchen" autocomplete="off">
            <div id="grpList" class="space-y-1.5"></div>
            <datalist id="ruleFolderList"></datalist>
            <div class="box mt-3 as-help">
                <h4>So schreibst du Einträge</h4>
                <p><b>youtube.com</b> <span>= diese Domain samt Unterseiten</span><br>
                   <b>amazon.*</b> <span>= jede Endung, also amazon.de, amazon.com usw.</span><br>
                   <b>.xxx</b> <span>= alle Domains mit dieser Endung</span><br>
                   <b>rezept</b> <span>= ganzes Wort in Titel, Adresse oder Beschreibung</span><br>
                   <b>programmier*</b> <span>= Wortanfang, also auch „programmieren“</span><br>
                   <b>*xxx*</b> <span>= steht irgendwo, auch mitten im Wort</span></p>
                <p>Für den Ordner zählen Treffer über die Domain vor Stichwörtern. Sonst gewinnt die Gruppe weiter oben.</p>
            </div>
        </div>
        <div class="px-4 py-3 border-t border-slate-700/45 flex gap-2 shrink-0">
            <button type="button" id="rulesCancel" class="btn btn-secondary flex-1">Abbrechen</button>
            <button type="button" id="rulesSave" class="btn btn-primary flex-1">Speichern</button>
        </div>
    </div>
</div>

<!-- TAGS VERWALTEN -->
<div id="tagsOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between shrink-0">
            <h3 class="text-base font-semibold text-white">Tags verwalten</h3>
            <button type="button" id="tagsClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>
        </div>
        <div class="p-4 overflow-y-auto flex-1">
            <p class="text-sm text-slate-400 mb-3 leading-relaxed">Namen ändern und mit „Speichern“ oder Enter übernehmen. Heißt er dann wie ein anderer Tag, werden beide zusammengelegt. „Löschen“ nimmt den Tag von allen Links, die Links selbst bleiben.</p>
            <input type="search" id="tagsFilter" class="field mb-2" placeholder="Tags durchsuchen" aria-label="Tags durchsuchen" autocomplete="off">
            <div id="tagsList" class="space-y-1.5"></div>
        </div>
    </div>
</div>

<!-- BACKUPS MODAL -->
<div id="backupsOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between shrink-0">
            <h3 class="text-base font-semibold text-white">Backups</h3>
            <button type="button" id="backupsClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </button>
        </div>
        <div class="p-4 overflow-y-auto flex-1">
            <p class="text-sm text-slate-400 mb-3 leading-relaxed" id="backupsHint">LinkVault sichert automatisch: einen Stand pro Tag und einen vor jeder großen Aktion.</p>
            <div id="backupsList" class="space-y-1.5"></div>
            <div class="box mt-3">
                <h4>Komplett-Backup als Datei</h4>
                <p>Eine einzige Datei mit allen Links, verschlüsselt. Sie lässt sich nur mit deinem Passwort von heute öffnen. Am besten ab und zu herunterladen und woanders aufheben.</p>
                <button type="button" id="btnFullBackup" class="btn btn-primary w-full">Komplett-Backup herunterladen</button>
            </div>
            <div class="box mt-3">
                <h4>Backup-Datei einspielen</h4>
                <p>Eine früher heruntergeladene .lvbak-Datei zurückholen. Gefragt ist das Passwort, das beim Herunterladen galt.</p>
                <input type="file" id="backupFile" accept=".lvbak,application/octet-stream,application/json" class="field mb-2">
                <input type="password" id="backupPass" class="field mb-2" placeholder="Passwort des Backups" autocomplete="off">
                <select id="backupMode" class="field mb-2" aria-label="Art des Einspielens">
                    <option value="merge">Nur fehlende Links ergänzen</option>
                    <option value="replace">Alles ersetzen (jetziger Stand wird vorher gesichert)</option>
                </select>
                <button type="button" id="backupImportBtn" class="btn btn-secondary w-full">Einspielen</button>
            </div>
        </div>
    </div>
</div>

<!-- BOOKMARKLET MODAL -->
<div id="bookmarkletOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between">
            <h3 class="text-base font-semibold text-white">Schnell speichern</h3>
            <button type="button" id="bookmarkletClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </button>
        </div>
        <div class="p-4 space-y-3">
            <p class="text-sm text-slate-400 leading-relaxed">Zieh den Knopf in deine Lesezeichenleiste. Ein Klick darauf öffnet LinkVault, Adresse und Titel der aktuellen Seite sind dann schon eingetragen.</p>
            <div class="flex justify-center py-1">
                <a id="bookmarkletLink" href="#" class="btn btn-primary" draggable="true">+ LinkVault</a>
            </div>
            <div class="box">
                <h4>Als App aufs Handy</h4>
                <p id="installHint">iPhone: in Safari auf „Teilen“ tippen, dann „Zum Home-Bildschirm“. Android: im Browser-Menü „App installieren“ wählen, danach taucht LinkVault auch beim Teilen einer Seite in der Liste auf.</p>
                <button type="button" id="installBtn" class="btn btn-primary w-full hidden">Jetzt als App installieren</button>
            </div>
            <p class="text-xs text-slate-500 leading-relaxed">Ohne App: den Code kopieren und als Adresse eines Lesezeichens einfügen.</p>
            <button type="button" id="bookmarkletCopy" class="btn btn-secondary w-full">Code kopieren</button>
        </div>
    </div>
</div>

<!-- KONTO & SICHERHEIT -->
<div id="accountOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between shrink-0">
            <h3 class="text-base font-semibold text-white">Konto &amp; Sicherheit</h3>
            <button type="button" id="accountClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>
        </div>
        <form id="accountForm" class="p-4 overflow-y-auto flex-1 space-y-3">
            <div>
                <label class="lbl" for="accCurrent">Aktuelles Passwort <span class="text-rose-400">*</span></label>
                <input type="password" id="accCurrent" class="field" autocomplete="current-password">
                <p class="text-[11px] text-slate-500 mt-1">Nötig als Bestätigung für alles in diesem Fenster, außer „Automatisch abmelden“.</p>
            </div>

            <div class="box">
                <h4>Benutzername und Passwort ändern</h4>
                <label class="lbl" for="accUser">Neuer Benutzername</label>
                <input type="text" id="accUser" class="field mb-2" autocomplete="username" maxlength="64" placeholder="leer = unverändert">
                <label class="lbl" for="accNew">Neues Passwort (min. 12 Zeichen, Buchstaben + Zahlen)</label>
                <input type="password" id="accNew" class="field mb-2" autocomplete="new-password" placeholder="leer = nur Name ändern" minlength="12">
                <label class="lbl" for="accNew2">Neues Passwort wiederholen</label>
                <input type="password" id="accNew2" class="field mb-2" autocomplete="new-password">
                <button type="submit" class="btn btn-primary w-full">Zugangsdaten speichern</button>
                <p class="mt-2" style="margin-bottom:0">Nach einem Passwortwechsel werden alle anderen Geräte abgemeldet. Deine Links und Backups bleiben lesbar.</p>
            </div>

            <div class="box">
                <h4>Zwei-Faktor-Anmeldung (2FA)</h4>
                <p id="totpStatus">Lade…</p>
                <div class="row">
                    <button type="button" id="totpStart" class="btn btn-secondary hidden">Einrichten</button>
                    <button type="button" id="totpOff" class="btn btn-danger hidden">Abschalten</button>
                </div>
                <div id="totpSetup" class="hidden mt-3">
                    <p>1. Diesen Schlüssel in deine Authenticator-App eintragen (Aegis, 2FAS, Google Authenticator …). Am Handy reicht der Knopf darunter.</p>
                    <div class="mono-box" id="totpSecret"></div>
                    <div class="row mb-2">
                        <a id="totpLink" href="#" class="btn btn-secondary">In App öffnen</a>
                        <button type="button" id="totpCopy" class="btn btn-secondary">Schlüssel kopieren</button>
                    </div>
                    <p>2. Den 6-stelligen Code aus der App eingeben. Oben muss dein aktuelles Passwort stehen.</p>
                    <div class="row">
                        <input type="text" id="totpCode" class="field" style="flex:1 1 8rem" inputmode="numeric" maxlength="7" placeholder="123456" autocomplete="off">
                        <button type="button" id="totpEnable" class="btn btn-primary">Aktivieren</button>
                    </div>
                </div>
            </div>

            <div class="box">
                <h4>Wiederherstellungscode</h4>
                <p id="recStatus">Lade…</p>
                <div class="mono-box hidden" id="recCode"></div>
                <div class="row">
                    <button type="button" id="recCreate" class="btn btn-secondary">Neuen Code erzeugen</button>
                    <button type="button" id="recCopy" class="btn btn-secondary hidden">Kopieren</button>
                </div>
            </div>

            <div class="box">
                <h4>Automatisch abmelden</h4>
                <p>Nach so langer Pause musst du dich neu anmelden. Bis 8 Stunden endet die Anmeldung zusätzlich, wenn der Browser geschlossen wird.</p>
                <select id="accIdle" class="field" aria-label="Automatisch abmelden nach">
                    <option value="15">nach 15 Minuten</option>
                    <option value="60">nach 1 Stunde</option>
                    <option value="480">nach 8 Stunden</option>
                    <option value="1440">nach 1 Tag (angemeldet bleiben)</option>
                    <option value="10080">nach 7 Tagen (angemeldet bleiben)</option>
                    <option value="43200">nach 30 Tagen (angemeldet bleiben)</option>
                </select>
            </div>
        </form>
    </div>
</div>

<!-- PAPIERKORB -->
<div id="trashOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between shrink-0">
            <h3 class="text-base font-semibold text-white">Papierkorb</h3>
            <button type="button" id="trashClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>
        </div>
        <div class="p-4 overflow-y-auto flex-1">
            <p class="text-sm text-slate-400 mb-3 leading-relaxed">Gelöschte Links bleiben <?php echo (int)LV_TRASH_DAYS; ?> Tage hier liegen und verschwinden danach von selbst.</p>
            <div id="trashList" class="stack"></div>
        </div>
        <div class="px-4 py-3 border-t border-slate-700/45 flex gap-2 shrink-0">
            <button type="button" id="trashRestoreAll" class="btn btn-secondary flex-1">Alle zurückholen</button>
            <button type="button" id="trashEmpty" class="btn btn-danger flex-1">Papierkorb leeren</button>
        </div>
    </div>
</div>

<!-- ANMELDEVERSUCHE -->
<div id="logOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between shrink-0">
            <h3 class="text-base font-semibold text-white">Anmeldeversuche</h3>
            <button type="button" id="logClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>
        </div>
        <div class="p-4 overflow-y-auto flex-1">
            <div id="logSummary" class="box mb-3"></div>
            <div id="logList" class="stack"></div>
        </div>
        <div class="px-4 py-3 border-t border-slate-700/45 flex gap-2 shrink-0">
            <button type="button" id="logClear" class="btn btn-secondary flex-1">Liste leeren</button>
            <button type="button" id="logDone" class="btn btn-primary flex-1">Schließen</button>
        </div>
    </div>
</div>

<!-- BENUTZER VERWALTEN (nur Administrator) -->
<div id="usersOverlay" class="fixed inset-0 z-[75] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-md glass-strong rounded-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
        <div class="px-4 py-3.5 border-b border-slate-700/45 flex items-center justify-between shrink-0">
            <h3 class="text-base font-semibold text-white">Benutzer verwalten</h3>
            <button type="button" id="usersClose" class="btn btn-ghost" aria-label="Schließen">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>
        </div>
        <div class="p-4 overflow-y-auto flex-1">
            <div id="usersPendingBox" class="hidden mb-3">
                <h4 class="text-[11px] font-semibold uppercase tracking-wider text-amber-300 mb-2">Wartet auf deine Freigabe</h4>
                <div id="usersPending" class="stack"></div>
            </div>
            <h4 class="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">Benutzer</h4>
            <div id="usersList" class="stack"></div>
            <div class="box mt-3">
                <h4>Neue Zugangsanfragen</h4>
                <p>Ist das an, steht auf der Anmeldeseite „Zugang anfragen“. Rein kommt trotzdem nur, wen du hier freigibst.</p>
                <div class="row">
                    <button type="button" id="regToggle" class="toggle green" role="switch" aria-checked="false" aria-label="Neue Zugangsanfragen annehmen"></button>
                    <span class="text-sm text-slate-300" id="regToggleLabel">Lade…</span>
                </div>
            </div>
            <div class="box mt-3">
                <h4>Gut zu wissen</h4>
                <p style="margin-bottom:0">Jeder Benutzer hat einen eigenen Bereich mit eigenem Schlüssel. Du siehst hier nur die Namen, nie die Links der anderen, und die anderen sehen deine nicht. Ein vergessenes Passwort kannst du deshalb auch nicht zurücksetzen, dafür hat jeder seinen eigenen Wiederherstellungscode unter Konto &amp; Sicherheit.</p>
            </div>
        </div>
    </div>
</div>

<!-- ALLGEMEINES HINWEIS-FENSTER -->
<div id="dialogOverlay" class="fixed inset-0 z-[80] hidden items-center justify-center p-3 bg-black/65 backdrop-blur-sm">
    <div class="modal-panel w-full max-w-sm glass-strong rounded-2xl shadow-2xl overflow-hidden" role="dialog" aria-modal="true" aria-labelledby="dialogTitle">
        <div class="p-4">
            <h3 class="text-base font-semibold text-white mb-2" id="dialogTitle"></h3>
            <div class="text-sm text-slate-300 leading-relaxed" id="dialogBody"></div>
            <div class="flex gap-2 mt-4" id="dialogActions"></div>
        </div>
    </div>
</div>

<div id="toastContainer" class="fixed bottom-20 left-1/2 -translate-x-1/2 sm:bottom-6 sm:left-auto sm:right-4 sm:translate-x-0 z-[80] flex flex-col gap-2 pointer-events-none items-center sm:items-end px-3 w-full sm:w-auto max-w-sm"></div>

<form id="exportForm" method="POST" class="hidden">
    <input type="hidden" name="action" id="exportAction">
    <input type="hidden" name="csrf" id="exportCsrf" value="<?php echo htmlspecialchars($lvCsrfPage, ENT_QUOTES, 'UTF-8'); ?>">
</form>


<?php require LV_APP . '/views/app.js.php'; ?>
<?php lvUiFoot(); ?>

</body>
</html>
