<?php defined('LV_VERSION') || exit; ?>
<script nonce="<?php echo htmlspecialchars($LV_NONCE, ENT_QUOTES, 'UTF-8'); ?>">
(() => {
    'use strict';
    let bookmarks = <?php echo json_encode($initialBookmarks, $lvJsonFlags) ?: '[]'; ?>;
    const LV_CORRUPT = <?php echo $LV_CORRUPT ? 'true' : 'false'; ?>;
    let LV_CSRF = <?php echo json_encode($lvCsrfPage, $lvJsonFlags); ?>;
    const LV_NOTICE = <?php echo json_encode($lvNotice, $lvJsonFlags) ?: 'null'; ?>;
    const LV_VERSION = <?php echo json_encode(LV_VERSION); ?>;
    const LV_ADMIN = <?php echo $lvIsAdmin ? 'true' : 'false'; ?>;
    const LV_USER = <?php echo json_encode($lvUserName, $lvJsonFlags) ?: '""'; ?>;
    const LV_PENDING_NAMES = <?php echo json_encode($lvPendingNames, $lvJsonFlags) ?: '[]'; ?>;
    let pendingCount = <?php echo (int)$lvPending; ?>;
    const TRASH_DAYS = <?php echo (int)LV_TRASH_DAYS; ?>;

    // Einstellungen dieses Geräts (nur Ansicht, nichts Geheimes)
    const store = {
        // Läuft über lvUi (Block am Dateiende), damit Änderungen auch am Konto gespeichert werden
        get(k, d) { try { const v = window.lvUi ? window.lvUi.get(k) : localStorage.getItem(k); return (v === null || v === undefined) ? d : v; } catch (_) { return d; } },
        set(k, v) { try { if (window.lvUi) window.lvUi.put(k, v); else localStorage.setItem(k, v); } catch (_) {} }
    };
    const oneOf = (v, list, d) => list.includes(v) ? v : d;
    let currentCategory = store.get('lv_cat', 'all');
    let searchQuery = '';
    let sortMode = oneOf(store.get('lv_sort', 'title'), ['title', 'title-desc', 'newest', 'oldest', 'clicks', 'opened', 'domain', 'folder'], 'title');
    // „Kompakt“ (bis 3.4) zeigte keine Adresse und heißt jetzt „Kacheln“
    let viewMode = oneOf({ compact: 'tiles' }[store.get('lv_view', 'cards')] || store.get('lv_view', 'cards'), ['cards', 'list', 'tiles'], 'cards');
    let groupMode = oneOf(store.get('lv_group', 'domain'), ['domain', 'folder', 'none'], 'domain');
    let favTop = store.get('lv_favtop', '1') === '1';
    let tagBarOn = store.get('lv_tagbar', '1') !== '0';
    let editingId = null;
    let formFavorite = false;
    let selectMode = false;
    let selected = new Set();
    let lastSelected = null;
    let kbCursor = null;   // Tastatur-Rahmen der Pfeiltasten: { el, id }
    let dragIds = null;
    let lastSync = Date.now();
    // Welche Gruppen ausgeklappt sind (bleibt nach render erhalten)
    let openDomains = new Set();
    try {
        const saved = JSON.parse(store.get('lv_open_domains', '[]'));
        if (Array.isArray(saved)) saved.forEach(d => openDomains.add(d));
    } catch (_) {}
    function persistOpenDomains() { store.set('lv_open_domains', JSON.stringify([...openDomains])); }

    const $ = s => document.querySelector(s);
    const $$ = s => document.querySelectorAll(s);

    const searchInput = $('#searchInput');
    const categoryBar = $('#categoryBar');
    const subCatBar = $('#subCatBar');
    const tagBar = $('#tagBar');
    const mainEl = document.querySelector('main');
    const favoritesSection = $('#favoritesSection');
    const favoritesGrid = $('#favoritesGrid');
    const bookmarksGrid = $('#bookmarksGrid');
    const emptyState = $('#emptyState');
    const totalCount = $('#totalCount');
    const favCount = $('#favCount');
    const sectionTitle = $('#sectionTitle');
    const sectionHeader = $('#sectionHeader');
    const modalOverlay = $('#modalOverlay');
    const importOverlay = $('#importOverlay');
    const confirmOverlay = $('#confirmOverlay');
    const moveOverlay = $('#moveOverlay');
    const bookmarkForm = $('#bookmarkForm');
    const toastContainer = $('#toastContainer');
    const favToggle = $('#formFavoriteToggle');
    const btnSelectMode = $('#btnSelectMode');
    const bulkCount = $('#bulkCount');
    const canDrag = window.matchMedia && window.matchMedia('(hover: hover) and (pointer: fine)').matches;
    const SEP = ' > ';

    const live = () => bookmarks.filter(b => !b.deleted);
    const trashed = () => bookmarks.filter(b => b.deleted);
    const byId = id => bookmarks.find(b => b.id === id);
    const isWeb = u => /^https?:\/\//i.test(u || '');

    // Auch Anführungszeichen maskieren, die Werte landen teils in HTML-Attributen
    const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
    function escapeHtml(str) {
        if (str === null || str === undefined || str === '') return '';
        return String(str).replace(/[&<>"']/g, c => ESC_MAP[c]);
    }
    function getDomain(url) {
        try { return new URL(url).hostname.replace(/^www\./, ''); }
        catch (_) { return url || ''; }
    }
    // Für die Anzeige auf der Karte: Adresse ohne „https://“ und „www.“, damit man Links derselben Seite auseinanderhält
    function shortUrl(url) {
        try {
            const u = new URL(url);
            if (!u.hostname) return url || '';
            let rest = (u.pathname + u.search + u.hash).replace(/\/$/, '');
            try { rest = decodeURI(rest); } catch (_) {}
            return u.hostname.replace(/^www\./, '') + rest;
        } catch (_) { return url || ''; }
    }
    // Ersatz-Icon mit dem Anfangsbuchstaben, falls eine Seite kein eigenes Icon hat
    function letterIcon(ch) {
        const c = escapeHtml((ch || '?').toUpperCase());
        return 'data:image/svg+xml,' + encodeURIComponent(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#334155"/>'
            + '<text x="12" y="16.5" text-anchor="middle" font-family="system-ui,sans-serif" font-size="12" font-weight="700" fill="#cbd5e1">' + c + '</text></svg>');
    }
    function faviconSrc(domain) {
        return /^[a-z0-9.-]+\.[a-z0-9-]+$/i.test(domain || '') ? `?action=favicon&domain=${encodeURIComponent(domain)}` : letterIcon((domain || '?')[0]);
    }
    document.addEventListener('error', e => {
        const t = e.target;
        if (t && t.tagName === 'IMG' && t.dataset && t.dataset.letter !== undefined && !t.dataset.fb) {
            t.dataset.fb = '1';
            t.src = letterIcon(t.dataset.letter);
        }
    }, true);

    const topOf = cat => (cat || 'Allgemein').split(SEP)[0];
    const prettyCat = cat => (cat || 'Allgemein').split(SEP).join(' › ');
    function inCat(bmCat, cur) {
        const a = (bmCat || '').toLowerCase(), b = (cur || '').toLowerCase();
        return a === b || a.startsWith(b + SEP);
    }
    function getCategories() {
        const s = new Set();
        live().forEach(b => { if (b.category) s.add(b.category); });
        return Array.from(s).sort((a, b) => a.localeCompare(b, 'de'));
    }
    function allTags() {
        const count = {};
        live().forEach(b => (b.tags || []).forEach(t => { count[t] = (count[t] || 0) + 1; }));
        return Object.keys(count).sort((a, b) => count[b] - count[a] || a.localeCompare(b, 'de'));
    }
    // Für Duplikat-Erkennung: www., Schrägstrich am Ende und Groß/Klein egal
    function normUrl(u) {
        try {
            const p = new URL(u);
            const host = p.hostname.replace(/^www\./, '');
            const path = (p.pathname || '/').replace(/\/$/, '') || '/';
            return (host + path + (p.search || '')).toLowerCase();
        } catch (_) { return (u || '').toLowerCase(); }
    }
    // Merkt sich den zuletzt geöffneten Eintrag (nur für diesen Tab) und hebt ihn hervor
    let lastOpened = '';
    try { lastOpened = sessionStorage.getItem('lv_last_opened') || ''; } catch (_) {}
    function markOpened(id) {
        lastOpened = String(id);
        try { sessionStorage.setItem('lv_last_opened', lastOpened); } catch (_) {}
        document.querySelectorAll('.bookmark-card.last-opened').forEach(c => c.classList.remove('last-opened'));
        document.querySelectorAll('.bookmark-card').forEach(c => { if (c.dataset.id === lastOpened) c.classList.add('last-opened'); });
    }
    function trackVisit(bm) {
        markOpened(bm.id);
        bm.clicks = (bm.clicks || 0) + 1;
        bm.opened = Math.floor(Date.now() / 1000);
        api('visit', { id: bm.id });
    }
    function openLink(bm) {
        if (!isWeb(bm.url)) { showToast('Das ist kein Web-Link', 'error'); return; }
        window.open(bm.url, '_blank', 'noopener,noreferrer');
        trackVisit(bm);
    }
    function copyText(text, okMsg) {
        const fallback = () => {
            const ta = document.createElement('textarea');
            ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
            document.body.appendChild(ta); ta.select();
            let ok = false;
            try { ok = document.execCommand('copy'); } catch (_) {}
            ta.remove();
            showToast(ok ? okMsg : 'Kopieren fehlgeschlagen', ok ? 'success' : 'error');
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => showToast(okMsg)).catch(fallback);
        } else fallback();
    }
    const fmtDate = ts => new Date(ts * 1000).toLocaleString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });

    // Fuzzy helpers: normalize + token match across all fields
    function normalizeText(str) {
        return (str || '')
            .toLowerCase()
            .normalize('NFD')
            .replace(/[\u0300-\u036f]/g, '')
            .replace(/[^\p{L}\p{N}\s./:_-]+/gu, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    }
    function fuzzyMatch(haystack, query) {
        if (!query) return true;
        const hay = normalizeText(haystack);
        const tokens = normalizeText(query).split(' ').filter(Boolean);
        if (!tokens.length) return true;
        // Every token must appear somewhere (order independent)
        return tokens.every(t => hay.includes(t));
    }
    function bookmarkSearchText(bm) {
        return [bm.title, bm.url, bm.description, bm.category, getDomain(bm.url || ''), (bm.tags || []).join(' ')].filter(Boolean).join(' ');
    }
    // Alle vorhandenen Tags (normalisiert), neu berechnet, sobald sich die Liste ändert
    let tagSetSrc = null, tagSet = new Set();
    function knownTags() {
        if (tagSetSrc !== bookmarks) {
            tagSetSrc = bookmarks;
            tagSet = new Set();
            bookmarks.forEach(b => { if (!b.deleted) (b.tags || []).forEach(t => tagSet.add(normalizeText(t))); });
        }
        return tagSet;
    }
    // Suche: normale Wörter überall, „#wort“ nur in den Schlagwörtern.
    // Gibt es genau diesen Tag, zählt nur er (Tag-Leiste), sonst alle, die so anfangen (#lin findet #linux)
    function matchesSearch(bm) {
        if (!searchQuery) return true;
        const tokens = searchQuery.split(/\s+/).filter(Boolean);
        const tagTokens = tokens.filter(t => t.length > 1 && t[0] === '#').map(t => normalizeText(t.slice(1)));
        const rest = tokens.filter(t => !(t.length > 1 && t[0] === '#')).join(' ');
        if (tagTokens.length) {
            const tags = (bm.tags || []).map(normalizeText);
            const known = knownTags();
            if (!tagTokens.every(t => known.has(t) ? tags.includes(t) : tags.some(x => x.startsWith(t)))) return false;
        }
        return fuzzyMatch(bookmarkSearchText(bm), rest);
    }
    // action = { label, fn } zeigt einen Knopf im Hinweis (z. B. „Rückgängig“)
    function showToast(msg, type = 'success', action = null) {
        const t = document.createElement('div');
        t.className = `toast pointer-events-auto flex items-center gap-2 px-3.5 py-2.5 rounded-xl shadow-xl text-sm font-medium max-w-full ${
            type === 'success' ? 'bg-emerald-600/95 text-white' : 'bg-rose-600/95 text-white'
        }`;
        t.innerHTML = `<span class="${type === 'success' ? 'truncate' : 'min-w-0'}">${escapeHtml(msg)}</span>`;
        const close = () => { t.style.opacity = '0'; t.style.transition = 'opacity 0.25s'; setTimeout(() => t.remove(), 250); };
        if (action) {
            const b = document.createElement('button');
            b.type = 'button';
            b.className = 'shrink-0 font-semibold underline underline-offset-2 px-1';
            b.textContent = action.label;
            b.addEventListener('click', () => { close(); action.fn(); });
            t.appendChild(b);
        }
        toastContainer.appendChild(t);
        setTimeout(close, action ? 8000 : (type === 'success' ? 2800 : 6000));
    }
    async function api(action, data = {}, files = null) {
        const fd = new FormData();
        fd.append('action', action);
        fd.append('csrf', LV_CSRF);
        for (const [k, v] of Object.entries(data)) {
            fd.append(k, (v !== null && typeof v === 'object') ? JSON.stringify(v) : v);
        }
        if (files) for (const [k, f] of Object.entries(files)) fd.append(k, f);
        let res, text;
        try {
            res = await fetch('', { method: 'POST', body: fd, credentials: 'same-origin', headers: { 'X-CSRF-Token': LV_CSRF } });
            text = await res.text();
        } catch (e) {
            return { success: false, message: 'Keine Verbindung zum Server.' };
        }
        try {
            const parsed = JSON.parse(text);
            if (parsed && parsed.auth_required) {
                showToast('Sitzung abgelaufen, bitte neu anmelden', 'error');
                setTimeout(() => { location.reload(); }, 1200);
            }
            if (parsed && parsed.csrf) setCsrf(parsed.csrf);
            if (parsed && typeof parsed.pending === 'number') syncPending(parsed.pending, true);
            if (parsed && parsed.success) lastSync = Date.now();
            return parsed;
        } catch (e) {
            if (res.status === 403) return { success: false, message: 'Sicherheits-Token abgelaufen. Bitte Seite neu laden.' };
            return { success: false, message: 'Server-Antwort ungültig (HTTP ' + res.status + '). Schreibrechte oder PHP-Fehler prüfen.' };
        }
    }
    function setCsrf(token) {
        LV_CSRF = token;
        const f = $('#exportCsrf');
        if (f) f.value = token;
    }
    // Antwort übernehmen: neue Liste zeigen, Meldung ausgeben. Ergebnis: hat geklappt?
    function applyRes(res, fallbackMsg, quiet) {
        if (res && res.success) {
            if (Array.isArray(res.bookmarks)) bookmarks = res.bookmarks;
            render();
            if (!quiet) showToast(res.message || fallbackMsg || 'Gespeichert');
            return true;
        }
        showToast((res && res.message) || 'Fehler', 'error');
        return false;
    }

    /* ---------- Fenster ---------- */
    let overlayReturnFocus = null;
    let dialogQueue = [];      // Hinweis-Fenster, die warten, bis das vorige zu ist
    let dialogDismiss = null;
    function showOverlay(el) {
        if (!overlayReturnFocus) overlayReturnFocus = document.activeElement;
        el.classList.remove('hidden'); el.classList.add('flex');
    }
    function hideOverlay(el) {
        el.classList.add('hidden'); el.classList.remove('flex');
        if (!anyOverlayOpen() && overlayReturnFocus) {
            try { overlayReturnFocus.focus({ preventScroll: true }); } catch (_) {}
            overlayReturnFocus = null;
        }
        if (dialogQueue.length) setTimeout(pumpDialogs, 200);
    }
    function pumpDialogs() {
        if (dialogQueue.length && !anyOverlayOpen()) showDialog(dialogQueue.shift());
    }
    function anyOverlayOpen() {
        return Array.from($$('[id$="Overlay"]')).some(o => !o.classList.contains('hidden'));
    }
    // Eigene Rückfrage statt des Browser-Fensters. Ergebnis: Promise<true|false>
    let confirmResolve = null;
    function confirmDialog({ title, text, ok = 'OK', danger = false }) {
        if (confirmResolve) confirmResolve(false);
        $('#confirmTitle').textContent = title;
        $('#confirmText').textContent = text || '';
        const okBtn = $('#confirmOk');
        okBtn.textContent = ok;
        okBtn.className = 'btn flex-1 ' + (danger ? 'btn-danger' : 'btn-primary');
        const icon = confirmOverlay.querySelector('.w-10');
        if (icon) icon.style.display = danger ? '' : 'none';
        showOverlay(confirmOverlay);
        setTimeout(() => okBtn.focus(), 60);
        return new Promise(resolve => { confirmResolve = resolve; });
    }
    function closeConfirm(result) {
        hideOverlay(confirmOverlay);
        if (confirmResolve) { const r = confirmResolve; confirmResolve = null; r(!!result); }
    }
    $('#confirmCancel').addEventListener('click', () => closeConfirm(false));
    $('#confirmOk').addEventListener('click', () => closeConfirm(true));
    confirmOverlay.addEventListener('click', e => { if (e.target === confirmOverlay) closeConfirm(false); });

    const dialogOverlay = $('#dialogOverlay');
    function showDialog(opts) {
        // Ist schon ein Hinweis offen, kommt dieser danach dran
        if (!dialogOverlay.classList.contains('hidden')) { dialogQueue.push(opts); return; }
        const { title, html, buttons, onDismiss } = opts;
        dialogDismiss = onDismiss || null;
        $('#dialogTitle').textContent = title;
        $('#dialogBody').innerHTML = html;
        const box = $('#dialogActions');
        box.innerHTML = '';
        (buttons || [{ label: 'OK', primary: true }]).forEach(b => {
            const el = document.createElement('button');
            el.type = 'button';
            el.className = 'btn flex-1 ' + (b.danger ? 'btn-danger' : (b.primary ? 'btn-primary' : 'btn-secondary'));
            if (b.primary) el.dataset.main = '1';
            el.textContent = b.label;
            el.addEventListener('click', () => closeDialog(b.fn));
            box.appendChild(el);
        });
        showOverlay(dialogOverlay);
    }
    function closeDialog(fn) {
        const dismiss = dialogDismiss;
        dialogDismiss = null;
        hideOverlay(dialogOverlay);
        if (fn) fn(); else if (dismiss) dismiss();
    }
    dialogOverlay.addEventListener('click', e => { if (e.target === dialogOverlay) closeDialog(); });
    // Rückfrage mit Passwort. Ergebnis: Promise<Passwort|null>
    function askPassword({ title, text, ok }) {
        return new Promise(resolve => {
            showDialog({
                title,
                html: `<p>${escapeHtml(text)}</p><input type="password" id="dialogPw" class="field" style="margin-top:0.75rem" placeholder="Dein Passwort" autocomplete="current-password">`,
                buttons: [
                    { label: 'Abbrechen', fn: () => resolve(null) },
                    { label: ok, primary: true, danger: true, fn: () => { const i = $('#dialogPw'); resolve(i ? i.value : null); } }
                ],
                onDismiss: () => resolve(null)
            });
            const input = $('#dialogPw');
            if (!input) return;
            setTimeout(() => input.focus(), 60);
            input.addEventListener('keydown', e => {
                if (e.key !== 'Enter') return;
                e.preventDefault();
                const b = $('#dialogActions [data-main]');
                if (b) b.click();
            });
        });
    }

    /* ---------- Auswahl ---------- */
    function updateBulkUI() {
        bulkCount.textContent = selected.size;
        document.body.classList.toggle('select-mode', selectMode);
        btnSelectMode.classList.toggle('active', selectMode);
    }
    function toggleSelectMode(force) {
        selectMode = typeof force === 'boolean' ? force : !selectMode;
        if (!selectMode) { selected.clear(); lastSelected = null; }
        kbCursor = null;
        updateBulkUI();
        render();
    }
    function paintSelection() {
        mainEl.querySelectorAll('.bookmark-card').forEach(card => {
            const on = selected.has(card.dataset.id);
            card.classList.toggle('selected', on);
            const check = card.querySelector('.sel-check');
            if (check) check.classList.toggle('checked', on);
        });
        bulkCount.textContent = selected.size;
    }
    // Mit gedrückter Umschalttaste wird der ganze Bereich bis zum letzten Klick gewählt
    function toggleSelect(id, range) {
        if (range && lastSelected && lastSelected !== id) {
            const order = [];
            mainEl.querySelectorAll('.bookmark-card').forEach(c => { if (!order.includes(c.dataset.id)) order.push(c.dataset.id); });
            const a = order.indexOf(lastSelected), b = order.indexOf(id);
            if (a >= 0 && b >= 0) {
                order.slice(Math.min(a, b), Math.max(a, b) + 1).forEach(x => selected.add(x));
                lastSelected = id;
                paintSelection();
                return;
            }
        }
        if (selected.has(id)) selected.delete(id); else selected.add(id);
        lastSelected = id;
        paintSelection();
    }

    /* ---------- Karten ---------- */
    const SVG = {
        check: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"/></svg>',
        open: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>',
        star: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z"/>',
        copy: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>',
        folder: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>',
        edit: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>',
        trash: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>',
        more: '<svg fill="currentColor" viewBox="0 0 24 24"><circle cx="5" cy="12" r="1.8"/><circle cx="12" cy="12" r="1.8"/><circle cx="19" cy="12" r="1.8"/></svg>',
        undo: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6"/></svg>',
        chevron: '<svg class="chevron" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>'
    };

    function createCard(bm) {
        const card = document.createElement('article');
        const isSelected = selected.has(bm.id);
        const domain = getDomain(bm.url);
        card.className = `bookmark-card glass rounded-xl ${bm.favorite ? 'favorite' : ''} ${bm.check ? 'has-warn' : ''} ${isSelected ? 'selected' : ''} ${String(bm.id) === lastOpened ? 'last-opened' : ''} ${kbCursor && kbCursor.id === String(bm.id) ? 'kb-cursor' : ''}`;
        card.dataset.id = bm.id;
        if (canDrag) card.draggable = true;

        const checkHtml = selectMode
            ? `<button type="button" class="sel-check ${isSelected ? 'checked' : ''}" data-action="select" aria-label="Auswählen">${SVG.check}</button>` : '';
        const title = escapeHtml(bm.title);
        // Der Titel ist ein echter Link: Mittelklick, „In neuem Tab öffnen“ und langes Drücken funktionieren
        const titleHtml = (!selectMode && isWeb(bm.url))
            ? `<a class="bm-title" href="${escapeHtml(bm.url)}" target="_blank" rel="noopener noreferrer" title="${title}" draggable="false">${title}</a>`
            : `<span class="bm-title" title="${title}">${title}</span>`;
        const tags = (bm.tags || []).map(t => `<span class="bm-chip bm-tag" data-tag="${escapeHtml(t)}" title="Alle Links mit #${escapeHtml(t)}">#${escapeHtml(t)}</span>`).join('');
        const warn = bm.check
            ? `<span class="bm-chip bm-warn ${bm.check.s === 'dead' ? '' : 'unclear'}" title="Beim letzten Link-Check am ${escapeHtml(fmtDate(bm.check.t || 0))} nicht erreichbar">${bm.check.s === 'dead' ? 'tot?' : 'unklar'}</span>` : '';

        card.innerHTML = `
            <div class="bm-main">
                ${checkHtml}
                <img src="${escapeHtml(faviconSrc(domain))}" data-letter="${escapeHtml((domain || '?')[0])}" alt="" class="favicon" loading="lazy" draggable="false">
                <div class="bm-text">
                    ${titleHtml}
                    <span class="bm-domain" title="${escapeHtml(bm.url)}">${escapeHtml(shortUrl(bm.url))}</span>
                    ${bm.description ? `<p class="bm-desc">${escapeHtml(bm.description)}</p>` : ''}
                    <div class="bm-meta"><span class="bm-chip">${escapeHtml(prettyCat(bm.category))}</span>${tags}${warn}</div>
                </div>
                <button type="button" class="bm-more" data-action="more" title="Aktionen" aria-label="Aktionen">${SVG.more}</button>
            </div>
            ${selectMode ? '' : `
            <div class="card-actions">
                <button type="button" class="card-btn card-btn-open" data-action="open" title="${escapeHtml(bm.url)}">${SVG.open}<span>Öffnen</span></button>
                <button type="button" class="card-btn card-btn-icon ${bm.favorite ? 'starred' : ''}" data-action="favorite" title="Favorit" aria-label="Favorit" aria-pressed="${bm.favorite ? 'true' : 'false'}">
                    <svg fill="${bm.favorite ? 'currentColor' : 'none'}" stroke="currentColor" viewBox="0 0 24 24">${SVG.star}</svg>
                </button>
                <button type="button" class="card-btn card-btn-icon" data-action="copy" title="URL kopieren" aria-label="URL kopieren">${SVG.copy}</button>
                <button type="button" class="card-btn card-btn-icon" data-action="folder" title="Ordner wählen" aria-label="Ordner wählen">${SVG.folder}</button>
                <button type="button" class="card-btn card-btn-icon" data-action="edit" title="Bearbeiten" aria-label="Bearbeiten">${SVG.edit}</button>
                <button type="button" class="card-btn card-btn-icon danger" data-action="delete" title="Löschen" aria-label="Löschen">${SVG.trash}</button>
            </div>`}
        `;
        return card;
    }

    // Ein Klick-Empfänger für alle Karten (schneller als einer pro Karte)
    mainEl.addEventListener('click', e => {
        const head = e.target.closest('.domain-group-header');
        if (head) {
            const wrap = head.parentElement;
            const key = wrap.dataset.key;
            wrap.classList.toggle('open');
            if (wrap.classList.contains('open')) openDomains.add(key); else openDomains.delete(key);
            head.setAttribute('aria-expanded', wrap.classList.contains('open') ? 'true' : 'false');
            persistOpenDomains();
            return;
        }
        const card = e.target.closest('.bookmark-card');
        if (!card) return;
        const bm = byId(card.dataset.id);
        if (!bm) return;
        if (selectMode) { e.preventDefault(); toggleSelect(bm.id, e.shiftKey); return; }
        const tag = e.target.closest('[data-tag]');
        if (tag) { e.preventDefault(); setSearch('#' + tag.dataset.tag); return; }
        if (e.target.closest('a.bm-title')) { trackVisit(bm); return; }
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        e.preventDefault();
        const action = btn.dataset.action;
        if (action === 'open') openLink(bm);
        else if (action === 'favorite') toggleFavorite(bm.id);
        else if (action === 'copy') copyText(bm.url, 'URL kopiert');
        else if (action === 'folder') openMoveModal([bm.id]);
        else if (action === 'edit') openEditModal(bm);
        else if (action === 'delete') deleteIds([bm.id]);
        else if (action === 'more') {
            mainEl.querySelectorAll('.bookmark-card.expanded').forEach(c => { if (c !== card) c.classList.remove('expanded'); });
            card.classList.toggle('expanded');
        }
    });
    mainEl.addEventListener('auxclick', e => {
        if (e.button !== 1 || selectMode) return;
        const link = e.target.closest('a.bm-title');
        const card = link && link.closest('.bookmark-card');
        const bm = card && byId(card.dataset.id);
        if (bm) trackVisit(bm);
    });

    // Ziehen und Ablegen: Karte auf einen Ordner in der Leiste ziehen (nur mit Maus)
    mainEl.addEventListener('dragstart', e => {
        const card = e.target.closest && e.target.closest('.bookmark-card');
        if (!card) return;
        const id = card.dataset.id;
        dragIds = (selectMode && selected.has(id)) ? Array.from(selected) : [id];
        const bm = byId(id);
        try {
            e.dataTransfer.effectAllowed = 'move';
            e.dataTransfer.setData('text/plain', bm ? bm.url : '');
        } catch (_) {}
        card.classList.add('dragging');
    });
    mainEl.addEventListener('dragend', () => {
        dragIds = null;
        $$('.dragging').forEach(c => c.classList.remove('dragging'));
        $$('.drop-ok').forEach(c => c.classList.remove('drop-ok'));
    });
    const dropTarget = e => {
        const btn = e.target.closest && e.target.closest('.cat-btn[data-cat]');
        return (btn && !['all', 'favorites', 'dead'].includes(btn.dataset.cat)) ? btn : null;
    };
    const headerEl = $('#appHeader');
    headerEl.addEventListener('dragover', e => {
        const btn = dragIds && dropTarget(e);
        if (!btn) return;
        e.preventDefault();
        btn.classList.add('drop-ok');
    });
    headerEl.addEventListener('dragleave', e => {
        const btn = e.target.closest && e.target.closest('.cat-btn');
        if (btn) btn.classList.remove('drop-ok');
    });
    headerEl.addEventListener('drop', e => {
        const btn = dragIds && dropTarget(e);
        if (!btn) return;
        e.preventDefault();
        const ids = dragIds;
        dragIds = null;
        doMove(btn.dataset.cat, ids);
    });

    /* ---------- Filtern, Sortieren, Gruppieren ---------- */
    function matchesFilter(bm) {
        if (bm.deleted) return false;
        if (currentCategory === 'favorites') { if (!bm.favorite) return false; }
        else if (currentCategory === 'dead') { if (!bm.check) return false; }
        else if (currentCategory !== 'all' && !inCat(bm.category, currentCategory)) return false;
        return matchesSearch(bm);
    }
    function sortList(list) {
        const arr = [...list];
        const byTitle = (a, b) => (a.title || '').localeCompare(b.title || '', 'de', { sensitivity: 'base', numeric: true });
        arr.sort((a, b) => {
            if (favTop && !searchQuery) {
                const af = a.favorite ? 1 : 0, bf = b.favorite ? 1 : 0;
                if (af !== bf) return bf - af;
            }
            let d = 0;
            if (sortMode === 'newest') d = (b.created || 0) - (a.created || 0);
            else if (sortMode === 'oldest') d = (a.created || 0) - (b.created || 0);
            else if (sortMode === 'clicks') d = (b.clicks || 0) - (a.clicks || 0);
            else if (sortMode === 'opened') d = (b.opened || 0) - (a.opened || 0);
            else if (sortMode === 'domain') d = getDomain(a.url || '').localeCompare(getDomain(b.url || ''), 'de');
            else if (sortMode === 'folder') d = (a.category || '').localeCompare(b.category || '', 'de');
            else if (sortMode === 'title-desc') return byTitle(b, a);
            return d || byTitle(a, b);
        });
        return arr;
    }
    // Liefert Gruppen (aufklappbar) und Einzel-Links
    function partition(list) {
        const singles = [];
        const groups = [];
        if (groupMode === 'none') return { singles: sortList(list), groups };
        const buckets = {};
        list.forEach(bm => {
            const k = groupMode === 'folder' ? (bm.category || 'Allgemein') : (getDomain(bm.url || '') || 'andere');
            (buckets[k] = buckets[k] || []).push(bm);
        });
        Object.entries(buckets).forEach(([name, items]) => {
            if (groupMode === 'folder') groups.push({ key: 'f:' + name, label: prettyCat(name), domain: null, items: sortList(items) });
            else if (items.length > 5) groups.push({ key: name, label: name, domain: name, items: sortList(items) });
            else singles.push(...items);
        });
        if (groupMode === 'folder') groups.sort((a, b) => a.label.localeCompare(b.label, 'de'));
        else groups.sort((a, b) => b.items.length - a.items.length);
        return { singles: sortList(singles), groups };
    }
    function createGroup(g) {
        const wrap = document.createElement('div');
        const isOpen = openDomains.has(g.key);
        wrap.className = 'domain-group' + (isOpen ? ' open' : '');
        wrap.dataset.key = g.key;
        const icon = g.domain
            ? `<img src="${escapeHtml(faviconSrc(g.domain))}" data-letter="${escapeHtml(g.domain[0] || '?')}" alt="" class="w-4 h-4 rounded" loading="lazy">`
            : `<span class="w-4 h-4 text-slate-400">${SVG.folder}</span>`;
        wrap.innerHTML = `
            <div class="domain-group-header" role="button" tabindex="0" aria-expanded="${isOpen ? 'true' : 'false'}">
                ${SVG.chevron}
                ${icon}
                <span class="font-semibold text-sm text-slate-100 truncate flex-1">${escapeHtml(g.label)}</span>
                <span class="text-[11px] text-slate-500 bg-slate-800/80 px-1.5 py-0.5 rounded shrink-0">${g.items.length} Links</span>
            </div>
            <div class="domain-group-body"></div>`;
        const body = wrap.querySelector('.domain-group-body');
        g.items.forEach(bm => body.appendChild(createCard(bm)));
        return wrap;
    }
    mainEl.addEventListener('keydown', e => {
        if ((e.key === 'Enter' || e.key === ' ') && e.target.classList && e.target.classList.contains('domain-group-header')) {
            e.preventDefault();
            e.target.click();
        }
    });

    function updateStats() {
        const l = live();
        const favs = l.filter(b => b.favorite).length;
        $('#toolsStats').textContent = `${l.length} Links · ${getCategories().length} Ordner · ${favs} Favoriten · v${LV_VERSION}`
            + (LV_USER ? ` · angemeldet als ${LV_USER}${LV_ADMIN ? ' (Administrator)' : ''}` : '');
        $('#trashCount').textContent = trashed().length;
    }
    function markMenus() {
        $$('#viewMenu [data-view]').forEach(b => b.classList.toggle('on', b.dataset.view === viewMode));
        $$('#viewMenu [data-sort]').forEach(b => b.classList.toggle('on', b.dataset.sort === sortMode));
        $$('#viewMenu [data-group]').forEach(b => b.classList.toggle('on', b.dataset.group === groupMode));
        $('#optFavTop').classList.toggle('on', favTop);
        $('#optTagBar').classList.toggle('on', tagBarOn);
        document.body.classList.toggle('view-list', viewMode === 'list');
        document.body.classList.toggle('view-tiles', viewMode === 'tiles');
    }

    function render() {
        // Scroll-Position merken, damit die Ansicht nach Löschen/Hinzufügen nicht springt
        const scrollY = window.scrollY || window.pageYOffset || 0;
        const all = live();
        const cats = getCategories();
        const deadTotal = all.filter(b => b.check).length;
        // Gemerkter Ordner existiert nicht mehr (umbenannt, geleert)? Dann zurück auf „Alle“
        const special = ['all', 'favorites', 'dead'].includes(currentCategory);
        if ((currentCategory === 'dead' && !deadTotal) || (!special && !all.some(b => inCat(b.category, currentCategory)))) {
            currentCategory = 'all';
            store.set('lv_cat', 'all');
        }
        const isSpecial = ['all', 'favorites', 'dead'].includes(currentCategory);
        const activeTop = isSpecial ? null : topOf(currentCategory);
        const filtered = bookmarks.filter(matchesFilter);
        const favTotal = all.filter(b => b.favorite).length;
        const countIn = c => all.filter(b => inCat(b.category, c)).length;

        // Ordnerleiste: oberste Ebene, Unterordner in der zweiten Zeile
        const tops = [];
        cats.forEach(c => { const t = topOf(c); if (!tops.some(x => x.toLowerCase() === t.toLowerCase())) tops.push(t); });
        const chip = (cat, label, count, active, extra = '') =>
            `<button type="button" class="cat-btn ${extra} ${active ? 'active' : ''}" data-cat="${escapeHtml(cat)}" aria-pressed="${active ? 'true' : 'false'}">${label} <span class="count">${count}</span></button>`;
        categoryBar.innerHTML =
            chip('all', 'Alle', all.length, currentCategory === 'all')
            + chip('favorites', '⭐ Favoriten', favTotal, currentCategory === 'favorites')
            + (deadTotal ? chip('dead', 'Tote Links', deadTotal, currentCategory === 'dead', 'warn') : '')
            + tops.map(t => chip(t, escapeHtml(t), countIn(t), !!activeTop && activeTop.toLowerCase() === t.toLowerCase())).join('');
        const subs = activeTop ? cats.filter(c => c.toLowerCase().startsWith(activeTop.toLowerCase() + SEP)) : [];
        subCatBar.innerHTML = subs.map(c =>
            chip(c, escapeHtml(prettyCat(c.slice(activeTop.length + SEP.length))), countIn(c), currentCategory.toLowerCase() === c.toLowerCase())).join('');

        renderTagBar();

        $('#categoryList').innerHTML = cats.map(c => `<option value="${escapeHtml(c)}">`).join('');
        fillCategoryPicker(cats);
        updateStats();
        markMenus();

        const { singles, groups } = partition(filtered);
        const groupedIds = new Set();
        groups.forEach(g => g.items.forEach(b => groupedIds.add(b.id)));
        const frontPage = currentCategory === 'all' && !searchQuery;

        // Favoriten-Bereich oben: nur auf der Startansicht und nur, wenn „Favoriten oben“ an ist
        const favSingles = (frontPage && favTop && groupMode !== 'folder') ? singles.filter(b => b.favorite) : [];
        favoritesGrid.innerHTML = '';
        if (favSingles.length > 0) {
            favoritesSection.classList.remove('hidden');
            favCount.textContent = favSingles.length;
            const frag = document.createDocumentFragment();
            favSingles.forEach(bm => frag.appendChild(createCard(bm)));
            favoritesGrid.appendChild(frag);
        } else {
            favoritesSection.classList.add('hidden');
        }

        bookmarksGrid.innerHTML = '';
        const frag = document.createDocumentFragment();
        groups.forEach(g => frag.appendChild(createGroup(g)));
        const rest = favSingles.length ? singles.filter(b => !b.favorite) : singles;
        rest.forEach(bm => frag.appendChild(createCard(bm)));
        bookmarksGrid.appendChild(frag);

        totalCount.textContent = filtered.length;
        sectionTitle.textContent =
            currentCategory === 'all' ? (searchQuery ? 'Suchergebnisse' : (favSingles.length ? 'Weitere Links' : 'Alle Links')) :
            currentCategory === 'favorites' ? 'Favoriten' :
            currentCategory === 'dead' ? 'Beim letzten Check nicht erreichbar' : prettyCat(currentCategory);
        sectionHeader.classList.toggle('hidden', frontPage && rest.length === 0 && groups.length === 0 && favSingles.length > 0);

        if (filtered.length === 0) {
            emptyState.classList.remove('hidden');
            const none = all.length === 0;
            $('#emptyTitle').textContent = none ? 'Noch keine Links' : 'Keine Treffer';
            $('#emptyText').textContent = none ? 'Füge deinen ersten Link hinzu oder importiere Lesezeichen.' : 'Anderen Suchbegriff oder Filter versuchen.';
            $('#btnAddEmpty').classList.toggle('hidden', !none);
        } else {
            emptyState.classList.add('hidden');
        }
        updateBulkUI();
        syncHeaderSpacer();
        requestAnimationFrame(() => { window.scrollTo(0, scrollY); });
    }

    /* ---------- Tag-Leiste: Antippen filtert nach dem Tag, noch mal antippen nimmt ihn wieder raus ---------- */
    const isTagToken = x => x.length > 1 && x[0] === '#';
    function activeTagKeys() {
        return new Set(searchQuery.split(/\s+/).filter(isTagToken).map(x => normalizeText(x.slice(1))));
    }
    function renderTagBar() {
        if (!tagBarOn) { tagBar.innerHTML = ''; return; }
        // Gezählt wird im gewählten Ordner, ohne die Suche, damit die Zahlen zur Ansicht passen
        const inView = b => {
            if (b.deleted) return false;
            if (currentCategory === 'favorites') return !!b.favorite;
            if (currentCategory === 'dead') return !!b.check;
            return currentCategory === 'all' || inCat(b.category, currentCategory);
        };
        const count = new Map();
        bookmarks.forEach(b => { if (inView(b)) (b.tags || []).forEach(t => count.set(t, (count.get(t) || 0) + 1)); });
        const active = activeTagKeys();
        if (!count.size && !active.size) { tagBar.innerHTML = ''; return; }
        const isOn = t => active.has(normalizeText(t));
        const list = [...count.keys()].sort((a, b) => (isOn(b) - isOn(a)) || count.get(b) - count.get(a) || a.localeCompare(b, 'de')).slice(0, 300);
        tagBar.innerHTML =
            `<button type="button" class="cat-btn tagm" data-cat="__tagmanage" title="Tags verwalten" aria-label="Tags verwalten">${SVG.edit}<span>Tags</span></button>`
            + (active.size ? '<button type="button" class="cat-btn" data-cat="__tagoff">✕ Tag-Filter aus</button>' : '')
            + list.map(t => {
                const on = isOn(t);
                return `<button type="button" class="cat-btn tagb ${on ? 'active' : ''}" data-tagbtn="${escapeHtml(t)}" aria-pressed="${on ? 'true' : 'false'}">#${escapeHtml(t)} <span class="count">${count.get(t)}</span></button>`;
            }).join('');
    }
    function toggleTagFilter(t) {
        const key = normalizeText(t);
        const toks = searchQuery.split(/\s+/).filter(Boolean);
        const has = toks.some(x => isTagToken(x) && normalizeText(x.slice(1)) === key);
        setSearch((has ? toks.filter(x => !(isTagToken(x) && normalizeText(x.slice(1)) === key)) : toks.concat('#' + t)).join(' '));
    }
    tagBar.addEventListener('click', e => {
        const b = e.target.closest('button');
        if (!b) return;
        if (b.dataset.cat === '__tagmanage') { openTags(); return; }
        if (b.dataset.cat === '__tagoff') { setSearch(searchQuery.split(/\s+/).filter(x => x && !isTagToken(x)).join(' ')); return; }
        if (b.dataset.tagbtn !== undefined) toggleTagFilter(b.dataset.tagbtn);
    });

    function pickCategory(cat) {
        if (currentCategory === cat && cat !== 'all') {
            // Noch mal auf denselben Ordner: eine Ebene zurück
            const i = cat.lastIndexOf(SEP);
            currentCategory = (i > 0 && !['favorites', 'dead'].includes(cat)) ? cat.slice(0, i) : 'all';
        } else currentCategory = cat;
        store.set('lv_cat', currentCategory);
        window.scrollTo(0, 0);
        render();
    }
    [categoryBar, subCatBar].forEach(bar => bar.addEventListener('click', e => {
        const btn = e.target.closest('[data-cat]');
        if (btn) pickCategory(btn.dataset.cat);
    }));

    /* ---------- Aktionen an Links ---------- */
    async function toggleFavorite(id) {
        applyRes(await api('toggle_favorite', { id }), '', true);
    }
    async function restoreIds(ids) {
        applyRes(await api('trash_restore', { ids }), 'Wiederhergestellt');
    }
    // Löschen = Papierkorb, mit „Rückgängig“
    async function deleteIds(ids) {
        const res = await api(ids.length === 1 ? 'delete' : 'bulk_delete', ids.length === 1 ? { id: ids[0] } : { ids });
        if (!res.success) { showToast(res.message || 'Löschen fehlgeschlagen', 'error'); return false; }
        bookmarks = res.bookmarks;
        selected.clear();
        if (selectMode) toggleSelectMode(false); else render();
        showToast(res.message || 'Gelöscht', 'success', { label: 'Rückgängig', fn: () => restoreIds(ids) });
        return true;
    }
    async function askDeleteBulk() {
        if (selected.size === 0) return;
        const ids = Array.from(selected);
        if (ids.length > 1 && !await confirmDialog({
            title: `${ids.length} Links löschen?`,
            text: `Sie landen im Papierkorb und lassen sich ${TRASH_DAYS} Tage lang zurückholen.`, ok: 'Löschen', danger: true })) return;
        deleteIds(ids);
    }

    let moveIds = [];
    function openMoveModal(ids) {
        moveIds = ids || Array.from(selected);
        if (!moveIds.length) return;
        const cats = getCategories();
        $('#moveHint').textContent = `${moveIds.length} Link(s) verschieben. Unterordner legst du mit „Ordner > Unterordner“ an.`;
        const list = $('#moveCatList');
        list.innerHTML = cats.length ? cats.map(c => `
            <button type="button" class="w-full text-left px-3 py-2.5 rounded-lg text-sm text-slate-200 hover:bg-violet-600/20 hover:text-violet-200 border border-transparent hover:border-violet-500/30 transition-colors flex items-center gap-2" data-movecat="${escapeHtml(c)}">
                <span class="w-4 h-4 text-slate-500 shrink-0">${SVG.folder}</span>
                ${escapeHtml(prettyCat(c))}
            </button>`).join('') : '<p class="text-sm text-slate-500 px-1">Noch keine Ordner. Lege unten einen an.</p>';
        $('#moveNewCat').value = '';
        showOverlay(moveOverlay);
    }
    $('#moveCatList').addEventListener('click', e => {
        const btn = e.target.closest('[data-movecat]');
        if (btn) doMove(btn.dataset.movecat, moveIds);
    });
    async function doMove(category, ids) {
        if (!category || !ids || !ids.length) return;
        const res = await api('bulk_move', { ids, category });
        closeMove();
        if (res.success) {
            bookmarks = res.bookmarks;
            selected.clear();
            if (selectMode) toggleSelectMode(false); else render();
            showToast(res.message || 'Verschoben');
        } else showToast(res.message || 'Fehler', 'error');
    }
    function closeMove() { hideOverlay(moveOverlay); }

    function setFormCategory(name) {
        const cat = (name || '').trim() || 'Allgemein';
        $('#formCategory').value = cat;
        const label = $('#formCatLabel');
        if (label) label.textContent = cat;
        const sel = $('#formCategorySelect');
        if (sel) {
            // ensure option exists
            let found = false;
            for (const opt of sel.options) {
                if (opt.value === cat) { found = true; break; }
            }
            if (!found && cat) {
                const o = document.createElement('option');
                o.value = cat; o.textContent = cat;
                sel.appendChild(o);
            }
            sel.value = cat;
        }
        $$('#formCatChips .cat-chip').forEach(chip => {
            chip.classList.toggle('active', chip.dataset.cat === cat);
        });
        const neu = $('#formCategoryNew');
        if (neu) neu.value = '';
    }

    function fillCategoryPicker(cats) {
        const list = cats && cats.length ? cats : getCategories();
        const chips = $('#formCatChips');
        const sel = $('#formCategorySelect');
        if (!chips || !sel) return;
        const current = $('#formCategory')?.value || 'Allgemein';
        chips.innerHTML = list.map(c =>
            `<button type="button" class="cat-chip ${c === current ? 'active' : ''}" data-cat="${escapeHtml(c)}">${escapeHtml(c)}</button>`
        ).join('') + `<button type="button" class="cat-chip" data-cat="__new" style="border-style:dashed;color:#a78bfa">+ Neu</button>`;
        chips.querySelectorAll('.cat-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                if (chip.dataset.cat === '__new') {
                    $('#formCategoryNew')?.focus();
                    return;
                }
                setFormCategory(chip.dataset.cat);
            });
        });
        sel.innerHTML = `<option value="">— Ordner wählen —</option>` +
            list.map(c => `<option value="${escapeHtml(c)}" ${c === current ? 'selected' : ''}>${escapeHtml(c)}</option>`).join('');
    }

    function fillTagChips() {
        const box = $('#formTagChips');
        const tags = allTags().slice(0, 14);
        box.innerHTML = tags.map(t => `<button type="button" class="bm-chip bm-tag" data-addtag="${escapeHtml(t)}">#${escapeHtml(t)}</button>`).join('');
    }
    const parseTags = v => (v || '').split(/[,;\n]+/).map(t => t.trim().replace(/^#/, '')).filter(Boolean);
    $('#formTagChips').addEventListener('click', e => {
        const btn = e.target.closest('[data-addtag]');
        if (!btn) return;
        const input = $('#formTags');
        const cur = parseTags(input.value);
        const t = btn.dataset.addtag;
        const i = cur.findIndex(x => x.toLowerCase() === t.toLowerCase());
        if (i >= 0) cur.splice(i, 1); else cur.push(t);
        input.value = cur.join(', ');
    });

    function openAddModal() {
        editingId = null; formFavorite = false;
        $('#modalTitle').textContent = 'Link hinzufügen';
        resetFetch();
        bookmarkForm.reset(); $('#formId').value = '';
        favToggle.classList.remove('on'); favToggle.setAttribute('aria-checked', 'false');
        fillCategoryPicker();
        fillTagChips();
        setFormCategory(!['all', 'favorites', 'dead'].includes(currentCategory) ? currentCategory : 'Allgemein');
        showOverlay(modalOverlay);
        setTimeout(() => $('#formUrl').focus(), 80);
    }
    function openEditModal(bm) {
        editingId = bm.id; formFavorite = !!bm.favorite;
        $('#modalTitle').textContent = 'Link bearbeiten';
        resetFetch();
        $('#formId').value = bm.id;
        $('#formTitle').value = bm.title || '';
        $('#formUrl').value = bm.url || '';
        $('#formDescription').value = bm.description || '';
        $('#formTags').value = (bm.tags || []).join(', ');
        favToggle.classList.toggle('on', formFavorite);
        favToggle.setAttribute('aria-checked', formFavorite ? 'true' : 'false');
        fillCategoryPicker();
        fillTagChips();
        setFormCategory(bm.category || 'Allgemein');
        showOverlay(modalOverlay);
        setTimeout(() => $('#formTitle').focus(), 80);
    }
    function closeModal() { hideOverlay(modalOverlay); }

    /* ---------- Suche ---------- */
    function syncSearchClear() {
        $('#searchWrap').classList.toggle('has-query', !!searchInput.value.trim());
    }
    function setSearch(q) {
        searchInput.value = q;
        searchQuery = q.trim();
        syncSearchClear();
        window.scrollTo(0, 0);
        render();
    }
    let searchTimer = null;
    searchInput.addEventListener('input', e => {
        searchQuery = e.target.value.trim();
        syncSearchClear();
        // Kurz warten, damit bei vielen Links nicht jeder Tastendruck alles neu aufbaut
        clearTimeout(searchTimer);
        searchTimer = setTimeout(render, 120);
    });
    // URL in die Suche einfügen → Schnell-Hinzufügen anbieten
    searchInput.addEventListener('paste', () => {
        setTimeout(async () => {
            let url = searchInput.value.trim();
            if (!/^https?:\/\//i.test(url) && /^[\w.-]+\.[a-z]{2,}(\/\S*)?$/i.test(url)) url = 'https://' + url;
            let u;
            try { u = new URL(url); } catch (_) { return; }
            if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
            if (!await confirmDialog({ title: 'Als neuen Link speichern?', text: u.href, ok: 'Hinzufügen' })) return;
            setSearch('');
            startAdd(u.href, '');
        }, 0);
    });
    $('#searchClear').addEventListener('click', () => { setSearch(''); searchInput.focus(); });
    btnSelectMode.addEventListener('click', () => toggleSelectMode());

    // Neuen Link mit vorbelegter Adresse anlegen (Suche, Schnell-Speichern, Teilen)
    function startAdd(url, title) {
        const existing = live().find(b => normUrl(b.url) === normUrl(url));
        if (existing) {
            showToast('Den Link hast du schon gespeichert');
            openEditModal(existing);
            return;
        }
        openAddModal();
        $('#formUrl').value = url;
        if (title) $('#formTitle').value = title;
        else {
            $('#formTitle').value = getDomain(url);
            autoTitle = $('#formTitle').value;
            fetchTitle(false);
        }
        setTimeout(() => $('#formTitle').focus(), 100);
    }

    /* ---------- Menüs ---------- */
    const menus = [['#btnView', '#viewMenu'], ['#btnTools', '#toolsMenu']];
    function closeMenus() { menus.forEach(([, m]) => $(m).classList.add('hidden')); }
    menus.forEach(([b, m]) => {
        $(b).addEventListener('click', e => {
            e.stopPropagation();
            const wasOpen = !$(m).classList.contains('hidden');
            closeMenus();
            if (!wasOpen) $(m).classList.remove('hidden');
        });
    });
    document.addEventListener('click', e => {
        if (!e.target.closest('#viewMenu')) closeMenus();
        // Aufgeklappte Aktionsleiste schließen, wenn woanders hingeklickt wird
        if (!e.target.closest('.bookmark-card')) mainEl.querySelectorAll('.bookmark-card.expanded').forEach(c => c.classList.remove('expanded'));
    });
    $('#toolsMenu').addEventListener('click', e => { if (e.target.closest('button')) closeMenus(); });
    $('#viewMenu').addEventListener('click', e => {
        const b = e.target.closest('button');
        if (!b) return;
        if (b.dataset.view) { viewMode = b.dataset.view; store.set('lv_view', viewMode); }
        else if (b.dataset.sort) { sortMode = b.dataset.sort; store.set('lv_sort', sortMode); }
        else if (b.dataset.group) { groupMode = b.dataset.group; store.set('lv_group', groupMode); }
        else if (b.id === 'optFavTop') { favTop = !favTop; store.set('lv_favtop', favTop ? '1' : '0'); }
        else if (b.id === 'optTagBar') { tagBarOn = !tagBarOn; store.set('lv_tagbar', tagBarOn ? '1' : '0'); }
        render();
    });

    /* ---------- Sammel-Leiste ---------- */
    $('#bulkCancel').addEventListener('click', () => toggleSelectMode(false));
    $('#bulkSelectAll').addEventListener('click', () => {
        const filtered = bookmarks.filter(matchesFilter);
        if (selected.size >= filtered.length) selected.clear();
        else filtered.forEach(b => selected.add(b.id));
        paintSelection();
    });
    $('#bulkDelete').addEventListener('click', askDeleteBulk);
    $('#bulkMove').addEventListener('click', () => openMoveModal());
    $('#bulkFav').addEventListener('click', async () => {
        if (selected.size === 0) return;
        // Sind schon alle ausgewählten Favoriten, wird der Stern wieder entfernt
        const ids = Array.from(selected);
        const allFav = ids.every(id => bookmarks.some(b => b.id === id && b.favorite));
        const res = await api('bulk_favorite', { ids, favorite: allFav ? '0' : '1' });
        if (res.success) {
            bookmarks = res.bookmarks; selected.clear(); toggleSelectMode(false);
            showToast(res.message || 'Favoriten gesetzt');
        } else showToast(res.message || 'Fehler', 'error');
    });

    $('#moveClose').addEventListener('click', closeMove);
    moveOverlay.addEventListener('click', e => { if (e.target === moveOverlay) closeMove(); });
    const moveNew = () => {
        const name = $('#moveNewCat').value.trim();
        if (!name) { showToast('Name eingeben', 'error'); return; }
        doMove(name, moveIds);
    };
    $('#moveCreateBtn').addEventListener('click', moveNew);
    $('#moveNewCat').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); moveNew(); } });

    /* ---------- Formular Hinzufügen/Bearbeiten ---------- */
    $('#btnAdd').addEventListener('click', openAddModal);
    $('#fabAdd').addEventListener('click', openAddModal);
    $('#btnAddEmpty').addEventListener('click', openAddModal);
    $('#modalClose').addEventListener('click', closeModal);
    $('#modalCancel').addEventListener('click', closeModal);
    modalOverlay.addEventListener('click', e => { if (e.target === modalOverlay) closeModal(); });

    favToggle.addEventListener('click', () => {
        formFavorite = !formFavorite;
        favToggle.classList.toggle('on', formFavorite);
        favToggle.setAttribute('aria-checked', formFavorite ? 'true' : 'false');
    });
    $('#formCategorySelect').addEventListener('change', e => { if (e.target.value) setFormCategory(e.target.value); });
    $('#formCatCreate').addEventListener('click', () => {
        const name = $('#formCategoryNew').value.trim();
        if (!name) { showToast('Ordnername eingeben', 'error'); $('#formCategoryNew').focus(); return; }
        setFormCategory(name);
        fillCategoryPicker();
        setFormCategory(name);
        showToast('Ordner „' + name + '“ gewählt');
    });
    $('#formCategoryNew').addEventListener('keydown', e => {
        if (e.key === 'Enter') { e.preventDefault(); $('#formCatCreate').click(); }
    });
    $('#formCategoryNew').setAttribute('placeholder', 'Neuer Ordner, auch „Ordner > Unterordner“');

    let saving = false;
    bookmarkForm.addEventListener('submit', async e => {
        e.preventDefault();
        if (saving) return;
        const typedNew = $('#formCategoryNew').value.trim();
        if (typedNew) setFormCategory(typedNew);
        const data = {
            title: $('#formTitle').value.trim(), url: $('#formUrl').value.trim(),
            category: ($('#formCategory').value.trim() || typedNew || 'Allgemein'),
            description: $('#formDescription').value.trim(),
            tags: parseTags($('#formTags').value),
            favorite: formFavorite ? '1' : '0'
        };
        if (!editingId) {
            const key = normUrl(/^https?:\/\//i.test(data.url) ? data.url : 'https://' + data.url);
            const dup = live().find(b => normUrl(b.url) === key);
            if (dup && !await confirmDialog({
                title: 'Diesen Link gibt es schon',
                text: `„${dup.title}“ im Ordner ${prettyCat(dup.category)}. Trotzdem noch mal speichern?`, ok: 'Trotzdem speichern' })) return;
        }
        saving = true;
        $('#modalSubmit').disabled = true;
        const res = editingId ? await api('update', { ...data, id: editingId }) : await api('add', data);
        saving = false;
        $('#modalSubmit').disabled = false;
        if (res.success) { bookmarks = res.bookmarks; closeModal(); render(); showToast(res.message || 'Gespeichert'); }
        else showToast(res.message || 'Fehler', 'error');
    });

    /* ---------- Import mit Vorschau ---------- */
    let importReady = false;
    function resetImportStep() {
        importReady = false;
        $('#importPreview').classList.add('hidden');
        $('#importSubmit').textContent = 'Datei prüfen';
    }
    function closeImport() {
        hideOverlay(importOverlay);
        $('#importForm').reset(); $('#importFileName').classList.add('hidden'); $('#importSubmit').disabled = true;
        resetImportStep();
    }
    $('#btnImport').addEventListener('click', () => { resetImportStep(); showOverlay(importOverlay); });
    $('#importClose').addEventListener('click', closeImport);
    importOverlay.addEventListener('click', e => { if (e.target === importOverlay) closeImport(); });
    $('#importFile').addEventListener('change', e => {
        const f = e.target.files[0];
        resetImportStep();
        if (f) { $('#importFileName').textContent = f.name; $('#importFileName').classList.remove('hidden'); $('#importSubmit').disabled = false; }
    });
    $('#importForm').addEventListener('submit', async e => {
        e.preventDefault();
        const file = $('#importFile').files[0];
        if (!file) return;
        const btn = $('#importSubmit');
        btn.disabled = true;
        if (!importReady) {
            btn.textContent = 'Prüfe…';
            const res = await api('import', { dry: '1' }, { bookmark_file: file });
            btn.disabled = false;
            if (!res.success) { btn.textContent = 'Datei prüfen'; showToast(res.message || 'Datei nicht lesbar', 'error'); return; }
            const folders = Object.entries(res.folders || {});
            const box = $('#importPreview');
            box.innerHTML = `<h4>${res.imported} neue Links${res.skipped ? `, ${res.skipped} sind schon da` : ''}</h4>`
                + (folders.length ? `<p style="margin:0">In ${res.folder_count} Ordner(n): ${folders.map(([n, c]) => `${escapeHtml(prettyCat(n))} (${c})`).join(', ')}${res.folder_count > folders.length ? ' …' : ''}</p>` : '');
            box.classList.remove('hidden');
            if (res.imported > 0) { importReady = true; btn.textContent = `${res.imported} Links importieren`; }
            else { btn.textContent = 'Nichts Neues dabei'; btn.disabled = true; }
            return;
        }
        btn.textContent = 'Importiere…';
        const res = await api('import', {}, { bookmark_file: file });
        btn.disabled = false;
        if (res.success) { bookmarks = res.bookmarks; closeImport(); render(); showToast(res.message || 'Import erfolgreich'); }
        else { resetImportStep(); showToast(res.message || 'Import fehlgeschlagen', 'error'); }
    });

    /* ---------- Export ---------- */
    function download(action) {
        $('#exportAction').value = action;
        $('#exportForm').submit();
    }
    $$('[data-export]').forEach(btn => {
        btn.addEventListener('click', async () => {
            if (!await confirmDialog({
                title: 'Unverschlüsselt exportieren?',
                text: 'Diese Datei enthält deine Links im Klartext, zum Beispiel für den Umzug in einen Browser. Für eine Sicherung nimm lieber das Komplett-Backup unter Werkzeuge → Backups.',
                ok: 'Exportieren' })) return;
            download(btn.dataset.export === 'json' ? 'export_json' : 'export_html');
        });
    });

    /* ---------- Duplikate ---------- */
    $('#btnDedupe').addEventListener('click', async () => {
        if (!await confirmDialog({
            title: 'Duplikate entfernen?',
            text: 'Pro Adresse bleibt der beste Eintrag (Favorit und Beschreibung zuerst). Die anderen landen im Papierkorb.', ok: 'Entfernen' })) return;
        applyRes(await api('dedupe', {}), 'Fertig');
    });

    /* ---------- Link-Check: in kleinen Häppchen mit Fortschritt ---------- */
    let deadRun = 0;
    const deadOverlay = $('#deadOverlay');
    const deadDeleteBtn = $('#deadDeleteBtn');
    function syncDeadButton() {
        const n = deadOverlay.querySelectorAll('.dead-check:checked').length;
        deadDeleteBtn.disabled = n === 0;
        deadDeleteBtn.textContent = n ? `Auswahl löschen (${n})` : 'Auswahl löschen';
    }
    function addDeadRow(r) {
        const isDead = r.status === 'dead';
        const group = $(isDead ? '#deadGroupDead' : '#deadGroupUnclear');
        group.classList.remove('hidden');
        const safe = isWeb(r.url) ? r.url : '#';
        const row = document.createElement('label');
        row.className = 'flex items-start gap-2 px-2.5 py-2 rounded-lg bg-slate-800/50 border border-slate-700/40 cursor-pointer';
        row.innerHTML = `
            <input type="checkbox" class="dead-check mt-1 shrink-0" style="accent-color:#8b5cf6" value="${escapeHtml(r.id)}" ${isDead ? 'checked' : ''}>
            <span class="min-w-0 flex-1">
                <span class="block text-sm text-slate-200 truncate font-medium">${escapeHtml(r.title || r.url)}</span>
                <span class="block text-[11px] text-slate-500 truncate">${escapeHtml(r.url)}</span>
                <span class="block text-[11px] ${isDead ? 'text-rose-300' : 'text-amber-300'}">${escapeHtml(r.note || '')}${r.code ? ' · HTTP ' + r.code : ''}
                    · <a href="https://web.archive.org/web/2/${escapeHtml(safe)}" target="_blank" rel="noopener noreferrer" class="underline underline-offset-2">Archiv-Kopie</a></span>
            </span>
            <a href="${escapeHtml(safe)}" target="_blank" rel="noopener noreferrer" class="card-btn card-btn-icon shrink-0" title="Selbst ansehen" aria-label="Selbst ansehen">${SVG.open}</a>`;
        group.appendChild(row);
    }
    async function runDeadCheck() {
        const run = ++deadRun;
        const hint = $('#deadHint');
        const bar = $('#deadBar');
        // Ist ein Ordner oder eine Suche aktiv, wird nur das geprüft, was gerade zu sehen ist
        const scoped = currentCategory !== 'all' || !!searchQuery;
        const ids = (scoped ? bookmarks.filter(matchesFilter) : live()).map(b => b.id);
        const total = ids.length;
        const statusMap = {};
        let done = 0, ok = 0, dead = 0, unclear = 0, failed = 0;

        $('#deadList').innerHTML = `
            <div id="deadGroupDead" class="hidden space-y-1.5">
                <h4 class="text-[11px] font-semibold uppercase tracking-wider text-rose-300">Sicher weg</h4>
            </div>
            <div id="deadGroupUnclear" class="hidden space-y-1.5">
                <h4 class="text-[11px] font-semibold uppercase tracking-wider text-amber-300">Unklar, bitte selbst ansehen</h4>
            </div>`;
        bar.style.width = '0%';
        syncDeadButton();
        showOverlay(deadOverlay);
        if (!total) { hint.textContent = 'Keine Links zum Prüfen.'; return; }
        const where = scoped ? ' in der aktuellen Ansicht' : '';
        hint.textContent = `Prüfe ${total} Link(s)${where}…`;

        const chunks = [];
        for (let i = 0; i < ids.length; i += 10) chunks.push(ids.slice(i, i + 10));
        let next = 0;
        const worker = async () => {
            while (next < chunks.length && run === deadRun) {
                const chunk = chunks[next++];
                const res = await api('check_urls', { ids: chunk });
                if (run !== deadRun) return;
                if (res.success) {
                    (res.results || []).forEach(r => {
                        statusMap[r.id] = { s: r.status, c: r.code || 0 };
                        if (r.status === 'ok') { ok++; return; }
                        if (r.status === 'dead') dead++; else unclear++;
                        addDeadRow(r);
                    });
                } else failed += chunk.length;
                done += chunk.length;
                bar.style.width = Math.round(done / total * 100) + '%';
                hint.textContent = `${done} von ${total} geprüft${where}…`;
                syncDeadButton();
            }
        };
        await Promise.all([worker(), worker()]);
        // Ergebnis an den Links merken, auch wenn das Fenster schon zu ist
        if (Object.keys(statusMap).length) {
            const res = await api('set_status', { results: statusMap });
            if (res.success && Array.isArray(res.bookmarks)) { bookmarks = res.bookmarks; render(); }
        }
        if (run !== deadRun) return;
        bar.style.width = '100%';
        hint.textContent = `Fertig: ${ok} erreichbar, ${dead} sicher weg, ${unclear} unklar.`
            + (failed ? ` ${failed} konnten nicht geprüft werden.` : '')
            + (dead + unclear === 0 && !failed ? ' Alles sauber.' : ' Auffällige Links sind jetzt markiert und oben unter „Tote Links“ zu finden.');
    }
    $('#btnCheckDead').addEventListener('click', runDeadCheck);
    function closeDead() {
        deadRun++; // laufende Prüfung abbrechen
        hideOverlay(deadOverlay);
    }
    $('#deadClose').addEventListener('click', closeDead);
    $('#deadCancel').addEventListener('click', closeDead);
    deadOverlay.addEventListener('click', e => { if (e.target === deadOverlay) closeDead(); });
    $('#deadList').addEventListener('change', syncDeadButton);
    deadDeleteBtn.addEventListener('click', async () => {
        const ids = Array.from(deadOverlay.querySelectorAll('.dead-check:checked')).map(c => c.value);
        if (!ids.length) return;
        closeDead();
        deleteIds(ids);
    });

    /* ---------- Automatisch sortieren ----------
       Ohne KI und ohne fremde Dienste, alles passiert hier im Browser:
       1. Gruppen mit Domains und Stichwörtern (eine gemeinsame Liste, komplett bearbeitbar, Standard jederzeit zurückholbar)
       2. deine bisherige Sortierung: Links derselben Seite, deine Tags und Ordnernamen im Text
       Erst wird alles nur vorgeschlagen. Übernommen wird, was angehakt bleibt. Tags kommen nur dazu, nie weg. */

    // Die Standard-Gruppen. d = Domains („name.*“ = jede Endung, „.xxx“ = alle Domains mit dieser Endung),
    // w = ganze Wörter („a_b“ = zwei Wörter hintereinander, „wort*“ = Wortanfang), s = Wortteile, die irgendwo stehen dürfen.
    const AS_CATS = [
        { id: 'nsfw', label: 'Erwachsene (NSFW)', t: 'nsfw', f: 'NSFW',
          d: 'pornhub.com xvideos.com xhamster.com xnxx.com youporn.com redtube.com onlyfans.com chaturbate.com stripchat.com livejasmin.com brazzers.com spankbang.com eporner.com nhentai.net e-hentai.org fansly.com literotica.com motherless.com beeg.com tube8.com porn.com .xxx .porn .sex .sexy .adult',
          w: 'sex sexy erotik erotic erotisch nackt nude nudes nsfw milf fetisch fetish bdsm escort sexcam porno pornos hentai',
          s: 'porn xxx hentai xvideo xhamster onlyfans camgirl' },
        { id: 'technik', label: 'Technik & Computer', t: 'technik', f: 'Technik',
          d: 'heise.de golem.de t3n.de chip.de computerbild.de netzwelt.de computerbase.de winfuture.de stadt-bremerhaven.de borncity.com deskmodder.de dr-windows.de android-hilfe.de giga.de connect.de tomshardware.com theverge.com arstechnica.com wired.com ifixit.com notebookcheck.com notebookcheck.net techradar.com howtogeek.com alternativeto.net raspberrypi.com raspberrypi.org support.apple.com support.microsoft.com ubuntuusers.de askubuntu.com superuser.com xda-developers.com',
          w: 'linux windows android iphone ipad macos ios smartphone laptop raspberry router wlan wifi hardware software treiber firmware homelab nas smarthome smart_home homeassistant home_assistant ubuntu debian' },
        { id: 'dev', label: 'Programmierung', t: 'dev', f: 'Programmierung',
          d: 'github.com gitlab.com bitbucket.org codeberg.org stackoverflow.com stackexchange.com serverfault.com developer.mozilla.org npmjs.com pypi.org packagist.org php.net python.org docker.com dev.to codepen.io jsfiddle.net replit.com vercel.com netlify.com w3schools.com selfhtml.org css-tricks.com aws.amazon.com learn.microsoft.com rust-lang.org go.dev nodejs.org react.dev vuejs.org angular.dev angular.io laravel.com symfony.com regex101.com caniuse.com sourceforge.net huggingface.co kaggle.com jetbrains.com code.visualstudio.com readthedocs.io readthedocs.org',
          w: 'api programmierung programmieren programming javascript typescript python php html css sql docker kubernetes git coding developer entwickler framework sdk json regex devops programmier*' },
        { id: 'video', label: 'Videos & Streaming', t: 'video', f: 'Videos',
          d: 'youtube.com youtu.be vimeo.com dailymotion.com twitch.tv netflix.com primevideo.com disneyplus.com ardmediathek.de zdf.de arte.tv joyn.de plus.rtl.de 3sat.de kika.de mediathekview.de rumble.com kick.com odysee.com crunchyroll.com wow.tv magentatv.de waipu.tv zattoo.com paramountplus.com tv.apple.com',
          w: 'video videos film filme films movie movies trailer mediathek doku dokus dokumentation serie serien livestream kino' },
        { id: 'musik', label: 'Musik', t: 'musik', f: 'Musik',
          d: 'spotify.com soundcloud.com bandcamp.com music.apple.com music.youtube.com deezer.com tidal.com last.fm genius.com discogs.com laut.de setlist.fm mixcloud.com beatport.com musicbrainz.org songtexte.com radio.de radio.net tunein.com musescore.com ultimate-guitar.com songsterr.com',
          w: 'musik music song songs album alben playlist konzert konzerte lyrics songtext songtexte radio gitarre guitar klavier piano akkorde chords' },
        { id: 'podcast', label: 'Podcasts', t: 'podcast', f: 'Podcasts',
          d: 'podcasts.apple.com podcasts.google.com pocketcasts.com overcast.fm podbean.com castbox.fm podigee.io podcast.de',
          w: 'podcast podcasts' },
        { id: 'news', label: 'Nachrichten', t: 'news', f: 'Nachrichten',
          d: 'spiegel.de zeit.de faz.net sueddeutsche.de tagesschau.de welt.de bild.de n-tv.de stern.de focus.de tagesspiegel.de taz.de handelsblatt.com nzz.ch derstandard.at diepresse.com orf.at srf.ch zdfheute.de br.de ndr.de wdr.de swr.de mdr.de hr.de rbb24.de deutschlandfunk.de rnd.de merkur.de tz.de t-online.de netzpolitik.org news.google.com news.ycombinator.com bbc.com bbc.co.uk cnn.com nytimes.com theguardian.com reuters.com apnews.com washingtonpost.com aljazeera.com euronews.com correctiv.org watson.de watson.ch 20min.ch heise.de golem.de',
          w: 'news nachrichten schlagzeilen eilmeldung' },
        { id: 'social', label: 'Social Media', t: 'social', f: 'Social Media',
          d: 'facebook.com fb.com instagram.com twitter.com x.com tiktok.com reddit.com pinterest.* tumblr.com mastodon.social threads.net threads.com bsky.app snapchat.com discord.com discord.gg telegram.org t.me whatsapp.com quora.com vk.com 9gag.com imgur.com' },
        { id: 'jobs', label: 'Job & Karriere', t: 'jobs', f: 'Job',
          d: 'stepstone.* indeed.* monster.* arbeitsagentur.de glassdoor.* kununu.com karriere.at jobware.de freelancermap.de upwork.com fiverr.com malt.de gulp.de xing.com linkedin.com',
          w: 'job jobs stellenangebot stellenangebote stellenanzeige karriere bewerbung bewerbungen lebenslauf gehalt career careers praktikum vorstellungsgespräch' },
        { id: 'shopping', label: 'Shopping', t: 'shopping', f: 'Shopping',
          d: 'amazon.* ebay.* etsy.com otto.de zalando.* idealo.* geizhals.* aliexpress.com alibaba.com temu.com shein.com kleinanzeigen.de ebay-kleinanzeigen.de mediamarkt.* saturn.de alternate.de mindfactory.de conrad.de ikea.* lidl.* kaufland.* notebooksbilliger.de cyberport.de aboutyou.* galaxus.* digitec.ch thomann.de rebuy.de vinted.* mydealz.de hm.com tchibo.de bonprix.de decathlon.* douglas.de dm.de rossmann.de bol.com coolblue.de',
          w: 'shop onlineshop webshop kaufen bestellen angebot angebote deal deals gutschein gutscheine rabatt rabatte warenkorb preisvergleich schnäppchen sale' },
        { id: 'kochen', label: 'Kochen & Rezepte', t: 'kochen', f: 'Kochen',
          d: 'chefkoch.de lecker.de kitchenstories.com eatsmarter.de essen-und-trinken.de kochbar.de allrecipes.com seriouseats.com bbcgoodfood.com einfachbacken.de springlane.de ichkoche.at gutekueche.at hellofresh.de kptncook.com cookidoo.de rezeptwelt.de oetker.de zuckerjagdwurst.com eat-this.org biancazapatka.com',
          w: 'rezept rezepte recipe recipes kochen backen kuchen torte torten auflauf suppe salat pasta grillen bbq vegan vegetarisch kochrezept kochrezepte backrezept backrezepte thermomix airfryer heißluftfritteuse plätzchen' },
        { id: 'reisen', label: 'Reisen', t: 'reisen', f: 'Reisen',
          d: 'booking.com airbnb.* expedia.* tripadvisor.* holidaycheck.* bahn.de bahn.com flixbus.* lufthansa.com ryanair.com eurowings.com condor.com skyscanner.* kayak.* momondo.* opodo.* trivago.* hrs.de hotels.com tui.com ab-in-den-urlaub.de weg.de lonelyplanet.com oebb.at sbb.ch rome2rio.com flightradar24.com wikivoyage.org urlaubspiraten.de urlaubsguru.de travelbook.de getyourguide.* viator.com hostelworld.com',
          w: 'reise reisen urlaub hotel hotels flug flüge travel ferienwohnung ferienhaus camping kreuzfahrt roadtrip sehenswürdigkeiten städtereise reiseführer wohnmobil' },
        { id: 'finanzen', label: 'Geld & Finanzen', t: 'finanzen', f: 'Finanzen',
          d: 'paypal.com paypal.me sparkasse.de comdirect.de dkb.de ing.de consorsbank.de n26.com commerzbank.de deutsche-bank.de postbank.de vr.de traderepublic.com scalable.capital finanzen.net onvista.de boerse.de ariva.de justetf.com finanztip.de verivox.de smava.de wise.com revolut.com coinbase.com binance.com kraken.com coinmarketcap.com coingecko.com tradingview.com morningstar.* extraetf.com finanzfluss.de elster.de bitpanda.com klarna.com',
          w: 'bank banking finanzen finance aktie aktien etf etfs depot börse boerse steuer steuern steuererklärung kredit versicherung versicherungen sparen geld rente krypto crypto bitcoin investieren trading dividende dividenden zinsen' },
        { id: 'behoerden', label: 'Ämter & Behörden', t: 'behörden', f: 'Ämter',
          d: 'bund.de bundesregierung.de bundestag.de europa.eu gv.at admin.ch ch.ch gov.uk usa.gov deutsche-rentenversicherung.de rundfunkbeitrag.de kba.de bzst.de elster.de',
          w: 'amt ämter behörde behörden bürgeramt antrag anträge reisepass personalausweis' },
        { id: 'wissen', label: 'Wissen & Lernen', t: 'wissen', f: 'Wissen',
          d: 'wikipedia.org wikibooks.org wiktionary.org wikiwand.com britannica.com duden.de dict.cc leo.org linguee.* dwds.de khanacademy.org coursera.org udemy.com edx.org ted.com studysmarter.de sofatutor.com serlo.org planet-wissen.de spektrum.de scinexx.de quarks.de arxiv.org researchgate.net scholar.google.com sciencedirect.com nature.com gutenberg.org projekt-gutenberg.org brilliant.org duolingo.com',
          w: 'wissen lernen learn learning kurs kurse course courses lexikon wiki studie studien wissenschaft science vokabeln grammatik' },
        { id: 'anleitung', label: 'Anleitungen', t: 'anleitung', f: '',
          d: 'wikihow.com wikihow.* ifixit.com instructables.com',
          w: 'anleitung anleitungen tutorial tutorials howto how_to guide schritt_für_schritt diy' },
        { id: 'spiele', label: 'Spiele & Gaming', t: 'gaming', f: 'Spiele',
          d: 'steampowered.com steamcommunity.com epicgames.com gog.com itch.io ign.com gamestar.de pcgames.de gamepro.de eurogamer.* polygon.com kotaku.com nintendo.* playstation.com xbox.com ea.com ubisoft.com blizzard.com battle.net minecraft.net roblox.com chess.com lichess.org boardgamegeek.com nexusmods.com curseforge.com howlongtobeat.com protondb.com speedrun.com mobygames.com pcgameshardware.de',
          w: 'game games gaming videospiel videospiele brettspiel brettspiele zocken walkthrough speedrun minecraft pokemon lets_play' },
        { id: 'sport', label: 'Sport & Fitness', t: 'sport', f: 'Sport',
          d: 'kicker.de sport1.de sportschau.de ran.de transfermarkt.* bundesliga.com fussball.de espn.com eurosport.* laola1.at strava.com komoot.* dazn.com sport.de weltfussball.de flashscore.* livescore.com 11freunde.de formel1.de formula1.com motorsport-total.com fcbayern.com bvb.de uefa.com fifa.com olympics.com runnersworld.de outdooractive.com bergfex.* alltrails.com',
          w: 'sport sports fussball fußball football soccer bundesliga champions_league fitness workout joggen marathon radsport tennis handball basketball nba nfl formel_1 wandern wanderung klettern yoga muskelaufbau trainingsplan' },
        { id: 'gesundheit', label: 'Gesundheit', t: 'gesundheit', f: 'Gesundheit',
          d: 'netdoktor.de apotheken-umschau.de gesundheit.de onmeda.de doccheck.com aok.de tk.de barmer.de dak.de docmorris.de shop-apotheke.com medpex.de doctolib.de jameda.de rki.de gesund.bund.de mayoclinic.org webmd.com healthline.com nhs.uk medlineplus.gov gelbe-liste.de',
          w: 'gesundheit health arzt ärzte ärztin doktor krankheit krankheiten symptom symptome medizin medikament medikamente apotheke ernährung diät abnehmen therapie krankenkasse zahnarzt rezeptfrei schmerzen impfung' },
        { id: 'wohnen', label: 'Wohnen & Garten', t: 'wohnen', f: 'Wohnen',
          d: 'immobilienscout24.de immowelt.de immonet.de wg-gesucht.de obi.de hornbach.* bauhaus.info toom.de hagebau.de mein-schoener-garten.de westwing.* home24.de wayfair.de houzz.de',
          w: 'wohnung wohnungen mieten miete immobilie immobilien garten garden pflanzen zimmerpflanzen heimwerken renovieren möbel deko balkon' },
        { id: 'auto', label: 'Auto & Verkehr', t: 'auto', f: 'Auto',
          d: 'mobile.de autoscout24.* adac.de auto-motor-und-sport.de autobild.de motor-talk.de carwow.de spritmonitor.de clever-tanken.de mehr-tanken.de tesla.com autozeitung.de motorradonline.de 1000ps.de',
          w: 'autos kfz pkw fahrzeug fahrzeuge motorrad gebrauchtwagen reifen tanken elektroauto e_auto werkstatt' },
        { id: 'wetter', label: 'Wetter', t: 'wetter', f: '',
          d: 'wetter.com wetter.de wetteronline.de dwd.de kachelmannwetter.com windy.com accuweather.com weather.com meteoblue.com wetter.at',
          w: 'wetter weather unwetter regenradar wettervorhersage' },
        { id: 'buecher', label: 'Bücher', t: 'bücher', f: 'Bücher',
          d: 'goodreads.com thalia.* hugendubel.de buecher.de audible.* storytel.com bookbeat.* kobo.com lovelybooks.de booklooker.de medimops.de zvab.com perlentaucher.de',
          w: 'buch bücher book books ebook ebooks hörbuch hörbücher roman romane leseprobe audiobook audiobooks' },
        { id: 'tools', label: 'Werkzeuge & Online-Dienste', t: 'tools', f: 'Tools',
          d: 'deepl.com translate.google.com docs.google.com drive.google.com dropbox.com onedrive.live.com icloud.com notion.so trello.com canva.com figma.com smallpdf.com ilovepdf.com wetransfer.com bitwarden.com 1password.com mail.google.com outlook.live.com outlook.com gmx.net gmx.de web.de proton.me tuta.com speedtest.net fast.com archive.ph tinyurl.com remove.bg photopea.com excalidraw.com draw.io app.diagrams.net calendar.google.com doodle.com virustotal.com haveibeenpwned.com cloudconvert.com online-convert.com tineye.com openstreetmap.org',
          w: 'tool tools rechner calculator converter konverter generator umrechner übersetzer translator' }
    ];
    // Große Plattformen mit ganz gemischtem Inhalt: Hier lernt die Sortierung nicht „wie die anderen Links dieser Seite“
    const AS_GENERIC = new Set(('youtube.com youtu.be google.com google.de github.com gitlab.com reddit.com medium.com substack.com amazon.de amazon.com '
        + 'twitter.com x.com facebook.com instagram.com pinterest.com pinterest.de tiktok.com t.me linkedin.com docs.google.com drive.google.com '
        + 'web.archive.org archive.org bit.ly tinyurl.com de.wikipedia.org en.wikipedia.org wikipedia.org wordpress.com blogspot.com '
        + 'stackoverflow.com ebay.de ebay.com spotify.com open.spotify.com vimeo.com twitch.tv').split(' '));
    // Sammelordner, die als „noch nicht einsortiert“ gelten (wie beim Import)
    const AS_UNSORTED = new Set(['', 'allgemein', 'lesezeichen-symbolleiste', 'lesezeichenleiste', 'lesezeichen-menü', 'lesezeichenmenü',
        'weitere lesezeichen', 'bookmarks bar', 'bookmarks toolbar', 'bookmarks menu', 'other bookmarks', 'mobile lesezeichen',
        'mobile bookmarks', 'favoritenleiste', 'favorites bar', 'importiert', 'imported']);
    // Eigene Tags und Ordnernamen, die zu allgemein sind, um sie im Text zu suchen
    const AS_STOP = new Set(('neu alt new old top gut tip tipp tipps todo wichtig später spaeter lesen read later info infos misc sonstiges sonstige '
        + 'diverses privat private test allgemein archiv archive import importiert imported favoriten favorites links link web www seite seiten '
        + 'home start main mehr more und and the der die das').split(' '));

    let asGroups = null;         // die Gruppen, wie sie gerade gelten (vom Server oder Standard)
    let asRulesOk = false;       // false = konnte nicht geladen werden, dann darf das Gruppen-Fenster nichts überschreiben
    let asSugs = [];             // Vorschläge der letzten Berechnung
    let asRun = 0;
    const autoOverlay = $('#autoOverlay');
    const rulesOverlay = $('#rulesOverlay');
    const asLower = s => String(s || '').toLocaleLowerCase('de');
    const asWords = s => asLower(s).split(/[^a-z0-9äöüß]+/).filter(Boolean).join(' ');

    // Standard als bearbeitbare Liste: jede Gruppe mit Name, Tags, Ordner und Einträgen
    function asDefaultGroups() {
        const tr = (window.lvUi && typeof window.lvUi.tr === 'function') ? window.lvUi.tr : (x => x);
        return AS_CATS.map(c => ({
            id: c.id, n: tr(c.label), on: true, t: c.t ? [c.t] : [], f: c.f || '',
            e: [].concat(
                (c.d || '').split(' ').filter(Boolean),
                (c.w || '').split(' ').filter(Boolean).map(w => w.replace(/_/g, ' ')),
                (c.s || '').split(' ').filter(Boolean).map(x => '*' + x + '*'))
        }));
    }
    // Erste Fassung (eigene Regeln + geänderte eingebaute Gruppen) in die gemeinsame Liste übernehmen
    function asFromLegacy(lg) {
        const groups = asDefaultGroups();
        const cats = (lg && lg.cats && typeof lg.cats === 'object') ? lg.cats : {};
        groups.forEach(g => { const o = cats[g.id]; if (o) { g.on = !!o.on; g.t = o.t ? [o.t] : []; g.f = o.f || ''; } });
        const own = ((lg && Array.isArray(lg.rules)) ? lg.rules : []).map(r => {
            const x = asEntry(r.m);
            return { id: '', n: r.m, on: true, t: r.t || [], f: r.f || '', e: [x && x.k === 'd' ? r.m : '*' + r.m + '*'] };
        });
        return own.concat(groups);
    }

    // Text eines Links als Wortkette „ wort wort … “: Titel, Beschreibung, Domain (ohne Endung) und Pfad
    function asText(bm) {
        let host = '', path = '';
        try {
            const u = new URL(bm.url);
            host = u.hostname.toLowerCase().replace(/^www\./, '');
            path = u.pathname || '';
            try { path = decodeURIComponent(path); } catch (_) {}
            // Dateiendungen wie .html oder .php sagen nichts über den Inhalt
            path = path.replace(/\.(s?html?|xhtml|php\d?|aspx?|jsp|cgi|pl|cfm)(?=\/|$)/gi, ' ');
        } catch (_) {}
        const labels = host.split('.');
        if (labels.length > 1) labels.pop();
        const raw = asLower([bm.title || '', bm.description || '', labels.join(' '), path].join(' '));
        const words = raw.split(/[^a-z0-9äöüß]+/).filter(Boolean);
        return { host, set: new Set(words), words: ' ' + words.join(' ') + ' ', full: asLower((bm.url || '') + ' ' + (bm.title || '') + ' ' + (bm.description || '')) };
    }
    // Was ein Eintrag bedeutet: „youtube.com“ Domain samt Unterdomains, „amazon.*“ jede Endung, „.xxx“ alle mit dieser Endung,
    // „*teil*“ steht irgendwo, „wort*“ Wortanfang, sonst ein ganzes Wort (oder mehrere hintereinander)
    const AS_DOMAIN_RX = /^\.?[a-z0-9äöüß-]+(\.[a-z0-9äöüß-]+)*(\.\*)?$/;
    function asEntry(raw) {
        const e = asLower(raw).trim();
        if (!e) return null;
        if (e.startsWith('*')) { const x = e.replace(/^\*+|\*+$/g, ''); return x ? { k: 's', v: x } : null; }
        if (e.includes('.') && AS_DOMAIN_RX.test(e)) return { k: 'd', v: e.replace(/^\./, '').replace(/^www\./, '') };
        if (e.endsWith('*')) { const x = asWords(e.slice(0, -1)); return x ? { k: 'p', v: x } : null; }
        const x = asWords(e);
        return x ? { k: 'w', v: x } : null;
    }
    // Ganzes Wort (oder mehrere Wörter) im Text? Mit ends = auch mit Endung (Rezept → Rezepte)
    const AS_ENDS = ['s', 'e', 'en', 'n', 'er'];
    function asHasWord(tx, w, ends) {
        if (w.includes(' ')) return tx.words.includes(' ' + w + ' ');
        if (tx.set.has(w)) return true;
        return !!ends && w.length >= 4 && AS_ENDS.some(x => tx.set.has(w + x));
    }
    // Gruppen einmal aufbereiten: Domains in eine Tabelle, Wörter und Wortteile je Gruppe
    function asCompileGroups(groups) {
        const dmap = new Map();
        const comp = (groups || []).map((g, i) => {
            const c = { i, n: g.n || '', on: !!g.on, t: g.t || [], f: g.f || '', words: [], pre: [], subs: [] };
            (g.e || []).forEach(raw => {
                const x = asEntry(raw);
                if (!x) return;
                if (x.k === 'd') {
                    if (!c.on) return;
                    const l = dmap.get(x.v) || [];
                    if (!l.includes(i)) l.push(i);
                    dmap.set(x.v, l);
                } else if (x.k === 's') c.subs.push(x.v);
                else if (x.k === 'p') c.pre.push(x.v);
                else c.words.push(x.v);
            });
            return c;
        });
        return { comp, dmap };
    }
    // Gruppen zu einer Domain: die genaueste Angabe gewinnt (music.youtube.com vor youtube.com), dann „name.*“
    function asDomainGroups(host, dmap) {
        if (!host) return null;
        let h = host;
        while (h) {
            if (dmap.has(h)) return dmap.get(h);
            const i = h.indexOf('.');
            if (i < 0) break;
            h = h.slice(i + 1);
        }
        const labels = host.split('.');
        labels.pop();
        if (labels.length >= 2 && /^(co|com|org|net|ac|gv|or|ne)$/.test(labels[labels.length - 1])) labels.pop();
        const core = labels[labels.length - 1];
        return (core && dmap.get(core + '.*')) || null;
    }
    const asIsUnsorted = cat => AS_UNSORTED.has(asLower(cat));

    function asCompute() {
        const optTags = $('#autoOptTags').checked;
        const optFolders = $('#autoOptFolders').checked;
        const optMove = $('#autoOptMove').checked;
        const all = live();
        // Ist ein Ordner oder eine Suche aktiv, geht es nur um das, was gerade zu sehen ist
        const scoped = currentCategory !== 'all' || !!searchQuery;
        const list = scoped ? bookmarks.filter(matchesFilter) : all;
        const G = asCompileGroups(asGroups);

        // Vorhandene Schreibweisen übernehmen: Tag „Video“ statt „video“, Ordner „Medien > Videos“ statt „Videos“
        const tagSpelling = new Map();
        allTags().forEach(t => { const k = asLower(t); if (!tagSpelling.has(k)) tagSpelling.set(k, t); });
        const folders = getCategories();
        const folderSize = {};
        all.forEach(b => { folderSize[b.category] = (folderSize[b.category] || 0) + 1; });
        const resolveTag = t => tagSpelling.get(asLower(t)) || t;
        const resolveFolder = f => {
            const k = asLower(f);
            let hit = folders.find(x => asLower(x) === k);
            if (hit) return hit;
            hit = folders.filter(x => asLower(x.split(SEP).pop()) === k).sort((a, b) => a.split(SEP).length - b.split(SEP).length)[0];
            return hit || f;
        };

        // Was du schon sortiert hast, pro Seite: welche Tags und Ordner kommen dort oft vor?
        const texts = new Map();
        const byHost = new Map();
        all.forEach(b => {
            const tx = asText(b);
            texts.set(b.id, tx);
            if (!tx.host) return;
            let st = byHost.get(tx.host);
            if (!st) { st = { n: 0, tags: {}, sorted: 0, folders: {} }; byHost.set(tx.host, st); }
            st.n++;
            (b.tags || []).forEach(t => { const k = asLower(t); st.tags[k] = (st.tags[k] || 0) + 1; });
            if (!asIsUnsorted(b.category)) { st.sorted++; st.folders[b.category] = (st.folders[b.category] || 0) + 1; }
        });
        // Eigene Tags und Ordnernamen, nach denen im Text gesucht wird
        // Einzelne Wörter kommen in eine Tabelle (schnell auch bei Hunderten Tags), mehrere Wörter werden einzeln geprüft
        const ownTagWord = new Map();
        const ownTagPhrases = [];
        tagSpelling.forEach((t, k) => {
            const phrase = asWords(k);
            if (phrase.length < 3 || /^\d+$/.test(phrase) || AS_STOP.has(phrase)) return;
            if (phrase.includes(' ')) ownTagPhrases.push({ t, phrase });
            else if (!ownTagWord.has(phrase)) ownTagWord.set(phrase, t);
        });
        const ownFolders = [];
        folders.forEach(f => {
            if (asIsUnsorted(f)) return;
            const phrase = asWords(f.split(SEP).pop());
            if (phrase.length >= 3 && !/^\d+$/.test(phrase) && !AS_STOP.has(phrase)) ownFolders.push({ f, phrase });
        });

        const out = [];
        list.forEach(b => {
            const tx = texts.get(b.id) || asText(b);
            const have = new Set((b.tags || []).map(asLower));
            const tags = [];       // { t, why }
            const seen = new Set();
            const addTag = (t, why) => {
                if (!t) return false;
                const k = asLower(t);
                if (have.has(k) || seen.has(k)) return false;
                seen.add(k);
                tags.push({ t: resolveTag(t), why });
                return true;
            };
            let folder = null;     // { f, why }
            const setFolder = (f, why) => { if (!folder && f) folder = { f, why }; };

            // Welche Gruppen passen? Erst über die Domain, dann über Stichwörter, jeweils in der Reihenfolge der Liste
            const hits = [];       // { c, dom, why }
            const domList = asDomainGroups(tx.host, G.dmap) || [];
            domList.forEach(i => { const c = G.comp[i]; if (c && c.on) hits.push({ c, dom: true, why: `Domain ${tx.host} (${c.n})` }); });
            G.comp.forEach(c => {
                if (!c.on || domList.includes(c.i)) return;
                let first = '';
                for (const w of c.words) { if (asHasWord(tx, w, false)) { first = w; break; } }
                if (!first) for (const p of c.pre) { if (tx.words.includes(' ' + p)) { first = p + '*'; break; } }
                if (!first) for (const s of c.subs) { if (tx.full.includes(s)) { first = s; break; } }
                if (first) hits.push({ c, dom: false, why: `Stichwort „${first}“ (${c.n})` });
            });
            let groupTags = 0;
            const takeTags = h => h.c.t.forEach(t => { if (groupTags < 6 && addTag(t, h.why)) groupTags++; });

            // 1. Gruppen, die über die Domain passen
            hits.filter(h => h.dom).forEach(h => { takeTags(h); if (h.c.f) setFolder(resolveFolder(h.c.f), h.why); });

            // 2. wie die anderen Links dieser Seite
            const st = tx.host ? byHost.get(tx.host) : null;
            if (st && !AS_GENERIC.has(tx.host)) {
                const why = `wie deine anderen Links von ${tx.host}`;
                Object.entries(st.tags).forEach(([k, n]) => { if (n >= 2 && n / st.n >= 0.4) addTag(tagSpelling.get(k) || k, why); });
                let best = null, bestN = 0;
                Object.entries(st.folders).forEach(([f, n]) => { if (n > bestN) { best = f; bestN = n; } });
                if (best && bestN >= 2 && bestN / st.sorted >= 0.6) setFolder(best, why);
            }

            // 3. deine Tags und Ordnernamen tauchen im Text auf (deine Ordner gehen vor allgemeinen Stichwörtern)
            const ownWhy = 'dein Tag steht im Titel oder in der Adresse';
            tx.set.forEach(w => {
                let t = ownTagWord.get(w);
                // Wort mit Endung (Rezepte → Tag „rezept“), wie bei asHasWord
                if (t === undefined) for (const x of AS_ENDS) {
                    if (w.length - x.length >= 4 && w.endsWith(x) && ownTagWord.has(w.slice(0, -x.length))) { t = ownTagWord.get(w.slice(0, -x.length)); break; }
                }
                if (t !== undefined) addTag(t, ownWhy);
            });
            ownTagPhrases.forEach(o => { if (asHasWord(tx, o.phrase, true)) addTag(o.t, ownWhy); });
            if (!folder) {
                let best = null;
                ownFolders.forEach(o => {
                    if (!asHasWord(tx, o.phrase, true)) return;
                    if (!best || o.phrase.length > best.phrase.length
                        || (o.phrase.length === best.phrase.length && (folderSize[o.f] || 0) > (folderSize[best.f] || 0))) best = o;
                });
                if (best) setFolder(best.f, 'Ordnername steht im Titel oder in der Adresse');
            }

            // 4. Gruppen, die über Stichwörter passen
            hits.filter(h => !h.dom).forEach(h => { takeTags(h); if (h.c.f) setFolder(resolveFolder(h.c.f), h.why); });

            // Was davon wird überhaupt vorgeschlagen?
            const sug = { id: b.id, title: b.title || b.url, url: b.url, host: tx.host, cat: b.category || 'Allgemein', tags: [], folder: null };
            if (optTags) sug.tags = tags.slice(0, 8).map(x => ({ t: x.t, why: x.why, on: true }));
            if (optFolders && folder && (optMove || asIsUnsorted(b.category))) {
                const cur = asLower(b.category || 'Allgemein'), f = asLower(folder.f);
                if (cur !== f && !cur.startsWith(f + asLower(SEP))) sug.folder = { f: folder.f, why: folder.why, on: true };
            }
            if (sug.tags.length || sug.folder) out.push(sug);
        });
        out.sort((a, b) => (a.title || '').localeCompare(b.title || '', 'de', { sensitivity: 'base', numeric: true }));
        return { list: out, total: list.length, scoped };
    }

    function asRowOn(s) { return s.tags.some(x => x.on) || !!(s.folder && s.folder.on); }
    function asRenderList(res) {
        asSugs = res.list;
        const hint = $('#autoHint');
        const where = res.scoped ? ' in der aktuellen Ansicht' : '';
        if (!res.total) hint.textContent = 'Keine Links zum Sortieren.';
        else if (!asSugs.length) hint.textContent = `Für ${res.total} Link(s)${where} gibt es keine neuen Vorschläge.`;
        else hint.textContent = `${asSugs.length} von ${res.total} Link(s)${where} bekommen Vorschläge. Antippen schaltet einzelne Vorschläge ab.`;
        const shown = asSugs.slice(0, 1500);
        $('#autoList').innerHTML = shown.map((s, i) => {
            const why = [...new Set(s.tags.map(x => x.why).concat(s.folder ? [s.folder.why] : []))];
            return `<label class="list-row as-row" data-i="${i}">
                <input type="checkbox" class="as-check" checked>
                <span class="grow">
                    <span class="t1 block">${escapeHtml(s.title)}</span>
                    <span class="t2 block as-keep">${escapeHtml(s.host || s.url)} · ${escapeHtml(prettyCat(s.cat))}</span>
                    <span class="as-chips">${s.tags.map((x, k) => `<button type="button" class="bm-chip bm-tag" data-k="t${k}" title="${escapeHtml(x.why)}">#${escapeHtml(x.t)}</button>`).join('')}${
                        s.folder ? `<button type="button" class="bm-chip as-folder" data-k="f" title="${escapeHtml(s.folder.why)}">→ ${escapeHtml(prettyCat(s.folder.f))}</button>` : ''}</span>
                    <span class="as-why">${why.map(escapeHtml).join(' · ')}</span>
                </span>
            </label>`;
        }).join('') + (asSugs.length > shown.length
            ? `<p class="text-sm text-slate-500">Die Liste zeigt die ersten ${shown.length}. Übernommen werden alle ${asSugs.length}, die Schalter oben gelten für alle.</p>` : '');
        asRenderSummary();
        asSyncApply();
    }
    // Übersicht oben: jeder vorgeschlagene Tag und Ordner mit Anzahl, Antippen schaltet ihn überall an oder aus
    function asSummaryKeys() {
        const m = new Map();
        asSugs.forEach(s => {
            s.tags.forEach(x => {
                const k = 't:' + asLower(x.t);
                const e = m.get(k) || { k, label: '#' + x.t, tag: true, n: 0, on: 0 };
                e.n++; if (x.on) e.on++; m.set(k, e);
            });
            if (s.folder) {
                const k = 'f:' + asLower(s.folder.f);
                const e = m.get(k) || { k, label: '→ ' + prettyCat(s.folder.f), tag: false, n: 0, on: 0 };
                e.n++; if (s.folder.on) e.on++; m.set(k, e);
            }
        });
        return [...m.values()].sort((a, b) => (b.tag - a.tag) || b.n - a.n || a.label.localeCompare(b.label, 'de'));
    }
    function asRenderSummary() {
        const keys = asSummaryKeys();
        $('#autoSummary').innerHTML = keys.length < 2 ? '' : keys.map(e =>
            `<button type="button" class="bm-chip ${e.tag ? 'bm-tag' : 'as-folder'}${e.on ? '' : ' as-off'}" data-s="${escapeHtml(e.k)}">${escapeHtml(e.label)} ${e.n}</button>`).join('');
    }
    function asPaintRow(i) {
        const s = asSugs[i];
        const row = $('#autoList').querySelector(`[data-i="${i}"]`);
        if (!s || !row) return;
        s.tags.forEach((x, k) => { const c = row.querySelector(`[data-k="t${k}"]`); if (c) c.classList.toggle('as-off', !x.on); });
        const fc = row.querySelector('[data-k="f"]');
        if (fc && s.folder) fc.classList.toggle('as-off', !s.folder.on);
        const on = asRowOn(s);
        row.querySelector('.as-check').checked = on;
        row.classList.toggle('as-dim', !on);
    }
    function asSyncApply() {
        const n = asSugs.filter(asRowOn).length;
        const btn = $('#autoApply');
        btn.disabled = n === 0;
        btn.textContent = n ? `Übernehmen (${n})` : 'Übernehmen';
    }
    function asRecompute() {
        asRenderList(asCompute());
    }
    // Lädt die Gruppen immer frisch (es könnte sie gerade jemand auf einem anderen Gerät geändert haben)
    async function asLoadRules() {
        const res = await api('autosort_rules');
        if (!res.success) {
            showToast(res.message || 'Gruppen konnten nicht geladen werden', 'error');
            if (!asRulesOk) asGroups = asDefaultGroups(); // Vorschläge gehen trotzdem, mit dem Standard
            return false;
        }
        if (Array.isArray(res.groups)) asGroups = res.groups;
        else if (res.legacy) asGroups = asFromLegacy(res.legacy);
        else asGroups = asDefaultGroups();
        asRulesOk = true;
        if (res.broken) showToast('Die Datei mit deinen Gruppen ist nicht lesbar, es gilt der Standard. Beim nächsten Speichern wird sie neu angelegt.', 'error');
        return true;
    }
    async function openAuto() {
        const run = ++asRun;
        $('#autoHint').textContent = 'Lade…';
        $('#autoSummary').innerHTML = '';
        $('#autoList').innerHTML = '';
        asSugs = [];
        asSyncApply();
        showOverlay(autoOverlay);
        await asLoadRules();
        if (run !== asRun || autoOverlay.classList.contains('hidden')) return;
        asRecompute();
    }
    function closeAuto() {
        asRun++;
        hideOverlay(autoOverlay);
    }
    $('#btnAutoSort').addEventListener('click', openAuto);
    $('#autoClose').addEventListener('click', closeAuto);
    $('#autoCancel').addEventListener('click', closeAuto);
    autoOverlay.addEventListener('click', e => { if (e.target === autoOverlay) closeAuto(); });
    ['#autoOptTags', '#autoOptFolders', '#autoOptMove'].forEach(s => $(s).addEventListener('change', () => {
        if (asGroups) asRecompute();
    }));
    $('#autoList').addEventListener('click', e => {
        const chip = e.target.closest('[data-k]');
        if (!chip) return;
        e.preventDefault(); // sonst schaltet das Label gleich die ganze Zeile mit um
        const i = +chip.closest('[data-i]').dataset.i;
        const s = asSugs[i];
        if (!s) return;
        const k = chip.dataset.k;
        if (k === 'f') { if (s.folder) s.folder.on = !s.folder.on; }
        else { const x = s.tags[+k.slice(1)]; if (x) x.on = !x.on; }
        asPaintRow(i);
        asRenderSummary();
        asSyncApply();
    });
    $('#autoList').addEventListener('change', e => {
        const cb = e.target.closest('.as-check');
        if (!cb) return;
        const i = +cb.closest('[data-i]').dataset.i;
        const s = asSugs[i];
        if (!s) return;
        s.tags.forEach(x => { x.on = cb.checked; });
        if (s.folder) s.folder.on = cb.checked;
        asPaintRow(i);
        asRenderSummary();
        asSyncApply();
    });
    $('#autoSummary').addEventListener('click', e => {
        const chip = e.target.closest('[data-s]');
        if (!chip) return;
        const key = chip.dataset.s;
        const e2 = asSummaryKeys().find(x => x.k === key);
        if (!e2) return;
        const on = e2.on < e2.n; // alles an, wenn mindestens einer aus ist, sonst alles aus
        asSugs.forEach((s, i) => {
            let hit = false;
            s.tags.forEach(x => { if ('t:' + asLower(x.t) === key) { x.on = on; hit = true; } });
            if (s.folder && 'f:' + asLower(s.folder.f) === key) { s.folder.on = on; hit = true; }
            if (hit) asPaintRow(i);
        });
        asRenderSummary();
        asSyncApply();
    });
    $('#autoApply').addEventListener('click', async () => {
        const changes = {};
        let n = 0;
        asSugs.forEach(s => {
            const t = s.tags.filter(x => x.on).map(x => x.t);
            const f = s.folder && s.folder.on ? s.folder.f : '';
            if (!t.length && !f) return;
            changes[s.id] = f ? { t, f } : { t };
            n++;
        });
        if (!n) return;
        const btn = $('#autoApply');
        btn.disabled = true;
        btn.textContent = 'Speichere…';
        const res = await api('autosort_apply', { changes });
        if (!res.success) { asSyncApply(); showToast(res.message || 'Fehler', 'error'); return; }
        if (Array.isArray(res.bookmarks)) bookmarks = res.bookmarks;
        closeAuto();
        render();
        const backup = res.backup;
        showToast(res.message || 'Sortiert', 'success', backup ? { label: 'Rückgängig', fn: undoBackup(backup) } : null);
    });

    /* ----- Gruppen bearbeiten: eine gemeinsame Liste, alles änderbar, löschbar und jederzeit auf Standard zurückzuholen ----- */
    let grpDraft = [];           // Arbeitskopie, gespeichert wird erst mit „Speichern“
    const grpList = $('#grpList');
    const grpSplitTags = s => String(s || '').split(/[,;\n]+/).map(x => x.trim().replace(/^#+/, '').replace(/\s+/g, '-')).filter(Boolean).slice(0, 5);
    const grpSplitEntries = s => {
        const seen = new Set();
        return String(s || '').split(/[,\n]+/).map(x => asLower(x).trim().replace(/\s+/g, ' ')).filter(x => x && !seen.has(x) && seen.add(x)).slice(0, 500);
    };
    const grpFolder = s => {
        const f = String(s || '').split('>').map(x => x.trim()).filter(Boolean).slice(0, 4).join(SEP);
        return asLower(f) === 'allgemein' ? '' : f;
    };
    function grpSummary(g) {
        const parts = [];
        if (g.t.length) parts.push(g.t.map(t => '#' + t).join(' '));
        if (g.f) parts.push('→ ' + prettyCat(g.f));
        return parts.length ? parts.join(' · ') + ' ·' : '';
    }
    const grpCount = g => g.e.length === 1 ? '1 Eintrag' : `${g.e.length} Einträge`;
    function grpMatches(g, q) {
        if (!q) return true;
        return [g.n, g.f].concat(g.t, g.e).some(x => asLower(x).includes(q));
    }
    function renderGroups() {
        const q = asLower($('#grpFilter').value.trim());
        if (!grpDraft.length) {
            grpList.innerHTML = '<p class="text-sm text-slate-500">Keine Gruppen. Leg eine neue an oder hol den Standard zurück.</p>';
            return;
        }
        grpList.innerHTML = grpDraft.map((g, i) => `
            <div class="as-grp${g.on ? '' : ' as-dim'}${grpMatches(g, q) ? '' : ' hidden'}" data-g="${i}">
                <div class="list-row">
                    <input type="checkbox" class="as-on" ${g.on ? 'checked' : ''} title="Gruppe benutzen" aria-label="Gruppe benutzen">
                    <button type="button" class="grow as-grp-head" data-gact="edit" aria-expanded="${g._open ? 'true' : 'false'}">
                        <span class="t1 block as-keep as-gname">${escapeHtml(g.n)}</span>
                        <span class="t2 block"><span class="as-keep as-gsum">${escapeHtml(grpSummary(g))}</span> <span class="as-gcount">${grpCount(g)}</span></span>
                    </button>
                    <button type="button" class="card-btn card-btn-icon" data-gact="edit" title="Bearbeiten" aria-label="Bearbeiten">${SVG.edit}</button>
                    <button type="button" class="card-btn card-btn-icon danger" data-gact="del" title="Gruppe löschen" aria-label="Gruppe löschen">${SVG.trash}</button>
                </div>
                <div class="as-grp-edit box${g._open ? '' : ' hidden'}">
                    <label class="lbl">Name</label>
                    <input type="text" class="field mb-2 as-gn" maxlength="60" value="${escapeHtml(g.n)}" autocomplete="off">
                    <div class="as-two">
                        <div><label class="lbl">Tags (mit Komma)</label>
                            <input type="text" class="field as-gt" maxlength="200" value="${escapeHtml(g.t.join(', '))}" placeholder="z. B. video, musik" autocomplete="off"></div>
                        <div><label class="lbl">Ordner</label>
                            <input type="text" class="field as-gf" maxlength="250" value="${escapeHtml(g.f)}" placeholder="leer = keiner" autocomplete="off" list="ruleFolderList"></div>
                    </div>
                    <label class="lbl mt-2">Domains und Stichwörter (mit Komma oder je Zeile)</label>
                    <textarea class="field as-ge" rows="5" spellcheck="false">${escapeHtml(g.e.join(', '))}</textarea>
                    <div class="flex flex-wrap gap-2 mt-2">
                        <button type="button" class="btn btn-secondary lv-mini" data-gact="up" ${i === 0 ? 'disabled' : ''}>Nach oben</button>
                        <button type="button" class="btn btn-secondary lv-mini" data-gact="down" ${i === grpDraft.length - 1 ? 'disabled' : ''}>Nach unten</button>
                        <button type="button" class="btn btn-primary lv-mini ml-auto" data-gact="edit">Fertig</button>
                    </div>
                </div>
            </div>`).join('');
    }
    function grpRowOf(el) {
        const row = el && el.closest('[data-g]');
        return row ? { row, i: +row.dataset.g, g: grpDraft[+row.dataset.g] } : null;
    }
    async function openRules() {
        // Ohne sicher geladene Gruppen kein Bearbeiten, sonst würde Speichern sie mit dem Standard überschreiben
        if (!await asLoadRules()) return;
        grpDraft = (asGroups || []).map(g => ({ id: g.id || '', n: g.n || '', on: !!g.on, t: (g.t || []).slice(), f: g.f || '', e: (g.e || []).slice(), _open: false }));
        $('#grpFilter').value = '';
        $('#ruleFolderList').innerHTML = getCategories().map(c => `<option value="${escapeHtml(c)}"></option>`).join('');
        renderGroups();
        showOverlay(rulesOverlay);
    }
    function closeRules() { hideOverlay(rulesOverlay); }
    $('#autoRulesBtn').addEventListener('click', openRules);
    $('#rulesClose').addEventListener('click', closeRules);
    $('#rulesCancel').addEventListener('click', closeRules);
    rulesOverlay.addEventListener('click', e => { if (e.target === rulesOverlay) closeRules(); });
    $('#grpFilter').addEventListener('input', () => {
        const q = asLower($('#grpFilter').value.trim());
        grpList.querySelectorAll('[data-g]').forEach(row => row.classList.toggle('hidden', !grpMatches(grpDraft[+row.dataset.g], q)));
    });
    $('#grpNew').addEventListener('click', () => {
        if (grpDraft.length >= 150) { showToast('Höchstens 150 Gruppen', 'error'); return; }
        grpDraft.forEach(g => { g._open = false; });
        grpDraft.unshift({ id: '', n: 'Neue Gruppe', on: true, t: [], f: '', e: [], _open: true });
        $('#grpFilter').value = '';
        renderGroups();
        const name = grpList.querySelector('[data-g="0"] .as-gn');
        if (name) { name.focus(); name.select(); }
    });
    $('#grpReset').addEventListener('click', async () => {
        if (!await confirmDialog({
            title: 'Standard wiederherstellen?',
            text: 'Alle eingebauten Gruppen kommen in der Originalfassung zurück, auch gelöschte. Deine eigenen Gruppen bleiben. Übernommen wird es erst mit „Speichern“.',
            ok: 'Wiederherstellen' })) return;
        const own = grpDraft.filter(g => !g.id);
        grpDraft = own.concat(asDefaultGroups().map(g => Object.assign(g, { _open: false })));
        $('#grpFilter').value = '';
        renderGroups();
        showToast('Standard ist wieder da. Zum Übernehmen „Speichern“ antippen.');
    });
    grpList.addEventListener('click', e => {
        const btn = e.target.closest('[data-gact]');
        const r = grpRowOf(btn);
        if (!btn || !r || btn.disabled) return;
        const act = btn.dataset.gact;
        if (act === 'edit') {
            r.g._open = !r.g._open;
            r.row.querySelector('.as-grp-edit').classList.toggle('hidden', !r.g._open);
            r.row.querySelector('.as-grp-head').setAttribute('aria-expanded', r.g._open ? 'true' : 'false');
            if (r.g._open) { const n = r.row.querySelector('.as-gn'); if (n) n.focus(); }
            return;
        }
        if (act === 'del') {
            const [gone] = grpDraft.splice(r.i, 1);
            renderGroups();
            showToast(`Gruppe „${gone.n}“ gelöscht`, 'success', { label: 'Rückgängig', fn: () => {
                grpDraft.splice(Math.min(r.i, grpDraft.length), 0, gone);
                renderGroups();
            } });
            return;
        }
        if (act === 'up' || act === 'down') {
            const j = act === 'up' ? r.i - 1 : r.i + 1;
            if (j < 0 || j >= grpDraft.length) return;
            [grpDraft[r.i], grpDraft[j]] = [grpDraft[j], grpDraft[r.i]];
            renderGroups();
            const moved = grpList.querySelector(`[data-g="${j}"] [data-gact="${act}"]`);
            if (moved && !moved.disabled) moved.focus();
            const row = grpList.querySelector(`[data-g="${j}"]`);
            if (row) row.scrollIntoView({ block: 'nearest' });
        }
    });
    // Eingaben landen sofort in der Arbeitskopie, die Zusammenfassung oben läuft mit
    grpList.addEventListener('input', e => {
        const r = grpRowOf(e.target);
        if (!r) return;
        const el = e.target;
        if (el.classList.contains('as-gn')) { r.g.n = el.value.trim(); r.row.querySelector('.as-gname').textContent = r.g.n || 'Gruppe'; }
        else if (el.classList.contains('as-gt')) r.g.t = grpSplitTags(el.value);
        else if (el.classList.contains('as-gf')) r.g.f = grpFolder(el.value);
        else if (el.classList.contains('as-ge')) r.g.e = grpSplitEntries(el.value);
        else return;
        r.row.querySelector('.as-gsum').textContent = grpSummary(r.g);
        r.row.querySelector('.as-gcount').textContent = grpCount(r.g);
    });
    grpList.addEventListener('change', e => {
        const cb = e.target.closest('.as-on');
        const r = grpRowOf(cb);
        if (!r) return;
        r.g.on = cb.checked;
        r.row.classList.toggle('as-dim', !cb.checked);
    });
    $('#rulesSave').addEventListener('click', async () => {
        const groups = grpDraft.map(g => ({ id: g.id, n: g.n.trim() || 'Gruppe', on: g.on, t: g.t, f: g.f, e: g.e }));
        const btn = $('#rulesSave');
        btn.disabled = true;
        const res = await api('autosort_rules_save', { groups });
        btn.disabled = false;
        if (!res.success) { showToast(res.message || 'Fehler', 'error'); return; }
        asGroups = Array.isArray(res.groups) ? res.groups : groups;
        asRulesOk = true;
        closeRules();
        showToast(res.message || 'Gespeichert');
        if (!autoOverlay.classList.contains('hidden')) asRecompute();
    });

    /* ---------- Tags verwalten: umbenennen, zusammenlegen, löschen. Die Links bleiben immer. ---------- */
    const tagsOverlay = $('#tagsOverlay');
    let tagsShown = [];
    function renderTags() {
        const count = new Map();
        live().forEach(b => (b.tags || []).forEach(t => count.set(t, (count.get(t) || 0) + 1)));
        tagsShown = [...count.keys()].sort((a, b) => a.localeCompare(b, 'de', { sensitivity: 'base', numeric: true }));
        const list = $('#tagsList');
        if (!tagsShown.length) { list.innerHTML = '<p class="text-sm text-slate-500">Noch keine Tags.</p>'; return; }
        const q = normalizeText($('#tagsFilter').value);
        list.innerHTML = tagsShown.map((t, i) => `
            <div class="flex items-center gap-1.5${q && !normalizeText(t).includes(q) ? ' hidden' : ''}" data-ti="${i}">
                <input type="text" class="field flex-1 min-w-0 !py-2 !text-sm" value="${escapeHtml(t)}" aria-label="Tag-Name" maxlength="40">
                <span class="text-[11px] text-slate-500 bg-slate-800/80 px-1.5 py-0.5 rounded shrink-0" title="Links mit diesem Tag">${count.get(t)}</span>
                <button type="button" class="btn btn-secondary lv-mini shrink-0" data-tact="rename">Speichern</button>
                <button type="button" class="btn btn-danger lv-mini shrink-0" data-tact="delete">Löschen</button>
            </div>`).join('');
    }
    function openTags() {
        $('#tagsFilter').value = '';
        renderTags();
        showOverlay(tagsOverlay);
    }
    function closeTags() { hideOverlay(tagsOverlay); }
    const afterTagUndo = () => { if (!tagsOverlay.classList.contains('hidden')) renderTags(); };
    async function renameTag(row) {
        const old = tagsShown[+row.dataset.ti];
        const input = row.querySelector('input');
        const neu = input.value.trim().replace(/^#+/, '').replace(/\s+/g, '-');
        if (old === undefined) return;
        if (!neu) { input.value = old; return; }
        if (neu === old) return;
        const other = tagsShown.find(t => t !== old && t.toLocaleLowerCase('de') === neu.toLocaleLowerCase('de'));
        if (other && !await confirmDialog({ title: 'Tags zusammenlegen?', text: `„#${other}“ gibt es schon. Alle Links mit „#${old}“ bekommen stattdessen „#${neu}“.`, ok: 'Zusammenlegen' })) return;
        const res = await api('tag_rename', { tag: old, new: neu });
        if (!res.success) { showToast(res.message || 'Fehler', 'error'); return; }
        bookmarks = res.bookmarks;
        // Filtert die Suche gerade nach dem alten Namen, gleich mitziehen
        const key = normalizeText(old);
        if (searchQuery.split(/\s+/).some(x => isTagToken(x) && normalizeText(x.slice(1)) === key)) {
            searchInput.value = searchQuery = searchQuery.split(/\s+/).map(x => isTagToken(x) && normalizeText(x.slice(1)) === key ? '#' + neu : x).join(' ');
            syncSearchClear();
        }
        render(); renderTags();
        showToast(res.message || 'Umbenannt', 'success', res.backup ? { label: 'Rückgängig', fn: undoBackup(res.backup, afterTagUndo) } : null);
    }
    $('#tagsList').addEventListener('click', async e => {
        const btn = e.target.closest('[data-tact]');
        const row = btn && btn.closest('[data-ti]');
        if (!row) return;
        if (btn.dataset.tact === 'rename') { renameTag(row); return; }
        const t = tagsShown[+row.dataset.ti];
        if (t === undefined) return;
        const n = live().filter(b => (b.tags || []).includes(t)).length;
        if (!await confirmDialog({ title: `Tag „#${t}“ löschen?`, text: `Er verschwindet von ${n} Link(s). Die Links selbst bleiben.`, ok: 'Tag löschen', danger: true })) return;
        const res = await api('tag_delete', { tag: t });
        if (!res.success) { showToast(res.message || 'Fehler', 'error'); return; }
        bookmarks = res.bookmarks;
        // Ein Filter auf den gelöschten Tag ergibt keinen Sinn mehr
        const key = normalizeText(t);
        if (searchQuery.split(/\s+/).some(x => isTagToken(x) && normalizeText(x.slice(1)) === key)) {
            searchInput.value = searchQuery = searchQuery.split(/\s+/).filter(x => !(isTagToken(x) && normalizeText(x.slice(1)) === key)).join(' ');
            syncSearchClear();
        }
        render(); renderTags();
        showToast(res.message || 'Gelöscht', 'success', res.backup ? { label: 'Rückgängig', fn: undoBackup(res.backup, afterTagUndo) } : null);
    });
    $('#tagsList').addEventListener('keydown', e => {
        if (e.key === 'Enter' && e.target.tagName === 'INPUT') { e.preventDefault(); renameTag(e.target.closest('[data-ti]')); }
    });
    $('#tagsFilter').addEventListener('input', () => {
        const q = normalizeText($('#tagsFilter').value);
        $('#tagsList').querySelectorAll('[data-ti]').forEach(row => row.classList.toggle('hidden', !!q && !normalizeText(tagsShown[+row.dataset.ti]).includes(q)));
    });
    $('#btnTags').addEventListener('click', openTags);
    $('#tagsClose').addEventListener('click', closeTags);
    tagsOverlay.addEventListener('click', e => { if (e.target === tagsOverlay) closeTags(); });

    /* ---------- Ordner verwalten ---------- */
    const foldersOverlay = $('#foldersOverlay');
    // „Rückgängig“ für große Aktionen: holt den Stand zurück, den der Server direkt davor gesichert hat
    function undoBackup(name, after) {
        return async () => {
            if (applyRes(await api('backup_restore', { name }), 'Zurückgeholt') && after) after();
        };
    }
    function renderFolders() {
        const cats = getCategories();
        const list = $('#foldersList');
        if (!cats.length) { list.innerHTML = '<p class="text-sm text-slate-500">Noch keine Ordner.</p>'; return; }
        const counts = {};
        live().forEach(b => { if (b.category) counts[b.category] = (counts[b.category] || 0) + 1; });
        list.innerHTML = cats.map(c => `
            <div class="flex items-center gap-1.5" data-folder="${escapeHtml(c)}">
                <input type="text" class="field flex-1 min-w-0 !py-2 !text-sm" value="${escapeHtml(c)}" aria-label="Ordnername" maxlength="150">
                <span class="text-[11px] text-slate-500 bg-slate-800/80 px-1.5 py-0.5 rounded shrink-0" title="Links in diesem Ordner">${counts[c] || 0}</span>
                <button type="button" class="btn btn-secondary lv-mini shrink-0" data-fact="rename">Speichern</button>
                <button type="button" class="btn btn-danger lv-mini shrink-0" data-fact="delete" ${c === 'Allgemein' ? 'disabled title="„Allgemein“ ist der Standard-Ordner"' : ''}>Löschen</button>
            </div>`).join('');
    }
    async function renameFolder(row) {
        const old = row.dataset.folder;
        const input = row.querySelector('input');
        const neu = input.value.trim();
        if (!neu) { input.value = old; return; }
        if (neu === old) return;
        if (getCategories().includes(neu) && !await confirmDialog({ title: 'Ordner zusammenlegen?', text: `„${neu}“ gibt es schon. Beide Ordner werden zusammengelegt.`, ok: 'Zusammenlegen' })) return;
        const res = await api('rename_category', { old, new: neu });
        if (res.success) {
            bookmarks = res.bookmarks;
            if (inCat(currentCategory, old)) { currentCategory = 'all'; store.set('lv_cat', 'all'); }
            render(); renderFolders();
            showToast(res.message || 'Umbenannt');
        } else showToast(res.message || 'Fehler', 'error');
    }
    $('#foldersList').addEventListener('click', async e => {
        const btn = e.target.closest('[data-fact]');
        const row = btn && btn.closest('[data-folder]');
        if (!row || btn.disabled) return;
        if (btn.dataset.fact === 'rename') { renameFolder(row); return; }
        const old = row.dataset.folder;
        const n = live().filter(b => inCat(b.category, old)).length;
        if (!await confirmDialog({
            title: `Ordner „${prettyCat(old)}“ löschen?`,
            text: `Nur der Ordner verschwindet. Die ${n} Link(s) darin bleiben erhalten und kommen nach „Allgemein“ (bei Unterordnern eine Ebene höher).`,
            ok: 'Ordner löschen', danger: true })) return;
        const res = await api('delete_category', { category: old });
        if (!res.success) { showToast(res.message || 'Fehler', 'error'); return; }
        bookmarks = res.bookmarks;
        render(); renderFolders();
        showToast(res.message || 'Ordner gelöscht', 'success', res.backup ? { label: 'Rückgängig', fn: undoBackup(res.backup, () => {
            if (!foldersOverlay.classList.contains('hidden')) renderFolders();
        }) } : null);
    });
    $('#foldersList').addEventListener('keydown', e => {
        if (e.key === 'Enter' && e.target.tagName === 'INPUT') { e.preventDefault(); renameFolder(e.target.closest('[data-folder]')); }
    });
    function closeFolders() { hideOverlay(foldersOverlay); }
    $('#btnFolders').addEventListener('click', () => { renderFolders(); showOverlay(foldersOverlay); });
    $('#foldersClose').addEventListener('click', closeFolders);
    foldersOverlay.addEventListener('click', e => { if (e.target === foldersOverlay) closeFolders(); });

    /* ---------- Papierkorb ---------- */
    const trashOverlay = $('#trashOverlay');
    function renderTrash() {
        const items = trashed().sort((a, b) => (b.deleted || 0) - (a.deleted || 0));
        const list = $('#trashList');
        $('#trashRestoreAll').disabled = $('#trashEmpty').disabled = !items.length;
        if (!items.length) { list.innerHTML = '<p class="text-sm text-slate-500">Der Papierkorb ist leer.</p>'; return; }
        list.innerHTML = items.map(b => `
            <div class="list-row" data-trash="${escapeHtml(b.id)}">
                <div class="grow">
                    <div class="t1">${escapeHtml(b.title)}</div>
                    <div class="t2">${escapeHtml(getDomain(b.url))} · gelöscht am ${escapeHtml(fmtDate(b.deleted))}</div>
                </div>
                <button type="button" class="card-btn card-btn-icon" data-tact="restore" title="Zurückholen" aria-label="Zurückholen">${SVG.undo}</button>
                <button type="button" class="card-btn card-btn-icon danger" data-tact="purge" title="Endgültig löschen" aria-label="Endgültig löschen">${SVG.trash}</button>
            </div>`).join('');
    }
    $('#trashList').addEventListener('click', async e => {
        const btn = e.target.closest('[data-tact]');
        const row = btn && btn.closest('[data-trash]');
        if (!row) return;
        const res = await api(btn.dataset.tact === 'restore' ? 'trash_restore' : 'trash_purge', { ids: [row.dataset.trash] });
        if (applyRes(res)) renderTrash();
    });
    $('#trashRestoreAll').addEventListener('click', async () => {
        if (applyRes(await api('trash_restore', { ids: trashed().map(b => b.id) }))) renderTrash();
    });
    $('#trashEmpty').addEventListener('click', async () => {
        const n = trashed().length;
        if (!await confirmDialog({ title: 'Papierkorb leeren?', text: `${n} Link(s) werden endgültig gelöscht.`, ok: 'Endgültig löschen', danger: true })) return;
        if (applyRes(await api('trash_purge', { ids: trashed().map(b => b.id) }))) renderTrash();
    });
    function closeTrash() { hideOverlay(trashOverlay); }
    $('#btnTrash').addEventListener('click', () => { renderTrash(); showOverlay(trashOverlay); });
    $('#trashClose').addEventListener('click', closeTrash);
    trashOverlay.addEventListener('click', e => { if (e.target === trashOverlay) closeTrash(); });

    /* ---------- Backups ---------- */
    const backupsOverlay = $('#backupsOverlay');
    async function loadBackups() {
        const list = $('#backupsList');
        list.innerHTML = '<p class="text-sm text-slate-500">Lade…</p>';
        const res = await api('backups_list');
        if (!res.success) { list.innerHTML = `<p class="text-sm text-rose-300">${escapeHtml(res.message || 'Fehler')}</p>`; return; }
        const items = res.backups || [];
        if (!items.length) {
            list.innerHTML = '<p class="text-sm text-slate-500">Noch keine Backups. Das erste entsteht bei der nächsten Änderung.</p>';
            return;
        }
        list.innerHTML = items.map(b => `
            <div class="flex items-center gap-2 px-2.5 py-2 rounded-lg bg-slate-800/50 border border-slate-700/40">
                <div class="min-w-0 flex-1">
                    <div class="text-sm text-slate-200 font-medium truncate">${escapeHtml(fmtDate(b.time))} Uhr</div>
                    <div class="text-[11px] text-slate-500 truncate">${escapeHtml(b.label)} · ${b.count} Einträge</div>
                </div>
                <button type="button" class="btn btn-secondary !py-2 !px-2.5 !text-xs shrink-0" data-backup="${escapeHtml(b.name)}" data-when="${escapeHtml(fmtDate(b.time))}">Zurückholen</button>
            </div>`).join('');
    }
    $('#backupsList').addEventListener('click', async e => {
        const btn = e.target.closest('[data-backup]');
        if (!btn) return;
        if (!await confirmDialog({ title: 'Stand zurückholen?', text: `Stand vom ${btn.dataset.when} Uhr. Der jetzige Stand wird vorher selbst als Backup gesichert.`, ok: 'Zurückholen' })) return;
        btn.disabled = true;
        const r = await api('backup_restore', { name: btn.dataset.backup });
        btn.disabled = false;
        if (applyRes(r, 'Wiederhergestellt')) closeBackups();
    });
    $('#btnFullBackup').addEventListener('click', () => download('export_full'));
    $('#backupImportBtn').addEventListener('click', async () => {
        const file = $('#backupFile').files[0];
        const pass = $('#backupPass').value;
        const mode = $('#backupMode').value;
        if (!file) { showToast('Erst eine .lvbak-Datei wählen', 'error'); return; }
        if (!pass) { showToast('Passwort des Backups eingeben', 'error'); return; }
        if (mode === 'replace' && !await confirmDialog({ title: 'Alles ersetzen?', text: 'Deine jetzigen Links werden durch das Backup ersetzt. Der jetzige Stand wird vorher gesichert.', ok: 'Ersetzen', danger: true })) return;
        const btn = $('#backupImportBtn');
        btn.disabled = true;
        const res = await api('backup_import', { backup_password: pass, mode }, { backup_file: file });
        btn.disabled = false;
        if (applyRes(res)) { $('#backupPass').value = ''; $('#backupFile').value = ''; closeBackups(); }
    });
    function closeBackups() { hideOverlay(backupsOverlay); }
    $('#btnBackups').addEventListener('click', () => { showOverlay(backupsOverlay); loadBackups(); });
    $('#backupsClose').addEventListener('click', closeBackups);
    backupsOverlay.addEventListener('click', e => { if (e.target === backupsOverlay) closeBackups(); });

    /* ---------- Schnell-Speichern-Knopf (Bookmarklet) ---------- */
    const bookmarkletOverlay = $('#bookmarkletOverlay');
    const bookmarkletCode = "javascript:(function(){window.open('" + (location.origin + location.pathname).replace(/'/g, '%27')
        + "?add='+encodeURIComponent(location.href)+'&title='+encodeURIComponent(document.title));})();";
    $('#bookmarkletLink').setAttribute('href', bookmarkletCode);
    $('#bookmarkletLink').addEventListener('click', e => {
        e.preventDefault();
        showToast('Nicht klicken, in die Lesezeichenleiste ziehen');
    });
    $('#bookmarkletCopy').addEventListener('click', () => copyText(bookmarkletCode, 'Code kopiert'));
    function closeBookmarklet() { hideOverlay(bookmarkletOverlay); }
    $('#btnBookmarklet').addEventListener('click', () => showOverlay(bookmarkletOverlay));
    $('#bookmarkletClose').addEventListener('click', closeBookmarklet);
    bookmarkletOverlay.addEventListener('click', e => { if (e.target === bookmarkletOverlay) closeBookmarklet(); });

    /* ---------- Konto & Sicherheit ---------- */
    const accountOverlay = $('#accountOverlay');
    let accInfo = null;
    function needPw() {
        const pw = $('#accCurrent').value;
        if (!pw) { showToast('Oben erst das aktuelle Passwort eingeben', 'error'); $('#accCurrent').focus(); }
        return pw;
    }
    async function loadAccount() {
        const res = await api('account_info');
        if (!res.success) { showToast(res.message || 'Fehler', 'error'); return; }
        accInfo = res;
        $('#accUser').placeholder = `leer = unverändert (${res.username})`;
        $('#accIdle').value = String(res.idle_minutes);
        $('#totpStatus').innerHTML = res.totp
            ? '<span class="ok-text">Aktiv.</span> Beim Anmelden wird zusätzlich ein Code aus deiner App verlangt.'
            : 'Nicht aktiv. Mit 2FA braucht ein Angreifer außer dem Passwort auch dein Handy.';
        $('#totpStart').classList.toggle('hidden', !!res.totp);
        $('#totpOff').classList.toggle('hidden', !res.totp);
        $('#totpSetup').classList.add('hidden');
        $('#recStatus').innerHTML = res.recovery
            ? '<span class="ok-text">Ein Code ist hinterlegt.</span> Damit kommst du wieder rein, wenn du das Passwort vergisst oder das Handy mit der 2FA-App weg ist.'
            : '<span class="warn-text">Noch kein Code.</span> Ohne ihn sind deine Links bei vergessenem Passwort für immer verloren, das ist der Preis der Verschlüsselung.';
    }
    function closeAccount() {
        hideOverlay(accountOverlay);
        $('#accountForm').reset();
        $('#recCode').classList.add('hidden'); $('#recCode').textContent = '';
        $('#recCopy').classList.add('hidden');
        $('#totpSetup').classList.add('hidden'); $('#totpSecret').textContent = '';
    }
    $('#btnAccount').addEventListener('click', () => { showOverlay(accountOverlay); loadAccount(); });
    $('#accountClose').addEventListener('click', closeAccount);
    accountOverlay.addEventListener('click', e => { if (e.target === accountOverlay) closeAccount(); });
    $('#accountForm').addEventListener('submit', async e => {
        e.preventDefault();
        const current_password = needPw();
        if (!current_password) return;
        const new_username = $('#accUser').value.trim();
        const new_password = $('#accNew').value;
        const new_password2 = $('#accNew2').value;
        if (new_password && new_password.length < 12) { showToast('Neues Passwort: mind. 12 Zeichen', 'error'); return; }
        if (new_password && new_password !== new_password2) { showToast('Neue Passwörter stimmen nicht überein', 'error'); return; }
        if (!new_username && !new_password) { showToast('Nichts zu ändern', 'error'); return; }
        const res = await api('change_password', { current_password, new_username, new_password, new_password2 });
        if (res.success) { closeAccount(); showToast(res.message || 'Gespeichert'); }
        else showToast(res.message || 'Fehler', 'error');
    });
    $('#totpStart').addEventListener('click', async () => {
        const res = await api('totp_begin');
        if (!res.success) { showToast(res.message || 'Fehler', 'error'); return; }
        $('#totpSecret').textContent = res.secret.replace(/(.{4})/g, '$1 ').trim();
        $('#totpSecret').dataset.raw = res.secret;
        $('#totpLink').setAttribute('href', res.uri);
        $('#totpCode').value = '';
        $('#totpSetup').classList.remove('hidden');
    });
    $('#totpCopy').addEventListener('click', () => copyText($('#totpSecret').dataset.raw || '', 'Schlüssel kopiert'));
    $('#totpEnable').addEventListener('click', async () => {
        const current_password = needPw();
        if (!current_password) return;
        const res = await api('totp_enable', { current_password, code: $('#totpCode').value });
        if (res.success) {
            showToast(res.message);
            await loadAccount();
            if (accInfo && !accInfo.recovery) showToast('Tipp: jetzt gleich einen Wiederherstellungscode erzeugen', 'success');
        } else showToast(res.message || 'Fehler', 'error');
    });
    $('#totpOff').addEventListener('click', async () => {
        const current_password = needPw();
        if (!current_password) return;
        if (!await confirmDialog({ title: '2FA abschalten?', text: 'Danach reicht wieder das Passwort allein.', ok: 'Abschalten', danger: true })) return;
        const res = await api('totp_disable', { current_password });
        if (res.success) { showToast(res.message); loadAccount(); } else showToast(res.message || 'Fehler', 'error');
    });
    $('#recCreate').addEventListener('click', async () => {
        const current_password = needPw();
        if (!current_password) return;
        if (accInfo && accInfo.recovery && !await confirmDialog({ title: 'Neuen Code erzeugen?', text: 'Der bisherige Wiederherstellungscode wird damit ungültig.', ok: 'Neuen Code erzeugen' })) return;
        const res = await api('recovery_create', { current_password });
        if (!res.success) { showToast(res.message || 'Fehler', 'error'); return; }
        $('#recCode').textContent = res.code;
        $('#recCode').classList.remove('hidden');
        $('#recCopy').classList.remove('hidden');
        $('#recStatus').innerHTML = '<span class="warn-text">Jetzt aufschreiben oder im Passwort-Manager ablegen.</span> Der Code wird nur dieses eine Mal angezeigt und liegt nirgends im Klartext.';
        if (accInfo) accInfo.recovery = true;
    });
    $('#recCopy').addEventListener('click', () => copyText($('#recCode').textContent, 'Code kopiert'));
    $('#accIdle').addEventListener('change', async e => {
        const res = await api('settings_save', { idle_minutes: e.target.value });
        showToast(res.message || (res.success ? 'Gespeichert' : 'Fehler'), res.success ? 'success' : 'error');
    });

    /* ---------- Anmeldeversuche ---------- */
    const logOverlay = $('#logOverlay');
    const LOG_KIND = {
        ok: ['Erfolgreich angemeldet', 'ok'],
        fail: ['Name oder Passwort falsch', ''],
        totp: ['Passwort richtig, 2FA-Code falsch', ''],
        recover: ['Wiederherstellungscode falsch', ''],
        locked: ['Versuch während einer Sperre', 'mid']
    };
    async function loadLog(clear) {
        const list = $('#logList');
        list.innerHTML = '<p class="text-sm text-slate-500">Lade…</p>';
        const res = await api('login_log', clear ? { clear: '1' } : {});
        if (!res.success) { list.innerHTML = `<p class="text-sm text-rose-300">${escapeHtml(res.message || 'Fehler')}</p>`; return; }
        const entries = res.entries || [];
        const now = Date.now() / 1000;
        const fails = entries.filter(r => r.k !== 'ok');
        const f24 = fails.filter(r => r.t > now - 86400).length;
        const f7 = fails.filter(r => r.t > now - 7 * 86400).length;
        const ips = new Set(fails.map(r => r.ip).filter(Boolean)).size;
        $('#logSummary').innerHTML = `<h4>${fails.length ? `<span class="${f24 ? 'bad-text' : 'warn-text'}">${fails.length} Fehlversuch(e) im Protokoll</span>` : '<span class="ok-text">Keine Fehlversuche</span>'}</h4>
            <p style="margin:0">Letzte 24 Stunden: ${f24} · letzte 7 Tage: ${f7}${ips ? ` · von ${ips} Adresse(n)` : ''}.
            ${res.details ? '' : '<br>Dein Server hat die PHP-Erweiterung „sodium“ nicht, deshalb werden nur Zeit und Art notiert.'}
            <br>Viele Versuche von fremden Adressen? Dann lohnt sich zusätzlich der Ordnerschutz deines Hosters oder 2FA.</p>`;
        list.innerHTML = entries.length ? entries.map(r => {
            const [label, cls] = LOG_KIND[r.k] || ['Unbekannt', 'mid'];
            return `<div class="list-row"><span class="dot ${cls}"></span><div class="grow">
                <div class="t1">${escapeHtml(label)}${r.u && r.k !== 'ok' ? ` als „${escapeHtml(r.u)}“` : ''}</div>
                <div class="t2">${escapeHtml(fmtDate(r.t))} Uhr${r.ip ? ' · ' + escapeHtml(r.ip) : ''}</div></div></div>`;
        }).join('') : '<p class="text-sm text-slate-500">Noch nichts protokolliert.</p>';
    }
    function closeLog() { hideOverlay(logOverlay); }
    $('#btnLoginLog').addEventListener('click', () => { showOverlay(logOverlay); loadLog(false); });
    $('#logClose').addEventListener('click', closeLog);
    $('#logDone').addEventListener('click', closeLog);
    $('#logClear').addEventListener('click', async () => {
        if (await confirmDialog({ title: 'Liste leeren?', text: 'Alle protokollierten Anmeldeversuche werden gelöscht.', ok: 'Leeren', danger: true })) loadLog(true);
    });
    logOverlay.addEventListener('click', e => { if (e.target === logOverlay) closeLog(); });

    /* ---------- Benutzer verwalten (nur Administrator) ---------- */
    const usersOverlay = $('#usersOverlay');
    // Zähler am Menü und Punkt am Werkzeug-Knopf: Es warten Zugangsanfragen
    function syncPending(n, announce) {
        const grew = n > pendingCount;
        pendingCount = n;
        const badge = $('#usersBadge');
        if (badge) { badge.textContent = n; badge.classList.toggle('hidden', n === 0); }
        $('#btnTools').classList.toggle('has-note', LV_ADMIN && n > 0);
        if (announce && grew && LV_ADMIN && usersOverlay.classList.contains('hidden')) {
            showToast('Eine neue Zugangsanfrage wartet auf dich', 'success', { label: 'Ansehen', fn: openUsers });
        }
    }
    function paintUsers(res) {
        const users = res.users || [];
        const waiting = users.filter(u => u.status === 'pending');
        const rest = users.filter(u => u.status !== 'pending');
        $('#usersPendingBox').classList.toggle('hidden', !waiting.length);
        $('#usersPending').innerHTML = waiting.map(u => `
            <div class="list-row" data-uid="${escapeHtml(u.uid)}" data-name="${escapeHtml(u.username)}">
                <span class="dot mid"></span>
                <div class="grow">
                    <div class="t1">${escapeHtml(u.username)}</div>
                    <div class="t2">angefragt am ${escapeHtml(fmtDate(u.created))} Uhr</div>
                    ${u.ip ? `<div class="t2">von ${escapeHtml(u.ip)}</div>` : ''}
                    ${u.note ? `<div class="user-note">„${escapeHtml(u.note)}“</div>` : ''}
                </div>
                <button type="button" class="btn btn-primary !py-2 !px-2.5 !text-xs shrink-0" data-uact="approve">Freigeben</button>
                <button type="button" class="card-btn card-btn-icon danger" data-uact="reject" title="Ablehnen" aria-label="Ablehnen">${SVG.trash}</button>
            </div>`).join('');
        const adminRow = `
            <div class="list-row">
                <span class="dot ok"></span>
                <div class="grow">
                    <div class="t1">${escapeHtml(res.admin || LV_USER)}</div>
                    <div class="t2">Administrator, das bist du</div>
                </div>
            </div>`;
        $('#usersList').innerHTML = adminRow + rest.map(u => {
            const blocked = u.status === 'blocked';
            const info = blocked ? 'gesperrt' : `dabei seit ${u.approved ? escapeHtml(fmtDate(u.approved)) + ' Uhr' : 'unbekannt'}${u.totp ? ' · 2FA aktiv' : ''}`;
            return `
            <div class="list-row" data-uid="${escapeHtml(u.uid)}" data-name="${escapeHtml(u.username)}">
                <span class="dot ${blocked ? '' : 'ok'}"></span>
                <div class="grow">
                    <div class="t1">${escapeHtml(u.username)}</div>
                    <div class="t2">${info}</div>
                </div>
                <button type="button" class="btn btn-secondary !py-2 !px-2.5 !text-xs shrink-0" data-uact="${blocked ? 'unblock' : 'block'}">${blocked ? 'Entsperren' : 'Sperren'}</button>
                <button type="button" class="card-btn card-btn-icon danger" data-uact="delete" title="Benutzer löschen" aria-label="Benutzer löschen">${SVG.trash}</button>
            </div>`;
        }).join('');
        paintRegToggle(!!res.allow_register);
    }
    function paintRegToggle(open) {
        const t = $('#regToggle');
        t.classList.toggle('on', open);
        t.setAttribute('aria-checked', open ? 'true' : 'false');
        $('#regToggleLabel').textContent = open ? 'Anfragen sind möglich' : 'Anfragen sind abgeschaltet';
    }
    async function loadUsers() {
        const res = await api('users_list');
        if (!res.success) {
            $('#usersList').innerHTML = `<p class="text-sm text-rose-300">${escapeHtml(res.message || 'Fehler')}</p>`;
            return;
        }
        paintUsers(res);
    }
    function openUsers() {
        $('#usersList').innerHTML = '<p class="text-sm text-slate-500">Lade…</p>';
        showOverlay(usersOverlay);
        loadUsers();
    }
    function closeUsers() { hideOverlay(usersOverlay); }
    if ($('#btnUsers')) $('#btnUsers').addEventListener('click', openUsers);
    $('#usersClose').addEventListener('click', closeUsers);
    usersOverlay.addEventListener('click', async e => {
        if (e.target === usersOverlay) { closeUsers(); return; }
        const btn = e.target.closest('[data-uact]');
        const row = btn && btn.closest('[data-uid]');
        if (!row) return;
        const uid = row.dataset.uid, name = row.dataset.name, act = btn.dataset.uact;
        const data = { uid };
        if (act === 'reject') {
            if (!await confirmDialog({ title: 'Anfrage ablehnen?', text: `Die Anfrage von „${name}“ wird gelöscht.`, ok: 'Ablehnen', danger: true })) return;
        } else if (act === 'block') {
            if (!await confirmDialog({ title: `„${name}“ sperren?`, text: 'Der Benutzer wird sofort überall abgemeldet und kommt nicht mehr rein. Seine Links bleiben erhalten, du kannst die Sperre jederzeit aufheben.', ok: 'Sperren', danger: true })) return;
        } else if (act === 'delete') {
            const pw = await askPassword({
                title: `„${name}“ löschen?`,
                text: 'Das Konto wird mit allen Links und Backups dieses Benutzers endgültig gelöscht. Das lässt sich nicht zurückholen. Zur Bestätigung dein eigenes Passwort:',
                ok: 'Endgültig löschen'
            });
            if (!pw) return;
            data.current_password = pw;
        }
        btn.disabled = true;
        const res = await api('user_' + act, data);
        btn.disabled = false;
        if (res.success) { showToast(res.message || 'Erledigt'); paintUsers(res); }
        else { showToast(res.message || 'Fehler', 'error'); loadUsers(); }
    });
    $('#regToggle').addEventListener('click', async () => {
        const open = !$('#regToggle').classList.contains('on');
        const res = await api('register_toggle', { open: open ? '1' : '0' });
        if (res.success) { paintRegToggle(!!res.allow_register); showToast(res.message || 'Gespeichert'); }
        else showToast(res.message || 'Fehler', 'error');
    });

    $('#btnReload').addEventListener('click', () => location.reload());

    /* ---------- App (PWA) ---------- */
    const isStandalone = (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) || window.navigator.standalone === true;
    if ('serviceWorker' in navigator && (location.protocol === 'https:' || ['localhost', '127.0.0.1'].includes(location.hostname))) {
        navigator.serviceWorker.register('./?action=sw', { scope: './' }).catch(() => {});
    }
    let installEvent = null;
    window.addEventListener('beforeinstallprompt', e => {
        e.preventDefault();
        installEvent = e;
        $('#installBtn').classList.remove('hidden');
    });
    $('#installBtn').addEventListener('click', async () => {
        if (!installEvent) return;
        installEvent.prompt();
        try { await installEvent.userChoice; } catch (_) {}
        installEvent = null;
        $('#installBtn').classList.add('hidden');
    });
    window.addEventListener('appinstalled', () => { $('#installBtn').classList.add('hidden'); showToast('LinkVault ist jetzt als App installiert'); });
    if (isStandalone) $('#installHint').textContent = 'LinkVault läuft gerade als App. Unter Android findest du es jetzt auch beim Teilen einer Seite in der Liste.';

    $('#btnLogout').addEventListener('click', async () => {
        const res = await api('logout', {});
        if (res.success) location.reload();
        else showToast(res.message || 'Abmelden fehlgeschlagen', 'error');
    });

    // Titel (und auf Knopfdruck Beschreibung) von der Seite holen
    let autoTitle = '';
    let fetchRun = 0;
    function resetFetch() {
        autoTitle = '';
        fetchRun++;
        const h = $('#formFetchHint');
        h.textContent = '';
        h.classList.add('hidden');
    }
    async function fetchTitle(manual) {
        const url = $('#formUrl').value.trim();
        const hint = $('#formFetchHint');
        if (!url) { if (manual) showToast('Erst eine URL eingeben', 'error'); return; }
        const titleEl = $('#formTitle');
        const cur = titleEl.value.trim();
        // Automatisch nur, wenn noch kein eigener Titel drinsteht
        if (!manual && cur !== '' && cur !== autoTitle) return;
        const run = ++fetchRun;
        hint.textContent = 'Hole Titel von der Seite…';
        hint.classList.remove('hidden');
        const res = await api('fetch_title', { url });
        if (run !== fetchRun) return;
        if (res.success && res.title) {
            const now = titleEl.value.trim();
            if (manual || now === '' || now === autoTitle) { titleEl.value = res.title; autoTitle = res.title; }
            if (manual && res.description && !$('#formDescription').value.trim()) $('#formDescription').value = res.description;
            hint.textContent = '';
            hint.classList.add('hidden');
        } else if (manual) {
            hint.textContent = res.message || 'Titel konnte nicht geholt werden.';
        } else {
            hint.textContent = '';
            hint.classList.add('hidden');
        }
    }
    $('#formFetchTitle').addEventListener('click', () => fetchTitle(true));
    $('#formUrl').addEventListener('change', () => { if (!editingId) fetchTitle(false); });

    /* ---------- Tastatur ---------- */
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') {
            if (kbHelp(false)) return;
            if (!confirmOverlay.classList.contains('hidden')) { closeConfirm(false); return; }
            if (!dialogOverlay.classList.contains('hidden')) { closeDialog(); return; }
            // Regeln liegen über „Automatisch sortieren“: erst nur dieses Fenster schließen
            if (!rulesOverlay.classList.contains('hidden')) { closeRules(); return; }
            if (anyOverlayOpen()) {
                closeModal(); closeImport(); closeMove(); closeDead(); closeFolders(); closeBackups(); closeAuto(); closeTags();
                closeBookmarklet(); closeAccount(); closeTrash(); closeLog(); closeUsers();
                return;
            }
            closeMenus();
            if (selectMode) toggleSelectMode(false);
            else if (searchQuery) setSearch('');
            return;
        }
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); searchInput.focus(); searchInput.select(); return; }
        const t = e.target;
        const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
        if (typing || e.metaKey || e.ctrlKey || e.altKey || anyOverlayOpen()) return;
        if (e.key === '/' || e.key === 's') { e.preventDefault(); searchInput.focus(); searchInput.select(); }
        else if (e.key === 'h') { e.preventDefault(); kbHelp(); }
        else if (e.key === 'n') { e.preventDefault(); openAddModal(); }
        else if (e.key === 'v') {
            viewMode = { cards: 'list', list: 'tiles', tiles: 'cards' }[viewMode];
            store.set('lv_view', viewMode);
            render();
            showToast('Ansicht: ' + { cards: 'Karten', list: 'Liste', tiles: 'Kacheln' }[viewMode]);
        }
        else cardKeys(e);
    });

    /* ---------- Tastatur an den Einträgen (Desktop) ----------
       Normal: Maus über einem Eintrag, dann Entf = löschen, F = Favorit, C = URL kopieren, E = bearbeiten.
       Mehrfachauswahl: Pfeiltasten wandern, Leertaste markiert, Umschalt+Pfeil markiert mit,
       A = alle angezeigten, Entf = markierte löschen. */
    // Hilfe mit allen Tastenkürzeln: H blendet sie ein, nach 10 Sekunden (oder H, Esc, Klick) ist sie wieder weg.
    // Rückgabe: true, wenn dabei eine offene Hilfe geschlossen wurde.
    let kbHelpEl = null, kbHelpTimer = 0;
    function kbHelp(show) {
        const open = !!kbHelpEl;
        if (open) { clearTimeout(kbHelpTimer); kbHelpEl.remove(); kbHelpEl = null; }
        if (show === false || (show === undefined && open)) return open;
        const row = (keys, text) => `<div class="kb-help-row"><span class="kb-help-keys">${keys.map(k => `<kbd>${k}</kbd>`).join('')}</span><span>${text}</span></div>`;
        kbHelpEl = document.createElement('div');
        kbHelpEl.className = 'kb-help';
        kbHelpEl.setAttribute('role', 'dialog');
        kbHelpEl.innerHTML = `
            <div class="kb-help-title">Tastenkürzel</div>
            <div class="kb-help-cols">
                <div>
                    <div class="kb-help-head">Überall</div>
                    ${row(['S'], 'Suchen')}
                    ${row(['N'], 'Neuen Link anlegen')}
                    ${row(['V'], 'Ansicht wechseln')}
                    ${row(['H'], 'Diese Hilfe')}
                    ${row(['Esc'], 'Schließen, Suche leeren')}
                    <div class="kb-help-head">Eintrag unter Maus oder Rahmen</div>
                    ${row(['↑', '↓', '←', '→'], 'Eintrag wechseln')}
                    ${row(['Leertaste'], 'Seite öffnen')}
                    ${row(['F'], 'Favorit')}
                    ${row(['C'], 'URL kopieren')}
                    ${row(['E'], 'Bearbeiten')}
                    ${row(['Entf'], 'Löschen')}
                </div>
                <div>
                    <div class="kb-help-head">Mehrfachauswahl</div>
                    ${row(['↑', '↓', '←', '→'], 'Eintrag wechseln')}
                    ${row(['Leertaste'], 'Markieren an/aus')}
                    ${row(['⇧', '↑↓'], 'Beim Wandern markieren')}
                    ${row(['A'], 'Alle angezeigten markieren')}
                    ${row(['Entf'], 'Markierte löschen')}
                </div>
            </div>
            <div class="kb-help-bar"></div>`;
        kbHelpEl.addEventListener('click', () => kbHelp(false));
        document.body.appendChild(kbHelpEl);
        kbHelpTimer = setTimeout(() => kbHelp(false), 10000);
        return open;
    }
    document.addEventListener('mousedown', e => { if (kbHelpEl && !kbHelpEl.contains(e.target)) kbHelp(false); });

    function kbSetCursor(card) {
        mainEl.querySelectorAll('.bookmark-card.kb-cursor').forEach(c => c.classList.remove('kb-cursor'));
        kbCursor = card ? { el: card, id: card.dataset.id } : null;
        if (!card) return;
        card.classList.add('kb-cursor');
        // In den sichtbaren Bereich holen, ohne unter Kopfzeile oder Sammel-Leiste zu rutschen
        const r = card.getBoundingClientRect();
        const head = document.getElementById('appHeader');
        const top = (head ? head.offsetHeight : 0) + 10;
        const bottom = window.innerHeight - ($('#bulkBar').offsetHeight || 0) - 10;
        if (r.top < top) window.scrollBy(0, r.top - top);
        else if (r.bottom > bottom) window.scrollBy(0, r.bottom - bottom);
    }
    function kbMove(cards, cur, key) {
        const i = cards.indexOf(cur);
        if (key === 'ArrowLeft') return cards[i - 1] || cur;
        if (key === 'ArrowRight') return cards[i + 1] || cur;
        // Hoch/Runter: nächste Reihe, dort der Eintrag, der am ehesten drüber bzw. drunter liegt
        const down = key === 'ArrowDown';
        const c = cur.getBoundingClientRect();
        let best = null, bestRow = Infinity, bestDx = Infinity;
        cards.forEach(el => {
            const r = el.getBoundingClientRect();
            const row = down ? r.top - c.top : c.top - r.top;
            if (row < 4) return;
            const dx = Math.abs((r.left + r.width / 2) - (c.left + c.width / 2));
            if (row < bestRow - 4 || (Math.abs(row - bestRow) <= 4 && dx < bestDx)) { best = el; bestRow = row; bestDx = dx; }
        });
        return best || cur;
    }
    function cardKeys(e) {
        const key = e.key.length === 1 ? e.key.toLowerCase() : e.key;
        const arrow = ['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(key);
        if (!selectMode) {
            if (!arrow && ![' ', 'Delete', 'f', 'c', 'e'].includes(key)) return;
            const cards = Array.from(mainEl.querySelectorAll('.bookmark-card')).filter(c => c.offsetParent !== null);
            const cur = kbCursor && (cards.includes(kbCursor.el) ? kbCursor.el : cards.find(c => c.dataset.id === kbCursor.id));
            if (arrow) {
                if (!cards.length) return;
                e.preventDefault();
                if (cur) { kbSetCursor(kbMove(cards, cur, key)); return; }
                // Start: der Eintrag unter der Maus, sonst der erste
                const start = mainEl.querySelector('.bookmark-card:hover');
                kbSetCursor(start && cards.includes(start) ? start : cards[0]);
                return;
            }
            // Der Rahmen der Pfeiltasten geht vor, sonst zählt der Eintrag unter der Maus.
            // Die Leertaste öffnet nur den Eintrag im Rahmen, sonst blättert sie wie gewohnt.
            const card = cur || (key !== ' ' && mainEl.querySelector('.bookmark-card:hover'));
            const bm = card && byId(card.dataset.id);
            if (!bm) return;
            e.preventDefault();
            if (e.repeat) return;
            if (key === ' ') {
                if (document.activeElement && document.activeElement !== document.body) document.activeElement.blur();
                openLink(bm);
            }
            else if (key === 'Delete') {
                // Rahmen vorher auf den Nachbarn setzen, damit man nach dem Löschen dort weitermacht
                if (cur) { const i = cards.indexOf(cur); kbSetCursor(cards[i + 1] || cards[i - 1] || null); }
                deleteIds([bm.id]);
            }
            else if (key === 'f') toggleFavorite(bm.id);
            else if (key === 'c') copyText(bm.url, 'URL kopiert');
            else openEditModal(bm);
            return;
        }
        if (!arrow && key !== ' ' && key !== 'a' && key !== 'Delete') return;
        e.preventDefault();
        // Ein noch fokussierter Knopf würde die Leertaste sonst als Klick werten
        if (document.activeElement && document.activeElement !== document.body) document.activeElement.blur();
        if (key === 'Delete') { if (!e.repeat) askDeleteBulk(); return; }
        if (key === 'a') { if (!e.repeat) $('#bulkSelectAll').click(); return; }
        const cards = Array.from(mainEl.querySelectorAll('.bookmark-card')).filter(c => c.offsetParent !== null);
        if (!cards.length) return;
        let cur = kbCursor && (cards.includes(kbCursor.el) ? kbCursor.el : cards.find(c => c.dataset.id === kbCursor.id));
        if (!cur) {
            // Start: der Eintrag unter der Maus, sonst der erste
            cur = mainEl.querySelector('.bookmark-card:hover');
            if (!cur || !cards.includes(cur)) cur = cards[0];
            kbSetCursor(cur);
            if (arrow && !e.shiftKey) return;
        }
        if (key === ' ') { if (!e.repeat) toggleSelect(cur.dataset.id, false); kbSetCursor(cur); return; }
        const next = kbMove(cards, cur, key);
        if (e.shiftKey) {
            selected.add(cur.dataset.id); selected.add(next.dataset.id);
            lastSelected = next.dataset.id;
            paintSelection();
        }
        kbSetCursor(next);
    }
    // Ausserhalb der Mehrfachauswahl übernimmt die Maus wieder, sobald sie wirklich bewegt wird
    let kbMouse = '';
    document.addEventListener('mousemove', e => {
        const pos = e.screenX + ',' + e.screenY;
        if (pos === kbMouse) return;
        kbMouse = pos;
        if (!selectMode && kbCursor) kbSetCursor(null);
    });
    // Klick in der Mehrfachauswahl setzt den Tastatur-Rahmen auf den angeklickten Eintrag
    mainEl.addEventListener('click', e => {
        const card = selectMode && e.target.closest('.bookmark-card');
        if (card) kbSetCursor(card);
    });

    // Keep content below fixed header
    function syncHeaderSpacer() {
        const h = document.getElementById('appHeader');
        const s = document.getElementById('headerSpacer');
        if (h && s) s.style.height = h.offsetHeight + 'px';
    }
    window.syncHeaderSpacer = syncHeaderSpacer;
    window.addEventListener('resize', syncHeaderSpacer);
    requestAnimationFrame(syncHeaderSpacer);
    setTimeout(syncHeaderSpacer, 120);
    setTimeout(syncHeaderSpacer, 500);

    // Kategorieleiste: Mausrad horizontal, Drag-to-Scroll mit Nachlauf (Momentum)
    [categoryBar, tagBar].forEach(function setupCategoryScroll(bar) {
        if (!bar) return;
        bar.addEventListener('wheel', e => {
            if (Math.abs(e.deltaY) > Math.abs(e.deltaX) && bar.scrollWidth > bar.clientWidth) {
                e.preventDefault();
                bar.scrollLeft += e.deltaY;
            }
        }, { passive: false });

        let dragging = false, startX = 0, startScroll = 0, moved = false;
        let lastX = 0, lastT = 0, velocity = 0; // px pro ms
        let momentumId = 0;

        const stopMomentum = () => {
            if (momentumId) { cancelAnimationFrame(momentumId); momentumId = 0; }
        };

        const runMomentum = () => {
            stopMomentum();
            // Zu langsam → kein Nachlauf
            if (Math.abs(velocity) < 0.05) { velocity = 0; return; }
            const friction = 0.95; // je näher an 1, desto länger der Nachlauf
            const step = () => {
                velocity *= friction;
                if (Math.abs(velocity) < 0.04) {
                    velocity = 0;
                    momentumId = 0;
                    return;
                }
                const max = bar.scrollWidth - bar.clientWidth;
                bar.scrollLeft = Math.max(0, Math.min(max, bar.scrollLeft - velocity * 16));
                // Am Rand abfangen
                if (bar.scrollLeft <= 0 || bar.scrollLeft >= max - 0.5) {
                    velocity = 0;
                    momentumId = 0;
                    return;
                }
                momentumId = requestAnimationFrame(step);
            };
            momentumId = requestAnimationFrame(step);
        };

        const onDown = e => {
            if (e.button != null && e.button !== 0) return;
            stopMomentum();
            dragging = true; moved = false;
            velocity = 0;
            startX = e.pageX ?? (e.touches && e.touches[0].pageX) ?? 0;
            lastX = startX;
            lastT = performance.now();
            startScroll = bar.scrollLeft;
            bar.style.scrollBehavior = 'auto';
        };
        const onMove = e => {
            if (!dragging) return;
            const x = e.pageX ?? (e.touches && e.touches[0].pageX) ?? 0;
            const now = performance.now();
            const dx = x - startX;
            if (Math.abs(dx) > 4) moved = true;
            bar.scrollLeft = startScroll - dx;
            // Geschwindigkeit aus den letzten Bewegungen
            const dt = now - lastT;
            if (dt > 0) {
                const v = (x - lastX) / dt; // positiv = Finger nach rechts
                // glätten
                velocity = velocity * 0.6 + v * 0.4;
            }
            lastX = x;
            lastT = now;
            if (e.cancelable) e.preventDefault();
        };
        const onUp = () => {
            if (!dragging) return;
            dragging = false;
            bar.style.scrollBehavior = '';
            // Wenn die letzte Bewegung schon etwas her ist, Velocity dämpfen
            if (performance.now() - lastT > 80) velocity = 0;
            runMomentum();
        };
        bar.addEventListener('mousedown', onDown);
        window.addEventListener('mousemove', onMove);
        window.addEventListener('mouseup', onUp);
        bar.addEventListener('touchstart', onDown, { passive: true });
        bar.addEventListener('touchmove', onMove, { passive: false });
        bar.addEventListener('touchend', onUp);
        bar.addEventListener('touchcancel', onUp);
        // Klicks auf Buttons nicht auslösen, wenn gerade gescrollt wurde
        bar.addEventListener('click', e => {
            if (moved) { e.preventDefault(); e.stopPropagation(); moved = false; }
        }, true);
    });

    // Zweites Gerät hat etwas geändert? Beim Zurückkommen auf die Seite still nachladen
    document.addEventListener('visibilitychange', async () => {
        if (document.visibilityState !== 'visible' || Date.now() - lastSync < 60000) return;
        if (anyOverlayOpen() || selectMode) return;
        const res = await api('list');
        if (res.success && Array.isArray(res.bookmarks) && JSON.stringify(res.bookmarks) !== JSON.stringify(bookmarks)) {
            bookmarks = res.bookmarks;
            render();
        }
    });

    render();
    syncHeaderSpacer();

    if (LV_CORRUPT) {
        showToast('bookmarks.json ist beschädigt und wird nicht überschrieben. Unter Werkzeuge → Backups kannst du einen Stand zurückholen.', 'error');
    }

    // Administrator: Wartet jemand auf Freigabe? Pro Sitzung nur einmal melden, der Punkt am Werkzeug-Knopf bleibt.
    syncPending(pendingCount, false);
    if (LV_ADMIN && pendingCount > 0) {
        const sig = pendingCount + '|' + LV_PENDING_NAMES.join('|');
        let seen = '';
        try { seen = sessionStorage.getItem('lv_pending_seen') || ''; } catch (_) {}
        if (seen !== sig) {
            try { sessionStorage.setItem('lv_pending_seen', sig); } catch (_) {}
            const one = pendingCount === 1;
            const names = LV_PENDING_NAMES.map(n => `„${escapeHtml(n)}“`).join(', ') + (pendingCount > LV_PENDING_NAMES.length ? ' und weitere' : '');
            showDialog({
                title: one ? 'Neue Zugangsanfrage' : `${pendingCount} neue Zugangsanfragen`,
                html: `<p>${names} ${one ? 'möchte' : 'möchten'} LinkVault mitbenutzen und ${one ? 'wartet' : 'warten'} auf deine Freigabe. Ohne dein Okay kommt niemand rein.</p>`,
                buttons: [{ label: 'Später' }, { label: 'Ansehen', primary: true, fn: openUsers }]
            });
        }
    }

    // Administrator: Ist der Ordner data/ von außen abrufbar? Dann fehlt die Sperre im Webserver (Nginx, oder Apache ohne AllowOverride).
    // Geprüft wird eine harmlose Datei ohne Geheimnisse, höchstens einmal pro Browser-Sitzung, solange alles in Ordnung ist.
    if (LV_ADMIN) (async () => {
        try { if (sessionStorage.getItem('lv_data_ok') === '1') return; } catch (_) {}
        let open = false;
        try {
            const r = await fetch('data/nginx-deny.conf', { cache: 'no-store', credentials: 'omit', redirect: 'manual' });
            open = r.ok && (await r.text()).includes('LinkVault');
        } catch (_) { return; }
        if (!open) { try { sessionStorage.setItem('lv_data_ok', '1'); } catch (_) {} return; }
        showDialog({
            title: 'Der Ordner data/ ist nicht geschützt',
            html: '<p>Dein Webserver liefert Dateien aus dem Ordner data/ an jeden aus, der die Adresse kennt. Deine Links sind zwar verschlüsselt, aber dort liegt auch die Datei mit deinem Passwort-Schutz. Das solltest du gleich abstellen.</p>'
                + '<p class="mt-2"><b>Nginx:</b> Den Block aus der Datei data/nginx-deny.conf in die Server-Konfiguration übernehmen und Nginx neu laden.</p>'
                + '<p class="mt-2"><b>Apache:</b> Für diesen Ordner „AllowOverride All“ einschalten, dann greifen die mitgelieferten .htaccess-Dateien.</p>'
                + '<p class="mt-2 text-xs text-slate-400">Die Meldung kommt bei jedem Öffnen, bis der Ordner gesperrt ist. Mehr dazu steht in der README.</p>',
            buttons: [{ label: 'Verstanden', primary: true }]
        });
    })();

    // Direkt nach der Anmeldung: Gab es fremde Anmeldeversuche?
    if (LV_NOTICE && typeof LV_NOTICE === 'object') {
        const n = LV_NOTICE;
        const last = n.last ? `Deine letzte Anmeldung war am ${escapeHtml(fmtDate(n.last))} Uhr${n.last_ip ? ' von ' + escapeHtml(n.last_ip) : ''}.` : '';
        if (n.fails > 0) {
            showDialog({
                title: `${n.fails} fehlgeschlagene${n.fails === 1 ? 'r' : ''} Anmeldeversuch${n.fails === 1 ? '' : 'e'}`,
                html: `<p>Seit deiner letzten Anmeldung hat ${n.fails === 1 ? 'jemand einmal' : `jemand ${n.fails} Mal`} versucht, sich hier anzumelden${n.ips > 0 ? `, von ${n.ips} Adresse${n.ips === 1 ? '' : 'n'}` : ''}. Hast du dich selbst vertippt, ist alles gut.</p>${last ? `<p class="mt-2 text-xs text-slate-400">${last}</p>` : ''}`,
                buttons: [{ label: 'Ansehen', fn: () => { showOverlay(logOverlay); loadLog(false); } }, { label: 'OK', primary: true }]
            });
        } else {
            showToast('Keine Fehlversuche seit deinem letzten Login');
        }
    }

    // Aufruf vom Schnell-Speichern-Knopf (?add=…&title=…) oder vom „Teilen“ am Handy (?url=…&text=…&title=…)
    (() => {
        const params = new URLSearchParams(location.search);
        let add = (params.get('add') || params.get('url') || '').trim();
        const text = (params.get('text') || '').trim();
        if (!add && text) { const m = text.match(/https?:\/\/\S+/i); if (m) add = m[0]; }
        if (!params.has('add') && !params.has('url') && !params.has('text') && !params.has('new')) return;
        history.replaceState(null, '', location.pathname);
        if (params.has('new') && !add) { openAddModal(); return; }
        if (!isWeb(add)) return;
        startAdd(add, (params.get('title') || '').trim());
    })();
})();
</script>
