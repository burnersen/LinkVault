<?php defined('LV_VERSION') || exit; ?>
    <style>
        /* Schrift liegt in dieser Datei und kommt vom eigenen Server, es wird nichts von außen geladen */
        @font-face { font-family: 'Inter'; font-style: normal; font-weight: 100 900; font-display: swap; src: url('?action=font') format('woff2'); }
        *, *::before, *::after { box-sizing: border-box; }
        html {
            width: 100%;
            margin: 0;
            padding: 0;
            /* overflow-x:hidden breaks position:sticky in many browsers – use clip */
            overflow-x: clip;
        }
        body {
            width: 100%;
            max-width: 100%;
            margin: 0;
            padding: 0;
            overflow-x: clip;
            background: linear-gradient(165deg, #0b1120 0%, #0f172a 45%, #1e1b4b 100%);
            min-height: 100vh;
            min-height: 100dvh;
            font-family: 'Inter', system-ui, sans-serif;
            color: #f1f5f9;
        }
        * { -webkit-tap-highlight-color: transparent; }
        ::-webkit-scrollbar { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #475569; border-radius: 3px; }

        .glass {
            background: rgba(30, 41, 59, 0.72);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(51, 65, 85, 0.65);
        }
        .glass-strong {
            background: rgba(15, 23, 42, 0.92);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid rgba(51, 65, 85, 0.55);
        }

        .btn {
            display: inline-flex; align-items: center; justify-content: center; gap: 0.35rem;
            font-weight: 600; font-size: 0.8125rem; line-height: 1;
            border-radius: 0.7rem; transition: all 0.15s ease; cursor: pointer;
            user-select: none; border: none; white-space: nowrap;
        }
        .btn:active { transform: scale(0.96); }
        .btn:disabled { opacity: 0.45; cursor: not-allowed; transform: none; }

        .btn-primary {
            background: linear-gradient(135deg, #8b5cf6, #7c3aed); color: #fff;
            box-shadow: 0 4px 14px -3px rgba(139, 92, 246, 0.45); padding: 0.65rem 1rem;
        }
        .btn-primary:hover:not(:disabled) { background: linear-gradient(135deg, #a78bfa, #8b5cf6); }

        .btn-secondary {
            background: rgba(30, 41, 59, 0.95); color: #e2e8f0;
            border: 1px solid rgba(71, 85, 105, 0.7); padding: 0.65rem 1rem;
        }
        .btn-secondary:hover:not(:disabled) { background: rgba(51, 65, 85, 0.95); color: #fff; }

        .btn-danger {
            background: rgba(127, 29, 29, 0.4); color: #fca5a5;
            border: 1px solid rgba(185, 28, 28, 0.4); padding: 0.65rem 1rem;
        }
        .btn-danger:hover:not(:disabled) { background: rgba(153, 27, 27, 0.55); color: #fecaca; }

        .btn-ghost { background: transparent; color: #94a3b8; padding: 0.5rem; border-radius: 0.6rem; }
        .btn-ghost:hover:not(:disabled) { background: rgba(51, 65, 85, 0.6); color: #f1f5f9; }

        .btn-icon {
            width: 2.35rem; height: 2.35rem; padding: 0; border-radius: 0.7rem;
            background: rgba(30, 41, 59, 0.9); border: 1px solid rgba(71, 85, 105, 0.6);
            color: #cbd5e1; flex-shrink: 0;
        }
        .btn-icon:hover:not(:disabled) { background: rgba(51, 65, 85, 0.95); color: #fff; }
        .btn-icon svg { width: 1.15rem; height: 1.15rem; }
        .btn-icon.active {
            background: rgba(139, 92, 246, 0.25); border-color: rgba(139, 92, 246, 0.45); color: #c4b5fd;
        }

        .card-actions {
            display: flex; flex-wrap: nowrap; align-items: center; gap: 0.25rem;
            margin-top: 0.5rem; padding-top: 0.5rem;
            border-top: 1px solid rgba(51, 65, 85, 0.45);
            min-width: 0;
        }
        .card-btn {
            display: inline-flex; align-items: center; justify-content: center; gap: 0.25rem;
            height: 1.85rem; padding: 0 0.5rem; border-radius: 0.5rem;
            font-size: 0.7rem; font-weight: 600; transition: all 0.15s ease;
            cursor: pointer; border: 1px solid transparent; user-select: none;
            flex-shrink: 0;
        }
        .card-btn:active { transform: scale(0.95); }
        .card-btn-open {
            flex: 1 1 auto; min-width: 0;
            background: linear-gradient(135deg, rgba(139, 92, 246, 0.25), rgba(124, 58, 237, 0.2));
            border-color: rgba(139, 92, 246, 0.35); color: #c4b5fd;
        }
        .card-btn-open:hover {
            background: linear-gradient(135deg, rgba(139, 92, 246, 0.4), rgba(124, 58, 237, 0.35)); color: #e9d5ff;
        }
        .card-btn-open span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .card-btn-icon {
            width: 1.85rem; flex: 0 0 1.85rem; padding: 0;
            background: rgba(30, 41, 59, 0.7); border-color: rgba(71, 85, 105, 0.5); color: #94a3b8;
        }
        .card-btn-icon:hover { background: rgba(51, 65, 85, 0.85); color: #e2e8f0; }
        .card-btn-icon.starred {
            color: #fbbf24; background: rgba(120, 53, 15, 0.25); border-color: rgba(245, 158, 11, 0.3);
        }
        .card-btn-icon.danger:hover {
            background: rgba(127, 29, 29, 0.4); border-color: rgba(185, 28, 28, 0.45); color: #fca5a5;
        }
        .card-btn svg { width: 0.85rem; height: 0.85rem; flex-shrink: 0; }

        .bookmark-card {
            transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease;
            width: 100%; max-width: 100%; min-width: 0;
            padding: 0.65rem 0.75rem !important;
        }
        .bookmark-card:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 16px -6px rgba(0,0,0,0.35);
            border-color: rgba(139, 92, 246, 0.3);
        }
        .bookmark-card.favorite {
            border-color: rgba(251, 191, 36, 0.3);
            background: linear-gradient(155deg, rgba(30, 41, 59, 0.85), rgba(69, 26, 3, 0.12));
        }
        .bookmark-card.selected {
            border-color: rgba(139, 92, 246, 0.65) !important;
            box-shadow: 0 0 0 2px rgba(139, 92, 246, 0.25);
            background: linear-gradient(155deg, rgba(30, 41, 59, 0.9), rgba(76, 29, 149, 0.15));
        }
        /* Zuletzt geöffneter Eintrag: Rahmen aussen herum, damit man die Stelle wiederfindet */
        .bookmark-card.last-opened {
            outline: 2px solid #a78bfa; outline-offset: 1px;
            box-shadow: 0 0 14px -2px rgba(139, 92, 246, 0.55);
        }
        /* Hilfe mit den Tastenkürzeln (Taste H) */
        .kb-help {
            position: fixed; left: 50%; top: 50%; transform: translate(-50%, -50%); z-index: 95;
            width: max-content; max-width: calc(100vw - 2rem); max-height: calc(100vh - 2rem); overflow: auto;
            padding: 1rem 1.25rem 1.1rem; border-radius: 1rem; cursor: pointer;
            background: var(--lv-raised, rgba(30, 41, 59, 0.97)); color: var(--lv-t2, #e2e8f0);
            border: 1px solid var(--lv-line2, rgba(71, 85, 105, 0.7));
            box-shadow: 0 25px 50px -12px var(--lv-shadow, rgba(0, 0, 0, 0.5));
            backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
            font-size: 0.8125rem; animation: kbHelpIn 0.15s ease-out;
        }
        @keyframes kbHelpIn { from { opacity: 0; } to { opacity: 1; } }
        .kb-help-title { font-size: 0.95rem; font-weight: 600; color: var(--lv-t1, #f1f5f9); margin-bottom: 0.25rem; }
        .kb-help-cols { display: flex; flex-wrap: wrap; gap: 0 2.25rem; }
        .kb-help-head {
            font-size: 0.6875rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;
            color: var(--lv-t3, #94a3b8); margin: 0.75rem 0 0.35rem;
        }
        .kb-help-row { display: flex; align-items: center; gap: 0.75rem; padding: 0.2rem 0; white-space: nowrap; }
        .kb-help-keys { display: inline-flex; gap: 0.25rem; min-width: 7.75rem; }
        .kb-help kbd {
            display: inline-block; min-width: 1.6rem; padding: 0.1rem 0.4rem; text-align: center;
            font: 600 0.75rem/1.35 inherit; font-family: inherit; border-radius: 0.375rem;
            background: var(--lv-field, rgba(15, 23, 42, 0.7)); color: var(--lv-t1, #f1f5f9);
            border: 1px solid var(--lv-line2, rgba(71, 85, 105, 0.7)); border-bottom-width: 2px;
        }
        .kb-help-bar {
            height: 2px; margin-top: 0.9rem; border-radius: 2px; background: var(--lv-a, #8b5cf6);
            transform-origin: left; animation: kbHelpBar 10s linear forwards;
        }
        @keyframes kbHelpBar { from { transform: scaleX(1); } to { transform: scaleX(0); } }
        /* Tastatur-Rahmen (Pfeiltasten) */
        .bookmark-card.kb-cursor { outline: 2px dashed #c4b5fd; outline-offset: 2px; }

        .favicon {
            width: 28px; height: 28px; border-radius: 7px; object-fit: contain;
            background: rgba(15, 23, 42, 0.65); padding: 3px; flex-shrink: 0;
        }

        .sel-check {
            width: 1.25rem; height: 1.25rem; border-radius: 0.35rem;
            border: 2px solid #64748b; background: transparent; cursor: pointer;
            display: flex; align-items: center; justify-content: center;
            flex-shrink: 0; transition: all 0.15s ease; padding: 0; color: transparent;
        }
        .sel-check.checked { background: #8b5cf6; border-color: #8b5cf6; color: #fff; }
        .sel-check svg { width: 0.75rem; height: 0.75rem; }

        .cat-btn {
            display: inline-flex; align-items: center; gap: 0.25rem;
            padding: 0.35rem 0.7rem; border-radius: 9999px; font-size: 0.72rem; font-weight: 550;
            border: 1px solid rgba(71, 85, 105, 0.55); background: rgba(30, 41, 59, 0.65);
            color: #cbd5e1; transition: all 0.15s ease; cursor: pointer; white-space: nowrap; flex-shrink: 0;
        }
        .cat-btn:hover { background: rgba(51, 65, 85, 0.8); color: #f1f5f9; }
        .cat-btn.active {
            background: linear-gradient(135deg, #8b5cf6, #7c3aed); border-color: transparent; color: #fff;
            box-shadow: 0 3px 12px -2px rgba(139, 92, 246, 0.45);
        }
        .cat-btn .count { opacity: 0.55; font-weight: 500; font-size: 0.7rem; }
        .cat-btn.active .count { opacity: 0.85; }

        #categoryBar {
            display: flex; gap: 0.35rem; overflow-x: auto; -webkit-overflow-scrolling: touch;
            overscroll-behavior-x: contain; touch-action: pan-x;
            scrollbar-width: thin; scrollbar-color: #475569 transparent;
            padding-bottom: 4px; max-width: 100%; cursor: grab;
        }
        #categoryBar:active { cursor: grabbing; }
        #categoryBar::-webkit-scrollbar { height: 4px; display: block; }
        #categoryBar::-webkit-scrollbar-track { background: transparent; }
        #categoryBar::-webkit-scrollbar-thumb {
            background: #475569; border-radius: 4px;
        }
        #categoryBar::-webkit-scrollbar-thumb:hover { background: #64748b; }

        .modal-panel { animation: modalIn 0.2s ease-out; }
        @keyframes modalIn {
            from { opacity: 0; transform: scale(0.96) translateY(10px); }
            to { opacity: 1; transform: scale(1) translateY(0); }
        }
        .toast { animation: toastIn 0.25s ease-out; }
        @keyframes toastIn {
            from { opacity: 0; transform: translateY(12px) scale(0.96); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }

        .fab {
            position: fixed; right: 1rem; bottom: max(1rem, env(safe-area-inset-bottom));
            z-index: 40; width: 3.25rem; height: 3.25rem; border-radius: 1rem;
            background: linear-gradient(135deg, #8b5cf6, #7c3aed); color: #fff;
            box-shadow: 0 8px 24px -4px rgba(139, 92, 246, 0.55);
            display: none; align-items: center; justify-content: center; border: none; cursor: pointer;
        }
        .fab:active { transform: scale(0.92); }
        @media (max-width: 640px) {
            .fab { display: flex; }
            .btn-add-desktop { display: none !important; }
            body.select-mode .fab { display: none; }
        }

        .bookmarks-grid {
            display: grid; grid-template-columns: 1fr; gap: 0.5rem; width: 100%; max-width: 100%;
        }
        @media (min-width: 480px) {
            .bookmarks-grid { grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 0.55rem; }
        }
        @media (min-width: 900px) {
            .bookmarks-grid { grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 0.65rem; }
        }

        .empty-state {
            background: radial-gradient(ellipse at 50% 30%, rgba(139, 92, 246, 0.07) 0%, transparent 65%);
        }
        input:focus, select:focus, textarea:focus, button:focus-visible {
            outline: none; box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.3);
        }

        .safe-bottom { padding-bottom: max(5.5rem, calc(env(safe-area-inset-bottom) + 5rem)); }
        @media (min-width: 641px) { .safe-bottom { padding-bottom: 2rem; } }
        body.select-mode .safe-bottom { padding-bottom: max(7rem, calc(env(safe-area-inset-bottom) + 6.5rem)); }

        .field {
            width: 100%; max-width: 100%; padding: 0.65rem 0.85rem; border-radius: 0.7rem;
            background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(71, 85, 105, 0.55);
            color: #f1f5f9; font-size: 0.9rem; transition: border-color 0.15s;
        }
        .field::placeholder { color: #64748b; }
        .field:focus { border-color: rgba(139, 92, 246, 0.55); box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.2); }

        .toggle {
            position: relative; width: 2.6rem; height: 1.4rem; background: #334155;
            border-radius: 9999px; transition: background 0.2s; cursor: pointer;
            flex-shrink: 0; border: none; padding: 0;
        }
        .toggle::after {
            content: ''; position: absolute; top: 2px; left: 2px;
            width: 1.15rem; height: 1.15rem; background: #fff; border-radius: 50%; transition: transform 0.2s;
        }
        .toggle.on { background: #f59e0b; }
        .toggle.on::after { transform: translateX(1.2rem); }

        .bulk-bar {
            position: fixed; left: 0; right: 0; bottom: 0; z-index: 45;
            transform: translateY(110%); transition: transform 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            padding: 0.75rem 0.75rem max(0.75rem, env(safe-area-inset-bottom));
        }
        body.select-mode .bulk-bar { transform: translateY(0); }

        .bulk-inner {
            max-width: 42rem; margin: 0 auto;
            background: rgba(15, 23, 42, 0.96); backdrop-filter: blur(20px);
            border: 1px solid rgba(139, 92, 246, 0.35); border-radius: 1rem;
            padding: 0.65rem 0.75rem;
            box-shadow: 0 -8px 32px -4px rgba(0,0,0,0.5), 0 0 24px -8px rgba(139, 92, 246, 0.2);
            display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem;
        }

        .header-row {
            display: flex; align-items: center; gap: 0.5rem; width: 100%; min-width: 0;
        }
        .header-actions { display: flex; align-items: center; gap: 0.35rem; flex-shrink: 0; position: relative; z-index: 40; }
        .search-wrap { flex: 1 1 auto; min-width: 0; position: relative; }
        .truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .min-w-0 { min-width: 0; }

        header, main, .max-w-7xl, .header-row, .search-wrap, .bookmarks-grid, .bookmark-card {
            max-width: 100%;
        }
        .header-top { position: relative; z-index: 40; }
        .header-cats { position: relative; z-index: 10; }
        #exportMenu, #toolsMenu {
            z-index: 100 !important;
            /* fast deckend: im Header greift der Unschärfe-Effekt nicht, sonst scheint der Inhalt durch */
            background: rgba(15, 23, 42, 0.97);
            box-shadow: 0 12px 40px -8px rgba(0,0,0,0.55), 0 0 0 1px rgba(51,65,85,0.5);
        }
        .search-clear {
            position: absolute; right: 0.45rem; top: 50%; transform: translateY(-50%);
            width: 1.5rem; height: 1.5rem; border-radius: 0.4rem;
            display: none; align-items: center; justify-content: center;
            color: #94a3b8; background: transparent; border: none; cursor: pointer;
        }
        .search-clear:hover { color: #f1f5f9; background: rgba(51,65,85,0.6); }
        .search-wrap.has-query .search-clear { display: flex; }
        .search-wrap.has-query input { padding-right: 2rem !important; }

        /* Fixed header = search always visible while scrolling */
        #appHeader {
            position: fixed !important;
            top: 0;
            left: 0;
            right: 0;
            width: 100%;
            z-index: 50;
            background: rgba(11, 17, 32, 0.98) !important;
            backdrop-filter: blur(18px);
            -webkit-backdrop-filter: blur(18px);
            border-bottom: 1px solid rgba(51, 65, 85, 0.5);
        }
        #headerSpacer {
            width: 100%;
            flex-shrink: 0;
        }
        .search-wrap .field {
            background: rgba(15, 23, 42, 0.95) !important;
        }

        .cat-chip {
            display: inline-flex; align-items: center; gap: 0.25rem;
            padding: 0.35rem 0.7rem; border-radius: 9999px;
            font-size: 0.75rem; font-weight: 550;
            border: 1px solid rgba(71, 85, 105, 0.6);
            background: rgba(30, 41, 59, 0.8); color: #cbd5e1;
            cursor: pointer; transition: all 0.15s;
        }
        .cat-chip:hover { border-color: rgba(139, 92, 246, 0.45); color: #e9d5ff; }
        .cat-chip.active {
            background: linear-gradient(135deg, #8b5cf6, #7c3aed);
            border-color: transparent; color: #fff;
        }

        /* Domain group – startet geschlossen */
        .domain-group {
            grid-column: 1 / -1;
            border-radius: 0.75rem;
            border: 1px solid rgba(51, 65, 85, 0.55);
            background: rgba(15, 23, 42, 0.4);
            overflow: hidden;
        }
        .domain-group-header {
            display: flex; align-items: center; gap: 0.5rem;
            padding: 0.5rem 0.75rem; cursor: pointer; user-select: none;
            transition: background 0.15s;
        }
        .domain-group-header:hover { background: rgba(51, 65, 85, 0.35); }
        .domain-group-header .chevron {
            transition: transform 0.2s ease; color: #64748b; flex-shrink: 0;
            width: 0.9rem; height: 0.9rem;
        }
        .domain-group.open .domain-group-header .chevron { transform: rotate(90deg); }
        .domain-group-body {
            display: none;
            padding: 0 0.5rem 0.55rem;
            grid-template-columns: 1fr;
            gap: 0.45rem;
        }
        .domain-group.open .domain-group-body { display: grid; }
        @media (min-width: 480px) {
            .domain-group-body { grid-template-columns: repeat(auto-fill, minmax(210px, 1fr)); }
        }

        /* Tools dropdown */
        .tools-menu {
            position: absolute; right: 0; top: calc(100% + 0.4rem);
            min-width: 13.5rem; z-index: 100;
            max-height: calc(100vh - 5rem); max-height: calc(100dvh - 5rem); overflow-y: auto;
        }

        /* ===== Neu in 3.0 ===== */
        /* App-Modus am Handy: Platz für Statusleiste, Notch und Wischbalken lassen.
           Ohne das liegt die Kopfzeile unter der Uhr und lässt sich nicht antippen. */
        html { background: #0b1120; }
        #appHeader {
            padding-top: env(safe-area-inset-top);
            padding-left: env(safe-area-inset-left);
            padding-right: env(safe-area-inset-right);
        }
        html body main {
            padding-left: max(0.75rem, env(safe-area-inset-left));
            padding-right: max(0.75rem, env(safe-area-inset-right));
        }
        @media (min-width: 640px) {
            html body main { padding-left: max(1.25rem, env(safe-area-inset-left)); padding-right: max(1.25rem, env(safe-area-inset-right)); }
        }
        .fab { right: calc(1rem + env(safe-area-inset-right)); }
        .bulk-bar { padding-left: max(0.75rem, env(safe-area-inset-left)); padding-right: max(0.75rem, env(safe-area-inset-right)); }
        [id$="Overlay"] {
            padding: max(0.75rem, env(safe-area-inset-top)) max(0.75rem, env(safe-area-inset-right)) max(0.75rem, env(safe-area-inset-bottom)) max(0.75rem, env(safe-area-inset-left));
        }
        [id$="Overlay"] > .modal-panel {
            max-height: calc(100vh - 1.5rem);
            max-height: calc(100dvh - env(safe-area-inset-top) - env(safe-area-inset-bottom) - 1.5rem);
        }
        #toastContainer { bottom: calc(5rem + env(safe-area-inset-bottom)); }
        @media (min-width: 640px) { #toastContainer { bottom: calc(1.5rem + env(safe-area-inset-bottom)); } }
        @media (display-mode: standalone) {
            body { overscroll-behavior-y: none; }
            #appHeader, .cat-btn, .btn, .card-btn, .menu-opt { -webkit-user-select: none; user-select: none; }
        }
        /* Fenster liegen über Kopfzeile und Plus-Knopf (die Ebenen fehlten im eingebauten CSS) */
        [id$="Overlay"] { z-index: 75; }
        #confirmOverlay, #dialogOverlay { z-index: 85; }
        #toastContainer { z-index: 90; }
        body { font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; }
        /* iPhone zoomt in Felder mit kleiner Schrift hinein, deshalb am Handy 16px */
        @media (pointer: coarse) {
            html body .field, html body input[type="text"], html body input[type="password"], html body input[type="search"],
            html body select, html body textarea { font-size: 16px !important; }
        }
        .bm-main { display: flex; align-items: flex-start; gap: 0.5rem; min-width: 0; }
        .bm-text { flex: 1 1 auto; min-width: 0; }
        .bm-title {
            display: block; font-weight: 600; font-size: 0.875rem; line-height: 1.375; color: #f1f5f9;
            overflow: hidden; text-overflow: ellipsis; white-space: nowrap; text-decoration: none;
        }
        a.bm-title:hover { color: #ddd6fe; text-decoration: underline; text-underline-offset: 2px; }
        a.bm-title:focus-visible { outline: 2px solid #8b5cf6; outline-offset: 2px; border-radius: 3px; }
        .bm-domain { display: block; font-size: 11px; color: #64748b; margin-top: 0.125rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .bm-desc {
            font-size: 11px; color: #94a3b8; margin: 0.15rem 0 0; line-height: 1.375;
            overflow: hidden; display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 2;
        }
        .bm-meta { display: flex; flex-wrap: wrap; gap: 0.25rem; margin-top: 0.3rem; min-width: 0; }
        .bm-chip {
            display: inline-block; padding: 0.1rem 0.375rem; border-radius: 0.25rem; font-size: 10px; font-weight: 500;
            background: rgba(30, 41, 59, 0.7); color: #94a3b8; border: 1px solid rgba(51, 65, 85, 0.45);
            max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; line-height: 1.5;
        }
        .bm-tag { color: #c4b5fd; border-color: rgba(139, 92, 246, 0.3); background: rgba(139, 92, 246, 0.1); cursor: pointer; }
        .bm-tag:hover { background: rgba(139, 92, 246, 0.25); }
        .bm-warn { color: #fda4af; border-color: rgba(244, 63, 94, 0.35); background: rgba(244, 63, 94, 0.12); }
        .bm-warn.unclear { color: #fcd34d; border-color: rgba(245, 158, 11, 0.35); background: rgba(245, 158, 11, 0.1); }
        .bm-more {
            display: none; align-items: center; justify-content: center; flex: 0 0 1.75rem; width: 1.75rem; height: 1.75rem;
            border-radius: 0.5rem; border: 1px solid transparent; background: transparent; color: #94a3b8; cursor: pointer; padding: 0;
        }
        .bm-more:hover, .bookmark-card.expanded .bm-more { background: rgba(51, 65, 85, 0.7); color: #f1f5f9; }
        .bm-more svg { width: 1rem; height: 1rem; }
        body.select-mode .bm-more { display: none !important; }
        .bookmark-card.dragging { opacity: 0.45; }
        .cat-btn.drop-ok { outline: 2px dashed #a78bfa; outline-offset: 1px; background: rgba(139, 92, 246, 0.25); color: #fff; }
        .cat-btn.warn { border-color: rgba(244, 63, 94, 0.4); color: #fda4af; }
        .cat-btn.warn.active { background: linear-gradient(135deg, #e11d48, #be123c); color: #fff; }

        /* Unterordner-Leiste */
        #subCatBar {
            display: flex; gap: 0.3rem; overflow-x: auto; margin-top: 0.35rem; padding-bottom: 3px;
            scrollbar-width: none; -webkit-overflow-scrolling: touch;
        }
        #subCatBar::-webkit-scrollbar { display: none; }
        #subCatBar:empty { display: none; }
        #subCatBar .cat-btn { padding: 0.25rem 0.6rem; font-size: 0.68rem; }
        /* Tag-Leiste (3.4): wie die Unterordner, Tags in Violett */
        #tagBar {
            display: flex; gap: 0.3rem; overflow-x: auto; margin-top: 0.35rem; padding-bottom: 3px;
            scrollbar-width: none; -webkit-overflow-scrolling: touch; overscroll-behavior-x: contain; touch-action: pan-x; cursor: grab;
        }
        #tagBar::-webkit-scrollbar { display: none; }
        #tagBar:empty { display: none; }
        #tagBar .cat-btn { padding: 0.25rem 0.6rem; font-size: 0.68rem; flex-shrink: 0; }
        #tagBar .cat-btn.tagb:not(.active) { color: #c4b5fd; }
        html.lvt #tagBar .cat-btn.tagb:not(.active) { color: var(--lv-at); }
        #tagBar .cat-btn.tagm { display: inline-flex; align-items: center; gap: 0.25rem; }
        #tagBar .cat-btn.tagm svg { width: 0.8rem; height: 0.8rem; }

        /* Ansicht „Liste“: eine Zeile pro Link */
        body.view-list .bookmarks-grid, body.view-list .domain-group-body { grid-template-columns: 1fr !important; gap: 0.3rem; }
        body.view-list .bookmark-card {
            padding: 0.4rem 0.6rem !important; display: flex; flex-wrap: wrap; align-items: center; column-gap: 0.5rem;
        }
        body.view-list .bookmark-card:hover { transform: none; }
        body.view-list .bm-main { flex: 1 1 0; align-items: center; }
        body.view-list .favicon { width: 20px; height: 20px; padding: 2px; border-radius: 5px; }
        body.view-list .bm-text { display: flex; align-items: center; gap: 0.6rem; }
        body.view-list .bm-title { flex: 0 1 auto; min-width: 2rem; }
        body.view-list .bm-domain { flex: 0 2 auto; margin: 0; min-width: 0; }
        body.view-list .bm-desc { display: none; }
        body.view-list .bm-meta { margin: 0 0 0 auto; flex-wrap: nowrap; flex: 0 1 auto; max-width: 45%; overflow: hidden; }
        body.view-list .bm-more { display: inline-flex; }
        body.view-list .card-actions { display: none; flex-basis: 100%; }
        body.view-list .bookmark-card.expanded .card-actions { display: flex; }
        @media (max-width: 640px) {
            /* Am Handy: Titel und darunter die Adresse, der Ordner steht rechts daneben */
            body.view-list .bm-text { display: grid; grid-template-columns: minmax(0, 1fr) auto; column-gap: 0.5rem; align-items: center; }
            body.view-list .bm-title { grid-column: 1; grid-row: 1; min-width: 0; }
            body.view-list .bm-domain { grid-column: 1; grid-row: 2; }
            body.view-list .bm-meta { grid-column: 2; grid-row: 1 / span 2; max-width: 6.5rem; margin: 0; }
            body.view-list .bm-meta .bm-tag { display: none; }
        }
        @media (hover: hover) and (min-width: 900px) {
            body.view-list .bm-more { display: none; }
            body.view-list .card-actions {
                display: flex; flex-basis: auto; margin: 0; padding: 0; border: 0; opacity: 0.25; transition: opacity 0.12s;
            }
            body.view-list .bookmark-card:hover .card-actions, body.view-list .bookmark-card:focus-within .card-actions { opacity: 1; }
            body.view-list .card-btn-open { display: none; }
            body.view-list .bm-desc {
                display: block; flex: 1 1 0; min-width: 0; margin: 0; white-space: nowrap; text-overflow: ellipsis; -webkit-line-clamp: unset;
            }
        }

        /* Ansicht „Kacheln“: schmale Kacheln nebeneinander, immer mit Titel und Adresse. Der Rest steckt hinter den drei Punkten. */
        body.view-tiles .bookmarks-grid, body.view-tiles .domain-group-body {
            grid-template-columns: repeat(2, minmax(0, 1fr)) !important; gap: 0.3rem;
        }
        @media (min-width: 560px) {
            body.view-tiles .bookmarks-grid, body.view-tiles .domain-group-body {
                grid-template-columns: repeat(auto-fill, minmax(215px, 1fr)) !important;
            }
        }
        body.view-tiles .bookmark-card { padding: 0.4rem 0.35rem 0.4rem 0.5rem !important; }
        body.view-tiles .bookmark-card:hover { transform: none; }
        body.view-tiles .bm-main { align-items: center; gap: 0.45rem; }
        body.view-tiles .favicon { width: 22px; height: 22px; padding: 2px; border-radius: 5px; }
        body.view-tiles .bm-title { font-size: 0.8rem; }
        body.view-tiles .bm-domain { margin-top: 0; }
        body.view-tiles .bm-desc, body.view-tiles .bm-meta, body.view-tiles .card-actions { display: none; }
        body.view-tiles .bm-more { display: inline-flex; flex-basis: 1.5rem; width: 1.5rem; height: 1.5rem; }
        body.view-tiles .bookmark-card.expanded { grid-column: 1 / -1; }
        body.view-tiles .bookmark-card.expanded .bm-meta, body.view-tiles .bookmark-card.expanded .card-actions { display: flex; }
        body.view-tiles .bookmark-card.expanded .bm-desc { display: -webkit-box; }
        body.view-tiles .bookmark-card.expanded .bm-title, body.view-tiles .bookmark-card.expanded .bm-domain { white-space: normal; overflow-wrap: anywhere; }
        /* Ein toter oder unklarer Link fällt auch ohne aufgeklappte Kachel auf */
        body.view-tiles .bookmark-card.has-warn:not(.expanded) { border-color: rgba(244, 63, 94, 0.45); }

        /* Menüs */
        #viewMenu { z-index: 100 !important; background: rgba(15, 23, 42, 0.97); box-shadow: 0 12px 40px -8px rgba(0,0,0,0.55), 0 0 0 1px rgba(51,65,85,0.5); }
        .menu-label { padding: 0.5rem 0.75rem 0.25rem; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; }
        .menu-opt {
            display: flex; align-items: center; gap: 0.5rem; width: 100%; text-align: left; padding: 0.5rem 0.75rem;
            font-size: 0.875rem; color: #e2e8f0; background: transparent; border: 0; cursor: pointer;
        }
        .menu-opt:hover { background: rgba(51, 65, 85, 0.7); }
        .menu-opt svg { width: 1rem; height: 1rem; color: #94a3b8; flex-shrink: 0; }
        .menu-opt.on { color: #c4b5fd; }
        .menu-opt.on::after { content: '✓'; margin-left: auto; color: #a78bfa; font-weight: 700; }
        .menu-opt.danger { color: #fda4af; }
        .menu-opt.danger svg { color: #fb7185; }
        .menu-opt .badge { margin-left: auto; font-size: 10px; color: #94a3b8; background: rgba(30, 41, 59, 0.9); padding: 0.05rem 0.4rem; border-radius: 9999px; }
        .menu-sep { border-top: 1px solid rgba(51, 65, 85, 0.5); margin: 0.25rem 0; }

        /* Fenster-Bausteine */
        .box { border: 1px solid rgba(51, 65, 85, 0.5); border-radius: 0.75rem; padding: 0.75rem; background: rgba(15, 23, 42, 0.45); }
        .box h4 { font-size: 0.8rem; font-weight: 600; color: #e2e8f0; margin: 0 0 0.35rem; }
        .box p { font-size: 0.78rem; color: #94a3b8; line-height: 1.5; margin: 0 0 0.5rem; }
        .box .row { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }
        .mono-box {
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85rem; letter-spacing: 0.04em;
            color: #ddd6fe; background: rgba(2, 6, 23, 0.6); border: 1px dashed rgba(139, 92, 246, 0.45);
            border-radius: 0.5rem; padding: 0.5rem 0.6rem; word-break: break-all; user-select: all; margin-bottom: 0.5rem;
        }
        .ok-text { color: #6ee7b7; } .warn-text { color: #fcd34d; } .bad-text { color: #fda4af; }
        .lbl { display: block; font-size: 0.75rem; font-weight: 500; color: #94a3b8; margin-bottom: 0.25rem; }
        .list-row {
            display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0.625rem; border-radius: 0.5rem;
            background: rgba(30, 41, 59, 0.5); border: 1px solid rgba(51, 65, 85, 0.4); min-width: 0;
        }
        .list-row .grow { flex: 1 1 auto; min-width: 0; }
        .list-row .t1 { font-size: 0.85rem; color: #e2e8f0; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .list-row .t2 { font-size: 11px; color: #64748b; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .stack > * + * { margin-top: 0.4rem; }
        .dot { width: 0.5rem; height: 0.5rem; border-radius: 50%; flex-shrink: 0; background: #f43f5e; }
        .dot.ok { background: #10b981; } .dot.mid { background: #f59e0b; }
        .tag-suggest { display: flex; flex-wrap: wrap; gap: 0.25rem; margin-top: 0.4rem; }
        kbd { font-family: inherit; font-size: 10px; padding: 0.05rem 0.3rem; border-radius: 0.25rem; border: 1px solid rgba(71, 85, 105, 0.7); color: #94a3b8; }
        /* ===== Neu in 3.1: mehrere Benutzer ===== */
        .btn-icon { position: relative; }
        .btn-icon.has-note::after {
            content: ''; position: absolute; top: -3px; right: -3px; width: 0.65rem; height: 0.65rem;
            border-radius: 50%; background: #f59e0b; border: 2px solid #0b1120;
        }
        .menu-opt .badge.hot { background: #f59e0b; color: #1e1b4b; font-weight: 700; }
        .user-note { font-size: 11px; color: #cbd5e1; margin-top: 0.15rem; line-height: 1.4; overflow-wrap: anywhere; }
        .toggle.green.on { background: #10b981; }
        /* ===== Neu in 3.4: Automatisch sortieren ===== */
        #autoOverlay > .modal-panel, #rulesOverlay > .modal-panel { max-width: 36rem; }
        #rulesOverlay { z-index: 78; }
        .as-opts { display: flex; flex-direction: column; gap: 0.45rem; }
        .as-opt { display: flex; align-items: flex-start; gap: 0.5rem; font-size: 0.8rem; line-height: 1.4; color: var(--lv-t2, #e2e8f0); cursor: pointer; }
        .as-opt input, .as-row input, .as-cat input[type="checkbox"] { accent-color: #8b5cf6; width: 1rem; height: 1rem; margin-top: 0.1rem; flex-shrink: 0; cursor: pointer; }
        .as-sum { display: flex; flex-wrap: wrap; gap: 0.3rem; margin-bottom: 0.65rem; }
        .as-sum:empty { display: none; }
        .as-row { align-items: flex-start; }
        .as-row.as-dim .grow { opacity: 0.45; }
        .as-chips { display: flex; flex-wrap: wrap; gap: 0.25rem; margin-top: 0.3rem; }
        button.bm-chip { font-family: inherit; cursor: pointer; }
        .bm-chip.as-off { opacity: 0.4; text-decoration: line-through; }
        html body .bm-chip.as-folder { color: var(--lv-ok-t, #6ee7b7); background: var(--lv-ok-bg, rgba(6, 78, 59, 0.35)); border-color: var(--lv-ok-line, rgba(16, 185, 129, 0.4)); }
        .as-sum .bm-chip { font-size: 11px; padding: 0.15rem 0.45rem; }
        .as-why { display: block; font-size: 10.5px; line-height: 1.4; color: var(--lv-t4, #64748b); margin-top: 0.25rem; }
        .as-grp .as-on { accent-color: #8b5cf6; width: 1rem; height: 1rem; flex-shrink: 0; cursor: pointer; }
        .as-grp-head { flex: 1 1 auto; min-width: 0; text-align: left; background: none; border: 0; padding: 0; cursor: pointer; color: inherit; }
        .as-grp.as-dim .as-grp-head { opacity: 0.45; }
        .as-grp-edit { margin-top: 0.35rem; }
        .as-grp-edit .field { padding: 0.4rem 0.55rem; font-size: 0.82rem; }
        .as-grp-edit textarea.field { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.78rem; line-height: 1.45; resize: vertical; }
        .as-two { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }
        @media (max-width: 560px) { .as-two { grid-template-columns: 1fr; } }
        .btn.lv-mini { padding: 0.35rem 0.65rem; font-size: 0.75rem; border-radius: 0.5rem; }
        .as-help p b { color: var(--lv-t1, #e2e8f0); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight: 600; }
        @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation: none !important; transition: none !important; } }
    </style>
<?php if (!LV_TAILWIND_CDN): ?>
    <!-- Tailwind fest eingebaut (nur die Klassen, die diese Seite benutzt). Neue Klassen? Oben LV_TAILWIND_CDN auf true stellen. -->
    <style id="tailwind-built">*,:after,:before{--tw-border-spacing-x:0;--tw-border-spacing-y:0;--tw-translate-x:0;--tw-translate-y:0;--tw-rotate:0;--tw-skew-x:0;--tw-skew-y:0;--tw-scale-x:1;--tw-scale-y:1;--tw-pan-x: ;--tw-pan-y: ;--tw-pinch-zoom: ;--tw-scroll-snap-strictness:proximity;--tw-gradient-from-position: ;--tw-gradient-via-position: ;--tw-gradient-to-position: ;--tw-ordinal: ;--tw-slashed-zero: ;--tw-numeric-figure: ;--tw-numeric-spacing: ;--tw-numeric-fraction: ;--tw-ring-inset: ;--tw-ring-offset-width:0px;--tw-ring-offset-color:#fff;--tw-ring-color:rgba(59,130,246,.5);--tw-ring-offset-shadow:0 0 #0000;--tw-ring-shadow:0 0 #0000;--tw-shadow:0 0 #0000;--tw-shadow-colored:0 0 #0000;--tw-blur: ;--tw-brightness: ;--tw-contrast: ;--tw-grayscale: ;--tw-hue-rotate: ;--tw-invert: ;--tw-saturate: ;--tw-sepia: ;--tw-drop-shadow: ;--tw-backdrop-blur: ;--tw-backdrop-brightness: ;--tw-backdrop-contrast: ;--tw-backdrop-grayscale: ;--tw-backdrop-hue-rotate: ;--tw-backdrop-invert: ;--tw-backdrop-opacity: ;--tw-backdrop-saturate: ;--tw-backdrop-sepia: ;--tw-contain-size: ;--tw-contain-layout: ;--tw-contain-paint: ;--tw-contain-style: }::backdrop{--tw-border-spacing-x:0;--tw-border-spacing-y:0;--tw-translate-x:0;--tw-translate-y:0;--tw-rotate:0;--tw-skew-x:0;--tw-skew-y:0;--tw-scale-x:1;--tw-scale-y:1;--tw-pan-x: ;--tw-pan-y: ;--tw-pinch-zoom: ;--tw-scroll-snap-strictness:proximity;--tw-gradient-from-position: ;--tw-gradient-via-position: ;--tw-gradient-to-position: ;--tw-ordinal: ;--tw-slashed-zero: ;--tw-numeric-figure: ;--tw-numeric-spacing: ;--tw-numeric-fraction: ;--tw-ring-inset: ;--tw-ring-offset-width:0px;--tw-ring-offset-color:#fff;--tw-ring-color:rgba(59,130,246,.5);--tw-ring-offset-shadow:0 0 #0000;--tw-ring-shadow:0 0 #0000;--tw-shadow:0 0 #0000;--tw-shadow-colored:0 0 #0000;--tw-blur: ;--tw-brightness: ;--tw-contrast: ;--tw-grayscale: ;--tw-hue-rotate: ;--tw-invert: ;--tw-saturate: ;--tw-sepia: ;--tw-drop-shadow: ;--tw-backdrop-blur: ;--tw-backdrop-brightness: ;--tw-backdrop-contrast: ;--tw-backdrop-grayscale: ;--tw-backdrop-hue-rotate: ;--tw-backdrop-invert: ;--tw-backdrop-opacity: ;--tw-backdrop-saturate: ;--tw-backdrop-sepia: ;--tw-contain-size: ;--tw-contain-layout: ;--tw-contain-paint: ;--tw-contain-style: }/*! tailwindcss v3.4.17 | MIT License | https://tailwindcss.com*/*,:after,:before{box-sizing:border-box;border:0 solid #e5e7eb}:after,:before{--tw-content:""}:host,html{line-height:1.5;-webkit-text-size-adjust:100%;-moz-tab-size:4;-o-tab-size:4;tab-size:4;font-family:Inter,system-ui,-apple-system,sans-serif;font-feature-settings:normal;font-variation-settings:normal;-webkit-tap-highlight-color:transparent}body{margin:0;line-height:inherit}hr{height:0;color:inherit;border-top-width:1px}abbr:where([title]){-webkit-text-decoration:underline dotted;text-decoration:underline dotted}h1,h2,h3,h4,h5,h6{font-size:inherit;font-weight:inherit}a{color:inherit;text-decoration:inherit}b,strong{font-weight:bolder}code,kbd,pre,samp{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,Courier New,monospace;font-feature-settings:normal;font-variation-settings:normal;font-size:1em}small{font-size:80%}sub,sup{font-size:75%;line-height:0;position:relative;vertical-align:baseline}sub{bottom:-.25em}sup{top:-.5em}table{text-indent:0;border-color:inherit;border-collapse:collapse}button,input,optgroup,select,textarea{font-family:inherit;font-feature-settings:inherit;font-variation-settings:inherit;font-size:100%;font-weight:inherit;line-height:inherit;letter-spacing:inherit;color:inherit;margin:0;padding:0}button,select{text-transform:none}button,input:where([type=button]),input:where([type=reset]),input:where([type=submit]){-webkit-appearance:button;background-color:transparent;background-image:none}:-moz-focusring{outline:auto}:-moz-ui-invalid{box-shadow:none}progress{vertical-align:baseline}::-webkit-inner-spin-button,::-webkit-outer-spin-button{height:auto}[type=search]{-webkit-appearance:textfield;outline-offset:-2px}::-webkit-search-decoration{-webkit-appearance:none}::-webkit-file-upload-button{-webkit-appearance:button;font:inherit}summary{display:list-item}blockquote,dd,dl,figure,h1,h2,h3,h4,h5,h6,hr,p,pre{margin:0}fieldset{margin:0}fieldset,legend{padding:0}menu,ol,ul{list-style:none;margin:0;padding:0}dialog{padding:0}textarea{resize:vertical}input::-moz-placeholder,textarea::-moz-placeholder{opacity:1;color:#9ca3af}input::placeholder,textarea::placeholder{opacity:1;color:#9ca3af}[role=button],button{cursor:pointer}:disabled{cursor:default}audio,canvas,embed,iframe,img,object,svg,video{display:block;vertical-align:middle}img,video{max-width:100%;height:auto}[hidden]:where(:not([hidden=until-found])){display:none}.container{width:100%}@media (min-width:640px){.container{max-width:640px}}@media (min-width:768px){.container{max-width:768px}}@media (min-width:1024px){.container{max-width:1024px}}@media (min-width:1280px){.container{max-width:1280px}}@media (min-width:1536px){.container{max-width:1536px}}.pointer-events-none{pointer-events:none}.pointer-events-auto{pointer-events:auto}.visible{visibility:visible}.fixed{position:fixed}.absolute{position:absolute}.relative{position:relative}.sticky{position:sticky}.inset-0{inset:0}.bottom-20{bottom:5rem}.left-1\/2{left:50%}.left-2\.5{left:.625rem}.right-0{right:0}.top-0{top:0}.top-1\/2{top:50%}.z-10{z-index:10}.z-50{z-index:50}.z-\[55\]{z-index:55}.z-\[60\]{z-index:60}.mx-auto{margin-left:auto;margin-right:auto}.my-1{margin-top:.25rem}.mb-1,.my-1{margin-bottom:.25rem}.mb-1\.5{margin-bottom:.375rem}.mb-2{margin-bottom:.5rem}.mb-3{margin-bottom:.75rem}.mb-4{margin-bottom:1rem}.mb-6{margin-bottom:1.5rem}.ml-auto{margin-left:auto}.mt-0\.5{margin-top:.125rem}.mt-1{margin-top:.25rem}.mt-1\.5{margin-top:.375rem}.mt-2{margin-top:.5rem}.mt-2\.5{margin-top:.625rem}.mt-3{margin-top:.75rem}.mt-4{margin-top:1rem}.line-clamp-2{overflow:hidden;display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:2}.block{display:block}.flex{display:flex}.inline-flex{display:inline-flex}.grid{display:grid}.hidden{display:none}.h-1\.5{height:.375rem}.h-10{height:2.5rem}.h-12{height:3rem}.h-28{height:7rem}.h-3\.5{height:.875rem}.h-4{height:1rem}.h-5{height:1.25rem}.h-6{height:1.5rem}.h-8{height:2rem}.h-full{height:100%}.max-h-28{max-height:7rem}.max-h-48{max-height:12rem}.max-h-\[85vh\]{max-height:85vh}.max-h-\[90vh\]{max-height:90vh}.w-10{width:2.5rem}.w-12{width:3rem}.w-3\.5{width:.875rem}.w-4{width:1rem}.w-44{width:11rem}.w-5{width:1.25rem}.w-6{width:1.5rem}.w-8{width:2rem}.w-full{width:100%}.min-w-0{min-width:0}.max-w-7xl{max-width:80rem}.max-w-full{max-width:100%}.max-w-md{max-width:28rem}.max-w-sm{max-width:24rem}.max-w-xs{max-width:20rem}.flex-1{flex:1 1 0%}.flex-shrink{flex-shrink:1}.shrink-0{flex-shrink:0}.-translate-x-1\/2{--tw-translate-x:-50%}.-translate-x-1\/2,.-translate-y-1\/2{transform:translate(var(--tw-translate-x),var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y))}.-translate-y-1\/2{--tw-translate-y:-50%}.transform{transform:translate(var(--tw-translate-x),var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y))}.cursor-pointer{cursor:pointer}.resize-none{resize:none}.resize{resize:both}.flex-col{flex-direction:column}.flex-wrap{flex-wrap:wrap}.items-start{align-items:flex-start}.items-center{align-items:center}.justify-center{justify-content:center}.justify-between{justify-content:space-between}.gap-1\.5{gap:.375rem}.gap-2{gap:.5rem}.gap-2\.5{gap:.625rem}.space-y-1\.5>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-top:calc(.375rem*(1 - var(--tw-space-y-reverse)));margin-bottom:calc(.375rem*var(--tw-space-y-reverse))}.space-y-3>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-top:calc(.75rem*(1 - var(--tw-space-y-reverse)));margin-bottom:calc(.75rem*var(--tw-space-y-reverse))}.space-y-3\.5>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-top:calc(.875rem*(1 - var(--tw-space-y-reverse)));margin-bottom:calc(.875rem*var(--tw-space-y-reverse))}.overflow-hidden{overflow:hidden}.overflow-y-auto{overflow-y:auto}.truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.\!rounded-lg{border-radius:.5rem!important}.rounded{border-radius:.25rem}.rounded-2xl{border-radius:1rem}.rounded-full{border-radius:9999px}.rounded-lg{border-radius:.5rem}.rounded-xl{border-radius:.75rem}.border{border-width:1px}.border-2{border-width:2px}.border-b{border-bottom-width:1px}.border-t{border-top-width:1px}.border-dashed{border-style:dashed}.border-slate-600{--tw-border-opacity:1;border-color:rgb(71 85 105/var(--tw-border-opacity,1))}.border-slate-700\/35{border-color:rgba(51,65,85,.35)}.border-slate-700\/40{border-color:rgba(51,65,85,.4)}.border-slate-700\/45{border-color:rgba(51,65,85,.45)}.border-slate-700\/50{border-color:rgba(51,65,85,.5)}.border-transparent{border-color:transparent}.bg-\[rgba\(15\2c 23\2c 42\2c 0\.95\)\]{background-color:rgba(15,23,42,.95)}.bg-black\/65{background-color:rgba(0,0,0,.65)}.bg-emerald-600\/95{background-color:rgba(5,150,105,.95)}.bg-rose-500\/15{background-color:rgba(244,63,94,.15)}.bg-rose-600\/95{background-color:rgba(225,29,72,.95)}.bg-slate-800{--tw-bg-opacity:1;background-color:rgb(30 41 59/var(--tw-bg-opacity,1))}.bg-slate-800\/50{background-color:rgba(30,41,59,.5)}.bg-slate-800\/70{background-color:rgba(30,41,59,.7)}.bg-slate-800\/80{background-color:rgba(30,41,59,.8)}.bg-violet-500{--tw-bg-opacity:1;background-color:rgb(139 92 246/var(--tw-bg-opacity,1))}.bg-gradient-to-br{background-image:linear-gradient(to bottom right,var(--tw-gradient-stops))}.from-violet-500{--tw-gradient-from:#8b5cf6 var(--tw-gradient-from-position);--tw-gradient-to:rgba(139,92,246,0) var(--tw-gradient-to-position);--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to)}.to-purple-700{--tw-gradient-to:#7e22ce var(--tw-gradient-to-position)}.p-3{padding:.75rem}.p-3\.5{padding:.875rem}.p-4{padding:1rem}.\!px-2{padding-left:.5rem!important;padding-right:.5rem!important}.\!px-2\.5{padding-left:.625rem!important;padding-right:.625rem!important}.\!px-3{padding-left:.75rem!important;padding-right:.75rem!important}.\!py-2{padding-top:.5rem!important;padding-bottom:.5rem!important}.px-1{padding-left:.25rem;padding-right:.25rem}.px-1\.5{padding-left:.375rem;padding-right:.375rem}.px-2\.5{padding-left:.625rem;padding-right:.625rem}.px-3{padding-left:.75rem;padding-right:.75rem}.px-3\.5{padding-left:.875rem;padding-right:.875rem}.px-4{padding-left:1rem;padding-right:1rem}.py-0\.5{padding-top:.125rem;padding-bottom:.125rem}.py-1{padding-top:.25rem;padding-bottom:.25rem}.py-1\.5{padding-top:.375rem;padding-bottom:.375rem}.py-12{padding-top:3rem;padding-bottom:3rem}.py-2{padding-top:.5rem;padding-bottom:.5rem}.py-2\.5{padding-top:.625rem;padding-bottom:.625rem}.py-3{padding-top:.75rem;padding-bottom:.75rem}.py-3\.5{padding-top:.875rem;padding-bottom:.875rem}.\!pl-8{padding-left:2rem!important}.\!pr-2{padding-right:.5rem!important}.pt-0\.5{padding-top:.125rem}.pt-1{padding-top:.25rem}.pt-4{padding-top:1rem}.text-left{text-align:left}.text-center{text-align:center}.\!text-sm{font-size:.875rem!important;line-height:1.25rem!important}.\!text-xs{font-size:.75rem!important;line-height:1rem!important}.text-\[10px\]{font-size:10px}.text-\[11px\]{font-size:11px}.text-base{font-size:1rem;line-height:1.5rem}.text-sm{font-size:.875rem;line-height:1.25rem}.text-xs{font-size:.75rem;line-height:1rem}.font-medium{font-weight:500}.font-semibold{font-weight:600}.uppercase{text-transform:uppercase}.leading-relaxed{line-height:1.625}.leading-snug{line-height:1.375}.tracking-wider{letter-spacing:.05em}.text-amber-300{--tw-text-opacity:1;color:rgb(252 211 77/var(--tw-text-opacity,1))}.text-amber-300\/90{color:rgba(252,211,77,.9)}.text-amber-400{--tw-text-opacity:1;color:rgb(251 191 36/var(--tw-text-opacity,1))}.text-rose-300{--tw-text-opacity:1;color:rgb(253 164 175/var(--tw-text-opacity,1))}.text-rose-400{--tw-text-opacity:1;color:rgb(251 113 133/var(--tw-text-opacity,1))}.text-slate-100{--tw-text-opacity:1;color:rgb(241 245 249/var(--tw-text-opacity,1))}.text-slate-200{--tw-text-opacity:1;color:rgb(226 232 240/var(--tw-text-opacity,1))}.text-slate-300{--tw-text-opacity:1;color:rgb(203 213 225/var(--tw-text-opacity,1))}.text-slate-400{--tw-text-opacity:1;color:rgb(148 163 184/var(--tw-text-opacity,1))}.text-slate-500{--tw-text-opacity:1;color:rgb(100 116 139/var(--tw-text-opacity,1))}.text-slate-600{--tw-text-opacity:1;color:rgb(71 85 105/var(--tw-text-opacity,1))}.text-violet-300{--tw-text-opacity:1;color:rgb(196 181 253/var(--tw-text-opacity,1))}.text-violet-400{--tw-text-opacity:1;color:rgb(167 139 250/var(--tw-text-opacity,1))}.text-white{--tw-text-opacity:1;color:rgb(255 255 255/var(--tw-text-opacity,1))}.underline{text-decoration-line:underline}.underline-offset-2{text-underline-offset:2px}.antialiased{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}.shadow-2xl{--tw-shadow:0 25px 50px -12px rgba(0,0,0,.25);--tw-shadow-colored:0 25px 50px -12px var(--tw-shadow-color)}.shadow-2xl,.shadow-\[0_0_14px_-3px_rgba\(139\2c 92\2c 246\2c 0\.5\)\]{box-shadow:var(--tw-ring-offset-shadow,0 0 #0000),var(--tw-ring-shadow,0 0 #0000),var(--tw-shadow)}.shadow-\[0_0_14px_-3px_rgba\(139\2c 92\2c 246\2c 0\.5\)\]{--tw-shadow:0 0 14px -3px rgba(139,92,246,.5);--tw-shadow-colored:0 0 14px -3px var(--tw-shadow-color)}.shadow-xl{--tw-shadow:0 20px 25px -5px rgba(0,0,0,.1),0 8px 10px -6px rgba(0,0,0,.1);--tw-shadow-colored:0 20px 25px -5px var(--tw-shadow-color),0 8px 10px -6px var(--tw-shadow-color);box-shadow:var(--tw-ring-offset-shadow,0 0 #0000),var(--tw-ring-shadow,0 0 #0000),var(--tw-shadow)}.outline{outline-style:solid}.blur{--tw-blur:blur(8px)}.blur,.filter{filter:var(--tw-blur) var(--tw-brightness) var(--tw-contrast) var(--tw-grayscale) var(--tw-hue-rotate) var(--tw-invert) var(--tw-saturate) var(--tw-sepia) var(--tw-drop-shadow)}.backdrop-blur-sm{--tw-backdrop-blur:blur(4px)}.backdrop-blur-sm,.backdrop-filter{-webkit-backdrop-filter:var(--tw-backdrop-blur) var(--tw-backdrop-brightness) var(--tw-backdrop-contrast) var(--tw-backdrop-grayscale) var(--tw-backdrop-hue-rotate) var(--tw-backdrop-invert) var(--tw-backdrop-opacity) var(--tw-backdrop-saturate) var(--tw-backdrop-sepia);backdrop-filter:var(--tw-backdrop-blur) var(--tw-backdrop-brightness) var(--tw-backdrop-contrast) var(--tw-backdrop-grayscale) var(--tw-backdrop-hue-rotate) var(--tw-backdrop-invert) var(--tw-backdrop-opacity) var(--tw-backdrop-saturate) var(--tw-backdrop-sepia)}.transition{transition-property:color,background-color,border-color,text-decoration-color,fill,stroke,opacity,box-shadow,transform,filter,-webkit-backdrop-filter;transition-property:color,background-color,border-color,text-decoration-color,fill,stroke,opacity,box-shadow,transform,filter,backdrop-filter;transition-property:color,background-color,border-color,text-decoration-color,fill,stroke,opacity,box-shadow,transform,filter,backdrop-filter,-webkit-backdrop-filter;transition-timing-function:cubic-bezier(.4,0,.2,1);transition-duration:.15s}.transition-colors{transition-property:color,background-color,border-color,text-decoration-color,fill,stroke;transition-timing-function:cubic-bezier(.4,0,.2,1);transition-duration:.15s}.hover\:border-violet-500\/30:hover{border-color:rgba(139,92,246,.3)}.hover\:border-violet-500\/50:hover{border-color:rgba(139,92,246,.5)}.hover\:bg-slate-700\/70:hover{background-color:rgba(51,65,85,.7)}.hover\:bg-slate-800\/30:hover{background-color:rgba(30,41,59,.3)}.hover\:bg-violet-600\/20:hover{background-color:rgba(124,58,237,.2)}.hover\:text-violet-200:hover{--tw-text-opacity:1;color:rgb(221 214 254/var(--tw-text-opacity,1))}@media (min-width:640px){.sm\:bottom-6{bottom:1.5rem}.sm\:left-auto{left:auto}.sm\:right-4{right:1rem}.sm\:w-auto{width:auto}.sm\:translate-x-0{--tw-translate-x:0px;transform:translate(var(--tw-translate-x),var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y))}.sm\:items-end{align-items:flex-end}.sm\:px-5{padding-left:1.25rem;padding-right:1.25rem}}@media (min-width:768px){.md\:inline{display:inline}}</style>
<?php endif; ?>
