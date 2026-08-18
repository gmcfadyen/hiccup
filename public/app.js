/*
 * hiccup — app.js
 * The Workbench app shell: boot/auth, capture sidebar + upload, trace-wide
 * search, the five Workbench panes (#searchbar #filter-pane #selection-pane
 * #ladder-pane/#time-pane #info-pane), the indicator lamps, the scenario chip
 * and the "ask hiccup" drawer.
 *
 * Wave 4 (ARCHITECTURE.md §"Wave 4 — Advice into the persistent drawer"):
 * #chat-drawer is open by default and leads with the Advice cards
 * (#chat-advice-body, rendered by renderDrawerAdvice) above the unchanged
 * conversation UI. Every selection path — tree click, search-result click,
 * lamp click, ladder/selection row click, finding jump — ends in
 * renderDrawer(), so advice and the chat scope always match what is selected
 * with no extra click. The info pane is three tabs (Contents/Packet/Media),
 * and retransmission collapsing is a fixed constant, not a toggle.
 *
 * DOM id contract (ARCHITECTURE.md §UI — the Workbench layout) is frozen and
 * shared with the UI-shell agent who owns app.html/app.css. This file assumes
 * every listed id may or may not be present and guards every access; it never
 * writes layout CSS (only per-element indentation and SVG geometry).
 *
 * Security: every piece of capture-derived text (message raw, headers, URIs,
 * numbers, aux summaries, advice text) goes in through textContent /
 * createTextNode. innerHTML is never used anywhere in this file.
 */
(function () {
  'use strict';

  var RFPLEX_URL = 'https://rfplex.ai/?utm_source=hiccup&utm_medium=app&utm_campaign=crosslink';

  var SEV_ORDER = { crit: 0, warn: 1, notice: 2, info: 3 };

  // Wave 4: three tabs. Advice left the info pane for the drawer (#chat-advice)
  // so there is exactly one advice surface, not two that can drift apart.
  var INFO_TABS = [
    { key: 'contents', label: 'Contents', panel: 'info-contents' },
    { key: 'packet', label: 'Packet Info', panel: 'info-packet' },
    { key: 'media', label: 'Media', panel: 'info-media' }
  ];

  var SEARCH_FIELDS = {
    call: 1, leg: 1, callid: 1, from: 1, to: 1, method: 1, status: 1,
    ip: 1, port: 1, codec: 1, proto: 1, sev: 1, has: 1
  };

  var IMS_HEADERS = ['p-charging-vector', 'p-charging-function-addresses', 'path',
    'service-route', 'p-associated-uri', 'p-access-network-info',
    'p-visited-network-id', 'p-early-media', 'p-preferred-identity', 'feature-caps'];

  var MAX_LADDER_ROWS = 1500;
  var SEARCH_CAP = 500;

  // Wave 3: remembers the upload dropzone's project choice across uploads.
  var UPLOAD_PROJECT_KEY = 'hiccup.upload.projectId';

  // ---------------------------------------------------------------- helpers

  function $(id) { return document.getElementById(id); }

  /** Create an element with optional class and textContent (never markup). */
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }

  function clear(node) { if (node) { while (node.firstChild) node.removeChild(node.firstChild); } }

  function arr(v) { return Array.isArray(v) ? v : []; }

  /** Array of real objects only — analysis arrays may contain nulls or scalars. */
  function objs(v) {
    var src = arr(v), out = [];
    for (var i = 0; i < src.length; i++) {
      if (src[i] && typeof src[i] === 'object') out.push(src[i]);
    }
    return out;
  }

  function str(v) { return v == null ? '' : String(v); }

  function isStr(v) { return typeof v === 'string' && v.length > 0; }

  function nnum(v) { return (typeof v === 'number' && isFinite(v)) ? v : null; }

  function p2(n) { return (n < 10 ? '0' : '') + n; }

  /** epoch-seconds float → HH:MM:SS.mmm local, or em-dash. */
  function fmtClock(ts) {
    var t = nnum(ts);
    if (t == null) return '—';
    var d = new Date(t * 1000);
    if (isNaN(d.getTime())) return '—';
    var ms = Math.floor((t - Math.floor(t)) * 1000);
    var p3 = (ms < 10 ? '00' : ms < 100 ? '0' : '') + ms;
    return p2(d.getHours()) + ':' + p2(d.getMinutes()) + ':' + p2(d.getSeconds()) + '.' + p3;
  }

  function fmtDateTime(iso) {
    if (!iso) return '—';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return str(iso);
    return d.getFullYear() + '-' + p2(d.getMonth() + 1) + '-' + p2(d.getDate()) +
      ' ' + p2(d.getHours()) + ':' + p2(d.getMinutes());
  }

  function fmtBytes(n) {
    var v = nnum(n);
    if (v == null) return '—';
    if (v < 1024) return v + ' B';
    if (v < 1024 * 1024) return (v / 1024).toFixed(1) + ' KB';
    return (v / (1024 * 1024)).toFixed(1) + ' MB';
  }

  function fmtNum(v, digits) {
    var n = nnum(v);
    if (n == null) return '—';
    return digits ? n.toFixed(digits) : String(n);
  }

  function sevChip(sev) { return el('span', 'chip sev-' + (sev || 'info'), sev || 'info'); }

  function sevRank(s) { return SEV_ORDER[s] == null ? 9 : SEV_ORDER[s]; }

  /** Strip the phone-shaped punctuation the contract lists, then keep digits. */
  function digitsOf(s) {
    return str(s).replace(/[+\-()\s.]/g, '').replace(/\D/g, '');
  }

  /** Best-effort user part of a SIP/SIPS/TEL URI (also handles name-addr form). */
  function uriUser(u) {
    var m = /(?:sips?|tel):([^@;>\s,]+)(?:@|$|[;>])/i.exec(str(u));
    return m ? m[1] : '';
  }

  function pathOf(o) {
    if (!o) return '—';
    return str(o.src == null ? '?' : o.src) + ':' + str(o.sport == null ? '?' : o.sport) +
      ' → ' + str(o.dst == null ? '?' : o.dst) + ':' + str(o.dport == null ? '?' : o.dport);
  }

  /** Debounce that never throws out of the timer. */
  function debounce(fn, ms) {
    var t = null;
    return function () {
      var args = arguments, self = this;
      if (t) clearTimeout(t);
      t = setTimeout(function () {
        t = null;
        try { fn.apply(self, args); } catch (e) { /* never break the UI */ }
      }, ms);
    };
  }

  /** Copy to clipboard with a legacy fallback; reports on the button itself. */
  function copyText(text, btn) {
    var original = btn ? btn.textContent : null;
    function done(ok) {
      if (!btn) return;
      btn.textContent = ok ? 'copied ✓' : 'copy failed';
      setTimeout(function () { btn.textContent = original; }, 1600);
    }
    function legacy() {
      try {
        var ta = document.createElement('textarea');
        ta.value = str(text);
        ta.setAttribute('readonly', 'readonly');
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand && document.execCommand('copy');
        document.body.removeChild(ta);
        done(!!ok);
      } catch (e) { done(false); }
    }
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(str(text)).then(function () { done(true); }, legacy);
        return;
      }
    } catch (e) { /* fall through */ }
    legacy();
  }

  /**
   * Append text to a parent, wrapping every occurrence of `terms` in
   * <mark class="hit">. All text goes through createTextNode.
   */
  function appendHighlighted(parent, text, terms) {
    var s = str(text);
    if (s.length > 400000) s = s.slice(0, 400000) + '\n… (truncated for display)';
    var list = [];
    for (var i = 0; i < arr(terms).length; i++) {
      var t = str(terms[i]).toLowerCase();
      if (t) list.push(t);
    }
    if (!list.length) { parent.appendChild(document.createTextNode(s)); return; }
    var low = s.toLowerCase();
    var ranges = [];
    for (var k = 0; k < list.length; k++) {
      var at = 0, guard = 0;
      while (guard++ < 8000) {
        var idx = low.indexOf(list[k], at);
        if (idx === -1) break;
        ranges.push([idx, idx + list[k].length]);
        at = idx + list[k].length;
      }
    }
    if (!ranges.length) { parent.appendChild(document.createTextNode(s)); return; }
    ranges.sort(function (a, b) { return a[0] - b[0]; });
    var merged = [];
    for (var r = 0; r < ranges.length; r++) {
      var last = merged[merged.length - 1];
      if (last && ranges[r][0] <= last[1]) last[1] = Math.max(last[1], ranges[r][1]);
      else merged.push([ranges[r][0], ranges[r][1]]);
    }
    var pos = 0;
    for (var mi = 0; mi < merged.length; mi++) {
      if (merged[mi][0] > pos) parent.appendChild(document.createTextNode(s.slice(pos, merged[mi][0])));
      parent.appendChild(el('mark', 'hit', s.slice(merged[mi][0], merged[mi][1])));
      pos = merged[mi][1];
    }
    if (pos < s.length) parent.appendChild(document.createTextNode(s.slice(pos)));
  }

  /**
   * Only http(s) links are ever put in an href — advice/KB citations are
   * hand-written server-side, but a javascript:/data: URL must never survive.
   * @returns {string|null} the safe URL, or null when it must not be a link
   */
  function safeHref(u) {
    var s = str(u).trim();
    if (!s) return null;
    return /^https?:\/\//i.test(s) ? s : null;
  }

  /** Shared empty-pane placeholder (.pane-empty comes from hiccup.css). */
  function emptyNote(parent, title, sub) {
    var box = el('div', 'pane-empty-wrap');
    box.appendChild(el('p', 'pane-empty', title));
    if (sub) box.appendChild(el('p', 'pane-empty', sub));
    if (parent) parent.appendChild(box);
    return box;
  }

  // ------------------------------------------------------------------ state

  var state = {
    user: null,
    llm: null,
    captures: [],
    captureId: null,
    analysis: null,

    // Wave 3: projects (folders within the shared capture library).
    projects: [],
    projectsInited: false,   // guards the one-time sessionStorage read below
    projectFilter: '',       // '' = all, 'unfiled' = unfiled only, else a project id
    uploadProjectId: '',     // '' = Unfiled; persisted in sessionStorage across uploads
    projectManageOpen: false,
    projectEditingId: null,  // project id currently showing its inline rename form
    projectBusy: false,      // guards double-submit on create/rename/delete

    msgById: {},
    legById: {},
    callById: {},
    findingById: {},
    msgToLeg: {},
    legToCall: {},
    msgToCall: {},
    collapseByMsg: {},
    adviceMsgIds: {},

    sel: { type: 'capture', callId: null, legId: null, txKey: null },
    selectedRowId: null,
    rows: [],
    rowById: {},
    scopeMsgs: [],
    truncatedRows: 0,
    pendingScope: null,

    treeExpanded: {},
    infoTab: 'contents',
    zoom: 1,
    selSort: { key: 'n', asc: true },

    searchQuery: '',
    searchTerms: [],
    searchHits: [],
    searchMatchIds: {},
    searchActive: false,
    searchTruncated: false,
    searchIndex: [],

    lampFilter: null,

    // Wave 4: the drawer is open on a fresh load. The flag survives because the
    // #chat-toggle button and body.chat-open still need to know the state — it
    // no longer gates whether the drawer's contents get rendered.
    chatOpen: true,
    chatBusy: false,
    chatError: null,

    // Wave 5A: which list j/k drives — 'tree' (#filter-tree) or 'selection'
    // (#selection-list). Set by whichever list last had a selection change;
    // the tree is the default before anything has been selected this session.
    keyList: 'tree',

    // Wave 5B: how many FRESH uploads are still resolving. Only uploadFile()
    // ever touches it — deliberately NOT a shared "app busy" flag, so an LLM
    // chat turn (state.chatBusy), a project write (state.projectBusy) or a
    // sidebar capture switch can never paint an upload skeleton. It is a
    // counter, not a boolean, because a second drop can land while the first
    // batch is still going.
    uploadsInFlight: 0,

    ladderSvg: null,
    ladderRowEls: {},
    selRowEls: {},
    gutterRowEls: {},
    sortBtns: [],
    toolbarOwn: true,
    scrollSyncWired: false
  };

  // ------------------------------------------------------------------- boot

  async function boot() {
    try {
      var r = await fetch('/api/me');
      if (r.status === 401) { location.href = '/'; return; }
      if (!r.ok) throw new Error('me failed');
      var j = await r.json();
      state.user = j.user || null;
    } catch (e) {
      location.href = '/';
      return;
    }
    var name = $('user-name');
    if (name && state.user) name.textContent = state.user.name || state.user.email || '';

    wireStatic();
    // On a narrow viewport the stacked layout has nowhere to put a fixed,
    // always-open drawer without covering the panes underneath (WCAG 2.2
    // §1.4.10 Reflow) -- start closed there, matching app.css's own
    // max-width: 1080px stacking breakpoint. Desktop keeps the Wave-4
    // default-open behaviour unchanged.
    if (isNarrowLayout()) {
      state.chatOpen = false;
    }
    applyDrawerOpen();   // reflect the default-open drawer without stealing focus
    fillRfplexPromo();
    ensureChatRfplexLine();
    pollStatus();
    setInterval(pollStatus, 60000);
    await loadProjects();
    await loadCaptures();
    renderAll();
  }

  async function pollStatus() {
    try {
      var r = await fetch('/api/status');
      if (!r.ok) throw new Error('status ' + r.status);
      var j = await r.json();
      state.llm = j.llm || null;
    } catch (e) {
      state.llm = null;
    }
    renderLlmChip();
    renderChat();   // model/offline state only — the scope has not moved
  }

  function renderLlmChip() {
    var chip = $('llm-chip');
    if (!chip) return;
    var llm = state.llm;
    if (llm && llm.available) {
      chip.textContent = 'LLM: ' + (llm.model || '?');
      chip.title = llm.source === 'rfplex'
        ? 'model chosen by RFPlex — hiccup shares the GPU with RFPlex'
        : 'local model available (source: ' + (llm.source || '?') + ')';
      chip.classList.remove('llm-off');
    } else {
      chip.textContent = 'LLM offline';
      chip.title = 'local model unavailable — every analysis feature still works';
      chip.classList.add('llm-off');
    }
  }

  // --------------------------------------------------------------- wiring

  function wireStatic() {
    var logout = $('logout-btn');
    if (logout) {
      logout.addEventListener('click', async function () {
        try { await fetch('/api/auth/logout', { method: 'POST' }); } catch (e) { /* ignore */ }
        location.href = '/';
      });
    }

    // Upload (drag-drop + file picker).
    var dz = $('dropzone');
    var input = $('file-input');
    var browse = $('browse-btn');
    if (browse && input) browse.addEventListener('click', function () { input.click(); });
    if (input) {
      input.addEventListener('change', function () {
        uploadFiles(input.files);
        input.value = '';
      });
    }
    if (dz) {
      dz.addEventListener('dragover', function (ev) { ev.preventDefault(); dz.classList.add('drag'); });
      dz.addEventListener('dragleave', function () { dz.classList.remove('drag'); });
      dz.addEventListener('drop', function (ev) {
        ev.preventDefault();
        dz.classList.remove('drag');
        if (ev.dataTransfer && ev.dataTransfer.files) uploadFiles(ev.dataTransfer.files);
      });
    }

    // Project filter + upload project picker + manage-projects panel (Wave 3).
    var projectFilterSel = $('project-filter');
    if (projectFilterSel) {
      projectFilterSel.addEventListener('change', function () {
        state.projectFilter = projectFilterSel.value || '';
        loadCaptures();
      });
    }

    var uploadProjectSel = $('upload-project');
    if (uploadProjectSel) {
      uploadProjectSel.addEventListener('change', function () {
        state.uploadProjectId = uploadProjectSel.value || '';
        try { sessionStorage.setItem(UPLOAD_PROJECT_KEY, state.uploadProjectId); }
        catch (e) { /* private mode / quota */ }
      });
    }

    var pmToggle = $('project-manage-toggle');
    if (pmToggle) pmToggle.addEventListener('click', function () { toggleProjectManage(); });
    var pmClose = $('project-manage-close');
    if (pmClose) pmClose.addEventListener('click', function () { toggleProjectManage(false); });

    var pmForm = $('project-create-form');
    if (pmForm) {
      pmForm.addEventListener('submit', function (ev) {
        ev.preventDefault();
        createProject();
      });
    }

    // Chat drawer.
    var ct = $('chat-toggle');
    if (ct) ct.addEventListener('click', function () { toggleChat(!state.chatOpen); });
    var cc = $('chat-close');
    if (cc) cc.addEventListener('click', function () { toggleChat(false); });
    var cf = $('chat-form');
    if (cf) cf.addEventListener('submit', function (ev) { ev.preventDefault(); submitChat(); });
    var ci = $('chat-input');
    if (ci) {
      ci.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter' && !ev.shiftKey) { ev.preventDefault(); submitChat(); }
      });
    }

    wireSearchbar();
    setupInfoTabs();
    setupLadderToolbar();
    setupSelectionSort();
    setupPaneActions();
    setupKeyboardLayer();   // Wave 5A: the one app-wide keydown listener

    // Wave 4: the scenario chip is a capture-level read-out, so it widens the
    // scope back to the whole capture and hands focus to the drawer's advice.
    var chip = $('scenario-chip');
    if (chip) {
      chip.addEventListener('click', function () {
        state.sel = { type: 'capture', callId: null, legId: null, txKey: null };
        state.selectedRowId = null;
        state.lampFilter = null;
        renderAll();
        focusDrawerAdvice();
      });
    }
  }

  function fillRfplexPromo() {
    var box = $('rfplex-promo');
    if (!box || box.firstChild) return;   // the shell may already have built it
    box.appendChild(el('p', 'promo-kicker', 'Also from the same workshop:'));
    var line = el('p', 'promo-body');
    var a = el('a', 'promo-link', 'RFPlex.ai');
    a.href = RFPLEX_URL;
    a.target = '_blank';
    a.rel = 'noopener';
    line.appendChild(a);
    line.appendChild(document.createTextNode(
      ' — AI that answers RFPs, RFIs and DDQs from your own document library. ' +
      'Self-hosted, EU-sovereign, free during beta.'));
    box.appendChild(line);
  }

  function ensureChatRfplexLine() {
    var drawer = $('chat-drawer');
    if (!drawer || $('chat-rfplex')) return;
    // app.html may already ship the line (.chat-crosslink) — don't duplicate it.
    if (drawer.querySelector && drawer.querySelector('.chat-crosslink')) return;
    if (str(drawer.textContent).indexOf('local-LLM stack') !== -1) return;
    var line = el('p', 'chat-crosslink muted');
    line.id = 'chat-rfplex';
    line.appendChild(document.createTextNode('hiccup and '));
    var a = el('a', null, 'RFPlex.ai');
    a.href = RFPLEX_URL;
    a.target = '_blank';
    a.rel = 'noopener';
    line.appendChild(a);
    line.appendChild(document.createTextNode(' share the same local-LLM stack.'));
    var msgs = $('chat-messages');
    if (msgs && msgs.parentNode) msgs.parentNode.insertBefore(line, msgs);
    else drawer.appendChild(line);
  }

  // --------------------------------------------------------------- captures

  async function loadCaptures() {
    try {
      var url = '/api/captures';
      var q = state.projectFilter === 'unfiled' ? 'unfiled'
        : (state.projectFilter ? encodeURIComponent(state.projectFilter) : '');
      if (q) url += '?project=' + q;
      var r = await fetch(url);
      if (!r.ok) throw new Error('captures ' + r.status);
      var j = await r.json();
      state.captures = arr(j);
    } catch (e) {
      state.captures = [];
    }
    renderSidebar();
  }

  function setUploadMsg(text, isError) {
    var m = $('upload-msg');
    if (!m) return;
    if (!text) { m.hidden = true; m.textContent = ''; return; }
    m.hidden = false;
    m.textContent = text;
    m.classList.toggle('err', !!isError);
  }

  async function uploadFiles(fileList) {
    var files = Array.prototype.slice.call(fileList || []);
    for (var i = 0; i < files.length; i++) await uploadFile(files[i]);
  }

  async function uploadFile(file) {
    if (!file) return;
    setUploadMsg('Analysing ' + file.name + ' …');
    // Wave 5B: skeletons for THIS upload only, raised with the busy text and
    // dropped in the finally below — which is what guarantees a 422/413/network
    // failure falls back to the normal empty state instead of hanging on a
    // placeholder. Nothing else in the app can raise them.
    beginUploadSkeletons();
    try {
      var buf = await file.arrayBuffer();
      var headers = { 'X-Filename': file.name };
      // Unfiled (the default) omits the header entirely — the capture just
      // gets projectId: null server-side, same as before projects existed.
      if (state.uploadProjectId) headers['X-Project-Id'] = state.uploadProjectId;
      var r = await fetch('/api/captures', {
        method: 'POST',
        headers: headers,
        body: buf
      });
      var j = null;
      try { j = await r.json(); } catch (e) { /* non-json */ }
      if (!r.ok) {
        setUploadMsg((j && j.error) || ('Upload failed (' + r.status + ')'), true);
        return;
      }
      setUploadMsg('');
      await loadCaptures();
      // Awaited (it used to be fire-and-forget) so the skeletons hand straight
      // over to the rendered capture rather than being torn down first and
      // flashing the previous capture, or an empty pane, in between.
      if (j && j.id) await openCapture(j.id);
    } catch (e) {
      setUploadMsg('Upload failed: ' + (e && e.message ? e.message : 'network error'), true);
    } finally {
      endUploadSkeletons();
    }
  }

  async function deleteCapture(cap) {
    if (!cap) return;
    if (!confirm('Delete "' + cap.filename + '"? This removes the capture and its analysis.')) return;
    try {
      var r = await fetch('/api/captures/' + encodeURIComponent(cap.id), { method: 'DELETE' });
      if (!r.ok) throw new Error('delete ' + r.status);
    } catch (e) {
      alert('Delete failed.');
      return;
    }
    if (state.captureId === cap.id) {
      state.captureId = null;
      state.analysis = null;
      resetSelection();
      indexAnalysis();
      renderAll();
    }
    await loadCaptures();
  }

  function renderSidebar() {
    var list = $('capture-list');
    if (!list) return;
    clear(list);
    if (!state.captures.length) {
      if (state.projectFilter) {
        emptyNote(list, 'No captures match this filter.',
          'Choose a different project, or clear the filter to see everything.');
      } else {
        emptyNote(list, 'No captures yet.',
          'Upload a pcap, pcapng, or an SBC log / SIP text export to get started.');
      }
      return;
    }
    for (var i = 0; i < state.captures.length; i++) {
      (function (cap) {
        var row = el('div', 'capture-row' + (cap.id === state.captureId ? ' active' : ''));
        var top = el('div', 'cap-top');
        top.appendChild(el('span', 'cap-name', cap.filename));
        // .icon-btn: WCAG 2.2 SC 2.5.8 hit area for a glyph-only control
        var del = el('button', 'cap-del icon-btn', '×');
        del.type = 'button';
        del.title = 'delete capture';
        del.addEventListener('click', function (ev) { ev.stopPropagation(); deleteCapture(cap); });
        top.appendChild(del);
        row.appendChild(top);

        row.appendChild(el('div', 'cap-sub mono',
          fmtDateTime(cap.uploadedAt) + ' · ' + fmtBytes(cap.sizeBytes)));

        var stats = cap.stats || {};
        row.appendChild(el('div', 'cap-stats mono',
          (stats.sipMessages || 0) + ' SIP · ' + (stats.h323Messages || 0) + ' H.323 · ' +
          (stats.calls || 0) + ' calls'));

        var fc = cap.findingCounts || {};
        var chips = el('div', 'cap-chips');
        var sevs = ['crit', 'warn', 'notice', 'info'];
        for (var s = 0; s < sevs.length; s++) {
          if (fc[sevs[s]]) chips.appendChild(el('span', 'chip sev-' + sevs[s], String(fc[sevs[s]])));
        }
        if (chips.firstChild) row.appendChild(chips);

        row.addEventListener('click', function () { openCapture(cap.id); });
        list.appendChild(row);
      })(state.captures[i]);
    }
  }

  // -------------------------------------------------------- projects (Wave 3)

  /**
   * Projects are folders within the team's shared capture library (or the
   * solo user's own — accountUid() makes no client-visible difference).
   * GET /api/projects drives #project-filter (scopes the existing
   * GET /api/captures call via ?project=) and the upload dropzone's project
   * picker (sets X-Project-Id on POST /api/captures, omitted for Unfiled).
   */

  async function loadProjects() {
    try {
      var r = await fetch('/api/projects');
      if (r.status === 401) { location.href = '/'; return; }
      if (!r.ok) throw new Error('projects ' + r.status);
      var j = await r.json();
      state.projects = arr(j);
    } catch (e) {
      state.projects = [];
    }

    if (!state.projectsInited) {
      state.projectsInited = true;
      try {
        var saved = sessionStorage.getItem(UPLOAD_PROJECT_KEY);
        if (saved) state.uploadProjectId = saved;
      } catch (e) { /* private mode / quota */ }
    }

    // Self-heal: a remembered/selected project may have been deleted
    // elsewhere (another tab, or this tab's own manage-projects panel).
    if (state.uploadProjectId && !projectExists(state.uploadProjectId)) {
      state.uploadProjectId = '';
      try { sessionStorage.removeItem(UPLOAD_PROJECT_KEY); } catch (e) { /* ignore */ }
    }
    if (state.projectFilter && state.projectFilter !== 'unfiled' && !projectExists(state.projectFilter)) {
      state.projectFilter = '';
    }

    renderProjectFilter();
    renderUploadProjectPicker();
    if (state.projectManageOpen) renderProjectManagePanel();
  }

  function projectExists(id) {
    for (var i = 0; i < state.projects.length; i++) {
      if (state.projects[i] && state.projects[i].id === id) return true;
    }
    return false;
  }

  function renderProjectFilter() {
    var sel = $('project-filter');
    if (!sel) return;
    clear(sel);
    var all = el('option', null, 'All captures');
    all.value = '';
    sel.appendChild(all);
    var unfiled = el('option', null, 'Unfiled');
    unfiled.value = 'unfiled';
    sel.appendChild(unfiled);
    for (var i = 0; i < state.projects.length; i++) {
      var p = state.projects[i];
      if (!p || !isStr(p.id)) continue;
      var o = el('option', null, p.name || p.id);
      o.value = p.id;
      sel.appendChild(o);
    }
    sel.value = state.projectFilter || '';
  }

  function renderUploadProjectPicker() {
    var sel = $('upload-project');
    if (!sel) return;
    clear(sel);
    var unfiled = el('option', null, 'Unfiled');
    unfiled.value = '';
    sel.appendChild(unfiled);
    for (var i = 0; i < state.projects.length; i++) {
      var p = state.projects[i];
      if (!p || !isStr(p.id)) continue;
      var o = el('option', null, p.name || p.id);
      o.value = p.id;
      sel.appendChild(o);
    }
    sel.value = state.uploadProjectId || '';
  }

  function setProjectManageMsg(text, isError) {
    var m = $('project-manage-msg');
    if (!m) return;
    m.textContent = text || '';
    m.classList.toggle('err', !!isError);
  }

  function toggleProjectManage(open) {
    state.projectManageOpen = (open === undefined) ? !state.projectManageOpen : !!open;
    var panel = $('project-manage-panel');
    if (panel) panel.hidden = !state.projectManageOpen;
    // Wave 5A: the panel covers the sidebar (and nearly the whole viewport below
    // the stacking breakpoint), so while it is open it owns focus — otherwise
    // Tab walks into the controls it is sitting on top of (WCAG 2.2 §2.4.11).
    var trap = projectManageTrap();
    if (state.projectManageOpen) {
      state.projectEditingId = null;
      setProjectManageMsg('');
      renderProjectManagePanel();
      if (trap && !trap.active()) trap.activate({ returnTo: $('project-manage-toggle') });
    } else if (trap && trap.active()) {
      trap.release();
    }
  }

  function renderProjectManagePanel() {
    var host = $('project-manage-list');
    if (!host) return;
    clear(host);
    if (!state.projects.length) {
      emptyNote(host, 'No projects yet.', 'Create one below to start filing captures.');
      return;
    }
    for (var i = 0; i < state.projects.length; i++) {
      var p = state.projects[i];
      if (!p || !isStr(p.id)) continue;
      host.appendChild(state.projectEditingId === p.id ? projectEditRow(p) : projectRow(p));
    }
  }

  function projectRow(p) {
    var row = el('div', 'pm-row');
    var head = el('div', 'pm-row-head');
    head.appendChild(el('span', 'pm-row-name', p.name || p.id));
    var count = (typeof p.captureCount === 'number' && isFinite(p.captureCount)) ? p.captureCount : 0;
    head.appendChild(el('span', 'chip pm-row-count', count + (count === 1 ? ' capture' : ' captures')));
    row.appendChild(head);
    if (isStr(p.description)) row.appendChild(el('div', 'pm-row-desc', p.description));

    var actions = el('div', 'pm-row-actions');
    var rename = el('button', 'btn', 'Rename');
    rename.type = 'button';
    rename.addEventListener('click', function () {
      state.projectEditingId = p.id;
      renderProjectManagePanel();
    });
    actions.appendChild(rename);

    var del = el('button', 'btn', 'Delete');
    del.type = 'button';
    del.addEventListener('click', function () { deleteProject(p, del); });
    actions.appendChild(del);

    row.appendChild(actions);
    return row;
  }

  function projectEditRow(p) {
    var wrap = el('div', 'pm-edit-row');

    var nameInput = el('input', 'input');
    nameInput.type = 'text';
    nameInput.maxLength = 80;
    nameInput.value = p.name || '';
    nameInput.setAttribute('aria-label', 'project name');
    wrap.appendChild(nameInput);

    var descInput = el('input', 'input');
    descInput.type = 'text';
    descInput.placeholder = 'Description (optional)';
    descInput.value = p.description || '';
    descInput.setAttribute('aria-label', 'project description');
    wrap.appendChild(descInput);

    var actions = el('div', 'pm-edit-actions');
    var save = el('button', 'btn btn-primary', 'Save');
    save.type = 'button';
    save.addEventListener('click', function () {
      var name = (nameInput.value || '').trim();
      if (!name) { setProjectManageMsg('Enter a project name.', true); return; }
      renameProject(p, name, (descInput.value || '').trim(), save);
    });
    actions.appendChild(save);

    var cancel = el('button', 'btn', 'Cancel');
    cancel.type = 'button';
    cancel.addEventListener('click', function () {
      state.projectEditingId = null;
      renderProjectManagePanel();
    });
    actions.appendChild(cancel);

    wrap.appendChild(actions);
    return wrap;
  }

  async function createProject() {
    if (state.projectBusy) return;
    var nameInput = $('project-create-name');
    var descInput = $('project-create-desc');
    var name = ((nameInput && nameInput.value) || '').trim();
    if (!name) { setProjectManageMsg('Enter a project name.', true); return; }

    var form = $('project-create-form');
    var btn = form ? form.querySelector('button[type="submit"]') : null;

    state.projectBusy = true;
    if (btn) { btn.disabled = true; btn.textContent = 'Creating…'; }
    setProjectManageMsg('');
    var res = null, payload = null;
    try {
      res = await fetch('/api/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name, description: ((descInput && descInput.value) || '').trim() })
      });
      if (res.status === 401) { location.href = '/'; return; }
      try { payload = await res.json(); } catch (e) { payload = null; }
    } catch (e) {
      state.projectBusy = false;
      if (btn) { btn.disabled = false; btn.textContent = 'Create project'; }
      setProjectManageMsg('Could not reach the server.', true);
      return;
    }
    state.projectBusy = false;
    if (btn) { btn.disabled = false; btn.textContent = 'Create project'; }
    if (!res.ok) {
      setProjectManageMsg((payload && (payload.error || payload.userMessage)) ||
        ('Could not create the project (status ' + res.status + ').'), true);
      return;
    }
    if (nameInput) nameInput.value = '';
    if (descInput) descInput.value = '';
    setProjectManageMsg('Created ' + name + '.');
    await loadProjects();
    await loadCaptures();
  }

  async function renameProject(p, name, description, btn) {
    if (state.projectBusy) return;
    state.projectBusy = true;
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    setProjectManageMsg('');
    var res = null, payload = null;
    try {
      res = await fetch('/api/projects/' + encodeURIComponent(p.id), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name, description: description })
      });
      if (res.status === 401) { location.href = '/'; return; }
      try { payload = await res.json(); } catch (e) { payload = null; }
    } catch (e) {
      state.projectBusy = false;
      if (btn) { btn.disabled = false; btn.textContent = 'Save'; }
      setProjectManageMsg('Could not reach the server.', true);
      return;
    }
    state.projectBusy = false;
    if (!res.ok) {
      if (btn) { btn.disabled = false; btn.textContent = 'Save'; }
      setProjectManageMsg((payload && (payload.error || payload.userMessage)) ||
        ('Could not rename the project (status ' + res.status + ').'), true);
      return;
    }
    state.projectEditingId = null;
    setProjectManageMsg('Saved.');
    await loadProjects();
    await loadCaptures();
  }

  async function deleteProject(p, btn) {
    if (state.projectBusy) return;
    if (!confirm('Delete project "' + (p.name || p.id) + '"? Its captures will become ' +
      'Unfiled, not deleted.')) return;

    state.projectBusy = true;
    if (btn) { btn.disabled = true; btn.textContent = 'Deleting…'; }
    setProjectManageMsg('');
    var res = null, payload = null;
    try {
      res = await fetch('/api/projects/' + encodeURIComponent(p.id), { method: 'DELETE' });
      if (res.status === 401) { location.href = '/'; return; }
      try { payload = await res.json(); } catch (e) { payload = null; }
    } catch (e) {
      state.projectBusy = false;
      if (btn) { btn.disabled = false; btn.textContent = 'Delete'; }
      setProjectManageMsg('Could not reach the server.', true);
      return;
    }
    state.projectBusy = false;
    if (!res.ok) {
      if (btn) { btn.disabled = false; btn.textContent = 'Delete'; }
      setProjectManageMsg((payload && (payload.error || payload.userMessage)) ||
        ('Could not delete the project (status ' + res.status + ').'), true);
      return;
    }
    if (state.uploadProjectId === p.id) {
      state.uploadProjectId = '';
      try { sessionStorage.removeItem(UPLOAD_PROJECT_KEY); } catch (e) { /* ignore */ }
    }
    if (state.projectFilter === p.id) state.projectFilter = '';
    setProjectManageMsg('Deleted ' + (p.name || p.id) + '.');
    await loadProjects();
    await loadCaptures();
  }

  function resetSelection() {
    state.sel = { type: 'capture', callId: null, legId: null, txKey: null };
    state.selectedRowId = null;
    state.lampFilter = null;
    state.treeExpanded = {};
    state.infoTab = 'contents';
    state.searchQuery = '';
    state.searchTerms = [];
    state.searchHits = [];
    state.searchMatchIds = {};
    state.searchActive = false;
    state.searchTruncated = false;
    state.searchIndex = [];
    var si = $('search-input');
    if (si) si.value = '';
  }

  async function openCapture(id) {
    var host = $('ladder-svg-host');
    // Wave 5B: a fresh upload already has its ladder skeleton in this host —
    // don't downgrade it to a plain note halfway through that flow. The other
    // caller (a sidebar capture switch) is unaffected and keeps the note.
    if (host && !uploadPending()) { clear(host); emptyNote(host, 'Loading analysis…'); }
    try {
      var r = await fetch('/api/captures/' + encodeURIComponent(id) + '/analysis');
      if (!r.ok) throw new Error('analysis ' + r.status);
      state.analysis = await r.json();
    } catch (e) {
      state.analysis = null;
      if (host) { clear(host); emptyNote(host, 'Could not load the analysis for this capture.'); }
      return;
    }
    state.captureId = id;
    resetSelection();
    indexAnalysis();
    buildSearchIndex();
    renderSidebar();
    renderAll();
  }

  // -------------------------------------------------------- analysis index

  function indexAnalysis() {
    state.msgById = {};
    state.legById = {};
    state.callById = {};
    state.findingById = {};
    state.msgToLeg = {};
    state.legToCall = {};
    state.msgToCall = {};
    state.collapseByMsg = {};
    state.adviceMsgIds = {};

    var a = state.analysis;
    if (!a) return;
    var i, j, ids;

    var msgs = arr(a.messages);
    for (i = 0; i < msgs.length; i++) { if (msgs[i] && msgs[i].id) state.msgById[msgs[i].id] = msgs[i]; }

    var legs = arr(a.legs);
    for (i = 0; i < legs.length; i++) {
      var leg = legs[i];
      if (!leg || !leg.id) continue;
      state.legById[leg.id] = leg;
      ids = arr(leg.msgIds);
      for (j = 0; j < ids.length; j++) state.msgToLeg[ids[j]] = leg.id;
    }

    var calls = arr(a.calls);
    for (i = 0; i < calls.length; i++) {
      var call = calls[i];
      if (!call || !call.id) continue;
      state.callById[call.id] = call;
      ids = arr(call.legIds);
      for (j = 0; j < ids.length; j++) state.legToCall[ids[j]] = call.id;
    }

    for (var mid in state.msgToLeg) {
      if (Object.prototype.hasOwnProperty.call(state.msgToLeg, mid)) {
        var cid = state.legToCall[state.msgToLeg[mid]];
        if (cid) state.msgToCall[mid] = cid;
      }
    }

    var findings = arr(a.findings);
    for (i = 0; i < findings.length; i++) { if (findings[i] && findings[i].id) state.findingById[findings[i].id] = findings[i]; }

    var collapses = (a.retrans && arr(a.retrans.collapses)) || [];
    for (i = 0; i < collapses.length; i++) {
      ids = arr(collapses[i] && collapses[i].msgIds);
      for (j = 0; j < ids.length; j++) state.collapseByMsg[ids[j]] = collapses[i];
    }

    var advice = arr(a.advice);
    for (i = 0; i < advice.length; i++) {
      var fids = arr(advice[i] && advice[i].findingIds);
      for (j = 0; j < fids.length; j++) {
        var f = state.findingById[fids[j]];
        if (!f) continue;
        var mids = arr(f.msgIds);
        for (var k = 0; k < mids.length; k++) state.adviceMsgIds[mids[k]] = true;
      }
    }
  }

  function mediaStreams() {
    var a = state.analysis;
    if (!a || !a.media) return [];
    return objs(Array.isArray(a.media) ? a.media : a.media.streams);
  }

  function rtcpReports() {
    var a = state.analysis;
    if (!a || !a.media || Array.isArray(a.media)) return [];
    return objs(a.media.rtcp);
  }

  function auxMessages() { return objs(state.analysis && state.analysis.aux); }

  function indicators() { return objs(state.analysis && state.analysis.indicators); }

  function adviceList() { return objs(state.analysis && state.analysis.advice); }

  function findingsList() { return objs(state.analysis && state.analysis.findings); }

  function collapsesList() {
    var a = state.analysis;
    return (a && a.retrans) ? objs(a.retrans.collapses) : [];
  }

  /** Stable transaction key for the filter tree (SIP CSeq, H.323 message type). */
  function txKeyOf(m) {
    if (!m) return 'tx:?';
    if (m.protocol === 'h323' || m.q931Type) {
      return 'q931:' + str(m.q931Type || '?') + ':' + str(m.callRef == null ? '' : m.callRef);
    }
    var c = m.cseq || {};
    return 'cseq:' + str(c.num == null ? '?' : c.num) + ':' + str(c.method || m.method || '?');
  }

  function callOf(o, kind) {
    if (!o) return null;
    if (kind === 'msg') return state.msgToCall[o.id] || null;
    var cids = arr(o.callIds);
    if (cids.length) return cids[0];
    var lids = arr(o.legIds);
    for (var i = 0; i < lids.length; i++) {
      if (state.legToCall[lids[i]]) return state.legToCall[lids[i]];
    }
    return null;
  }

  function legOfCall(callId) {
    var call = state.callById[callId];
    if (!call) return [];
    var out = [];
    var ids = arr(call.legIds);
    for (var i = 0; i < ids.length; i++) { if (state.legById[ids[i]]) out.push(state.legById[ids[i]]); }
    return out;
  }

  function callProtocolLabel(call) {
    if (!call) return 'SIP';
    if (call.type === 'sip-sip') return 'SIP↔SIP';
    if (call.type === 'sip-h323') return 'SIP↔H.323';
    var leg = state.legById[arr(call.legIds)[0]];
    return leg && leg.protocol === 'h323' ? 'H.323' : 'SIP';
  }

  /**
   * Findings AND advice, both read for tree-edge severity: some advisor rules
   * (e.g. the indicator-issue catch-all) go straight from detection to an
   * Advice card with no backing Finding, so Advice must count on its own too
   * — see the equivalent fallback in ladder.js's buildSeverityMap().
   */
  function findingsAndAdvice() { return findingsList().concat(adviceList()); }

  /**
   * Worst severity ('crit' | 'warn' | null) tied to this call, directly or via
   * any of its legs — drives the tree's red/amber left-edge marker so a
   * problem call is visible without expanding it. Crit always wins over warn.
   */
  function worstSeverityForCall(callId) {
    var fs = findingsAndAdvice();
    var call = state.callById[callId];
    var legIds = call ? arr(call.legIds) : [];
    var worst = null;
    for (var i = 0; i < fs.length; i++) {
      var f = fs[i];
      if (!f || (f.severity !== 'crit' && f.severity !== 'warn')) continue;
      var hit = arr(f.callIds).indexOf(callId) !== -1;
      if (!hit) {
        var lids = arr(f.legIds);
        for (var j = 0; j < lids.length && !hit; j++) { if (legIds.indexOf(lids[j]) !== -1) hit = true; }
      }
      if (!hit) continue;
      if (f.severity === 'crit') return 'crit';
      worst = 'warn';
    }
    return worst;
  }

  /** Same idea as worstSeverityForCall(), scoped to a single leg. */
  function worstSeverityForLeg(legId) {
    var fs = findingsAndAdvice();
    var worst = null;
    for (var i = 0; i < fs.length; i++) {
      var f = fs[i];
      if (!f || (f.severity !== 'crit' && f.severity !== 'warn')) continue;
      if (arr(f.legIds).indexOf(legId) === -1) continue;
      if (f.severity === 'crit') return 'crit';
      worst = 'warn';
    }
    return worst;
  }

  function legRetransCount(legId) {
    var n = 0;
    var cs = collapsesList();
    for (var i = 0; i < cs.length; i++) {
      if (cs[i] && cs[i].legId === legId) n += (nnum(cs[i].count) || arr(cs[i].msgIds).length);
    }
    return n;
  }

  // ------------------------------------------------------- scope → row set

  /** Message ids that belong to the current scope (before the lamp filter). */
  function scopeMessages() {
    var a = state.analysis;
    if (!a) return [];
    var all = arr(a.messages);
    var sel = state.sel;
    if (sel.type === 'capture') return all;

    var legIds = {};
    if (sel.type === 'call') {
      var call = state.callById[sel.callId];
      var ids = call ? arr(call.legIds) : [];
      for (var i = 0; i < ids.length; i++) legIds[ids[i]] = true;
    } else if (sel.legId) {
      legIds[sel.legId] = true;
    }
    var out = [];
    for (var k = 0; k < all.length; k++) {
      var m = all[k];
      if (!m || !m.id) continue;
      var lid = state.msgToLeg[m.id];
      if (!legIds[lid]) continue;
      if (sel.type === 'transaction' && sel.txKey && txKeyOf(m) !== sel.txKey) continue;
      out.push(m);
    }
    return out;
  }

  function scopeLegIds() {
    var sel = state.sel;
    if (sel.type === 'call') {
      var call = state.callById[sel.callId];
      return call ? arr(call.legIds) : [];
    }
    if (sel.legId) return [sel.legId];
    return null;   // capture scope = everything
  }

  function matchesScopeAssoc(o) {
    var legIds = scopeLegIds();
    if (!legIds) return true;
    var sel = state.sel;
    var cids = arr(o && o.callIds);
    if (sel.type === 'call' && cids.indexOf(sel.callId) !== -1) return true;
    var lids = arr(o && o.legIds);
    for (var i = 0; i < lids.length; i++) { if (legIds.indexOf(lids[i]) !== -1) return true; }
    return false;
  }

  function activeLamp() {
    if (!state.lampFilter) return null;
    var inds = indicators();
    for (var i = 0; i < inds.length; i++) {
      if (inds[i] && inds[i].key === state.lampFilter) return inds[i];
    }
    return null;
  }

  /** Rebuild state.rows for the current scope + lamp filter. */
  function buildScopedRows() {
    var L = window.Ladder;
    var msgs = scopeMessages();
    var streams = mediaStreams().filter(matchesScopeAssoc);
    var auxes = auxMessages().filter(matchesScopeAssoc);

    var lamp = activeLamp();
    if (lamp) {
      var evMsg = {}, evCall = {};
      var em = arr(lamp.evidenceMsgIds), ec = arr(lamp.evidenceCallIds);
      var i;
      for (i = 0; i < em.length; i++) evMsg[em[i]] = true;
      for (i = 0; i < ec.length; i++) evCall[ec[i]] = true;
      var anyEvidence = em.length || ec.length;
      if (anyEvidence) {
        msgs = msgs.filter(function (m) {
          return evMsg[m.id] || (state.msgToCall[m.id] && evCall[state.msgToCall[m.id]]);
        });
        streams = streams.filter(function (s) {
          var c = callOf(s, 'media');
          return (c && evCall[c]) || false;
        });
        auxes = auxes.filter(function (x) {
          var c = callOf(x, 'aux');
          return (c && evCall[c]) || false;
        });
      }
    }

    var built = (L && typeof L.buildRows === 'function')
      ? L.buildRows({
        messages: msgs,
        collapses: collapsesList(),
        media: streams,
        aux: auxes,
        findings: findingsList(),
        advice: adviceList(),
        collapsed: true            // Wave 4: always collapsed, no user-facing toggle
      })
      : { rows: [] };

    state.scopeMsgs = msgs;
    var rows = arr(built.rows);
    state.truncatedRows = 0;
    if (rows.length > MAX_LADDER_ROWS) {
      state.truncatedRows = rows.length - MAX_LADDER_ROWS;
      rows = rows.slice(0, MAX_LADDER_ROWS);
    }
    for (var r = 0; r < rows.length; r++) {
      if (rows[r].kind === 'msg') rows[r].legId = state.msgToLeg[rows[r].id] || null;
    }
    state.rows = rows;
    state.rowById = {};
    for (var q = 0; q < rows.length; q++) state.rowById[rows[q].rowId] = rows[q];
    if (state.selectedRowId && !state.rowById[state.selectedRowId]) state.selectedRowId = null;
  }

  // ------------------------------------------------------------ render all

  function renderAll() {
    buildScopedRows();
    renderLamps();
    renderScenarioChip();
    if (state.searchActive) renderSearchResults(); else renderFilterTree();
    renderSelectionList();
    renderLadder();
    renderInfo();
    renderDrawer();
    renderSearchCount();
  }

  /** Re-render everything that depends on the current selection (not the tree). */
  function renderSelectionDependent() {
    buildScopedRows();
    renderSelectionList();
    renderLadder();
    renderInfo();
    renderDrawer();
  }

  /**
   * The drawer is scope-dependent on both halves now: the advice section
   * re-renders for the new selection, the conversation re-renders its scope
   * chip. Every selection path funnels through here (Wave 4 step 3/4).
   */
  function renderDrawer() {
    renderDrawerAdvice();
    renderChat();
  }

  // ------------------------------------------- Wave 5B: upload skeletons ---

  /*
   * Shape-matched placeholders for the gap between a fresh upload starting and
   * its capture being on screen. Three panes get one (#filter-tree,
   * #ladder-svg-host, #selection-list); #upload-msg keeps its own status text
   * unchanged — these are additive to it, not a replacement.
   *
   * Scope is deliberately narrow. beginUploadSkeletons() has exactly one
   * caller, uploadFile(), so switching between already-loaded captures in the
   * sidebar stays instant (openCapture keeps its plain "Loading analysis…"
   * note) and nothing else in the app can trigger a skeleton.
   *
   * The ladder placeholder is its own simple DOM, NOT a mode of ladder.js — it
   * is drawn before Ladder.render() is ever called for the incoming capture.
   */

  var SKEL_HOST_IDS = ['filter-tree', 'ladder-svg-host', 'selection-list'];

  /** One placeholder bar. `w` is any CSS width, `cls` an extra shape class. */
  function skelBar(cls, w) {
    var b = el('span', 'skel-bar' + (cls ? ' ' + cls : ''));
    if (w) b.style.width = w;
    return b;
  }

  /** Skeleton root. Decorative — #upload-msg carries the real status text. */
  function skelRoot(tag, cls) {
    var root = el(tag, 'skel ' + cls);
    root.setAttribute('data-skeleton', '1');
    root.setAttribute('aria-hidden', 'true');
    return root;
  }

  /** #filter-tree: an indented label bar + a shorter sub-label bar, x4. */
  function skeletonTree(host) {
    // indent px / label width / sub width — a root, two calls and a leg, so
    // the block reads as a tree rather than a stack of identical bars.
    var shape = [[0, '58%', '38%'], [12, '72%', '46%'], [12, '63%', '41%'], [26, '51%', '32%']];
    var root = skelRoot('div', 'skel-tree');
    for (var i = 0; i < shape.length; i++) {
      var row = el('div', 'skel-row skel-tree-row');
      row.style.marginLeft = shape[i][0] + 'px';
      row.appendChild(skelBar('skel-tree-label', shape[i][1]));
      row.appendChild(skelBar('skel-tree-sub', shape[i][2]));
      root.appendChild(row);
    }
    host.appendChild(root);
  }

  /**
   * #ladder-svg-host: the host-column header band (46px — ladder.js TOP) over
   * faint row bars on the real 26px pitch (ladder.js ROWH), alternating sides
   * so it echoes request/response arrows without claiming to show real data.
   */
  function skeletonLadder(host) {
    var root = skelRoot('div', 'skel-ladder');

    var head = el('div', 'skel-lad-head');
    var cols = ['76px', '92px', '68px'];
    for (var c = 0; c < cols.length; c++) head.appendChild(skelBar('skel-lad-col', cols[c]));
    root.appendChild(head);

    var body = el('div', 'skel-lad-rows');
    var widths = ['62%', '47%', '71%', '39%', '58%', '34%'];
    for (var i = 0; i < widths.length; i++) {
      var row = el('div', 'skel-row skel-lad-row' + (i % 2 ? ' is-rtl' : ''));
      row.appendChild(skelBar('skel-lad-line', widths[i]));
      body.appendChild(row);
    }
    root.appendChild(body);

    host.appendChild(root);
  }

  /**
   * #selection-list: the numbered-table shape — a number-width bar, a longer
   * description bar, a short delta bar. Handles both host shapes app.js
   * already supports (see selectionHost).
   */
  function skeletonSelection(target) {
    var widths = ['78%', '63%', '87%', '54%'];
    var i;

    if (target.isTable) {
      var tb = skelRoot('tbody', 'skel-sel');
      for (i = 0; i < widths.length; i++) {
        var tr = el('tr', 'skel-row skel-sel-row');
        var c1 = el('td'); c1.appendChild(skelBar('skel-sel-n')); tr.appendChild(c1);
        var c2 = el('td'); c2.appendChild(skelBar('skel-sel-desc', widths[i])); tr.appendChild(c2);
        var c3 = el('td'); c3.appendChild(skelBar('skel-sel-delta')); tr.appendChild(c3);
        tb.appendChild(tr);
      }
      target.node.appendChild(tb);
      return;
    }

    var root = skelRoot('div', 'skel-sel');
    for (i = 0; i < widths.length; i++) {
      var row = el('div', 'skel-row skel-sel-row');
      row.appendChild(skelBar('skel-sel-n'));
      row.appendChild(skelBar('skel-sel-desc', widths[i]));
      row.appendChild(skelBar('skel-sel-delta'));
      root.appendChild(row);
    }
    target.node.appendChild(root);
  }

  /** True while at least one fresh upload is still resolving. */
  function uploadPending() { return state.uploadsInFlight > 0; }

  /** Paint all three skeletons (once, however many uploads are queued). */
  function beginUploadSkeletons() {
    state.uploadsInFlight++;
    if (state.uploadsInFlight > 1) return;

    var tree = $('filter-tree');
    if (tree) { clear(tree); skeletonTree(tree); tree.setAttribute('aria-busy', 'true'); }

    var lad = $('ladder-svg-host');
    if (lad) { clear(lad); skeletonLadder(lad); lad.setAttribute('aria-busy', 'true'); }

    // #time-gutter is the ladder's other half — renderLadder() always draws the
    // two together. Left alone it would sit there showing the PREVIOUS
    // capture's real timestamps next to a placeholder ladder, which is exactly
    // the "claiming to show real data" the placeholder exists to avoid. Blank
    // it for the duration; every path that restores the ladder restores it too,
    // because renderLadder() owns both.
    var gut = $('time-gutter');
    if (gut) clear(gut);

    var sel = selectionHost();
    if (sel) { clear(sel.node); skeletonSelection(sel); sel.node.setAttribute('aria-busy', 'true'); }
  }

  /**
   * Runs on EVERY exit path of uploadFile — success, HTTP error, network
   * throw — so a 422 can never leave a skeleton stuck on screen.
   *
   * Per-host, not all-or-nothing: the success path already replaced all three
   * via openCapture -> renderAll, and a failed analysis GET leaves its own
   * error note in the ladder host. Only a host still holding a [data-skeleton]
   * gets re-rendered, which for a failed upload is the normal empty state (or
   * the previously open capture, untouched in state).
   */
  function endUploadSkeletons() {
    state.uploadsInFlight = Math.max(0, state.uploadsInFlight - 1);
    if (state.uploadsInFlight > 0) return;

    for (var i = 0; i < SKEL_HOST_IDS.length; i++) {
      var h = $(SKEL_HOST_IDS[i]);
      if (h) h.removeAttribute('aria-busy');
    }

    var tree = $('filter-tree');
    if (tree && tree.querySelector('[data-skeleton]')) {
      if (state.searchActive) renderSearchResults(); else renderFilterTree();
    }

    var sel = selectionHost();
    if (sel && sel.node.querySelector('[data-skeleton]')) renderSelectionList();

    var lad = $('ladder-svg-host');
    if (lad && lad.querySelector('[data-skeleton]')) renderLadder();
  }

  // ---------------------------------------------------------- #filter-tree

  function treeKeyExpanded(key, dflt) {
    if (Object.prototype.hasOwnProperty.call(state.treeExpanded, key)) return !!state.treeExpanded[key];
    return !!dflt;
  }

  /** A small round lifecycle dot (.state-dot + .state-<state> from hiccup.css). */
  function stateDot(st) {
    var dot = el('span', 'state-dot state-' + (st || 'unknown'));
    dot.setAttribute('data-state', str(st || 'unknown'));
    dot.title = 'state: ' + (st || 'unknown');
    dot.setAttribute('aria-hidden', 'true');
    return dot;
  }

  /**
   * Build one tree node: `.tree-node > .tree-row (+ .tree-children)`.
   * Indentation and the guide line come from hiccup.css's .tree-children — this
   * file never sets layout.
   * @returns {{node:HTMLElement, children:HTMLElement|null}}
   */
  function treeNode(opts) {
    var node = el('div', 'tree-node' + (opts.kindClass ? ' ' + opts.kindClass : ''));
    node.setAttribute('role', 'treeitem');
    if (opts.hasChildren) node.setAttribute('aria-expanded', opts.open ? 'true' : 'false');

    var row = el('div', 'tree-row' +
      (opts.selected ? ' is-selected' : '') +
      (opts.edge ? ' edge-' + opts.edge : ''));
    row.setAttribute('tabindex', '0');
    if (opts.nodeKey) row.setAttribute('data-node', str(opts.nodeKey));
    row.setAttribute('aria-selected', opts.selected ? 'true' : 'false');
    if (opts.title) row.title = opts.title;

    if (opts.hasChildren) {
      // .icon-btn goes on the real expander only; the spacer below stays inert
      var tog = el('button', 'tree-toggle icon-btn', opts.open ? '\u25be' : '\u25b8');
      tog.type = 'button';
      tog.setAttribute('aria-label', opts.open ? 'collapse' : 'expand');
      tog.addEventListener('click', function (ev) {
        ev.stopPropagation();
        state.treeExpanded[opts.nodeKey] = !opts.open;
        renderFilterTree();
      });
      row.appendChild(tog);
    } else {
      var pad = el('span', 'tree-toggle');
      pad.setAttribute('aria-hidden', 'true');
      row.appendChild(pad);
    }

    if (opts.state !== undefined) row.appendChild(stateDot(opts.state));
    if (opts.proto) {
      row.appendChild(el('span', 'tree-proto is-' + (opts.proto === 'h323' ? 'h323' : 'sip'),
        opts.proto === 'h323' ? 'H.323' : 'SIP'));
    }
    row.appendChild(el('span', 'tree-label', opts.label));
    if (opts.sub) row.appendChild(el('span', 'tree-sub mono', opts.sub));
    if (opts.retrans) {
      var badge = el('span', 'tree-badge is-retrans', '\u00d7' + opts.retrans);
      badge.title = opts.retrans + ' retransmissions here';
      row.appendChild(badge);
    }
    if (opts.badge) row.appendChild(el('span', 'tree-badge', opts.badge));
    if (opts.chip) row.appendChild(opts.chip);

    if (opts.onSelect) {
      row.addEventListener('click', function () { opts.onSelect(); });
      row.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); opts.onSelect(); }
      });
    }
    node.appendChild(row);

    var children = null;
    if (opts.hasChildren && opts.open) {
      children = el('div', 'tree-children');
      children.setAttribute('role', 'group');
      node.appendChild(children);
    }
    return { node: node, children: children };
  }

  function selectScope(sel) {
    state.sel = {
      type: sel.type || 'capture',
      callId: sel.callId || null,
      legId: sel.legId || null,
      txKey: sel.txKey || null
    };
    state.selectedRowId = sel.rowId || null;
    state.keyList = 'tree';   // Wave 5A: the tree is what just changed selection
    if (!state.searchActive) renderFilterTree();
    renderSelectionDependent();
  }

  function isSelectedNode(sel) {
    var s = state.sel;
    return s.type === sel.type && str(s.callId) === str(sel.callId) &&
      str(s.legId) === str(sel.legId) && str(s.txKey) === str(sel.txKey);
  }

  /** #filter-pane's expand-all / collapse-all buttons. */
  function setAllTreeExpanded(open) {
    var a = state.analysis;
    if (!a) return;
    var map = { other: open };
    var calls = objs(a.calls), legs = objs(a.legs);
    var i;
    for (i = 0; i < calls.length; i++) { if (calls[i].id) map['call:' + calls[i].id] = open; }
    for (i = 0; i < legs.length; i++) { if (legs[i].id) map['leg:' + legs[i].id] = open; }
    map.root = true;   // the root stays open, else the pane just looks broken
    state.treeExpanded = map;
    renderFilterTree();
  }

  function renderFilterTree() {
    var host = $('filter-tree');
    if (!host) return;
    clear(host);
    host.setAttribute('role', 'tree');

    if (!state.analysis) {
      emptyNote(host, 'No capture selected.',
        'Calls, their legs and each transaction appear here. Selecting a node scopes the ladder, the message list and the info pane.');
      return;
    }

    var calls = objs(state.analysis.calls);
    var legs = objs(state.analysis.legs);
    var stats = state.analysis.stats || {};

    var rootSel = { type: 'capture' };
    var root = treeNode({
      nodeKey: 'root',
      kindClass: 'is-root',
      label: 'whole capture',
      sub: ' ' + (stats.sipMessages || 0) + ' SIP \u00b7 ' + (stats.h323Messages || 0) + ' H.323 \u00b7 ' +
        calls.length + ' calls',
      hasChildren: true,
      open: treeKeyExpanded('root', true),
      selected: isSelectedNode(rootSel),
      title: 'select the whole capture',
      onSelect: function () { selectScope(rootSel); }
    });
    host.appendChild(root.node);
    if (!root.children) return;

    var legsInCalls = {};
    var i, j;
    for (i = 0; i < calls.length; i++) {
      var lids0 = arr(calls[i].legIds);
      for (j = 0; j < lids0.length; j++) legsInCalls[lids0[j]] = true;
    }

    var callsOpenDefault = calls.length <= 10;
    var legsOpenDefault = legs.length <= 12;

    for (i = 0; i < calls.length; i++) {
      renderCallNode(root.children, calls[i], callsOpenDefault, legsOpenDefault);
    }

    var orphans = [];
    for (i = 0; i < legs.length; i++) {
      if (legs[i].id && !legsInCalls[legs[i].id]) orphans.push(legs[i]);
    }
    if (orphans.length) {
      var otherOpen = treeKeyExpanded('other', orphans.length <= 12);
      var other = treeNode({
        nodeKey: 'other',
        kindClass: 'is-other',
        label: 'other legs',
        badge: String(orphans.length),
        hasChildren: true,
        open: otherOpen,
        title: 'legs outside any correlated call \u2014 REGISTER, OPTIONS, SUBSCRIBE, strays'
      });
      root.children.appendChild(other.node);
      if (other.children) {
        for (i = 0; i < orphans.length; i++) renderLegNode(other.children, orphans[i], null, legsOpenDefault);
      }
    }

    if (!calls.length && !orphans.length) {
      emptyNote(root.children, 'No legs in this capture.',
        'The ladder still shows every message hiccup could parse.');
    }
  }

  function renderCallNode(parent, call, callsOpenDefault, legsOpenDefault) {
    if (!call || !call.id) return;
    var sel = { type: 'call', callId: call.id };
    var nodeKey = 'call:' + call.id;
    var open = treeKeyExpanded(nodeKey, callsOpenDefault);
    var lids = arr(call.legIds);
    var ingress = state.legById[lids[0]] || {};
    var retrans = 0;
    for (var i = 0; i < lids.length; i++) retrans += legRetransCount(lids[i]);

    var chip = null;
    if (call.state === 'ambiguous') {
      chip = el('span', 'chip sev-warn ambiguous-chip', 'AMBIGUOUS');
      chip.title = 'hiccup will not guess between competing pairings';
    } else if (call.type !== 'single') {
      chip = el('span', 'tree-badge', Math.round((call.confidence || 0) * 100) + '%');
      chip.title = 'pairing confidence';
    }

    var built = treeNode({
      nodeKey: nodeKey,
      kindClass: 'is-call',
      label: call.id + ' \u00b7 ' + callProtocolLabel(call),
      sub: ' ' + str(ingress.from || '?') + ' \u2192 ' + str(ingress.to || '?'),
      state: ingress.state,
      hasChildren: lids.length > 0,
      open: open,
      retrans: retrans,
      edge: worstSeverityForCall(call.id),
      selected: isSelectedNode(sel),
      chip: chip,
      title: 'call ' + call.id + ' \u2014 ' + str(call.state) +
        (call.type !== 'single' ? ', confidence ' + Math.round((call.confidence || 0) * 100) + '%' : ''),
      onSelect: function () { selectScope(sel); }
    });
    parent.appendChild(built.node);
    if (!built.children) return;

    for (var k = 0; k < lids.length; k++) {
      var leg = state.legById[lids[k]];
      if (leg) renderLegNode(built.children, leg, call.id, legsOpenDefault);
    }
  }

  function renderLegNode(parent, leg, callId, legsOpenDefault) {
    if (!leg || !leg.id) return;
    var sel = { type: 'leg', callId: callId || null, legId: leg.id };
    var nodeKey = 'leg:' + leg.id;
    var txs = legTransactions(leg);
    var open = treeKeyExpanded(nodeKey, legsOpenDefault);

    var built = treeNode({
      nodeKey: nodeKey,
      kindClass: 'is-leg',
      proto: leg.protocol === 'h323' ? 'h323' : 'sip',
      label: leg.id + (leg.kind ? ' \u00b7 ' + str(leg.kind) : ''),
      sub: ' ' + pathOf(leg),
      state: leg.state,
      hasChildren: txs.length > 0,
      open: open,
      retrans: legRetransCount(leg.id),
      edge: worstSeverityForLeg(leg.id),
      selected: isSelectedNode(sel),
      title: (leg.callId ? 'Call-ID ' + leg.callId + ' \u00b7 ' : '') + 'state ' + str(leg.state) +
        (leg.failCode != null ? ' (' + leg.failCode + ')' : ''),
      onSelect: function () { selectScope(sel); }
    });
    parent.appendChild(built.node);
    if (!built.children) return;

    for (var i = 0; i < txs.length; i++) {
      (function (tx) {
        var tsel = { type: 'transaction', callId: callId || null, legId: leg.id, txKey: tx.key };
        var tnode = treeNode({
          nodeKey: 'tx:' + leg.id + ':' + tx.key,
          kindClass: 'is-tx',
          label: tx.label,
          sub: tx.sub,
          state: tx.state,
          hasChildren: false,
          open: false,
          retrans: tx.retrans,
          edge: tx.state === 'failed' ? 'warn' : null,
          selected: isSelectedNode(tsel),
          title: tx.title,
          onSelect: function () { selectScope(tsel); }
        });
        built.children.appendChild(tnode.node);
      })(txs[i]);
    }
  }

  /** Group a leg's messages into transactions (method + final status). */
  function legTransactions(leg) {
    var out = [], byKey = {};
    var ids = arr(leg && leg.msgIds);
    for (var i = 0; i < ids.length; i++) {
      var m = state.msgById[ids[i]];
      if (!m) continue;
      var key = txKeyOf(m);
      var tx = byKey[key];
      if (!tx) {
        tx = byKey[key] = {
          key: key, label: '', sub: '', state: undefined, retrans: 0, count: 0,
          method: null, worstStatus: null, reason: '', title: ''
        };
        out.push(tx);
      }
      tx.count++;
      if (m.retransOf) tx.retrans++;
      if (m.protocol === 'h323' || m.q931Type) {
        tx.method = str(m.q931Type || 'H.323');
        if (m.causeCode != null) tx.worstStatus = m.causeCode;
      } else {
        if (m.isRequest && !tx.method) tx.method = str(m.method || '?');
        if (!tx.method && m.cseq) tx.method = str(m.cseq.method || '?');
        var st = nnum(m.status);
        if (st != null && (tx.worstStatus == null || st >= tx.worstStatus)) {
          tx.worstStatus = st;
          tx.reason = str(m.reason || '');
        }
      }
    }
    for (var k = 0; k < out.length; k++) {
      var t = out[k];
      t.label = str(t.method || '?');
      if (t.worstStatus != null) t.label += ' \u2192 ' + t.worstStatus + (t.reason ? ' ' + t.reason : '');
      t.sub = ' ' + t.count + ' msg' + (t.count === 1 ? '' : 's');
      if (t.worstStatus != null && t.worstStatus >= 400) t.state = 'failed';
      else if (t.worstStatus != null && t.worstStatus >= 200 && t.worstStatus < 300) t.state = 'answered';
      else t.state = 'in-progress';
      t.title = 'transaction ' + t.key + ' \u2014 ' + t.count + ' message(s)' +
        (t.retrans ? ', ' + t.retrans + ' retransmission(s)' : '');
    }
    return out;
  }

  // -------------------------------------------------------- #selection-list

  /**
   * app.css supports two shapes for #selection-list:
   *   (a) `#selection-list > .sel-row > .sel-n + .sel-desc + .sel-delta` — used
   *       when the host is a plain container, because app.html already ships the
   *       static `.sel-head` header row and the `[data-sort]` buttons;
   *   (b) `#selection-list > table.table-dense` — used when the host is itself a
   *       <table>; app.css then hides the static header automatically.
   */
  function selectionHost() {
    var node = $('selection-list');
    if (!node) return null;
    var isTable = !!(node.tagName && node.tagName.toLowerCase() === 'table');
    return { node: node, isTable: isTable };
  }

  /** Wire the pane-header sort buttons (#selection-pane [data-sort]). */
  function setupSelectionSort() {
    var pane = $('selection-pane') || document;
    var btns = pane.querySelectorAll ? pane.querySelectorAll('[data-sort]') : [];
    for (var i = 0; i < btns.length; i++) {
      (function (btn) {
        var key = str(btn.getAttribute('data-sort')).toLowerCase() === 'delta' ? 'delta' : 'n';
        btn.addEventListener('click', function (ev) {
          ev.preventDefault();
          if (state.selSort.key === key) state.selSort.asc = !state.selSort.asc;
          else state.selSort = { key: key, asc: true };
          renderSelectionList();
        });
      })(btns[i]);
    }
    state.sortBtns = btns;
  }

  function syncSelectionSort() {
    var btns = state.sortBtns || [];
    for (var i = 0; i < btns.length; i++) {
      var key = str(btns[i].getAttribute('data-sort')).toLowerCase() === 'delta' ? 'delta' : 'n';
      var on = state.selSort.key === key;
      btns[i].classList.toggle('is-active', on);
      btns[i].setAttribute('aria-pressed', on ? 'true' : 'false');
      btns[i].title = on
        ? ('sorted by ' + key + ', ' + (state.selSort.asc ? 'ascending' : 'descending') + ' — click to reverse')
        : ('sort by ' + key);
    }
  }

  /** Row tint class: crit/warn wash for the rows an engineer must not miss. */
  function rowTint(row) {
    if (!row) return null;
    if (row.sev === 'crit') return 'tint-crit';
    if (row.sev === 'warn') return 'tint-warn';
    if (row.colorKey === '4xx' || row.colorKey === '5xx' || row.colorKey === '6xx') return 'tint-crit';
    // Retransmissions are NOT a warning on their own — the ladder says so
    // explicitly (ladder.js: "no border, no pill, no warn colour") and Wave 4
    // doubles down on handling them silently. The row still shows its muted
    // ×N marker via .sel-row.is-retrans; it just no longer gets an amber wash.
    if (row.kind === 'media' && nnum(row.obj && row.obj.lossPct) != null && row.obj.lossPct >= 5) return 'tint-crit';
    if (row.kind === 'media' && row.obj && row.obj.oneWay) return 'tint-warn';
    return null;
  }

  function kindLabel(row) {
    if (!row) return '';
    if (row.kind === 'media') return 'media';
    if (row.kind === 'aux') return str((row.obj && row.obj.protocol) || 'aux');
    return row.proto === 'h323' ? 'H.323' : 'SIP';
  }

  function kindClass(row) {
    if (!row) return '';
    if (row.kind === 'media') return 'is-media';
    if (row.kind === 'aux') return 'is-aux';
    return row.proto === 'h323' ? 'is-h323' : 'is-sip';
  }

  function deltaClass(row) {
    if (!row || row.deltaMs == null) return '';
    if (row.deltaMs >= 4000) return ' is-stalled';
    if (row.deltaMs >= 500) return ' is-slow';
    return '';
  }

  function sortedRows() {
    var rows = state.rows.slice();
    if (state.selSort.key === 'delta') {
      rows.sort(function (a, b) {
        var da = a.deltaMs == null ? -1 : a.deltaMs;
        var db = b.deltaMs == null ? -1 : b.deltaMs;
        if (da === db) return a.n - b.n;
        return state.selSort.asc ? da - db : db - da;
      });
    } else if (!state.selSort.asc) {
      rows.reverse();
    }
    return rows;
  }

  function renderSelectionList() {
    var target = selectionHost();
    if (!target) return;
    syncSelectionSort();
    state.selRowEls = {};
    clear(target.node);

    if (!state.analysis) {
      emptyNote(target.node, 'No capture open.',
        'Every message of the selected session lands here, numbered, with the delta from the previous row.');
      return;
    }

    var rows = sortedRows();
    if (!rows.length) {
      emptyNote(target.node, 'Nothing in this selection.',
        state.lampFilter
          ? 'The active lamp filter may be hiding everything — click the lamp again to clear it.'
          : 'Pick a call, leg or transaction in the tree above.');
      return;
    }

    if (target.isTable) {
      renderSelectionTable(target.node, rows);
    } else {
      for (var i = 0; i < rows.length; i++) target.node.appendChild(selectionRow(rows[i]));
      if (state.truncatedRows) {
        emptyNote(target.node, state.truncatedRows +
          ' further rows not shown — narrow the selection in the tree.');
      }
    }
  }

  /** Shape (a): a .sel-row grid matching app.html's static .sel-head. */
  function selectionRow(row) {
    var tint = rowTint(row);
    var tr = el('div', 'sel-row sel-kind-' + row.kind +
      (tint ? ' ' + tint : '') +
      (row.retransCount > 1 ? ' is-retrans' : '') +
      (row.rowId === state.selectedRowId ? ' is-selected' : '') +
      (state.searchMatchIds[row.rowId] ? ' is-match' : ''));
    tr.setAttribute('data-row-id', row.rowId);
    tr.setAttribute('tabindex', '0');
    tr.setAttribute('aria-selected', row.rowId === state.selectedRowId ? 'true' : 'false');
    if (row.retransCount > 1) tr.setAttribute('data-retrans', '\u00d7' + row.retransCount);

    tr.appendChild(el('span', 'sel-n', String(row.n)));

    var desc = el('span', 'sel-desc');
    desc.appendChild(el('span', 'sel-kind ' + kindClass(row), kindLabel(row)));
    var text = el('span', 'sel-text');
    appendHighlighted(text, row.desc, state.searchTerms);
    desc.appendChild(text);
    desc.title = row.desc + (row.adviceTitle ? '  —  ' + row.adviceTitle
      : (row.findingTitle ? '  —  ' + row.findingTitle : ''));
    tr.appendChild(desc);

    tr.appendChild(el('span', 'sel-delta' + deltaClass(row),
      row.deltaMs == null ? '\u2014' : ('+' + row.deltaMs)));

    wireSelectionRow(tr, row);
    return tr;
  }

  /** Shape (b): a dense table, when #selection-list is itself a <table>. */
  function renderSelectionTable(table, rows) {
    if (!/table-dense/.test(str(table.className))) {
      table.className = str(table.className ? table.className + ' ' : '') + 'table-dense';
    }
    var thead = el('thead');
    var hr = el('tr');
    var cols = [
      { key: 'n', label: '#', cls: 'num' },
      { key: null, label: 'description', cls: '' },
      { key: 'delta', label: '\u0394 ms', cls: 'num' }
    ];
    for (var c = 0; c < cols.length; c++) {
      (function (col) {
        var th = el('th', col.cls + (col.key ? ' sortable' : ''), col.label);
        if (col.key) {
          if (state.selSort.key === col.key) {
            th.appendChild(el('span', 'sort-arrow', state.selSort.asc ? ' \u25b2' : ' \u25bc'));
          }
          th.setAttribute('tabindex', '0');
          th.title = 'sort by ' + col.label;
          var doSort = function () {
            if (state.selSort.key === col.key) state.selSort.asc = !state.selSort.asc;
            else state.selSort = { key: col.key, asc: true };
            renderSelectionList();
          };
          th.addEventListener('click', doSort);
          th.addEventListener('keydown', function (ev) {
            if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); doSort(); }
          });
        }
        hr.appendChild(th);
      })(cols[c]);
    }
    thead.appendChild(hr);
    table.appendChild(thead);

    var tbody = el('tbody');
    for (var i = 0; i < rows.length; i++) {
      (function (row) {
        var tint = rowTint(row);
        var tr = el('tr', 'sel-row sel-kind-' + row.kind +
          (tint ? ' ' + tint : '') +
          (row.retransCount > 1 ? ' is-retrans' : '') +
          (row.rowId === state.selectedRowId ? ' is-selected' : '') +
          (state.searchMatchIds[row.rowId] ? ' is-match' : ''));
        tr.setAttribute('data-row-id', row.rowId);
        tr.setAttribute('tabindex', '0');
        if (row.retransCount > 1) tr.setAttribute('data-retrans', '\u00d7' + row.retransCount);

        tr.appendChild(el('td', 'num sel-n', String(row.n)));

        var td = el('td', 'sel-desc');
        td.appendChild(el('span', 'sel-kind ' + kindClass(row), kindLabel(row)));
        var text = el('span', 'sel-text');
        appendHighlighted(text, row.desc, state.searchTerms);
        td.appendChild(text);
        if (row.retransCount > 1) {
          var rb = el('span', 'tree-badge is-retrans', '\u00d7' + row.retransCount);
          rb.title = (row.collapse && row.collapse.label) || (row.retransCount + ' retransmissions');
          td.appendChild(rb);
        }
        tr.appendChild(td);

        tr.appendChild(el('td', 'num sel-delta' + deltaClass(row),
          row.deltaMs == null ? '\u2014' : ('+' + row.deltaMs)));

        wireSelectionRow(tr, row);
        tbody.appendChild(tr);
      })(rows[i]);
    }
    table.appendChild(tbody);

    if (state.truncatedRows) {
      var tf = el('tfoot');
      var ftr = el('tr');
      var ftd = el('td');
      ftd.colSpan = 3;
      ftd.appendChild(el('span', 'pane-empty',
        state.truncatedRows + ' further rows not shown — narrow the selection in the tree.'));
      ftr.appendChild(ftd);
      tf.appendChild(ftr);
      table.appendChild(tf);
    }
  }

  function wireSelectionRow(node, row) {
    node.addEventListener('click', function () { selectRow(row.rowId); });
    node.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); selectRow(row.rowId); }
    });
    node.addEventListener('mouseenter', function () {
      crossHighlight(row.rowId, true);
      showSevHovercard(row.rowId, node);
    });
    node.addEventListener('mouseleave', function () {
      crossHighlight(row.rowId, false);
      hideSevHovercard();
    });
    // Keyboard parity: the card is reachable without a mouse, same as the row.
    node.addEventListener('focus', function () { showSevHovercard(row.rowId, node); });
    node.addEventListener('blur', hideSevHovercard);
    state.selRowEls[row.rowId] = node;
  }

  /** Hover cross-highlight between the ladder and #selection-list. */
  function crossHighlight(rowId, on) {
    var a = state.selRowEls[rowId];
    if (a) a.classList.toggle('is-cross', !!on);
    var b = state.ladderRowEls[rowId];
    if (b) {
      // SVG elements: className is read-only in older engines, so use the attribute.
      var cls = str(b.getAttribute('class')).replace(/\s*is-cross\b/g, '');
      b.setAttribute('class', on ? cls + ' is-cross' : cls);
    }
    var g = state.gutterRowEls[rowId];
    if (g) g.classList.toggle('is-cross', !!on);
  }

  // ------------------------------------------------- flagged-row hover card

  /** The advice object behind a row's flag, when the row names one. */
  function adviceForRow(row) {
    if (!row || !row.adviceId) return null;
    var list = adviceList();
    for (var i = 0; i < list.length; i++) {
      if (list[i] && list[i].id === row.adviceId) return list[i];
    }
    return null;
  }

  /**
   * Show the "what's wrong here" card for a warn/crit row near `anchorEl`.
   * Non-warn/crit rows hide it — every hover path calls this unconditionally
   * and lets it decide, so there is exactly one place that knows the rule.
   */
  function showSevHovercard(rowId, anchorEl) {
    var card = $('sev-hovercard');
    if (!card) return;
    var row = state.rowById[rowId];
    if (!row || (row.sev !== 'crit' && row.sev !== 'warn') || !anchorEl) {
      hideSevHovercard();
      return;
    }

    var ad = adviceForRow(row);
    var title = row.adviceTitle || row.findingTitle ||
      (row.sev === 'crit' ? 'Critical condition on this message' : 'Warning on this message');
    // whatsWrong is the advisor's plain-English "here is the actual problem"
    // paragraph — exactly what this card is for. Absent when the flag came
    // from a bare Finding with no Advice attached; the title still stands alone.
    var body = ad ? str(ad.whatsWrong) : '';

    clear(card);
    card.className = 'is-' + row.sev;

    var head = el('div', 'hovercard-head');
    head.appendChild(el('span', 'hovercard-sev', row.sev === 'crit' ? 'error' : 'warning'));
    head.appendChild(el('span', 'hovercard-title', title));
    card.appendChild(head);

    if (body) card.appendChild(el('p', 'hovercard-body', body));
    if (ad) card.appendChild(el('p', 'hovercard-foot', 'Full advice, fixes and RFC citations are in the ask hiccup panel.'));

    card.hidden = false;
    positionSevHovercard(card, anchorEl);
  }

  /**
   * Place the card beside its anchor, flipping to whichever side has room.
   * Measured after the card is visible, so getBoundingClientRect is truthful.
   */
  function positionSevHovercard(card, anchorEl) {
    var a = anchorEl.getBoundingClientRect();
    var c = card.getBoundingClientRect();
    var pad = 10;
    var left = a.right + pad;
    if (left + c.width > window.innerWidth - pad) left = a.left - c.width - pad;
    if (left < pad) left = pad;
    var top = a.top;
    if (top + c.height > window.innerHeight - pad) top = window.innerHeight - c.height - pad;
    if (top < pad) top = pad;
    card.style.left = Math.round(left) + 'px';
    card.style.top = Math.round(top) + 'px';
  }

  function hideSevHovercard() {
    var card = $('sev-hovercard');
    if (card) card.hidden = true;
  }

  function selectRow(rowId) {
    state.selectedRowId = rowId || null;
    state.keyList = 'selection';   // Wave 5A: message rows are the selection list's
    renderSelectionList();
    renderLadder();
    renderInfo();
    renderDrawer();
  }

  // ------------------------------------------------------------ ladder pane

  function setupLadderToolbar() {
    var bar = $('ladder-toolbar');
    if (!bar) return;
    var existing = bar.querySelectorAll('[data-action]');
    if (existing.length) {
      state.toolbarOwn = false;
      for (var i = 0; i < existing.length; i++) {
        (function (btn) {
          btn.addEventListener('click', function (ev) {
            ev.preventDefault();
            toolbarAction(str(btn.getAttribute('data-action')).toLowerCase());
          });
        })(existing[i]);
      }
      return;
    }
    state.toolbarOwn = true;
    clear(bar);

    // Zoom + export only. Retransmission collapsing is not a control any more
    // (Wave 4) — it is always on, handled silently by the row builder.
    var zo = el('button', 'btn lad-btn', '−');
    zo.type = 'button';
    zo.title = 'zoom out';
    zo.setAttribute('aria-label', 'zoom out');
    zo.addEventListener('click', function () { toolbarAction('zoom-out'); });
    bar.appendChild(zo);

    var zlabel = el('span', 'lad-zoom-label mono', '100%');
    zlabel.id = 'lad-zoom-label';
    bar.appendChild(zlabel);

    var zi = el('button', 'btn lad-btn', '+');
    zi.type = 'button';
    zi.title = 'zoom in';
    zi.setAttribute('aria-label', 'zoom in');
    zi.addEventListener('click', function () { toolbarAction('zoom-in'); });
    bar.appendChild(zi);

    var zr = el('button', 'btn lad-btn', 'reset');
    zr.type = 'button';
    zr.title = 'reset zoom';
    zr.addEventListener('click', function () { toolbarAction('zoom-reset'); });
    bar.appendChild(zr);

    var ex = el('button', 'btn lad-btn', 'export SVG');
    ex.type = 'button';
    ex.title = 'download this ladder as an SVG file';
    ex.addEventListener('click', function () { toolbarAction('export'); });
    bar.appendChild(ex);

    var count = el('span', 'lad-rowcount muted', '');
    count.id = 'lad-rowcount';
    bar.appendChild(count);
  }

  /**
   * Ladder toolbar actions. Matched by substring so both this file's own control
   * names and app.html's prefixed ones ('ladder-zoom-in', 'ladder-export', …)
   * resolve to the same behaviour. Zoom and export are the whole toolbar now.
   */
  function toolbarAction(action) {
    var a = str(action).toLowerCase();
    if (a.indexOf('export') !== -1) { exportLadderSvg(); return; }
    if (a.indexOf('zoom') !== -1) {
      if (a.indexOf('in') !== -1) state.zoom = Math.min(3, Math.round((state.zoom + 0.15) * 100) / 100);
      else if (a.indexOf('out') !== -1) state.zoom = Math.max(0.4, Math.round((state.zoom - 0.15) * 100) / 100);
      else state.zoom = 1;
      renderLadder();
      syncLadderToolbar();
    }
  }

  /**
   * Wire the buttons app.html ships outside #ladder-toolbar:
   * #filter-pane [data-action=tree-expand-all|tree-collapse-all] and
   * #info-pane [data-action=explain-selection].
   */
  function setupPaneActions() {
    var i;
    var fp = $('filter-pane');
    if (fp && fp.querySelectorAll) {
      var tb = fp.querySelectorAll('[data-action]');
      for (i = 0; i < tb.length; i++) {
        (function (btn) {
          var a = str(btn.getAttribute('data-action')).toLowerCase();
          if (a.indexOf('tree') === -1) return;
          var open = a.indexOf('expand') !== -1;
          btn.addEventListener('click', function (ev) { ev.preventDefault(); setAllTreeExpanded(open); });
        })(tb[i]);
      }
    }
    var ip = $('info-pane');
    if (ip && ip.querySelectorAll) {
      var eb = ip.querySelectorAll('[data-action]');
      for (i = 0; i < eb.length; i++) {
        (function (btn) {
          var a = str(btn.getAttribute('data-action')).toLowerCase();
          if (a.indexOf('explain') === -1) return;
          btn.addEventListener('click', function (ev) {
            ev.preventDefault();
            explainCurrentSelection();
          });
        })(eb[i]);
      }
    }
  }

  /** "explain in chat" for whatever is selected right now. */
  function explainCurrentSelection() {
    var row = selectedRow();
    if (row && row.kind === 'msg') {
      var m = row.obj || {};
      openChatPrefilled('Explain this ' + (m.protocol === 'h323' ? 'H.323' : 'SIP') +
        ' message: what is it doing in this call, and is anything wrong with it?',
        { type: 'message', id: row.id });
      return;
    }
    if (row) {
      openChatPrefilled('Explain this ' + row.kind + ' observation: "' + row.desc + '".', chatScope());
      return;
    }
    var sel = state.sel;
    if (sel.type === 'call' && sel.callId) {
      openChatPrefilled('Walk me through call ' + sel.callId +
        ': what happened, and is anything wrong with it?', { type: 'call', id: sel.callId });
    } else if (sel.legId) {
      openChatPrefilled('Walk me through leg ' + sel.legId + ': what happened on it?',
        { type: 'leg', id: sel.legId });
    } else {
      openChatPrefilled('Summarise this capture: what is it, and what is wrong with it?',
        { type: 'capture', id: state.captureId });
    }
  }

  function syncLadderToolbar() {
    var bar = $('ladder-toolbar');
    if (!bar) return;
    var zl = $('lad-zoom-label');
    if (zl) zl.textContent = Math.round(state.zoom * 100) + '%';
    var rc = $('lad-rowcount');
    if (rc) {
      rc.textContent = state.rows.length
        ? (state.rows.length + ' rows' + (state.truncatedRows ? ' (+' + state.truncatedRows + ' hidden)' : ''))
        : '';
    }
    // Shell-supplied controls: reflect state on anything carrying data-action.
    var owned = bar.querySelectorAll('[data-action]');
    for (var i = 0; i < owned.length; i++) {
      var a = str(owned[i].getAttribute('data-action')).toLowerCase();
      if (a.indexOf('zoom') !== -1 && a.indexOf('reset') !== -1) {
        owned[i].textContent = Math.round(state.zoom * 100) + '%';
      }
    }
  }

  function exportLadderSvg() {
    var L = window.Ladder;
    if (!L || !state.ladderSvg) return;
    var text = L.toSvgString(state.ladderSvg);
    if (!text) return;
    try {
      var blob = new Blob([text], { type: 'image/svg+xml;charset=utf-8' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'hiccup-ladder-' + (state.captureId || 'capture') + '.svg';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function () { try { URL.revokeObjectURL(url); } catch (e) { /* ignore */ } }, 2000);
    } catch (e) { /* export is a convenience, never fatal */ }
  }

  function renderLadder() {
    var host = $('ladder-svg-host');
    var L = window.Ladder;
    state.ladderRowEls = {};

    if (host) {
      clear(host);
      if (!state.analysis) {
        emptyNote(host, 'see where the call went wrong',
          'Select a capture on the left, or drop a pcap / SBC log to analyse it.');
      } else if (!L || typeof L.render !== 'function') {
        emptyNote(host, 'Ladder renderer unavailable.');
      } else {
        var svg = L.render({
          rows: state.rows,
          messages: arr(state.scopeMsgs),
          legs: (function () {
            var ids = scopeLegIds();
            if (!ids) return arr(state.analysis.legs);
            var out = [];
            for (var i = 0; i < ids.length; i++) { if (state.legById[ids[i]]) out.push(state.legById[ids[i]]); }
            return out;
          })(),
          collapses: collapsesList(),
          media: mediaStreams(),
          aux: auxMessages(),
          findings: findingsList(),
          advice: adviceList(),
          collapsed: true,           // Wave 4: fixed, not UI state
          selectedId: state.selectedRowId,
          matchIds: state.searchMatchIds,
          zoom: state.zoom,
          onSelect: function (rowId) { selectRow(rowId); },
          onHover: function (rowId) {
            if (rowId) {
              crossHighlight(rowId, true);
              showSevHovercard(rowId, state.ladderRowEls[rowId]);
            } else {
              hideSevHovercard();
              for (var k in state.selRowEls) {
                if (Object.prototype.hasOwnProperty.call(state.selRowEls, k)) {
                  state.selRowEls[k].classList.remove('is-cross');
                }
              }
              for (var k2 in state.gutterRowEls) {
                if (Object.prototype.hasOwnProperty.call(state.gutterRowEls, k2)) {
                  state.gutterRowEls[k2].classList.remove('is-cross');
                }
              }
            }
          }
        });
        state.ladderSvg = svg;
        host.appendChild(svg);
        var groups = svg.querySelectorAll('[data-row-id]');
        for (var g = 0; g < groups.length; g++) {
          state.ladderRowEls[groups[g].getAttribute('data-row-id')] = groups[g];
        }
      }
    }

    // #time-gutter — a .tg-spacer + one .tg-row per ladder row at the same row
    // height, so it lines up with the arrows without any layout CSS here.
    var gut = $('time-gutter');
    state.gutterRowEls = {};
    if (gut) {
      clear(gut);
      if (L && typeof L.timeGutter === 'function' && state.analysis) {
        gut.appendChild(L.timeGutter(state.rows, state.zoom, state.selectedRowId));
        var grows = gut.querySelectorAll('[data-row-id]');
        for (var gi = 0; gi < grows.length; gi++) {
          state.gutterRowEls[grows[gi].getAttribute('data-row-id')] = grows[gi];
        }
      }
    }

    wireScrollSync();
    syncLadderToolbar();
  }

  /** Keep #time-pane's vertical scroll locked to the ladder's, whichever scrolls. */
  function wireScrollSync() {
    if (state.scrollSyncWired) return;
    var host = $('ladder-svg-host');
    var pane = $('time-pane') || (function () { var g = $('time-gutter'); return g && g.parentNode; })();
    if (!host || !pane || host === pane) return;
    var syncing = false;
    function mirror(from, to) {
      return function () {
        if (syncing) return;
        syncing = true;
        try { to.scrollTop = from.scrollTop; } catch (e) { /* ignore */ }
        syncing = false;
      };
    }
    host.addEventListener('scroll', mirror(host, pane));
    pane.addEventListener('scroll', mirror(pane, host));
    state.scrollSyncWired = true;
  }

  // -------------------------------------------------------------- #lamps

  function renderLamps() {
    var host = $('lamps');
    if (!host) return;
    clear(host);
    // Only what is actually IN this capture. detectIndicators() always returns
    // the full fixed key set so the shape is stable, but a strip of ~20 dim
    // "absent" lamps is noise that pushes the real ones off into a scroller \u2014
    // so the 'off' state is dropped from the UI entirely rather than greyed.
    var inds = indicators().filter(function (ind) {
      return ind && ind.key && str(ind.state || 'off') !== 'off';
    });
    if (!inds.length) {
      host.appendChild(el('span', 'lamps-empty', state.analysis
        ? 'no protocol features detected in this capture'
        : 'indicators light up once a capture is analysed \u2014 one lamp per protocol feature hiccup found.'));
      return;
    }
    for (var i = 0; i < inds.length; i++) {
      (function (ind) {
        if (!ind.key) return;
        var st = str(ind.state || 'off');
        var active = state.lampFilter === ind.key;
        var lamp = el('button', 'lamp lamp-' + st + (active ? ' is-active' : ''));
        lamp.type = 'button';
        lamp.setAttribute('data-key', str(ind.key));
        lamp.setAttribute('data-state', st);
        lamp.setAttribute('aria-pressed', active ? 'true' : 'false');
        var detail = str(ind.detail || '');
        var label = str(ind.label || ind.key);
        lamp.title = label + ' \u2014 ' + st + (detail ? '. ' + detail : '');
        lamp.setAttribute('aria-label', label + ': ' + st + (detail ? '. ' + detail : ''));
        lamp.appendChild(el('span', 'lamp-dot'));
        lamp.appendChild(el('span', 'lamp-label', label));
        lamp.addEventListener('click', function () { toggleLamp(ind); });
        host.appendChild(lamp);
      })(inds[i]);
    }
  }

  /** Clicking a lamp filters every pane down to that indicator's evidence. */
  function toggleLamp(ind) {
    if (state.lampFilter === ind.key) {
      state.lampFilter = null;
    } else {
      var mids = arr(ind.evidenceMsgIds);
      var cids = arr(ind.evidenceCallIds);
      state.lampFilter = (mids.length || cids.length) ? ind.key : null;
      if (cids.length && state.callById[cids[0]]) {
        state.sel = { type: 'call', callId: cids[0], legId: null, txKey: null };
      } else {
        state.sel = { type: 'capture', callId: null, legId: null, txKey: null };
      }
      state.selectedRowId = mids.length ? mids[0] : null;
      // When a lamp has no evidence to filter to, the drawer's advice section
      // still says why — it is always on screen, so there is no tab to switch.
    }
    renderAll();
  }

  function renderScenarioChip() {
    var chip = $('scenario-chip');
    if (!chip) return;
    var sc = state.analysis && state.analysis.scenario;
    if (!sc || !sc.primary) {
      chip.textContent = 'scenario: \u2014';
      chip.title = state.analysis
        ? 'hiccup could not classify this capture'
        : 'no capture open';
      chip.hidden = true;
      return;
    }
    chip.hidden = false;
    var pct = Math.round((nnum(sc.confidence) || 0) * 100);
    chip.textContent = 'scenario: ' + str(sc.primary) + ' \u00b7 ' + pct + '%';
    chip.title = (str(sc.detail || '') || ('scenario: ' + sc.primary)) +
      '  \u2014  click for the full capture-wide read-out in the advice drawer';
  }

  // ----------------------------------------------------------- #info-pane

  function normTab(v) {
    var s = str(v).toLowerCase();
    if (s.indexOf('content') !== -1) return 'contents';
    if (s.indexOf('packet') !== -1) return 'packet';
    if (s.indexOf('media') !== -1) return 'media';
    return null;   // 'advice' is deliberately absent — it is not a tab any more
  }

  function setupInfoTabs() {
    var host = $('info-tabs');
    if (!host) return;
    var existing = host.querySelectorAll('[data-tab], [data-panel], button');
    var wired = 0;
    for (var i = 0; i < existing.length; i++) {
      var btn = existing[i];
      var key = normTab(btn.getAttribute('data-tab')) ||
        normTab(btn.getAttribute('data-panel')) ||
        normTab(btn.textContent);
      if (!key) continue;
      btn.setAttribute('data-tab', key);
      (function (k, b) {
        b.addEventListener('click', function (ev) {
          ev.preventDefault();
          state.infoTab = k;
          renderInfo();
        });
      })(key, btn);
      wired++;
    }
    if (wired) return;

    clear(host);
    host.setAttribute('role', 'tablist');
    for (var t = 0; t < INFO_TABS.length; t++) {
      (function (spec) {
        var b = el('button', 'info-tab', spec.label);
        b.type = 'button';
        b.setAttribute('data-tab', spec.key);
        b.setAttribute('role', 'tab');
        b.addEventListener('click', function () { state.infoTab = spec.key; renderInfo(); });
        host.appendChild(b);
      })(INFO_TABS[t]);
    }
  }

  /**
   * Move the tab state. app.css accepts either convention, and app.html's own
   * chrome script uses `.is-active` + `hidden` + aria-selected together — so we
   * move all three, or a programmatic tab switch would leave the panel hidden by
   * the `.info-body:has(.is-active)` rule.
   */
  function syncInfoTabs() {
    var host = $('info-tabs');
    if (host) {
      var btns = host.querySelectorAll('[data-tab]');
      for (var i = 0; i < btns.length; i++) {
        var on = btns[i].getAttribute('data-tab') === state.infoTab;
        btns[i].classList.toggle('is-active', on);
        btns[i].setAttribute('aria-selected', on ? 'true' : 'false');
      }
    }
    for (var t = 0; t < INFO_TABS.length; t++) {
      var panel = $(INFO_TABS[t].panel);
      if (!panel) continue;
      var active = INFO_TABS[t].key === state.infoTab;
      panel.hidden = !active;
      panel.classList.toggle('is-active', active);
    }
  }

  function selectedRow() {
    return state.selectedRowId ? (state.rowById[state.selectedRowId] || null) : null;
  }

  function renderInfo() {
    syncInfoTabs();
    renderInfoContents();
    renderInfoPacket();
    renderInfoMedia();
    // Advice is rendered by renderDrawerAdvice() into #chat-advice-body.
  }

  function infoHeader(parent, row) {
    var head = el('div', 'info-head');
    if (row) {
      head.appendChild(el('strong', null,
        str(row.kind === 'msg' ? 'message ' : (row.kind === 'media' ? 'stream ' : 'aux ')) + row.rowId));
      head.appendChild(el('span', 'mono muted', ' ' + fmtClock(row.ts) + ' \u00b7 ' + pathOf(row)));
      var explain = el('button', 'explain-btn', 'explain in chat');
      explain.type = 'button';
      explain.addEventListener('click', function () {
        var q, scope;
        if (row.kind === 'msg') {
          var m = row.obj || {};
          q = 'Explain this ' + (m.protocol === 'h323' ? 'H.323' : 'SIP') +
            ' message: what is it doing in this call, and is anything wrong with it?';
          scope = { type: 'message', id: row.id };
        } else if (row.kind === 'media') {
          q = 'Explain this media stream (' + row.desc + '). Is the loss/jitter a problem, and what would cause it?';
          scope = chatScope();
        } else {
          q = 'Explain this ' + str((row.obj && row.obj.protocol) || 'auxiliary') +
            ' observation: "' + str(row.obj && row.obj.summary) + '". What does it mean for the call?';
          scope = chatScope();
        }
        openChatPrefilled(q, scope);
      });
      head.appendChild(explain);
    }
    parent.appendChild(head);
  }

  function renderInfoContents() {
    var panel = $('info-contents');
    if (!panel) return;
    clear(panel);
    var row = selectedRow();
    if (!state.analysis) { emptyNote(panel, 'No capture open.'); return; }
    if (!row) {
      emptyNote(panel, 'Nothing selected.',
        'Pick a message in the ladder or the selection list to read its full text here — redacted, monospaced, with search terms highlighted.');
      return;
    }
    infoHeader(panel, row);

    if (row.kind === 'msg') {
      var m = row.obj || {};
      panel.appendChild(el('h4', 'ptree-title',
        m.protocol === 'h323' ? 'raw (hex \u2014 Q.931 / H.225)' : 'raw (redacted)'));
      var pre = el('pre', 'mono info-raw');
      appendHighlighted(pre, m.raw, state.searchTerms);
      panel.appendChild(pre);
      panel.appendChild(el('p', 'pane-empty',
        'Digest credentials are redacted server-side before the analysis is stored.'));
      return;
    }

    if (row.kind === 'media') {
      var st = row.obj || {};
      var g = ptreeGroup(ptree(panel), 'media stream');
      kv(g, 'kind', st.kind);
      kv(g, 'path', pathOf(st));
      kv(g, 'ssrc', st.ssrc);
      kv(g, 'codec', str(st.codec) + (st.clockRate ? ' @ ' + st.clockRate : ''));
      kv(g, 'packets', st.packets);
      kv(g, 'bytes', fmtBytes(st.bytes));
      kv(g, 'duration', st.durationSec == null ? null : st.durationSec + ' s');
      if (st.kind === 'srtp') {
        panel.appendChild(el('p', 'pane-empty',
          'SRTP: the payload is encrypted. hiccup reports header-derived statistics only and never attempts decryption.'));
      }
      return;
    }

    var x = row.obj || {};
    panel.appendChild(el('h4', 'ptree-title', str(x.protocol || 'aux').toUpperCase() + ' observation'));
    var sum = el('p', 'mono info-aux-summary');
    appendHighlighted(sum, x.summary, state.searchTerms);
    panel.appendChild(sum);
    if (x.raw) {
      var praw = el('pre', 'mono info-raw');
      appendHighlighted(praw, x.raw, state.searchTerms);
      panel.appendChild(praw);
    } else {
      panel.appendChild(el('p', 'pane-empty', 'No raw bytes retained for this observation.'));
    }
  }

  /** One `.ptree-row` of the parsed-packet tree: key + monospace value. */
  function kv(group, k, v, flagged) {
    if (v == null || v === '') return;
    var row = el('div', 'ptree-row' + (flagged ? ' is-flagged' : ''));
    row.appendChild(el('span', 'ptree-key', k));
    var val = el('span', 'ptree-val mono');
    appendHighlighted(val, String(v), state.searchTerms);
    row.appendChild(val);
    group.appendChild(row);
  }

  /** A titled `.ptree-group` inside a `.ptree`. */
  function ptreeGroup(parent, title) {
    var g = el('div', 'ptree-group');
    if (title) g.appendChild(el('div', 'ptree-title', title));
    parent.appendChild(g);
    return g;
  }

  function ptree(parent) {
    var t = el('div', 'ptree');
    parent.appendChild(t);
    return t;
  }

  /**
   * Generic value tree for per-protocol `detail` objects — every leaf rendered
   * with textContent, nested as .ptree-group/.ptree-row so app.css styles it.
   */
  function valueTree(container, value, depth) {
    depth = depth || 0;
    if (value === null || value === undefined) {
      container.appendChild(el('span', 'ptree-val muted', '\u2014'));
      return;
    }
    var t = typeof value;
    if (t === 'string' || t === 'number' || t === 'boolean') {
      var span = el('span', 'ptree-val mono');
      appendHighlighted(span, String(value), state.searchTerms);
      container.appendChild(span);
      return;
    }
    if (depth > 6) {
      var flat = el('span', 'ptree-val mono');
      try { flat.textContent = JSON.stringify(value).slice(0, 400); }
      catch (e) { flat.textContent = '(unserializable)'; }
      container.appendChild(flat);
      return;
    }
    if (Array.isArray(value)) {
      if (!value.length) { container.appendChild(el('span', 'ptree-val muted', '(empty)')); return; }
      var list = el('div', 'tree-children');
      for (var i = 0; i < value.length; i++) {
        var item = el('div', 'ptree-row');
        item.appendChild(el('span', 'ptree-key', '[' + i + ']'));
        valueTree(item, value[i], depth + 1);
        list.appendChild(item);
      }
      container.appendChild(list);
      return;
    }
    var keys = [];
    try { keys = Object.keys(value); } catch (e) { keys = []; }
    if (!keys.length) { container.appendChild(el('span', 'ptree-val muted', '(empty)')); return; }
    var box = el('div', 'tree-children');
    for (var k = 0; k < keys.length; k++) {
      if (keys[k] === 'raw' && typeof value[keys[k]] === 'string' && value[keys[k]].length > 600) continue;
      var node = el('div', 'ptree-row');
      node.appendChild(el('span', 'ptree-key', keys[k]));
      valueTree(node, value[keys[k]], depth + 1);
      box.appendChild(node);
    }
    container.appendChild(box);
  }

  function section(parent, title) {
    var h = el('h4', 'ptree-title info-sub', title);
    parent.appendChild(h);
    return h;
  }

  function renderInfoPacket() {
    var panel = $('info-packet');
    if (!panel) return;
    clear(panel);
    var row = selectedRow();
    if (!state.analysis) { emptyNote(panel, 'No capture open.'); return; }
    if (!row) {
      emptyNote(panel, 'Nothing selected.',
        'The parsed view: SIP headers and SDP, ISUP parameters for SIP-I bodies, Q.931 information elements for H.323 — field by field.');
      return;
    }
    infoHeader(panel, row);
    var tree = ptree(panel);

    if (row.kind !== 'msg') {
      var dg = ptreeGroup(tree, str(row.kind === 'media' ? 'stream' : (row.obj && row.obj.protocol) || 'aux') + ' detail');
      valueTree(dg, (row.obj && row.obj.detail) || row.obj, 0);
      return;
    }

    var m = row.obj || {};

    if (m.protocol === 'h323' || m.q931Type) {
      var hg = ptreeGroup(tree, 'Q.931 / H.225');
      kv(hg, 'message type', m.q931Type);
      kv(hg, 'summary', m.summary);
      kv(hg, 'time', fmtClock(m.ts));
      kv(hg, 'path', pathOf(m) + ' (' + str(m.transport) + ')');
      kv(hg, 'size', m.size == null ? null : m.size + ' B');

      var ig = ptreeGroup(tree, 'information elements');
      kv(ig, 'call reference', m.callRef == null ? null : m.callRef + ' (flag ' + (m.callRefFlag ? 1 : 0) + ')');
      kv(ig, 'Calling Party Number (0x6C)', m.calling);
      kv(ig, 'Called Party Number (0x70)', m.called);
      if (m.causeCode != null) {
        kv(ig, 'Cause (0x08)', m.causeCode + (m.causeText ? ' \u2014 ' + m.causeText : ''), true);
      }
      kv(ig, 'User-User (0x7E) callIdentifier', m.guid);
      kv(ig, 'fastStart', m.hasFastStart ? 'present (heuristic)' : 'not seen');
      if (!ig.querySelector || !ig.querySelector('.ptree-row')) {
        ig.appendChild(el('p', 'pane-empty', 'No decodable IEs in this message.'));
      }
      if (Array.isArray(m.ies) && m.ies.length) {
        valueTree(ptreeGroup(tree, 'additional IEs'), m.ies, 0);
      }
      return;
    }

    var g = ptreeGroup(tree, m.isRequest ? 'request' : 'response');
    kv(g, 'line', m.isRequest
      ? (str(m.method) + ' ' + str(m.requestUri || ''))
      : ('SIP/2.0 ' + str(m.status) + ' ' + str(m.reason || '')),
      !m.isRequest && nnum(m.status) != null && m.status >= 400);
    kv(g, 'time', fmtClock(m.ts));
    kv(g, 'path', pathOf(m) + ' (' + str(m.transport) + ')');
    kv(g, 'Call-ID', m.callId);
    kv(g, 'From', str(m.fromUri) + (m.fromTag ? ';tag=' + m.fromTag : ''));
    kv(g, 'To', str(m.toUri) + (m.toTag ? ';tag=' + m.toTag : ''));
    if (m.cseq) kv(g, 'CSeq', str(m.cseq.num) + ' ' + str(m.cseq.method));
    kv(g, 'branch', m.branch);
    kv(g, 'Contact', m.contact);
    kv(g, 'body type', m.bodyType);
    kv(g, 'size', m.size == null ? null : m.size + ' B');
    if (m.retransOf) kv(g, 'retransmission of', m.retransOf, true);
    var legId = state.msgToLeg[m.id];
    if (legId) {
      kv(g, 'leg', legId + (state.legToCall[legId] ? ' (call ' + state.legToCall[legId] + ')' : ''));
    }

    var headers = arr(m.headers);
    var hg2 = ptreeGroup(tree, 'headers');
    if (!headers.length) {
      hg2.appendChild(el('p', 'pane-empty', 'No headers parsed.'));
    } else {
      for (var i = 0; i < headers.length; i++) {
        if (!headers[i]) continue;
        kv(hg2, str(headers[i].name), headers[i].value);
      }
    }

    if (m.sdp) {
      var sg = ptreeGroup(tree, 'SDP');
      if (m.sdp.origin) {
        kv(sg, 'o= origin', str(m.sdp.origin.user) + ' ' + str(m.sdp.origin.sessId) + ' ' +
          str(m.sdp.origin.sessVersion) + ' IN ' + str(m.sdp.origin.addr));
      }
      kv(sg, 'c= connection', m.sdp.connection);
      var sattrs = arr(m.sdp.sessionAttrs);
      if (sattrs.length) kv(sg, 'session a=', sattrs.join('  \u00b7  '));

      var mblocks = arr(m.sdp.media);
      if (!mblocks.length) {
        sg.appendChild(el('p', 'pane-empty', 'No m= blocks.'));
      } else {
        for (var b = 0; b < mblocks.length; b++) {
          var mb = mblocks[b] || {};
          var mg = ptreeGroup(tree, 'm=' + str(mb.type || '?') + ' block');
          kv(mg, 'm=', str(mb.type) + ' ' + str(mb.port) + ' ' + str(mb.proto));
          var pls = arr(mb.payloads).map(function (pl) {
            if (!pl) return '';
            return str(pl.pt) + ' ' + str(pl.codec || '?') + (pl.rate ? '/' + pl.rate : '') +
              (pl.fmtp ? ' (' + pl.fmtp + ')' : '');
          }).filter(Boolean);
          if (pls.length) kv(mg, 'payloads', pls.join('  \u00b7  '));
          kv(mg, 'ptime', mb.ptime);
          kv(mg, 'direction', mb.direction);
          var ma = arr(mb.attrs);
          if (ma.length) kv(mg, 'a=', ma.join('  \u00b7  '));
        }
      }
    }

    if (m.isup) {
      var ig2 = ptreeGroup(tree, 'ISUP (SIP-I)');
      kv(ig2, 'message type', m.isup.messageType);
      kv(ig2, 'called party', m.isup.calledParty);
      kv(ig2, 'calling party', m.isup.callingParty);
      if (m.isup.causeCode != null) {
        kv(ig2, 'cause', m.isup.causeCode + (m.isup.causeText ? ' \u2014 ' + m.isup.causeText : ''), true);
      }
      kv(ig2, 'nature of connection', m.isup.natureOfConnection);
      var params = arr(m.isup.params);
      if (params.length) {
        var pg = ptreeGroup(tree, 'ISUP parameters');
        for (var pi = 0; pi < params.length; pi++) {
          if (params[pi]) kv(pg, str(params[pi].name), params[pi].value);
        }
      } else {
        ig2.appendChild(el('p', 'pane-empty', 'No ISUP parameters decoded.'));
      }
    }

    if (Array.isArray(m.bodyParts) && m.bodyParts.length) {
      for (var bp = 0; bp < m.bodyParts.length; bp++) {
        var part = m.bodyParts[bp] || {};
        var bg = ptreeGroup(tree, 'body part \u2014 ' + str(part.contentType || '?') +
          (part.disposition ? ' (' + part.disposition + ')' : ''));
        var ppre = el('pre', 'mono info-raw');
        appendHighlighted(ppre, part.body, state.searchTerms);
        bg.appendChild(ppre);
      }
    }

    var col = state.collapseByMsg[m.id];
    if (col) {
      var cg = ptreeGroup(tree, 'retransmission collapse');
      kv(cg, 'label', col.label, true);
      kv(cg, 'count', col.count);
      kv(cg, 'outcome', col.outcome);
      if (col.classification) {
        kv(cg, 'classification', str(col.classification.code) +
          ' (' + Math.round((col.classification.confidence || 0) * 100) + '%)');
        kv(cg, 'likely cause', col.classification.cause);
        kv(cg, 'evidence', col.classification.detail);
      }
    }
  }

  // ------------------------------------------------------------ Media tab

  /**
   * A small loss-over-time sparkline. Prefers the RTCP fraction-lost series for
   * this SSRC; falls back to bucketed silence/black-hole gaps.
   * @returns {HTMLElement} a .spark-host wrapping an svg.spark
   */
  function lossSparkline(stream) {
    var SVGNS = 'http://www.w3.org/2000/svg';
    var W = 96, H = 18;
    var host = el('div', 'spark-host');
    var svg = document.createElementNS(SVGNS, 'svg');
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.setAttribute('preserveAspectRatio', 'none');
    svg.setAttribute('class', 'spark');
    svg.setAttribute('role', 'img');
    host.appendChild(svg);

    var series = [], label = '', isLoss = true;
    var reports = rtcpReports();
    var ssrc = stream && stream.ssrc;
    if (ssrc != null) {
      var pts = [];
      for (var i = 0; i < reports.length; i++) {
        var rep = reports[i];
        var blocks = arr(rep && rep.blocks);
        for (var b = 0; b < blocks.length; b++) {
          if (blocks[b] && blocks[b].ssrc === ssrc && nnum(blocks[b].fractionLostPct) != null) {
            pts.push({ ts: nnum(rep.ts), v: blocks[b].fractionLostPct });
          }
        }
      }
      pts.sort(function (a, b2) { return (a.ts || 0) - (b2.ts || 0); });
      if (pts.length > 1) {
        series = pts.map(function (pt) { return pt.v; });
        label = 'RTCP fraction-lost over time (%)';
      }
    }
    if (!series.length) {
      var gaps = arr(stream && stream.gaps);
      var first = nnum(stream && stream.firstTs);
      var last = nnum(stream && stream.lastTs);
      var buckets = 24;
      var vals = [];
      for (var z = 0; z < buckets; z++) vals.push(0);
      if (gaps.length && first != null && last != null && last > first) {
        for (var gi = 0; gi < gaps.length; gi++) {
          var ts = nnum(gaps[gi] && gaps[gi].ts);
          if (ts == null) continue;
          var idx = Math.min(buckets - 1, Math.max(0, Math.floor(((ts - first) / (last - first)) * buckets)));
          vals[idx] += nnum(gaps[gi].ms) || 0;
        }
        series = vals;
        label = 'silence / black-hole gap milliseconds over the stream';
        isLoss = false;
      }
    }

    var title = document.createElementNS(SVGNS, 'title');
    if (!series.length) {
      title.textContent = 'no loss series available' +
        (nnum(stream && stream.lossPct) != null ? ' (overall ' + stream.lossPct + '% lost)' : '');
      svg.appendChild(title);
      var axis = document.createElementNS(SVGNS, 'line');
      axis.setAttribute('x1', 1); axis.setAttribute('y1', H - 1.5);
      axis.setAttribute('x2', W - 1); axis.setAttribute('y2', H - 1.5);
      axis.setAttribute('class', 'spark-axis');
      svg.appendChild(axis);
      host.title = title.textContent;
      return host;
    }
    title.textContent = label;
    svg.appendChild(title);
    host.title = label;

    var max = 0;
    for (var s2 = 0; s2 < series.length; s2++) max = Math.max(max, series[s2]);
    if (max <= 0) max = 1;
    var step = (W - 2) / series.length;
    var bw = Math.max(1, step - 1);
    for (var k = 0; k < series.length; k++) {
      if (!(series[k] > 0)) continue;
      var h = Math.max(1.5, (series[k] / max) * (H - 3));
      var rect = document.createElementNS(SVGNS, 'rect');
      rect.setAttribute('x', 1 + k * step);
      rect.setAttribute('y', H - 1 - h);
      rect.setAttribute('width', bw);
      rect.setAttribute('height', h);
      rect.setAttribute('class', 'spark-bar' + (isLoss ? ' is-loss' : ' spark-gap'));
      svg.appendChild(rect);
    }
    return host;
  }

  function renderInfoMedia() {
    var panel = $('info-media');
    if (!panel) return;
    clear(panel);
    if (!state.analysis) { emptyNote(panel, 'No capture open.'); return; }

    var streams = mediaStreams().filter(matchesScopeAssoc);
    var reports = rtcpReports().filter(matchesScopeAssoc);

    if (!streams.length && !reports.length) {
      emptyNote(panel, 'No media in this selection.',
        mediaStreams().length
          ? 'This selection has no RTP/RTCP associated with it — widen it to the whole capture in the tree.'
          : 'This capture has no RTP/RTCP: signalling only, or an analysis produced before the media module existed.');
      return;
    }

    if (streams.length) {
      section(panel, 'streams');
      var scroll = el('div', 'scroll-area');
      var table = el('table', 'table-dense media-table');
      var thead = el('thead');
      var hr = el('tr');
      var cols = ['stream', 'kind', 'path', 'ssrc', 'codec', 'pkts', 'loss %', 'jitter ms mean/max', 'MOS', 'loss over time'];
      for (var c = 0; c < cols.length; c++) {
        var th = el('th', /pkts|loss %|jitter|MOS/.test(cols[c]) ? 'num' : null, cols[c]);
        if (cols[c] === 'MOS') {
          th.title = 'ESTIMATE only — ITU-T G.107 simplified E-model from packet loss and jitter, not a listening test';
        }
        hr.appendChild(th);
      }
      thead.appendChild(hr);
      table.appendChild(thead);

      var tbody = el('tbody');
      for (var i = 0; i < streams.length; i++) {
        (function (st) {
          var tint = (nnum(st.lossPct) != null && st.lossPct >= 5) ? ' tint-crit'
            : (st.oneWay || (nnum(st.lossPct) != null && st.lossPct >= 1) ? ' tint-warn' : '');
          var tr = el('tr', 'media-row' + tint);
          tr.appendChild(el('td', 'mono', str(st.id)));
          var kindTd = el('td', 'mono', str(st.kind));
          if (st.kind === 'srtp') kindTd.title = 'encrypted — statistics from headers only, no decryption attempted';
          tr.appendChild(kindTd);
          tr.appendChild(el('td', 'mono', pathOf(st)));
          tr.appendChild(el('td', 'mono', st.ssrc == null ? '\u2014' : String(st.ssrc)));
          tr.appendChild(el('td', 'mono', str(st.codec || '\u2014')));
          tr.appendChild(el('td', 'num', st.packets == null ? '\u2014' : String(st.packets)));

          var lossTd = el('td', 'num', fmtNum(st.lossPct, 2));
          if (nnum(st.lossPct) != null && st.lossPct >= 5) lossTd.classList.add('sev-crit');
          else if (nnum(st.lossPct) != null && st.lossPct >= 1) lossTd.classList.add('sev-warn');
          tr.appendChild(lossTd);

          tr.appendChild(el('td', 'num', fmtNum(st.meanJitterMs, 1) + ' / ' + fmtNum(st.maxJitterMs, 1)));

          var mosTd = el('td', 'num');
          var mos = el('span', 'mos' + (nnum(st.mos) != null && st.mos < 3.6 ? ' sev-warn' : ''), fmtNum(st.mos, 1));
          mosTd.appendChild(mos);
          var est = el('span', 'badge-estimate', 'est.');
          est.title = 'estimate' + (st.mosMethod ? ' \u2014 method: ' + st.mosMethod : '');
          mosTd.appendChild(est);
          tr.appendChild(mosTd);

          var sparkTd = el('td');
          sparkTd.appendChild(lossSparkline(st));
          tr.appendChild(sparkTd);

          var flags = [];
          if (st.oneWay) flags.push('one-way — no reverse stream seen for a paired leg');
          if (nnum(st.maxGapMs) != null && st.maxGapMs > 0) flags.push('max gap ' + st.maxGapMs + 'ms');
          if (nnum(st.outOfOrder) ) flags.push(st.outOfOrder + ' out of order');
          if (st.ssrcChanges) flags.push(st.ssrcChanges + ' SSRC change(s)');
          if (st.markerResets) flags.push(st.markerResets + ' marker reset(s)');
          if (arr(st.dtmfEvents).length) flags.push(arr(st.dtmfEvents).length + ' RFC 4733 DTMF event(s)');
          if (flags.length) tr.title = flags.join('  \u00b7  ');
          tbody.appendChild(tr);
        })(streams[i]);
      }
      table.appendChild(tbody);
      scroll.appendChild(table);
      panel.appendChild(scroll);
      panel.appendChild(el('p', 'spark-caption',
        'MOS is an ESTIMATE derived from loss and jitter (ITU-T G.107 simplified) — not a listening test. ' +
        'The sparkline is RTCP fraction-lost where available, otherwise silence gaps.'));
    }

    if (reports.length) {
      section(panel, 'RTCP');
      var rscroll = el('div', 'scroll-area');
      var rtable = el('table', 'table-dense rtcp-table');
      var rhead = el('thead');
      var rhr = el('tr');
      var rcols = ['time', 'path', 'type', 'ssrc', 'cname', 'fraction lost %', 'cumulative lost', 'jitter', 'RTT ms'];
      for (var rc = 0; rc < rcols.length; rc++) {
        rhr.appendChild(el('th', /lost|jitter|RTT/.test(rcols[rc]) ? 'num' : null, rcols[rc]));
      }
      rhead.appendChild(rhr);
      rtable.appendChild(rhead);
      var rbody = el('tbody');
      for (var r = 0; r < reports.length; r++) {
        var rep = reports[r] || {};
        var blocks = arr(rep.blocks);
        if (!blocks.length) blocks = [null];
        for (var b = 0; b < blocks.length; b++) {
          var blk = blocks[b] || {};
          var trr = el('tr', 'rtcp-row' +
            (nnum(blk.fractionLostPct) != null && blk.fractionLostPct >= 5 ? ' tint-crit' : ''));
          trr.appendChild(el('td', 'mono', fmtClock(rep.ts)));
          trr.appendChild(el('td', 'mono', pathOf(rep)));
          trr.appendChild(el('td', 'mono', str(rep.type || '\u2014')));
          trr.appendChild(el('td', 'mono',
            blk.ssrc == null ? str(rep.ssrc == null ? '\u2014' : rep.ssrc) : String(blk.ssrc)));
          trr.appendChild(el('td', 'mono', str(rep.cname || '\u2014')));
          trr.appendChild(el('td', 'num', fmtNum(blk.fractionLostPct, 2)));
          trr.appendChild(el('td', 'num', blk.cumulativeLost == null ? '\u2014' : String(blk.cumulativeLost)));
          trr.appendChild(el('td', 'num', blk.jitter == null ? '\u2014' : String(blk.jitter)));
          trr.appendChild(el('td', 'num', fmtNum(blk.rttMs, 1)));
          rbody.appendChild(trr);
        }
      }
      rtable.appendChild(rbody);
      rscroll.appendChild(rtable);
      panel.appendChild(rscroll);
    }
  }

  // ------------------------------------------------- Advice (in the drawer)

  /** Does this Advice object touch the current scope? */
  function adviceInScope(a) {
    var sel = state.sel;
    if (sel.type === 'capture' && !state.selectedRowId) return true;
    var fids = arr(a && a.findingIds);
    if (!fids.length) return sel.type === 'capture';
    var legIds = scopeLegIds();
    for (var i = 0; i < fids.length; i++) {
      var f = state.findingById[fids[i]];
      if (!f) continue;
      if (sel.type === 'call' && arr(f.callIds).indexOf(sel.callId) !== -1) return true;
      if (state.selectedRowId && arr(f.msgIds).indexOf(state.selectedRowId) !== -1) return true;
      if (legIds) {
        var lids = arr(f.legIds);
        for (var j = 0; j < lids.length; j++) { if (legIds.indexOf(lids[j]) !== -1) return true; }
        var mids = arr(f.msgIds);
        for (var k = 0; k < mids.length; k++) {
          if (legIds.indexOf(state.msgToLeg[mids[k]]) !== -1) return true;
        }
      } else {
        return true;
      }
    }
    return false;
  }

  function findingInScope(f) {
    var sel = state.sel;
    if (sel.type === 'capture') return true;
    var legIds = scopeLegIds();
    if (sel.type === 'call' && arr(f.callIds).indexOf(sel.callId) !== -1) return true;
    if (legIds) {
      var lids = arr(f.legIds);
      for (var j = 0; j < lids.length; j++) { if (legIds.indexOf(lids[j]) !== -1) return true; }
      var mids = arr(f.msgIds);
      for (var k = 0; k < mids.length; k++) {
        if (legIds.indexOf(state.msgToLeg[mids[k]]) !== -1) return true;
      }
    }
    return false;
  }

  /**
   * Wave 4: the Advice cards live in the always-open drawer, above the
   * conversation. Same cards, same scoping, same severity ordering as the old
   * #info-advice panel — only the host node moved. Called from renderDrawer()
   * on every scope change, so it never needs a manual refresh.
   */
  function renderDrawerAdvice() {
    var panel = $('chat-advice-body');
    if (!panel) return;
    clear(panel);
    setAdviceCount(null);
    if (!state.analysis) { emptyNote(panel, 'No capture open.'); return; }

    // Scenario block — the "what am I even looking at" header.
    var sc = state.analysis.scenario;
    if (sc && sc.primary) {
      var scard = el('div', 'advice-card scenario-card');
      var stop = el('div', 'advice-title');
      stop.appendChild(el('span', 'chip', str(sc.primary)));
      stop.appendChild(el('span', 'mono muted',
        ' confidence ' + Math.round((nnum(sc.confidence) || 0) * 100) + '%'));
      scard.appendChild(stop);
      if (sc.detail) scard.appendChild(el('p', 'advice-block', str(sc.detail)));
      var sigs = objs(sc.signals);
      if (sigs.length) {
        var sul = el('ul', 'fix-steps');
        for (var si = 0; si < sigs.length; si++) {
          var sg = sigs[si];
          var sli = el('li', null);
          sli.appendChild(el('span', 'mono', str(sg.name)));
          if (sg.weight != null) sli.appendChild(el('span', 'muted', ' (' + sg.weight + ')'));
          if (sg.detail) sli.appendChild(document.createTextNode(' \u2014 ' + str(sg.detail)));
          sul.appendChild(sli);
        }
        scard.appendChild(sul);
      }
      var alts = objs(sc.alternatives);
      if (alts.length) {
        scard.appendChild(el('p', 'pane-empty', 'alternatives: ' + alts.map(function (a) {
          return str(a.primary) + ' ' + Math.round((a.confidence || 0) * 100) + '%';
        }).join('  \u00b7  ')));
      }
      panel.appendChild(scard);
    }

    var advice = adviceList().filter(adviceInScope);
    advice.sort(function (a, b) { return sevRank(a.severity) - sevRank(b.severity); });

    if (advice.length) {
      for (var i = 0; i < advice.length; i++) panel.appendChild(adviceCard(advice[i]));
    }

    // Findings fallback (Wave-1 captures have no advice at all).
    var findings = findingsList().filter(findingInScope);
    findings.sort(function (a, b) { return sevRank(a.severity) - sevRank(b.severity); });
    var covered = {};
    for (var a2 = 0; a2 < advice.length; a2++) {
      var fids = arr(advice[a2].findingIds);
      for (var f2 = 0; f2 < fids.length; f2++) covered[fids[f2]] = true;
    }
    var uncovered = findings.filter(function (f) { return !f || !f.id || !covered[f.id]; });
    if (uncovered.length) {
      section(panel, advice.length ? 'Other findings' : 'Findings');
      if (!advice.length) {
        panel.appendChild(el('p', 'pane-empty',
          'This analysis has no advisory objects — findings are shown raw. ' +
          'Re-upload the capture once the advisor module is live to get cited fixes.'));
      }
      for (var u = 0; u < uncovered.length; u++) panel.appendChild(findingCard(uncovered[u]));
    }

    setAdviceCount(advice.length + uncovered.length);

    // Retransmission classification for this scope.
    var cols = collapsesList().filter(function (c) {
      var legIds = scopeLegIds();
      if (!legIds) return true;
      return legIds.indexOf(c && c.legId) !== -1;
    });
    if (cols.length) {
      section(panel, 'Retransmissions');
      for (var c2 = 0; c2 < cols.length; c2++) panel.appendChild(collapseCard(cols[c2]));
    }

    var storms = (state.analysis.retrans && state.analysis.retrans.aggregate &&
      arr(state.analysis.retrans.aggregate.stormWindows)) || [];
    if (storms.length && state.sel.type === 'capture') {
      section(panel, 'Box-wide storms');
      for (var s3 = 0; s3 < storms.length; s3++) {
        var w = storms[s3] || {};
        var stormCard = el('div', 'advice-card sev-crit');
        var stormTop = el('div', 'advice-title');
        stormTop.appendChild(sevChip('crit'));
        stormTop.appendChild(el('span', 'chip', str(w.verdict || 'box-wide')));
        stormTop.appendChild(el('span', 'advice-title-text',
          str(w.legsAffected) + ' legs retransmitting together'));
        stormCard.appendChild(stormTop);
        stormCard.appendChild(el('p', 'advice-block',
          str(w.retransCount) + ' retransmissions between ' + fmtClock(w.startTs) + ' and ' +
          fmtClock(w.endTs) + '. This is the box melting, not one broken call — look at licence ' +
          'exhaustion, CPU, or an unreachable session agent before you look at the call.'));
        panel.appendChild(stormCard);
      }
    }

    if (!panel.firstChild) {
      emptyNote(panel, 'Nothing to advise on for this selection.',
        'hiccup found no warn/crit conditions here. Widen the selection to the whole capture in the tree.');
    }
  }

  /**
   * The little count chip on the drawer's advice header. Neutral by design —
   * it says how many cards are in scope, never what colour the worst one is
   * (the cards carry their own severity accents).
   * @param {?number} n card count, or null for "no capture / nothing yet"
   */
  function setAdviceCount(n) {
    var chip = $('chat-advice-count');
    if (!chip) return;
    if (n == null) { chip.textContent = ''; chip.title = ''; return; }
    chip.textContent = n ? String(n) : 'none';
    chip.title = n === 1
      ? '1 advisory card for the current selection'
      : n + ' advisory cards for the current selection';
  }

  /** Reveal the drawer's advice section and put focus on it. */
  function focusDrawerAdvice() {
    if (!state.chatOpen) { state.chatOpen = true; applyDrawerOpen(); renderDrawer(); }
    var body = $('chat-advice-body');
    if (body) body.scrollTop = 0;
    var box = $('chat-advice');
    if (box && typeof box.focus === 'function') {
      try { box.focus(); } catch (e) { /* focus is a nicety, never fatal */ }
    }
  }

  function explainButton(question, scope, label) {
    var b = el('button', 'explain-btn', label || 'explain in chat');
    b.type = 'button';
    b.addEventListener('click', function (ev) {
      ev.stopPropagation();
      openChatPrefilled(question, scope);
    });
    return b;
  }

  function adviceCard(a) {
    if (!a) {
      var stub = el('div', 'advice-card');
      stub.appendChild(el('p', 'pane-empty', '(empty advice)'));
      return stub;
    }
    var card = el('div', 'advice-card sev-' + str(a.severity || 'info'));
    var top = el('div', 'advice-title');
    top.appendChild(sevChip(a.severity));
    top.appendChild(el('span', 'advice-title-text', str(a.title || '(untitled advice)')));
    top.appendChild(explainButton(
      'Explain this advice in your own words: "' + str(a.title) + '". ' +
      'Use only the supplied Advice object and its citations — do not invent RFC section numbers.',
      firstScopeForAdvice(a)));
    card.appendChild(top);

    function block(labelText, text, extra) {
      if (!text) return;
      var wrap = el('p', 'advice-block' + (extra ? ' ' + extra : ''));
      wrap.appendChild(el('span', 'advice-label', labelText));
      var span = el('span', 'advice-text');
      appendHighlighted(span, text, state.searchTerms);
      wrap.appendChild(span);
      card.appendChild(wrap);
    }
    block('what is wrong', a.whatsWrong, 'is-whats-wrong');
    block('why it matters', a.whyItMatters, 'is-why');
    block('mechanism', a.mechanism, 'is-mechanism');

    var fixes = objs(a.fixes);
    for (var i = 0; i < fixes.length; i++) card.appendChild(fixCard(fixes[i]));

    var cites = objs(a.citations);
    if (cites.length) {
      var ul = el('ul', 'citation-list');
      for (var c = 0; c < cites.length; c++) {
        var cit = cites[c];
        var li = el('li', 'citation');
        var label = str(cit.source || 'reference') + (cit.section ? ' ' + cit.section : '');
        var href = safeHref(cit.url);
        if (href) {
          var link = el('a', 'citation-link', label);
          link.href = href;
          link.target = '_blank';
          link.rel = 'noopener';
          link.title = 'opens in a new tab';
          li.appendChild(link);
        } else {
          li.appendChild(el('span', 'citation-link is-unlinked', label));
        }
        if (cit.title) li.appendChild(el('span', 'citation-title', ' ' + str(cit.title)));
        if (cit.note) li.appendChild(el('span', 'citation-note', ' \u2014 ' + str(cit.note)));
        ul.appendChild(li);
      }
      card.appendChild(ul);
    }

    var kbs = objs(a.kbCitations);
    if (kbs.length) {
      var kul = el('ul', 'kb-list');
      for (var k = 0; k < kbs.length; k++) {
        var kb = kbs[k];
        var kli = el('li', 'kb-hit');
        kli.appendChild(el('span', 'kb-src', str(kb.docTitle || 'document')));
        if (kb.page != null) kli.appendChild(el('span', 'kb-page', ' p.' + kb.page));
        if (kb.heading) kli.appendChild(el('span', 'kb-page', ' \u00b7 ' + str(kb.heading)));
        if (kb.excerpt) {
          var q = el('div', 'kb-excerpt');
          appendHighlighted(q, kb.excerpt, state.searchTerms);
          kli.appendChild(q);
        }
        kul.appendChild(kli);
      }
      card.appendChild(kul);
      card.appendChild(el('p', 'pane-empty',
        'Guide excerpts ground a reviewable draft — they are not a verified change.'));
    }
    return card;
  }

  function fixCard(fix) {
    var box = el('div', 'fix-card');
    if (!fix) { box.appendChild(el('p', 'pane-empty', '(empty fix)')); return box; }
    var head = el('div', 'fix-head');
    head.appendChild(el('span', 'chip fix-target', str(fix.target || 'generic')));
    if (fix.confidence) {
      var conf = el('span', 'chip fix-conf', str(fix.confidence));
      conf.title = 'how likely this fix is to be the right one here';
      head.appendChild(conf);
    }
    head.appendChild(el('span', 'fix-summary', str(fix.summary || '')));
    box.appendChild(head);

    var steps = arr(fix.steps);
    if (steps.length) {
      var ol = el('ol', 'fix-steps');
      for (var i = 0; i < steps.length; i++) ol.appendChild(el('li', null, str(steps[i])));
      box.appendChild(ol);
    }
    if (fix.config) {
      var wrap = el('div', 'config-wrap');
      var pre = el('pre', 'mono fix-config');
      pre.textContent = str(fix.config);           // draft config — textContent only
      wrap.appendChild(pre);
      var copy = el('button', 'copy-btn', 'copy');
      copy.type = 'button';
      copy.title = 'copy this draft to the clipboard — review before applying';
      copy.addEventListener('click', function (ev) {
        ev.stopPropagation();
        copyText(str(fix.config), copy);
      });
      wrap.appendChild(copy);
      box.appendChild(wrap);
      box.appendChild(el('p', 'pane-empty', 'Draft only — review before applying to a live box.'));
    }
    if (fix.caution) box.appendChild(el('p', 'fix-caution', str(fix.caution)));
    return box;
  }

  function firstScopeForAdvice(a) {
    var fids = arr(a && a.findingIds);
    for (var i = 0; i < fids.length; i++) {
      var f = state.findingById[fids[i]];
      if (!f) continue;
      if (arr(f.callIds).length) return { type: 'call', id: arr(f.callIds)[0] };
      if (arr(f.msgIds).length) return { type: 'message', id: arr(f.msgIds)[0] };
      if (f.id) return { type: 'finding', id: f.id };
    }
    return chatScope();
  }

  function findingCard(f) {
    var card = el('div', 'advice-card finding-card sev-' + str(f && f.severity || 'info'));
    if (!f) { card.appendChild(el('p', 'pane-empty', '(empty finding)')); return card; }
    var top = el('div', 'advice-title');
    top.appendChild(sevChip(f.severity));
    top.appendChild(el('span', 'chip mono', str(f.category || '?')));
    top.appendChild(el('span', 'advice-title-text', str(f.title || '(untitled)')));
    top.appendChild(explainButton(
      'Explain this finding: "' + str(f.title) + '". What causes it and what should I check?',
      f.id ? { type: 'finding', id: f.id } : chatScope()));
    card.appendChild(top);
    if (f.detail) {
      var p2 = el('p', 'advice-block');
      appendHighlighted(p2, f.detail, state.searchTerms);
      card.appendChild(p2);
    }
    var refs = [];
    if (arr(f.callIds).length) refs.push('calls: ' + arr(f.callIds).join(', '));
    if (arr(f.legIds).length) refs.push('legs: ' + arr(f.legIds).join(', '));
    if (arr(f.msgIds).length) refs.push('msgs: ' + arr(f.msgIds).join(', '));
    if (refs.length) {
      var jump = el('button', 'explain-btn', refs.join('  \u00b7  '));
      jump.type = 'button';
      jump.title = 'jump to the first referenced object';
      jump.addEventListener('click', function (ev) { ev.stopPropagation(); jumpToFinding(f); });
      card.appendChild(jump);
    }
    return card;
  }

  function collapseCard(col) {
    var card = el('div', 'advice-card retrans-card sev-warn');
    if (!col) { card.appendChild(el('p', 'pane-empty', '(empty collapse)')); return card; }
    var cls = col.classification || {};
    var top = el('div', 'advice-title');
    top.appendChild(el('span', 'chip mono code-chip code-' + str(cls.code || 'unknown'),
      str(cls.code || 'unknown')));
    top.appendChild(el('span', 'advice-title-text',
      str(col.label || (str(col.method) + ' \u00d7' + str(col.count)))));
    if (cls.confidence != null) {
      top.appendChild(el('span', 'chip mono', Math.round((cls.confidence || 0) * 100) + '%'));
    }
    top.appendChild(explainButton(
      'Explain this retransmission pattern: "' + str(col.label) + '" classified as ' +
      str(cls.code) + '. What would cause it and how do I confirm it?',
      col.legId ? { type: 'leg', id: col.legId } : chatScope()));
    card.appendChild(top);
    if (cls.cause) {
      var cp = el('p', 'advice-block');
      cp.appendChild(el('span', 'advice-label', 'likely cause'));
      cp.appendChild(document.createTextNode(str(cls.cause)));
      card.appendChild(cp);
    }
    if (cls.detail) {
      var dp = el('p', 'advice-block');
      dp.appendChild(el('span', 'advice-label', 'evidence'));
      dp.appendChild(document.createTextNode(str(cls.detail)));
      card.appendChild(dp);
    }
    card.appendChild(el('p', 'pane-empty',
      str(col.legId || '') + '  \u00b7  ' + fmtClock(col.firstTs) + ' \u2192 ' + fmtClock(col.lastTs) +
      '  \u00b7  outcome ' + str(col.outcome || '?')));
    var first = arr(col.msgIds)[0];
    if (first) {
      var show = el('button', 'explain-btn', 'show in ladder');
      show.type = 'button';
      show.addEventListener('click', function (ev) {
        ev.stopPropagation();
        if (col.legId && state.legById[col.legId]) {
          state.sel = { type: 'leg', callId: state.legToCall[col.legId] || null, legId: col.legId, txKey: null };
        }
        state.selectedRowId = first;
        renderAll();
      });
      card.appendChild(show);
    }
    return card;
  }

  function jumpToFinding(f) {
    if (!f) return;
    var cids = arr(f.callIds), lids = arr(f.legIds), mids = arr(f.msgIds);
    if (cids.length && state.callById[cids[0]]) {
      state.sel = { type: 'call', callId: cids[0], legId: null, txKey: null };
    } else if (lids.length && state.legById[lids[0]]) {
      state.sel = { type: 'leg', callId: state.legToCall[lids[0]] || null, legId: lids[0], txKey: null };
    } else if (mids.length && state.msgToLeg[mids[0]]) {
      var lg = state.msgToLeg[mids[0]];
      state.sel = { type: 'leg', callId: state.legToCall[lg] || null, legId: lg, txKey: null };
    }
    if (mids.length) state.selectedRowId = mids[0];
    renderAll();
  }

  // -------------------------------------------------------------- search

  function wireSearchbar() {
    var input = $('search-input');
    var clearBtn = $('search-clear');
    if (input) {
      var run = debounce(function () {
        state.searchQuery = input.value || '';
        runSearch();
      }, 150);
      input.addEventListener('input', run);
      input.addEventListener('keydown', function (ev) {
        if (ev.key === 'Escape') { ev.preventDefault(); clearSearch(); }
        if (ev.key === 'Enter') { ev.preventDefault(); state.searchQuery = input.value || ''; runSearch(); }
      });
      input.setAttribute('placeholder',
        'search raw, headers, numbers…  or call: leg: callid: from: to: method: status: ip: port: codec: proto: sev: has:');
      input.setAttribute('title',
        'Substring search over raw messages, headers, URIs, Call-IDs, tags, branches, SDP, ' +
        'H.323 numbers, aux summaries, findings and advice.\n' +
        'Digits are matched phone-normalized: 654321 finds +33987654321.\n' +
        'Filters: call: leg: callid: from: to: method: status: ip: port: codec: ' +
        'proto:(sip|h323|rtp|dns|diameter|stun) sev:(crit|warn|notice|info) ' +
        'has:(t38|ims|sipi|srtp|dtmf|retrans|advice)');
    }
    if (clearBtn) {
      clearBtn.addEventListener('click', function (ev) { ev.preventDefault(); clearSearch(); });
      clearBtn.title = 'clear the search';
    }
  }

  function clearSearch() {
    var input = $('search-input');
    if (input) input.value = '';
    state.searchQuery = '';
    state.searchTerms = [];
    state.searchHits = [];
    state.searchMatchIds = {};
    state.searchActive = false;
    state.searchTruncated = false;
    renderSearchCount();
    renderFilterTree();
    renderSelectionList();
    renderLadder();
    renderInfo();
  }

  function pushField(fields, name, text) {
    if (text == null || text === '') return;
    var s = String(text);
    fields.push({ field: name, text: s, low: s.toLowerCase() });
  }

  function buildSearchIndex() {
    state.searchIndex = [];
    var a = state.analysis;
    if (!a) return;
    var idx = state.searchIndex;
    var i, j;

    // --- signalling messages
    var msgs = arr(a.messages);
    for (i = 0; i < msgs.length; i++) {
      var m = msgs[i];
      if (!m || !m.id) continue;
      var fields = [];
      var digits = [];
      var codecs = [];
      var tags = {};
      var isH = m.protocol === 'h323' || !!m.q931Type;

      if (isH) {
        pushField(fields, 'summary', m.summary);
        pushField(fields, 'q931', m.q931Type);
        pushField(fields, 'calling', m.calling);
        pushField(fields, 'called', m.called);
        if (m.causeCode != null) pushField(fields, 'cause', m.causeCode + ' ' + str(m.causeText));
        pushField(fields, 'guid', m.guid);
        pushField(fields, 'raw (hex)', m.raw);
        digits.push(digitsOf(m.calling), digitsOf(m.called));
      } else {
        pushField(fields, 'line', m.isRequest
          ? (str(m.method) + ' ' + str(m.requestUri))
          : ('SIP/2.0 ' + str(m.status) + ' ' + str(m.reason)));
        pushField(fields, 'Call-ID', m.callId);
        pushField(fields, 'From', m.fromUri);
        pushField(fields, 'To', m.toUri);
        pushField(fields, 'Contact', m.contact);
        pushField(fields, 'from-tag', m.fromTag);
        pushField(fields, 'to-tag', m.toTag);
        pushField(fields, 'branch', m.branch);
        var hdrs = arr(m.headers);
        for (j = 0; j < hdrs.length; j++) {
          if (!hdrs[j] || hdrs[j].name == null) continue;
          pushField(fields, str(hdrs[j].name), hdrs[j].value);
          var hn = str(hdrs[j].name).toLowerCase();
          if (IMS_HEADERS.indexOf(hn) !== -1) tags.ims = true;
        }
        if (m.sdp) {
          pushField(fields, 'SDP', m.sdp.raw);
          var mb = arr(m.sdp.media);
          for (j = 0; j < mb.length; j++) {
            var blk = mb[j] || {};
            if (str(blk.type).toLowerCase() === 'image' || /udptl|t38/i.test(str(blk.proto))) tags.t38 = true;
            if (/savp/i.test(str(blk.proto))) tags.srtp = true;
            var pls = arr(blk.payloads);
            for (var p = 0; p < pls.length; p++) {
              if (!pls[p]) continue;
              if (pls[p].codec) codecs.push(String(pls[p].codec));
              if (/telephone-event/i.test(str(pls[p].codec))) tags.dtmf = true;
            }
            var attrs = arr(blk.attrs);
            for (var at = 0; at < attrs.length; at++) {
              if (/^a?=?\s*crypto/i.test(str(attrs[at]))) tags.srtp = true;
              if (/telephone-event/i.test(str(attrs[at]))) tags.dtmf = true;
              if (/t38|udptl/i.test(str(attrs[at]))) tags.t38 = true;
              if (/curr:|des:|conf:/i.test(str(attrs[at]))) tags.ims = true;
            }
          }
          var satt = arr(m.sdp.sessionAttrs);
          for (var s2 = 0; s2 < satt.length; s2++) {
            if (/^a?=?\s*crypto/i.test(str(satt[s2]))) tags.srtp = true;
            if (/ice-ufrag/i.test(str(satt[s2]))) tags['stun-ice'] = true;
          }
        }
        if (m.isup) {
          tags.sipi = true;
          pushField(fields, 'ISUP', str(m.isup.messageType) + ' ' + str(m.isup.calledParty) + ' ' + str(m.isup.callingParty));
          var ips = arr(m.isup.params);
          for (var ip = 0; ip < ips.length; ip++) {
            if (ips[ip]) pushField(fields, 'ISUP ' + str(ips[ip].name), ips[ip].value);
          }
          digits.push(digitsOf(m.isup.calledParty), digitsOf(m.isup.callingParty));
        }
        var bps = arr(m.bodyParts);
        for (var bp = 0; bp < bps.length; bp++) {
          if (!bps[bp]) continue;
          pushField(fields, 'body ' + str(bps[bp].contentType), bps[bp].body);
          if (/isup/i.test(str(bps[bp].contentType))) tags.sipi = true;
        }
        pushField(fields, 'raw', m.raw);
        digits.push(digitsOf(uriUser(m.fromUri)), digitsOf(uriUser(m.toUri)), digitsOf(uriUser(m.requestUri)));
        if (/application\/isup/i.test(str(m.bodyType)) || /application\/isup/i.test(str(m.raw).slice(0, 4000))) tags.sipi = true;
      }

      if (m.retransOf || state.collapseByMsg[m.id]) tags.retrans = true;
      if (state.adviceMsgIds[m.id]) tags.advice = true;

      var legId = state.msgToLeg[m.id] || null;
      var leg = legId ? state.legById[legId] : null;
      if (leg) {
        digits.push(digitsOf(leg.fromUser), digitsOf(leg.toUser));
        if (leg.kind === 'register') { /* nothing extra */ }
      }

      var sev = null;
      var fs = findingsList();
      for (j = 0; j < fs.length; j++) {
        if (fs[j] && arr(fs[j].msgIds).indexOf(m.id) !== -1) {
          if (sev == null || sevRank(fs[j].severity) < sevRank(sev)) sev = fs[j].severity;
        }
      }

      idx.push({
        kind: 'msg',
        id: m.id,
        rowId: m.id,
        callId: state.msgToCall[m.id] || null,
        legId: legId,
        proto: isH ? 'h323' : 'sip',
        method: str(isH ? m.q931Type : (m.method || (m.cseq && m.cseq.method))),
        status: nnum(m.status),
        callid: str(m.callId),
        fromUri: str(m.fromUri), toUri: str(m.toUri),
        ips: [str(m.src), str(m.dst)],
        ports: [nnum(m.sport), nnum(m.dport)],
        codecs: codecs,
        sev: sev,
        tags: tags,
        fields: fields,
        digits: digits.join(' ')
      });
    }

    // --- media streams
    var streams = mediaStreams();
    for (i = 0; i < streams.length; i++) {
      var s = streams[i];
      if (!s) continue;
      var mf = [];
      pushField(mf, 'stream', str(s.id) + ' ' + str(s.kind) + ' ' + str(s.codec) +
        ' ssrc=' + str(s.ssrc) + ' ' + pathOf(s));
      pushField(mf, 'stats', 'packets=' + str(s.packets) + ' lost=' + str(s.lost) +
        ' lossPct=' + str(s.lossPct) + ' jitter=' + str(s.meanJitterMs) + ' mos=' + str(s.mos));
      var mtags = {};
      if (s.kind === 'srtp') mtags.srtp = true;
      if (s.kind === 't38-udptl') mtags.t38 = true;
      if (arr(s.dtmfEvents).length) mtags.dtmf = true;
      idx.push({
        kind: 'media', id: str(s.id), rowId: str(s.id),
        callId: callOf(s, 'media'), legId: arr(s.legIds)[0] || null,
        proto: 'rtp', method: '', status: null, callid: '',
        fromUri: '', toUri: '',
        ips: [str(s.src), str(s.dst)], ports: [nnum(s.sport), nnum(s.dport)],
        codecs: s.codec ? [String(s.codec)] : [],
        sev: null, tags: mtags, fields: mf, digits: ''
      });
    }

    // --- aux observations
    var auxes = auxMessages();
    for (i = 0; i < auxes.length; i++) {
      var x = auxes[i];
      if (!x) continue;
      var xf = [];
      pushField(xf, 'summary', x.summary);
      var detailText = '';
      try { detailText = JSON.stringify(x.detail); } catch (e) { detailText = ''; }
      pushField(xf, 'detail', detailText);
      pushField(xf, 'raw', x.raw);
      idx.push({
        kind: 'aux', id: str(x.id), rowId: str(x.id),
        callId: callOf(x, 'aux'), legId: arr(x.legIds)[0] || null,
        proto: str(x.protocol || 'aux'), method: '', status: null, callid: '',
        fromUri: '', toUri: '',
        ips: [str(x.src), str(x.dst)], ports: [nnum(x.sport), nnum(x.dport)],
        codecs: [], sev: null, tags: {}, fields: xf, digits: ''
      });
    }

    // --- findings
    var fsAll = findingsList();
    for (i = 0; i < fsAll.length; i++) {
      var f = fsAll[i];
      if (!f) continue;
      var ff = [];
      pushField(ff, 'finding', str(f.title));
      pushField(ff, 'detail', str(f.detail));
      idx.push({
        kind: 'finding', id: str(f.id), rowId: arr(f.msgIds)[0] || null,
        callId: arr(f.callIds)[0] || (arr(f.legIds).length ? state.legToCall[arr(f.legIds)[0]] : null) || null,
        legId: arr(f.legIds)[0] || null,
        proto: '', method: '', status: null, callid: '', fromUri: '', toUri: '',
        ips: [], ports: [], codecs: [], sev: f.severity || null,
        tags: {}, fields: ff, digits: ''
      });
    }

    // --- advice
    var adv = adviceList();
    for (i = 0; i < adv.length; i++) {
      var ad = adv[i];
      if (!ad) continue;
      var af = [];
      pushField(af, 'advice', str(ad.title));
      pushField(af, 'whatsWrong', str(ad.whatsWrong));
      pushField(af, 'whyItMatters', str(ad.whyItMatters));
      pushField(af, 'mechanism', str(ad.mechanism));
      var fixes = arr(ad.fixes);
      for (j = 0; j < fixes.length; j++) {
        if (!fixes[j]) continue;
        pushField(af, 'fix ' + str(fixes[j].target), str(fixes[j].summary) + ' ' +
          arr(fixes[j].steps).join(' ') + ' ' + str(fixes[j].config));
      }
      var cites = arr(ad.citations);
      for (j = 0; j < cites.length; j++) {
        if (!cites[j]) continue;
        pushField(af, 'citation', str(cites[j].source) + ' ' + str(cites[j].section) + ' ' + str(cites[j].title));
      }
      var firstF = state.findingById[arr(ad.findingIds)[0]];
      idx.push({
        kind: 'advice', id: str(ad.id), rowId: (firstF && arr(firstF.msgIds)[0]) || null,
        callId: (firstF && arr(firstF.callIds)[0]) || null,
        legId: (firstF && arr(firstF.legIds)[0]) || null,
        proto: '', method: '', status: null, callid: '', fromUri: '', toUri: '',
        ips: [], ports: [], codecs: [], sev: ad.severity || null,
        tags: { advice: true }, fields: af, digits: ''
      });
    }
  }

  /** Split a query into bare terms + field:value filters. */
  function parseQuery(q) {
    var terms = [], filters = [];
    var re = /"([^"]*)"|(\S+)/g;
    var m;
    while ((m = re.exec(str(q))) !== null) {
      var quoted = m[1] != null;
      var tok = quoted ? m[1] : m[2];
      if (!tok) continue;
      if (!quoted) {
        var c = tok.indexOf(':');
        if (c > 0) {
          var name = tok.slice(0, c).toLowerCase();
          if (SEARCH_FIELDS[name]) {
            var v = tok.slice(c + 1);
            if (v !== '') filters.push({ field: name, value: v, low: v.toLowerCase() });
            continue;
          }
        }
      }
      terms.push(tok);
    }
    return { terms: terms, filters: filters };
  }

  function isDigitQuery(t) {
    var s = str(t);
    if (!/^[+\-()\s.\d]+$/.test(s)) return false;
    return digitsOf(s).length >= 4;
  }

  function filterPass(item, f) {
    var v = f.low;
    var i;
    switch (f.field) {
      case 'call': return str(item.callId).toLowerCase() === v || str(item.callId).toLowerCase().indexOf(v) === 0;
      case 'leg': return str(item.legId).toLowerCase() === v || str(item.legId).toLowerCase().indexOf(v) === 0;
      case 'callid': return str(item.callid).toLowerCase().indexOf(v) !== -1;
      case 'from':
        return str(item.fromUri).toLowerCase().indexOf(v) !== -1 ||
          (isDigitQuery(f.value) && item.digits.indexOf(digitsOf(f.value)) !== -1);
      case 'to':
        return str(item.toUri).toLowerCase().indexOf(v) !== -1 ||
          (isDigitQuery(f.value) && item.digits.indexOf(digitsOf(f.value)) !== -1);
      case 'method': return str(item.method).toLowerCase().indexOf(v) !== -1;
      case 'status': return item.status != null && String(item.status).indexOf(f.value) === 0;
      case 'ip':
        for (i = 0; i < item.ips.length; i++) { if (item.ips[i].toLowerCase().indexOf(v) !== -1) return true; }
        return false;
      case 'port':
        for (i = 0; i < item.ports.length; i++) { if (item.ports[i] != null && String(item.ports[i]) === f.value) return true; }
        return false;
      case 'codec':
        for (i = 0; i < item.codecs.length; i++) { if (item.codecs[i].toLowerCase().indexOf(v) !== -1) return true; }
        return false;
      case 'proto': return str(item.proto).toLowerCase() === v || str(item.proto).toLowerCase().indexOf(v) === 0;
      case 'sev': return str(item.sev).toLowerCase() === v;
      case 'has': return !!item.tags[v];
      default: return true;
    }
  }

  function excerptAround(text, term, terms) {
    var s = str(text);
    var low = s.toLowerCase();
    var at = term ? low.indexOf(str(term).toLowerCase()) : 0;
    if (at < 0) at = 0;
    var start = Math.max(0, at - 42);
    var end = Math.min(s.length, at + Math.max(24, str(term).length) + 48);
    var out = (start > 0 ? '…' : '') + s.slice(start, end).replace(/[\r\n\t]+/g, ' ⏎ ') + (end < s.length ? '…' : '');
    return out;
  }

  function runSearch() {
    var q = str(state.searchQuery).trim();
    if (!q) { clearSearch(); return; }
    if (!state.analysis) { renderSearchCount(); return; }
    if (!state.searchIndex.length) buildSearchIndex();

    var parsed = parseQuery(q);
    var lows = parsed.terms.map(function (t) { return str(t).toLowerCase(); });
    var digitTerms = parsed.terms.map(function (t) { return isDigitQuery(t) ? digitsOf(t) : null; });

    state.searchTerms = parsed.terms.slice();
    var hits = [];
    var matchIds = {};
    var truncated = false;
    var idx = state.searchIndex;

    for (var i = 0; i < idx.length; i++) {
      var item = idx[i];
      var ok = true, fi;
      for (fi = 0; fi < parsed.filters.length; fi++) {
        if (!filterPass(item, parsed.filters[fi])) { ok = false; break; }
      }
      if (!ok) continue;

      var hitField = null, hitText = null, hitTerm = null;
      if (lows.length) {
        for (var t = 0; t < lows.length; t++) {
          var found = false;
          for (var fdi = 0; fdi < item.fields.length; fdi++) {
            if (item.fields[fdi].low.indexOf(lows[t]) !== -1) {
              found = true;
              if (!hitField) {
                hitField = item.fields[fdi].field;
                hitText = item.fields[fdi].text;
                hitTerm = parsed.terms[t];
              }
              break;
            }
          }
          if (!found && digitTerms[t] && item.digits && item.digits.indexOf(digitTerms[t]) !== -1) {
            found = true;
            if (!hitField) {
              hitField = 'number (digit-normalized)';
              hitText = item.digits;
              hitTerm = digitTerms[t];
            }
          }
          if (!found) { ok = false; break; }
        }
      } else {
        hitField = 'filter';
        hitText = item.fields.length ? item.fields[0].text : str(item.id);
        hitTerm = '';
      }
      if (!ok) continue;

      if (hits.length >= SEARCH_CAP) { truncated = true; break; }
      hits.push({
        kind: item.kind,
        id: item.id,
        rowId: item.rowId,
        callId: item.callId,
        legId: item.legId,
        field: hitField,
        excerpt: excerptAround(hitText, hitTerm, parsed.terms),
        sev: item.sev
      });
      if (item.rowId) matchIds[item.rowId] = true;
    }

    state.searchHits = hits;
    state.searchMatchIds = matchIds;
    state.searchTruncated = truncated;
    state.searchActive = true;

    renderSearchCount();
    renderSearchResults();
    renderSelectionList();
    renderLadder();
    renderInfo();
  }

  function renderSearchCount() {
    var node = $('search-count');
    if (!node) return;
    if (!state.searchActive) {
      node.textContent = 'no search';
      node.title = '';
      node.classList.remove('is-hits');
      return;
    }
    var sessions = {};
    var n = 0;
    for (var i = 0; i < state.searchHits.length; i++) {
      sessions[str(state.searchHits[i].callId || 'none')] = true;
      n++;
    }
    var sessCount = Object.keys(sessions).length;
    if (!n) {
      node.textContent = 'no matches';
      node.title = 'nothing in this capture matched the query';
      node.classList.remove('is-hits');
      return;
    }
    node.classList.add('is-hits');
    node.textContent = (state.searchTruncated ? SEARCH_CAP + '+' : String(n)) + ' hits · ' +
      sessCount + ' session' + (sessCount === 1 ? '' : 's');
    node.title = state.searchTruncated
      ? 'capped at ' + SEARCH_CAP + ' hits — narrow the query with a field filter such as call: or method:'
      : n + ' hits across ' + sessCount + ' session(s)';
  }

  /**
   * Search results take over #filter-tree while a query is active: they are
   * grouped by session (call), which is exactly the tree's own grouping.
   */
  function renderSearchResults() {
    var host = $('filter-tree');
    if (!host) return;
    clear(host);

    var head = el('div', 'tree-row search-results-head');
    head.appendChild(el('span', 'tree-label', 'search results'));
    var back = el('button', 'tree-toggle search-clear-inline icon-btn', '\u00d7');
    back.type = 'button';
    back.title = 'clear the search and go back to the session tree';
    back.setAttribute('aria-label', 'clear search');
    back.addEventListener('click', function (ev) { ev.stopPropagation(); clearSearch(); });
    head.appendChild(back);
    host.appendChild(head);

    if (!state.searchHits.length) {
      emptyNote(host, 'No matches.',
        'Try a shorter substring, a phone-number fragment (digits are matched ignoring + - ( ) spaces), or a filter like method:INVITE or has:retrans.');
      return;
    }

    var order = [], groups = {};
    for (var i = 0; i < state.searchHits.length; i++) {
      var h = state.searchHits[i];
      var key = str(h.callId || '');
      if (!groups[key]) { groups[key] = []; order.push(key); }
      groups[key].push(h);
    }

    for (var g = 0; g < order.length; g++) {
      (function (key) {
        var call = key ? state.callById[key] : null;
        var ingress = call ? (state.legById[arr(call.legIds)[0]] || {}) : {};
        var node = treeNode({
          nodeKey: 'hits:' + key,
          kindClass: 'is-call',
          label: call ? (call.id + ' \u00b7 ' + callProtocolLabel(call)) : 'not tied to a call',
          sub: call ? (' ' + str(ingress.from || '?') + ' \u2192 ' + str(ingress.to || '?')) : null,
          state: call ? ingress.state : undefined,
          badge: groups[key].length + ' hit' + (groups[key].length === 1 ? '' : 's'),
          edge: key ? worstSeverityForCall(key) : null,
          hasChildren: true,
          open: true,
          selected: !!(call && isSelectedNode({ type: 'call', callId: call.id })),
          title: call ? ('select call ' + call.id) : 'matches with no call association',
          onSelect: call ? function () { selectScopeFromSearch({ type: 'call', callId: call.id }, null); } : null
        });
        host.appendChild(node.node);
        if (!node.children) return;

        var list = groups[key];
        for (var k = 0; k < list.length; k++) {
          (function (hit) {
            var row = el('div', 'tree-node is-hit');
            var line = el('div', 'tree-row search-hit');
            line.setAttribute('tabindex', '0');
            line.appendChild(el('span', 'tree-toggle'));
            line.appendChild(el('span', 'tree-badge hit-kind', hit.kind));
            line.appendChild(el('span', 'tree-label mono', str(hit.id) + ' ' + str(hit.field)));
            if (hit.sev) line.appendChild(sevChip(hit.sev));
            var ex = el('span', 'tree-sub mono hit-excerpt');
            appendHighlighted(ex, hit.excerpt, state.searchTerms);
            line.appendChild(ex);
            line.title = str(hit.field) + ': ' + str(hit.excerpt);
            var act = function () { openSearchHit(hit); };
            line.addEventListener('click', act);
            line.addEventListener('keydown', function (ev) {
              if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); act(); }
            });
            row.appendChild(line);
            node.children.appendChild(row);
          })(list[k]);
        }
      })(order[g]);
    }

    if (state.searchTruncated) {
      emptyNote(host, 'More matches exist — capped at ' + SEARCH_CAP + '.',
        'Narrow the query with a filter (call:, method:, has:…).');
    }
  }

  function selectScopeFromSearch(sel, rowId) {
    state.sel = {
      type: sel.type || 'capture',
      callId: sel.callId || null,
      legId: sel.legId || null,
      txKey: sel.txKey || null
    };
    state.selectedRowId = rowId || null;
    state.keyList = 'tree';   // Wave 5A: results live in #filter-tree's host
    buildScopedRows();
    renderSelectionList();
    renderLadder();
    renderInfo();
    renderDrawer();
  }

  /** Click a result → select that call, highlight the match in ladder + info. */
  function openSearchHit(hit) {
    if (!hit) return;
    var sel = { type: 'capture' };
    if (hit.callId && state.callById[hit.callId]) sel = { type: 'call', callId: hit.callId };
    else if (hit.legId && state.legById[hit.legId]) {
      sel = { type: 'leg', callId: state.legToCall[hit.legId] || null, legId: hit.legId };
    }
    // Advice/finding hits leave the info tab alone — the drawer's advice
    // section is where they land, and it re-renders (scrolled to the top) as
    // part of selectScopeFromSearch's renderDrawer().
    if (hit.kind === 'media') state.infoTab = 'media';
    else if (hit.kind !== 'advice' && hit.kind !== 'finding') state.infoTab = 'contents';
    selectScopeFromSearch(sel, hit.rowId || null);
  }

  // ------------------------------------------------------------ chat drawer

  function chatKey() { return 'hiccup-chat-' + (state.captureId || 'none'); }

  /** @returns {Array<{role:string,content:string,model?:string}>} */
  function chatHistory() {
    try {
      var raw = sessionStorage.getItem(chatKey());
      var parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) { return []; }
  }

  function saveChat(hist) {
    try { sessionStorage.setItem(chatKey(), JSON.stringify(hist)); } catch (e) { /* quota */ }
  }

  /**
   * Push state.chatOpen into the DOM. Separate from toggleChat() so boot can
   * reflect the default-open drawer (Wave 4) without stealing focus into the
   * chat box on page load. body.chat-open is what gives #layout its
   * margin-right, so the drawer takes width from the grid instead of covering
   * the info pane.
   */
  function applyDrawerOpen() {
    var drawer = $('chat-drawer');
    if (drawer) drawer.hidden = !state.chatOpen;
    if (document.body) document.body.classList.toggle('chat-open', !!state.chatOpen);
    var toggle = $('chat-toggle');
    if (toggle) {
      toggle.classList.toggle('active', !!state.chatOpen);
      toggle.setAttribute('aria-expanded', state.chatOpen ? 'true' : 'false');
    }
  }

  function toggleChat(open) {
    var drawer = $('chat-drawer');
    var cameFromInside = !!(drawer && drawer.contains && drawer.contains(document.activeElement));
    state.chatOpen = !!open;
    applyDrawerOpen();
    // Wave 5A: below the stacking breakpoint the open drawer covers the panes,
    // so it becomes a real modal there (focus trap + scrim + Escape). No-op on
    // a wide viewport, where it only displaces the layout.
    syncDrawerModality();
    if (state.chatOpen) {
      renderDrawer();
      var input = $('chat-input');
      if (input) input.focus();
      return;
    }
    // Closing while focus was inside (#chat-close, say): hiding the drawer drops
    // that focus on the floor. Hand it to #chat-toggle instead. Below the
    // breakpoint the focus trap has already restored it — this is the wide,
    // non-modal case, and it deliberately does nothing when focus was elsewhere
    // (a resize must never steal it).
    if (cameFromInside && (!document.activeElement || document.activeElement === document.body)) {
      focusQuietly($('chat-toggle'));
    }
  }

  /** Map the Workbench selection onto the server's scope contract. */
  function chatScope() {
    if (state.selectedRowId && state.msgById[state.selectedRowId]) {
      return { type: 'message', id: state.selectedRowId };
    }
    var sel = state.sel;
    if (sel.type === 'call' && sel.callId) return { type: 'call', id: sel.callId };
    if ((sel.type === 'leg' || sel.type === 'transaction') && sel.legId) return { type: 'leg', id: sel.legId };
    return { type: 'capture', id: state.captureId };
  }

  function scopeLabel() {
    var s = chatScope();
    if (!s || s.type === 'capture' || !s.id) return 'whole capture';
    var extra = '';
    if (state.sel.type === 'transaction' && state.sel.txKey) extra = ' · ' + state.sel.txKey;
    return s.type + ' ' + s.id + extra;
  }

  function renderChat() {
    var llm = state.llm;
    var available = !!(llm && llm.available);

    var modelChip = $('chat-model');
    if (modelChip) modelChip.textContent = available ? str(llm.model) : 'offline';

    var hint = $('chat-hint');
    if (hint) {
      if (available && llm.source === 'rfplex') {
        hint.hidden = false;
        hint.textContent = str(llm.model || 'model') +
          ' — shares its brain with RFPlex — answers may queue behind RFPlex work';
      } else {
        hint.hidden = true;
        hint.textContent = '';
      }
    }

    var scopeBox = $('chat-scope');
    if (scopeBox) {
      clear(scopeBox);
      scopeBox.appendChild(el('span', 'muted', 'scope: '));
      scopeBox.appendChild(el('span', 'chip mono', scopeLabel()));
      var cur = chatScope();
      if (cur && cur.type !== 'capture') {
        var reset = el('button', 'btn scope-reset', '\u00d7 whole capture');
        reset.type = 'button';
        reset.title = 'reset the scope to the whole capture';
        reset.addEventListener('click', function () {
          state.sel = { type: 'capture', callId: null, legId: null, txKey: null };
          state.selectedRowId = null;
          renderAll();   // ends in renderDrawer() — advice widens back out too
        });
        scopeBox.appendChild(reset);
      }
    }

    var box = $('chat-messages');
    if (box) {
      clear(box);
      if (!state.captureId) {
        emptyNote(box, 'Open a capture first — hiccup answers about what it can see.');
      } else {
        var hist = chatHistory();
        if (!hist.length && !state.chatBusy) {
          emptyNote(box, 'Ask about this capture or about SIP/H.323 in general.',
            'Try: "why is this call ambiguous?" \u00b7 "what does Session-Expires do?" \u00b7 "what stripped the PAI header?"');
        }
        for (var i = 0; i < hist.length; i++) {
          var bubble = el('div', 'chat-bubble ' + (hist[i].role === 'user' ? 'from-user' : 'from-bot'));
          bubble.textContent = str(hist[i].content);
          box.appendChild(bubble);
        }
        if (state.chatBusy) {
          var busy = el('div', 'chat-bubble from-bot busy');
          busy.appendChild(el('span', 'spinner'));
          busy.appendChild(document.createTextNode(' thinking…'));
          box.appendChild(busy);
        }
      }
      box.scrollTop = box.scrollHeight;
    }

    var errBox = $('chat-error');
    if (errBox) {
      if (state.chatError) { errBox.hidden = false; errBox.textContent = state.chatError; }
      else { errBox.hidden = true; errBox.textContent = ''; }
    }

    var form = $('chat-form');
    var offline = $('chat-offline');
    if (!available) {
      if (offline) offline.hidden = false;
      if (form) form.hidden = true;
    } else {
      if (offline) offline.hidden = true;
      if (form) form.hidden = !state.captureId;
      var send = $('chat-send');
      if (send) send.disabled = state.chatBusy;
      var input = $('chat-input');
      if (input) input.disabled = state.chatBusy;
    }
  }

  /** Open the drawer with a prefilled question and an explicit scope. */
  function openChatPrefilled(question, scope) {
    if (scope && scope.type) {
      // Reflect the requested scope in the Workbench selection where we can.
      if (scope.type === 'message' && state.msgById[scope.id]) {
        var lg = state.msgToLeg[scope.id];
        if (lg) state.sel = { type: 'leg', callId: state.legToCall[lg] || null, legId: lg, txKey: null };
        state.selectedRowId = scope.id;
      } else if (scope.type === 'call' && state.callById[scope.id]) {
        state.sel = { type: 'call', callId: scope.id, legId: null, txKey: null };
      } else if (scope.type === 'leg' && state.legById[scope.id]) {
        state.sel = { type: 'leg', callId: state.legToCall[scope.id] || null, legId: scope.id, txKey: null };
      }
      state.pendingScope = scope;
    }
    toggleChat(true);
    var input = $('chat-input');
    if (input) { input.value = str(question); input.focus(); }
  }

  async function submitChat() {
    if (state.chatBusy || !state.captureId) return;
    var llm = state.llm;
    if (!llm || !llm.available) return;
    var input = $('chat-input');
    if (!input) return;
    var text = str(input.value).trim();
    if (!text) return;
    input.value = '';
    state.chatError = null;

    var hist = chatHistory();
    hist.push({ role: 'user', content: text });
    saveChat(hist);
    state.chatBusy = true;
    renderChat();

    var scope = state.pendingScope || chatScope();
    state.pendingScope = null;

    try {
      var r = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          captureId: state.captureId,
          messages: hist.map(function (m) { return { role: m.role, content: m.content }; }),
          scope: scope
        })
      });
      var j = null;
      try { j = await r.json(); } catch (e) { /* non-json */ }
      if (r.status === 503) {
        state.chatError = (j && j.error) || 'local model unavailable right now';
        if (j && j.llm) { state.llm = j.llm; renderLlmChip(); }
      } else if (!r.ok) {
        state.chatError = (j && j.error) || ('chat failed (' + r.status + ')');
      } else {
        hist.push({ role: 'assistant', content: str(j && j.reply), model: j && j.model });
        saveChat(hist);
      }
    } catch (e) {
      state.chatError = 'chat failed: ' + (e && e.message ? e.message : 'network error');
    }
    state.chatBusy = false;
    renderChat();
  }

  // ======================================================== Wave 5A ========
  // Global keyboard layer, focus-trap utility, command palette and the `?`
  // shortcuts overlay (ARCHITECTURE.md §"Wave 5 — A. Global keyboard layer +
  // command palette").
  //
  // Everything below is additive: the per-element keydown handlers this file
  // already had (tree rows, selection rows, table headers, #search-input,
  // #chat-input) are untouched and still authoritative for their own element.
  // There is exactly ONE document-level keydown listener, installed by
  // setupKeyboardLayer(), and it runs in the CAPTURE phase on purpose — see
  // onGlobalKeyDown.

  // ------------------------------------------------------------ focus trap

  var FOCUSABLE_SEL = 'a[href], button:not([disabled]), input:not([disabled]), ' +
    'select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

  /** Active traps, innermost last. Only the top of the stack handles keys. */
  var trapStack = [];

  function topTrap() { return trapStack.length ? trapStack[trapStack.length - 1] : null; }

  function isRendered(node) {
    if (!node) return false;
    if (node.offsetWidth || node.offsetHeight) return true;
    return !!(node.getClientRects && node.getClientRects().length);
  }

  /** Tabbable descendants of `container`, in DOM order, visible ones only. */
  function focusablesIn(container) {
    var out = [];
    if (!container || !container.querySelectorAll) return out;
    var nodes = container.querySelectorAll(FOCUSABLE_SEL);
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].hasAttribute('hidden')) continue;
      if (!isRendered(nodes[i])) continue;
      out.push(nodes[i]);
    }
    return out;
  }

  /**
   * The one focus trap, shared by every modal surface in the app:
   *   - #command-palette          (new, Wave 5A)
   *   - #shortcuts-help           (new, Wave 5A)
   *   - #project-manage-panel     (existing panel that had no trap)
   *   - #chat-drawer              (only below the stacking breakpoint, where it
   *                                covers the panes instead of displacing them)
   *
   * Tab/Shift+Tab cycling and Escape are handled centrally in onGlobalKeyDown
   * against the top of the trap stack, so a trap adds no keydown listener of
   * its own. A `focusin` guard catches focus arriving from anywhere else
   * (programmatic focus, a click on something behind the overlay) and pulls it
   * back in.
   *
   * @param {HTMLElement} container the element focus may not leave
   * @param {{onEscape?:function, onOutsideClick?:function, dialog?:boolean}} opts
   *   onEscape        — called for Escape (typically closes the surface)
   *   onOutsideClick  — called on a pointerdown outside; omit for no-op
   *   dialog          — add role=dialog + aria-modal while active, and remove
   *                     them on release (for surfaces whose markup is not
   *                     already a dialog: the drawer and the projects panel)
   * @returns {{activate:function, release:function, active:function,
   *            container:HTMLElement}}
   */
  function createFocusTrap(container, opts) {
    var o = opts || {};
    var trap = {
      container: container,
      returnTo: null,
      isActive: false,
      hadRole: null,
      hadModal: null,
      onDown: null
    };

    trap.active = function () { return trap.isActive; };

    trap.escape = function () { if (typeof o.onEscape === 'function') o.onEscape(); };

    /** True for the element the surface was opened from — never an outside click. */
    trap.isTrigger = function (node) {
      var rt = trap.returnTo;
      if (!rt || !node) return false;
      if (rt === document.body || rt === document.documentElement) return false;
      return rt === node || (rt.contains && rt.contains(node));
    };

    trap.activate = function (arg) {
      if (trap.isActive || !container) return;
      var a = arg || {};
      trap.returnTo = a.returnTo || document.activeElement || null;
      trap.isActive = true;
      trapStack.push(trap);

      if (o.dialog) {
        trap.hadRole = container.getAttribute('role');
        trap.hadModal = container.getAttribute('aria-modal');
        container.setAttribute('role', 'dialog');
        container.setAttribute('aria-modal', 'true');
      }

      if (typeof o.onOutsideClick === 'function') {
        trap.onDown = function (ev) {
          if (topTrap() !== trap) return;
          var t = ev.target;
          if (container.contains && container.contains(t)) return;
          if (trap.isTrigger(t)) return;   // else the trigger's click re-opens it
          o.onOutsideClick();
        };
        document.addEventListener('pointerdown', trap.onDown, true);
      }

      var first = a.initialFocus || focusablesIn(container)[0] || container;
      if (first === container && !container.hasAttribute('tabindex')) {
        container.setAttribute('tabindex', '-1');
      }
      focusQuietly(first);
    };

    /**
     * @param {{restoreFocus?:boolean}} [arg] restoreFocus defaults to true; pass
     *   false when the surface is staying open and merely stopped being modal
     *   (the drawer when the viewport widens) — moving focus then would be rude.
     */
    trap.release = function (arg) {
      if (!trap.isActive) return;
      var a = arg || {};
      trap.isActive = false;
      for (var i = trapStack.length - 1; i >= 0; i--) {
        if (trapStack[i] === trap) { trapStack.splice(i, 1); break; }
      }
      if (trap.onDown) {
        document.removeEventListener('pointerdown', trap.onDown, true);
        trap.onDown = null;
      }
      if (o.dialog && container) {
        if (trap.hadRole == null) container.removeAttribute('role');
        else container.setAttribute('role', trap.hadRole);
        if (trap.hadModal == null) container.removeAttribute('aria-modal');
        else container.setAttribute('aria-modal', trap.hadModal);
      }
      var back = trap.returnTo;
      trap.returnTo = null;
      if (a.restoreFocus === false) return;
      if (back && back.focus && document.contains(back) && isRendered(back)) focusQuietly(back);
    };

    return trap;
  }

  function focusQuietly(node) {
    if (!node || !node.focus) return;
    try { node.focus({ preventScroll: true }); } catch (e) { node.focus(); }
  }

  /** Tab / Shift+Tab, confined to the top trap's container. */
  function trapTab(trap, ev) {
    var items = focusablesIn(trap.container);
    ev.preventDefault();
    if (!items.length) { focusQuietly(trap.container); return; }
    var first = items[0], last = items[items.length - 1];
    var at = document.activeElement;
    if (!trap.container.contains || !trap.container.contains(at)) {
      focusQuietly(ev.shiftKey ? last : first);
      return;
    }
    var i = -1;
    for (var k = 0; k < items.length; k++) { if (items[k] === at) { i = k; break; } }
    if (i === -1) { focusQuietly(ev.shiftKey ? last : first); return; }
    focusQuietly(ev.shiftKey ? (i === 0 ? last : items[i - 1]) : (i === items.length - 1 ? first : items[i + 1]));
  }

  /** Focus arriving from outside a trapped surface is pulled straight back. */
  function onGlobalFocusIn(ev) {
    var trap = topTrap();
    if (!trap || !trap.container) return;
    var t = ev.target;
    if (t === trap.container || (trap.container.contains && trap.container.contains(t))) return;
    var items = focusablesIn(trap.container);
    focusQuietly(items[0] || trap.container);
  }

  // -------------------------------------------------- global keyboard layer

  var NARROW_MQ = '(max-width: 1080px)';

  /** The stacked layout from app.css's max-width:1080px breakpoint. */
  function isNarrowLayout() {
    return !!(window.matchMedia && window.matchMedia(NARROW_MQ).matches);
  }

  var TYPING_TAGS = { INPUT: 1, TEXTAREA: 1, SELECT: 1 };

  /**
   * THE hard rule of this layer: a single-key binding is a no-op while the user
   * is typing. Checked first, on the element that actually has focus (and on
   * the event target, for the shadow/retarget case), so "j" in #search-input
   * types a j.
   */
  function isTypingTarget(node) {
    if (!node || node.nodeType !== 1) return false;
    if (node.isContentEditable) return true;
    return !!TYPING_TAGS[str(node.tagName).toUpperCase()];
  }

  function setupKeyboardLayer() {
    // Capture phase: this handler must see Escape BEFORE #search-input's own
    // keydown handler clears the box, otherwise the "focused with a query"
    // branch below can never tell a query from an empty field. Every other
    // binding is unaffected by the phase.
    document.addEventListener('keydown', onGlobalKeyDown, true);
    document.addEventListener('focusin', onGlobalFocusIn, true);

    var opener = $('command-palette-open');
    if (opener) {
      opener.addEventListener('click', function () {
        if (isPaletteOpen()) closePalette(); else openPalette();
      });
    }

    var helpClose = $('shortcuts-help-close');
    if (helpClose) helpClose.addEventListener('click', function () { closeShortcutsHelp(); });

    // Crossing the stacking breakpoint changes whether the drawer covers the
    // panes, so it changes whether the drawer is modal.
    if (window.matchMedia) {
      var mq = window.matchMedia(NARROW_MQ);
      var onChange = function () {
        if (mq.matches && state.chatOpen) {
          // Wide → narrow with the drawer open: it would now float over the
          // stacked panes. Close it, exactly as boot() does on a narrow load —
          // quieter than yanking focus into it mid-resize.
          toggleChat(false);
        } else {
          syncDrawerModality();
        }
      };
      if (mq.addEventListener) mq.addEventListener('change', onChange);
      else if (mq.addListener) mq.addListener(onChange);   // older Safari/Firefox
    }
  }

  function onGlobalKeyDown(ev) {
    if (!ev || ev.altKey || ev.isComposing || ev.keyCode === 229) return;
    var key = ev.key;
    if (!key) return;

    // --- Ctrl/Cmd+K: the one binding that fires while typing --------------
    // Peer tools (GitHub, Linear, Slack, VS Code) all open the palette from
    // inside a field, and that is genuinely useful in a one-line input you can
    // retype in a second. A <textarea> is different: #chat-input holds a
    // half-composed question and /hmr's paste box holds a whole config, and
    // having a dialog steal focus mid-thought there is the surprising case the
    // spec calls out. So: suppressed for textareas, live everywhere else.
    if ((ev.ctrlKey || ev.metaKey) && !ev.shiftKey && (key === 'k' || key === 'K')) {
      var ae = document.activeElement;
      if (ae && str(ae.tagName).toUpperCase() === 'TEXTAREA') return;
      ev.preventDefault();
      if (isPaletteOpen()) closePalette(); else openPalette();
      return;
    }

    // Every other modifier combination belongs to the browser or the OS.
    if (ev.ctrlKey || ev.metaKey) return;

    // --- a modal surface is up: only Tab and Escape reach it --------------
    var trap = topTrap();
    if (trap) {
      if (key === 'Tab') { trapTab(trap, ev); return; }
      if (key === 'Escape' || key === 'Esc') { ev.preventDefault(); trap.escape(); return; }
      return;   // no page-level shortcut fires behind an open dialog
    }

    // --- Escape: context-sensitive, and allowed from inside a field -------
    // (the palette/dialog case is the trap branch above — first in priority
    // because a trap is only ever active while one of them is open)
    if (key === 'Escape' || key === 'Esc') { handleGlobalEscape(ev); return; }

    // --- HARD RULE: nothing below this line fires while typing ------------
    if (isTypingTarget(document.activeElement) || isTypingTarget(ev.target)) return;

    if (key === '/') {
      var si = $('search-input');
      if (!si) return;
      ev.preventDefault();       // else the "/" lands in the field we just focused
      focusQuietly(si);
      si.select();
      return;
    }

    if (key === 'j' || key === 'k' || key === 'J' || key === 'K') {
      if (moveListSelection((key === 'j' || key === 'J') ? 1 : -1)) ev.preventDefault();
      return;
    }

    if (key === '?') { ev.preventDefault(); openShortcutsHelp(); return; }
  }

  /**
   * Escape, in the spec's priority order. Anything not ours is left alone so
   * the browser's own Escape (leaving fullscreen, cancelling an IME, stopping a
   * load) still works.
   */
  function handleGlobalEscape(ev) {
    var si = $('search-input');
    if (si && document.activeElement === si && str(si.value).length) {
      ev.preventDefault();
      clearSearch();
      si.blur();
      return;
    }
    if (state.chatOpen && isNarrowLayout()) {
      // Belt and braces: syncDrawerModality normally has the drawer trapped in
      // this state, so the trap branch would have caught it first.
      ev.preventDefault();
      toggleChat(false);
      return;
    }
  }

  // ------------------------------------------------------------ j/k in lists

  function navRows(which) {
    var host = which === 'selection' ? $('selection-list') : $('filter-tree');
    var out = [];
    if (!host || !host.querySelectorAll) return out;
    // #filter-tree: treeNode() puts tabindex="0" on every actionable row, and
    // only on those (the search-results header deliberately has none).
    // #selection-list: both shapes give real rows a data-row-id.
    var nodes = host.querySelectorAll(which === 'selection'
      ? '.sel-row[data-row-id]'
      : '.tree-row[tabindex]');
    for (var i = 0; i < nodes.length; i++) out.push(nodes[i]);
    return out;
  }

  /** Where j/k is now: keyboard focus wins, else the selected row, else nowhere. */
  function navIndex(rows) {
    var at = document.activeElement, i;
    for (i = 0; i < rows.length; i++) { if (rows[i] === at) return i; }
    for (i = 0; i < rows.length; i++) {
      if (rows[i].classList && rows[i].classList.contains('is-selected')) return i;
    }
    return -1;
  }

  /**
   * Move one row in the list that last had a selection change. Selection itself
   * goes through the row's own click handler, so j/k can never drift from what
   * a mouse click does — which also means the list re-renders underneath us and
   * the row has to be looked up again before it can take focus.
   * @returns {boolean} whether the key was consumed
   */
  function moveListSelection(delta) {
    var which = state.keyList === 'selection' ? 'selection' : 'tree';
    var rows = navRows(which);
    if (!rows.length) {
      which = which === 'selection' ? 'tree' : 'selection';
      rows = navRows(which);
    }
    if (!rows.length) return false;

    var at = navIndex(rows);
    var next = at < 0 ? (delta > 0 ? 0 : rows.length - 1) : at + delta;
    if (next < 0) next = 0;
    if (next > rows.length - 1) next = rows.length - 1;

    if (next !== at) {
      rows[next].click();
      var fresh = navRows(which);
      if (fresh.length === rows.length && fresh[next]) rows = fresh;
    }
    var target = rows[next];
    if (target) {
      focusQuietly(target);
      if (target.scrollIntoView) target.scrollIntoView({ block: 'nearest' });
    }
    return true;
  }

  // -------------------------------------------------------- command palette

  var palette = { trap: null, wired: false, items: [], active: -1 };

  function paletteHost() { return $('command-palette'); }
  function palettePanel() {
    var host = paletteHost();
    return host ? host.querySelector('.overlay-panel') : null;
  }
  function isPaletteOpen() {
    var host = paletteHost();
    return !!(host && !host.hidden);
  }

  /** theme.js owns the three-state theme model — never reimplement it here. */
  function togglePageTheme() {
    if (window.HiccupTheme && typeof window.HiccupTheme.toggle === 'function') {
      window.HiccupTheme.toggle();
      return;
    }
    var btn = document.querySelector('[data-theme-toggle]');
    if (btn) btn.click();
  }

  /**
   * Navigation and actions only — capture-content search stays #search-input's
   * job, deliberately. Rebuilt on every open so labels can reflect state
   * ("Open"/"Close the drawer") and capture-only actions can be left out
   * entirely when nothing is loaded.
   * @returns {Array<{kind:string,label:string,hint:string,run:function}>}
   */
  function paletteActions() {
    var out = [];
    function add(kind, label, hint, run) {
      out.push({ kind: kind, label: label, hint: hint || '', run: run });
    }
    function clickId(id) { var n = $(id); if (n) n.click(); }

    add('go', 'Go to the workbench', '/app', function () { location.href = '/app'; });
    add('go', 'Go to the HMR translator', '/hmr', function () { location.href = '/hmr'; });
    add('go', 'Go to the guides', '/kb', function () { location.href = '/kb'; });
    add('go', 'Go to the team page', '/team', function () { location.href = '/team'; });

    add('view', 'Toggle light / dark theme', '', togglePageTheme);
    add('chat', state.chatOpen ? 'Close the ask-hiccup drawer' : 'Open the ask-hiccup drawer',
      '', function () { toggleChat(!state.chatOpen); });
    add('view', state.projectManageOpen ? 'Close the manage-projects panel' : 'Manage projects',
      '', function () { toggleProjectManage(!state.projectManageOpen); });
    add('go', 'Upload a capture', '', function () { clickId('browse-btn'); });

    add('find', 'Search the trace', '/', function () {
      var si = $('search-input');
      if (!si) return;
      focusQuietly(si);
      si.select();
    });
    if (state.searchActive) add('find', 'Clear the search', 'esc', function () { clearSearch(); });

    if (state.analysis) {
      for (var i = 0; i < INFO_TABS.length; i++) {
        (function (spec) {
          add('view', 'Show ' + spec.label, '', function () {
            state.infoTab = spec.key;
            renderInfo();
            focusQuietly($(spec.panel));   // land on what you just asked to see
          });
        })(INFO_TABS[i]);
      }
      add('view', 'Expand all sessions', '', function () { setAllTreeExpanded(true); });
      add('view', 'Collapse all sessions', '', function () { setAllTreeExpanded(false); });
      add('view', 'Export the ladder as SVG', '', function () { toolbarAction('export'); });
    }

    add('help', 'Keyboard shortcuts', '?', function () { openShortcutsHelp(); });
    add('acct', 'Sign out', '', function () { clickId('logout-btn'); });
    return out;
  }

  /**
   * Substring first, subsequence as a fallback — enough for a list this size,
   * and no scoring library.
   * @returns {number} higher is better, -1 for no match at all
   */
  function fuzzyScore(hay, needle) {
    if (!needle) return 0;
    var h = str(hay).toLowerCase(), n = str(needle).toLowerCase();
    var idx = h.indexOf(n);
    if (idx === 0) return 1000 - h.length;
    if (idx > 0) return (/[\s/(-]/.test(h.charAt(idx - 1)) ? 800 : 600) - idx;

    var pos = 0, gaps = 0, start = -1;
    for (var i = 0; i < n.length; i++) {
      var c = n.charAt(i);
      if (c === ' ') continue;                 // spaces just separate fragments
      var found = h.indexOf(c, pos);
      if (found === -1) return -1;
      if (start < 0) start = found;
      if (i > 0 && found > pos) gaps += found - pos;
      pos = found + 1;
    }
    return 300 - Math.min(gaps, 200) - Math.min(start, 60);
  }

  function scoreAction(act, q) {
    var s = fuzzyScore(act.label, q);
    if (s >= 0) return s;
    var alt = fuzzyScore(act.kind + ' ' + act.label + ' ' + act.hint, q);
    return alt < 0 ? -1 : alt - 200;
  }

  function renderPaletteList(q) {
    var host = $('command-palette-list');
    var empty = $('command-palette-empty');
    if (!host) return;
    clear(host);

    var all = palette.actions || [];
    var scored = [];
    for (var i = 0; i < all.length; i++) {
      var s = scoreAction(all[i], q);
      if (s >= 0) scored.push({ act: all[i], score: s, at: i });
    }
    scored.sort(function (a, b) { return b.score - a.score || a.at - b.at; });

    palette.items = [];
    for (var k = 0; k < scored.length; k++) {
      (function (act, index) {
        palette.items.push(act);
        var opt = el('div', 'palette-option');
        opt.id = 'cmd-opt-' + index;
        opt.setAttribute('role', 'option');
        opt.setAttribute('aria-selected', 'false');
        opt.appendChild(el('span', 'palette-opt-kind', act.kind));
        opt.appendChild(el('span', 'palette-opt-label', act.label));
        if (act.hint) opt.appendChild(el('span', 'palette-opt-hint', act.hint));
        // mousedown would blur the input before the click lands — the input is
        // where focus has to stay for aria-activedescendant to mean anything.
        opt.addEventListener('mousedown', function (ev) { ev.preventDefault(); });
        opt.addEventListener('mouseenter', function () { setPaletteActive(index); });
        opt.addEventListener('click', function () { runPaletteAction(index); });
        host.appendChild(opt);
      })(scored[k].act, k);
    }

    if (empty) empty.hidden = palette.items.length > 0;
    setPaletteActive(palette.items.length ? 0 : -1);
  }

  /** Roving highlight via aria-activedescendant — real focus never moves. */
  function setPaletteActive(index) {
    var host = $('command-palette-list');
    var input = $('command-palette-input');
    if (!host) return;
    var opts = host.querySelectorAll('.palette-option');
    if (!opts.length) {
      palette.active = -1;
      if (input) input.removeAttribute('aria-activedescendant');
      return;
    }
    if (index < 0) index = opts.length - 1;
    if (index > opts.length - 1) index = 0;
    palette.active = index;
    for (var i = 0; i < opts.length; i++) {
      var on = i === index;
      opts[i].classList.toggle('is-active', on);
      opts[i].setAttribute('aria-selected', on ? 'true' : 'false');
      if (on) {
        if (input) input.setAttribute('aria-activedescendant', opts[i].id);
        if (opts[i].scrollIntoView) opts[i].scrollIntoView({ block: 'nearest' });
      }
    }
  }

  function runPaletteAction(index) {
    var act = palette.items[index];
    if (!act) return;
    // Close FIRST: closing restores focus to whatever opened the palette, so an
    // action that focuses something itself (search, an info panel) must run
    // after that, or the restore would undo it.
    closePalette();
    try { act.run(); } catch (e) { /* one bad action must not kill the layer */ }
  }

  function wirePalette() {
    if (palette.wired) return;
    var host = paletteHost();
    var panel = palettePanel();
    var input = $('command-palette-input');
    if (!host || !panel || !input) return;

    palette.trap = createFocusTrap(panel, {
      onEscape: function () { closePalette(); },
      onOutsideClick: function () { closePalette(); }
    });

    input.addEventListener('input', function () { renderPaletteList(input.value || ''); });
    input.addEventListener('keydown', function (ev) {
      if (ev.key === 'ArrowDown') { ev.preventDefault(); setPaletteActive(palette.active + 1); }
      else if (ev.key === 'ArrowUp') { ev.preventDefault(); setPaletteActive(palette.active - 1); }
      else if (ev.key === 'Home' && palette.items.length) { ev.preventDefault(); setPaletteActive(0); }
      else if (ev.key === 'End' && palette.items.length) { ev.preventDefault(); setPaletteActive(palette.items.length - 1); }
      else if (ev.key === 'Enter') { ev.preventDefault(); runPaletteAction(palette.active); }
      // Escape and Tab are the global layer's, via the focus trap.
    });

    palette.wired = true;
  }

  function openPalette() {
    wirePalette();
    var host = paletteHost();
    var input = $('command-palette-input');
    if (!host || !input || !palette.trap) return;
    if (isPaletteOpen()) return;
    palette.actions = paletteActions();
    host.hidden = false;
    input.value = '';
    renderPaletteList('');
    palette.trap.activate({ initialFocus: input });
  }

  function closePalette() {
    var host = paletteHost();
    if (!host || host.hidden) return;
    host.hidden = true;
    palette.items = [];
    palette.active = -1;
    if (palette.trap) palette.trap.release();
  }

  // -------------------------------------------------------- shortcuts help

  var helpTrap = null;

  function shortcutsPanel() {
    var host = $('shortcuts-help');
    return host ? host.querySelector('.overlay-panel') : null;
  }

  function openShortcutsHelp() {
    var host = $('shortcuts-help');
    var panel = shortcutsPanel();
    if (!host || !panel || !host.hidden) return;
    if (!helpTrap) {
      helpTrap = createFocusTrap(panel, {
        onEscape: function () { closeShortcutsHelp(); },
        onOutsideClick: function () { closeShortcutsHelp(); }
      });
    }
    host.hidden = false;
    helpTrap.activate({ initialFocus: $('shortcuts-help-close') });
  }

  function closeShortcutsHelp() {
    var host = $('shortcuts-help');
    if (!host || host.hidden) return;
    host.hidden = true;
    if (helpTrap) helpTrap.release();
  }

  // ----------------------------------------- #project-manage-panel + drawer

  var pmTrap = null;

  function projectManageTrap() {
    if (pmTrap) return pmTrap;
    var panel = $('project-manage-panel');
    if (!panel) return null;
    pmTrap = createFocusTrap(panel, {
      dialog: true,
      onEscape: function () { toggleProjectManage(false); },
      onOutsideClick: function () { toggleProjectManage(false); }
    });
    return pmTrap;
  }

  var drawerTrap = null;

  function chatDrawerTrap() {
    if (drawerTrap) return drawerTrap;
    var drawer = $('chat-drawer');
    if (!drawer) return null;
    drawerTrap = createFocusTrap(drawer, {
      dialog: true,
      onEscape: function () { toggleChat(false); },
      onOutsideClick: function () { toggleChat(false); }
    });
    return drawerTrap;
  }

  /**
   * The drawer is modal when — and only when — it is covering something.
   *
   * Wide: body.chat-open gives #layout a margin-right, so the drawer takes its
   * width from the grid and obscures nothing. It stays a plain side panel:
   * no trap, no role=dialog, Tab flows through it into the page as before.
   *
   * Narrow (app.css's max-width:1080px block drops that margin): the fixed
   * drawer floats over the stacked panes, which is exactly WCAG 2.2 §2.4.11
   * "focus not obscured". There it becomes a real modal — focus trapped inside,
   * role=dialog/aria-modal on, #chat-scrim painted behind it by CSS, Escape and
   * an outside click both closing it and handing focus back to #chat-toggle.
   */
  function syncDrawerModality(arg) {
    var trap = chatDrawerTrap();
    if (!trap) return;
    var wantModal = !!state.chatOpen && isNarrowLayout();
    if (wantModal && !trap.active()) {
      trap.activate({
        returnTo: (arg && arg.returnTo) || $('chat-toggle'),
        initialFocus: $('chat-input')
      });
    } else if (!wantModal && trap.active()) {
      // Still open, just no longer covering anything (the viewport widened):
      // drop the modality but leave focus where the user put it.
      trap.release({ restoreFocus: !state.chatOpen });
    }
  }

  // ------------------------------------------------- Wave 6: context probe

  /**
   * Read-only probe used by feedback.js to describe WHAT IS ON SCREEN without
   * describing WHAT IS IN THE CAPTURE.
   *
   * Everything returned here is either a count, one of hiccup's own generated
   * ids (c4/d4/s29 — meaningless outside this capture), a SIP protocol verb
   * (INVITE/486), or a rule/lamp key from hiccup's own vocabulary.
   *
   * Deliberately NOT exposed, even though both sit in easy reach on `state`
   * and would genuinely help reproduce a bug: the capture FILENAME (routinely
   * carries a customer's name) and state.searchQuery (people search by phone
   * number). lib/feedback.js would strip them anyway — this is the same
   * decision enforced at the other end, so neither side can drift alone.
   * See ARCHITECTURE.md "Wave 6".
   */
  window.hiccupContextProbe = function () {
    var out = {};
    var a = state.analysis;
    if (!a) return out;

    var stats = a.stats || {};
    out.counts = {
      sip: num0(stats.sipMessages),
      h323: num0(stats.h323Messages),
      calls: objs(a.calls).length,
      legs: objs(a.legs).length,
      media: mediaStreams().length,
      aux: auxMessages().length
    };

    var sc = a.scenario;
    if (sc && sc.key) {
      out.scenario = { key: str(sc.key) };
      if (typeof sc.confidence === 'number') out.scenario.confidence = sc.confidence;
    }

    out.scopeType = str(state.sel && state.sel.type) || 'capture';
    var ids = {};
    if (state.sel && state.sel.callId) ids.callId = str(state.sel.callId);
    if (state.sel && state.sel.legId) ids.legId = str(state.sel.legId);
    if (state.sel && state.sel.txKey) ids.txKey = str(state.sel.txKey);
    if (Object.keys(ids).length) out.scopeIds = ids;

    var row = state.selectedRowId ? state.rowById[state.selectedRowId] : null;
    if (row) {
      var sel = { kind: str(row.kind) };
      // row.obj is the parsed message; only its method/status are read, never
      // its headers, body or addresses.
      var m = row.obj || {};
      if (m.method) sel.method = str(m.method);
      if (typeof m.status === 'number') sel.status = m.status;
      if (m.q931Type) sel.method = str(m.q931Type);
      out.selectedRow = sel;
    }

    var lamps = [];
    var inds = indicators();
    for (var i = 0; i < inds.length; i++) {
      if (inds[i] && inds[i].key && inds[i].state && inds[i].state !== 'off') {
        lamps.push({ key: str(inds[i].key), state: str(inds[i].state) });
      }
    }
    if (lamps.length) out.lamps = lamps;

    var ruleIds = [];
    var adv = adviceList();
    for (var j = 0; j < adv.length; j++) {
      if (adv[j] && adv[j].ruleId) ruleIds.push(str(adv[j].ruleId));
    }
    if (ruleIds.length) out.adviceRuleIds = ruleIds;

    return out;
  };

  function num0(v) { return typeof v === 'number' && isFinite(v) ? v : 0; }

  // ------------------------------------------------------------------- go

  boot();
})();
