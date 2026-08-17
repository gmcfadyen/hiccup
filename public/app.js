/*
 * hiccup — app.js
 * App shell: boot/auth, capture sidebar + upload, tab router, renderers
 * (Calls/Flow, Ladder, Retrans, Findings), inspector, chat drawer.
 *
 * All DOM building is vanilla createElement; user-derived data only ever goes
 * through textContent (never innerHTML) — SIP raw text is attacker-controlled.
 */
(function () {
  'use strict';

  // ---------------------------------------------------------------- helpers

  function $(id) { return document.getElementById(id); }

  /** Create an element with optional class and textContent. */
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  function p2(n) { return (n < 10 ? '0' : '') + n; }

  /** epoch-seconds float → HH:MM:SS.mmm local, or em-dash. */
  function fmtClock(ts) {
    if (ts == null || !isFinite(ts)) return '—';
    var d = new Date(ts * 1000);
    var ms = Math.floor((ts % 1) * 1000);
    var p3 = (ms < 10 ? '00' : ms < 100 ? '0' : '') + ms;
    return p2(d.getHours()) + ':' + p2(d.getMinutes()) + ':' + p2(d.getSeconds()) + '.' + p3;
  }

  function fmtDateTime(iso) {
    if (!iso) return '—';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return d.getFullYear() + '-' + p2(d.getMonth() + 1) + '-' + p2(d.getDate()) +
      ' ' + p2(d.getHours()) + ':' + p2(d.getMinutes());
  }

  function fmtBytes(n) {
    if (n == null) return '—';
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / (1024 * 1024)).toFixed(1) + ' MB';
  }

  var SEV_ORDER = { crit: 0, warn: 1, notice: 2, info: 3 };

  function sevChip(sev) {
    return el('span', 'chip sev-' + (sev || 'info'), sev || 'info');
  }

  // ------------------------------------------------------------------ state

  var state = {
    user: null,
    llm: null,               // /api/status .llm
    captures: [],
    captureId: null,
    analysis: null,
    msgById: {},
    legById: {},
    callById: {},
    tab: 'calls',
    selectedCallId: null,
    selectedMsgId: null,
    scope: { type: 'capture', id: null },
    expandRetrans: false,
    sortAsc: true,
    chatOpen: false,
    chatBusy: false,
    chatError: null
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
    if (state.user) name.textContent = state.user.name || state.user.email || '';

    wireStatic();
    pollStatus();
    setInterval(pollStatus, 60000);
    await loadCaptures();
    renderMain();
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
    if (state.chatOpen) renderChat();
  }

  function renderLlmChip() {
    var chip = $('llm-chip');
    var llm = state.llm;
    if (llm && llm.available) {
      chip.textContent = 'LLM: ' + (llm.model || '?');
      chip.title = llm.source === 'rfplex'
        ? 'model chosen by RFPlex — hiccup shares the GPU with RFPlex'
        : 'local model available (source: ' + (llm.source || '?') + ')';
      chip.classList.remove('llm-off');
    } else {
      chip.textContent = 'LLM offline';
      chip.title = 'local model unavailable — analysis features all still work';
      chip.classList.add('llm-off');
    }
  }

  function wireStatic() {
    // Tabs.
    var tabbar = $('tabs');
    var buttons = tabbar.querySelectorAll('.tab');
    for (var i = 0; i < buttons.length; i++) {
      (function (btn) {
        btn.addEventListener('click', function () {
          state.tab = btn.getAttribute('data-tab');
          state.selectedCallId = null;
          syncTabbar();
          renderMain();
        });
      })(buttons[i]);
    }

    // Logout.
    $('logout-btn').addEventListener('click', async function () {
      try { await fetch('/api/auth/logout', { method: 'POST' }); } catch (e) { /* ignore */ }
      location.href = '/';
    });

    // Upload.
    var dz = $('dropzone');
    var input = $('file-input');
    $('browse-btn').addEventListener('click', function () { input.click(); });
    input.addEventListener('change', function () {
      uploadFiles(input.files);
      input.value = '';
    });
    dz.addEventListener('dragover', function (ev) {
      ev.preventDefault();
      dz.classList.add('drag');
    });
    dz.addEventListener('dragleave', function () { dz.classList.remove('drag'); });
    dz.addEventListener('drop', function (ev) {
      ev.preventDefault();
      dz.classList.remove('drag');
      if (ev.dataTransfer && ev.dataTransfer.files) uploadFiles(ev.dataTransfer.files);
    });

    // Chat drawer.
    $('chat-toggle').addEventListener('click', function () { toggleChat(!state.chatOpen); });
    $('chat-close').addEventListener('click', function () { toggleChat(false); });
    $('chat-form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      submitChat();
    });
    $('chat-input').addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter' && !ev.shiftKey) {
        ev.preventDefault();
        submitChat();
      }
    });
  }

  function syncTabbar() {
    var buttons = $('tabs').querySelectorAll('.tab');
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].classList.toggle('active', buttons[i].getAttribute('data-tab') === state.tab);
    }
  }

  // --------------------------------------------------------------- captures

  async function loadCaptures() {
    try {
      var r = await fetch('/api/captures');
      if (!r.ok) throw new Error('captures ' + r.status);
      state.captures = await r.json();
    } catch (e) {
      state.captures = [];
    }
    renderSidebar();
  }

  function setUploadMsg(text, isError) {
    var m = $('upload-msg');
    if (!text) { m.hidden = true; m.textContent = ''; return; }
    m.hidden = false;
    m.textContent = text;
    m.classList.toggle('err', !!isError);
  }

  async function uploadFiles(fileList) {
    var files = Array.prototype.slice.call(fileList || []);
    for (var i = 0; i < files.length; i++) {
      await uploadFile(files[i]);
    }
  }

  async function uploadFile(file) {
    setUploadMsg('Analysing ' + file.name + ' …');
    try {
      var buf = await file.arrayBuffer();
      var r = await fetch('/api/captures', {
        method: 'POST',
        headers: { 'X-Filename': file.name },
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
      openCapture(j.id);
    } catch (e) {
      setUploadMsg('Upload failed: ' + (e && e.message ? e.message : 'network error'), true);
    }
  }

  async function deleteCapture(cap) {
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
      state.selectedCallId = null;
      state.selectedMsgId = null;
      state.scope = { type: 'capture', id: null };
      renderInspector();
      renderMain();
      if (state.chatOpen) renderChat();
    }
    await loadCaptures();
  }

  function renderSidebar() {
    var list = $('capture-list');
    clear(list);
    if (!state.captures.length) {
      var empty = el('div', 'empty-note');
      empty.appendChild(el('p', null, 'No captures yet.'));
      empty.appendChild(el('p', 'muted-note', 'Upload a pcap, pcapng, or an SBC log/SIP text export to get started.'));
      list.appendChild(empty);
      return;
    }
    for (var i = 0; i < state.captures.length; i++) {
      (function (cap) {
        var row = el('div', 'capture-row' + (cap.id === state.captureId ? ' active' : ''));
        var top = el('div', 'cap-top');
        top.appendChild(el('span', 'cap-name', cap.filename));
        var del = el('button', 'cap-del', '×');
        del.type = 'button';
        del.title = 'delete capture';
        del.addEventListener('click', function (ev) {
          ev.stopPropagation();
          deleteCapture(cap);
        });
        top.appendChild(del);
        row.appendChild(top);

        var sub = el('div', 'cap-sub');
        sub.appendChild(el('span', 'mono cap-meta',
          fmtDateTime(cap.uploadedAt) + ' · ' + fmtBytes(cap.sizeBytes)));
        row.appendChild(sub);

        var stats = cap.stats || {};
        var line = el('div', 'cap-stats mono',
          (stats.sipMessages || 0) + ' SIP · ' + (stats.h323Messages || 0) + ' H.323 · ' +
          (stats.calls || 0) + ' calls');
        row.appendChild(line);

        var fc = cap.findingCounts || {};
        var chips = el('div', 'cap-chips');
        var sevs = ['crit', 'warn', 'notice', 'info'];
        for (var s = 0; s < sevs.length; s++) {
          if (fc[sevs[s]]) {
            chips.appendChild(el('span', 'chip sev-' + sevs[s], String(fc[sevs[s]])));
          }
        }
        if (chips.firstChild) row.appendChild(chips);

        row.addEventListener('click', function () { openCapture(cap.id); });
        list.appendChild(row);
      })(state.captures[i]);
    }
  }

  async function openCapture(id) {
    var content = $('main-content');
    clear(content);
    content.appendChild(el('div', 'empty-note', 'Loading analysis…'));
    try {
      var r = await fetch('/api/captures/' + encodeURIComponent(id) + '/analysis');
      if (!r.ok) throw new Error('analysis ' + r.status);
      state.analysis = await r.json();
    } catch (e) {
      state.analysis = null;
      clear(content);
      content.appendChild(el('div', 'empty-note err', 'Could not load the analysis for this capture.'));
      return;
    }
    state.captureId = id;
    state.selectedCallId = null;
    state.selectedMsgId = null;
    state.scope = { type: 'capture', id: id };
    indexAnalysis();
    renderSidebar();
    renderInspector();
    renderMain();
    if (state.chatOpen) renderChat();
  }

  function indexAnalysis() {
    state.msgById = {};
    state.legById = {};
    state.callById = {};
    var a = state.analysis;
    if (!a) return;
    var i;
    for (i = 0; i < (a.messages || []).length; i++) state.msgById[a.messages[i].id] = a.messages[i];
    for (i = 0; i < (a.legs || []).length; i++) state.legById[a.legs[i].id] = a.legs[i];
    for (i = 0; i < (a.calls || []).length; i++) state.callById[a.calls[i].id] = a.calls[i];
  }

  // ------------------------------------------------------------- tab router

  function renderMain() {
    syncTabbar();
    var content = $('main-content');
    var scroller = content.querySelector('.scroll-area');
    var keepTop = scroller ? scroller.scrollTop : 0;
    var keepLeft = scroller ? scroller.scrollLeft : 0;
    clear(content);

    if (!state.analysis) {
      var hero = el('div', 'empty-hero');
      hero.appendChild(el('h2', null, 'see where the call went wrong'));
      hero.appendChild(el('p', null, 'Select a capture on the left, or drop a pcap / SBC log to analyse it.'));
      content.appendChild(hero);
      return;
    }

    var view;
    switch (state.tab) {
      case 'ladder': view = renderLadderTab(); break;
      case 'retrans': view = renderRetransTab(); break;
      case 'findings': view = renderFindingsTab(); break;
      default: view = renderCallsTab(); break;
    }
    content.appendChild(view);

    var scroller2 = content.querySelector('.scroll-area');
    if (scroller2) { scroller2.scrollTop = keepTop; scroller2.scrollLeft = keepLeft; }
  }

  /** Re-render the main view but keep ladder scroll position (used on select). */
  function rerenderKeepingScroll() { renderMain(); }

  // -------------------------------------------------------------- Calls tab

  function callStartTs(call) {
    var first = state.legById[call.legIds[0]];
    return first ? first.startTs : 0;
  }

  function callStopTs(call) {
    var max = null;
    for (var i = 0; i < call.legIds.length; i++) {
      var leg = state.legById[call.legIds[i]];
      if (leg && leg.endTs != null && (max == null || leg.endTs > max)) max = leg.endTs;
    }
    return max;
  }

  function callProtocolLabel(call) {
    if (call.type === 'sip-sip') return 'SIP↔SIP';
    if (call.type === 'sip-h323') return 'SIP↔H.323';
    var leg = state.legById[call.legIds[0]];
    return leg && leg.protocol === 'h323' ? 'H.323' : 'SIP';
  }

  function callMsgCount(call) {
    var n = 0;
    for (var i = 0; i < call.legIds.length; i++) {
      var leg = state.legById[call.legIds[i]];
      if (leg) n += (leg.msgIds || []).length;
    }
    return n;
  }

  function renderCallsTab() {
    var wrap = el('div', 'view');
    var a = state.analysis;
    var calls = a.calls || [];

    if (state.selectedCallId && state.callById[state.selectedCallId]) {
      wrap.appendChild(renderFlow(state.callById[state.selectedCallId]));
      return wrap;
    }

    if (!calls.length) {
      wrap.appendChild(el('div', 'empty-note', 'No calls in this capture. The Ladder tab still shows every message (REGISTER, OPTIONS…).'));
      return wrap;
    }

    var scroll = el('div', 'scroll-area');
    var table = el('table', 'calls-table');
    var thead = el('thead');
    var hr = el('tr');
    var cols = ['Start', 'Stop', 'Initial Speaker', 'From', 'To', 'Protocol', 'State', 'Confidence', 'Msgs'];
    for (var c = 0; c < cols.length; c++) {
      var th = el('th', null, cols[c]);
      if (cols[c] === 'Start') {
        th.className = 'sortable';
        th.appendChild(el('span', 'sort-arrow', state.sortAsc ? ' ▲' : ' ▼'));
        th.addEventListener('click', function () {
          state.sortAsc = !state.sortAsc;
          renderMain();
        });
      }
      hr.appendChild(th);
    }
    thead.appendChild(hr);
    table.appendChild(thead);

    var sorted = calls.slice().sort(function (x, y) {
      var d = callStartTs(x) - callStartTs(y);
      return state.sortAsc ? d : -d;
    });

    var tbody = el('tbody');
    for (var i = 0; i < sorted.length; i++) {
      (function (call) {
        var ingress = state.legById[call.legIds[0]] || {};
        var tr = el('tr', 'call-row');
        tr.appendChild(el('td', 'mono', fmtClock(callStartTs(call))));
        tr.appendChild(el('td', 'mono', fmtClock(callStopTs(call))));
        tr.appendChild(el('td', 'mono', (ingress.src || '?') + ':' + (ingress.sport || '?')));
        tr.appendChild(el('td', 'mono cell-uri', ingress.from || '—'));
        tr.appendChild(el('td', 'mono cell-uri', ingress.to || '—'));
        tr.appendChild(el('td', null, callProtocolLabel(call)));

        var stTd = el('td');
        var stTxt = ingress.state || '—';
        if (ingress.state === 'failed' && ingress.failCode != null) stTxt += ' (' + ingress.failCode + ')';
        stTd.appendChild(el('span', 'state-' + (ingress.state || 'na'), stTxt));
        tr.appendChild(stTd);

        var confTd = el('td', 'conf-cell');
        if (call.state === 'ambiguous') {
          confTd.appendChild(el('span', 'chip sev-warn ambiguous-chip', 'AMBIGUOUS'));
        } else if (call.type === 'single') {
          confTd.appendChild(el('span', 'muted-note', '—'));
        } else {
          var bar = el('span', 'conf-bar');
          var fill = el('span', 'conf-fill');
          fill.style.width = Math.round((call.confidence || 0) * 100) + '%';
          bar.appendChild(fill);
          confTd.appendChild(bar);
          confTd.appendChild(el('span', 'mono conf-num', ' ' + Math.round((call.confidence || 0) * 100) + '%'));
        }
        tr.appendChild(confTd);

        tr.appendChild(el('td', 'mono', String(callMsgCount(call))));

        tr.addEventListener('click', function () {
          state.selectedCallId = call.id;
          state.scope = { type: 'call', id: call.id };
          renderMain();
          if (state.chatOpen) renderChat();
        });
        tbody.appendChild(tr);
      })(sorted[i]);
    }
    table.appendChild(tbody);
    scroll.appendChild(table);
    wrap.appendChild(scroll);
    return wrap;
  }

  // -------------------------------------------------------------- Flow view

  function callMessages(call) {
    var idSet = {};
    for (var i = 0; i < call.legIds.length; i++) {
      var leg = state.legById[call.legIds[i]];
      if (!leg) continue;
      for (var j = 0; j < (leg.msgIds || []).length; j++) idSet[leg.msgIds[j]] = true;
    }
    var msgs = [];
    var all = state.analysis.messages || [];
    for (var k = 0; k < all.length; k++) {
      if (idSet[all[k].id]) msgs.push(all[k]);
    }
    return msgs;
  }

  function callCollapses(call) {
    var legSet = {};
    for (var i = 0; i < call.legIds.length; i++) legSet[call.legIds[i]] = true;
    var out = [];
    var collapses = (state.analysis.retrans && state.analysis.retrans.collapses) || [];
    for (var j = 0; j < collapses.length; j++) {
      if (legSet[collapses[j].legId]) out.push(collapses[j]);
    }
    return out;
  }

  function renderFlow(call) {
    var wrap = el('div', 'flow-view');

    var head = el('div', 'flow-head');
    var back = el('button', 'btn', '← All calls');
    back.type = 'button';
    back.addEventListener('click', function () {
      state.selectedCallId = null;
      state.scope = { type: 'capture', id: state.captureId };
      renderMain();
      if (state.chatOpen) renderChat();
    });
    head.appendChild(back);

    var title = el('span', 'flow-title');
    title.appendChild(el('strong', null, 'Call ' + call.id));
    title.appendChild(el('span', 'mono flow-sub',
      '  ' + callProtocolLabel(call) + ' · ' + call.legIds.join(' → ') + ' · ' + call.state));
    head.appendChild(title);

    if (call.state === 'ambiguous') {
      head.appendChild(el('span', 'chip sev-warn ambiguous-chip', 'AMBIGUOUS'));
    } else if (call.type !== 'single') {
      head.appendChild(el('span', 'chip', 'confidence ' + Math.round((call.confidence || 0) * 100) + '%'));
    }

    var expand = el('label', 'expand-toggle');
    var cb = el('input');
    cb.type = 'checkbox';
    cb.checked = state.expandRetrans;
    cb.addEventListener('change', function () {
      state.expandRetrans = cb.checked;
      renderMain();
    });
    expand.appendChild(cb);
    expand.appendChild(document.createTextNode(' expand retransmissions'));
    head.appendChild(expand);

    wrap.appendChild(head);

    // Ambiguity explainer with competing candidates.
    if (call.state === 'ambiguous' && call.candidates && call.candidates.length) {
      var amb = el('div', 'card amb-card');
      amb.appendChild(el('h3', null, 'Ambiguous pairing — hiccup will not guess'));
      amb.appendChild(el('p', 'muted-note', 'These candidate legs scored too close together to pick a winner:'));
      for (var ci = 0; ci < call.candidates.length; ci++) {
        var cand = call.candidates[ci];
        amb.appendChild(el('div', 'mono amb-cand',
          cand.legId + ' — confidence ' + Math.round((cand.confidence || 0) * 100) + '%'));
      }
      wrap.appendChild(amb);
    }

    // Per-call ladder.
    var scroll = el('div', 'scroll-area ladder-wrap');
    scroll.appendChild(window.Ladder.render({
      messages: callMessages(call),
      legs: call.legIds.map(function (id) { return state.legById[id]; }).filter(Boolean),
      collapses: callCollapses(call),
      expandRetrans: state.expandRetrans,
      selectedId: state.selectedMsgId,
      onSelect: selectMessage
    }));
    wrap.appendChild(scroll);

    // IWF pairing card (sip-h323) or diff category cards (sip-sip).
    if (call.type === 'sip-h323') {
      wrap.appendChild(renderIwfCard(call));
    } else if (call.type === 'sip-sip') {
      wrap.appendChild(renderDiffCards(call));
    }

    return wrap;
  }

  function renderIwfCard(call) {
    var card = el('div', 'card iwf-card');
    card.appendChild(el('h3', null, 'IWF pairing'));
    card.appendChild(el('p', 'muted-note',
      'This call crosses a SIP↔H.323 interworking function. Pairing is signal-based, not a header diff:'));
    var pairings = call.pairings || [];
    if (!pairings.length) {
      card.appendChild(el('p', 'muted-note', 'No pairing signals recorded.'));
      return card;
    }
    for (var i = 0; i < pairings.length; i++) {
      var p = pairings[i];
      var head = el('div', 'iwf-pair mono',
        p.a + ' ↔ ' + p.b + ' — confidence ' + Math.round((p.confidence || 0) * 100) + '%');
      card.appendChild(head);
      var list = el('ul', 'signal-list');
      var signals = p.signals || [];
      for (var s = 0; s < signals.length; s++) {
        var sig = signals[s];
        var li = el('li', 'signal-item' + (sig.matched ? ' matched' : ''));
        li.appendChild(el('span', 'sig-mark', sig.matched ? '✓' : '✗'));
        li.appendChild(el('span', 'mono sig-name', sig.name));
        li.appendChild(el('span', 'sig-weight mono', ' (' + sig.weight + ')'));
        if (sig.detail) li.appendChild(el('span', 'sig-detail', ' — ' + sig.detail));
        list.appendChild(li);
      }
      card.appendChild(list);
    }
    return card;
  }

  function renderDiffCards(call) {
    var wrap = el('div', 'diff-wrap');
    var diffs = call.diffs || [];
    var any = false;

    for (var d = 0; d < diffs.length; d++) {
      (function (pair) {
        var categories = (pair.diff && pair.diff.categories) || [];
        var nonEmpty = categories.filter(function (c) { return c.items && c.items.length; });
        if (!nonEmpty.length) return;
        any = true;

        wrap.appendChild(el('h3', 'diff-pair-title mono', pair.a + ' → ' + pair.b + '  (ingress → egress)'));
        var grid = el('div', 'diff-grid');

        for (var c = 0; c < nonEmpty.length; c++) {
          var cat = nonEmpty[c];
          var card = el('div', 'card diff-card');
          card.appendChild(el('h4', 'diff-cat-title', cat.title));

          for (var it = 0; it < cat.items.length; it++) {
            (function (item) {
              var row = el('div', 'diff-item');
              var top = el('div', 'diff-item-top');
              top.appendChild(sevChip(item.severity));
              top.appendChild(el('span', 'diff-label', item.label));
              var explain = el('button', 'btn explain-btn', 'explain');
              explain.type = 'button';
              explain.title = 'ask hiccup about this';
              explain.addEventListener('click', function (ev) {
                ev.stopPropagation();
                openChatPrefilled(
                  'Explain this difference between the legs: "' + item.label + '" (' + item.tag +
                  '). Ingress: ' + (item.ingress == null ? '(absent)' : item.ingress) +
                  '. Egress: ' + (item.egress == null ? '(absent)' : item.egress) + '.',
                  { type: 'call', id: call.id });
              });
              top.appendChild(explain);
              row.appendChild(top);

              var vals = el('div', 'diff-vals');
              var ing = el('div', 'diff-val');
              ing.appendChild(el('div', 'diff-val-head', 'ingress'));
              ing.appendChild(el('div', 'mono diff-val-body', item.ingress == null ? '(absent)' : item.ingress));
              var egr = el('div', 'diff-val');
              egr.appendChild(el('div', 'diff-val-head', 'egress'));
              egr.appendChild(el('div', 'mono diff-val-body', item.egress == null ? '(absent)' : item.egress));
              vals.appendChild(ing);
              vals.appendChild(egr);
              row.appendChild(vals);

              if (item.detail) row.appendChild(el('p', 'diff-detail', item.detail));
              card.appendChild(row);
            })(cat.items[it]);
          }
          grid.appendChild(card);
        }
        wrap.appendChild(grid);
      })(diffs[d]);
    }

    if (!any) {
      wrap.appendChild(el('div', 'empty-note', 'No differences detected between the legs of this call.'));
    }
    return wrap;
  }

  // ------------------------------------------------------------- Ladder tab

  function renderLadderTab() {
    var wrap = el('div', 'view');
    var a = state.analysis;
    var messages = a.messages || [];

    var bar = el('div', 'view-toolbar');
    var expand = el('label', 'expand-toggle');
    var cb = el('input');
    cb.type = 'checkbox';
    cb.checked = state.expandRetrans;
    cb.addEventListener('change', function () {
      state.expandRetrans = cb.checked;
      renderMain();
    });
    expand.appendChild(cb);
    expand.appendChild(document.createTextNode(' expand retransmissions'));
    bar.appendChild(expand);
    bar.appendChild(el('span', 'muted-note',
      messages.length + ' messages · click an arrow to inspect it'));
    wrap.appendChild(bar);

    if (!messages.length) {
      wrap.appendChild(el('div', 'empty-note', 'No signalling messages in this capture.'));
      return wrap;
    }

    var scroll = el('div', 'scroll-area ladder-wrap');
    scroll.appendChild(window.Ladder.render({
      messages: messages,
      legs: a.legs || [],
      collapses: (a.retrans && a.retrans.collapses) || [],
      expandRetrans: state.expandRetrans,
      selectedId: state.selectedMsgId,
      onSelect: selectMessage
    }));
    wrap.appendChild(scroll);
    return wrap;
  }

  function selectMessage(msgId) {
    state.selectedMsgId = msgId;
    state.scope = { type: 'message', id: msgId };
    renderInspector();
    rerenderKeepingScroll();
    if (state.chatOpen) renderChat();
  }

  // ------------------------------------------------------------ Retrans tab

  function renderRetransTab() {
    var wrap = el('div', 'view');
    var rt = (state.analysis && state.analysis.retrans) || { collapses: [], aggregate: { buckets: [], stormWindows: [] } };
    var collapses = rt.collapses || [];
    var agg = rt.aggregate || { buckets: [], stormWindows: [] };

    // Storm strip first — the box-wide view.
    wrap.appendChild(renderStormStrip(agg));

    var card = el('div', 'card');
    card.appendChild(el('h3', null, 'Retransmission collapses'));
    if (!collapses.length) {
      card.appendChild(el('p', 'muted-note', 'No retransmissions detected — every message got where it was going first time.'));
      wrap.appendChild(card);
      return wrap;
    }

    var scroll = el('div', 'scroll-area');
    var table = el('table', 'retrans-table');
    var thead = el('thead');
    var hr = el('tr');
    var cols = ['Collapse', 'Classification', 'Likely cause', 'Confidence'];
    for (var c = 0; c < cols.length; c++) hr.appendChild(el('th', null, cols[c]));
    thead.appendChild(hr);
    table.appendChild(thead);

    var tbody = el('tbody');
    for (var i = 0; i < collapses.length; i++) {
      (function (col) {
        var cls = col.classification || {};
        var tr = el('tr', 'retrans-row');
        tr.title = cls.detail || '';

        var labelTd = el('td');
        labelTd.appendChild(el('div', 'retrans-label', col.label || (col.method + ' ×' + col.count)));
        labelTd.appendChild(el('div', 'mono muted-note',
          (col.legId || '') + ' · ' + fmtClock(col.firstTs) + ' → ' + fmtClock(col.lastTs)));
        tr.appendChild(labelTd);

        var codeTd = el('td');
        codeTd.appendChild(el('span', 'chip mono code-chip code-' + (cls.code || 'unknown'), cls.code || 'unknown'));
        tr.appendChild(codeTd);

        tr.appendChild(el('td', 'cause-cell', cls.cause || '—'));

        var confTd = el('td', 'conf-cell');
        var bar = el('span', 'conf-bar');
        var fill = el('span', 'conf-fill');
        fill.style.width = Math.round((cls.confidence || 0) * 100) + '%';
        bar.appendChild(fill);
        confTd.appendChild(bar);
        confTd.appendChild(el('span', 'mono conf-num', ' ' + Math.round((cls.confidence || 0) * 100) + '%'));
        tr.appendChild(confTd);

        tr.addEventListener('click', function () {
          var first = (col.msgIds && col.msgIds[0]) || null;
          state.tab = 'ladder';
          if (first) {
            state.selectedMsgId = first;
            state.scope = { type: 'message', id: first };
          }
          renderMain();
          renderInspector();
          if (state.chatOpen) renderChat();
        });
        tbody.appendChild(tr);
      })(collapses[i]);
    }
    table.appendChild(tbody);
    scroll.appendChild(table);
    card.appendChild(scroll);
    wrap.appendChild(card);
    return wrap;
  }

  function renderStormStrip(agg) {
    var card = el('div', 'card storm-card');
    card.appendChild(el('h3', null, 'Retransmission timeline'));
    var buckets = (agg.buckets || []).slice().sort(function (a, b) { return a.ts - b.ts; });
    var windows = agg.stormWindows || [];

    if (!buckets.length) {
      card.appendChild(el('p', 'muted-note', 'No retransmissions in this capture.'));
      return card;
    }

    var SVGNS = 'http://www.w3.org/2000/svg';
    var minTs = Math.floor(buckets[0].ts);
    var maxTs = Math.floor(buckets[buckets.length - 1].ts);
    var span = Math.max(1, maxTs - minTs + 1);
    var PADL = 10, PADR = 10;
    var plotW = Math.max(300, Math.min(880, span * 14));
    var W = PADL + plotW + PADR;
    var plotH = 64, base = 78, H = 100;
    var maxCount = 1;
    for (var b = 0; b < buckets.length; b++) maxCount = Math.max(maxCount, buckets[b].retransCount);

    var svg = document.createElementNS(SVGNS, 'svg');
    svg.setAttribute('width', W);
    svg.setAttribute('height', H);
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.setAttribute('class', 'storm-svg');

    function tsX(ts) { return PADL + ((ts - minTs) / span) * plotW; }
    var bw = Math.max(3, Math.floor(plotW / span) - 2);

    // Storm windows tinted behind the bars.
    for (var w = 0; w < windows.length; w++) {
      var win = windows[w];
      var rx = tsX(win.startTs);
      var rw = Math.max(bw, tsX(win.endTs) - rx + bw);
      var rect = document.createElementNS(SVGNS, 'rect');
      rect.setAttribute('x', rx);
      rect.setAttribute('y', 6);
      rect.setAttribute('width', rw);
      rect.setAttribute('height', base - 6);
      rect.setAttribute('class', 'storm-window');
      svg.appendChild(rect);
    }

    // 1s bucket bars.
    for (var i = 0; i < buckets.length; i++) {
      var bu = buckets[i];
      var h = Math.max(2, (bu.retransCount / maxCount) * plotH);
      var bar = document.createElementNS(SVGNS, 'rect');
      bar.setAttribute('x', tsX(Math.floor(bu.ts)));
      bar.setAttribute('y', base - h);
      bar.setAttribute('width', bw);
      bar.setAttribute('height', h);
      bar.setAttribute('class', 'storm-bar');
      var t = document.createElementNS(SVGNS, 'title');
      t.textContent = fmtClock(bu.ts) + ' — ' + bu.retransCount + ' retransmissions across ' + bu.legsAffected + ' leg(s)';
      bar.appendChild(t);
      svg.appendChild(bar);
    }

    // Axis labels.
    var t0 = document.createElementNS(SVGNS, 'text');
    t0.setAttribute('x', PADL); t0.setAttribute('y', H - 6);
    t0.setAttribute('class', 'storm-axis');
    t0.textContent = fmtClock(minTs);
    svg.appendChild(t0);
    var t1 = document.createElementNS(SVGNS, 'text');
    t1.setAttribute('x', W - PADR); t1.setAttribute('y', H - 6);
    t1.setAttribute('text-anchor', 'end');
    t1.setAttribute('class', 'storm-axis');
    t1.textContent = fmtClock(maxTs);
    svg.appendChild(t1);

    var scroll = el('div', 'scroll-area');
    scroll.appendChild(svg);
    card.appendChild(scroll);

    if (windows.length) {
      for (var v = 0; v < windows.length; v++) {
        var vw = windows[v];
        var verdict = el('p', 'storm-verdict');
        verdict.appendChild(el('span', 'chip sev-crit', vw.verdict || 'box-wide'));
        verdict.appendChild(document.createTextNode(
          ' ' + vw.legsAffected + ' legs retransmitting together (' + vw.retransCount +
          ' retransmissions, ' + fmtClock(vw.startTs) + ' – ' + fmtClock(vw.endTs) +
          '). This is the box melting, not one broken call.'));
        card.appendChild(verdict);
      }
    } else {
      card.appendChild(el('p', 'muted-note', 'No box-wide storms — retransmissions are call-local.'));
    }
    return card;
  }

  // ----------------------------------------------------------- Findings tab

  function renderFindingsTab() {
    var wrap = el('div', 'view');
    var findings = (state.analysis && state.analysis.findings) || [];
    if (!findings.length) {
      wrap.appendChild(el('div', 'empty-note', 'No findings — this capture looks clean.'));
      return wrap;
    }

    var sorted = findings.slice().sort(function (a, b) {
      return (SEV_ORDER[a.severity] != null ? SEV_ORDER[a.severity] : 9) -
             (SEV_ORDER[b.severity] != null ? SEV_ORDER[b.severity] : 9);
    });

    var list = el('div', 'findings-list');
    for (var i = 0; i < sorted.length; i++) {
      (function (f) {
        var row = el('div', 'card finding-row');
        var top = el('div', 'finding-top');
        top.appendChild(sevChip(f.severity));
        top.appendChild(el('span', 'chip mono', f.category || '?'));
        top.appendChild(el('strong', 'finding-title', f.title || '(untitled)'));
        var explain = el('button', 'btn explain-btn', 'explain');
        explain.type = 'button';
        explain.addEventListener('click', function (ev) {
          ev.stopPropagation();
          openChatPrefilled('Explain this finding: "' + (f.title || '') + '". What causes it and what should I check?',
            { type: 'finding', id: f.id });
        });
        top.appendChild(explain);
        row.appendChild(top);
        if (f.detail) row.appendChild(el('p', 'finding-detail', f.detail));

        var refs = [];
        if (f.callIds && f.callIds.length) refs.push('calls: ' + f.callIds.join(', '));
        if (f.legIds && f.legIds.length) refs.push('legs: ' + f.legIds.join(', '));
        if (f.msgIds && f.msgIds.length) refs.push('msgs: ' + f.msgIds.join(', '));
        if (refs.length) row.appendChild(el('p', 'mono muted-note', refs.join(' · ')));

        row.addEventListener('click', function () { focusFinding(f); });
        list.appendChild(row);
      })(sorted[i]);
    }
    wrap.appendChild(list);
    return wrap;
  }

  /** Jump from a finding to the view that best shows it. */
  function focusFinding(f) {
    if (f.callIds && f.callIds.length && state.callById[f.callIds[0]]) {
      state.tab = 'calls';
      state.selectedCallId = f.callIds[0];
      state.scope = { type: 'call', id: f.callIds[0] };
    } else if (f.category === 'retrans') {
      state.tab = 'retrans';
      state.scope = { type: 'finding', id: f.id };
    } else if (f.msgIds && f.msgIds.length && state.msgById[f.msgIds[0]]) {
      state.tab = 'ladder';
      state.selectedMsgId = f.msgIds[0];
      state.scope = { type: 'message', id: f.msgIds[0] };
      renderInspector();
    } else if (f.legIds && f.legIds.length) {
      // Find the call containing this leg.
      var calls = state.analysis.calls || [];
      for (var i = 0; i < calls.length; i++) {
        if (calls[i].legIds.indexOf(f.legIds[0]) !== -1) {
          state.tab = 'calls';
          state.selectedCallId = calls[i].id;
          state.scope = { type: 'call', id: calls[i].id };
          break;
        }
      }
    }
    renderMain();
    if (state.chatOpen) renderChat();
  }

  // -------------------------------------------------------------- inspector

  function renderInspector() {
    var panel = $('inspector');
    clear(panel);
    var m = state.selectedMsgId ? state.msgById[state.selectedMsgId] : null;
    if (!m) {
      panel.hidden = true;
      return;
    }
    panel.hidden = false;

    var head = el('div', 'insp-head');
    head.appendChild(el('strong', null, 'Message ' + m.id));
    var spacer = el('span', 'topbar-spacer');
    head.appendChild(spacer);
    var explain = el('button', 'btn explain-btn', 'explain this');
    explain.type = 'button';
    explain.addEventListener('click', function () {
      openChatPrefilled('Explain this ' + (m.protocol === 'h323' ? 'H.323' : 'SIP') +
        ' message: what is it doing in this call, and is anything wrong with it?',
        { type: 'message', id: m.id });
    });
    head.appendChild(explain);
    var close = el('button', 'btn chat-close', '×');
    close.type = 'button';
    close.title = 'close inspector';
    close.addEventListener('click', function () {
      state.selectedMsgId = null;
      state.scope = state.selectedCallId
        ? { type: 'call', id: state.selectedCallId }
        : { type: 'capture', id: state.captureId };
      renderInspector();
      rerenderKeepingScroll();
      if (state.chatOpen) renderChat();
    });
    head.appendChild(close);
    panel.appendChild(head);

    var summary = el('dl', 'insp-summary');
    function kv(k, v) {
      if (v == null || v === '') return;
      summary.appendChild(el('dt', null, k));
      summary.appendChild(el('dd', 'mono', String(v)));
    }

    if (m.protocol === 'h323') {
      kv('Type', m.q931Type);
      kv('Summary', m.summary);
      kv('Time', fmtClock(m.ts));
      kv('Path', m.src + ':' + m.sport + ' → ' + m.dst + ':' + m.dport + ' (' + m.transport + ')');
      kv('Call ref', m.callRef + (m.callRefFlag ? ' (flag 1)' : ' (flag 0)'));
      kv('Calling', m.calling);
      kv('Called', m.called);
      if (m.causeCode != null) kv('Cause', m.causeCode + (m.causeText ? ' — ' + m.causeText : ''));
      kv('GUID', m.guid);
      kv('Fast start', m.hasFastStart ? 'yes' : 'no');
      kv('Size', m.size + ' B');
    } else {
      kv('Line', m.isRequest
        ? (m.method + ' ' + (m.requestUri || ''))
        : ('SIP/2.0 ' + m.status + ' ' + (m.reason || '')));
      kv('Time', fmtClock(m.ts));
      kv('Path', m.src + ':' + m.sport + ' → ' + m.dst + ':' + m.dport + ' (' + m.transport + ')');
      kv('Call-ID', m.callId);
      kv('From', m.fromUri + (m.fromTag ? ';tag=' + m.fromTag : ''));
      kv('To', m.toUri + (m.toTag ? ';tag=' + m.toTag : ''));
      if (m.cseq) kv('CSeq', m.cseq.num + ' ' + m.cseq.method);
      kv('Branch', m.branch);
      kv('Body', m.bodyType);
      kv('Size', m.size + ' B');
      if (m.retransOf) kv('Retransmission of', m.retransOf);
    }
    panel.appendChild(summary);

    panel.appendChild(el('h4', 'insp-raw-title', m.protocol === 'h323' ? 'Raw (hex)' : 'Raw'));
    var pre = el('pre', 'mono insp-raw');
    pre.textContent = m.raw || '';   // textContent only — raw is untrusted
    panel.appendChild(pre);
  }

  // ------------------------------------------------------------ chat drawer

  function chatKey() { return 'hiccup-chat-' + (state.captureId || 'none'); }

  /** @returns {Array<{role:string,content:string,model?:string}>} */
  function chatHistory() {
    try {
      var raw = sessionStorage.getItem(chatKey());
      var arr = raw ? JSON.parse(raw) : [];
      return Array.isArray(arr) ? arr : [];
    } catch (e) { return []; }
  }

  function saveChat(hist) {
    try { sessionStorage.setItem(chatKey(), JSON.stringify(hist)); } catch (e) { /* full */ }
  }

  function toggleChat(open) {
    state.chatOpen = open;
    $('chat-drawer').hidden = !open;
    $('chat-toggle').classList.toggle('active', open);
    if (open) {
      renderChat();
      $('chat-input').focus();
    }
  }

  function scopeLabel() {
    var s = state.scope || { type: 'capture' };
    if (s.type === 'capture' || !s.id) return 'whole capture';
    return s.type + ' ' + s.id;
  }

  function renderChat() {
    var llm = state.llm;
    var available = !!(llm && llm.available);

    // Model chip + RFPlex-sharing hint.
    var modelChip = $('chat-model');
    modelChip.textContent = available ? (llm.model || '') : 'offline';
    var hint = $('chat-hint');
    if (available && llm.source === 'rfplex') {
      hint.hidden = false;
      hint.textContent = (llm.model || 'model') +
        ' — shares its brain with RFPlex — answers may queue behind RFPlex work';
    } else {
      hint.hidden = true;
      hint.textContent = '';
    }

    // Scope chip.
    var scopeBox = $('chat-scope');
    clear(scopeBox);
    scopeBox.appendChild(el('span', 'muted-note', 'scope: '));
    scopeBox.appendChild(el('span', 'chip mono', scopeLabel()));
    if (state.scope && state.scope.type !== 'capture') {
      var reset = el('button', 'btn scope-reset', '× whole capture');
      reset.type = 'button';
      reset.title = 'reset scope to the whole capture';
      reset.addEventListener('click', function () {
        state.scope = { type: 'capture', id: state.captureId };
        renderChat();
      });
      scopeBox.appendChild(reset);
    }

    // Messages.
    var box = $('chat-messages');
    clear(box);
    if (!state.captureId) {
      box.appendChild(el('div', 'empty-note', 'Open a capture first — hiccup answers about what it can see.'));
    } else {
      var hist = chatHistory();
      if (!hist.length && !state.chatBusy) {
        var welcome = el('div', 'empty-note');
        welcome.appendChild(el('p', null, 'Ask about this capture or about SIP/H.323 in general.'));
        welcome.appendChild(el('p', 'muted-note', 'Try: "why is this call ambiguous?" · "what does Session-Expires do?" · "what stripped the PAI header?"'));
        box.appendChild(welcome);
      }
      for (var i = 0; i < hist.length; i++) {
        var mrow = el('div', 'chat-bubble ' + (hist[i].role === 'user' ? 'from-user' : 'from-bot'));
        mrow.textContent = hist[i].content;
        box.appendChild(mrow);
      }
      if (state.chatBusy) {
        var busy = el('div', 'chat-bubble from-bot busy');
        busy.appendChild(el('span', 'spinner'));
        busy.appendChild(document.createTextNode(' thinking…'));
        box.appendChild(busy);
      }
    }
    box.scrollTop = box.scrollHeight;

    // Error line.
    var errBox = $('chat-error');
    if (state.chatError) {
      errBox.hidden = false;
      errBox.textContent = state.chatError;
    } else {
      errBox.hidden = true;
      errBox.textContent = '';
    }

    // Availability: offline note replaces the input.
    var form = $('chat-form');
    var offline = $('chat-offline');
    if (!available) {
      offline.hidden = false;
      form.hidden = true;
    } else {
      offline.hidden = true;
      form.hidden = !state.captureId;
      $('chat-send').disabled = state.chatBusy;
      $('chat-input').disabled = state.chatBusy;
    }
  }

  /** Open the drawer with a prefilled question and a scope (explain buttons). */
  function openChatPrefilled(question, scope) {
    if (scope) state.scope = scope;
    toggleChat(true);
    var input = $('chat-input');
    input.value = question;
    input.focus();
  }

  async function submitChat() {
    if (state.chatBusy || !state.captureId) return;
    var llm = state.llm;
    if (!llm || !llm.available) return;
    var input = $('chat-input');
    var text = input.value.trim();
    if (!text) return;
    input.value = '';
    state.chatError = null;

    var hist = chatHistory();
    hist.push({ role: 'user', content: text });
    saveChat(hist);
    state.chatBusy = true;
    renderChat();

    try {
      var r = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          captureId: state.captureId,
          messages: hist.map(function (m) { return { role: m.role, content: m.content }; }),
          scope: state.scope
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
        hist.push({ role: 'assistant', content: j.reply, model: j.model });
        saveChat(hist);
      }
    } catch (e) {
      state.chatError = 'chat failed: ' + (e && e.message ? e.message : 'network error');
    }
    state.chatBusy = false;
    renderChat();
  }

  // ------------------------------------------------------------------- go

  boot();
})();
