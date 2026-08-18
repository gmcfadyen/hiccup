/*
 * hiccup — hmr.js
 * The header-manipulation workbench page (public/hmr.html).
 *
 * Paste or pick an SBC config -> POST /api/hmr/analyze -> vendor detection plus one
 * card per rule: plain-English intent, correctness verdict with citations, improvement
 * suggestions, a translate-to renderer for the other vendors, and (when a capture is
 * picked) the matchAgainstAnalysis verdicts for that rule.
 *
 * All DOM building is vanilla createElement; every string that came from the server or
 * the user goes through textContent — never innerHTML. Config text and SIP values are
 * attacker-controlled.
 */
(function () {
  'use strict';
  // public/i18n.js publishes window._t from a blocking <head> script. The local
  // alias keeps this file working — in English — if that script is ever missing,
  // rather than throwing a ReferenceError out of every render.
  var _t = (window && window._t) || function (s) { return s; };

  // ---------------------------------------------------------------- helpers

  function $(id) { return document.getElementById(id); }

  /** Create an element with optional class and textContent. */
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }

  function clear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

  function p2(n) { return (n < 10 ? '0' : '') + n; }

  function fmtDateTime(iso) {
    if (!iso) return '';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return d.getFullYear() + '-' + p2(d.getMonth() + 1) + '-' + p2(d.getDate()) +
      ' ' + p2(d.getHours()) + ':' + p2(d.getMinutes());
  }

  function isStr(v) { return typeof v === 'string' && v.length > 0; }

  function pct(n) {
    if (typeof n !== 'number' || !isFinite(n)) return null;
    var v = n <= 1 ? n * 100 : n;
    return Math.max(0, Math.min(100, Math.round(v)));
  }

  function sevChip(sev) {
    var s = (sev === 'crit' || sev === 'warn' || sev === 'notice' || sev === 'info') ? sev : 'info';
    return el('span', 'chip sev-' + s, s);
  }

  // ---------------------------------------------------------------- vendors

  var VENDORS = [
    { key: 'oracle-acme', label: 'Oracle / Acme Packet',
      aliases: ['oracle-acme', 'oracle_acme', 'oracleacme', 'oracle', 'acme', 'acme-packet', 'acmepacket'] },
    { key: 'audiocodes', label: 'AudioCodes',
      aliases: ['audiocodes', 'audio-codes', 'audio_codes', 'ac'] },
    { key: 'ribbon', label: 'Ribbon',
      aliases: ['ribbon', 'ribbon-smm', 'ribbonsmm', 'smm', 'sonus'] }
  ];

  /** Canonicalise a vendor string to one of the three keys, or null. */
  function vendorKey(raw) {
    if (!isStr(raw)) return null;
    var norm = raw.toLowerCase().replace(/\s+/g, '-');
    for (var i = 0; i < VENDORS.length; i++) {
      if (VENDORS[i].aliases.indexOf(norm) !== -1) return VENDORS[i].key;
    }
    return null;
  }

  function vendorLabel(raw) {
    var k = vendorKey(raw);
    if (k) {
      for (var i = 0; i < VENDORS.length; i++) if (VENDORS[i].key === k) return VENDORS[i].label;
    }
    // lib/hmr-generate.js stamps freshly-generated rules 'generic' (not yet
    // rendered for any one vendor) — that is not a real product, so it gets
    // its own label rather than being shown as if it were one.
    if (raw === 'generic') return _t('not vendor-specific');
    return isStr(raw) ? raw : _t('unknown vendor');
  }

  var VERDICTS = {
    'observed-as-configured': {
      label: _t('observed as configured'), cls: 'chip verdict-observed',
      note: _t('the capture shows this manipulation actually happening')
    },
    'configured-not-observed': {
      label: _t('configured, not observed'), cls: 'chip sev-warn',
      note: _t('the rule is configured but the capture never shows it fire')
    },
    'observed-not-configured': {
      label: _t('observed, not configured'), cls: 'chip sev-notice',
      note: _t('the capture shows a manipulation that no rule in this config accounts for')
    }
  };

  var DRAFT_WARNING = _t('reviewable draft — never apply unverified');

  // ------------------------------------------------------------------ state

  var state = {
    user: null,
    captures: [],
    captureId: '',
    result: null,       // last /api/hmr/analyze response
    entries: [],        // normalised [{ rule, explanation, rendered }]
    matchesByRule: {},  // ruleId -> [match]
    orphanMatches: [],
    translateTo: {},    // ruleId -> vendor key currently shown
    busy: false,
    genBusy: false
  };

  // ------------------------------------------------------------------- boot

  async function boot() {
    try {
      var r = await fetch('/api/me');
      if (r.status === 401) { location.href = '/'; return; }
      if (!r.ok) throw new Error('me ' + r.status);
      var j = await r.json();
      state.user = j && j.user ? j.user : null;
    } catch (e) {
      location.href = '/';
      return;
    }
    if (state.user) {
      $('user-name').textContent = state.user.name || state.user.email || '';
    }
    wire();
    await loadCaptures();
  }

  function wire() {
    $('logout-btn').addEventListener('click', async function () {
      try { await fetch('/api/auth/logout', { method: 'POST' }); } catch (e) { /* ignore */ }
      location.href = '/';
    });

    $('hmr-analyze').addEventListener('click', function () { analyse(); });
    $('hmr-browse').addEventListener('click', function () { $('hmr-file').click(); });
    $('hmr-clear').addEventListener('click', function () { resetAll(); });

    $('hmr-gen-go').addEventListener('click', function () { runGenerate(); });
    $('hmr-gen-clear').addEventListener('click', function () {
      $('hmr-gen-text').value = '';
      setGenStatus('');
      clear($('hmr-gen-result'));
    });

    $('hmr-file').addEventListener('change', async function () {
      var f = $('hmr-file').files && $('hmr-file').files[0];
      $('hmr-file').value = '';
      if (!f) return;
      $('hmr-file-name').textContent = f.name;
      try {
        var text = await readAsText(f);
        $('hmr-text').value = text;
        setStatus(_t('Loaded ') + f.name + ' (' + text.length + _t(' chars). Press “Analyse config”.'));
        analyse();
      } catch (e) {
        setStatus(_t('Could not read that file as text.'), true);
      }
    });

    $('hmr-capture').addEventListener('change', function () {
      state.captureId = $('hmr-capture').value || '';
      if ($('hmr-text').value.trim()) analyse();
    });
  }

  /** FileReader-free text read, with a FileReader fallback for older browsers. */
  function readAsText(file) {
    if (file.text) return file.text();
    return new Promise(function (resolve, reject) {
      try {
        var fr = new FileReader();
        fr.onload = function () { resolve(String(fr.result || '')); };
        fr.onerror = function () { reject(new Error('read failed')); };
        fr.readAsText(file);
      } catch (e) { reject(e); }
    });
  }

  // --------------------------------------------------------------- captures

  async function loadCaptures() {
    try {
      var r = await fetch('/api/captures');
      if (r.status === 401) { location.href = '/'; return; }
      if (!r.ok) throw new Error(_t('captures ') + r.status);
      var list = await r.json();
      state.captures = Array.isArray(list) ? list : [];
    } catch (e) {
      state.captures = [];
    }
    renderCapturePicker();
  }

  function renderCapturePicker() {
    var sel = $('hmr-capture');
    clear(sel);
    var none = el('option', null,
      state.captures.length ? _t('— config only (no capture) —') : _t('— no captures uploaded yet —'));
    none.value = '';
    sel.appendChild(none);
    for (var i = 0; i < state.captures.length; i++) {
      var c = state.captures[i] || {};
      var label = (c.filename || c.id || 'capture');
      if (c.uploadedAt) label += '  ·  ' + fmtDateTime(c.uploadedAt);
      var o = el('option', null, label);
      o.value = c.id || '';
      sel.appendChild(o);
    }
    sel.value = state.captureId || '';
  }

  // ---------------------------------------------------------------- analyse

  function setStatus(text, isError) {
    var s = $('hmr-status');
    s.textContent = text || '';
    s.classList.toggle('err', !!isError);
  }

  function setBusy(on) {
    state.busy = !!on;
    $('hmr-analyze').disabled = !!on;
    $('hmr-analyze').textContent = on ? _t('Analysing…') : _t('Analyse config');
  }

  function resetAll() {
    $('hmr-text').value = '';
    $('hmr-file-name').textContent = '';
    state.result = null;
    state.entries = [];
    state.matchesByRule = {};
    state.orphanMatches = [];
    state.translateTo = {};
    setStatus('');
    render();
  }

  async function analyse() {
    if (state.busy) return;
    var text = $('hmr-text').value || '';
    if (!text.trim()) {
      setStatus(_t('Paste a config, or choose a config file, first.'), true);
      return;
    }
    if (text.length > 900000) {
      setStatus(_t('That config is too big for the 1 MB request limit — trim it to the ') +
        _t('sip-manipulation / MessageManipulations section.'), true);
      return;
    }

    setBusy(true);
    setStatus(_t('Reading the config…'));
    var body = { text: text };
    if (state.captureId) body.captureId = state.captureId;

    var res = null, payload = null;
    try {
      res = await fetch('/api/hmr/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      if (res.status === 401) { location.href = '/'; return; }
      try { payload = await res.json(); } catch (e) { payload = null; }
    } catch (e) {
      setBusy(false);
      setStatus(_t('Could not reach the server. Is hiccup still running?'), true);
      return;
    }
    setBusy(false);

    if (!res.ok) {
      state.result = null;
      state.entries = [];
      state.matchesByRule = {};
      state.orphanMatches = [];
      render();
      var err = _t((payload && (payload.error || payload.userMessage)) || '') ||
        (_t('Analysis failed (') + res.status + ').');
      // A 404 while a capture is selected means that capture is gone (deleted in
      // another tab). Drop the selection so the next Analyse is not a dead end.
      if (res.status === 404 && state.captureId) {
        state.captureId = '';
        await loadCaptures();
        setStatus(err + _t(' — the capture picker has been reset; press “Analyse config” again.'), true);
        return;
      }
      setStatus(err, true);
      return;
    }

    ingest(payload || {});
    render();
    var n = state.entries.length;
    setStatus(n
      ? (_t('Read ') + n + _t(' rule') + (n === 1 ? '' : 's') + '.' +
         (state.captureId ? _t(' Checked against the selected capture.') : ''))
      : _t('No header-manipulation rules found in that text.'));
  }

  // ------------------------------------------------------------- generate

  function setGenStatus(text, isError) {
    var s = $('hmr-gen-status');
    s.textContent = text || '';
    s.classList.toggle('err', !!isError);
  }

  function setGenBusy(on) {
    state.genBusy = !!on;
    $('hmr-gen-go').disabled = !!on;
    $('hmr-gen-go').textContent = on ? _t('Generating…') : _t('Generate rule');
  }

  async function runGenerate() {
    if (state.genBusy) return;
    var text = $('hmr-gen-text').value || '';
    if (!text.trim()) {
      setGenStatus(_t('Describe what the rule should do first.'), true);
      return;
    }

    setGenBusy(true);
    setGenStatus(_t('Thinking…'));

    var res = null, payload = null;
    try {
      res = await fetch('/api/hmr/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ description: text })
      });
      if (res.status === 401) { location.href = '/'; return; }
      try { payload = await res.json(); } catch (e) { payload = null; }
    } catch (e) {
      setGenBusy(false);
      setGenStatus(_t('Could not reach the server. Is hiccup still running?'), true);
      return;
    }
    setGenBusy(false);

    if (!res.ok) {
      clear($('hmr-gen-result'));
      var err = _t((payload && (payload.error || payload.userMessage)) || '') ||
        (_t('Generation failed (') + res.status + ').');
      setGenStatus(err, true);
      return;
    }

    renderGenResult(payload || {});
    setGenStatus((payload && payload.ok)
      ? _t('Draft ready — review before use, then attach it to the right interface.')
      : _t('hiccup could not build a rule from that description — see below.'), !(payload && payload.ok));
  }

  /**
   * Render one /api/hmr/generate response. On success this reshapes the
   * result into the same { rule, explanation, rendered } entry shape
   * ingest() builds from /api/hmr/analyze, and hands it to the existing
   * ruleCard() — intent, correctness, translate-to-vendor and the copy
   * button are all identical UI for a generated rule and an analysed one,
   * so there is exactly one renderer for both rather than a second copy
   * that would drift from the first.
   */
  function renderGenResult(out) {
    var host = $('hmr-gen-result');
    clear(host);
    if (!out) return;

    if (!out.ok) {
      var card = el('div', 'card hmr-empty');
      var qs = Array.isArray(out.questions) ? out.questions.filter(isStr) : [];
      var warns = Array.isArray(out.warnings) ? out.warnings.filter(isStr) : [];
      if (qs.length) {
        card.appendChild(el('div', 'hmr-section-title', _t('hiccup needs to know more')));
        var ul = el('ul', 'hmr-questions');
        for (var i = 0; i < qs.length; i++) ul.appendChild(el('li', null, qs[i]));
        card.appendChild(ul);
      }
      for (var w = 0; w < warns.length; w++) card.appendChild(el('p', 'muted', warns[w]));
      if (!qs.length && !warns.length) {
        card.appendChild(el('p', null, _t('hiccup could not turn that into a rule.')));
      }
      host.appendChild(card);
      return;
    }

    var assumptions = Array.isArray(out.assumptions) ? out.assumptions.filter(isStr) : [];
    if (assumptions.length) {
      var aHost = el('ul', 'hmr-assumptions');
      for (var a = 0; a < assumptions.length; a++) aHost.appendChild(el('li', null, assumptions[a]));
      host.appendChild(aHost);
    }

    var entry = {
      rule: out.rule || {},
      explanation: out.explain || {},
      rendered: out.drafts || {},
      key: 'generated'
    };
    host.appendChild(ruleCard(entry, 0));

    var warnings = Array.isArray(out.warnings) ? out.warnings.filter(isStr) : [];
    if (warnings.length) {
      var wCard = el('div', 'card hmr-empty');
      for (var w2 = 0; w2 < warnings.length; w2++) wCard.appendChild(el('p', 'muted', warnings[w2]));
      host.appendChild(wCard);
    }

    if (out.regex && isStr(out.regex.pattern)) {
      var rxCard = el('section', 'card hmr-rule-card');
      rxCard.appendChild(el('div', 'hmr-section-title', _t('Suggested match pattern')));
      rxCard.appendChild(el('p', 'mono hmr-intent', out.regex.pattern));
      if (isStr(out.regex.explanation)) rxCard.appendChild(el('p', 'muted', out.regex.explanation));
      var tested = Array.isArray(out.regex.tested) ? out.regex.tested : [];
      for (var t = 0; t < tested.length; t++) {
        var tt = tested[t];
        if (!tt || !isStr(tt.input)) continue;
        var row = el('p');
        row.appendChild(el('span', 'mono', tt.input));
        row.appendChild(document.createTextNode(' — '));
        row.appendChild(el('span', tt.matched ? 'hmr-ok' : 'sev-warn',
          tt.matched ? _t('matches') : _t('does not match')));
        rxCard.appendChild(row);
      }
      host.appendChild(rxCard);
    }
  }

  // ---------------------------------------------------- response normalising

  /**
   * Fold the response into { entries, matchesByRule, orphanMatches }, tolerating
   * shape drift (rules as bare HmrRules, rendered as map/array/string, matches as
   * an array or a { matches } wrapper).
   */
  function ingest(payload) {
    state.result = payload;
    state.translateTo = {};

    var rawRules = Array.isArray(payload.rules) ? payload.rules : [];
    var entries = [];
    for (var i = 0; i < rawRules.length; i++) {
      var item = rawRules[i];
      if (!item || typeof item !== 'object') continue;
      var rule = (item.rule && typeof item.rule === 'object') ? item.rule : item;
      var explanation = (item.explanation && typeof item.explanation === 'object')
        ? item.explanation
        : ((item.explain && typeof item.explain === 'object') ? item.explain : {});
      entries.push({
        rule: rule || {},
        explanation: explanation,
        rendered: normalizeRendered(item.rendered),
        key: isStr(rule && rule.id) ? rule.id : ('idx' + i)
      });
    }
    state.entries = entries;

    var matches = normalizeMatches(payload.matches);
    var byRule = {};
    var orphans = [];
    var known = {};
    for (var k = 0; k < entries.length; k++) {
      if (isStr(entries[k].rule.id)) known[entries[k].rule.id] = true;
    }
    for (var m = 0; m < matches.length; m++) {
      var match = matches[m];
      var rid = isStr(match.ruleId) ? match.ruleId : null;
      if (rid && known[rid]) {
        if (!byRule[rid]) byRule[rid] = [];
        byRule[rid].push(match);
      } else {
        orphans.push(match);
      }
    }
    state.matchesByRule = byRule;
    state.orphanMatches = orphans;
  }

  /** rendered -> { <vendorKey>: string, __any?: string }. */
  function normalizeRendered(rendered) {
    var out = {};
    if (rendered == null) return out;
    if (typeof rendered === 'string') {
      if (rendered.trim()) out.__any = rendered;
      return out;
    }
    if (Array.isArray(rendered)) {
      for (var i = 0; i < rendered.length; i++) {
        var it = rendered[i];
        if (!it || typeof it !== 'object') continue;
        var k = vendorKey(it.vendor || it.target || it.key);
        var txt = firstString([it.text, it.config, it.rendered, it.value, it.draft]);
        if (k && txt) out[k] = txt;
      }
      return out;
    }
    if (typeof rendered === 'object') {
      var keys = Object.keys(rendered);
      for (var j = 0; j < keys.length; j++) {
        var vk = vendorKey(keys[j]);
        var val = rendered[keys[j]];
        var text = null;
        if (typeof val === 'string') text = val;
        else if (val && typeof val === 'object') text = firstString([val.text, val.config, val.rendered, val.value, val.draft]);
        if (vk && isStr(text)) out[vk] = text;
      }
    }
    return out;
  }

  function firstString(list) {
    for (var i = 0; i < list.length; i++) if (isStr(list[i])) return list[i];
    return null;
  }

  function normalizeMatches(m) {
    var arr = [];
    if (Array.isArray(m)) arr = m;
    else if (m && typeof m === 'object' && Array.isArray(m.matches)) arr = m.matches;
    var out = [];
    for (var i = 0; i < arr.length; i++) {
      if (arr[i] && typeof arr[i] === 'object') out.push(arr[i]);
    }
    return out;
  }

  // ----------------------------------------------------------------- render

  function render() {
    renderSummary();
    renderWarnings();
    renderRules();
    renderOrphans();
  }

  function renderSummary() {
    var host = $('hmr-summary');
    clear(host);
    if (!state.result) { host.hidden = true; return; }
    host.hidden = false;

    host.appendChild(el('span', 'hmr-summary-vendor', vendorLabel(state.result.vendor)));

    var conf = pct(state.result.confidence);
    if (conf != null) {
      var bar = el('span', 'hmr-conf-bar');
      bar.title = _t('vendor detection confidence ') + conf + '%';
      var fill = el('span', 'hmr-conf-fill');
      fill.style.width = conf + '%';
      bar.appendChild(fill);
      host.appendChild(bar);
      host.appendChild(el('span', 'chip', conf + _t('% confidence')));
    }
    if (!vendorKey(state.result.vendor)) {
      host.appendChild(el('span', 'chip sev-warn', _t('vendor not recognised')));
    }
    host.appendChild(el('span', 'chip', state.entries.length + _t(' rule') +
      (state.entries.length === 1 ? '' : 's')));
    if (state.captureId) {
      var cap = null;
      for (var i = 0; i < state.captures.length; i++) {
        if (state.captures[i] && state.captures[i].id === state.captureId) cap = state.captures[i];
      }
      host.appendChild(el('span', 'chip', _t('checked against ') +
        ((cap && cap.filename) || state.captureId)));
    }
  }

  function renderWarnings() {
    var host = $('hmr-warnings');
    clear(host);
    var warnings = state.result && Array.isArray(state.result.warnings) ? state.result.warnings : [];
    if (!warnings.length) { host.hidden = true; return; }
    host.hidden = false;
    for (var i = 0; i < warnings.length; i++) {
      host.appendChild(el('li', null, String(warnings[i])));
    }
  }

  function renderRules() {
    var host = $('hmr-rules');
    clear(host);

    if (!state.result) {
      var intro = el('div', 'card hmr-empty');
      intro.appendChild(el('p', null,
        _t('Nothing analysed yet. Paste an Oracle/Acme sip-manipulation block, an AudioCodes ') +
        _t('MessageManipulations table, or Ribbon SMM rule text above.')));
      intro.appendChild(el('p', 'muted',
        _t('Pick a capture as well and hiccup will tell you which of these rules the trace ') +
        _t('actually shows firing.')));
      host.appendChild(intro);
      return;
    }
    if (!state.entries.length) {
      var empty = el('div', 'card hmr-empty');
      empty.appendChild(el('p', null, _t('No header-manipulation rules were recognised in that text.')));
      empty.appendChild(el('p', 'muted',
        _t('hiccup reads Oracle/Acme sip-manipulation blocks, AudioCodes .ini ') +
        _t('MessageManipulations rows and Ribbon SMM rules. Other config sections are ignored.')));
      host.appendChild(empty);
      return;
    }

    for (var i = 0; i < state.entries.length; i++) {
      host.appendChild(ruleCard(state.entries[i], i));
    }
  }

  function ruleCard(entry, index) {
    var rule = entry.rule || {};
    var card = el('section', 'card hmr-rule-card');

    // ---- head
    var head = el('div', 'hmr-rule-head');
    head.appendChild(el('span', 'hmr-rule-name', rule.name || rule.id || (_t('rule ') + (index + 1))));
    if (isStr(rule.id)) head.appendChild(el('span', 'chip mono', rule.id));
    if (isStr(rule.vendor)) head.appendChild(el('span', 'chip', vendorLabel(rule.vendor)));
    card.appendChild(head);

    // ---- IR meta chips
    var meta = el('div', 'hmr-meta');
    if (isStr(rule.operation)) meta.appendChild(el('span', 'chip', rule.operation));
    var scope = rule.scope && typeof rule.scope === 'object' ? rule.scope : {};
    if (isStr(scope.direction)) meta.appendChild(el('span', 'chip', _t('direction ') + scope.direction));
    if (isStr(scope.msgType)) meta.appendChild(el('span', 'chip', scope.msgType));
    if (Array.isArray(scope.methods) && scope.methods.length) {
      meta.appendChild(el('span', 'chip mono', scope.methods.join(', ')));
    }
    var tgt = targetText(rule.target);
    if (tgt) meta.appendChild(el('span', 'chip mono', _t('target ') + tgt));
    if (rule.value && typeof rule.value === 'object' && isStr(rule.value.text)) {
      meta.appendChild(el('span', 'chip mono', _t('value ') + trunc(rule.value.text, 60)));
    }
    var bindings = Array.isArray(rule.bindings) ? rule.bindings : [];
    for (var b = 0; b < bindings.length; b++) {
      var bd = bindings[b];
      if (!bd || typeof bd !== 'object') continue;
      meta.appendChild(el('span', 'chip',
        (bd.kind || 'binding') + (isStr(bd.name) ? ': ' + bd.name : '')));
    }
    if (meta.firstChild) card.appendChild(meta);

    // ---- intent (the headline)
    var intentSec = el('div', 'hmr-section');
    intentSec.appendChild(el('div', 'hmr-section-title', _t('What it does')));
    var intent = entry.explanation && isStr(entry.explanation.intent)
      ? entry.explanation.intent
      : _t('hiccup could not put this rule into plain English.');
    intentSec.appendChild(el('p', 'hmr-intent', intent));
    card.appendChild(intentSec);

    // ---- conditions
    var conds = Array.isArray(rule.conditions) ? rule.conditions : [];
    if (conds.length) {
      var cSec = el('div', 'hmr-section');
      cSec.appendChild(el('div', 'hmr-section-title', _t('Conditions')));
      var cl = el('ul', 'hmr-improve');
      for (var c = 0; c < conds.length; c++) {
        var cd = conds[c];
        if (!cd || typeof cd !== 'object') continue;
        var parts = [];
        if (isStr(cd.element)) parts.push(cd.element);
        if (isStr(cd.comparison)) parts.push(cd.comparison);
        if (cd.value != null && String(cd.value) !== '') parts.push(String(cd.value));
        cl.appendChild(el('li', 'mono', parts.join(' ') || _t('(empty condition)')));
      }
      if (cl.firstChild) { cSec.appendChild(cl); card.appendChild(cSec); }
    }

    // ---- raw snippet (collapsible)
    if (isStr(rule.raw)) {
      var rawSec = el('div', 'hmr-section');
      var det = el('details', 'hmr-details');
      det.appendChild(el('summary', null, _t('Config as written')));
      det.appendChild(el('pre', 'mono hmr-snippet', rule.raw));
      rawSec.appendChild(det);
      card.appendChild(rawSec);
    }

    // ---- correctness
    card.appendChild(correctnessSection(entry.explanation));

    // ---- improvements
    var impSec = improvementsSection(entry.explanation);
    if (impSec) card.appendChild(impSec);

    // ---- translate-to
    card.appendChild(translateSection(entry));

    // ---- capture match verdicts
    var mSec = matchesSection(entry);
    if (mSec) card.appendChild(mSec);

    return card;
  }

  function targetText(target) {
    if (!target || typeof target !== 'object') return null;
    var t = isStr(target.header) ? target.header : '';
    if (isStr(target.element) && target.element !== 'value') t += (t ? '.' : '') + target.element;
    if (target.index != null && target.index !== '') t += '[' + target.index + ']';
    return t || null;
  }

  function trunc(text, n) {
    var s = String(text);
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }

  function correctnessSection(explanation) {
    var sec = el('div', 'hmr-section');
    sec.appendChild(el('div', 'hmr-section-title', _t('Correctness')));

    var corr = explanation && typeof explanation.correctness === 'object' && explanation.correctness
      ? explanation.correctness
      : null;
    var issues = corr && Array.isArray(corr.issues) ? corr.issues.filter(Boolean) : [];

    if (!corr) {
      sec.appendChild(el('p', 'muted', _t('No correctness check available for this rule.')));
      return sec;
    }
    if (!issues.length) {
      var ok = el('p', 'hmr-ok', (corr.ok === false ? '' : '✓ ') +
        (corr.ok === false
          ? _t('hiccup flagged this rule but reported no detail.')
          : _t('No problems found — the rule looks internally consistent.')));
      if (corr.ok === false) ok.className = 'sev-warn';
      sec.appendChild(ok);
      return sec;
    }

    var list = el('ul', 'hmr-issues');
    for (var i = 0; i < issues.length; i++) {
      var iss = issues[i];
      var li = el('li', 'hmr-issue');
      if (typeof iss === 'string') {
        li.appendChild(sevChip('warn'));
        li.appendChild(el('span', 'hmr-issue-detail', iss));
      } else if (iss && typeof iss === 'object') {
        li.appendChild(sevChip(iss.severity));
        li.appendChild(el('span', 'hmr-issue-detail',
          isStr(iss.detail) ? iss.detail : (isStr(iss.title) ? iss.title : 'issue')));
        var cites = Array.isArray(iss.citations) ? iss.citations : (iss.citation ? [iss.citation] : []);
        for (var c = 0; c < cites.length; c++) {
          var node = citationNode(cites[c]);
          if (node) li.appendChild(node);
        }
      } else {
        continue;
      }
      list.appendChild(li);
    }
    sec.appendChild(list);
    return sec;
  }

  /** Citation -> a link (new tab) when it has a url, else a plain labelled span. */
  function citationNode(cite) {
    if (!cite) return null;
    if (typeof cite === 'string') return el('span', 'hmr-cite muted', cite);
    if (typeof cite !== 'object') return null;

    var label = [cite.source, cite.section].filter(isStr).join(' ');
    if (!label) label = isStr(cite.title) ? cite.title : 'reference';
    var tip = [cite.title, cite.note].filter(isStr).join(' — ');

    if (isStr(cite.url) && /^https?:\/\//i.test(cite.url)) {
      var a = el('a', 'hmr-cite citation-link', label);
      a.href = cite.url;
      a.target = '_blank';
      a.rel = 'noopener';
      if (tip) a.title = tip;
      return a;
    }
    var span = el('span', 'hmr-cite citation-link is-unlinked muted', label);
    if (tip) span.title = tip;
    return span;
  }

  function improvementsSection(explanation) {
    var imps = explanation && Array.isArray(explanation.improvements)
      ? explanation.improvements.filter(Boolean) : [];
    if (!imps.length) return null;
    var sec = el('div', 'hmr-section');
    sec.appendChild(el('div', 'hmr-section-title', _t('Suggested improvements')));
    var ul = el('ul', 'hmr-improve');
    for (var i = 0; i < imps.length; i++) {
      var it = imps[i];
      var li = el('li');
      if (typeof it === 'string') {
        li.appendChild(document.createTextNode(it));
      } else if (typeof it === 'object') {
        li.appendChild(document.createTextNode(isStr(it.detail) ? it.detail : 'suggestion'));
        if (isStr(it.rationale)) li.appendChild(el('span', 'hmr-rationale', it.rationale));
        var cn = it.citation ? citationNode(it.citation) : null;
        if (cn) { li.appendChild(document.createTextNode(' ')); li.appendChild(cn); }
      }
      ul.appendChild(li);
    }
    sec.appendChild(ul);
    return sec;
  }

  function translateSection(entry) {
    var sec = el('div', 'hmr-section');
    sec.appendChild(el('div', 'hmr-section-title', _t('Translate to')));

    var rendered = entry.rendered || {};
    var chosen = state.translateTo[entry.key];
    if (!chosen) {
      var detected = vendorKey(entry.rule && entry.rule.vendor) ||
        (state.result ? vendorKey(state.result.vendor) : null);
      if (detected && (rendered[detected] || rendered.__any)) chosen = detected;
      if (!chosen) {
        for (var i = 0; i < VENDORS.length; i++) {
          if (rendered[VENDORS[i].key]) { chosen = VENDORS[i].key; break; }
        }
      }
      if (!chosen) chosen = detected || VENDORS[0].key;
      state.translateTo[entry.key] = chosen;
    }

    var row = el('div', 'hmr-translate-row');
    var sel = el('select', 'input');
    sel.setAttribute('aria-label', _t('render this rule for another vendor'));
    for (var v = 0; v < VENDORS.length; v++) {
      var have = rendered[VENDORS[v].key] || rendered.__any;
      var o = el('option', null, VENDORS[v].label + (have ? '' : _t(' (no draft)')));
      o.value = VENDORS[v].key;
      sel.appendChild(o);
    }
    sel.value = chosen;
    row.appendChild(sel);
    sec.appendChild(row);

    sec.appendChild(el('p', 'hmr-draft-warn', '⚠ ' + DRAFT_WARNING));

    var body = el('div');
    sec.appendChild(body);

    function paint() {
      clear(body);
      var key = state.translateTo[entry.key];
      var text = rendered[key] || rendered.__any || null;
      if (!text) {
        body.appendChild(el('p', 'muted',
          _t('hiccup has no ') + vendorLabel(key) + _t(' rendering for this rule. Concepts that do ') +
          _t('not map across vendors are left out rather than guessed at.')));
        return;
      }
      // Same shape as the Advice fix cards in app.html: pre + floating copy button.
      var wrap = el('div', 'config-wrap');
      wrap.appendChild(el('pre', 'mono fix-config hmr-draft', text));
      var copy = el('button', 'copy-btn', _t('Copy'));
      copy.type = 'button';
      copy.title = _t('copy this draft to the clipboard');
      var note = el('span', 'hmr-copy-note');
      copy.addEventListener('click', function () {
        copyText(text).then(function () {
          copy.textContent = _t('Copied');
          copy.classList.add('is-copied');
          setTimeout(function () {
            copy.textContent = _t('Copy');
            copy.classList.remove('is-copied');
          }, 1600);
        }, function () {
          note.textContent = _t('Copy blocked by the browser — select the text instead.');
          setTimeout(function () { note.textContent = ''; }, 4000);
        });
      });
      wrap.appendChild(copy);
      body.appendChild(wrap);
      body.appendChild(note);
    }

    sel.addEventListener('change', function () {
      state.translateTo[entry.key] = sel.value;
      paint();
    });
    paint();
    return sec;
  }

  function matchesSection(entry) {
    if (!state.captureId) return null;
    var rid = isStr(entry.rule && entry.rule.id) ? entry.rule.id : null;
    var list = rid && state.matchesByRule[rid] ? state.matchesByRule[rid] : [];

    var sec = el('div', 'hmr-section');
    sec.appendChild(el('div', 'hmr-section-title', _t('Against the capture')));
    if (!list.length) {
      sec.appendChild(el('p', 'muted', _t('hiccup could not tie this rule to anything in the ') +
        _t('selected capture — it may simply never have been exercised.')));
      return sec;
    }
    for (var i = 0; i < list.length; i++) sec.appendChild(matchRow(list[i]));
    return sec;
  }

  function matchRow(match) {
    var row = el('div', 'hmr-match');
    var line = el('div', 'hmr-match-line');
    var v = VERDICTS[match.verdict];
    var chip = el('span', v ? v.cls : 'chip', v ? v.label : (isStr(match.verdict) ? match.verdict : 'unknown'));
    if (v) chip.title = v.note;
    line.appendChild(chip);
    if (isStr(match.detail)) line.appendChild(el('span', null, match.detail));
    row.appendChild(line);

    var tags = Array.isArray(match.diffTags) ? match.diffTags.filter(isStr) : [];
    var callIds = Array.isArray(match.callIds) ? match.callIds.filter(isStr) : [];
    if (tags.length || callIds.length) {
      var ids = el('div', 'hmr-match-line hmr-ids');
      for (var t = 0; t < tags.length; t++) ids.appendChild(el('span', 'chip mono', tags[t]));
      if (callIds.length) {
        ids.appendChild(el('span', 'mono', _t('calls: ') + callIds.join(', ')));
      }
      row.appendChild(ids);
    }
    return row;
  }

  function renderOrphans() {
    var host = $('hmr-orphans');
    clear(host);
    if (!state.captureId || !state.orphanMatches.length) return;

    var card = el('section', 'card hmr-rule-card');
    card.appendChild(el('div', 'hmr-rule-name', _t('Seen in the capture, not in this config')));
    card.appendChild(el('p', 'muted',
      _t('These manipulations show up in the trace but no rule above accounts for them — ') +
      _t('another manipulation set, a different binding, or a rule hiccup could not parse.')));
    for (var i = 0; i < state.orphanMatches.length; i++) {
      card.appendChild(matchRow(state.orphanMatches[i]));
    }
    host.appendChild(card);
  }

  // ------------------------------------------------------------------- copy

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      try {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.top = '-1000px';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand && document.execCommand('copy');
        document.body.removeChild(ta);
        if (ok) resolve(); else reject(new Error('copy blocked'));
      } catch (e) { reject(e); }
    });
  }

  // ------------------------------------------------------------------- init

  render();
  boot();
})();
