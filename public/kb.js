/*
 * hiccup — kb.js
 * The config-guide knowledge base page (public/kb.html).
 *
 * Upload vendor guides (POST /api/kb/docs, raw body + X-Filename), list/delete them
 * (GET/DELETE /api/kb/docs), and keyword-search them (POST /api/kb/search). The KB
 * exists so config advice can cite the vendor's own guide instead of guessing.
 *
 * All DOM building is vanilla createElement; document text and filenames go through
 * textContent (or a <mark>-splitting highlighter) — never innerHTML.
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

  function isStr(v) { return typeof v === 'string' && v.length > 0; }

  function p2(n) { return (n < 10 ? '0' : '') + n; }

  function fmtDateTime(iso) {
    if (!iso) return '—';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return d.getFullYear() + '-' + p2(d.getMonth() + 1) + '-' + p2(d.getDate()) +
      ' ' + p2(d.getHours()) + ':' + p2(d.getMinutes());
  }

  function fmtBytes(n) {
    if (typeof n !== 'number' || !isFinite(n)) return '—';
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / (1024 * 1024)).toFixed(1) + ' MB';
  }

  /**
   * HTTP header values must be ISO-8859-1-safe or fetch() throws, so keep
   * printable ASCII only (the server sanitises again on its side).
   */
  function headerSafe(value) {
    var s = String(value == null ? '' : value)
      .replace(/[^\x20-\x7E]+/g, '_')
      .replace(/[\r\n]+/g, '_')
      .slice(0, 200)
      .trim();
    return s;
  }

  // ------------------------------------------------------------------ state

  var state = {
    user: null,
    docs: [],
    hits: [],
    terms: [],
    query: '',
    uploading: false,
    searching: false
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
    await loadDocs();
  }

  function wire() {
    $('logout-btn').addEventListener('click', async function () {
      try { await fetch('/api/auth/logout', { method: 'POST' }); } catch (e) { /* ignore */ }
      location.href = '/';
    });

    var dz = $('kb-dropzone');
    var input = $('kb-file');

    $('kb-browse').addEventListener('click', function () { input.click(); });
    input.addEventListener('change', function () {
      var files = input.files;
      input.value = '';
      uploadFiles(files);
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

    $('kb-search-form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      search();
    });

    $('kb-link-add').addEventListener('click', function () { addLink(); });
    $('kb-link-url').addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter') { ev.preventDefault(); addLink(); }
    });
  }

  // ------------------------------------------------------------------ docs

  function setMsg(text, isError) {
    var m = $('kb-msg');
    m.textContent = text || '';
    m.classList.toggle('err', !!isError);
  }

  function showNote(serverMessage) {
    var note = $('kb-note');
    clear(note);
    note.hidden = false;
    note.appendChild(el('p', null, serverMessage));
    var p = el('p', 'muted');
    p.appendChild(document.createTextNode('PDF support is optional on purpose — hiccup ships ' +
      _t('with zero runtime dependencies. Either run ')));
    p.appendChild(el('code', 'mono', 'npm install pdf-parse'));
    p.appendChild(document.createTextNode(' in the hiccup folder and restart it, or save the ' +
      _t('guide as .txt, .md or .html and upload that instead.')));
    note.appendChild(p);
  }

  function hideNote() {
    var note = $('kb-note');
    note.hidden = true;
    clear(note);
  }

  /** True when a server message is the optional-PDF-dependency message. */
  function isPdfDepMessage(msg) {
    return isStr(msg) && (/pdf-parse/i.test(msg) || /PDF support/i.test(msg));
  }

  async function loadDocs() {
    try {
      var r = await fetch('/api/kb/docs');
      if (r.status === 401) { location.href = '/'; return; }
      if (!r.ok) throw new Error('docs ' + r.status);
      var j = await r.json();
      var list = Array.isArray(j) ? j : (j && Array.isArray(j.docs) ? j.docs : []);
      state.docs = list.filter(function (d) { return d && typeof d === 'object'; });
      renderDocs();
    } catch (e) {
      state.docs = [];
      renderDocs(_t('Could not load your guides. Is hiccup still running?'));
    }
  }

  async function uploadFiles(fileList) {
    var files = Array.prototype.slice.call(fileList || []);
    if (!files.length || state.uploading) return;
    state.uploading = true;
    for (var i = 0; i < files.length; i++) {
      await uploadFile(files[i]);
    }
    state.uploading = false;
    await loadDocs();
  }

  async function uploadFile(file) {
    setMsg(_t('Indexing ') + file.name + ' …');
    var res = null, payload = null;
    try {
      var buf = await file.arrayBuffer();
      var headers = { 'X-Filename': headerSafe(file.name) || 'guide.txt' };
      // Optional tags: the server also accepts X-Vendor / X-Product and passes
      // them through to kb.addDoc, which is what fills the table's column.
      var vendor = headerSafe($('kb-vendor').value);
      var product = headerSafe($('kb-product').value);
      if (vendor) headers['X-Vendor'] = vendor;
      if (product) headers['X-Product'] = product;
      res = await fetch('/api/kb/docs', {
        method: 'POST',
        headers: headers,
        body: buf
      });
      if (res.status === 401) { location.href = '/'; return; }
      try { payload = await res.json(); } catch (e) { payload = null; }
    } catch (e) {
      setMsg(_t('Upload of ') + file.name + _t(' failed: ') +
        (e && e.message ? e.message : _t('network error')), true);
      return;
    }

    var msg = payload ? (_t(payload.error || payload.userMessage || '') || null) : null;
    if (!res.ok) {
      if (isPdfDepMessage(msg)) {
        showNote(msg);
        setMsg(file.name + _t(' was not indexed — see the note below.'), true);
      } else {
        setMsg(msg || (_t('Upload of ') + file.name + _t(' failed (') + res.status + ').'), true);
      }
      return;
    }

    hideNote();
    var doc = payload && payload.doc ? payload.doc : payload;
    var chunks = doc && typeof doc.chunks === 'number' ? doc.chunks : null;
    setMsg(_t('Indexed ') + ((doc && (doc.title || doc.filename)) || file.name) +
      (chunks != null ? ' — ' + chunks + _t(' chunk') + (chunks === 1 ? '' : 's') : '') + '.');
  }

  /**
   * Register a link to a vendor's own hosted guide. Unlike uploadFile(), this
   * sends JSON — there is no file, so no bytes ever leave the browser for
   * this action beyond the URL and the two tag fields the user already typed.
   */
  async function addLink() {
    var url = ($('kb-link-url').value || '').trim();
    if (!url) {
      setMsg(_t('Paste a link first.'), true);
      return;
    }
    if (!/^https?:\/\//i.test(url)) {
      setMsg(_t('That does not look like a web link — it must start with http:// or https://.'), true);
      return;
    }
    if (state.uploading) return;
    state.uploading = true;
    setMsg(_t('Adding link…'));

    var res = null, payload = null;
    try {
      res = await fetch('/api/kb/link', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: url,
          vendor: $('kb-vendor').value || undefined,
          product: $('kb-product').value || undefined
        })
      });
      if (res.status === 401) { location.href = '/'; return; }
      try { payload = await res.json(); } catch (e) { payload = null; }
    } catch (e) {
      state.uploading = false;
      setMsg(_t('Could not reach the server.'), true);
      return;
    }
    state.uploading = false;

    if (!res.ok) {
      setMsg(_t((payload && (payload.error || payload.userMessage)) || '') ||
        (_t('Could not add that link (') + res.status + ').'), true);
      return;
    }

    $('kb-link-url').value = '';
    var doc = payload && payload.doc ? payload.doc : payload;
    setMsg(_t('Added ') + ((doc && (doc.title || doc.url)) || url) + '.');
    await loadDocs();
  }

  async function deleteDoc(doc) {
    var name = doc.title || doc.filename || doc.id;
    var question = isStr(doc.url)
      ? _t('Remove the link "{0}"?', name)
      : (_t('Remove "') + name + _t('" from the knowledge base?\n') +
         _t('Config advice will stop citing it.'));
    if (!confirm(question)) return;
    try {
      var r = await fetch('/api/kb/docs/' + encodeURIComponent(doc.id), { method: 'DELETE' });
      if (r.status === 401) { location.href = '/'; return; }
      if (!r.ok) {
        var j = null;
        try { j = await r.json(); } catch (e2) { /* non-json */ }
        setMsg(_t((j && (j.error || j.userMessage)) || '') ||
          (_t('Could not delete "') + name + '" (' + r.status + ').'), true);
        await loadDocs();
        return;
      }
    } catch (e) {
      setMsg(_t('Could not delete "') + name + _t('" — the server did not answer.'), true);
      return;
    }
    setMsg(_t('Removed ') + name + '.');
    // Hits from the deleted doc are stale — drop them.
    var kept = [];
    for (var i = 0; i < state.hits.length; i++) {
      if (state.hits[i] && state.hits[i].docId !== doc.id) kept.push(state.hits[i]);
    }
    state.hits = kept;
    renderHits();
    await loadDocs();
  }

  function renderDocs(errorText) {
    var host = $('kb-docs');
    clear(host);

    var totalChunks = 0;
    for (var t = 0; t < state.docs.length; t++) {
      var c = state.docs[t] && state.docs[t].chunks;
      if (typeof c === 'number' && isFinite(c)) totalChunks += c;
    }
    $('kb-doc-count').textContent = state.docs.length
      ? (state.docs.length + ' doc' + (state.docs.length === 1 ? '' : 's') +
         ' · ' + totalChunks + _t(' chunks'))
      : '';

    if (errorText) {
      var errBox = el('div', 'card kb-empty');
      errBox.appendChild(el('p', 'sev-crit', errorText));
      host.appendChild(errBox);
      return;
    }
    if (!state.docs.length) {
      var empty = el('div', 'card kb-empty');
      empty.appendChild(el('p', null, _t('No guides yet.')));
      empty.appendChild(el('p', 'muted',
        _t('Add the SBC administration guide, a release note, or your own runbook. hiccup ') +
        _t('chunks it, indexes the words (no embeddings — the GPU stays free for RFPlex), and ') +
        _t('quotes the relevant passage next to any config suggestion.')));
      host.appendChild(empty);
      return;
    }

    var table = el('table', 'kb-table');
    var thead = el('thead');
    var hrow = el('tr');
    [_t('Title'), _t('Vendor / product'), _t('Chunks'), _t('Size'), _t('Added'), ''].forEach(function (h) {
      hrow.appendChild(el('th', null, h));
    });
    thead.appendChild(hrow);
    table.appendChild(thead);

    var tbody = el('tbody');
    for (var i = 0; i < state.docs.length; i++) {
      (function (doc) {
        if (!doc || typeof doc !== 'object') return;
        var row = el('tr');
        var isLink = isStr(doc.url);

        var tdTitle = el('td');
        if (isLink) {
          var a = el('a', 'kb-doc-title', doc.title || doc.url);
          a.href = doc.url;
          a.target = '_blank';
          a.rel = 'noopener';
          a.title = doc.url;
          tdTitle.appendChild(a);
          tdTitle.appendChild(el('span', 'kb-link-chip', _t('link')));
        } else {
          tdTitle.appendChild(el('span', 'kb-doc-title', doc.title || doc.filename || doc.id || 'document'));
          if (isStr(doc.filename) && doc.filename !== doc.title) {
            tdTitle.appendChild(el('span', 'kb-doc-file mono', doc.filename));
          }
        }
        row.appendChild(tdTitle);

        var vp = [doc.vendor, doc.product].filter(isStr).join(' · ');
        row.appendChild(el('td', vp ? null : 'muted', vp || '—'));

        row.appendChild(el('td', 'kb-num mono',
          isLink ? '—' : (typeof doc.chunks === 'number' ? doc.chunks : '—')));
        row.appendChild(el('td', 'kb-num mono', isLink ? '—' : fmtBytes(doc.sizeBytes)));
        row.appendChild(el('td', 'mono', fmtDateTime(doc.addedAt)));

        var tdDel = el('td');
        if (isStr(doc.id)) {
          var del = el('button', 'btn kb-del', _t('Delete'));
          del.type = 'button';
          del.title = _t('remove this guide from the knowledge base');
          del.addEventListener('click', function () { deleteDoc(doc); });
          tdDel.appendChild(del);
        }
        row.appendChild(tdDel);

        tbody.appendChild(row);
      })(state.docs[i]);
    }
    table.appendChild(tbody);
    host.appendChild(table);
  }

  // ---------------------------------------------------------------- search

  function setCount(text, isError) {
    var c = $('kb-count');
    c.textContent = text || '';
    c.classList.toggle('sev-crit', !!isError);
  }

  /** Query -> highlight terms (2+ chars, regex-escaped later, capped). */
  function queryTerms(q) {
    var raw = String(q || '').split(/[\s,;"'()\[\]]+/);
    var out = [];
    for (var i = 0; i < raw.length && out.length < 12; i++) {
      var t = raw[i];
      if (!t || t.length < 2) continue;
      if (out.indexOf(t.toLowerCase()) !== -1) continue;
      out.push(t.toLowerCase());
    }
    return out;
  }

  async function search() {
    var q = ($('kb-query').value || '').trim();
    state.query = q;
    if (!q) {
      state.hits = [];
      state.terms = [];
      renderHits();
      setCount(_t('Type a few words from the guide — hiccup scores passages by keyword, ') +
        _t('so nouns beat sentences.'));
      return;
    }
    if (state.searching) return;
    state.searching = true;
    $('kb-search-btn').disabled = true;
    setCount(_t('Searching…'));

    var res = null, payload = null;
    try {
      res = await fetch('/api/kb/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ q: q, k: 12 })
      });
      if (res.status === 401) { location.href = '/'; return; }
      try { payload = await res.json(); } catch (e) { payload = null; }
    } catch (e) {
      state.searching = false;
      $('kb-search-btn').disabled = false;
      setCount(_t('Search failed — could not reach the server.'), true);
      return;
    }
    state.searching = false;
    $('kb-search-btn').disabled = false;

    if (!res.ok) {
      var msg = payload ? _t(payload.error || payload.userMessage || '') : null;
      if (isPdfDepMessage(msg)) showNote(msg);
      state.hits = [];
      renderHits();
      setCount(msg || (_t('Search failed (') + res.status + ').'), true);
      return;
    }

    var hits = [];
    if (payload && Array.isArray(payload.hits)) hits = payload.hits;
    else if (Array.isArray(payload)) hits = payload;
    state.hits = hits.filter(function (h) { return h && typeof h === 'object'; });
    state.terms = queryTerms(q);
    renderHits();
    setCount(state.hits.length
      ? (state.hits.length + _t(' passage') + (state.hits.length === 1 ? '' : 's') +
         _t(' matched “') + q + '”')
      : '');
  }

  function renderHits() {
    var host = $('kb-results');
    clear(host);
    if (!state.hits.length) {
      if (state.query) {
        var none = el('div', 'card kb-empty');
        none.appendChild(el('p', null, _t('Nothing in your guides matched “') + state.query + '”.'));
        none.appendChild(el('p', 'muted', state.docs.length
          ? _t('Try the vendor’s own wording — parameter names beat descriptions.')
          : _t('There are no guides uploaded yet, so there is nothing to search.')));
        host.appendChild(none);
      }
      return;
    }
    for (var i = 0; i < state.hits.length; i++) {
      host.appendChild(hitCard(state.hits[i]));
    }
  }

  function hitCard(hit) {
    var card = el('article', 'card kbp-hit');

    var head = el('div', 'kbp-hit-head');
    head.appendChild(el('span', 'kbp-hit-title', hit.docTitle || hit.docId || 'document'));
    if (hit.page != null && hit.page !== '') {
      head.appendChild(el('span', 'chip', 'page ' + hit.page));
    }
    if (typeof hit.score === 'number' && isFinite(hit.score)) {
      var s = el('span', 'chip mono', _t('score ') + hit.score.toFixed(2));
      s.title = _t('BM25-ish keyword score — higher is a closer keyword match, not a ranking of truth');
      head.appendChild(s);
    }
    card.appendChild(head);

    if (isStr(hit.heading)) card.appendChild(el('p', 'kbp-hit-heading', hit.heading));

    if (isStr(hit.text)) {
      var body = el('p', 'kbp-excerpt');
      highlightInto(body, excerptFor(hit.text, state.terms, 700), state.terms);
      card.appendChild(body);
    } else {
      card.appendChild(el('p', 'muted', _t('This passage came back without text.')));
    }

    return card;
  }

  /** Window the chunk text around the first matching term so the hit is visible. */
  function excerptFor(text, terms, max) {
    if (text.length <= max) return text;
    var lower = text.toLowerCase();
    var at = -1;
    for (var i = 0; i < terms.length; i++) {
      var idx = lower.indexOf(terms[i]);
      if (idx !== -1 && (at === -1 || idx < at)) at = idx;
    }
    var start = at === -1 ? 0 : Math.max(0, at - Math.floor(max / 3));
    // Snap to a word boundary so we do not cut mid-token.
    if (start > 0) {
      var sp = text.indexOf(' ', start);
      if (sp !== -1 && sp - start < 40) start = sp + 1;
    }
    var slice = text.slice(start, start + max);
    return (start > 0 ? '… ' : '') + slice + (start + max < text.length ? ' …' : '');
  }

  function escapeRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  /**
   * Append text to `node`, wrapping term matches in <mark>. Text nodes only —
   * document content is never treated as markup.
   */
  function highlightInto(node, text, terms) {
    if (!text) return;
    var list = (terms || []).filter(function (t) { return isStr(t); });
    if (!list.length) { node.appendChild(document.createTextNode(text)); return; }

    var re;
    try {
      re = new RegExp('(' + list.map(escapeRe).join('|') + ')', 'gi');
    } catch (e) {
      node.appendChild(document.createTextNode(text));
      return;
    }

    var last = 0, m, guard = 0;
    while ((m = re.exec(text)) !== null && guard++ < 5000) {
      if (!m[0]) { re.lastIndex++; continue; }
      if (m.index > last) node.appendChild(document.createTextNode(text.slice(last, m.index)));
      node.appendChild(el('mark', null, m[0]));
      last = m.index + m[0].length;
    }
    if (last < text.length) node.appendChild(document.createTextNode(text.slice(last)));
  }

  // ------------------------------------------------------------------- init

  renderDocs();
  boot();
})();
