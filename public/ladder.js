/*
 * hiccup — ladder.js
 * Pure SVG ladder-diagram builder for the Workbench layout. No fetch, no app
 * state; the only global is window.Ladder. Consumed by app.js.
 *
 * Contract (ARCHITECTURE.md §UI — the Workbench layout):
 *   Ladder.render({messages, legs, collapses, media, aux, findings, advice,
 *                  onSelect, collapsed}) -> SVGElement
 *
 * Colouring is layered on purpose:
 *   - every element carries the `.lad-*` classes app.css styles, so in-app the
 *     palette, hover and selection rules come from the stylesheet;
 *   - the same colours are ALSO written as SVG *presentation attributes* (which
 *     lose to any CSS rule), so an exported standalone SVG still carries the
 *     frozen contract map:
 *       request --accent · 1xx --notice · 2xx #3fb950 · 3xx #a371f7 ·
 *       4xx/5xx/6xx --crit · H.323 #d2a8ff · media #39c5cf dashed ·
 *       aux (DNS/Diameter/STUN) #8b949e dotted
 *
 * Security: every label/host/summary goes in through textContent. Capture-derived
 * text is attacker-controlled and never touches innerHTML.
 */
(function () {
  'use strict';

  var SVGNS = 'http://www.w3.org/2000/svg';

  // Geometry (base units; `zoom` scales the rendered box, never the row model).
  var TOP = 46;        // host header band — app.css's .tg-spacer matches this
  var ROWH = 26;       // one message row — app.css's .tg-row matches this
  var COLW = 158;      // host column spacing
  var PADL = 14;       // left pad before the first column
  var PADR = 60;       // right pad after the last column
  var MAXCOLS = 8;     // host columns before overflow grouping

  // ------------------------------------------------------------------ helpers

  function arr(v) { return Array.isArray(v) ? v : []; }

  function num(v) { return (typeof v === 'number' && isFinite(v)) ? v : null; }

  function str(v) { return v == null ? '' : String(v); }

  /** Create an SVG element with attributes (null/undefined values skipped). */
  function svgEl(tag, attrs) {
    var e = document.createElementNS(SVGNS, tag);
    if (attrs) {
      for (var k in attrs) {
        if (Object.prototype.hasOwnProperty.call(attrs, k) && attrs[k] != null) {
          e.setAttribute(k, String(attrs[k]));
        }
      }
    }
    return e;
  }

  /** SVG <text> helper — textContent only, never markup. */
  function svgText(x, y, text, cls, anchor) {
    var t = svgEl('text', { x: x, y: y, 'text-anchor': anchor || 'start' });
    if (cls) t.setAttribute('class', cls);
    t.textContent = str(text);
    return t;
  }

  /** Attach an SVG <title> (native tooltip) using textContent. */
  function addTitle(node, text) {
    if (!text) return;
    var t = svgEl('title');
    t.textContent = str(text);
    node.appendChild(t);
  }

  function htmlEl(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }

  function hostKey(ip, port) {
    var p = (port == null || port === '') ? '' : ':' + port;
    return str(ip == null ? '?' : ip) + p;
  }

  /** epoch-seconds float -> HH:MM:SS.mmm local time ('' when unknown). */
  function fmtClock(ts) {
    var t = num(ts);
    if (t == null) return '';
    var d = new Date(t * 1000);
    if (isNaN(d.getTime())) return '';
    function p2(n) { return (n < 10 ? '0' : '') + n; }
    var ms = Math.floor((t - Math.floor(t)) * 1000);
    var p3 = (ms < 10 ? '00' : ms < 100 ? '0' : '') + ms;
    return p2(d.getHours()) + ':' + p2(d.getMinutes()) + ':' + p2(d.getSeconds()) + '.' + p3;
  }

  /** Middle-ellipsis truncation. */
  function truncate(s, max) {
    s = str(s);
    if (s.length <= max) return s;
    if (max <= 1) return s.slice(0, max);
    var half = Math.floor((max - 1) / 2);
    return s.slice(0, half) + '…' + s.slice(-(max - 1 - half));
  }

  var FALLBACK = {
    bg: '#0e1116', text: '#dce3ea', muted: '#8b949e', border: '#2f3947',
    accent: '#f5a623', notice: '#58a6ff', crit: '#f2545b', warn: '#f5a623',
    ok: '#3fb950', redirect: '#a371f7', h323: '#d2a8ff', media: '#39c5cf'
  };

  /**
   * Resolve the design-system palette to literal colours so the presentation
   * attributes (and therefore an exported SVG) match the running theme.
   */
  function palette() {
    var out = {
      req: FALLBACK.accent,
      '1xx': FALLBACK.notice,
      '2xx': FALLBACK.ok,
      redir: FALLBACK.redirect,
      '4xx': FALLBACK.crit,
      '5xx': FALLBACK.crit,
      '6xx': FALLBACK.crit,
      h323: FALLBACK.h323,
      media: FALLBACK.media,
      aux: FALLBACK.muted,
      bg: FALLBACK.bg, text: FALLBACK.text, muted: FALLBACK.muted,
      border: FALLBACK.border, panel2: '#1d242e',
      warn: FALLBACK.warn, crit: FALLBACK.crit
    };
    try {
      var cs = window.getComputedStyle(document.documentElement);
      if (!cs) return out;
      function v(name, fb) {
        var s = cs.getPropertyValue(name);
        s = s && s.trim();
        return s || fb;
      }
      out.req = v('--accent', out.req);
      out['1xx'] = v('--notice', out['1xx']);
      out['2xx'] = v('--ok', out['2xx']);
      out.redir = v('--redirect', out.redir);
      out['4xx'] = out['5xx'] = out['6xx'] = v('--crit', out['4xx']);
      out.h323 = v('--h323', out.h323);
      out.media = v('--media-ink', out.media);
      out.aux = v('--aux-ink', out.aux);
      out.bg = v('--bg', out.bg);
      out.text = v('--text', out.text);
      out.muted = v('--muted', out.muted);
      out.border = v('--border-strong', out.border);
      out.panel2 = v('--panel2', out.panel2);
      out.warn = v('--warn', out.warn);
      out.crit = v('--crit', out.crit);
    } catch (e) { /* non-DOM or odd host — fall back */ }
    return out;
  }

  var SEV_RANK = { crit: 0, warn: 1, notice: 2, info: 3 };

  function worseSev(a, b) {
    var ra = SEV_RANK[a] == null ? 9 : SEV_RANK[a];
    var rb = SEV_RANK[b] == null ? 9 : SEV_RANK[b];
    return ra <= rb ? a : b;
  }

  // ------------------------------------------------------------- row model

  /**
   * Colour/class key for a signalling message:
   * req / 1xx / 2xx / redir / 4xx / 5xx / 6xx / h323.
   */
  function msgColorKey(m) {
    if (!m) return 'req';
    if (m.protocol === 'h323' || m.q931Type) return 'h323';
    if (m.isRequest) return 'req';
    var s = num(m.status);
    if (s == null) return 'req';
    if (s < 200) return '1xx';
    if (s < 300) return '2xx';
    if (s < 400) return 'redir';
    if (s < 500) return '4xx';
    if (s < 600) return '5xx';
    return '6xx';
  }

  /** Short arrow label: SIP method / status+reason, H.323 q931Type. */
  function msgLabel(m) {
    if (!m) return '?';
    if (m.protocol === 'h323' || m.q931Type) return str(m.q931Type || 'H.323');
    if (m.isRequest) return str(m.method || '?');
    var s = m.status == null ? '?' : String(m.status);
    if (m.reason) s += ' ' + m.reason;
    return truncate(s, 30);
  }

  /** Longer row description used by #selection-list. */
  function msgDesc(m) {
    if (!m) return '?';
    if (m.protocol === 'h323' || m.q931Type) {
      var h = str(m.q931Type || 'H.323');
      if (m.causeCode != null) h += ' (cause ' + m.causeCode + (m.causeText ? ' ' + m.causeText : '') + ')';
      return h;
    }
    if (m.isRequest) {
      var r = str(m.method || '?');
      if (m.requestUri) r += ' ' + truncate(m.requestUri, 46);
      return r;
    }
    return (m.status == null ? '?' : String(m.status)) + (m.reason ? ' ' + m.reason : '');
  }

  /** Media stream row label (RTP/SRTP/T.38). */
  function mediaLabel(s) {
    if (!s) return 'media';
    var kind = str(s.kind || 'rtp').toUpperCase();
    if (kind === 'T38-UDPTL') kind = 'T.38';
    var bits = [kind];
    if (s.codec && s.codec !== 'unknown') bits.push(str(s.codec));
    var pk = num(s.packets);
    if (pk != null) bits.push(pk + ' pkts');
    return bits.join(' ');
  }

  function mediaDesc(s) {
    var d = mediaLabel(s);
    if (!s) return d;
    var extra = [];
    var loss = num(s.lossPct);
    if (loss != null) extra.push(loss.toFixed(2) + '% loss');
    var jit = num(s.meanJitterMs);
    if (jit != null) extra.push(jit.toFixed(1) + 'ms jitter');
    if (s.oneWay) extra.push('one-way');
    return extra.length ? d + ' · ' + extra.join(' · ') : d;
  }

  function auxLabel(x) {
    if (!x) return 'aux';
    var proto = str(x.protocol || 'aux').toUpperCase();
    var s = str(x.summary || '');
    return s ? truncate(proto + ' ' + s, 44) : proto;
  }

  function auxDesc(x) {
    if (!x) return 'aux';
    var proto = str(x.protocol || 'aux').toUpperCase();
    return proto + (x.summary ? ' ' + str(x.summary) : '');
  }

  /**
   * Build the severity/advice overlay: message id -> {sev, findingTitle, adviceTitle}.
   * Only warn/crit drive the ladder's error highlighting, but every severity is
   * recorded so the selection list can tint consistently.
   */
  function buildSeverityMap(findings, advice) {
    var out = {};
    var fById = {};
    var i, j, ids, f;
    for (i = 0; i < findings.length; i++) {
      f = findings[i];
      if (!f) continue;
      if (f.id) fById[f.id] = f;
      ids = arr(f.msgIds);
      for (j = 0; j < ids.length; j++) {
        var id = ids[j];
        if (!id) continue;
        var cur = out[id] || (out[id] = { sev: null, findingTitle: null, adviceTitle: null });
        var next = worseSev(f.severity, cur.sev);
        if (cur.sev == null || next !== cur.sev) {
          cur.sev = next;
          if (next === f.severity) cur.findingTitle = str(f.title || '') || cur.findingTitle;
        }
        if (!cur.findingTitle) cur.findingTitle = str(f.title || '') || null;
      }
    }
    for (i = 0; i < advice.length; i++) {
      var a = advice[i];
      if (!a) continue;
      var fids = arr(a.findingIds);
      for (j = 0; j < fids.length; j++) {
        var fin = fById[fids[j]];
        if (!fin) continue;
        var mids = arr(fin.msgIds);
        for (var k = 0; k < mids.length; k++) {
          var e = out[mids[k]] || (out[mids[k]] = {
            sev: fin.severity || null,
            findingTitle: str(fin.title || '') || null,
            adviceTitle: null
          });
          if (!e.adviceTitle) e.adviceTitle = str(a.title || '') || null;
        }
      }
    }
    return out;
  }

  /**
   * Build the unified, ts-ordered row model shared by the ladder, the time
   * gutter and #selection-list. Exported so app.js renders exactly the same
   * rows in every pane (cross-highlighting depends on it).
   *
   * @param {Object} opts see render()
   * @returns {{rows:Array, collapsedCount:number, severity:Object, inCollapse:Object}}
   */
  function buildRows(opts) {
    opts = opts || {};
    var messages = arr(opts.messages);
    var collapses = arr(opts.collapses);
    var mediaIn = opts.media;
    var streams = Array.isArray(mediaIn)
      ? mediaIn
      : (mediaIn && Array.isArray(mediaIn.streams) ? mediaIn.streams : []);
    var auxes = arr(opts.aux);
    var findings = arr(opts.findings);
    var advice = arr(opts.advice);
    var collapsed = opts.collapsed !== false;

    var severity = buildSeverityMap(findings, advice);

    // Retransmission collapse bookkeeping: the first message of a collapse
    // carries the ×N badge; the rest are folded away unless expanded.
    var badge = {};
    var hidden = {};
    var inCollapse = {};
    var ci, col, ids, hi;
    for (ci = 0; ci < collapses.length; ci++) {
      col = collapses[ci];
      if (!col) continue;
      ids = arr(col.msgIds);
      for (hi = 0; hi < ids.length; hi++) inCollapse[ids[hi]] = col;
      if (ids.length < 2) continue;
      badge[ids[0]] = col;
      if (collapsed) { for (hi = 1; hi < ids.length; hi++) hidden[ids[hi]] = true; }
    }

    var rows = [];
    var collapsedCount = 0;
    var i;

    for (i = 0; i < messages.length; i++) {
      var m = messages[i];
      if (!m || !m.id) continue;
      if (hidden[m.id]) { collapsedCount++; continue; }
      var col2 = badge[m.id] || null;
      var sev = severity[m.id] || null;
      rows.push({
        rowId: m.id,
        kind: 'msg',
        id: m.id,
        ts: num(m.ts),
        src: m.src, sport: m.sport, dst: m.dst, dport: m.dport,
        colorKey: msgColorKey(m),
        proto: (m.protocol === 'h323' || m.q931Type) ? 'h323' : 'sip',
        label: msgLabel(m),
        desc: msgDesc(m),
        retransCount: col2 ? (num(col2.count) || arr(col2.msgIds).length) : 0,
        collapse: col2,
        isRetrans: !!m.retransOf,
        sev: sev ? sev.sev : null,
        findingTitle: sev ? sev.findingTitle : null,
        adviceTitle: sev ? sev.adviceTitle : null,
        legId: null,          // filled by app.js (it owns the leg index)
        obj: m
      });
    }

    for (i = 0; i < streams.length; i++) {
      var s = streams[i];
      if (!s || typeof s !== 'object') continue;
      rows.push({
        rowId: str(s.id || ('rs?' + i)),
        kind: 'media',
        id: str(s.id || ('rs?' + i)),
        ts: num(s.firstTs),
        src: s.src, sport: s.sport, dst: s.dst, dport: s.dport,
        colorKey: 'media',
        proto: 'rtp',
        label: mediaLabel(s),
        desc: mediaDesc(s),
        retransCount: 0, collapse: null, isRetrans: false,
        sev: null, findingTitle: null, adviceTitle: null,
        legId: arr(s.legIds)[0] || null,
        obj: s
      });
    }

    for (i = 0; i < auxes.length; i++) {
      var x = auxes[i];
      if (!x || typeof x !== 'object') continue;
      rows.push({
        rowId: str(x.id || ('x?' + i)),
        kind: 'aux',
        id: str(x.id || ('x?' + i)),
        ts: num(x.ts),
        src: x.src, sport: x.sport, dst: x.dst, dport: x.dport,
        colorKey: 'aux',
        proto: str(x.protocol || 'aux'),
        label: auxLabel(x),
        desc: auxDesc(x),
        retransCount: 0, collapse: null, isRetrans: false,
        sev: null, findingTitle: null, adviceTitle: null,
        legId: arr(x.legIds)[0] || null,
        obj: x
      });
    }

    // Stable ts sort; rows with no timestamp keep their arrival order at the end.
    for (i = 0; i < rows.length; i++) rows[i]._i = i;
    rows.sort(function (a, b) {
      if (a.ts == null && b.ts == null) return a._i - b._i;
      if (a.ts == null) return 1;
      if (b.ts == null) return -1;
      if (a.ts === b.ts) return a._i - b._i;
      return a.ts - b.ts;
    });

    // Delta ms since the previous row — the column engineers actually read.
    var prev = null;
    for (i = 0; i < rows.length; i++) {
      rows[i].n = i + 1;
      rows[i].deltaMs = (rows[i].ts == null || prev == null)
        ? null
        : Math.round((rows[i].ts - prev) * 1000);
      if (rows[i].ts != null) prev = rows[i].ts;
      delete rows[i]._i;
    }

    return { rows: rows, collapsedCount: collapsedCount, severity: severity, inCollapse: inCollapse };
  }

  // ------------------------------------------------------------- columns

  /**
   * Decide the host:port columns. Max ~8; overflow hosts are grouped into a
   * single 'others' column at the far right.
   */
  function computeColumns(rows, legs, hosts) {
    var order = [];
    var seen = {};
    function add(k) {
      if (!k || k === '?') return;
      if (!seen[k]) { seen[k] = true; order.push(k); }
    }
    var i;
    if (Array.isArray(hosts)) { for (i = 0; i < hosts.length; i++) add(str(hosts[i])); }
    // Prefer the ordering implied by the legs (ingress first) so the SBC's two
    // legs land side by side.
    var ls = arr(legs);
    for (i = 0; i < ls.length; i++) {
      if (!ls[i]) continue;
      add(hostKey(ls[i].src, ls[i].sport));
      add(hostKey(ls[i].dst, ls[i].dport));
    }
    for (i = 0; i < rows.length; i++) {
      add(hostKey(rows[i].src, rows[i].sport));
      add(hostKey(rows[i].dst, rows[i].dport));
    }
    // Drop preferred hosts that never appear in these rows.
    var used = {};
    for (i = 0; i < rows.length; i++) {
      used[hostKey(rows[i].src, rows[i].sport)] = true;
      used[hostKey(rows[i].dst, rows[i].dport)] = true;
    }
    var live = [];
    for (i = 0; i < order.length; i++) { if (used[order[i]]) live.push(order[i]); }
    if (!live.length) live = order.slice(0, 1);

    var cols = live;
    var others = null;
    if (live.length > MAXCOLS) {
      cols = live.slice(0, MAXCOLS - 1).concat(['others']);
      others = {};
      var extra = live.slice(MAXCOLS - 1);
      for (var x = 0; x < extra.length; x++) others[extra[x]] = true;
    }
    var index = {};
    for (var c = 0; c < cols.length; c++) index[cols[c]] = c;
    return { cols: cols, index: index, others: others };
  }

  function colKeyFor(ip, port, layout) {
    var k = hostKey(ip, port);
    if (layout.others && layout.others[k]) return 'others';
    if (layout.index[k] == null) return layout.cols[0];
    return k;
  }

  // ------------------------------------------------------------- rendering

  /**
   * Render the ladder for a selection.
   *
   * @param {Object} opts
   * @param {Array}  opts.messages    SipMessage|H323Message objects
   * @param {Array}  [opts.legs]      Leg objects (drive the column ordering)
   * @param {Array}  [opts.collapses] retrans collapses ({id,msgIds,count,...})
   * @param {Array|{streams:Array}} [opts.media]  MediaStream[] (dashed rows)
   * @param {Array}  [opts.aux]       AuxMessage[] (dotted rows)
   * @param {Array}  [opts.findings]  Finding[] — warn/crit drive error highlighting
   * @param {Array}  [opts.advice]    Advice[] — supplies the error tooltip title
   * @param {Function} [opts.onSelect] called with (rowId, row) on click
   * @param {boolean}  [opts.collapsed=true] true → one bold row + ×N badge
   * @param {Array<string>} [opts.hosts]      preferred 'ip:port' column order
   * @param {string|null}   [opts.selectedId] row id to mark selected
   * @param {Object}        [opts.matchIds]   {rowId:true} search matches to ring
   * @param {Function}      [opts.onHover]    called with (rowId|null) on hover
   * @param {number}        [opts.zoom=1]     rendered scale (row model unchanged)
   * @param {Array}         [opts.rows]       pre-built rows from buildRows()
   * @returns {SVGElement} with `.ladderRows` and `.ladderGeom` attached
   */
  function render(opts) {
    opts = opts || {};
    var built = Array.isArray(opts.rows) ? { rows: opts.rows } : buildRows(opts);
    var rows = arr(built.rows);
    var onSelect = (typeof opts.onSelect === 'function') ? opts.onSelect : null;
    var onHover = (typeof opts.onHover === 'function') ? opts.onHover : null;
    var selectedId = opts.selectedId || null;
    var matchIds = opts.matchIds || null;
    var zoom = num(opts.zoom);
    if (zoom == null || zoom <= 0) zoom = 1;
    zoom = Math.max(0.4, Math.min(3, zoom));
    var C = palette();

    var layout = computeColumns(rows, opts.legs, opts.hosts);
    var ncols = Math.max(1, layout.cols.length);
    var width = PADL + ncols * COLW + PADR;
    var height = rows.length ? (TOP + rows.length * ROWH + 14) : (TOP + 44);

    var svg = svgEl('svg', {
      xmlns: SVGNS,
      width: Math.round(width * zoom),
      height: Math.round(height * zoom),
      viewBox: '0 0 ' + width + ' ' + height,
      'class': 'ladder-svg',
      'data-zoom': zoom,
      'font-family': 'ui-monospace, Consolas, monospace',
      role: 'img',
      'aria-label': 'ladder diagram, ' + rows.length + ' rows'
    });

    // Opaque background so an exported SVG is readable outside the app.
    svg.appendChild(svgEl('rect', {
      x: 0, y: 0, width: width, height: height, fill: C.bg, 'class': 'lad-bg'
    }));

    function colX(key) {
      var idx = layout.index[key];
      if (idx == null) idx = 0;
      return PADL + idx * COLW + COLW / 2;
    }

    // Host headers + lifelines.
    for (var k = 0; k < layout.cols.length; k++) {
      var key = layout.cols[k];
      var hx = colX(key);
      var label = key, full = key;
      if (key === 'others' && layout.others) {
        var n = 0, names = [];
        for (var ok in layout.others) {
          if (Object.prototype.hasOwnProperty.call(layout.others, ok) && layout.others[ok]) {
            n++; names.push(ok);
          }
        }
        label = 'others (' + n + ')';
        full = names.join(', ');
      }
      var ht = svgText(hx, 16, truncate(label, 21), 'lad-host', 'middle');
      ht.setAttribute('fill', C.text);
      ht.setAttribute('font-size', '11');
      ht.setAttribute('font-weight', '600');
      addTitle(ht, full);
      svg.appendChild(ht);

      svg.appendChild(svgEl('line', {
        x1: hx, y1: TOP - 10, x2: hx, y2: height - 6, 'class': 'lad-lifeline',
        stroke: C.border, 'stroke-width': 1, 'stroke-dasharray': '2 4'
      }));
    }

    if (!rows.length) {
      var empty = svgText(PADL + 4, TOP + 18, 'Nothing to draw for this selection.', 'lad-empty');
      empty.setAttribute('fill', C.muted);
      empty.setAttribute('font-size', '12');
      svg.appendChild(empty);
      svg.ladderRows = rows;
      svg.ladderGeom = { top: TOP, rowH: ROWH, width: width, height: height, zoom: zoom, cols: layout.cols };
      return svg;
    }

    for (var r = 0; r < rows.length; r++) {
      var row = rows[r];
      var y = TOP + r * ROWH + ROWH / 2;
      var ink = C[row.colorKey] || C.req;
      var isErrorRow = row.sev === 'crit' || row.sev === 'warn';
      var srcKey = colKeyFor(row.src, row.sport, layout);
      var dstKey = colKeyFor(row.dst, row.dport, layout);
      var x1 = colX(srcKey);
      var x2 = colX(dstKey);

      // Class vocabulary app.css styles: .lad-msg + .lad-<key>, .has-warn/.has-crit,
      // .lad-retrans, .lad-selected/.is-selected, .is-cross (toggled by app.js).
      var cls = 'lad-msg lad-row lad-' + row.colorKey + ' lad-kind-' + row.kind;
      if (row.retransCount > 1) cls += ' lad-retrans';
      if (row.isRetrans) cls += ' lad-retrans-dup';
      if (isErrorRow) cls += ' has-' + row.sev;
      if (row.rowId === selectedId) cls += ' lad-selected is-selected';
      if (matchIds && matchIds[row.rowId]) cls += ' lad-match';

      var g = svgEl('g', { 'class': cls });
      g.setAttribute('data-row-id', row.rowId);
      g.setAttribute('data-kind', row.kind);
      if (row.kind === 'msg') g.setAttribute('data-msg-id', row.id);

      // Selection / search backdrops.
      if (row.rowId === selectedId) {
        g.appendChild(svgEl('rect', {
          x: 2, y: y - ROWH / 2 + 1, width: width - 4, height: ROWH - 2, rx: 4,
          'class': 'lad-selrect', fill: 'rgba(245,166,35,0.14)',
          stroke: 'rgba(245,166,35,0.5)', 'stroke-width': 1
        }));
      } else if (matchIds && matchIds[row.rowId]) {
        g.appendChild(svgEl('rect', {
          x: 2, y: y - ROWH / 2 + 1, width: width - 4, height: ROWH - 2, rx: 4,
          'class': 'lad-matchrect', fill: 'rgba(88,166,255,0.12)'
        }));
      }

      var labelStr = row.label;
      var midX, labelAnchor = 'middle';
      var dash = row.kind === 'media' ? '6 3' : (row.kind === 'aux' ? '1 4' : null);
      // Retransmissions are collapsed silently: same stroke weight as any
      // normal row. Only a genuine finding (has-warn/has-crit, an actual
      // protocol fault) earns the heavier stroke — being a retransmission
      // is not itself an alert.
      var strokeW = isErrorRow ? (row.sev === 'crit' ? 3.4 : 3) : 1.6;

      if (srcKey === dstKey) {
        // Self-loop (both ends in the same column, e.g. folded into 'others').
        var lx = x1;
        g.appendChild(svgEl('path', {
          d: 'M ' + lx + ' ' + (y - 5) + ' h 30 a 5 5 0 0 1 5 5 a 5 5 0 0 1 -5 5 h -22',
          'class': 'lad-line', fill: 'none', stroke: ink, 'stroke-width': strokeW,
          'stroke-dasharray': dash
        }));
        g.appendChild(svgEl('polygon', {
          points: (lx + 8) + ',' + (y + 5) + ' ' + (lx + 16) + ',' + (y + 1) + ' ' + (lx + 16) + ',' + (y + 9),
          'class': 'lad-head', fill: ink
        }));
        midX = lx + 44;
        labelAnchor = 'start';
      } else {
        g.appendChild(svgEl('line', {
          x1: x1, y1: y, x2: x2, y2: y, 'class': 'lad-hit',
          stroke: 'transparent', 'stroke-width': 16
        }));
        g.appendChild(svgEl('line', {
          x1: x1, y1: y, x2: x2, y2: y, 'class': 'lad-line',
          stroke: ink, 'stroke-width': strokeW, 'stroke-dasharray': dash, fill: 'none'
        }));
        var dir = x2 > x1 ? 1 : -1;
        g.appendChild(svgEl('polygon', {
          points: x2 + ',' + y + ' ' + (x2 - dir * 9) + ',' + (y - 4) + ' ' + (x2 - dir * 9) + ',' + (y + 4),
          'class': 'lad-head', fill: ink
        }));
        midX = (x1 + x2) / 2;
      }

      var labelEl = svgText(midX, y - 5, labelStr, 'lad-label', labelAnchor);
      labelEl.setAttribute('fill', ink);
      labelEl.setAttribute('font-size', '10.5');
      if (row.sev === 'crit') labelEl.setAttribute('font-weight', '700');
      g.appendChild(labelEl);

      var approxLabelW = String(labelStr).length * 6.2;
      var badgeX = labelAnchor === 'middle' ? midX + approxLabelW / 2 + 6 : midX + approxLabelW + 6;

      // A collapsed retransmission burst gets a quiet ×N note, not an alert:
      // no border, no pill, no warn colour -- muted text, same visual weight
      // as any other secondary label. The full detail is one hover away.
      if (row.retransCount > 1) {
        var badgeStr = '×' + row.retransCount;
        var bt = svgText(badgeX, y - 5, badgeStr, 'lad-badge', 'start');
        bt.setAttribute('fill', C.muted);
        bt.setAttribute('font-size', '9.5');
        g.appendChild(bt);
        addTitle(g, (row.collapse && row.collapse.label)
          ? row.collapse.label
          : (badgeStr + ' retransmissions'));
        badgeX += bw + 6;
      }

      // Error highlighting: severity dot + tooltip carrying the advice title.
      if (isErrorRow) {
        var dot = svgEl('circle', {
          cx: badgeX + 5, cy: y - 9, r: 4, 'class': 'lad-sevdot',
          fill: row.sev === 'crit' ? C.crit : C.warn
        });
        g.appendChild(dot);
        var tip = row.adviceTitle || row.findingTitle || (row.sev + ' finding on this message');
        addTitle(dot, tip);
        if (!g.querySelector('title')) addTitle(g, tip);
      }

      if (onSelect) {
        g.setAttribute('tabindex', '0');
        (function (rw) {
          g.addEventListener('click', function () { onSelect(rw.rowId, rw); });
          g.addEventListener('keydown', function (ev) {
            if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); onSelect(rw.rowId, rw); }
          });
        })(row);
      }
      if (onHover) {
        (function (rw) {
          g.addEventListener('mouseenter', function () { onHover(rw.rowId); });
          g.addEventListener('mouseleave', function () { onHover(null); });
        })(row);
      }

      svg.appendChild(g);
    }

    svg.ladderRows = rows;
    svg.ladderGeom = { top: TOP, rowH: ROWH, width: width, height: height, zoom: zoom, cols: layout.cols };
    return svg;
  }

  /**
   * Build the #time-gutter contents: a .tg-spacer matching the ladder's host
   * header band, then one .tg-row (.tg-ts + .tg-delta) per ladder row at the
   * same row height — so it lines up without any layout CSS of our own.
   *
   * @param {Array} rows rows from buildRows()/render()
   * @param {number} [zoom=1] must match the ladder's zoom
   * @param {string|null} [selectedId] row id to mark .is-selected
   * @returns {DocumentFragment}
   */
  function timeGutter(rows, zoom, selectedId) {
    rows = arr(rows);
    var z = num(zoom);
    if (z == null || z <= 0) z = 1;
    z = Math.max(0.4, Math.min(3, z));
    var frag = document.createDocumentFragment();

    var spacer = htmlEl('div', 'tg-spacer');
    if (z !== 1) spacer.style.height = (TOP * z) + 'px';
    spacer.setAttribute('aria-hidden', 'true');
    frag.appendChild(spacer);

    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      var cls = 'tg-row';
      if (selectedId && row.rowId === selectedId) cls += ' is-selected';
      var line = htmlEl('div', cls);
      line.setAttribute('data-row-id', str(row.rowId));
      if (z !== 1) line.style.height = (ROWH * z) + 'px';

      line.appendChild(htmlEl('span', 'tg-ts', fmtClock(row.ts) || '—'));

      var dcls = 'tg-delta';
      if (row.deltaMs != null && row.deltaMs >= 4000) dcls += ' is-stalled';
      else if (row.deltaMs != null && row.deltaMs >= 500) dcls += ' is-slow';
      line.appendChild(htmlEl('span', dcls, row.deltaMs == null ? '—' : ('+' + row.deltaMs)));

      frag.appendChild(line);
    }
    return frag;
  }

  /**
   * Serialize a rendered ladder to a standalone SVG document string. The
   * presentation attributes carry the colours, so the file needs no stylesheet.
   * @param {SVGElement} svg
   * @returns {string} '' when serialization is unavailable
   */
  function toSvgString(svg) {
    try {
      if (!svg) return '';
      var clone = svg.cloneNode(true);
      clone.setAttribute('xmlns', SVGNS);
      clone.setAttribute('xmlns:xlink', 'http://www.w3.org/1999/xlink');
      var s = new XMLSerializer().serializeToString(clone);
      return '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n' + s;
    } catch (e) {
      return '';
    }
  }

  /**
   * @namespace window.Ladder
   * Pure SVG ladder rendering (no fetch, no app state).
   * `render` is the frozen contract entry point; `buildRows`, `timeGutter` and
   * `toSvgString` are the helpers app.js shares with the other panes.
   */
  window.Ladder = {
    render: render,
    buildRows: buildRows,
    timeGutter: timeGutter,
    toSvgString: toSvgString,
    fmtClock: fmtClock,
    palette: palette,
    ROW_HEIGHT: ROWH,
    HEADER_HEIGHT: TOP
  };
})();
