/*
 * hiccup — ladder.js
 * Pure SVG ladder-diagram builder. No fetch, no app state; the only global is
 * window.Ladder. Consumed by app.js for the whole-capture Ladder tab and the
 * per-call Flow panel.
 *
 * Styling contract: every element carries classes (lad-*) that app.css colors
 * using the hiccup.css design-system variables.
 */
(function () {
  'use strict';

  var SVGNS = 'http://www.w3.org/2000/svg';

  /** Create an SVG element with attributes. */
  function svgEl(tag, attrs) {
    var e = document.createElementNS(SVGNS, tag);
    if (attrs) {
      for (var k in attrs) {
        if (Object.prototype.hasOwnProperty.call(attrs, k)) {
          e.setAttribute(k, String(attrs[k]));
        }
      }
    }
    return e;
  }

  /** SVG text node helper (textContent only — never markup). */
  function svgText(x, y, str, cls, anchor) {
    var t = svgEl('text', { x: x, y: y, 'text-anchor': anchor || 'start' });
    if (cls) t.setAttribute('class', cls);
    t.textContent = str;
    return t;
  }

  function hostKey(ip, port) { return String(ip) + ':' + String(port); }

  /** Format an epoch-seconds float as HH:MM:SS.mmm local time. */
  function fmtClock(ts) {
    if (ts == null || !isFinite(ts)) return '';
    var d = new Date(ts * 1000);
    function p2(n) { return (n < 10 ? '0' : '') + n; }
    var ms = Math.floor((ts % 1) * 1000);
    var p3 = (ms < 10 ? '00' : ms < 100 ? '0' : '') + ms;
    return p2(d.getHours()) + ':' + p2(d.getMinutes()) + ':' + p2(d.getSeconds()) + '.' + p3;
  }

  function truncate(s, max) {
    s = String(s);
    if (s.length <= max) return s;
    var half = Math.floor((max - 1) / 2);
    return s.slice(0, half) + '…' + s.slice(-(max - 1 - half));
  }

  /**
   * Decide the host:port columns. Max 8 columns; overflow hosts are grouped
   * into a single 'others' column at the far right.
   * @param {Array} messages
   * @param {Array<string>|undefined} hosts optional preferred 'ip:port' order
   * @returns {{cols:string[], index:Map<string,number>, others:Set<string>|null}}
   */
  function computeColumns(messages, hosts) {
    var MAX = 8;
    var order = [];
    var seen = {};
    function add(k) { if (!seen[k]) { seen[k] = true; order.push(k); } }
    if (Array.isArray(hosts)) {
      for (var i = 0; i < hosts.length; i++) add(hosts[i]);
    }
    for (var j = 0; j < messages.length; j++) {
      var m = messages[j];
      add(hostKey(m.src, m.sport));
      add(hostKey(m.dst, m.dport));
    }
    var cols = order;
    var others = null;
    if (order.length > MAX) {
      cols = order.slice(0, MAX - 1).concat(['others']);
      others = {};
      var extra = order.slice(MAX - 1);
      for (var x = 0; x < extra.length; x++) others[extra[x]] = true;
    }
    var index = {};
    for (var c = 0; c < cols.length; c++) index[cols[c]] = c;
    return { cols: cols, index: index, others: others };
  }

  /** Column key for one end of a message (folds overflow hosts into 'others'). */
  function colKeyFor(ip, port, layout) {
    var k = hostKey(ip, port);
    if (layout.others && layout.others[k]) return 'others';
    return k;
  }

  /** CSS class for a message arrow: request / 1xx / 2xx / 3xx+ / h323. */
  function msgClass(m) {
    if (m.protocol === 'h323') return 'lad-h323';
    if (m.isRequest) return 'lad-req';
    if (m.status != null && m.status < 200) return 'lad-1xx';
    if (m.status != null && m.status < 300) return 'lad-2xx';
    return 'lad-3xx';
  }

  /** Short arrow label: SIP method / status+reason, H.323 q931Type. */
  function msgLabel(m) {
    if (m.protocol === 'h323') return m.q931Type || 'H.323';
    if (m.isRequest) return m.method || '?';
    var s = String(m.status == null ? '?' : m.status);
    if (m.reason) s += ' ' + m.reason;
    if (s.length > 26) s = s.slice(0, 25) + '…';
    return s;
  }

  /**
   * Render a ladder diagram.
   *
   * @param {Object} opts
   * @param {Array}  opts.messages   SipMessage|H323Message objects, ts order
   * @param {Array}  [opts.legs]     Leg objects (currently informational)
   * @param {Array}  [opts.collapses]  retrans collapses ({id,msgIds,count,...})
   * @param {Array<string>} [opts.hosts]  preferred 'ip:port' column order
   * @param {Function} [opts.onSelect]   called with (msgId) on arrow click
   * @param {boolean}  [opts.expandRetrans=false]  true → show every retransmission
   *                   as its own row; false → one bold arrow with an ×N badge
   * @param {string|null} [opts.selectedId]  message id to highlight
   * @returns {SVGElement}
   */
  function render(opts) {
    var messages = (opts && opts.messages) || [];
    var collapses = (opts && opts.collapses) || [];
    var onSelect = (opts && typeof opts.onSelect === 'function') ? opts.onSelect : null;
    var expand = !!(opts && opts.expandRetrans);
    var selectedId = (opts && opts.selectedId) || null;

    // Retransmission collapse bookkeeping: first msg of a collapse gets the
    // badge; the rest are hidden unless expanded.
    var badge = {};   // firstMsgId -> collapse
    var hidden = {};  // msgId -> true (collapsed away)
    if (!expand) {
      for (var ci = 0; ci < collapses.length; ci++) {
        var col = collapses[ci];
        var ids = col.msgIds || [];
        if (ids.length < 2) continue;
        badge[ids[0]] = col;
        for (var hi = 1; hi < ids.length; hi++) hidden[ids[hi]] = true;
      }
    }

    var rows = [];
    for (var mi = 0; mi < messages.length; mi++) {
      if (!hidden[messages[mi].id]) rows.push(messages[mi]);
    }

    var layout = computeColumns(rows, opts && opts.hosts);

    // Geometry.
    var GUTTER = 96;      // timestamp gutter
    var COLW = 158;       // column spacing
    var TOP = 46;         // host header band
    var ROWH = 26;
    var PADR = 60;
    var width = GUTTER + Math.max(1, layout.cols.length) * COLW + PADR;
    var height = TOP + rows.length * ROWH + 16;
    if (!rows.length) height = TOP + 40;

    var svg = svgEl('svg', {
      xmlns: SVGNS,
      width: width,
      height: height,
      viewBox: '0 0 ' + width + ' ' + height,
      'class': 'ladder-svg',
      role: 'img'
    });

    function colX(key) {
      var idx = layout.index[key];
      if (idx == null) idx = 0;
      return GUTTER + idx * COLW + COLW / 2;
    }

    // Host headers + lifelines.
    for (var k = 0; k < layout.cols.length; k++) {
      var key = layout.cols[k];
      var x = colX(key);
      var label = key;
      if (key === 'others' && layout.others) {
        var n = 0;
        for (var ok in layout.others) { if (layout.others[ok]) n++; }
        label = 'others (' + n + ')';
      }
      svg.appendChild(svgText(x, 16, truncate(label, 20), 'lad-host', 'middle'));
      svg.appendChild(svgEl('line', {
        x1: x, y1: TOP - 8, x2: x, y2: height - 6, 'class': 'lad-lifeline'
      }));
    }

    if (!rows.length) {
      svg.appendChild(svgText(GUTTER + 8, TOP + 16, 'No messages to display.', 'lad-empty'));
      return svg;
    }

    // Arrows, one row per (visible) message. Equal spacing — time is non-linear;
    // the gutter carries the real timestamps.
    for (var r = 0; r < rows.length; r++) {
      var m = rows[r];
      var y = TOP + r * ROWH + ROWH / 2;
      var cls = msgClass(m);
      var collapse = badge[m.id] || null;
      var srcKey = colKeyFor(m.src, m.sport, layout);
      var dstKey = colKeyFor(m.dst, m.dport, layout);
      var x1 = colX(srcKey);
      var x2 = colX(dstKey);

      var g = svgEl('g', { 'class': 'lad-msg ' + cls + (collapse ? ' lad-retrans' : '') + (m.id === selectedId ? ' lad-selected' : '') });
      g.setAttribute('data-msg-id', m.id);

      // Selection backdrop.
      if (m.id === selectedId) {
        g.appendChild(svgEl('rect', {
          x: 2, y: y - ROWH / 2 + 1, width: width - 4, height: ROWH - 2,
          'class': 'lad-selrect', rx: 4
        }));
      }

      // Timestamp gutter.
      svg.appendChild(svgText(GUTTER - 10, y + 4, fmtClock(m.ts), 'lad-ts', 'end'));

      var labelStr = msgLabel(m);
      var midX, labelAnchor = 'middle';

      if (srcKey === dstKey) {
        // Self-loop (both ends folded into the same column, e.g. 'others').
        var lx = x1;
        var p = svgEl('path', {
          d: 'M ' + lx + ' ' + (y - 5) + ' h 30 a 5 5 0 0 1 5 5 a 5 5 0 0 1 -5 5 h -22',
          'class': 'lad-line', fill: 'none'
        });
        g.appendChild(p);
        g.appendChild(svgEl('polygon', {
          points: (lx + 8) + ',' + (y + 5) + ' ' + (lx + 16) + ',' + (y + 1) + ' ' + (lx + 16) + ',' + (y + 9),
          'class': 'lad-head'
        }));
        midX = lx + 44;
        labelAnchor = 'start';
      } else {
        // Wide invisible hit area for easier clicking.
        g.appendChild(svgEl('line', {
          x1: x1, y1: y, x2: x2, y2: y, 'class': 'lad-hit'
        }));
        g.appendChild(svgEl('line', {
          x1: x1, y1: y, x2: x2, y2: y, 'class': 'lad-line'
        }));
        var dir = x2 > x1 ? 1 : -1;
        g.appendChild(svgEl('polygon', {
          points: x2 + ',' + y + ' ' + (x2 - dir * 9) + ',' + (y - 4) + ' ' + (x2 - dir * 9) + ',' + (y + 4),
          'class': 'lad-head'
        }));
        midX = (x1 + x2) / 2;
      }

      var labelEl = svgText(midX, y - 5, labelStr, 'lad-label', labelAnchor);
      g.appendChild(labelEl);

      // ×N badge on collapsed retransmissions.
      if (collapse) {
        var badgeStr = '×' + (collapse.count || collapse.msgIds.length);
        var approxLabelW = labelStr.length * 6.4;
        var bx = labelAnchor === 'middle' ? midX + approxLabelW / 2 + 6 : midX + approxLabelW + 6;
        var bw = badgeStr.length * 7 + 10;
        g.appendChild(svgEl('rect', {
          x: bx, y: y - 16, width: bw, height: 14, rx: 7, 'class': 'lad-badge-bg'
        }));
        g.appendChild(svgText(bx + bw / 2, y - 5, badgeStr, 'lad-badge', 'middle'));
      }

      if (onSelect) {
        (function (id) {
          g.addEventListener('click', function () { onSelect(id); });
        })(m.id);
        g.setAttribute('tabindex', '0');
      }

      svg.appendChild(g);
    }

    return svg;
  }

  /** @namespace window.Ladder — pure SVG ladder rendering (no fetch, no app state). */
  window.Ladder = { render: render };
})();
