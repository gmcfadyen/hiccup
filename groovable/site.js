/* groovable.ai — the groove canvas and the theme toggle. No dependencies. */
(function () {
  'use strict';

  /* ---------- theme toggle ---------- */
  var root = document.documentElement;
  var btn = document.getElementById('theme-toggle');
  function effectiveTheme() {
    var t = root.getAttribute('data-theme');
    if (t === 'light' || t === 'dark') return t;
    return matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  if (btn) {
    btn.addEventListener('click', function () {
      var next = effectiveTheme() === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('groovable-theme', next); } catch (e) { /* fine */ }
    });
  }

  /* ---------- the groove ---------- */
  var c = document.getElementById('groove');
  if (!c) return;
  var ctx = c.getContext('2d');
  var reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  var TURNS = 7.2;
  /* nine machines: position along the spiral (in turns) and state */
  var NODES = [
    { t: 0.9, s: 'serving' }, { t: 1.6, s: 'idle' },    { t: 2.3, s: 'serving' },
    { t: 3.1, s: 'serving' }, { t: 3.8, s: 'owner' },   { t: 4.5, s: 'idle' },
    { t: 5.2, s: 'serving' }, { t: 5.9, s: 'idle' },    { t: 6.6, s: 'serving' }
  ];
  var W = 0, H = 0, tk = tokens();

  function tokens() {
    var cs = getComputedStyle(root);
    var v = function (n) { return cs.getPropertyValue(n).trim(); };
    return { line: v('--groove'), serving: v('--pool'), idle: v('--muted'), owner: v('--accent'), bg: v('--bg') };
  }
  function resize() {
    var r = c.getBoundingClientRect();
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = r.width; H = r.height;
    c.width = Math.round(W * dpr); c.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  function pos(turns) {
    var th = turns * 2 * Math.PI;
    var R = Math.min(W, H) / 2 - 16;
    var r = R * (turns / TURNS);
    return [W / 2 + r * Math.cos(th), H / 2 + r * Math.sin(th)];
  }
  function draw(now) {
    ctx.clearRect(0, 0, W, H);
    /* the groove */
    ctx.beginPath();
    var steps = 1500;
    for (var i = 0; i <= steps; i++) {
      var p = pos(TURNS * i / steps);
      if (i) ctx.lineTo(p[0], p[1]); else ctx.moveTo(p[0], p[1]);
    }
    ctx.strokeStyle = tk.line; ctx.lineWidth = 1.25; ctx.stroke();
    /* the machines */
    for (var k = 0; k < NODES.length; k++) {
      var n = NODES[k], q = pos(n.t);
      var col = n.s === 'serving' ? tk.serving : n.s === 'owner' ? tk.owner : tk.idle;
      if (n.s === 'serving' && !reduce) {
        var ph = ((now / 1600) + n.t) % 1;           /* each node on its own phase */
        ctx.beginPath(); ctx.arc(q[0], q[1], 6 + ph * 16, 0, Math.PI * 2);
        ctx.strokeStyle = col; ctx.lineWidth = 1.5; ctx.globalAlpha = 0.55 * (1 - ph); ctx.stroke();
        ctx.globalAlpha = 1;
      }
      ctx.beginPath(); ctx.arc(q[0], q[1], n.s === 'idle' ? 4 : 5.5, 0, Math.PI * 2);
      ctx.fillStyle = tk.bg; ctx.fill();
      ctx.lineWidth = 2; ctx.strokeStyle = col; ctx.stroke();
      if (n.s !== 'idle') { ctx.beginPath(); ctx.arc(q[0], q[1], 2.4, 0, Math.PI * 2); ctx.fillStyle = col; ctx.fill(); }
    }
    if (!reduce) requestAnimationFrame(draw);
  }

  resize(); draw(performance.now());
  window.addEventListener('resize', function () { resize(); if (reduce) draw(0); });
  new MutationObserver(function () { tk = tokens(); if (reduce) draw(0); })
    .observe(root, { attributes: true, attributeFilter: ['data-theme'] });
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () { tk = tokens(); if (reduce) draw(0); });
})();
