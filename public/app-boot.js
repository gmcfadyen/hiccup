/* hiccup - app-boot.js (lifted from app.html so the site can run under a CSP with no 'unsafe-inline'). */
/*
 * Layout chrome only — pane resizing and info-tab switching. No data, no fetch,
 * no app state: app.js owns everything that fills a pane. Both behaviours are
 * additive and idempotent; if app.js binds its own tab handling the result is the
 * same (hidden + .is-active + aria-selected all move together).
 */
(function () {
  'use strict';

  var layout = document.getElementById('layout');
  if (!layout) return;

  // ---------------------------------------------------------------- resizers

  var STORE = 'hiccup.layout.v1';
  var MIN_COL = 190, MAX_COL = 640;

  function readNum(v, fallback) {
    var n = parseFloat(v);
    return isFinite(n) ? n : fallback;
  }

  function cssVar(name, fallback) {
    return readNum(getComputedStyle(layout).getPropertyValue(name), fallback);
  }

  function persist() {
    try {
      localStorage.setItem(STORE, JSON.stringify({
        left: layout.style.getPropertyValue('--w-left'),
        top: layout.style.getPropertyValue('--r-top'),
        bot: layout.style.getPropertyValue('--r-bot')
      }));
    } catch (e) { /* private mode / quota — layout just won't persist */ }
  }

  try {
    var saved = JSON.parse(localStorage.getItem(STORE) || 'null');
    if (saved) {
      if (saved.left) layout.style.setProperty('--w-left', saved.left);
      if (saved.top) layout.style.setProperty('--r-top', saved.top);
      if (saved.bot) layout.style.setProperty('--r-bot', saved.bot);
    }
  } catch (e) { /* ignore malformed storage */ }

  function setLeft(px) {
    px = Math.max(MIN_COL, Math.min(MAX_COL, px));
    layout.style.setProperty('--w-left', px.toFixed(0) + 'px');
  }

  function setRows(topPx, botPx) {
    if (topPx < 120 || botPx < 120) return;
    layout.style.setProperty('--r-top', topPx.toFixed(0) + 'fr');
    layout.style.setProperty('--r-bot', botPx.toFixed(0) + 'fr');
  }

  function rowSizes() {
    var top = document.getElementById('ladder-pane');
    var bot = document.getElementById('info-pane');
    return {
      top: top ? top.getBoundingClientRect().height : 0,
      bot: bot ? bot.getBoundingClientRect().height : 0
    };
  }

  function startDrag(handle, ev) {
    var vertical = handle.classList.contains('rz-col');
    var startX = ev.clientX, startY = ev.clientY;
    var startLeft = cssVar('--w-left', 288);
    var rows = rowSizes();
    handle.classList.add('is-dragging');
    document.body.classList.add('is-resizing');

    function move(e) {
      if (vertical) setLeft(startLeft + (e.clientX - startX));
      else {
        var d = e.clientY - startY;
        setRows(rows.top + d, rows.bot - d);
      }
    }
    function up() {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
      window.removeEventListener('pointercancel', up);
      handle.classList.remove('is-dragging');
      document.body.classList.remove('is-resizing');
      persist();
    }
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
    window.addEventListener('pointercancel', up);
    ev.preventDefault();
  }

  var handles = layout.querySelectorAll('.rz');
  for (var i = 0; i < handles.length; i++) {
    (function (handle) {
      handle.addEventListener('pointerdown', function (e) { startDrag(handle, e); });
      handle.addEventListener('dblclick', function () {
        layout.style.removeProperty(handle.classList.contains('rz-col') ? '--w-left' : '--r-top');
        if (!handle.classList.contains('rz-col')) layout.style.removeProperty('--r-bot');
        persist();
      });
      handle.addEventListener('keydown', function (e) {
        var vertical = handle.classList.contains('rz-col');
        var rows = rowSizes();
        if (vertical && (e.key === 'ArrowLeft' || e.key === 'ArrowRight')) {
          setLeft(cssVar('--w-left', 288) + (e.key === 'ArrowLeft' ? -16 : 16));
        } else if (!vertical && (e.key === 'ArrowUp' || e.key === 'ArrowDown')) {
          var d = e.key === 'ArrowUp' ? -24 : 24;
          setRows(rows.top + d, rows.bot - d);
        } else {
          return;
        }
        e.preventDefault();
        persist();
      });
    })(handles[i]);
  }

  // -------------------------------------------------------------- info tabs

  var tabsHost = document.getElementById('info-tabs');
  if (!tabsHost) return;
  var tabs = tabsHost.querySelectorAll('.info-tab');

  function selectTab(tab) {
    for (var t = 0; t < tabs.length; t++) {
      var on = tabs[t] === tab;
      tabs[t].classList.toggle('is-active', on);
      tabs[t].setAttribute('aria-selected', on ? 'true' : 'false');
      var panel = document.getElementById(tabs[t].getAttribute('data-panel') || '');
      if (panel) {
        panel.hidden = !on;
        panel.classList.toggle('is-active', on);
      }
    }
  }

  for (var k = 0; k < tabs.length; k++) {
    (function (tab) {
      tab.addEventListener('click', function () { selectTab(tab); });
      tab.addEventListener('keydown', function (e) {
        if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
        var idx = Array.prototype.indexOf.call(tabs, tab);
        var next = tabs[(idx + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
        if (next) { selectTab(next); next.focus(); }
        e.preventDefault();
      });
    })(tabs[k]);
  }

  // Wave 4: #scenario-chip no longer switches an info tab — app.js opens and
  // focuses the drawer's advice section instead. Nothing to wire here.
})();
