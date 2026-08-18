'use strict';
/**
 * hiccup — theme.js
 *
 * Wires up any [data-theme-toggle] button on the page. The actual FOUC-safe
 * application of a stored choice happens earlier, in a tiny inline <script>
 * at the top of each page's <head> (before hiccup.css is even requested) --
 * this file only handles the click behaviour and keeping the button's icon
 * in sync afterwards. See ARCHITECTURE.md / hiccup.css's top comment for the
 * three-state model (system / explicit light / explicit dark).
 */
(function () {
  // public/i18n.js publishes window._t from a blocking <head> script. The local
  // alias keeps this file working — in English — if that script is ever missing,
  // rather than throwing a ReferenceError out of every render.
  var _t = (window && window._t) || function (s) { return s; };
  var STORAGE_KEY = 'hiccup-theme';
  var root = document.documentElement;

  function systemPrefersLight() {
    return !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches);
  }

  /** Effective theme right now: explicit attribute, else system preference. */
  function effective() {
    var explicit = root.getAttribute('data-theme');
    if (explicit === 'light' || explicit === 'dark') return explicit;
    return systemPrefersLight() ? 'light' : 'dark';
  }

  function apply(theme) {
    if (theme === 'light' || theme === 'dark') {
      root.setAttribute('data-theme', theme);
      try { localStorage.setItem(STORAGE_KEY, theme); } catch (e) { /* private mode etc. */ }
    } else {
      root.removeAttribute('data-theme');
      try { localStorage.removeItem(STORAGE_KEY); } catch (e) { /* private mode etc. */ }
    }
    sync();
  }

  function toggle() {
    apply(effective() === 'light' ? 'dark' : 'light');
  }

  function sync() {
    var isLight = effective() === 'light';
    var btns = document.querySelectorAll('[data-theme-toggle]');
    for (var i = 0; i < btns.length; i++) {
      var b = btns[i];
      b.setAttribute('aria-label', isLight ? _t('Switch to dark theme') : _t('Switch to light theme'));
      b.setAttribute('title', isLight ? _t('Switch to dark theme') : _t('Switch to light theme'));
      b.textContent = isLight ? '☾' : '☀'; // crescent moon / sun -- shows what you'd switch TO
    }
  }

  document.addEventListener('click', function (e) {
    var t = e.target.closest && e.target.closest('[data-theme-toggle]');
    if (t) toggle();
  });

  if (window.matchMedia) {
    var mq = window.matchMedia('(prefers-color-scheme: light)');
    var onChange = function () { if (!root.getAttribute('data-theme')) sync(); };
    if (mq.addEventListener) mq.addEventListener('change', onChange);
    else if (mq.addListener) mq.addListener(onChange); // older Safari/Firefox
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', sync);
  } else {
    sync();
  }

  window.HiccupTheme = { get: effective, set: apply, toggle: toggle };
})();
