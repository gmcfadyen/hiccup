'use strict';
/**
 * hiccup — i18n.js  (UI chrome only: en / fr / es / de)
 *
 * Loaded by a BLOCKING <script> in every page's <head>, immediately after the
 * tiny inline snippet that picks the language and pulls in /i18n/<lang>.js.
 * Same shape as theme.js's FOUC-safe inline chooser, and for the same reason:
 * `_t()` has to exist before app.js's first render, and the catalogue has to be
 * present before `_t()` is first called. An async/fetch load would race both.
 *
 * Lookup is keyed by a hash of the ENGLISH SOURCE STRING, never by a
 * hand-written key name. That is the whole safety argument: edit the English
 * and the key changes, the lookup misses, and the UI shows the NEW English
 * instead of a stale translation of the old one. `_t()` takes the English text
 * as its argument, so a miss returns that argument — rendering blank is
 * structurally impossible, not merely unlikely.
 *
 * DELIBERATELY OUT OF SCOPE: the domain corpus in lib/advisor.js, lib/detect.js,
 * lib/hmr.js and lib/isup.js. Those are hand-authored diagnostic instructions
 * executed against production SBCs (a dropped negation turns a caution into an
 * instruction) and normative ITU-T terminology. They stay English. See
 * docs/i18n-plan.md §4 and §6.2.
 *
 * This file is also require()d by lib/i18n.js and bin/i18n-*.js so that Node and
 * the browser share ONE hash implementation. Two copies could drift by a single
 * whitespace rule and silently turn every lookup into a fallback-to-English,
 * which looks like "translation just stopped working" and nothing would report it.
 */
(function () {
  var LANGS = ['en', 'fr', 'es', 'de'];

  /** Display names, each written in its own language — never translated. */
  var LANG_NAMES = { en: 'English', fr: 'Français', es: 'Español', de: 'Deutsch' };

  var STORAGE_KEY = 'hiccup-lang';

  /**
   * Canonical form of a source string before hashing: trim the ends, collapse
   * every internal whitespace run to one space. HTML text nodes carry the
   * source file's indentation and line wrapping, so without this the same
   * visible sentence would hash differently after a re-indent.
   * @param {string} s
   * @returns {string}
   */
  function normalise(s) {
    return String(s == null ? '' : s).replace(/\s+/g, ' ').trim();
  }

  /**
   * FNV-1a (64-bit, split into two 32-bit halves so it survives JS's 53-bit
   * integer precision) over the UTF-8 bytes of the normalised source, rendered
   * as 16 hex chars.
   *
   * Why not sha1 as docs/i18n-plan.md §2.1 suggested: the browser has no
   * SYNCHRONOUS sha1 (crypto.subtle is async and secure-context only), and
   * `_t()` must be synchronous. The alternatives were a hand-rolled SHA-1 in
   * the client or a second hash that could drift from Node's. This is an
   * addressing function, not a security primitive — and bin/i18n-extract.js
   * hard-fails on any collision across the whole catalogue, so the residual
   * birthday risk at ~1k strings is checked, not assumed.
   * @param {string} s English source text
   * @returns {string} 16 lowercase hex chars
   */
  var _hashCache = {};

  function hashKey(s) {
    var str = normalise(s);
    var cached = Object.prototype.hasOwnProperty.call(_hashCache, str) ? _hashCache[str] : null;
    if (cached) return cached;

    // offset basis 14695981039346656037 = 0xcbf29ce4_84222325, held as two
    // unsigned 32-bit halves because JS integers are exact only to 2^53.
    var h1 = 0xcbf29ce4, h0 = 0x84222325;
    var bytes = utf8Bytes(str);
    for (var b = 0; b < bytes.length; b++) {
      h0 = (h0 ^ bytes[b]) >>> 0;
      // × the FNV prime 1099511628211 = 0x100_000001b3, in 16-bit limbs.
      var lo0 = h0 & 0xffff, lo1 = h0 >>> 16;
      var p0 = lo0 * 0x1b3;
      var p1 = lo1 * 0x1b3;
      var mid = (p0 >>> 16) + (p1 & 0xffff);
      var newLow = (((mid & 0xffff) << 16) | (p0 & 0xffff)) >>> 0;
      var newHigh = ((mid >>> 16) + (p1 >>> 16) + (h1 * 0x1b3) + (h0 * 0x100)) >>> 0;
      h0 = newLow;
      h1 = newHigh;
    }
    var out = ('00000000' + h1.toString(16)).slice(-8) +
      ('00000000' + h0.toString(16)).slice(-8);
    _hashCache[str] = out;
    return out;
  }

  /**
   * UTF-8 bytes of a JS string. Hand-rolled so Node and the browser hash the
   * same octets without depending on Buffer or TextEncoder.
   * @param {string} str
   * @returns {number[]}
   */
  function utf8Bytes(str) {
    var out = [];
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (c < 0x80) {
        out.push(c);
      } else if (c < 0x800) {
        out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
      } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length &&
                 str.charCodeAt(i + 1) >= 0xdc00 && str.charCodeAt(i + 1) <= 0xdfff) {
        var cp = 0x10000 + ((c - 0xd800) << 10) + (str.charCodeAt(i + 1) - 0xdc00);
        i++;
        out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f),
          0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
      } else {
        out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
      }
    }
    return out;
  }

  /**
   * Substitute {0}, {1}, … from the extra arguments. Only used by the handful
   * of call sites where the sentence's word order genuinely differs between
   * languages; most interpolation in this codebase is prefix + value + suffix
   * and is translated as separate fragments instead.
   * @param {string} s
   * @param {IArrayLike<*>} args arguments object, index 0 being the source text
   * @returns {string}
   */
  function format(s, args) {
    return s.replace(/\{(\d+)\}/g, function (whole, n) {
      var v = args[Number(n) + 1];
      return v === undefined ? whole : String(v);
    });
  }

  var api = {
    LANGS: LANGS,
    LANG_NAMES: LANG_NAMES,
    STORAGE_KEY: STORAGE_KEY,
    normalise: normalise,
    hash: hashKey,
  };

  // Node side (lib/i18n.js, bin/i18n-extract.js, bin/i18n-build.js) stops here:
  // everything below needs a document.
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
    return;
  }

  // ---------------------------------------------------------------- browser

  var cat = (typeof window !== 'undefined' && window.HICCUP_I18N) || null;
  var LANG = (cat && cat.lang) || 'en';
  var STRINGS = (cat && cat.strings) || {};
  var DEBUG = typeof location !== 'undefined' && /(^|[?&])i18ndebug(=|&|$)/.test(location.search);
  var missing = [];

  /**
   * Translate one English source string.
   *
   * Leading and trailing whitespace of the argument is preserved around the
   * translated core, because a lot of call sites are concatenation fragments
   * (`n + _t(' calls')`) where dropping the space would run words together.
   *
   * @param {string} en English source text — also the fallback when unmatched
   * @param {...*} params values for {0}, {1}, … placeholders
   * @returns {string} the translation, or `en` unchanged when there is none
   */
  function _t(en) {
    if (typeof en !== 'string' || en === '') return en;
    if (LANG === 'en') return arguments.length > 1 ? format(en, arguments) : en;
    var m = /^(\s*)([\s\S]*?)(\s*)$/.exec(en);
    var core = m[2];
    if (!core) return en;
    var hit = STRINGS[hashKey(core)];
    var out;
    if (typeof hit === 'string' && hit !== '') {
      out = m[1] + hit + m[3];
    } else {
      out = en; // the English argument IS the fallback — never blank
      if (DEBUG && missing.indexOf(core) === -1) missing.push(core);
    }
    return arguments.length > 1 ? format(out, arguments) : out;
  }

  /**
   * One-shot DOM pass over [data-i18n] / [data-i18n-attrs].
   *
   * `data-i18n` carries no key: the element's own English text IS the key, so
   * the markup stays readable and a missed translation leaves the node exactly
   * as authored. Only DIRECT child text nodes are touched, so an element that
   * mixes text with child elements (`<p>foo <a>bar</a> baz</p>`) keeps its
   * children instead of being flattened by a textContent assignment.
   *
   * Idempotent: re-running translates already-translated text, misses, and
   * returns it unchanged.
   *
   * @param {ParentNode} [root] defaults to document
   */
  function apply(root) {
    var scope = root || document;
    var els = scope.querySelectorAll('[data-i18n], [data-i18n-attrs]');
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      if (el.hasAttribute('data-i18n')) {
        for (var n = el.firstChild; n; n = n.nextSibling) {
          if (n.nodeType === 3 && /\S/.test(n.nodeValue)) n.nodeValue = _t(n.nodeValue);
        }
      }
      var attrs = el.getAttribute('data-i18n-attrs');
      if (attrs) {
        var list = attrs.split(',');
        for (var a = 0; a < list.length; a++) {
          var name = list[a].trim();
          if (!name) continue;
          var v = el.getAttribute(name);
          if (v) el.setAttribute(name, _t(v));
        }
      }
    }
    var title = scope === document && document.querySelector('title[data-i18n]');
    if (title && document.title) document.title = _t(document.title);
  }

  /**
   * Drop a <select id="lang-select"> into the topbar of every page that has
   * one. Built here rather than repeated in nine HTML files so the option list
   * cannot drift between pages; the empty <span data-lang-switcher> in the
   * markup is only a placement anchor.
   */
  function mountSwitcher() {
    var hosts = document.querySelectorAll('[data-lang-switcher]');
    for (var h = 0; h < hosts.length; h++) {
      var host = hosts[h];
      if (host.firstChild) continue;
      var sel = document.createElement('select');
      // Only the first switcher on a page may own the contract id.
      if (h === 0) sel.id = 'lang-select';
      sel.className = 'input lang-select';
      sel.setAttribute('aria-label', _t('Language'));
      sel.setAttribute('title', _t('Language'));
      for (var i = 0; i < LANGS.length; i++) {
        var o = document.createElement('option');
        o.value = LANGS[i];
        o.textContent = LANG_NAMES[LANGS[i]];
        if (LANGS[i] === LANG) o.selected = true;
        sel.appendChild(o);
      }
      sel.addEventListener('change', function (e) {
        set(e.target.value);
      });
      host.appendChild(sel);
    }
  }

  /**
   * Persist a language choice and reload.
   *
   * A reload rather than a live re-render on purpose: app.js rebuilds most of
   * its panes from JS at runtime, so re-rendering in place would mean auditing
   * every render path for re-entrancy. A reload is free here and guarantees
   * every surface is consistent.
   * @param {string} lang one of LANGS
   */
  function set(lang) {
    if (LANGS.indexOf(lang) === -1) return;
    try { localStorage.setItem(STORAGE_KEY, lang); } catch (e) { /* private mode */ }
    location.reload();
  }

  function ready() {
    apply(document);
    mountSwitcher();
    if (DEBUG && missing.length) {
      // Behind ?i18ndebug only: client JS is otherwise console-silent by design.
      console.warn('hiccup i18n: ' + missing.length + ' untranslated string(s) for "' +
        LANG + '"\n' + missing.join('\n'));
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', ready);
  } else {
    ready();
  }

  window._t = _t;
  api.t = _t;
  api.apply = apply;
  api.set = set;
  api.lang = LANG;
  api.missing = function () { return missing.slice(); };
  window.HiccupI18n = api;
})();
