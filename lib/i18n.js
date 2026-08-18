// lib/i18n.js — UI-chrome translation catalogue: extraction, build, audit, schedule.
// Zero dependencies. The hash and the normalisation rules are NOT defined here:
// they are require()d from public/i18n.js so the browser and Node share exactly
// one implementation (see that file's header for why that matters).
'use strict';

const fs = require('fs');
const path = require('path');
const store = require('./store');
const shared = require('../public/i18n.js');

const ROOT = path.join(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const LOCALES_DIR = path.join(ROOT, 'locales');
const CATALOGUE_DIR = path.join(PUBLIC_DIR, 'i18n');

const LANGS = shared.LANGS;                    // en fr es de
const TARGET_LANGS = LANGS.filter((l) => l !== 'en');
const LANG_NAMES = shared.LANG_NAMES;

/**
 * Files scanned for translatable UI chrome.
 *
 * lib/advisor.js, lib/detect.js, lib/hmr.js and lib/isup.js are absent ON
 * PURPOSE and must stay absent: that is ~82% of the product's text, it is
 * hand-authored diagnostic instruction executed against production SBCs, and
 * advisor.js's own header guarantees every word of it is deterministic and
 * never machine-produced. docs/i18n-plan.md §4 / §6.2.
 */
const SERVER_FILES = ['server.js'];

/** Never enter the catalogue: brand and product names are the same in every language. */
const SKIP = [
  'hiccup', 'hiccup.monster', 'RFPlex.ai', 'rfplex.ai', 'ask hiccup',
  'Buy Me a Coffee', '☕ Buy Me a Coffee', 'HMR', 'SIP', 'H.323', 'SDP', 'RTP',
];

// ---------------------------------------------------------------- primitives

/** @param {string} s @returns {string} whitespace-collapsed, trimmed source text */
function normalise(s) { return shared.normalise(s); }

/** @param {string} s @returns {string} 16-hex catalogue key for an English source string */
function hash(s) { return shared.hash(s); }

/**
 * Is this string worth a catalogue entry? Filters the identifiers, CSS class
 * lists and selectors that share a lexical form with prose.
 * @param {string} s
 * @returns {boolean}
 */
function translatable(s) {
  const v = normalise(s);
  if (!v) return false;
  if (SKIP.indexOf(v) !== -1) return false;
  if (!/[A-Za-z]/.test(v)) return false;                 // pure punctuation / digits
  if (/^https?:\/\//.test(v) || /^mailto:/.test(v)) return false;
  return true;
}

// ------------------------------------------------------------- HTML scanning

const VOID_TAGS = {
  area: 1, base: 1, br: 1, col: 1, embed: 1, hr: 1, img: 1, input: 1,
  link: 1, meta: 1, param: 1, source: 1, track: 1, wbr: 1,
};

/**
 * Parse one start tag's attributes.
 * @param {string} body the text between the tag name and the closing `>`
 * @returns {Object<string,string>}
 */
function parseAttrs(body) {
  const attrs = {};
  const re = /([A-Za-z_:][-A-Za-z0-9_:.]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
  let m;
  while ((m = re.exec(body)) !== null) {
    const v = m[2] !== undefined ? m[2] : (m[3] !== undefined ? m[3] : (m[4] !== undefined ? m[4] : ''));
    attrs[m[1].toLowerCase()] = v;
  }
  return attrs;
}

/**
 * Extract every translatable unit from one HTML page.
 *
 * Mirrors public/i18n.js's DOM pass exactly — `data-i18n` means "each DIRECT
 * child text node of this element", `data-i18n-attrs="a,b"` means "the values
 * of these attributes". If the two ever disagree the catalogue fills up with
 * keys nothing looks up, so they are deliberately written to the same rule.
 *
 * @param {string} src the file contents
 * @param {string} file path used in the `where` trail
 * @returns {{text: string, where: string}[]}
 */
function scanHtml(src, file) {
  const out = [];
  const stack = [];                 // { name, i18n }
  let i = 0;
  const n = src.length;
  let line = 1;

  const push = (text, ln) => {
    if (translatable(text)) out.push({ text: normalise(text), where: file + ':' + ln });
  };

  while (i < n) {
    const lt = src.indexOf('<', i);
    if (lt === -1) break;
    if (lt > i) {
      const text = src.slice(i, lt);
      const top = stack[stack.length - 1];
      if (top && top.i18n) push(text, line);
      line += (text.match(/\n/g) || []).length;
    }
    if (src.startsWith('<!--', lt)) {
      const end = src.indexOf('-->', lt + 4);
      const chunk = src.slice(lt, end === -1 ? n : end + 3);
      line += (chunk.match(/\n/g) || []).length;
      i = end === -1 ? n : end + 3;
      continue;
    }
    if (src.startsWith('<!', lt)) {                       // doctype
      const end = src.indexOf('>', lt);
      i = end === -1 ? n : end + 1;
      continue;
    }
    if (src.startsWith('</', lt)) {
      const end = src.indexOf('>', lt);
      const name = src.slice(lt + 2, end === -1 ? n : end).trim().toLowerCase();
      for (let s = stack.length - 1; s >= 0; s--) {
        if (stack[s].name === name) { stack.length = s; break; }
      }
      i = end === -1 ? n : end + 1;
      continue;
    }
    const end = src.indexOf('>', lt);
    if (end === -1) break;
    const raw = src.slice(lt + 1, end);
    const tagLine = line;
    line += (raw.match(/\n/g) || []).length;
    const nameMatch = /^([A-Za-z][-A-Za-z0-9]*)/.exec(raw);
    i = end + 1;
    if (!nameMatch) continue;
    const name = nameMatch[1].toLowerCase();
    const attrs = parseAttrs(raw.slice(nameMatch[1].length));

    if (attrs['data-i18n-attrs']) {
      for (const a of attrs['data-i18n-attrs'].split(',')) {
        const key = a.trim().toLowerCase();
        if (key && attrs[key]) push(attrs[key], tagLine);
      }
    }

    // <script>/<style> hold raw text, never markup or prose.
    if (name === 'script' || name === 'style') {
      const closeRe = new RegExp('</' + name + '\\s*>', 'i');
      const rest = src.slice(i);
      const cm = closeRe.exec(rest);
      const chunk = cm ? rest.slice(0, cm.index + cm[0].length) : rest;
      line += (chunk.match(/\n/g) || []).length;
      i += chunk.length;
      continue;
    }
    if (VOID_TAGS[name] || /\/\s*$/.test(raw)) continue;
    stack.push({ name, i18n: Object.prototype.hasOwnProperty.call(attrs, 'data-i18n') });
  }
  return out;
}

// --------------------------------------------------------------- JS scanning

/**
 * Split JS source into string literals, tracking comments and regex literals
 * so a `/` inside `a / b` is not mistaken for the start of a regex (which
 * would swallow the rest of the file and lose every literal after it).
 * @param {string} src
 * @returns {{start: number, end: number, quote: string, raw: string, line: number}[]}
 */
function jsLiterals(src) {
  const out = [];
  const n = src.length;
  let i = 0;
  let line = 1;
  let prev = '';                    // last significant char, for regex-vs-divide
  while (i < n) {
    const c = src[i];
    if (c === '\n') { line++; i++; continue; }
    if (c === ' ' || c === '\t' || c === '\r') { i++; continue; }
    if (c === '/' && src[i + 1] === '/') { while (i < n && src[i] !== '\n') i++; continue; }
    if (c === '/' && src[i + 1] === '*') {
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) { if (src[i] === '\n') line++; i++; }
      i += 2;
      continue;
    }
    if (c === '/' && !/[A-Za-z0-9_$)\]]/.test(prev)) {    // regex literal
      i++;
      let cls = false;
      while (i < n) {
        if (src[i] === '\\') { i += 2; continue; }
        if (src[i] === '[') cls = true;
        else if (src[i] === ']') cls = false;
        else if (src[i] === '/' && !cls) { i++; break; }
        else if (src[i] === '\n') break;
        i++;
      }
      prev = '/';
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      const start = i;
      const startLine = line;
      i++;
      while (i < n) {
        if (src[i] === '\\') { i += 2; continue; }
        if (src[i] === c) break;
        if (src[i] === '\n') line++;
        i++;
      }
      i++;
      out.push({ start, end: i, quote: c, raw: src.slice(start + 1, i - 1), line: startLine });
      prev = c;
      continue;
    }
    prev = c;
    i++;
  }
  return out;
}

/** Turn a raw literal body back into its runtime value (escape sequences only). */
function unescapeLiteral(raw) {
  return raw.replace(/\\(u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|n|r|t|b|f|v|0|\\|'|"|`|\n)/g,
    (m, _all, uBrace, u4, x2) => {
      if (uBrace) return String.fromCodePoint(parseInt(uBrace, 16));
      if (u4) return String.fromCharCode(parseInt(u4, 16));
      if (x2) return String.fromCharCode(parseInt(x2, 16));
      const c = m[1];
      if (c === 'n') return '\n';
      if (c === 'r') return '\r';
      if (c === 't') return '\t';
      if (c === 'b') return '\b';
      if (c === 'f') return '\f';
      if (c === 'v') return '\v';
      if (c === '0') return '\0';
      if (c === '\n') return '';
      return c;
    });
}

/**
 * Every string literal that is the first argument of a `_t(...)` call.
 * `_t` rather than a bare `t` because app.js and ladder.js both use `t` as a
 * local variable name in dozens of places, where a global `t` would be shadowed.
 * @param {string} src
 * @param {string} file
 * @returns {{text: string, where: string}[]}
 */
function scanJs(src, file) {
  const out = [];
  for (const lit of jsLiterals(src)) {
    const before = src.slice(Math.max(0, lit.start - 3), lit.start);
    if (!/(^|[^A-Za-z0-9_$.])_t\($/.test(before)) continue;
    const text = unescapeLiteral(lit.raw);
    if (translatable(text)) out.push({ text: normalise(text), where: file + ':' + lit.line });
  }
  return out;
}

/**
 * Server-side error sentences that reach the browser.
 *
 * server.js sends `{ error: '<English sentence>' }` with no `code` field, so
 * rather than refactor 2,900 lines to add codes, the client runs the sentence
 * it received through `_t()`. Source-text keying makes that work with no server
 * change at all — the English sentence IS the key.
 * @param {string} src
 * @param {string} file
 * @returns {{text: string, where: string}[]}
 */
function scanServerErrors(src, file) {
  const out = [];
  for (const lit of jsLiterals(src)) {
    if (lit.quote === '`') continue;
    const before = src.slice(Math.max(0, lit.start - 12), lit.start);
    if (!/\berror:\s*$/.test(before)) continue;
    const text = unescapeLiteral(lit.raw);
    if (!/\s/.test(text)) continue;                       // 'not found' yes, 'x' no
    if (translatable(text)) out.push({ text: normalise(text), where: file + ':' + lit.line });
  }
  return out;
}

// ------------------------------------------------------------- the inventory

/** @param {string} p @returns {string} contents, or '' when the file is gone */
function read(p) {
  try { return fs.readFileSync(p, 'utf8'); } catch { return ''; }
}

/** @param {string} dir @param {RegExp} re @returns {string[]} sorted file names */
function listFiles(dir, re) {
  let names;
  try { names = fs.readdirSync(dir); } catch { return []; }
  return names.filter((f) => re.test(f)).sort();
}

/**
 * Scan the working tree and build the English inventory in memory.
 *
 * @returns {{strings: Object<string, {text: string, cat: string, where: string[]}>, order: string[]}}
 *   `strings` is hash → entry; `order` is the hashes in first-seen order so a
 *   regenerated locales/en.json has a stable, reviewable diff.
 */
function buildInventory() {
  const strings = Object.create(null);
  const order = [];
  const add = (unit, cat) => {
    const key = hash(unit.text);
    if (!strings[key]) {
      strings[key] = { text: unit.text, cat, where: [] };
      order.push(key);
    }
    if (strings[key].where.length < 6 && strings[key].where.indexOf(unit.where) === -1) {
      strings[key].where.push(unit.where);
    }
  };

  for (const f of listFiles(PUBLIC_DIR, /\.html$/)) {
    for (const u of scanHtml(read(path.join(PUBLIC_DIR, f)), 'public/' + f)) add(u, 'html');
  }
  for (const f of listFiles(PUBLIC_DIR, /\.js$/)) {
    for (const u of scanJs(read(path.join(PUBLIC_DIR, f)), 'public/' + f)) add(u, 'js');
  }
  for (const f of SERVER_FILES) {
    for (const u of scanServerErrors(read(path.join(ROOT, f)), f)) add(u, 'server');
  }
  return { strings, order };
}

/** @returns {{text: string, cat: string, where: string[]}[]} inventory entries, ordered */
function inventoryList(inv) {
  return inv.order.map((k) => Object.assign({ key: k }, inv.strings[k]));
}

/** @param {string} lang @returns {string} path of the hand-edited translation file */
function translationsFile(lang) { return path.join(LOCALES_DIR, lang + '.json'); }

/** @returns {string} path of the generated English inventory */
function inventoryFile() { return path.join(LOCALES_DIR, 'en.json'); }

/** @param {string} lang @returns {string} path of the browser catalogue */
function catalogueFile(lang) { return path.join(CATALOGUE_DIR, lang + '.js'); }

/**
 * Load one language's translations.
 *
 * Keyed by the ENGLISH SOURCE TEXT, not by the hash, because these are the only
 * files a human edits and a wall of hex is unreviewable. The hash is applied
 * when the browser catalogue is generated, so the safety property is identical:
 * change the English anywhere and the key it hashes to changes with it.
 * @param {string} lang
 * @returns {Object<string,string>}
 */
function loadTranslations(lang) {
  const data = store.loadJson(translationsFile(lang), null);
  return (data && typeof data === 'object' && !Array.isArray(data)) ? data : {};
}

/**
 * hash → translated text for one language, dropping empty and identical-to-
 * English entries (an entry equal to its source is what the fallback already
 * does, so shipping it only makes the catalogue bigger).
 * @param {string} lang
 * @param {object} [inv] inventory to restrict to; omit for "everything on file"
 * @returns {Object<string,string>}
 */
function buildCatalogue(lang, inv) {
  const tr = loadTranslations(lang);
  const out = {};
  for (const en of Object.keys(tr)) {
    const v = tr[en];
    if (typeof v !== 'string' || v === '' || v === en) continue;
    const key = hash(en);
    if (inv && !inv.strings[key]) continue;
    out[key] = v;
  }
  return out;
}

/**
 * Compare the live English inventory against one language's translations.
 * @param {string} lang
 * @param {object} inv result of buildInventory()
 * @returns {{lang: string, total: number, translated: number, missing: object[], orphans: string[]}}
 *   `missing` are English strings with no entry (the nightly job's work list);
 *   `orphans` are translations whose English source no longer exists anywhere.
 */
function auditLang(lang, inv) {
  const tr = loadTranslations(lang);
  const have = Object.create(null);
  for (const en of Object.keys(tr)) {
    if (typeof tr[en] === 'string' && tr[en] !== '') have[hash(en)] = true;
  }
  const missing = [];
  for (const key of inv.order) {
    if (!have[key]) missing.push({ key, text: inv.strings[key].text, where: inv.strings[key].where });
  }
  const orphans = [];
  for (const en of Object.keys(tr)) {
    if (!inv.strings[hash(en)]) orphans.push(en);
  }
  return {
    lang,
    total: inv.order.length,
    translated: inv.order.length - missing.length,
    missing,
    orphans,
  };
}

/**
 * Full audit across every target language.
 * @param {object} [inv] pre-built inventory; built fresh when omitted
 * @returns {object} report, ready to serialise
 */
function audit(inv) {
  const inventory = inv || buildInventory();
  const languages = {};
  for (const lang of TARGET_LANGS) languages[lang] = auditLang(lang, inventory);
  return {
    generatedAt: new Date().toISOString(),
    sourceStrings: inventory.order.length,
    languages,
  };
}

/**
 * One line per language, e.g. `fr: 812/812 translated, 0 missing, 0 orphaned`.
 * @param {object} report
 * @returns {string[]}
 */
function summaryLines(report) {
  return TARGET_LANGS.map((lang) => {
    const a = report.languages[lang];
    return lang + ': ' + a.translated + '/' + a.total + ' translated, ' +
      a.missing.length + ' missing, ' + a.orphans.length + ' orphaned';
  });
}

// ------------------------------------------------------- nightly refresh job

/** @param {string} dataDir @returns {string} */
function refreshStateFile(dataDir) { return path.join(dataDir, 'i18n-state.json'); }

/** @param {string} dataDir @returns {string} */
function reportFile(dataDir) { return path.join(dataDir, 'i18n-missing.json'); }

/** Local calendar day, `YYYY-MM-DD` — the unit the refresh dedupes on. */
function today(now) {
  const d = now || new Date();
  return d.getFullYear() + '-' +
    String(d.getMonth() + 1).padStart(2, '0') + '-' +
    String(d.getDate()).padStart(2, '0');
}

/** @param {string} dataDir @returns {object} */
function getRefreshState(dataDir) {
  const s = store.loadJson(refreshStateFile(dataDir), {});
  return (s && typeof s === 'object') ? s : {};
}

/**
 * Should the nightly refresh run right now?
 *
 * Phrased as "today's refresh has not happened yet" rather than "it is exactly
 * 00:00", copying lib/feedback.js's digestDue(). Same reason, and it is not a
 * style preference: this box reboots for Windows updates, so a setInterval(24h)
 * both drifts by the boot time on every restart and skips the day entirely if
 * the reboot straddles midnight. A day-stamped marker cannot drift and cannot
 * skip — the run simply happens at the first poll after the box is back.
 *
 * @param {string} dataDir
 * @param {Date} [now]
 * @returns {boolean}
 */
function refreshDue(dataDir, now) {
  return getRefreshState(dataDir).lastRunDay !== today(now);
}

/** @param {string} dataDir @param {string} day @param {object} summary */
function setRefreshed(dataDir, day, summary) {
  store.saveJson(refreshStateFile(dataDir), {
    lastRunDay: day,
    lastRunTs: Date.now(),
    lastSummary: summary,
  });
}

/**
 * The nightly job: re-scan the tree, find English strings whose hash has no
 * entry in a target catalogue, and RECORD them in `<dataDir>/i18n-missing.json`.
 *
 * It records rather than machine-translates. Translating unattended would mean
 * writing generated text into the repo with nobody reading it, and the same
 * argument that keeps lib/advisor.js out of scope applies in miniature to the
 * chrome: a wrong button label is cheap, a wrong confirmation dialog is not.
 * Until a string is translated by hand the UI shows English, which is correct
 * and obvious rather than confidently wrong.
 *
 * Writes only into dataDir — never into the repo. Regenerating locales/ and
 * public/i18n/ is a deploy step (`npm run i18n`), not something a long-running
 * service should do to its own source tree.
 *
 * @param {string} dataDir
 * @param {{force?: boolean, now?: Date}} [opts]
 * @returns {{ran: boolean, skipped?: string, day?: string, report?: object, lines?: string[]}}
 */
function refreshIfDue(dataDir, opts) {
  const o = opts || {};
  if (!o.force && !refreshDue(dataDir, o.now)) return { ran: false, skipped: 'already run today' };
  const report = audit();
  const day = today(o.now);
  const summary = {};
  for (const lang of TARGET_LANGS) {
    summary[lang] = {
      missing: report.languages[lang].missing.length,
      orphans: report.languages[lang].orphans.length,
    };
  }
  store.saveJson(reportFile(dataDir), report);
  setRefreshed(dataDir, day, summary);
  return { ran: true, day, report, lines: summaryLines(report) };
}

module.exports = {
  LANGS, TARGET_LANGS, LANG_NAMES, SKIP,
  LOCALES_DIR, CATALOGUE_DIR, PUBLIC_DIR,
  normalise, hash, translatable,
  scanHtml, scanJs, scanServerErrors, jsLiterals, unescapeLiteral,
  buildInventory, inventoryList, inventoryFile, translationsFile, catalogueFile,
  loadTranslations, buildCatalogue,
  auditLang, audit, summaryLines,
  today, refreshDue, refreshIfDue, setRefreshed, getRefreshState,
  refreshStateFile, reportFile,
};
