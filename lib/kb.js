'use strict';
/**
 * lib/kb.js — hiccup's config-guide knowledge base (ARCHITECTURE §Config-guide KB).
 *
 * Ingests vendor documentation (Acme/Oracle SCX guides, AudioCodes .ini refs,
 * Ribbon SMM notes, release notes, pasted CLI docs) so advisor.js can ground a
 * *reviewable draft* in a passage the user actually owns, and so /api/kb/search
 * can answer "what does this box call that parameter".
 *
 *  - Formats: .txt .md .html .htm .ini .cfg .conf .cli .log natively (HTML is
 *    tag-stripped, script/style dropped, common entities decoded). PDF through a
 *    LAZY `require('pdf-parse')` — absent module ⇒ a clean rejection carrying the
 *    contract's exact userMessage. Content is sniffed as well as the extension:
 *    a mislabelled file still works, and a non-PDF binary is refused politely.
 *  - Chunking: ~1200 chars with ~150 chars of overlap, cut on heading and
 *    paragraph boundaries (never mid-sentence unless one sentence is longer than
 *    a whole chunk), each chunk carrying its nearest preceding heading
 *    (markdown #/##, HTML h1–h3, `[ini-section]`, numbered `4.2 Title` or
 *    ALL-CAPS lines in plain text) and a page number when the source gives one
 *    (pdf-parse page breaks, or form feeds in text).
 *  - Retrieval: BM25 (k1=1.2, b=0.75) over tokenised chunks — lowercase folded,
 *    small stopword list, a modest boost when query terms hit the chunk heading.
 *    **No embeddings and no network**: an embedding model would compete with
 *    RFPlex for the GPU, which the LLM contract forbids.
 *  - Index: in-memory, per user, built lazily from disk and invalidated on
 *    add/delete. Token ids are interned and stored in typed arrays so a
 *    500-page guide indexes in a couple of seconds and searches in ms.
 *  - Storage: `data/kb/<userId>/<docId>/{meta.json,chunks.json}` through
 *    lib/store.js (atomic writes); ids are 12 hex chars, filenames are
 *    sanitised before they go anywhere near the filesystem.
 *  - Guard rails: 20 MB of extracted text and 20 000 chunks per document —
 *    beyond that the document is truncated and says so in `warnings`.
 *
 * Defensive by contract: nothing here throws on malformed input. The only
 * rejections are deliberate, user-facing ones from addDoc (unreadable upload,
 * missing PDF support), each carrying `err.userMessage`.
 *
 * Zero runtime dependencies (pdf-parse is an optionalDependency, required
 * lazily). CommonJS.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { loadJson, saveJson } = require('./store');

// ── Tunables ────────────────────────────────────────────────────────────────

const CHUNK_TARGET = 1200;              // ~chars of body per chunk
const CHUNK_MIN_TARGET = 400;           // floor once a long heading is subtracted
const CHUNK_OVERLAP = 150;              // ~chars carried from the previous chunk
const MAX_TEXT_BYTES = 20 * 1024 * 1024; // per document, extracted text
const MAX_CHUNKS = 20000;               // per document
const MAX_INDEX_CHUNKS = 60000;         // per user, in memory
const MAX_CACHED_INDEXES = 4;           // resident per-user indexes
const MAX_HEADING_LEN = 200;
const MAX_FILENAME_LEN = 180;
const MAX_META_LEN = 80;

const DEFAULT_K = 8;
const MAX_K = 200;
const MAX_QUERY_TERMS = 32;
const MAX_TOKEN_LEN = 40;

const BM25_K1 = 1.2;
const BM25_B = 0.75;
const HEADING_BOOST = 0.5;              // max multiplier 1.5x when every term hits the heading
const MIN_SCORE_RATIO = 0.08;           // drop hits scoring under 8% of the best hit

/** Extensions handled without any optional dependency (informational only —
 *  ingest is decided by sniffing content, never by the extension alone). */
const TEXT_EXTS = new Set(['.txt', '.md', '.markdown', '.html', '.htm', '.ini',
  '.cfg', '.conf', '.cli', '.log']);

/** Deliberately small: SIP/SBC guides are full of short meaningful tokens. */
const STOPWORDS = new Set([
  'a', 'an', 'the', 'and', 'or', 'of', 'to', 'in', 'on', 'at', 'by', 'for',
  'is', 'are', 'was', 'were', 'be', 'been', 'being', 'as', 'it', 'its', 'this',
  'that', 'these', 'those', 'with', 'from', 'into', 'if', 'then', 'than',
  'there', 'their', 'they', 'them', 'you', 'your', 'we', 'our', 'i', 'he',
  'she', 'his', 'her', 'but', 'not', 'no', 'so', 'such', 'will', 'would',
  'can', 'could', 'should', 'may', 'might', 'must', 'do', 'does', 'did',
  'has', 'have', 'had', 'about', 'also', 'any', 'all', 'each', 'more', 'most',
  'other', 'some', 'only', 'own', 'same', 'too', 'very', 'up', 'down', 'out',
  'over', 'under', 'when', 'where', 'which', 'while', 'who', 'whom', 'what',
]);

/** Common HTML entities (case-sensitive lookup first, see _decodeEntities). */
const ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ensp: ' ',
  emsp: ' ', thinsp: ' ', shy: '', zwnj: '', zwj: '', ndash: '-', mdash: '-',
  minus: '-', hellip: '...', lsquo: "'", rsquo: "'", sbquo: ',', ldquo: '"',
  rdquo: '"', bdquo: '"', bull: '*', middot: '.', sdot: '.', dagger: '+',
  copy: '(c)', reg: '(R)', trade: '(TM)', deg: ' deg', plusmn: '+/-',
  times: 'x', divide: '/', frac12: '1/2', frac14: '1/4', frac34: '3/4',
  sup2: '2', sup3: '3', micro: 'u', para: 'P', sect: 'S', laquo: '<<',
  raquo: '>>', lsaquo: '<', rsaquo: '>', euro: 'EUR', pound: 'GBP',
  yen: 'JPY', cent: 'c', dollar: '$', larr: '<-', rarr: '->', harr: '<->',
  agrave: 'à', aacute: 'á', acirc: 'â', auml: 'ä',
  aring: 'å', aelig: 'æ', ccedil: 'ç', egrave: 'è',
  eacute: 'é', ecirc: 'ê', euml: 'ë', igrave: 'ì',
  iacute: 'í', icirc: 'î', iuml: 'ï', ntilde: 'ñ',
  ograve: 'ò', oacute: 'ó', ocirc: 'ô', ouml: 'ö',
  oslash: 'ø', ugrave: 'ù', uacute: 'ú', ucirc: 'û',
  uuml: 'ü', szlig: 'ß', yacute: 'ý', yuml: 'ÿ',
};

/** Binary magics we can name in a friendly refusal (hex prefix → message). */
const BINARY_SIGNATURES = [
  { magic: '504b0304', msg: 'That looks like a zip or Office (.docx/.xlsx) file — export the guide as PDF, HTML or plain text and upload that.' },
  { magic: 'd0cf11e0', msg: 'That looks like a legacy Word/Excel file — save the guide as PDF or plain text and upload that.' },
  { magic: '25504446', msg: null }, // %PDF — handled before we get here
  { magic: '1f8b', msg: 'That file is gzip-compressed — unpack it and upload the document inside.' },
  { magic: '425a68', msg: 'That file is bzip2-compressed — unpack it and upload the document inside.' },
  { magic: '377abcaf', msg: 'That file is a 7-zip archive — unpack it and upload the document inside.' },
  { magic: '52617221', msg: 'That file is a RAR archive — unpack it and upload the document inside.' },
  { magic: '89504e47', msg: 'Images cannot be indexed — upload a text or PDF version of the guide.' },
  { magic: 'ffd8ff', msg: 'Images cannot be indexed — upload a text or PDF version of the guide.' },
  { magic: '47494638', msg: 'Images cannot be indexed — upload a text or PDF version of the guide.' },
  { magic: 'a1b2c3d4', msg: 'That looks like a packet capture — upload it on the captures page, not the guide library.' },
  { magic: 'd4c3b2a1', msg: 'That looks like a packet capture — upload it on the captures page, not the guide library.' },
  { magic: 'a1b23c4d', msg: 'That looks like a packet capture — upload it on the captures page, not the guide library.' },
  { magic: '4d3cb2a1', msg: 'That looks like a packet capture — upload it on the captures page, not the guide library.' },
  { magic: '0a0d0d0a', msg: 'That looks like a pcapng capture — upload it on the captures page, not the guide library.' },
  { magic: '7f454c46', msg: 'Executables cannot be indexed — upload the documentation instead.' },
  { magic: '4d5a90', msg: 'Executables cannot be indexed — upload the documentation instead.' },
  { magic: '53514c69', msg: 'Database files cannot be indexed — export the guide as text or PDF first.' },
];

const NOT_TEXT_MSG = 'hiccup could not read that as text. Config guides can be ' +
  'PDF or text (.txt .md .html .htm .ini .cfg .conf .cli .log).';
const PDF_DEP_MSG = 'PDF support needs an optional dependency: npm install pdf-parse';

// ── Module state ────────────────────────────────────────────────────────────

let _dataDir = null;                 // set by initKb (lazily defaulted otherwise)
const _index = new Map();            // userId -> in-memory index (see _buildIndex)

// ── Small helpers ───────────────────────────────────────────────────────────

/** Build an Error carrying a user-safe message (server maps it to 4xx JSON). */
function _err(userMessage, detail) {
  const e = new Error(detail || userMessage);
  e.userMessage = userMessage;
  return e;
}

/** @returns {boolean} true when id is a plain token safe as a directory name */
function _safeId(id) {
  return typeof id === 'string' && id.length > 0 && id.length <= 64 &&
    /^[A-Za-z0-9_-]+$/.test(id);
}

/** Effective data directory; defaults to <cwd>/data when initKb was skipped. */
function _ensureDataDir() {
  if (!_dataDir) _dataDir = path.join(process.cwd(), 'data');
  return _dataDir;
}

/** Root of the guide library: `<dataDir>/kb`. */
function _kbRoot() {
  return path.join(_ensureDataDir(), 'kb');
}

/** `<dataDir>/kb/<userId>` or null when the id is not filesystem-safe. */
function _userDir(userId) {
  return _safeId(userId) ? path.join(_kbRoot(), userId) : null;
}

/** `<dataDir>/kb/<userId>/<docId>` or null when either id is unsafe. */
function _docDir(userId, docId) {
  const u = _userDir(userId);
  return u && _safeId(docId) ? path.join(u, docId) : null;
}

/** New opaque document id: 12 lowercase hex chars (same shape as capture ids). */
function _newDocId() {
  return crypto.randomBytes(6).toString('hex');
}

/**
 * Make an uploaded name safe to store and safe to echo back: basename only, no
 * control characters, no Windows-illegal characters, no leading dots, no
 * reserved device names, bounded length.
 * @param {*} name
 * @returns {string} always non-empty
 */
function _sanitizeFilename(name) {
  let s = String(name == null ? '' : name);
  s = s.replace(/\\/g, '/');
  s = s.split('/').pop();                      // strip any path
  s = s.replace(/[\u0000-\u001f\u007f]/g, ' '); // control chars
  s = s.replace(/[<>:"|?*]/g, '_');            // illegal on Windows
  s = s.replace(/\s+/g, ' ').trim();
  s = s.replace(/^\.+/, '').trim();            // no '.', '..', hidden files
  if (!s) s = 'document.txt';
  if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)/i.test(s)) s = '_' + s;
  if (s.length > MAX_FILENAME_LEN) {
    const ext = path.extname(s).slice(0, 12);
    s = s.slice(0, MAX_FILENAME_LEN - ext.length) + ext;
  }
  return s;
}

/** Clean a short metadata string (vendor/product) → trimmed string or null. */
function _cleanMeta(v) {
  if (v == null) return null;
  const s = String(v).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
  if (!s) return null;
  return s.length > MAX_META_LEN ? s.slice(0, MAX_META_LEN) : s;
}

// ── Decoding + content sniffing ─────────────────────────────────────────────

/** Does this buffer start with (or nearly start with) a PDF header? */
function _isPdf(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 5) return false;
  const head = buf.slice(0, 1024).toString('latin1');
  return head.startsWith('%PDF-') || head.indexOf('%PDF-') !== -1;
}

/** Friendly refusal message for a recognised non-PDF binary, else null. */
function _binaryKind(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 2) return null;
  const head = buf.slice(0, 8).toString('hex');
  for (const sig of BINARY_SIGNATURES) {
    if (head.startsWith(sig.magic)) return sig.msg;
  }
  return null;
}

/** Count C1 control characters (0x80–0x9f) — the tell that a latin-1 decode
 *  is really binary, since no natural-language text uses them. */
function _c1Ratio(s) {
  const sample = s.length > 200000 ? s.slice(0, 200000) : s;
  if (!sample.length) return 0;
  let n = 0;
  for (let i = 0; i < sample.length; i++) {
    const c = sample.charCodeAt(i);
    if (c >= 0x80 && c <= 0x9f) n++;
  }
  return n / sample.length;
}

/**
 * Decode bytes to text, honouring BOMs (UTF-8, UTF-16LE/BE — PowerShell and
 * many Windows exports emit UTF-16). When the UTF-8 decode produces any
 * replacement character the bytes are re-read as latin-1, and latin-1 wins
 * unless it looks like binary (French/German vendor guides saved as CP1252 are
 * common, and three accented bytes must not get a file rejected).
 * @param {Buffer} buf
 * @returns {{text: string, encoding: 'utf8'|'utf16le'|'utf16be'|'latin1'}}
 */
function _decodeBuffer(buf) {
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    return { text: buf.slice(2).toString('utf16le'), encoding: 'utf16le' };
  }
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    const swapped = Buffer.from(buf.slice(2));
    try { swapped.swap16(); } catch { /* odd length — best effort */ }
    return { text: swapped.toString('utf16le'), encoding: 'utf16be' };
  }
  let body = buf;
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    body = buf.slice(3);
  }
  const utf8 = body.toString('utf8');
  let bad = 0;
  const sample = utf8.length > 200000 ? utf8.slice(0, 200000) : utf8;
  for (let i = 0; i < sample.length; i++) if (sample.charCodeAt(i) === 0xfffd) bad++;
  if (!bad) return { text: utf8, encoding: 'utf8' };
  const latin = body.toString('latin1');
  if (_c1Ratio(latin) < 0.01) return { text: latin, encoding: 'latin1' };
  return { text: utf8, encoding: 'utf8' };   // genuinely not text; caller refuses it
}

/**
 * Heuristic "this is not text" check on decoded content: NULs, control
 * characters, and (for latin-1 fallbacks) C1 bytes that real prose never uses.
 * @param {string} text
 * @param {string} encoding
 * @returns {boolean}
 */
function _looksBinary(text, encoding) {
  const sample = text.length > 20000 ? text.slice(0, 20000) : text;
  if (!sample.length) return false;
  let odd = 0;
  for (let i = 0; i < sample.length; i++) {
    const c = sample.charCodeAt(i);
    if (c === 0) return true;
    if (c < 9 || (c > 13 && c < 32) || c === 0x7f || c === 0xfffd) { odd++; continue; }
    if (encoding === 'latin1' && c >= 0x80 && c <= 0x9f) odd++;
  }
  // Absolute floor as well as a ratio: a 40-byte snippet with one stray
  // control character is still a text snippet.
  return odd >= 4 && odd / sample.length > 0.03;
}

/**
 * Which heading dialect to apply. HTML is converted to markdown-ish text first,
 * so it shares the markdown rules. Plain text and config files deliberately do
 * NOT use `#` headings — in a .conf or .cli file `#` starts a comment.
 * @param {string} ext lowercased extension including the dot
 * @param {string} text decoded text
 * @returns {'html'|'md'|'text'}
 */
function _detectSourceType(ext, text) {
  if (ext === '.html' || ext === '.htm') return 'html';
  const sample = text.length > 200000 ? text.slice(0, 200000) : text;
  const tags = sample.match(/<\/?(?:html|head|body|div|p|br|table|tr|td|span|h[1-6]|ul|ol|li|pre|code|a)\b[^>]*>/gi);
  if (tags && tags.length >= 5 && /<\//.test(sample)) return 'html';
  if (ext === '.md' || ext === '.markdown') return 'md';
  const configish = ext === '.ini' || ext === '.cfg' || ext === '.conf' ||
    ext === '.cli' || ext === '.log';
  if (!configish) {
    const atx = sample.match(/^[ \t]{0,3}#{1,6}[ \t]+\S/gm);
    if (atx && atx.length >= 2) return 'md';
  }
  return 'text';
}

/** Decode HTML entities, numeric and named (case-sensitive first). */
function _decodeEntities(s) {
  return String(s).replace(/&(#[xX]?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]{1,31});/g,
    (m, body) => {
      if (body[0] === '#') {
        const hex = body[1] === 'x' || body[1] === 'X';
        const code = parseInt(hex ? body.slice(2) : body.slice(1), hex ? 16 : 10);
        if (!Number.isFinite(code) || code < 9 || code > 0x10ffff) return m;
        try { return String.fromCodePoint(code); } catch { return m; }
      }
      const exact = Object.prototype.hasOwnProperty.call(ENTITIES, body)
        ? ENTITIES[body] : undefined;
      if (exact !== undefined) return exact;
      const lower = body.toLowerCase();
      const v = Object.prototype.hasOwnProperty.call(ENTITIES, lower)
        ? ENTITIES[lower] : undefined;
      if (v === undefined) return m;
      return /^[a-z]$/.test(v) ? v.toUpperCase() : v;
    });
}

/** Strip every tag from a fragment and decode entities (inline text only). */
function _stripTags(frag) {
  return _decodeEntities(String(frag).replace(/<[^>]*>/g, ' '))
    .replace(/\s+/g, ' ').trim();
}

/**
 * HTML → plain text: script/style/comments dropped, h1–h6 turned into
 * markdown-style heading lines, block boundaries turned into newlines,
 * entities decoded. `<title>` is returned as a title hint.
 * @param {string} html
 * @returns {{text: string, title: string|null}}
 */
function _htmlToText(html) {
  let s = String(html);
  let title = null;
  const tm = /<title[^>]*>([\s\S]{0,500}?)<\/title\s*>/i.exec(s);
  if (tm) {
    const t = _stripTags(tm[1]);
    if (t) title = t.slice(0, MAX_HEADING_LEN);
  }
  s = s.replace(/<!--[\s\S]*?-->/g, ' ');
  s = s.replace(/<(script|style|noscript|svg|math|template|head)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, ' ');
  s = s.replace(/<(script|style)\b[^>]*>[\s\S]*$/gi, ' ');   // unterminated
  s = s.replace(/<h([1-6])\b[^>]*>([\s\S]{0,2000}?)<\/h\1\s*>/gi, (m, lvl, inner) => {
    const t = _stripTags(inner);
    if (!t) return '\n\n';
    const n = Math.min(3, Math.max(1, parseInt(lvl, 10) || 1));
    return '\n\n' + '#'.repeat(n) + ' ' + t.slice(0, MAX_HEADING_LEN) + '\n\n';
  });
  s = s.replace(/<br\s*\/?>/gi, '\n');
  s = s.replace(/<li\b[^>]*>/gi, '\n- ');
  s = s.replace(/<\/(p|div|li|tr|table|thead|tbody|section|article|ul|ol|pre|blockquote|dl|dd|dt|figure|form|header|footer|nav|main|h[1-6])\s*>/gi, '\n');
  s = s.replace(/<\/(td|th)\s*>/gi, '  ');
  s = s.replace(/<(p|div|tr|table|section|article|ul|ol|pre|blockquote)\b[^>]*>/gi, '\n');
  s = s.replace(/<[^>]*>/g, ' ');
  s = _decodeEntities(s);
  s = s.replace(/\r\n?/g, '\n');
  s = s.replace(/[ \t\u00a0]+/g, ' ');
  s = s.replace(/[ \t]+\n/g, '\n');
  s = s.replace(/\n{3,}/g, '\n\n');
  return { text: s.trim(), title };
}

// ── PDF (lazy, optional dependency) ─────────────────────────────────────────

/**
 * pdf-parse page renderer that keeps line structure and terminates each page
 * with a form feed, so page numbers survive into chunks.
 * @param {object} pageData pdf.js page proxy handed over by pdf-parse
 * @returns {Promise<string>}
 */
function _pdfPageRender(pageData) {
  try {
    return pageData
      .getTextContent({ normalizeWhitespace: true, disableCombineTextItems: false })
      .then((tc) => {
        let out = '';
        let lastY = null;
        const items = (tc && Array.isArray(tc.items)) ? tc.items : [];
        for (const item of items) {
          const str = item && typeof item.str === 'string' ? item.str : '';
          const y = item && item.transform ? item.transform[5] : null;
          if (lastY === null || y === lastY) out += str;
          else out += '\n' + str;
          lastY = y;
        }
        return out + '\f';
      }, () => '\f');
  } catch {
    return Promise.resolve('\f');
  }
}

/**
 * Extract text from a PDF using the optional `pdf-parse` dependency.
 * @param {Buffer} buf
 * @param {string[]} warnings collected for the returned doc object
 * @returns {Promise<{text: string, pageCount: number|null}>}
 */
async function _extractPdf(buf, warnings) {
  let pdfParse = null;
  try {
    // Lazy on purpose: a core install of hiccup stays dependency-free.
    pdfParse = require('pdf-parse');
  } catch {
    throw _err(PDF_DEP_MSG, 'kb: pdf-parse not installed');
  }
  if (typeof pdfParse !== 'function' && pdfParse && typeof pdfParse.default === 'function') {
    pdfParse = pdfParse.default;
  }
  if (typeof pdfParse !== 'function') {
    throw _err(PDF_DEP_MSG, 'kb: pdf-parse did not export a function');
  }
  let data = null;
  try {
    data = await pdfParse(buf, { pagerender: _pdfPageRender });
  } catch (e1) {
    try {
      data = await pdfParse(buf);                      // default renderer
      warnings.push('page numbers unavailable for this PDF');
    } catch (e2) {
      throw _err('That PDF could not be read — it may be encrypted, damaged or image-only.',
        'kb: pdf-parse failed: ' + (e2 && e2.message));
    }
  }
  const text = data && typeof data.text === 'string' ? data.text : '';
  if (!text.trim()) {
    throw _err('That PDF has no extractable text — it is probably a scan. Run OCR on it, or paste the relevant section as text.');
  }
  const pageCount = data && Number.isFinite(data.numpages) ? data.numpages : null;
  return { text, pageCount };
}

// ── Pagination ──────────────────────────────────────────────────────────────

/**
 * Split extracted text into pages on form feeds (pdf page breaks or literal
 * \f in text exports). Non-paginated sources yield one page with `pageNo:null`.
 * @param {string} text
 * @returns {{pages: Array<{pageNo: number|null, text: string}>, pageCount: number}}
 */
function _splitPages(text) {
  if (text.indexOf('\f') === -1) {
    return { pages: [{ pageNo: null, text }], pageCount: 0 };
  }
  const parts = text.split('\f');
  const pages = [];
  for (let i = 0; i < parts.length; i++) {
    const t = parts[i];
    if (!t || !t.trim()) continue;
    pages.push({ pageNo: i + 1, text: t });
  }
  if (!pages.length) return { pages: [{ pageNo: null, text }], pageCount: 0 };
  return { pages, pageCount: pages[pages.length - 1].pageNo };
}

// ── Heading detection + chunking ────────────────────────────────────────────

const ATX_HEADING = /^[ \t]{0,3}(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$/;
const SETEXT_UNDERLINE = /^[ \t]{0,3}([=\-~_])\1{2,}[ \t]*$/;
const INI_SECTION = /^[ \t]*\[([^\]\r\n]{1,80})\][ \t]*$/;
const NUMBERED_HEADING = /^[ \t]*(\d{1,3}(?:\.\d{1,3}){0,2})[.):]?[ \t]+([A-Za-z(\[][^\r\n]{0,98})$/;

/** A `4.2 Session timers`-style section line → heading text, else null. */
function _numberedHeading(line) {
  const m = NUMBERED_HEADING.exec(line);
  if (!m) return null;
  const text = m[2].trim();
  if (!text) return null;
  if (/[.,;]$/.test(text)) return null;             // that is a sentence, not a title
  if (text.split(/\s+/).length > 14) return null;
  return (m[1] + ' ' + text).slice(0, MAX_HEADING_LEN);
}

/** An `ADVANCED SIP SETTINGS`-style line → heading text, else null. */
function _allCapsHeading(line) {
  const t = line.trim();
  if (t.length < 3 || t.length > 80) return null;
  if (/[a-z]/.test(t)) return null;
  if (!/[A-Z]{3}/.test(t)) return null;
  if (/[=;|<>{}]/.test(t)) return null;             // config assignment / markup
  if (/^[-=_*+#~.\s]+$/.test(t)) return null;       // rule line
  const letters = t.replace(/[^A-Z]/g, '').length;
  if (letters < 3 || letters / t.length < 0.4) return null;
  return t.replace(/[:\s]+$/, '').slice(0, MAX_HEADING_LEN);
}

/**
 * Turn text into heading / paragraph blocks.
 * @param {string} text
 * @param {'html'|'md'|'text'} sourceType
 * @returns {Array<{type: 'heading'|'text', text: string}>}
 */
function _blocksFromText(text, sourceType) {
  const allowAtx = sourceType === 'md' || sourceType === 'html';
  const lines = String(text).split(/\r\n|\r|\n/);
  const blocks = [];
  let para = [];
  const flush = () => {
    if (!para.length) return;
    const t = para.join('\n').trim();
    if (t) blocks.push({ type: 'text', text: t });
    para = [];
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) { flush(); continue; }
    let heading = null;
    if (allowAtx) {
      const m = ATX_HEADING.exec(line);
      if (m) heading = m[2].trim();
    }
    if (!heading) {
      const m = INI_SECTION.exec(line);
      if (m) heading = m[1].trim();
    }
    if (!heading && i + 1 < lines.length && SETEXT_UNDERLINE.test(lines[i + 1]) &&
        line.trim().length <= 100 && /[A-Za-z]/.test(line)) {
      heading = line.trim();
      i++;                                          // swallow the underline
    }
    if (!heading) heading = _numberedHeading(line);
    if (!heading) heading = _allCapsHeading(line);
    if (heading) {
      flush();
      blocks.push({ type: 'heading', text: heading.slice(0, MAX_HEADING_LEN) });
      continue;
    }
    para.push(line);
  }
  flush();
  return blocks;
}

/**
 * Group blocks into sections, each carrying the nearest preceding heading. A
 * heading with no body of its own becomes a breadcrumb on the next one
 * (`Chapter 4 > 4.2 Session timers`), capped at two levels.
 * @param {Array<{type: string, text: string}>} blocks
 * @returns {Array<{heading: string|null, parts: string[]}>}
 */
function _sectionsFromBlocks(blocks) {
  const sections = [];
  let cur = { heading: null, parts: [] };
  for (const b of blocks) {
    if (b.type === 'heading') {
      if (cur.parts.length) {
        sections.push(cur);
        cur = { heading: b.text, parts: [] };
      } else if (cur.heading) {
        const segs = (cur.heading + ' > ' + b.text).split(' > ').slice(-2);
        let bc = segs.join(' > ');
        if (bc.length > MAX_HEADING_LEN) bc = b.text.slice(0, MAX_HEADING_LEN);
        cur = { heading: bc, parts: [] };
      } else {
        cur = { heading: b.text, parts: [] };
      }
      continue;
    }
    cur.parts.push(b.text);
  }
  if (cur.parts.length) sections.push(cur);
  return sections;
}

/** Last ~n chars of s, moved forward to a sentence or word boundary. */
function _overlapTail(s, n) {
  if (!s) return '';
  if (s.length <= n) return s.trim();
  let t = s.slice(s.length - n);
  const sent = t.search(/[.!?]\s/);
  if (sent >= 0 && sent < n * 0.5) {
    t = t.slice(sent + 1);
  } else {
    const sp = t.search(/\s/);
    if (sp >= 0 && sp < 40) t = t.slice(sp + 1);
  }
  return t.trim();
}

/** Split one oversized paragraph on sentence ends, then (last resort) words. */
function _splitLongParagraph(p, target) {
  const out = [];
  const sentences = p.match(/[^.!?\n]*[.!?]+["')\]]*\s*|[^.!?\n]+\n*/g) || [p];
  let cur = '';
  for (const sRaw of sentences) {
    let s = sRaw;
    while (s.length > target) {                     // one sentence longer than a chunk
      if (cur) { out.push(cur.trim()); cur = ''; }
      let cut = s.lastIndexOf(' ', target);
      if (cut < target * 0.5) cut = target;
      out.push(s.slice(0, cut).trim());
      s = s.slice(cut);
    }
    if (cur && cur.length + s.length > target) { out.push(cur.trim()); cur = s; }
    else cur += s;
  }
  if (cur.trim()) out.push(cur.trim());
  return out.filter(Boolean);
}

/**
 * Split a section body into ~target-sized pieces on paragraph (then sentence)
 * boundaries, prefixing each continuation with ~overlap chars of the previous
 * piece so a phrase straddling a boundary is still findable.
 * @param {string} body
 * @param {number} target
 * @param {number} overlap
 * @returns {string[]}
 */
function _splitBody(body, target, overlap) {
  const t = Math.max(CHUNK_MIN_TARGET, target | 0);
  const trimmed = String(body).trim();
  if (!trimmed) return [];
  if (trimmed.length <= t) return [trimmed];
  const units = [];
  for (const paraRaw of trimmed.split(/\n{2,}/)) {
    const para = paraRaw.trim();
    if (!para) continue;
    if (para.length <= t) units.push(para);
    else for (const piece of _splitLongParagraph(para, t)) units.push(piece);
  }
  const out = [];
  let cur = '';
  for (const u of units) {
    if (cur && cur.length + 2 + u.length > t) {
      out.push(cur);
      const tail = _overlapTail(cur, overlap);
      cur = tail ? tail + '\n' + u : u;
    } else {
      cur = cur ? cur + '\n\n' + u : u;
    }
  }
  if (cur.trim()) out.push(cur);
  return out;
}

/**
 * Chunk every page of a document.
 * @param {Array<{pageNo: number|null, text: string}>} pages
 * @param {'html'|'md'|'text'} sourceType
 * @returns {{chunks: Array<{i: number, page: number|null, heading: string|null, text: string}>,
 *            firstHeading: string|null, truncated: boolean}}
 */
function _chunkPages(pages, sourceType) {
  const chunks = [];
  let firstHeading = null;
  let truncated = false;
  for (const page of pages) {
    if (truncated) break;
    const blocks = _blocksFromText(page.text, sourceType);
    if (!firstHeading) {
      const h = blocks.find(b => b.type === 'heading');
      if (h) firstHeading = h.text;
    }
    const sections = _sectionsFromBlocks(blocks);
    for (const sec of sections) {
      const body = sec.parts.join('\n\n').trim();
      if (!body) continue;
      const heading = sec.heading || null;
      const target = CHUNK_TARGET - (heading ? heading.length + 1 : 0);
      for (const piece of _splitBody(body, target, CHUNK_OVERLAP)) {
        if (chunks.length >= MAX_CHUNKS) { truncated = true; break; }
        chunks.push({
          i: chunks.length,
          page: page.pageNo,
          heading,
          text: heading ? heading + '\n' + piece : piece,
        });
      }
      if (truncated) break;
    }
  }
  if (!chunks.length) {
    // Nothing looked like a paragraph (single heading, or one giant line):
    // fall back to raw splitting so the document is never silently empty.
    for (const page of pages) {
      const body = String(page.text || '').trim();
      if (!body) continue;
      for (const piece of _splitBody(body, CHUNK_TARGET, CHUNK_OVERLAP)) {
        if (chunks.length >= MAX_CHUNKS) { truncated = true; break; }
        chunks.push({ i: chunks.length, page: page.pageNo, heading: null, text: piece });
      }
      if (truncated) break;
    }
  }
  return { chunks, firstHeading, truncated };
}

// ── Tokenising + BM25 index ─────────────────────────────────────────────────

const TOKEN_RE = /[a-z0-9_\u00c0-\u024f]+/g;

/**
 * Lowercase-folded tokens, stopwords and lone letters dropped.
 * @param {*} s
 * @returns {string[]}
 */
function _tokenize(s) {
  const str = String(s == null ? '' : s).toLowerCase();
  const out = [];
  TOKEN_RE.lastIndex = 0;
  let m;
  while ((m = TOKEN_RE.exec(str)) !== null) {
    let t = m[0];
    if (t.length > MAX_TOKEN_LEN) t = t.slice(0, MAX_TOKEN_LEN);
    if (t.length === 1 && !(t >= '0' && t <= '9')) continue;
    if (STOPWORDS.has(t)) continue;
    out.push(t);
  }
  return out;
}

/** Token → integer id inside one user's index (interned to keep it compact). */
function _intern(idx, token) {
  let id = idx.vocab.get(token);
  if (id === undefined) {
    id = idx.df.length;
    idx.vocab.set(token, id);
    idx.df.push(0);
  }
  return id;
}

/** Binary search in an ascending Int32Array. @returns {number} index or -1 */
function _bsearch(arr, want) {
  let lo = 0;
  let hi = arr.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const v = arr[mid];
    if (v === want) return mid;
    if (v < want) lo = mid + 1;
    else hi = mid - 1;
  }
  return -1;
}

/** Add one stored chunk record to the in-memory index. */
function _addChunkToIndex(idx, rec) {
  const tokens = _tokenize(rec.text);
  if (!tokens.length) return;
  const counts = new Map();
  for (const t of tokens) counts.set(t, (counts.get(t) || 0) + 1);
  const size = counts.size;
  const rawIds = new Int32Array(size);
  const rawFreq = new Uint16Array(size);
  let j = 0;
  for (const [t, f] of counts) {
    rawIds[j] = _intern(idx, t);
    rawFreq[j] = f > 65535 ? 65535 : f;
    j++;
  }
  const order = new Array(size);
  for (let k = 0; k < size; k++) order[k] = k;
  order.sort((a, b) => rawIds[a] - rawIds[b]);
  const ids = new Int32Array(size);
  const freq = new Uint16Array(size);
  for (let k = 0; k < size; k++) { ids[k] = rawIds[order[k]]; freq[k] = rawFreq[order[k]]; }
  for (let k = 0; k < size; k++) idx.df[ids[k]]++;

  const headTokens = rec.heading ? _tokenize(rec.heading) : [];
  const headSet = new Set();
  for (const t of headTokens) {
    const id = idx.vocab.get(t);
    if (id !== undefined) headSet.add(id);
  }
  const headIds = Int32Array.from(headSet).sort();

  idx.chunks.push(rec);
  idx.tokIds.push(ids);
  idx.tokFreq.push(freq);
  idx.headIds.push(headIds);
  idx.len.push(tokens.length);
  idx.totalLen += tokens.length;
}

/**
 * Read one user's documents from disk and build their BM25 index.
 * Never throws: unreadable documents are skipped.
 * @param {string} userId
 * @returns {object} index
 */
function _buildIndex(userId) {
  const idx = {
    docs: [], chunks: [], tokIds: [], tokFreq: [], headIds: [], len: [],
    vocab: new Map(), df: [], totalLen: 0, avgdl: 1, truncated: false,
    builtAt: Date.now(),
  };
  const metas = _readMetas(userId);
  for (const meta of metas) {
    idx.docs.push(meta);
    if (idx.chunks.length >= MAX_INDEX_CHUNKS) { idx.truncated = true; continue; }
    const dir = _docDir(userId, meta.id);
    if (!dir) continue;
    const stored = loadJson(path.join(dir, 'chunks.json'), []);
    if (!Array.isArray(stored)) continue;
    const docTitle = meta.title || meta.filename || meta.id;
    for (const ch of stored) {
      if (idx.chunks.length >= MAX_INDEX_CHUNKS) { idx.truncated = true; break; }
      if (!ch || typeof ch.text !== 'string' || !ch.text.trim()) continue;
      _addChunkToIndex(idx, {
        docId: meta.id,
        docTitle,
        page: Number.isFinite(ch.page) ? ch.page : null,
        heading: typeof ch.heading === 'string' && ch.heading ? ch.heading : null,
        text: ch.text,
      });
    }
  }
  idx.avgdl = idx.chunks.length ? Math.max(1, idx.totalLen / idx.chunks.length) : 1;
  return idx;
}

/**
 * Cached index for a user, built on first use after any add/delete. At most
 * MAX_CACHED_INDEXES are kept resident (least-recently-built dropped first) so
 * a busy multi-user box cannot accumulate indexes forever.
 */
function _getIndex(userId) {
  if (!_safeId(userId)) return null;
  let idx = _index.get(userId);
  if (!idx) {
    idx = _buildIndex(userId);
    while (_index.size >= MAX_CACHED_INDEXES) {
      const oldest = _index.keys().next();
      if (oldest.done) break;
      _index.delete(oldest.value);
    }
    _index.set(userId, idx);
  }
  return idx;
}

/** Read every meta.json for a user, newest first. Skips unreadable docs. */
function _readMetas(userId) {
  const dir = _userDir(userId);
  if (!dir) return [];
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];                                       // no library yet
  }
  const metas = [];
  for (const ent of entries) {
    if (!ent.isDirectory() || !_safeId(ent.name)) continue;
    const meta = loadJson(path.join(dir, ent.name, 'meta.json'), null);
    if (!meta || typeof meta !== 'object') continue;
    meta.id = ent.name;                              // the directory is the truth
    metas.push(meta);
  }
  metas.sort((a, b) => (Date.parse(b.addedAt || '') || 0) - (Date.parse(a.addedAt || '') || 0));
  return metas;
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Point the knowledge base at a data directory and drop any cached indexes.
 * Safe to call more than once. When it is never called, the module falls back
 * to `<cwd>/data`.
 * @param {string} dataDir the app data directory (server passes DATA_DIR)
 * @returns {string} the guide-library root (`<dataDir>/kb`), informational
 */
function initKb(dataDir) {
  _dataDir = (typeof dataDir === 'string' && dataDir.trim()) ? dataDir : null;
  _index.clear();
  const root = _kbRoot();
  try { fs.mkdirSync(root, { recursive: true }); } catch { /* created on first save */ }
  return root;
}

/**
 * Ingest one config guide: extract text, chunk it with heading and page
 * capture, store it under `data/kb/<userId>/<docId>/` and invalidate the
 * user's search index.
 *
 * Async because PDF extraction is. Rejects with `err.userMessage` set when the
 * upload is unusable (binary, empty, image-only PDF) or when PDF support is
 * missing (`'PDF support needs an optional dependency: npm install pdf-parse'`).
 *
 * @param {{userId: string, filename: string, buffer: Buffer|string,
 *          vendor?: string, product?: string}} opts
 * @returns {Promise<{id: string, chunks: number, pages: number, title: string,
 *          filename: string, vendor: string|null, product: string|null,
 *          addedAt: string, sizeBytes: number, truncated: boolean,
 *          warnings: string[]}>}
 *          `pages` is 0 when the source is not paginated.
 */
async function addDoc(opts) {
  const o = (opts && typeof opts === 'object') ? opts : {};
  const userId = String(o.userId == null ? '' : o.userId);
  if (!_safeId(userId)) {
    throw _err('Sign in again to add a guide.', 'kb.addDoc: invalid userId');
  }
  let buf = o.buffer;
  if (typeof buf === 'string') buf = Buffer.from(buf, 'utf8');
  if (!Buffer.isBuffer(buf) || !buf.length) {
    throw _err('That upload was empty — pick a file and try again.',
      'kb.addDoc: empty buffer');
  }
  const filename = _sanitizeFilename(o.filename);
  const vendor = _cleanMeta(o.vendor);
  const product = _cleanMeta(o.product);
  const ext = path.extname(filename).toLowerCase();
  const warnings = [];

  // 1. Extract text (content sniffed first, extension only as a hint).
  let text = '';
  let pdfPageCount = null;
  let sourceType = 'text';
  let titleHint = null;
  if (_isPdf(buf)) {
    const got = await _extractPdf(buf, warnings);
    text = got.text;
    pdfPageCount = got.pageCount;
    sourceType = 'text';
  } else {
    if (ext === '.pdf') {
      throw _err('That file is named .pdf but is not a PDF. Re-export it, or upload the text version.');
    }
    const bin = _binaryKind(buf);
    if (bin) throw _err(bin, 'kb.addDoc: recognised binary');
    const dec = _decodeBuffer(buf);
    if (_looksBinary(dec.text, dec.encoding)) {
      throw _err(NOT_TEXT_MSG, 'kb.addDoc: content does not look like text');
    }
    if (!dec.text.trim()) {
      throw _err('That file has no text in it.', 'kb.addDoc: blank text');
    }
    if (!TEXT_EXTS.has(ext) && ext) {
      warnings.push('unknown extension "' + ext + '" — indexed as plain text');
    }
    sourceType = _detectSourceType(ext, dec.text);
    if (sourceType === 'html') {
      const conv = _htmlToText(dec.text);
      text = conv.text;
      titleHint = conv.title;
    } else {
      text = dec.text;
    }
  }

  // 2. Guard rails: 20 MB of text, 20k chunks.
  if (Buffer.byteLength(text, 'utf8') > MAX_TEXT_BYTES) {
    text = text.slice(0, MAX_TEXT_BYTES);
    warnings.push('document truncated at 20 MB of extracted text');
  }
  const { pages, pageCount } = _splitPages(text);
  const { chunks, firstHeading, truncated } = _chunkPages(pages, sourceType);
  if (!chunks.length) {
    throw _err('No readable text found in that file.', 'kb.addDoc: zero chunks');
  }
  if (truncated) {
    warnings.push('document truncated at ' + MAX_CHUNKS + ' chunks — later pages were not indexed');
  }
  const title = (firstHeading || titleHint || filename).slice(0, MAX_HEADING_LEN);
  const pagesOut = Number.isFinite(pdfPageCount) && pdfPageCount > 0
    ? pdfPageCount
    : pageCount;

  // 3. Store: chunks first, then meta, so a half-written doc is simply invisible.
  let id = _newDocId();
  let dir = _docDir(userId, id);
  for (let tries = 0; dir && fs.existsSync(dir) && tries < 5; tries++) {
    id = _newDocId();
    dir = _docDir(userId, id);
  }
  if (!dir) throw _err('Could not save that guide.', 'kb.addDoc: bad doc dir');
  const meta = {
    id,
    filename,
    title,
    vendor,
    product,
    chunks: chunks.length,
    pages: pagesOut,
    addedAt: new Date().toISOString(),
    sizeBytes: buf.length,
    textBytes: Buffer.byteLength(text, 'utf8'),
    sourceType,
    truncated: !!truncated,
    warnings,
  };
  try {
    saveJson(path.join(dir, 'chunks.json'), chunks);
    saveJson(path.join(dir, 'meta.json'), meta);
  } catch (e) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    throw _err('Could not save that guide — the data directory is not writable.',
      'kb.addDoc: save failed: ' + (e && e.message));
  }
  _index.delete(userId);                             // invalidate

  return {
    id,
    chunks: chunks.length,
    pages: pagesOut,
    title,
    filename,
    vendor,
    product,
    addedAt: meta.addedAt,
    sizeBytes: meta.sizeBytes,
    truncated: !!truncated,
    warnings,
  };
}

/**
 * List a user's guides, newest first. Never throws; returns [] when the user
 * has no library yet.
 * @param {string} userId
 * @returns {Array<{id: string, filename: string, title: string,
 *          vendor: string|null, product: string|null, chunks: number,
 *          addedAt: string, sizeBytes: number, pages: number,
 *          warnings: string[]}>}
 */
function listDocs(userId) {
  try {
    return _readMetas(String(userId == null ? '' : userId)).map(m => ({
      id: m.id,
      filename: typeof m.filename === 'string' ? m.filename : m.id,
      title: typeof m.title === 'string' && m.title ? m.title : (m.filename || m.id),
      vendor: m.vendor == null ? null : String(m.vendor),
      product: m.product == null ? null : String(m.product),
      chunks: Number.isFinite(m.chunks) ? m.chunks : 0,
      addedAt: typeof m.addedAt === 'string' ? m.addedAt : null,
      sizeBytes: Number.isFinite(m.sizeBytes) ? m.sizeBytes : 0,
      pages: Number.isFinite(m.pages) ? m.pages : 0,
      warnings: Array.isArray(m.warnings) ? m.warnings : [],
    }));
  } catch {
    return [];
  }
}

/**
 * Delete one guide and invalidate the user's index.
 * @param {string} userId
 * @param {string} id document id
 * @returns {boolean} true when the document existed and was removed
 */
function deleteDoc(userId, id) {
  try {
    const uid = String(userId == null ? '' : userId);
    const did = String(id == null ? '' : id);
    const dir = _docDir(uid, did);
    if (!dir || !fs.existsSync(dir)) return false;
    fs.rmSync(dir, { recursive: true, force: true });
    _index.delete(uid);
    return true;
  } catch {
    return false;
  }
}

/**
 * BM25 keyword search over a user's guides (k1=1.2, b=0.75), with a modest
 * boost for query terms appearing in a chunk's heading. No embeddings, no
 * network — the GPU belongs to RFPlex.
 *
 * The index is built lazily on first search after an add/delete, so the first
 * call after an upload pays the (seconds, for a 500-page guide) build cost and
 * later calls are milliseconds. Matching is OR over the query terms, with a
 * relative floor: hits scoring under 8% of the best hit are dropped, so a
 * single common word cannot pad the citation list. Never throws; returns []
 * on anything odd.
 *
 * @param {string} userId
 * @param {string} query free text, e.g. 'session-expires refresher uas'
 * @param {number} [k=8] maximum hits (capped at 200)
 * @returns {Array<{docId: string, docTitle: string, page: number|null,
 *          heading: string|null, text: string, score: number}>} score-sorted
 */
function searchKb(userId, query, k) {
  try {
    const limit = Number.isFinite(k) && k > 0 ? Math.min(Math.floor(k), MAX_K) : DEFAULT_K;
    const idx = _getIndex(String(userId == null ? '' : userId));
    if (!idx || !idx.chunks.length) return [];
    const seen = new Set();
    const qIds = [];
    for (const t of _tokenize(query)) {
      if (seen.has(t)) continue;
      seen.add(t);
      const id = idx.vocab.get(t);
      if (id !== undefined) qIds.push(id);
      if (qIds.length >= MAX_QUERY_TERMS) break;
    }
    if (!qIds.length) return [];
    const N = idx.chunks.length;
    const idf = qIds.map((id) => {
      const df = idx.df[id] || 0;
      return Math.log(1 + (N - df + 0.5) / (df + 0.5));
    });
    const hits = [];
    for (let c = 0; c < N; c++) {
      const ids = idx.tokIds[c];
      const freq = idx.tokFreq[c];
      const dl = idx.len[c] || 1;
      const norm = BM25_K1 * (1 - BM25_B + BM25_B * (dl / idx.avgdl));
      const headIds = idx.headIds[c];
      let score = 0;
      let headMatched = 0;
      for (let q = 0; q < qIds.length; q++) {
        const pos = _bsearch(ids, qIds[q]);
        if (pos >= 0) {
          const f = freq[pos];
          score += idf[q] * ((f * (BM25_K1 + 1)) / (f + norm));
        }
        if (headIds.length && _bsearch(headIds, qIds[q]) >= 0) headMatched++;
      }
      if (score <= 0) continue;
      if (headMatched) score *= 1 + HEADING_BOOST * (headMatched / qIds.length);
      hits.push({ c, score });
    }
    hits.sort((a, b) => (b.score - a.score) || (a.c - b.c));
    // BM25 is OR-matching, so a query's most common word alone can drag in
    // near-irrelevant chunks. A relative floor keeps citations honest.
    const floor = hits.length ? hits[0].score * MIN_SCORE_RATIO : 0;
    let keep = hits.length;
    while (keep > 1 && hits[keep - 1].score < floor) keep--;
    if (keep < hits.length) hits.length = keep;
    if (hits.length > limit) hits.length = limit;
    return hits.map((h) => {
      const r = idx.chunks[h.c];
      return {
        docId: r.docId,
        docTitle: r.docTitle,
        page: r.page,
        heading: r.heading,
        text: r.text,
        score: Math.round(h.score * 10000) / 10000,
      };
    });
  } catch {
    return [];
  }
}

module.exports = {
  initKb,
  addDoc,
  listDocs,
  deleteDoc,
  searchKb,
};
