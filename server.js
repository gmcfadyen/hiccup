// server.js — hiccup HTTP server: routes, auth glue, capture upload/analysis,
// chat proxy, advice/HMR/KB routes, static files, robots/sitemap. Plain node
// http, zero runtime dependencies (pdf-parse is an optionalDependency used only
// inside lib/kb.js).
// Contract: ARCHITECTURE.md §HTTP API + §Wave 2 §New routes. Windows-safe paths.
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const store = require('./lib/store');
const auth = require('./lib/auth');
const adminlist = require('./lib/adminlist');
const llm = require('./lib/llm');

// lib/analyze.js is the integrator's module. Require it gracefully so a partial
// deploy (or standalone server testing) stays diagnosable: the server boots and
// every route works except upload, which returns 501 until analyze is present.
let analyzeCapture = null;
try {
  analyzeCapture = require('./lib/analyze').analyzeCapture;
} catch (e) {
  console.warn('hiccup: lib/analyze.js unavailable (' + (e && e.message) +
    ') — POST /api/captures will return 501 until the analysis engine is deployed');
}

// The Wave-2 sibling modules (lib/advisor.js, lib/hmr.js, lib/kb.js) are built by
// other agents, so they get the same treatment as lib/analyze.js above: a lazy
// try/catch require, warned about once, so a missing or broken module degrades
// exactly the routes that need it (501) instead of stopping the server booting.
// A successful load is cached; a failure is retried on the next use, so a module
// deployed after boot is picked up without a restart.
const _optCache = new Map();
const _optWarned = new Set();

/**
 * Require an optional sibling module, returning null when it cannot be loaded.
 * Warns once per module path; never throws.
 * @param {string} rel module path relative to this file, e.g. './lib/kb'
 * @returns {object|null} the module exports, or null when unavailable
 */
function optionalModule(rel) {
  if (_optCache.has(rel)) return _optCache.get(rel);
  try {
    const mod = require(rel);
    _optCache.set(rel, mod);
    if (_optWarned.has(rel)) console.log('hiccup: ' + rel + ' is available now');
    return mod;
  } catch (e) {
    if (!_optWarned.has(rel)) {
      _optWarned.add(rel);
      console.warn('hiccup: ' + rel + ' unavailable (' + (e && e.message) +
        ') — the routes that need it answer 501 until it is deployed');
    }
    return null;
  }
}

let VERSION = '0.0.0';
try { VERSION = require('./package.json').version || VERSION; } catch { /* optional */ }

// ---------------------------------------------------------------------------
// Config + boot
// ---------------------------------------------------------------------------

const DATA_DIR = process.env.HICCUP_DATA_DIR
  ? path.resolve(process.env.HICCUP_DATA_DIR)
  : path.join(__dirname, 'data');

const CONFIG_DEFAULTS = {
  port: 8400,
  host: '127.0.0.1',
  baseUrl: 'http://127.0.0.1:8400',
  googleClientId: null,
  ollamaUrl: 'http://127.0.0.1:11434',
  rfplexStatusUrl: 'http://127.0.0.1:3001/api/status/llm',
  preferredModels: ['qwen3.5:9b', 'qwen3.5:2b', 'qwen3:8b', 'llama3.1:8b'],
  maxUploadMb: 50,
  // Wave 6: where the weekly feedback digest goes. Empty disables the digest
  // entirely (the feedback itself is still collected and readable at
  // /admin/feedback — only the email is skipped).
  digestRecipient: '',
  // Wave 6: who may reach /admin/*. An explicit allow-list, because the
  // alternative — lib/auth.js's role:'admin', which is simply "whoever signed
  // up first" — is not something to hang the ops surface on: recreate the user
  // store and it silently transfers to a stranger. When this list is non-empty
  // it is authoritative and the role is ignored entirely.
  adminEmails: ['360gav@gmail.com'],
  // GDPR Art. 25 (data protection by default): mask caller/callee digits in the
  // DERIVED analysis unless the uploader opts out per capture via the
  // X-Mask-Numbers header. The uploaded file itself is never altered.
  maskNumbersByDefault: true,
  // GDPR Art. 5(1)(e) (storage limitation): delete captures older than this.
  // 0 disables the sweep — which is a real choice, not a safe default, so it
  // is stated here rather than left implicit.
  captureRetentionDays: 0,
};

/**
 * Load data/config.json, merge in any missing default keys, and write it back
 * so the file on disk always shows the full current schema.
 * @returns {object} the effective config
 */
function loadConfig() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const file = path.join(DATA_DIR, 'config.json');
  const cfg = store.loadJson(file, {});
  let changed = !fs.existsSync(file);
  for (const key of Object.keys(CONFIG_DEFAULTS)) {
    if (!(key in cfg)) {
      cfg[key] = CONFIG_DEFAULTS[key];
      changed = true;
    }
  }
  if (changed) store.saveJson(file, cfg);
  return cfg;
}

const config = loadConfig();
auth.initAuth(DATA_DIR, config);
llm.initLlm(config);

// lib/kb.js keeps the config-guide library under <dataDir>/kb; initialise it at
// boot when the module is present. A missing kb module is not fatal.
let kbInitialised = false;
initKbIfPossible();

/**
 * Load lib/kb.js (if present) and run initKb(DATA_DIR) exactly once.
 * @returns {object|null} the kb module when it is usable, else null
 */
function initKbIfPossible() {
  const kb = optionalModule('./lib/kb');
  if (!kb) return null;
  if (kbInitialised) return kb;
  try {
    if (typeof kb.initKb === 'function') kb.initKb(DATA_DIR);
    kbInitialised = true;
    return kb;
  } catch (e) {
    console.warn('hiccup: initKb failed (' + (e && e.message) +
      ') — /api/kb/* will answer 501');
    return null;
  }
}

// lib/teams.js + lib/projects.js (Wave 3) get the same graceful-optional-
// require treatment as lib/kb.js above.
let teamsInitialised = false;
let projectsInitialised = false;
initTeamsIfPossible();
initProjectsIfPossible();

/**
 * Load lib/teams.js (if present) and run initTeams(DATA_DIR) exactly once.
 * @returns {object|null} the teams module when it is usable, else null
 */
function initTeamsIfPossible() {
  const teams = optionalModule('./lib/teams');
  if (!teams) return null;
  if (teamsInitialised) return teams;
  try {
    if (typeof teams.initTeams === 'function') teams.initTeams(DATA_DIR);
    teamsInitialised = true;
    return teams;
  } catch (e) {
    console.warn('hiccup: initTeams failed (' + (e && e.message) +
      ') — /api/team/* will answer 501 and every account behaves teamless');
    return null;
  }
}

/**
 * Load lib/projects.js (if present) and run initProjects(DATA_DIR) exactly once.
 * @returns {object|null} the projects module when it is usable, else null
 */
function initProjectsIfPossible() {
  const projects = optionalModule('./lib/projects');
  if (!projects) return null;
  if (projectsInitialised) return projects;
  try {
    if (typeof projects.initProjects === 'function') projects.initProjects(DATA_DIR);
    projectsInitialised = true;
    return projects;
  } catch (e) {
    console.warn('hiccup: initProjects failed (' + (e && e.message) +
      ') — /api/projects/* will answer 501');
    return null;
  }
}

const PORT = process.env.PORT ? Number(process.env.PORT) : config.port;
const HOST = process.env.HOST || config.host;
const PUBLIC_DIR = path.join(__dirname, 'public');
const JSON_BODY_LIMIT = 1024 * 1024; // 1 MB for JSON bodies
const SESSION_COOKIE = 'hiccup_session';

// ---------------------------------------------------------------------------
// Small HTTP helpers
// ---------------------------------------------------------------------------

/**
 * Write a JSON response with status `code`.
 * @param {http.ServerResponse} res
 * @param {number} code HTTP status
 * @param {*} obj JSON-serialisable body
 */
function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

/**
 * Buffer a request body up to `maxBytes`. Rejects with err.code='TOO_LARGE'
 * when the declared or actual size exceeds the cap.
 * @param {http.IncomingMessage} req
 * @param {number} maxBytes
 * @returns {Promise<Buffer>}
 */
function readRawBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > maxBytes) {
      const err = new Error('body too large');
      err.code = 'TOO_LARGE';
      req.resume(); // drain what arrives so the response can go out
      reject(err);
      return;
    }
    const chunks = [];
    let size = 0;
    let done = false;
    req.on('data', (chunk) => {
      if (done) return;
      size += chunk.length;
      if (size > maxBytes) {
        done = true;
        const err = new Error('body too large');
        err.code = 'TOO_LARGE';
        reject(err);
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!done) { done = true; resolve(Buffer.concat(chunks)); }
    });
    req.on('error', (e) => {
      if (!done) { done = true; reject(e); }
    });
  });
}

/**
 * Read + parse a JSON request body (1 MB cap). Rejects with err.code
 * 'TOO_LARGE' or 'BAD_JSON'.
 * @param {http.IncomingMessage} req
 * @returns {Promise<object>}
 */
async function readJsonBody(req) {
  const buf = await readRawBody(req, JSON_BODY_LIMIT);
  try {
    const obj = JSON.parse(buf.toString('utf8') || '{}');
    if (!obj || typeof obj !== 'object') throw new Error('not an object');
    return obj;
  } catch {
    const err = new Error('invalid JSON body');
    err.code = 'BAD_JSON';
    throw err;
  }
}

/**
 * Map a readRawBody/readJsonBody rejection to an HTTP error response.
 * @param {http.ServerResponse} res
 * @param {Error & {code?: string}} e
 */
function sendBodyError(res, e) {
  if (e && e.code === 'TOO_LARGE') {
    res.setHeader('Connection', 'close');
    sendJson(res, 413, { error: 'request body too large' });
  } else if (e && e.code === 'BAD_JSON') {
    sendJson(res, 400, { error: 'invalid JSON body' });
  } else {
    sendJson(res, 400, { error: 'could not read request body' });
  }
}

/**
 * Parse the Cookie header into a name→value object.
 * @param {http.IncomingMessage} req
 * @returns {Object<string,string>}
 */
function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  for (const part of raw.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim();
    if (name) out[name] = part.slice(eq + 1).trim();
  }
  return out;
}

/**
 * Parse the request's query string. Never throws.
 * @param {http.IncomingMessage} req
 * @returns {URLSearchParams}
 */
function queryParams(req) {
  const url = req.url || '';
  const i = url.indexOf('?');
  try {
    return new URLSearchParams(i === -1 ? '' : url.slice(i + 1));
  } catch {
    return new URLSearchParams('');
  }
}

/**
 * First non-empty trimmed string among the arguments, capped at 120 chars.
 * @param {...*} vals candidates (headers, query values, body fields)
 * @returns {string|null}
 */
function firstString(...vals) {
  for (const v of vals) {
    if (typeof v !== 'string') continue;
    const t = v.trim();
    if (t) return t.slice(0, 120);
  }
  return null;
}

/**
 * Sanitise a client-supplied X-Filename header: strip any directory part and
 * non-printable-ASCII bytes, cap the length. Returns '' when nothing usable.
 * @param {*} raw the header value
 * @returns {string}
 */
function cleanFilename(raw) {
  return String(raw || '')
    .trim()
    .replace(/^.*[\\/]/, '')
    .replace(/[^ -~]/g, '')
    .slice(0, 200)
    .trim();
}

/**
 * Set the session cookie: HttpOnly, SameSite=Lax, Path=/, Secure when
 * config.baseUrl is https, Expires from the session's expiresAt.
 * @param {http.ServerResponse} res
 * @param {string} token
 * @param {number|string} [expiresAt] epoch ms or ISO date string
 */
function setSessionCookie(res, token, expiresAt) {
  const parts = [SESSION_COOKIE + '=' + token, 'HttpOnly', 'SameSite=Lax', 'Path=/'];
  if (expiresAt != null) {
    const d = new Date(expiresAt);
    if (!isNaN(d.getTime())) parts.push('Expires=' + d.toUTCString());
  }
  if (String(config.baseUrl || '').startsWith('https')) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

/**
 * Clear the session cookie.
 * @param {http.ServerResponse} res
 */
function clearSessionCookie(res) {
  const parts = [SESSION_COOKIE + '=', 'HttpOnly', 'SameSite=Lax', 'Path=/',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT', 'Max-Age=0'];
  if (String(config.baseUrl || '').startsWith('https')) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

/**
 * Resolve the signed-in user from the session cookie, or answer 401 and
 * return null (caller must then stop).
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 * @returns {object|null} the user, or null after a 401 was written
 */
function requireAuth(req, res) {
  const token = parseCookies(req)[SESSION_COOKIE];
  const sess = token ? auth.getSession(token) : null;
  if (!sess || !sess.user) {
    sendJson(res, 401, { error: 'sign in required' });
    return null;
  }
  // Wave 3: a suspended team member is rejected exactly as if they had no
  // session at all. lib/auth.js knows nothing about teams -- this stays a
  // server.js-level decoration over the session check above, never a change
  // to lib/auth.js itself.
  const teams = initTeamsIfPossible();
  let suspended = false;
  if (teams && typeof teams.isSuspended === 'function') {
    try { suspended = teams.isSuspended(sess.user.id); } catch { suspended = false; }
  }
  if (suspended) {
    clearSessionCookie(res);
    sendJson(res, 401, { error: 'sign in required' });
    return null;
  }
  return sess.user;
}

/**
 * Resolve the storage account id for a signed-in user: the team's shared
 * dataRootId when the user is on a team, otherwise the user's own id
 * unchanged (teamless behaviour is byte-for-byte identical to pre-Wave-3
 * hiccup). ARCHITECTURE.md's Wave 3 hard rule: every handler that touches
 * captures/KB docs/projects resolves this exactly ONCE at the top and uses
 * the result — never `user.id` again — for every storage call in that
 * handler. Degrades to the raw id when lib/teams.js is not deployed.
 * @param {string} userId
 * @returns {string}
 */
function resolveAccountUid(userId) {
  const teams = initTeamsIfPossible();
  if (!teams || typeof teams.accountUid !== 'function') return String(userId);
  try {
    return teams.accountUid(userId);
  } catch {
    return String(userId);
  }
}

/**
 * Public projection of a user record (never leak passwordHash).
 * @param {object} u
 * @returns {object}
 */
function sanitizeUser(u) {
  return {
    id: u.id,
    email: u.email,
    name: u.name != null ? u.name : null,
    role: u.role,
    // 'free' for any record read before this field existed — same rule as
    // lib/auth.js's own _publicUser(), which this duplicates rather than
    // reuses (this file gets `user` from auth.getSession(), already a public
    // view by the time it gets here). An absent plan must read as the
    // least-privileged one, never as an accidental grant.
    plan: u.plan === 'paid' ? 'paid' : 'free',
    createdAt: u.createdAt,
    lastLoginAt: u.lastLoginAt != null ? u.lastLoginAt : null,
  };
}

/**
 * Find an existing user by email (lowercased). Prefers an auth-module lookup
 * export when one exists; otherwise falls back to reading data/users.json
 * (tolerating array, {users:[...]}, or id-keyed-object layouts).
 * @param {string} email
 * @returns {object|null}
 */
function findUserByEmail(email) {
  const needle = String(email || '').trim().toLowerCase();
  if (!needle) return null;
  if (typeof auth.getUserByEmail === 'function') return auth.getUserByEmail(needle) || null;
  if (typeof auth.findUserByEmail === 'function') return auth.findUserByEmail(needle) || null;
  const data = store.loadJson(path.join(DATA_DIR, 'users.json'), null);
  let list = [];
  if (Array.isArray(data)) list = data;
  else if (data && Array.isArray(data.users)) list = data.users;
  else if (data && typeof data === 'object') list = Object.values(data);
  for (const u of list) {
    if (u && typeof u.email === 'string' && u.email.toLowerCase() === needle) return u;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Static files
// ---------------------------------------------------------------------------

const STATIC_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json',
};

/**
 * Serve one named file from public/ (used for / and /app).
 * @param {http.ServerResponse} res
 * @param {string} name file name inside public/
 */
function servePublicFile(res, name) {
  const file = path.join(PUBLIC_DIR, name);
  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('hiccup: public/' + name + ' is not deployed yet');
      return;
    }
    res.writeHead(200, { 'Content-Type': STATIC_TYPES['.html'], 'Cache-Control': 'no-cache' });
    res.end(data);
  });
}

/**
 * Serve one of the Wave-2 pages (public/hmr.html, public/kb.html). These are
 * built by another agent, so a missing file answers a clear JSON 404 rather
 * than a bare text 404 — the fetch-driven UI can then show the reason.
 * @param {http.ServerResponse} res
 * @param {string} name file name inside public/
 */
function servePublicPage(res, name) {
  const file = path.join(PUBLIC_DIR, name);
  fs.readFile(file, (err, data) => {
    if (err) {
      sendJson(res, 404, {
        error: 'hiccup: public/' + name + ' is not deployed on this server yet',
      });
      return;
    }
    res.writeHead(200, { 'Content-Type': STATIC_TYPES['.html'], 'Cache-Control': 'no-cache' });
    res.end(data);
  });
}

/**
 * Static file server for public/*: extension whitelist + normalize-based
 * traversal guard. Anything outside the whitelist or the directory is a 404.
 * @param {http.ServerResponse} res
 * @param {string} urlPath the request path (no query string)
 */
function serveStatic(res, urlPath) {
  let rel;
  try {
    rel = decodeURIComponent(urlPath);
  } catch {
    rel = null;
  }
  if (rel) rel = rel.replace(/^[/\\]+/, '');
  if (!rel || rel.includes('\0') || rel.includes(':')) return notFoundText(res);
  const normalized = path.normalize(rel);
  if (normalized.startsWith('..') || path.isAbsolute(normalized)) return notFoundText(res);
  const ext = path.extname(normalized).toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(STATIC_TYPES, ext)) return notFoundText(res);
  const file = path.join(PUBLIC_DIR, normalized);
  fs.readFile(file, (err, data) => {
    if (err) return notFoundText(res);
    // no-cache (not no-store): the browser may still keep a copy, but must
    // revalidate with the server before using it. hiccup's HTML/JS/CSS have
    // no content-hashed filenames, so without this a browser's heuristic
    // caching can silently serve a pre-deploy version of the app for hours
    // after a real update -- exactly the "the UI looks wrong/stale" bug
    // class this exists to prevent.
    res.writeHead(200, { 'Content-Type': STATIC_TYPES[ext], 'Cache-Control': 'no-cache' });
    res.end(data);
  });
}

/** @param {http.ServerResponse} res plain-text 404 */
function notFoundText(res) {
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('not found');
}

// ---------------------------------------------------------------------------
// The crawlable surface
// ---------------------------------------------------------------------------

/**
 * Clean URL -> file under public/, for every page a signed-out visitor can
 * usefully read. This is the whole of hiccup that belongs in a search index:
 * the workbench, HMR, the config guides and /team all need a session, and a
 * crawler that reaches them gets a login redirect and an empty shell.
 *
 * It is one table rather than another chain of ifs because /sitemap.xml is
 * generated from the same entries — a page added here becomes routable AND
 * crawlable in a single edit, so the router and the sitemap cannot drift apart.
 * A Map rather than an object literal, so that a request for /__proto__ or
 * /constructor resolves to nothing at all.
 */
const PUBLIC_PAGES = new Map([
  ['/', 'index.html'],
  ['/privacy', 'privacy.html'],
  ['/subscribe', 'subscribe.html'],
  ['/sip', 'sip/index.html'],
  ['/sip/488-not-acceptable-here', 'sip/488-not-acceptable-here.html'],
  ['/sip/408-request-timeout', 'sip/408-request-timeout.html'],
  ['/sip/486-busy-here', 'sip/486-busy-here.html'],
  ['/sip/one-way-audio', 'sip/one-way-audio.html'],
  ['/sip/retransmissions', 'sip/retransmissions.html'],
]);

/**
 * The absolute origin to put in crawler-facing documents.
 *
 * config.baseUrl already knows hiccup's public name — it is what team invite
 * links are built from (lib/teams.js) — so reuse it rather than reading the
 * request's Host header, which is client-controlled and would let a visitor
 * dictate the hostnames in our own sitemap.
 * @returns {string} origin with no trailing slash
 */
function publicOrigin() {
  const configured = String(config.baseUrl || '').trim().replace(/\/+$/, '');
  return configured || 'http://' + HOST + ':' + PORT;
}

/**
 * Escape text for XML character data. Only needed because publicOrigin() comes
 * out of an operator-edited config.json and is not guaranteed to be clean.
 * @param {string} s
 * @returns {string}
 */
function xmlEscape(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * GET /robots.txt — the crawl policy.
 *
 * Note what this is not: every path below is already behind requireAuth, and
 * robots.txt is advisory in any case. It exists to keep auth-walled URLs out of
 * search results — where they are noise for the searcher and a dead end for the
 * crawler — not to protect them.
 * @param {http.ServerResponse} res
 */
function handleRobots(res) {
  const body = [
    '# hiccup — the analyser needs a session. Only the landing page and the',
    '# /sip reference are worth crawling.',
    'User-agent: *',
    'Disallow: /api/',
    'Disallow: /admin/',
    'Disallow: /app',
    'Disallow: /hmr',
    'Disallow: /kb',
    'Disallow: /team',
    'Disallow: /settings',
    // A single-use token in the query string. Nothing to index, and an indexed
    // invite URL would be an indexed credential.
    'Disallow: /accept-invite',
    // Last, and deliberately so: a bare "Allow: /" placed above the Disallow
    // lines would undo every one of them on a first-match-wins crawler.
    'Allow: /',
    '',
    'Sitemap: ' + publicOrigin() + '/sitemap.xml',
    '',
  ].join('\n');
  res.writeHead(200, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-cache',
  });
  res.end(body);
}

/**
 * GET /sitemap.xml — PUBLIC_PAGES rendered as a urlset.
 *
 * lastmod comes from each file's mtime rather than a literal date, because a
 * literal starts lying the day after it is typed and nothing in a deploy would
 * ever remind anyone to update it. Deploys here are file copies, so the mtime is
 * the one timestamp that cannot disagree with what is actually being served. A
 * page whose file is missing is dropped rather than advertised as a 404.
 *
 * The stat calls are synchronous: there are seven of them, on a route a crawler
 * visits about once a day, and the async plumbing would cost more to read than
 * it could ever save.
 * @param {http.ServerResponse} res
 */
function handleSitemap(res) {
  const origin = publicOrigin();
  const entries = [];
  for (const [urlPath, file] of PUBLIC_PAGES) {
    let stat;
    try {
      stat = fs.statSync(path.join(PUBLIC_DIR, file));
    } catch {
      continue;
    }
    entries.push('  <url>\n' +
      '    <loc>' + xmlEscape(origin + urlPath) + '</loc>\n' +
      '    <lastmod>' + stat.mtime.toISOString().slice(0, 10) + '</lastmod>\n' +
      '  </url>');
  }
  const body = '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
    entries.join('\n') + '\n' +
    '</urlset>\n';
  res.writeHead(200, {
    'Content-Type': 'application/xml; charset=utf-8',
    'Cache-Control': 'no-cache',
  });
  res.end(body);
}

// ---------------------------------------------------------------------------
// Captures
// ---------------------------------------------------------------------------

/**
 * Count findings by severity for meta.findingCounts.
 * @param {Array<{severity:string}>} findings
 * @returns {{crit:number,warn:number,notice:number,info:number}}
 */
function countFindings(findings) {
  const counts = { crit: 0, warn: 0, notice: 0, info: 0 };
  for (const f of findings || []) {
    if (f && Object.prototype.hasOwnProperty.call(counts, f.severity)) counts[f.severity]++;
  }
  return counts;
}

/**
 * Resolve a capture directory for this account, or null when the id is
 * invalid or the capture does not exist (ownership is structural: captures
 * live under the account's directory only).
 * @param {string} uid resolved account id (teams.accountUid(user.id) — see
 *   the Wave 3 hard rule; never a raw user.id once a handler has computed uid)
 * @param {string} captureId
 * @returns {string|null}
 */
function findCaptureDir(uid, captureId) {
  let dir;
  try {
    dir = store.captureDir(DATA_DIR, String(uid), String(captureId || ''));
  } catch {
    return null;
  }
  return fs.existsSync(dir) ? dir : null;
}

/** POST /api/captures — raw upload, synchronous analysis. */
async function handleUpload(req, res, user) {
  if (!analyzeCapture) {
    sendJson(res, 501, { error: 'analysis engine not deployed on this server yet' });
    return;
  }
  const uid = resolveAccountUid(user.id);

  // Wave 3: an optional X-Project-Id header. Validated (shape THEN ownership,
  // via resolveOwnedProjectId) before the upload proceeds — this is the same
  // check every project-id-accepting route must do, done here before any
  // bytes are read off the wire.
  let projectId = null;
  const rawProjectHeader = req.headers['x-project-id'];
  if (rawProjectHeader != null && String(rawProjectHeader).trim() !== '') {
    projectId = resolveOwnedProjectId(uid, String(rawProjectHeader).trim());
    if (!projectId) {
      sendJson(res, 404, { error: 'that project was not found' });
      return;
    }
  }

  const maxBytes = (Number(config.maxUploadMb) || CONFIG_DEFAULTS.maxUploadMb) * 1024 * 1024;
  let buf;
  try {
    buf = await readRawBody(req, maxBytes);
  } catch (e) {
    if (e && e.code === 'TOO_LARGE') {
      res.setHeader('Connection', 'close');
      sendJson(res, 413, { error: 'upload exceeds the ' + config.maxUploadMb + ' MB limit' });
    } else {
      sendJson(res, 400, { error: 'could not read upload' });
    }
    return;
  }
  if (!buf.length) {
    sendJson(res, 400, { error: 'empty upload' });
    return;
  }
  const filename = cleanFilename(req.headers['x-filename']) || 'capture.bin';

  const id = store.newCaptureId();
  const dir = store.captureDir(DATA_DIR, uid, id);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'original.bin'), buf);

  // GDPR: caller/callee masking. lib/analyze.js has always had
  // redactNumbersInMessage() behind an opts.redactNumbers flag, but nothing
  // ever set it — the masking was written and then left unreachable. The
  // header lets the uploader decide per capture; config.maskNumbersByDefault
  // decides when they say nothing (Art. 25, data protection BY DEFAULT).
  //
  // Note this only masks the DERIVED analysis. original.bin above is the
  // user's own unmodified file and is never rewritten — masking a trace you
  // uploaded yourself, in place, would be destroying your own evidence.
  const maskHeader = req.headers['x-mask-numbers'];
  const maskNumbers = (maskHeader == null || String(maskHeader).trim() === '')
    ? config.maskNumbersByDefault !== false
    : /^(1|true|yes|on)$/i.test(String(maskHeader).trim());

  let analysis;
  try {
    analysis = await analyzeCapture(buf, { redactNumbers: maskNumbers });
  } catch (e) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    sendJson(res, 422, { error: (e && e.userMessage) || 'could not parse this file' });
    return;
  }

  const meta = {
    id,
    filename,
    uploadedAt: new Date().toISOString(),
    sizeBytes: buf.length,
    maskedNumbers: maskNumbers,   // shown in the UI so nobody wonders why numbers are "…"
    stats: analysis.stats,
    findingCounts: countFindings(analysis.findings),
    projectId,
  };
  store.saveJson(path.join(dir, 'meta.json'), meta);
  store.saveJson(path.join(dir, 'analysis.json'), analysis);
  sendJson(res, 200, { id, meta });
}

/**
 * Load a capture's stored analysis for this account.
 * @param {string} uid resolved account id (see the Wave 3 hard rule)
 * @param {string} captureId
 * @returns {object|null} AnalysisJSON, or null when missing/unreadable
 */
function loadAnalysis(uid, captureId) {
  const dir = findCaptureDir(uid, captureId);
  if (!dir) return null;
  const analysis = store.loadJson(path.join(dir, 'analysis.json'), null);
  return analysis && typeof analysis === 'object' ? analysis : null;
}

// ---------------------------------------------------------------------------
// Advice (Wave 2) — GET /api/captures/:id/advice
// ---------------------------------------------------------------------------

/**
 * GET /api/captures/:id/advice — the Advice array from the stored analysis.
 * Analyses written before the advisor pass existed are topped up on the fly
 * when lib/advisor.js is available; otherwise the list is simply empty.
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {object} user
 * @param {string} captureId
 */
function handleAdvice(req, res, user, captureId) {
  const uid = resolveAccountUid(user.id);
  const analysis = loadAnalysis(uid, captureId);
  if (!analysis) {
    sendJson(res, 404, { error: 'capture not found' });
    return;
  }
  if (Array.isArray(analysis.advice)) {
    sendJson(res, 200, { advice: analysis.advice });
    return;
  }
  const advisor = optionalModule('./lib/advisor');
  if (!advisor || typeof advisor.buildAdvice !== 'function') {
    sendJson(res, 200, { advice: [] });
    return;
  }
  try {
    const out = advisor.buildAdvice(analysis, { retrieve: makeKbRetriever(uid) });
    sendJson(res, 200, { advice: (out && Array.isArray(out.advice)) ? out.advice : [] });
  } catch (e) {
    console.warn('hiccup: buildAdvice failed for capture ' + captureId + ': ' +
      (e && e.message));
    sendJson(res, 200, { advice: [] });
  }
}

// ---------------------------------------------------------------------------
// HMR (Wave 2) — POST /api/hmr/analyze
// ---------------------------------------------------------------------------

/** Vendors every rule is rendered for, per the HmrRule contract. */
const HMR_VENDORS = ['oracle-acme', 'audiocodes', 'ribbon'];

/**
 * POST /api/hmr/generate {description, name?, vendors?} — plain English -> a
 * draft HMR rule, per lib/hmr-generate.js.
 *
 * Deliberately thin: this route does no interpretation of its own. Every
 * decision about what the description means lives in hmr-generate.js, which
 * is unit-tested on its own; this handler's only job is body parsing and
 * shaping the response the same way handleHmrAnalyze() does, so the client
 * does not need two different result shapes for a parsed rule and a
 * generated one.
 */
async function handleHmrGenerate(req, res) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }

  const gen = optionalModule('./lib/hmr-generate');
  if (!gen || typeof gen.generateRule !== 'function') {
    sendJson(res, 501, { error: 'the rule generator is not deployed on this server yet' });
    return;
  }

  const description = typeof body.description === 'string' ? body.description : '';
  if (!description.trim()) {
    sendJson(res, 400, { error: 'description (what the rule should do, in English) is required' });
    return;
  }

  let vendors;
  if (Array.isArray(body.vendors) && body.vendors.length) {
    vendors = body.vendors.filter((v) => HMR_VENDORS.indexOf(v) !== -1);
    if (!vendors.length) {
      sendJson(res, 400, { error: 'vendors must be a subset of ' + HMR_VENDORS.join(', ') });
      return;
    }
  }

  const name = typeof body.name === 'string' && body.name.trim() ? body.name.trim().slice(0, 60) : undefined;

  let result;
  try {
    result = gen.generateRule(description, { name, vendors });
  } catch (e) {
    // generateRule() is written to never throw — this is a last-resort net,
    // not an expected path, and it must not 500 on a user's typed sentence.
    sendJson(res, 422, { error: 'could not process that description' });
    return;
  }

  sendJson(res, 200, result);
}

/**
 * POST /api/hmr/analyze {text, captureId?} — parse an SBC config excerpt into
 * the HMR IR, attach explainRule output and all three vendor renderings per
 * rule, and (when captureId is given) match the rules against that capture's
 * stored analysis.
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {object} user
 */
async function handleHmrAnalyze(req, res, user) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }
  const uid = resolveAccountUid(user.id);
  const hmr = optionalModule('./lib/hmr');
  if (!hmr || typeof hmr.parseConfig !== 'function') {
    sendJson(res, 501, {
      error: 'the config-manipulation engine is not deployed on this server yet',
    });
    return;
  }
  const text = typeof body.text === 'string' ? body.text : '';
  if (!text.trim()) {
    sendJson(res, 400, { error: 'text (an SBC config excerpt) is required' });
    return;
  }
  let parsed;
  try {
    parsed = hmr.parseConfig(text) || {};
  } catch (e) {
    sendJson(res, 422, { error: (e && e.userMessage) || 'could not read this config' });
    return;
  }
  const rules = Array.isArray(parsed.rules) ? parsed.rules : [];

  const ruleEntries = rules.map((rule) => {
    let explanation = null;
    if (typeof hmr.explainRule === 'function') {
      try { explanation = hmr.explainRule(rule) || null; } catch { explanation = null; }
    }
    const rendered = {};
    for (const vendor of HMR_VENDORS) {
      let out = null;
      if (typeof hmr.renderRule === 'function') {
        try {
          const r = hmr.renderRule(rule, vendor);
          out = typeof r === 'string' ? r : (r == null ? null : String(r));
        } catch { out = null; }
      }
      rendered[vendor] = out;
    }
    return { rule, explanation, rendered };
  });

  let matches = null;
  const captureId = body.captureId ? String(body.captureId) : '';
  if (captureId) {
    const analysis = loadAnalysis(uid, captureId);
    if (!analysis) {
      sendJson(res, 404, { error: 'capture not found' });
      return;
    }
    matches = [];
    if (typeof hmr.matchAgainstAnalysis === 'function') {
      try {
        const m = hmr.matchAgainstAnalysis(rules, analysis);
        if (Array.isArray(m)) matches = m;
        else if (m && Array.isArray(m.matches)) matches = m.matches;
      } catch (e) {
        console.warn('hiccup: matchAgainstAnalysis failed: ' + (e && e.message));
      }
    }
  }

  sendJson(res, 200, {
    vendor: parsed.vendor || 'unknown',
    confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0,
    rules: ruleEntries,
    matches,
    warnings: Array.isArray(parsed.warnings) ? parsed.warnings : [],
  });
}

// ---------------------------------------------------------------------------
// Config-guide KB (Wave 2) — /api/kb/*
// ---------------------------------------------------------------------------

/**
 * Resolve lib/kb.js for a request, or answer 501 and return null. Every KB
 * route is per-user: the caller always passes the session user's id, so a
 * user can only ever see or delete their own documents.
 * @param {http.ServerResponse} res
 * @returns {object|null}
 */
function requireKb(res) {
  const kb = initKbIfPossible();
  if (!kb) {
    sendJson(res, 501, {
      error: 'the config-guide library is not deployed on this server yet',
    });
    return null;
  }
  return kb;
}

/**
 * Per-account KB search that never throws and never rejects.
 * @param {string} uid resolved account id (see the Wave 3 hard rule)
 * @param {string} q free-text query
 * @param {number} k max hits
 * @returns {Array<object>} searchKb hits (possibly empty)
 */
function kbSearchSafe(uid, q, k) {
  const kb = initKbIfPossible();
  if (!kb || typeof kb.searchKb !== 'function' || !q) return [];
  try {
    const hits = kb.searchKb(String(uid), String(q), k);
    return Array.isArray(hits) ? hits : [];
  } catch {
    return [];
  }
}

/**
 * Build the retriever lib/advisor.js expects: `retrieve(query)` -> KB hits.
 * Hits carry both the searchKb field names and the kbCitations names so
 * either convention works on the advisor side.
 * @param {string} uid resolved account id (see the Wave 3 hard rule)
 * @returns {function(string): Array<object>}
 */
function makeKbRetriever(uid) {
  return function retrieve(query) {
    return kbSearchSafe(uid, query, 3).map((h) => ({
      docId: h.docId,
      docTitle: h.docTitle,
      page: h.page,
      heading: h.heading,
      text: h.text,
      excerpt: typeof h.text === 'string' ? h.text.slice(0, 600) : h.text,
      score: h.score,
    }));
  };
}

/** POST /api/kb/docs — raw document body + X-Filename header. */
async function handleKbAdd(req, res, user) {
  const uid = resolveAccountUid(user.id);
  const kb = requireKb(res);
  if (!kb || typeof kb.addDoc !== 'function') {
    if (kb) sendJson(res, 501, { error: 'this build of lib/kb.js cannot add documents' });
    req.resume();
    return;
  }
  const maxBytes = (Number(config.maxUploadMb) || CONFIG_DEFAULTS.maxUploadMb) * 1024 * 1024;
  let buf;
  try {
    buf = await readRawBody(req, maxBytes);
  } catch (e) {
    if (e && e.code === 'TOO_LARGE') {
      res.setHeader('Connection', 'close');
      sendJson(res, 413, {
        error: 'document exceeds the ' + config.maxUploadMb + ' MB limit',
      });
    } else {
      sendJson(res, 400, { error: 'could not read upload' });
    }
    return;
  }
  if (!buf.length) {
    sendJson(res, 400, { error: 'empty upload' });
    return;
  }
  const filename = cleanFilename(req.headers['x-filename']) || 'guide.txt';
  const q = queryParams(req);
  const vendor = firstString(req.headers['x-vendor'], q.get('vendor'));
  const product = firstString(req.headers['x-product'], q.get('product'));
  let doc;
  try {
    doc = await kb.addDoc({ userId: uid, filename, buffer: buf, vendor, product });
  } catch (e) {
    sendJson(res, 422, { error: (e && e.userMessage) || 'could not read this document' });
    return;
  }
  sendJson(res, 200, {
    doc: Object.assign(
      { filename, vendor, product, sizeBytes: buf.length },
      (doc && typeof doc === 'object') ? doc : {}
    ),
  });
}

/**
 * POST /api/kb/link {url, title?, vendor?, product?} — register a link to a
 * vendor's own hosted guide instead of uploading a copy of it. See
 * lib/kb.js's addLink() header for why this exists in place of hiccup
 * fetching and indexing the page itself.
 */
async function handleKbAddLink(req, res, user) {
  const uid = resolveAccountUid(user.id);
  const kb = requireKb(res);
  if (!kb || typeof kb.addLink !== 'function') {
    if (kb) sendJson(res, 501, { error: 'this build of lib/kb.js cannot add links' });
    else req.resume();
    return;
  }
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }
  let link;
  try {
    link = kb.addLink({
      userId: uid,
      url: body && body.url,
      title: body && body.title,
      vendor: body && body.vendor,
      product: body && body.product,
    });
  } catch (e) {
    sendJson(res, 422, { error: (e && e.userMessage) || 'could not save that link' });
    return;
  }
  sendJson(res, 200, { doc: link });
}

/** GET /api/kb/docs — this account's documents. */
function handleKbList(req, res, user) {
  const uid = resolveAccountUid(user.id);
  const kb = requireKb(res);
  if (!kb) return;
  let docs = null;
  if (typeof kb.listDocs === 'function') {
    try { docs = kb.listDocs(uid); } catch { docs = null; }
  }
  sendJson(res, 200, Array.isArray(docs) ? docs : []);
}

/** DELETE /api/kb/docs/:id — scoped to this account (kb.deleteDoc is scoped by userId). */
async function handleKbDelete(req, res, user, docId) {
  const uid = resolveAccountUid(user.id);
  const kb = requireKb(res);
  if (!kb) return;
  if (typeof kb.deleteDoc !== 'function') {
    sendJson(res, 501, { error: 'this build of lib/kb.js cannot delete documents' });
    return;
  }
  let ok;
  try {
    ok = await kb.deleteDoc(uid, docId);
  } catch (e) {
    sendJson(res, 422, { error: (e && e.userMessage) || 'could not delete that document' });
    return;
  }
  if (!ok) {
    sendJson(res, 404, { error: 'document not found' });
    return;
  }
  sendJson(res, 200, { ok: true });
}

// ---------------------------------------------------------------------------
// Wave 6 — feedback
// See ARCHITECTURE.md "Wave 6 — In-app feedback with structural context".
// ---------------------------------------------------------------------------

let feedbackMod = null;
let feedbackTried = false;
/** lib/feedback.js, or null. Optional like every other Wave-2+ module. */
function requireFeedback(res) {
  if (!feedbackTried) {
    feedbackTried = true;
    try { feedbackMod = require('./lib/feedback'); } catch { feedbackMod = null; }
  }
  if (!feedbackMod) {
    sendJson(res, 501, { error: 'this build has no feedback module' });
    return null;
  }
  return feedbackMod;
}

let mailMod = null;
let mailTried = false;
function getMail() {
  if (!mailTried) {
    mailTried = true;
    try { mailMod = require('./lib/mail'); } catch { mailMod = null; }
  }
  return mailMod;
}

/**
 * Site-wide admin gate for every /admin/* surface.
 *
 * Two sources of truth, in this order:
 *   1. config.adminEmails — an explicit allow-list. When non-empty it is
 *      AUTHORITATIVE and role is ignored.
 *   2. lib/auth.js's role:'admin' — only consulted when the list is empty.
 *
 * The list wins because role:'admin' just means "signed up first"; on a fresh
 * user store that would silently hand the ops surface to whoever registers
 * next. An email allow-list says what is actually meant: this box is mine.
 *
 * Note this is NOT the team owner/admin role used elsewhere in this file —
 * a team admin administers their own team, not the whole box.
 */
function isSiteAdmin(user) {
  if (!user) return false;
  const allow = Array.isArray(config.adminEmails)
    ? config.adminEmails.map((e) => String(e || '').trim().toLowerCase()).filter(Boolean)
    : [];
  if (allow.length) return allow.indexOf(String(user.email || '').trim().toLowerCase()) !== -1;
  return user.role === 'admin';
}

function requireSiteAdmin(req, res) {
  const user = requireAuth(req, res);
  if (!user) return null;
  if (!isSiteAdmin(user)) {
    sendJson(res, 403, { error: 'admin only' });
    return null;
  }
  return user;
}

// Abuse here is noise in one inbox, not a security boundary, so an in-memory
// counter that resets on restart is proportionate.
/**
 * Best-effort client IP.
 *
 * hiccup binds 127.0.0.1 and is published through a Cloudflare tunnel, so
 * req.socket.remoteAddress is ALWAYS loopback and useless for rate limiting.
 * CF-Connecting-IP is set by Cloudflare and cannot be spoofed by a remote
 * caller here precisely BECAUSE the only routes to this process are the tunnel
 * and localhost -- there is no path by which an internet client reaches the
 * socket directly to forge it. If this server is ever bound to a public
 * interface, that assumption dies and this must be revisited.
 */
function clientIp(req) {
  const h = req.headers || {};
  const cf = h['cf-connecting-ip'];
  if (typeof cf === 'string' && cf.trim()) return cf.trim();
  const xff = h['x-forwarded-for'];
  if (typeof xff === 'string' && xff.trim()) return xff.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

/**
 * Sliding-window counter shared by the auth limiters below. Same shape as
 * feedbackRateLimited, kept generic because auth needs four buckets rather
 * than one. Memory-only and per-process: a restart forgives everyone, which
 * is an acceptable trade for a single-process app with no store dependency.
 * `peek` counts without recording, so a SUCCESSFUL login does not consume the
 * failure budget.
 */
function _slidingLimited(map, key, max, windowMs, peek) {
  const now = Date.now();
  const cut = now - windowMs;
  const hits = (map.get(key) || []).filter((t) => t > cut);
  if (hits.length >= max) { map.set(key, hits); return true; }
  if (!peek) hits.push(now);
  map.set(key, hits);
  return false;
}

// Login is limited on TWO axes on purpose. Per-email stops a focused attack on
// one known account from a botnet; per-IP stops a spray across many accounts
// from one host. Either alone leaves an obvious hole.
const LOGIN_MAX_PER_EMAIL = 8;
const LOGIN_MAX_PER_IP = 30;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const SIGNUP_MAX_PER_IP = 5;
const SIGNUP_WINDOW_MS = 60 * 60 * 1000;
const _loginByEmail = new Map();
const _loginByIp = new Map();
const _signupByIp = new Map();

/** Prune the auth maps so a long-running process cannot grow them without bound. */
function _sweepAuthLimiters() {
  const now = Date.now();
  for (const [map, win] of [[_loginByEmail, LOGIN_WINDOW_MS], [_loginByIp, LOGIN_WINDOW_MS],
    [_signupByIp, SIGNUP_WINDOW_MS]]) {
    for (const [k, arr] of map) {
      const live = arr.filter((t) => t > now - win);
      if (live.length) map.set(k, live); else map.delete(k);
    }
  }
}
setInterval(_sweepAuthLimiters, 10 * 60 * 1000).unref();

const FEEDBACK_MAX_PER_HOUR = 5;
const _feedbackHits = new Map();   // userId -> number[] (epoch ms)

function feedbackRateLimited(userId) {
  const now = Date.now();
  const cut = now - 3600000;
  const hits = (_feedbackHits.get(userId) || []).filter((t) => t > cut);
  if (hits.length >= FEEDBACK_MAX_PER_HOUR) { _feedbackHits.set(userId, hits); return true; }
  hits.push(now);
  _feedbackHits.set(userId, hits);
  return false;
}

/** POST /api/feedback {kind, rating, comment, context} */
async function handleFeedbackSubmit(req, res, user) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }
  const fb = requireFeedback(res);
  if (!fb) return;

  const comment = typeof body.comment === 'string' ? body.comment.trim() : '';
  if (!comment) {
    sendJson(res, 400, { error: 'comment is required' });
    return;
  }
  if (feedbackRateLimited(user.id)) {
    sendJson(res, 429, { error: 'too many submissions — try again later' });
    return;
  }

  let rec;
  try {
    // userId/email come from the SESSION, never from the body: a client must
    // not be able to file feedback as somebody else. context is re-sanitised
    // server-side by lib/feedback.js regardless of what the widget sent.
    rec = fb.save(DATA_DIR, {
      userId: user.id,
      email: user.email,
      kind: body.kind,
      rating: body.rating,
      comment,
      context: body.context,
    });
  } catch (e) {
    sendJson(res, 422, { error: (e && e.message) || 'could not save that feedback' });
    return;
  }
  sendJson(res, 200, { ok: true, id: rec.id });
}

// ---------------------------------------------------------------------------
// GDPR subject rights — Art. 15/20 (access + portability) and Art. 17 (erasure)
// ---------------------------------------------------------------------------

/**
 * GET /api/me/export — everything held about the signed-in user, as one JSON.
 *
 * Capture BYTES are deliberately excluded and listed as metadata instead: the
 * originals are already downloadable per capture, and inlining base64 pcaps
 * would turn a rights request into a multi-hundred-megabyte response. The
 * export says plainly that they are excluded and where to get them, so this is
 * a documented scope decision rather than a silent omission.
 */
function handleMeExport(req, res, user) {
  const uid = resolveAccountUid(user.id);
  const out = {
    exportedAt: new Date().toISOString(),
    note: 'Everything hiccup holds about this account. Capture FILE CONTENTS are ' +
      'not inlined — download them individually from /api/captures/:id/original.',
    account: sanitizeUser(user),
    storageAccountId: uid,
  };

  try { out.captures = store.listCaptures(DATA_DIR, uid); } catch { out.captures = []; }

  try {
    const projects = optionalModule('./lib/projects');
    out.projects = (projects && typeof projects.listProjects === 'function')
      ? projects.listProjects(uid) : [];
  } catch { out.projects = []; }

  try {
    const teams = initTeamsIfPossible();
    out.team = (teams && typeof teams.getTeamView === 'function')
      ? teams.getTeamView(user.id) : null;
  } catch { out.team = null; }

  try {
    const kb = optionalModule('./lib/kb');
    out.kbDocuments = (kb && typeof kb.listDocs === 'function') ? kb.listDocs(uid) : [];
  } catch { out.kbDocuments = []; }

  try {
    const fb = require('./lib/feedback');
    out.feedback = fb.list(DATA_DIR).filter((r) => r && r.userId === user.id);
  } catch { out.feedback = []; }

  res.writeHead(200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Disposition': 'attachment; filename="hiccup-export-' +
      new Date().toISOString().slice(0, 10) + '.json"',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(out, null, 2));
}

/**
 * DELETE /api/me {confirm:"DELETE"} — erase this account and its data.
 *
 * Requires an explicit typed confirmation because this is irreversible and
 * there is no undo anywhere in the system.
 *
 * SHARED-DATA HAZARD, handled deliberately: under Wave 3 a team's captures
 * live under the TEAM's accountUid, not the individual's. Deleting a team
 * member's account must therefore NOT delete the shared library — that would
 * let one departing member destroy their colleagues' data. So captures are
 * only removed when the user's storage account is their own (uid === user.id).
 * A team member who leaves has their membership and personal records removed;
 * the team's shared captures stay with the team.
 */
async function handleMeDelete(req, res, user) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }
  if (String(body && body.confirm) !== 'DELETE') {
    sendJson(res, 400, { error: 'send {"confirm":"DELETE"} to confirm this irreversible deletion' });
    return;
  }

  // OWNERSHIP CHECK FIRST, BEFORE ANYTHING IS ERASED.
  //
  // The `solo` test below is `uid === user.id`, and a team's dataRootId IS the
  // founding owner's user id -- so an owner deleting their account reads as
  // "solo" and falls straight into the capture-erase loop, destroying the
  // WHOLE TEAM's shared library. The shared-data hazard note above protects
  // ordinary members and never covered the owner.
  //
  // An owner of a team with other members must hand over first. Refusing here,
  // before a single byte is removed, is the difference between a clean 409 and
  // an account that keeps existing with its team's captures already gone.
  try {
    const teams = initTeamsIfPossible();
    if (teams && typeof teams.getAccountRole === 'function' &&
        teams.getAccountRole(user.id) === 'owner') {
      const view = teams.getTeamView(user.id);
      const others = ((view && view.members) || []).filter((m) => m && m.userId !== user.id);
      if (others.length) {
        // One fixed sentence, not a concatenation. The client runs _t() over
        // the error text, and a string with a count spliced into it can never
        // match a catalogue key -- so an interpolated message is permanently
        // English. The exact number is visible on the team page anyway.
        sendJson(res, 409, {
          error: 'You still own a team with other members. Transfer ownership to one of them first, then delete your account. Nothing has been deleted.',
          memberCount: others.length,
        });
        return;
      }
    }
  } catch { /* teams unavailable -> fall through; deletion is still allowed */ }

  const uid = resolveAccountUid(user.id);
  const solo = uid === user.id;
  const removed = { captures: 0, sharedLibraryKept: !solo, feedback: 0, team: false, account: false };

  if (solo) {
    try {
      for (const cap of store.listCaptures(DATA_DIR, uid)) {
        if (store.deleteCapture(DATA_DIR, uid, cap.id)) removed.captures++;
      }
    } catch { /* keep going — a partial erase still beats none */ }
  }

  try {
    const teams = initTeamsIfPossible();
    if (teams && typeof teams.leaveTeam === 'function' && teams.getTeamIdFor(user.id)) {
      // leaveTeam(), NOT removeMember(self, self): removeMember refuses a plain
      // member and refuses acting on yourself, so it could never express a
      // leave. It always threw here, the bare catch below swallowed it, and the
      // account was then deleted anyway -- leaving a member row pointing at a
      // user that no longer exists.
      removed.team = !!teams.leaveTeam(user.id).ok;
    }
  } catch (e) {
    // An owner cannot leave, and by this point the erase above has already run,
    // so failing silently would delete their data and keep their account. Stop
    // and tell them what to do instead.
    sendJson(res, 409, {
      error: (e && e.userMessage) ||
        'You own a team, so transfer ownership to another member before deleting your account.',
      erased: removed,
    });
    return;
  }

  try {
    const fb = require('./lib/feedback');
    const mine = fb.list(DATA_DIR).filter((r) => r && r.userId === user.id);
    // Feedback is retained but de-identified: the comment is operationally
    // useful to keep, the person behind it is not. Erasure of the personal
    // data is what Art. 17 requires, not destruction of the observation.
    for (const r of mine) {
      if (typeof fb.anonymise === 'function') fb.anonymise(DATA_DIR, r.id);
      removed.feedback++;
    }
  } catch { /* best effort */ }

  try {
    if (typeof auth.deleteUser === 'function') removed.account = !!auth.deleteUser(user.id);
  } catch { /* reported below */ }

  // A deleted account's email must not stay in config.adminEmails: left
  // behind, it is a reclaimable admin slot — anyone who later registers that
  // exact email inherits superuser access instantly. This was a real,
  // adversarial-review-confirmed privilege-escalation path (grant yourself
  // superuser, delete your account via this exact route, re-register the
  // same email). pruneEmail() never refuses, even if this is the sole
  // remaining admin's own account — GDPR erasure is the account holder's
  // right regardless of admin status; see lib/adminlist.js's header for why
  // that tradeoff is accepted rather than blocking the deletion.
  if (removed.account) {
    try {
      const pruned = adminlist.pruneEmail(config.adminEmails, user.email);
      if (pruned.changed) {
        const prevEmails = config.adminEmails;
        config.adminEmails = pruned.adminEmails;
        try {
          store.saveJson(path.join(DATA_DIR, 'config.json'), config);
        } catch {
          config.adminEmails = prevEmails;
        }
      }
    } catch { /* best effort — the account is already gone either way */ }
  }

  clearSessionCookie(res);
  sendJson(res, 200, {
    ok: true,
    removed,
    note: removed.account
      ? 'Account deleted.'
      : 'Data removed, but the account record could not be deleted automatically — ' +
        'contact the administrator to finish erasure.',
  });
}

/**
 * DELETE /api/me/data {confirm:"ERASE"} — erase this account's captures,
 * projects and library documents, keeping the account, login and (if on one)
 * team membership intact.
 *
 * The distinct confirm word ("ERASE" here vs. "DELETE" for /api/me) is
 * deliberate, not decoration: a mistyped confirmation must not silently fall
 * through into the OTHER irreversible action next to it on the settings page.
 *
 * Same shared-library hazard as handleMeDelete, same fix: only erase when
 * this account's storage is solo (uid === user.id). A team member's captures
 * live under the TEAM's accountUid, so this is a no-op for them beyond
 * whatever they hold that is genuinely theirs — nothing, today, since
 * projects and captures are both stored against the resolved account.
 */
async function handleMeDataDelete(req, res, user) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }
  if (String(body && body.confirm) !== 'ERASE') {
    sendJson(res, 400, { error: 'send {"confirm":"ERASE"} to confirm erasing your data' });
    return;
  }

  const uid = resolveAccountUid(user.id);
  const solo = uid === user.id;
  const removed = { captures: 0, projects: 0, kbDocuments: 0, sharedLibraryKept: !solo };

  if (solo) {
    try {
      for (const cap of store.listCaptures(DATA_DIR, uid)) {
        if (store.deleteCapture(DATA_DIR, uid, cap.id)) removed.captures++;
      }
    } catch { /* keep going — a partial erase still beats none */ }

    try {
      const projects = optionalModule('./lib/projects');
      if (projects && typeof projects.listProjects === 'function' && typeof projects.deleteProject === 'function') {
        for (const p of projects.listProjects(uid)) {
          if (p && projects.deleteProject(uid, p.id)) removed.projects++;
        }
      }
    } catch { /* best effort */ }

    try {
      const kb = optionalModule('./lib/kb');
      if (kb && typeof kb.listDocs === 'function' && typeof kb.deleteDoc === 'function') {
        for (const d of kb.listDocs(uid)) {
          if (d && kb.deleteDoc(uid, d.id)) removed.kbDocuments++;
        }
      }
    } catch { /* best effort */ }
  }

  sendJson(res, 200, {
    ok: true,
    removed,
    note: solo
      ? 'Your captures, projects and library documents have been erased. Your account stays signed in.'
      : 'Your account is on a shared team library, so there is nothing solely yours to erase here — ' +
        'leave the team (in Delete account, or from the team page) to stop sharing it.',
  });
}

/** Recursive byte total for a directory. Bounded so it cannot walk forever. */
function dirSize(p, depth) {
  let total = 0;
  let files = 0;
  if ((depth || 0) > 6) return { bytes: 0, files: 0 };
  let entries;
  try { entries = fs.readdirSync(p, { withFileTypes: true }); } catch { return { bytes: 0, files: 0 }; }
  for (const e of entries) {
    const full = path.join(p, e.name);
    try {
      if (e.isDirectory()) {
        const sub = dirSize(full, (depth || 0) + 1);
        total += sub.bytes; files += sub.files;
      } else if (e.isFile()) {
        total += fs.statSync(full).size; files += 1;
      }
    } catch { /* a file vanishing mid-walk is not an error worth failing on */ }
  }
  return { bytes: total, files };
}

/**
 * GET /api/admin/status — the ops view.
 *
 * Deliberately reports CONFIGURED/NOT CONFIGURED for anything sensitive rather
 * than the value: no SMTP password, no Google client secret, no session
 * tokens. An admin page is still a web page, and a screenshot of it should
 * never be a credential leak.
 */
function handleAdminStatus(req, res, user) {
  const out = {
    app: 'hiccup',
    version: VERSION,
    node: process.version,
    platform: process.platform,
    pid: process.pid,
    uptimeSeconds: Math.round(process.uptime()),
    memoryMb: Math.round(process.memoryUsage().rss / 1048576),
    now: new Date().toISOString(),
    dataDir: DATA_DIR,
    you: { email: user.email, id: user.id, role: user.role || 'user' },
    config: {
      baseUrl: config.baseUrl,
      port: PORT,
      host: HOST,
      maxUploadMb: config.maxUploadMb,
      preferredModels: config.preferredModels,
      digestRecipient: config.digestRecipient || null,
      adminEmails: Array.isArray(config.adminEmails) ? config.adminEmails : [],
      googleSignIn: config.googleClientId ? 'configured' : 'not configured',
    },
    engine: { analysis: !!analyzeCapture },
    llm: llm.getLlmStatus(),
  };

  try { out.users = auth.countUsers(); } catch { out.users = null; }

  try {
    const capRoot = store.capturesRoot(DATA_DIR);
    const accounts = fs.existsSync(capRoot) ? fs.readdirSync(capRoot) : [];
    let captures = 0;
    for (const a of accounts) {
      try { captures += fs.readdirSync(path.join(capRoot, a)).length; } catch { /* skip */ }
    }
    out.captures = { accounts: accounts.length, total: captures };
  } catch { out.captures = null; }

  try {
    const d = dirSize(DATA_DIR, 0);
    out.disk = { bytes: d.bytes, mb: Math.round(d.bytes / 1048576 * 10) / 10, files: d.files };
  } catch { out.disk = null; }

  try {
    const fb = require('./lib/feedback');
    const items = fb.list(DATA_DIR);
    out.feedback = {
      total: items.length,
      unread: items.filter((r) => !r.read).length,
      last7d: fb.since(DATA_DIR, 7 * 24 * 3600 * 1000).length,
      digest: fb.getDigestState(DATA_DIR),
      dueNow: fb.digestDue(DATA_DIR, new Date()),
    };
  } catch { out.feedback = null; }

  const mail = getMail();
  out.mail = { configured: !!(mail && mail.isConfigured(DATA_DIR)) };

  sendJson(res, 200, out);
}

/**
 * GET /api/admin/users — every account, for the site-admin user-management
 * panel. Each row is annotated with `isSuperuser` computed through the exact
 * same isSiteAdmin() check the real gate uses, so the panel can never show a
 * state that disagrees with what a restart would actually enforce — and with
 * best-effort team context (role, team name) since "is this person alone or
 * on a team" is the first thing an admin looking at a user list wants to know.
 */
function handleAdminUsers(req, res, user) {
  let list;
  try { list = auth.listUsers(); } catch { list = []; }

  const teams = initTeamsIfPossible();
  const out = list.map((u) => {
    const row = {
      id: u.id,
      email: u.email,
      name: u.name,
      role: u.role,
      plan: u.plan === 'paid' ? 'paid' : 'free',
      createdAt: u.createdAt,
      lastLoginAt: u.lastLoginAt,
      isSuperuser: isSiteAdmin(u),
      isYou: u.id === user.id,
      team: null,
    };
    if (teams) {
      try {
        const teamRole = typeof teams.getAccountRole === 'function' ? teams.getAccountRole(u.id) : null;
        if (teamRole) row.team = { role: teamRole };
      } catch { /* best effort */ }
    }
    return row;
  });

  sendJson(res, 200, { users: out, you: { id: user.id, email: user.email } });
}

/**
 * PATCH /api/admin/users/:id {superuser?: true|false, plan?: 'free'|'paid'}
 * — grant/revoke site-admin (superuser) status and/or set the subscription
 * plan. Same shape as PATCH /api/team/members/:userId (role and suspended as
 * independent optional fields) — at least one of the two must be present.
 *
 * superuser: adds/removes the target's email from config.adminEmails, then
 * persists config.json so the change survives a restart. All the actual
 * safety rules (last-live-admin guard, role-fallback self-seed on grant,
 * refusing a lying "success" on revoke while the list is empty) live in
 * lib/adminlist.js's applyChange() — a pure function chosen specifically so
 * those rules are unit tested directly, after an adversarial review found
 * real bugs in a first version that had this logic inline here. See
 * ARCHITECTURE.md for the full writeup.
 *
 * plan: there is no payment gateway wired up (see ARCHITECTURE.md) — this is
 * the one place 'paid' status is granted, after a Buy Me a Coffee payment is
 * seen and matched to an account manually.
 *
 * Origin-checked like handleServerControl() just below: granting site-admin
 * or a paid plan is at least as consequential as restarting the process, so
 * both get the same defence-in-depth even though SameSite=Lax already blocks
 * a cross-site fetch from carrying the session cookie.
 */
async function handleAdminUserSet(req, res, user, targetId) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }

  const origin = String(req.headers.origin || '');
  if (origin) {
    let ok = false;
    try {
      const h = new URL(origin).host;
      ok = h === String(req.headers.host || '') ||
           h === String(config.baseUrl || '').replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    } catch { ok = false; }
    if (!ok) {
      sendJson(res, 403, { error: 'cross-origin request refused' });
      return;
    }
  }

  const hasSuperuser = typeof body.superuser === 'boolean';
  const hasPlan = body.plan === 'free' || body.plan === 'paid';
  if (!hasSuperuser && !hasPlan) {
    sendJson(res, 400, { error: 'send {"superuser": true|false} and/or {"plan": "free"|"paid"}' });
    return;
  }

  const target = auth.findUserById(targetId);
  if (!target) {
    sendJson(res, 404, { error: 'no such user' });
    return;
  }

  const out = { ok: true, email: adminlist.normalise(target.email) };

  if (hasSuperuser) {
    const result = adminlist.applyChange({
      currentEmails: config.adminEmails,
      targetEmail: target.email,
      wantSuperuser: body.superuser,
      actorEmail: user.email,
      accountExists: (email) => !!auth.findUserByEmail(email),
    });
    if (!result.ok) {
      sendJson(res, 400, { error: result.error });
      return;
    }
    const prevEmails = config.adminEmails;
    config.adminEmails = result.adminEmails;
    try {
      store.saveJson(path.join(DATA_DIR, 'config.json'), config);
    } catch (e) {
      config.adminEmails = prevEmails; // roll back — the live gate must match what is actually on disk
      sendJson(res, 500, { error: 'could not save the updated admin list to disk' });
      return;
    }
    console.log('hiccup: admin list change — ' + user.email + ' ' +
      (body.superuser ? 'granted' : 'revoked') + ' superuser for ' + target.email +
      ' at ' + new Date().toISOString());
    out.isSuperuser = adminlist.cleanList(result.adminEmails).indexOf(out.email) !== -1;
    out.adminEmails = result.adminEmails;
  }

  if (hasPlan) {
    let updated;
    try {
      updated = auth.setUserPlan(target.id, body.plan);
    } catch (e) {
      sendJson(res, 400, { error: (e && e.userMessage) || 'could not set the plan' });
      return;
    }
    if (!updated) {
      sendJson(res, 404, { error: 'no such user' });
      return;
    }
    console.log('hiccup: plan change — ' + user.email + ' set ' + target.email +
      ' to plan "' + body.plan + '" at ' + new Date().toISOString());
    out.plan = updated.plan;
  }

  sendJson(res, 200, out);
}

/**
 * POST /api/admin/server/control {action:'status'|'restart'}
 *
 * Exists because every deploy on this box otherwise needs an elevated
 * `Restart-Service hiccup`, and a non-elevated one fails SILENTLY — which
 * repeatedly looked like "the feature is broken" when the code was fine and
 * the process was simply old. Ported from RFPlex's proven equivalent.
 *
 * The mechanism is NSSM's, not ours: the service is installed with
 * `AppExit Default Restart` and `AppRestartDelay 2000`, so exiting cleanly IS
 * the restart — NSSM relaunches the process on the new code ~2s later. We
 * therefore never spawn anything; we answer the request, then exit.
 *
 * There is deliberately no 'stop': under AppExit=Restart a stop is
 * indistinguishable from a restart from in here, and pretending otherwise
 * would be a button that lies. A real stop needs `nssm stop hiccup` as
 * administrator, and the status action says so.
 */
async function handleServerControl(req, res, user) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }

  // Defence in depth. The session cookie is already SameSite=Lax, which stops
  // a cross-site POST carrying it, but this endpoint ends the process — worth
  // a second, independent check that costs nothing.
  const origin = String(req.headers.origin || '');
  if (origin) {
    let ok = false;
    try {
      const h = new URL(origin).host;
      ok = h === String(req.headers.host || '') ||
           h === String(config.baseUrl || '').replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    } catch { ok = false; }
    if (!ok) {
      sendJson(res, 403, { error: 'cross-origin request refused' });
      return;
    }
  }

  const action = String((body && body.action) || '').trim();
  if (action !== 'status' && action !== 'restart') {
    sendJson(res, 400, { error: "action must be 'status' or 'restart'" });
    return;
  }

  const svc = await nssmServiceState();
  const svcState = svc.state;
  // Supervised AND it is us — see nssmServiceState().
  const underNssm = svc.state === 'Running' && svc.isMine;

  if (action === 'status') {
    sendJson(res, 200, {
      svcState,
      underNssm,
      pid: process.pid,
      version: VERSION,
      uptimeSeconds: Math.round(process.uptime()),
      canSelfRestart: underNssm,
      note: underNssm
        ? 'Managed by the hiccup service (AppExit=Restart): exiting relaunches on the new code.'
        : 'This process is not the one the hiccup service supervises (service state: ' + svcState +
          ') — a self-restart would exit into nothing, so it is refused.',
    });
    return;
  }

  // --- restart ---
  if (!underNssm) {
    // Exiting here would just kill a dev/manual process with nothing to bring
    // it back. Refuse loudly rather than take the app down.
    sendJson(res, 409, {
      error: 'Not supervised by the hiccup service (state: ' + svcState + ') — refusing to exit, ' +
        'because nothing would restart this process. Restart it however you started it.',
    });
    return;
  }

  console.log('hiccup: restart requested via /api/admin/server/control by ' + (user && user.email));
  sendJson(res, 200, {
    ok: true,
    via: 'nssm',
    msg: 'Restarting — the hiccup service relaunches on the new code in about 3 seconds.',
  });
  // Let the response flush before the socket dies under us. shutdown() closes
  // the listener and force-exits after 3s if a socket lingers.
  setTimeout(() => shutdown('admin restart'), 400);
}

/**
 * Is THIS process the one the 'hiccup' Windows service is supervising?
 *
 * Presence of a running service by that name is NOT enough, and getting this
 * wrong is dangerous in a specific way: a manually-started dev instance would
 * see the real service running, believe itself supervised, exit on restart —
 * and nothing would bring it back, because NSSM is supervising a different
 * process entirely.
 *
 * So compare identity, not existence. NSSM spawns the app as its direct child,
 * so the service's ProcessId (nssm.exe) is our parent when we are the one it
 * launched.
 *
 * Never throws, never hangs the request (4s cap), and every failure path
 * resolves to NOT-supervised — the safe answer, because it refuses the restart
 * rather than exiting on a guess.
 *
 * @returns {Promise<{state:string, isMine:boolean}>}
 */
function nssmServiceState() {
  if (process.platform !== 'win32') return Promise.resolve({ state: 'NotWindows', isMine: false });
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    try {
      const { spawn } = require('child_process');
      const p = spawn('powershell.exe',
        ['-NoProfile', '-NonInteractive', '-Command',
          "try { $s = Get-CimInstance Win32_Service -Filter \"Name='hiccup'\" -ErrorAction Stop; " +
          "'{0}|{1}' -f $s.State, $s.ProcessId } catch { 'NotFound|0' }"],
        { windowsHide: true });
      let out = '';
      p.stdout.on('data', (d) => { out += d.toString(); });
      p.on('close', () => {
        const parts = out.trim().split('|');
        const state = parts[0] || 'Unknown';
        const svcPid = Number(parts[1] || 0);
        finish({ state, isMine: svcPid > 0 && svcPid === process.ppid });
      });
      p.on('error', () => finish({ state: 'Unknown', isMine: false }));
      setTimeout(() => { try { p.kill(); } catch { /* already gone */ } finish({ state: 'Unknown', isMine: false }); }, 4000);
    } catch { finish({ state: 'Unknown', isMine: false }); }
  });
}

/** GET /api/admin/feedback */
function handleFeedbackList(req, res) {
  const fb = requireFeedback(res);
  if (!fb) return;
  const items = fb.list(DATA_DIR);
  const mail = getMail();
  sendJson(res, 200, {
    items,
    unread: items.filter((r) => !r.read).length,
    mailConfigured: !!(mail && mail.isConfigured(DATA_DIR)),
    digest: fb.getDigestState(DATA_DIR),
  });
}

/** POST /api/admin/feedback/:id/read {read} */
async function handleFeedbackRead(req, res, id) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }
  const fb = requireFeedback(res);
  if (!fb) return;
  const rec = fb.setRead(DATA_DIR, id, body.read !== false);
  if (!rec) { sendJson(res, 404, { error: 'no such feedback' }); return; }
  sendJson(res, 200, { ok: true, item: rec });
}

/** POST /api/admin/feedback/digest/send[?dry=1] — send this week's digest now. */
async function handleFeedbackDigestSend(req, res) {
  req.resume();
  const fb = requireFeedback(res);
  if (!fb) return;
  // `url` in handle() is a plain string, not a URL object — this file's own
  // queryParams(req) helper is the one place that knows that.
  const dry = queryParams(req).get('dry') === '1';
  const out = await sendFeedbackDigest({ force: true, dry });
  sendJson(res, out.ok ? 200 : 422, out);
}

/**
 * Build and send the weekly digest.
 * @param {{force?:boolean, dry?:boolean}} [opts] force skips the schedule check
 */
async function sendFeedbackDigest(opts) {
  const o = opts || {};
  let fb;
  try { fb = require('./lib/feedback'); } catch { return { ok: false, error: 'no feedback module' }; }

  if (!o.force && !fb.digestDue(DATA_DIR, new Date())) return { ok: true, skipped: 'not due' };

  const records = fb.since(DATA_DIR, 7 * 24 * 3600 * 1000);
  const digest = fb.buildDigest(records);
  if (!digest) {
    // Nothing happened this week. Still stamp the week so the timer does not
    // re-check every 15 minutes for the rest of it.
    if (!o.dry) fb.setDigestSent(DATA_DIR, fb.isoWeek(new Date()));
    return { ok: true, skipped: 'no feedback this week', count: 0 };
  }

  const to = String(config.digestRecipient || '').trim();
  if (!to) return { ok: false, error: 'no digestRecipient configured', count: records.length };
  if (o.dry) return { ok: true, dry: true, count: records.length, subject: digest.subject, to };

  const mail = getMail();
  if (!mail) return { ok: false, error: 'no mail module', count: records.length };

  let sent;
  try {
    sent = await mail.send(DATA_DIR, {
      to, subject: digest.subject, text: digest.text, html: digest.html,
    });
  } catch (e) {
    // A send failure must NOT stamp the week — otherwise one transient SMTP
    // error silently eats that week's digest entirely.
    console.error('hiccup: feedback digest send failed:', (e && e.message) || e);
    return { ok: false, error: (e && e.message) || 'send failed', count: records.length };
  }
  if (!sent.sent) return { ok: false, error: sent.reason || 'not sent', count: records.length };

  fb.setDigestSent(DATA_DIR, fb.isoWeek(new Date()));
  return { ok: true, sent: true, count: records.length, to };
}

/** POST /api/kb/search {q, k} — BM25-ish keyword search over this user's docs. */
async function handleKbSearch(req, res, user) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }
  const uid = resolveAccountUid(user.id);
  const kb = requireKb(res);
  if (!kb) return;
  if (typeof kb.searchKb !== 'function') {
    sendJson(res, 501, { error: 'this build of lib/kb.js cannot search' });
    return;
  }
  const q = typeof body.q === 'string' ? body.q.trim() : '';
  if (!q) {
    sendJson(res, 400, { error: 'q (a search query) is required' });
    return;
  }
  let k = Number(body.k);
  if (!Number.isFinite(k) || k <= 0) k = 8;
  k = Math.min(Math.round(k), 50);
  let hits;
  try {
    hits = await kb.searchKb(uid, q, k);
  } catch (e) {
    sendJson(res, 422, { error: (e && e.userMessage) || 'could not search the library' });
    return;
  }
  sendJson(res, 200, { hits: Array.isArray(hits) ? hits : [] });
}

// ---------------------------------------------------------------------------
// Teams & Projects (Wave 3)
// ---------------------------------------------------------------------------

/**
 * Path safety for every route that accepts a project id from the URL, a
 * header, or the request body: shape validation FIRST (12 lowercase hex
 * chars — same convention as capture ids), ownership lookup SECOND, only
 * reachable once the shape check passed. This is the fix for RFPlex's
 * shipped path-traversal CVE (a caller-supplied projectId reaching
 * path.join() with no ownership check) — mandatory here from the first
 * commit, never bolted on later. Never trust a client-supplied id for "which
 * account does this belong to"; accountUid must already have been derived
 * from the authenticated session before this is called.
 * @param {string} accountUid resolved via resolveAccountUid(user.id) — never
 *   anything the request itself claims
 * @param {*} rawId the client-supplied id (URL segment, header, or body field)
 * @returns {string|null} rawId when it is well-shaped AND owned by accountUid,
 *   else null (callers map null to 404 — a bad shape and someone else's id
 *   must look identical to the caller)
 */
function resolveOwnedProjectId(accountUid, rawId) {
  if (typeof rawId !== 'string' || !/^[a-f0-9]{12}$/.test(rawId)) return null;
  const projects = initProjectsIfPossible();
  if (!projects) return null;
  return projects.getProject(accountUid, rawId) ? rawId : null;
}

/** POST /api/team {name} -> {team} */
async function handleTeamCreate(req, res, user) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }
  const teams = initTeamsIfPossible();
  if (!teams) {
    sendJson(res, 501, { error: 'the teams module is not deployed on this server yet' });
    return;
  }
  let team;
  try {
    team = teams.createTeam(user.id, typeof body.name === 'string' ? body.name : '');
  } catch (e) {
    sendJson(res, 400, { error: (e && e.userMessage) || 'could not create the team' });
    return;
  }
  sendJson(res, 200, { team });
}

/** GET /api/team -> {team, members, pendingInvites, myRole, myCanManage} */
function handleTeamGet(req, res, user) {
  const teams = initTeamsIfPossible();
  if (!teams) {
    sendJson(res, 501, { error: 'the teams module is not deployed on this server yet' });
    return;
  }
  sendJson(res, 200, teams.getTeamView(user.id));
}

/** POST /api/team/invite {email} -> {token, inviteUrl, email} */
async function handleTeamInvite(req, res, user) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }
  const teams = initTeamsIfPossible();
  if (!teams) {
    sendJson(res, 501, { error: 'the teams module is not deployed on this server yet' });
    return;
  }
  let result;
  try {
    result = teams.createInvite(user.id, typeof body.email === 'string' ? body.email : '');
  } catch (e) {
    // createInvite independently re-checks permission itself (the real
    // enforcement); this pre-check only exists so a plain member gets 403
    // rather than 400 for the permission case specifically.
    const status = teams.canManageMembers(user.id) ? 400 : 403;
    sendJson(res, status, { error: (e && e.userMessage) || 'could not create an invite' });
    return;
  }
  sendJson(res, 200, { token: result.token, inviteUrl: result.inviteUrl, email: body.email });
}

/** GET /api/team/invite-info/:token -> {email, teamName, emailExists, hasPassword} | 404 — public. */
function handleInviteInfo(req, res, token) {
  const teams = initTeamsIfPossible();
  if (!teams) {
    sendJson(res, 501, { error: 'the teams module is not deployed on this server yet' });
    return;
  }
  const info = teams.getInviteInfo(token);
  if (!info) {
    sendJson(res, 404, { error: 'this invite link is invalid or has expired' });
    return;
  }
  sendJson(res, 200, info);
}

/**
 * POST /api/team/accept {token, password?, name?, email?} -> {user} + Set-Cookie — public.
 * `email` (if sent) is not required or used to change behaviour: the invite
 * token itself is the sole source of truth for which email is being
 * accepted, exactly so an invite can never be redirected to a different
 * account by a client claiming a different email.
 */
async function handleTeamAccept(req, res) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }
  const teams = initTeamsIfPossible();
  if (!teams) {
    sendJson(res, 501, { error: 'the teams module is not deployed on this server yet' });
    return;
  }
  const token = typeof body.token === 'string' ? body.token : '';
  if (!token) {
    sendJson(res, 400, { error: 'token is required' });
    return;
  }
  const info = teams.getInviteInfo(token);
  if (!info) {
    sendJson(res, 404, { error: 'this invite link is invalid or has expired' });
    return;
  }

  // Best-effort session peek — this route is public, so a missing/invalid
  // cookie is not an error, just "branch 2 or 3" instead of "branch 1".
  const cookieToken = parseCookies(req)[SESSION_COOKIE];
  const sess = cookieToken ? auth.getSession(cookieToken) : null;
  const sessionUser = sess && sess.user ? sess.user : null;

  let result;
  try {
    result = await teams.acceptInvite(token, {
      sessionUserId: sessionUser ? sessionUser.id : null,
      password: typeof body.password === 'string' ? body.password : undefined,
      createAccount: typeof body.password === 'string'
        ? { password: body.password, name: typeof body.name === 'string' ? body.name : undefined }
        : undefined,
    });
  } catch (e) {
    sendJson(res, 400, { error: (e && e.userMessage) || 'could not accept this invite' });
    return;
  }

  const fullUser = (sessionUser && sessionUser.id === result.userId)
    ? sessionUser
    : findUserByEmail(info.email);
  if (!fullUser) {
    sendJson(res, 500, { error: 'joined the team, but could not load the account' });
    return;
  }
  respondSignedIn(res, fullUser);
}

/** PATCH /api/team/members/:userId {role?, suspended?} -> {ok} */
async function handleTeamMemberPatch(req, res, user, targetUserId) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }
  const teams = initTeamsIfPossible();
  if (!teams) {
    sendJson(res, 501, { error: 'the teams module is not deployed on this server yet' });
    return;
  }

  const hasRole = Object.prototype.hasOwnProperty.call(body, 'role') && body.role != null;
  const hasSuspended = Object.prototype.hasOwnProperty.call(body, 'suspended') &&
    body.suspended !== undefined;
  if (!hasRole && !hasSuspended) {
    sendJson(res, 400, { error: 'role or suspended is required' });
    return;
  }

  if (hasRole) {
    if (teams.getAccountRole(user.id) !== 'owner') {
      sendJson(res, 403, { error: 'Only the team owner can change member roles.' });
      return;
    }
    try {
      teams.setMemberRole(user.id, targetUserId, body.role);
    } catch (e) {
      sendJson(res, 400, { error: (e && e.userMessage) || 'could not change that member role' });
      return;
    }
  }
  if (hasSuspended) {
    if (!teams.canManageMembers(user.id)) {
      sendJson(res, 403, { error: 'Only a team owner or admin can suspend members.' });
      return;
    }
    try {
      teams.setMemberSuspended(user.id, targetUserId, !!body.suspended);
    } catch (e) {
      sendJson(res, 400, { error: (e && e.userMessage) || 'could not update that member' });
      return;
    }
  }
  sendJson(res, 200, { ok: true });
}

/** DELETE /api/team/members/:userId -> {ok} */
function handleTeamMemberDelete(req, res, user, targetUserId) {
  const teams = initTeamsIfPossible();
  if (!teams) {
    sendJson(res, 501, { error: 'the teams module is not deployed on this server yet' });
    return;
  }
  if (!teams.canManageMembers(user.id)) {
    sendJson(res, 403, { error: 'Only a team owner or admin can remove members.' });
    return;
  }
  try {
    teams.removeMember(user.id, targetUserId);
  } catch (e) {
    sendJson(res, 400, { error: (e && e.userMessage) || 'could not remove that member' });
    return;
  }
  sendJson(res, 200, { ok: true });
}

/** POST /api/team/transfer-ownership {userId} -> {ok} */
/**
 * POST /api/team/leave — leave the team you are on.
 *
 * Separate from DELETE /api/team/members/:id, which is a management action one
 * person takes against another. This is the one a member takes on themselves,
 * and until now no such control existed anywhere: two places in the UI told
 * users to "leave the team" and there was nothing to click.
 */
async function handleTeamLeave(req, res, user) {
  req.resume();
  const teams = initTeamsIfPossible();
  if (!teams || typeof teams.leaveTeam !== 'function') {
    sendJson(res, 501, { error: 'the teams module is not deployed on this server yet' });
    return;
  }
  let out;
  try {
    out = teams.leaveTeam(user.id);
  } catch (e) {
    sendJson(res, 400, { error: (e && e.userMessage) || 'could not leave the team' });
    return;
  }
  console.log('hiccup: ' + user.email + ' left team ' + out.teamId + (out.dissolved ? ' (dissolved)' : ''));
  sendJson(res, 200, { ok: true, dissolved: !!out.dissolved });
}

/** GET /api/team/recovery — can this member take the team over, and why not. */
function handleTeamRecoveryGet(req, res, user) {
  const teams = initTeamsIfPossible();
  if (!teams || typeof teams.getRecoveryState !== 'function') {
    sendJson(res, 501, { error: 'the teams module is not deployed on this server yet' });
    return;
  }
  sendJson(res, 200, teams.getRecoveryState(user.id));
}

/**
 * POST /api/team/claim-ownership — take over a team whose owner is gone or
 * long dormant. The eligibility rules live entirely in lib/teams.js so the
 * banner the user sees and the decision enforced here cannot disagree.
 */
async function handleTeamClaim(req, res, user) {
  req.resume();
  const teams = initTeamsIfPossible();
  if (!teams || typeof teams.claimOwnership !== 'function') {
    sendJson(res, 501, { error: 'the teams module is not deployed on this server yet' });
    return;
  }
  let out;
  try {
    out = teams.claimOwnership(user.id);
  } catch (e) {
    sendJson(res, 403, { error: (e && e.userMessage) || 'could not take over this team' });
    return;
  }
  // Worth a log line: this is an ownership change nobody explicitly approved.
  console.log('hiccup: ' + user.email + ' CLAIMED ownership of team ' + out.teamId +
    (out.previousOwnerRemoved ? ' (previous owner account was gone)' : ' (previous owner demoted to admin)'));
  sendJson(res, 200, { ok: true });
}

async function handleTeamTransfer(req, res, user) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }
  const teams = initTeamsIfPossible();
  if (!teams) {
    sendJson(res, 501, { error: 'the teams module is not deployed on this server yet' });
    return;
  }
  if (teams.getAccountRole(user.id) !== 'owner') {
    sendJson(res, 403, { error: 'Only the team owner can transfer ownership.' });
    return;
  }
  try {
    teams.transferOwnership(user.id, typeof body.userId === 'string' ? body.userId : '');
  } catch (e) {
    sendJson(res, 400, { error: (e && e.userMessage) || 'could not transfer ownership' });
    return;
  }
  sendJson(res, 200, { ok: true });
}

/** GET /api/projects -> [Project] */
function handleProjectsList(req, res, user) {
  const projects = initProjectsIfPossible();
  if (!projects) {
    sendJson(res, 501, { error: 'the projects module is not deployed on this server yet' });
    return;
  }
  const uid = resolveAccountUid(user.id);
  sendJson(res, 200, projects.listProjects(uid));
}

/** POST /api/projects {name, description?} -> {project} */
async function handleProjectsCreate(req, res, user) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }
  const projects = initProjectsIfPossible();
  if (!projects) {
    sendJson(res, 501, { error: 'the projects module is not deployed on this server yet' });
    return;
  }
  const uid = resolveAccountUid(user.id);
  let project;
  try {
    project = projects.createProject(uid, {
      name: typeof body.name === 'string' ? body.name : '',
      description: typeof body.description === 'string' ? body.description : '',
    });
  } catch (e) {
    sendJson(res, 400, { error: (e && e.userMessage) || 'could not create the project' });
    return;
  }
  sendJson(res, 200, { project });
}

/** PATCH /api/projects/:id {name?, description?} -> {project} */
async function handleProjectsPatch(req, res, user, rawId) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }
  const projects = initProjectsIfPossible();
  if (!projects) {
    sendJson(res, 501, { error: 'the projects module is not deployed on this server yet' });
    return;
  }
  const uid = resolveAccountUid(user.id);
  const projectId = resolveOwnedProjectId(uid, rawId);
  if (!projectId) {
    sendJson(res, 404, { error: 'project not found' });
    return;
  }
  let project;
  try {
    project = projects.renameProject(uid, projectId, {
      name: typeof body.name === 'string' ? body.name : undefined,
      description: typeof body.description === 'string' ? body.description : undefined,
    });
  } catch (e) {
    sendJson(res, 400, { error: (e && e.userMessage) || 'could not update the project' });
    return;
  }
  sendJson(res, 200, { project });
}

/** DELETE /api/projects/:id -> {ok} */
function handleProjectsDelete(req, res, user, rawId) {
  const projects = initProjectsIfPossible();
  if (!projects) {
    sendJson(res, 501, { error: 'the projects module is not deployed on this server yet' });
    return;
  }
  const uid = resolveAccountUid(user.id);
  const projectId = resolveOwnedProjectId(uid, rawId);
  if (!projectId) {
    sendJson(res, 404, { error: 'project not found' });
    return;
  }
  const removed = projects.deleteProject(uid, projectId);
  if (!removed) {
    sendJson(res, 404, { error: 'project not found' });
    return;
  }
  sendJson(res, 200, { ok: true });
}

// ---------------------------------------------------------------------------
// Chat
// ---------------------------------------------------------------------------

const SCOPE_TYPES = new Set(['capture', 'call', 'leg', 'message', 'finding']);

/**
 * Compact one leg for prompt/scope serialization.
 * @param {object} leg
 * @returns {object}
 */
function summarizeLeg(leg) {
  return {
    id: leg.id,
    protocol: leg.protocol,
    kind: leg.kind,
    from: leg.from,
    to: leg.to,
    fromUser: leg.fromUser,
    toUser: leg.toUser,
    src: leg.src,
    dst: leg.dst,
    transport: leg.transport,
    startTs: leg.startTs,
    endTs: leg.endTs,
    state: leg.state,
    failCode: leg.failCode,
    answered: leg.answered,
    messageCount: Array.isArray(leg.msgIds) ? leg.msgIds.length : 0,
    callId: leg.callId != null ? leg.callId : undefined,
  };
}

/**
 * Serialize the chat scope object compactly per the contract: message raw
 * capped at 4 KB; call = legs summary + diff items. Returns '' for capture
 * scope (the stats/findings summary already covers it).
 * @param {object} analysis AnalysisJSON
 * @param {{type:string,id:string}|undefined} scope
 * @returns {string}
 */
function buildScopeText(analysis, scope) {
  if (!scope || !scope.type || scope.type === 'capture' || !SCOPE_TYPES.has(scope.type)) return '';
  const id = String(scope.id || '');
  let obj = null;
  if (scope.type === 'message') {
    const msg = (analysis.messages || []).find((m) => m.id === id);
    if (msg) {
      obj = Object.assign({}, msg);
      if (typeof obj.raw === 'string' && obj.raw.length > 4096) {
        obj.raw = obj.raw.slice(0, 4096) + '\n...[truncated]';
      }
    }
  } else if (scope.type === 'call') {
    const call = (analysis.calls || []).find((c) => c.id === id);
    if (call) {
      const legById = new Map((analysis.legs || []).map((l) => [l.id, l]));
      obj = {
        id: call.id,
        type: call.type,
        state: call.state,
        confidence: call.confidence,
        pairings: call.pairings,
        candidates: call.candidates,
        legs: (call.legIds || []).map((lid) => {
          const leg = legById.get(lid);
          return leg ? summarizeLeg(leg) : { id: lid };
        }),
        diffs: (call.diffs || []).map((d) => ({
          a: d.a,
          b: d.b,
          items: ((d.diff && d.diff.categories) || []).reduce((acc, cat) => {
            for (const item of cat.items || []) acc.push(Object.assign({ category: cat.key }, item));
            return acc;
          }, []),
        })),
      };
    }
  } else if (scope.type === 'leg') {
    const leg = (analysis.legs || []).find((l) => l.id === id);
    if (leg) obj = summarizeLeg(leg);
  } else if (scope.type === 'finding') {
    obj = (analysis.findings || []).find((f) => f.id === id) || null;
  }
  if (!obj) {
    return 'The user\'s current focus is ' + scope.type + ' ' + id +
      ', but it was not found in this capture — say so if asked about it.';
  }
  let json = JSON.stringify(obj);
  if (json.length > 16384) json = json.slice(0, 16384) + '...[truncated]';
  return 'The user\'s current focus (scope ' + scope.type + ' ' + id + '):\n' + json;
}

/**
 * Questions that look config-shaped — the trigger for injecting KB excerpts:
 * config/configure, header manipulation/HMR wording, a vendor name, or a
 * "how do I fix/change/configure" phrasing.
 */
const CONFIG_QUESTION_RE = new RegExp(
  '\\b(config|configs|configure|configured|configuration|manipulate|manipulation|' +
  'manipulations|hmr|sip-manipulation|header-rule|element-rule|smm|message ' +
  'manipulations|acme|oracle|audiocodes|ribbon|cisco|cube|freeswitch|asterisk|avaya|' +
  'mitel|3cx|sbc setting|ip profile|ip-profile|session-agent|signaling group)\\b' +
  '|how (do i|to|can i) (fix|change|configure|stop|prevent|set)' +
  '|what (do i|should i) (change|configure|set)',
  'i'
);

/**
 * Does this question look config-shaped?
 * @param {string} text the user's question
 * @returns {boolean}
 */
function looksConfigShaped(text) {
  try {
    return CONFIG_QUESTION_RE.test(String(text || ''));
  } catch {
    return false;
  }
}

/** Sort order for indicator emphasis: problems first. */
const INDICATOR_RANK = { issue: 0, partial: 1, on: 2, off: 3 };

/**
 * One prompt block listing every Indicator as key=state, then a detail line
 * for each indicator that is actually present (issue/partial/on).
 * @param {object} analysis AnalysisJSON
 * @returns {string|null} null when the analysis has no indicators
 */
function indicatorsText(analysis) {
  const list = Array.isArray(analysis.indicators) ? analysis.indicators : [];
  if (!list.length) return null;
  const pairs = list
    .filter((i) => i && i.key)
    .map((i) => i.key + '=' + (i.state || 'unknown'));
  const lines = ['Indicators (key=state, all keys always reported): ' + pairs.join(', ')];
  const notable = list
    .filter((i) => i && i.key && i.state && i.state !== 'off')
    .sort((a, b) => (INDICATOR_RANK[a.state] != null ? INDICATOR_RANK[a.state] : 9) -
      (INDICATOR_RANK[b.state] != null ? INDICATOR_RANK[b.state] : 9));
  for (const i of notable.slice(0, 14)) {
    lines.push('- ' + i.key + ' [' + i.state + ']' +
      (i.detail ? ': ' + String(i.detail).slice(0, 220) : ''));
  }
  return lines.join('\n');
}

/**
 * One prompt block for the detected Scenario (primary + confidence + detail).
 * @param {object} analysis AnalysisJSON
 * @returns {string|null}
 */
function scenarioText(analysis) {
  const s = analysis.scenario;
  if (!s || typeof s !== 'object' || !s.primary) return null;
  let line = 'Scenario: ' + s.primary;
  if (typeof s.confidence === 'number') line += ' (confidence ' + s.confidence.toFixed(2) + ')';
  if (s.detail) line += '\n' + String(s.detail).slice(0, 700);
  if (Array.isArray(s.alternatives) && s.alternatives.length) {
    line += '\nAlternatives considered: ' + s.alternatives
      .slice(0, 3)
      .map((a) => (a && a.primary) + ' ' + (a && typeof a.confidence === 'number'
        ? a.confidence.toFixed(2) : '?'))
      .join(', ');
  }
  return line;
}

/**
 * One prompt block listing the deterministic Advice objects (id, severity,
 * title and their pre-verified citation strings) — the model's only permitted
 * source of protocol citations.
 * @param {object} analysis AnalysisJSON
 * @returns {string|null}
 */
function adviceText(analysis) {
  const list = Array.isArray(analysis.advice) ? analysis.advice : [];
  if (!list.length) return null;
  const lines = ['Advice available for this capture (deterministic, already ' +
    'cited — quote these citations verbatim or not at all):'];
  for (const a of list.slice(0, 20)) {
    if (!a) continue;
    let line = '- ' + (a.id || '?') + ' [' + (a.severity || 'info') + '] ' + (a.title || '');
    const cites = (Array.isArray(a.citations) ? a.citations : [])
      .filter((c) => c && c.source)
      .map((c) => c.source + (c.section ? ' ' + c.section : ''));
    if (cites.length) line += ' — citations: ' + cites.join('; ');
    const kbCites = (Array.isArray(a.kbCitations) ? a.kbCitations : [])
      .filter((c) => c && c.docTitle)
      .map((c) => c.docTitle + (c.page != null ? ' p' + c.page : ''));
    if (kbCites.length) line += ' — guide refs: ' + kbCites.join('; ');
    lines.push(line);
  }
  if (list.length > 20) lines.push('(and ' + (list.length - 20) + ' more)');
  return lines.join('\n');
}

/**
 * One prompt block summarising the media streams and RTCP reports.
 * @param {object} analysis AnalysisJSON
 * @returns {string|null}
 */
function mediaText(analysis) {
  const media = (analysis.media && typeof analysis.media === 'object') ? analysis.media : {};
  const streams = Array.isArray(media.streams) ? media.streams : [];
  const rtcp = Array.isArray(media.rtcp) ? media.rtcp : [];
  if (!streams.length && !rtcp.length) return null;
  const lines = ['Media: ' + streams.length + ' stream(s), ' + rtcp.length + ' RTCP report(s). ' +
    'MOS values are simplified-E-model ESTIMATES, not measurements.'];
  for (const s of streams.slice(0, 12)) {
    if (!s) continue;
    const bits = [
      s.id,
      s.kind,
      s.codec,
      (s.src || '?') + ':' + (s.sport != null ? s.sport : '?') + ' -> ' +
        (s.dst || '?') + ':' + (s.dport != null ? s.dport : '?'),
      s.packets != null ? s.packets + ' pkts' : null,
      s.lossPct != null ? 'loss ' + s.lossPct + '%' : null,
      s.meanJitterMs != null ? 'jitter mean ' + s.meanJitterMs + 'ms' : null,
      s.maxJitterMs != null ? 'max ' + s.maxJitterMs + 'ms' : null,
      s.maxGapMs != null ? 'maxGap ' + s.maxGapMs + 'ms' : null,
      s.mos != null ? 'MOS~' + s.mos : null,
      s.oneWay ? 'ONE-WAY (no reverse stream)' : null,
      Array.isArray(s.legIds) && s.legIds.length ? 'legs ' + s.legIds.join('/') : null,
    ].filter((b) => b != null && b !== '');
    lines.push('- ' + bits.join('  '));
  }
  if (streams.length > 12) lines.push('(and ' + (streams.length - 12) + ' more streams)');
  return lines.join('\n');
}

/**
 * One prompt block with the retrieved knowledge-base excerpts.
 * @param {Array<{docTitle?:string,page?:number,heading?:string,text?:string}>} hits
 * @returns {string|null}
 */
function kbHitsText(hits) {
  const list = Array.isArray(hits) ? hits.filter(Boolean) : [];
  if (!list.length) return null;
  const lines = ['Knowledge-base excerpts from vendor guides this user uploaded ' +
    '(cite as "<document title>, p<page>"; nothing outside these excerpts and the ' +
    'Advice citations above may be cited):'];
  list.slice(0, 6).forEach((h, i) => {
    lines.push('[' + (i + 1) + '] ' + (h.docTitle || 'document') +
      (h.page != null ? ' p' + h.page : '') +
      (h.heading ? ' — ' + h.heading : ''));
    lines.push(String(h.text || h.excerpt || '').slice(0, 900));
  });
  return lines.join('\n');
}

/**
 * Build the /api/chat system prompt: persona + capture stats + scenario +
 * indicators + findings summary + advice titles + media summary + KB excerpts
 * + the scope serialization + the citation rules.
 * @param {object} analysis AnalysisJSON
 * @param {{type:string,id:string}|undefined} scope
 * @param {Array<object>} [kbHits] KB hits for a config-shaped question
 * @returns {string}
 */
function buildSystemPrompt(analysis, scope, kbHits) {
  const parts = [];
  parts.push(
    'You are hiccup, an expert SIP/SBC/H.323 engineer explaining a capture to an ' +
    'SBC-curious engineer. Be precise and practical: reference message/leg/call ids ' +
    'and timestamps from the capture when relevant, explain protocol concepts clearly, ' +
    'and say plainly when the capture does not contain the answer. Phone-number and ' +
    'credential material in the capture is already redacted; never invent replacements.'
  );
  parts.push('Capture stats: ' + JSON.stringify(analysis.stats || {}));
  const scenario = scenarioText(analysis);
  if (scenario) parts.push(scenario);
  const indicators = indicatorsText(analysis);
  if (indicators) parts.push(indicators);
  const findings = analysis.findings || [];
  const counts = countFindings(findings);
  const summary = ['Findings: ' + findings.length + ' total (crit ' + counts.crit +
    ', warn ' + counts.warn + ', notice ' + counts.notice + ', info ' + counts.info + ')'];
  for (const f of findings.slice(0, 20)) {
    summary.push('- [' + f.severity + '] ' + f.title +
      (f.detail ? ': ' + String(f.detail).slice(0, 200) : ''));
  }
  if (findings.length > 20) summary.push('(and ' + (findings.length - 20) + ' more)');
  parts.push(summary.join('\n'));
  const advice = adviceText(analysis);
  if (advice) parts.push(advice);
  const media = mediaText(analysis);
  if (media) parts.push(media);
  const kb = kbHitsText(kbHits);
  if (kb) parts.push(kb);
  const scopeText = buildScopeText(analysis, scope);
  if (scopeText) parts.push(scopeText);
  parts.push(
    'Citation rules (strict): the ONLY citations you may give are the ones carried by ' +
    'the Advice objects listed above and the knowledge-base excerpts supplied above. ' +
    'Never invent, guess or recall an RFC number, an RFC section number, a 3GPP TS ' +
    'number or an ITU-T reference — if the supporting reference is not in the material ' +
    'above, explain the mechanism in your own words and say which document the reader ' +
    'should look it up in, without a section number. Any vendor configuration you ' +
    'suggest is a reviewable draft, never a verified change.'
  );
  return parts.join('\n\n');
}

/** POST /api/chat */
async function handleChat(req, res, user) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch (e) {
    sendBodyError(res, e);
    return;
  }
  if (!Array.isArray(body.messages) || body.messages.length === 0) {
    sendJson(res, 400, { error: 'messages array is required' });
    return;
  }
  const uid = resolveAccountUid(user.id);
  const analysis = loadAnalysis(uid, body.captureId);
  if (!analysis) {
    sendJson(res, 404, { error: 'capture not found' });
    return;
  }
  const status = llm.getLlmStatus();
  if (!status.available) {
    sendJson(res, 503, { error: 'local model is offline', llm: status });
    return;
  }
  const messages = body.messages.slice(-12).map((m) => ({
    role: m && m.role === 'assistant' ? 'assistant' : 'user',
    content: String((m && m.content) || ''),
  }));
  // Config-shaped questions get the account's own vendor-guide excerpts injected.
  let question = '';
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i].role === 'user') { question = messages[i].content; break; }
  }
  const kbHits = looksConfigShaped(question) ? kbSearchSafe(uid, question, 4) : [];
  const system = buildSystemPrompt(analysis, body.scope, kbHits);
  try {
    const out = await llm.askLlm({ system, messages });
    sendJson(res, 200, { reply: out.text, model: out.model });
  } catch (e) {
    if (e && e.code === 'busy') {
      sendJson(res, 429, { error: 'hiccup is busy answering another question — try again in a moment' });
    } else {
      sendJson(res, 503, {
        error: (e && (e.userMessage || e.message)) || 'local model unavailable',
        llm: llm.getLlmStatus(),
      });
    }
  }
}

// ---------------------------------------------------------------------------
// Auth routes
// ---------------------------------------------------------------------------

/**
 * Create a session for `user`, set the cookie, respond {user}.
 * @param {http.ServerResponse} res
 * @param {object} user
 */
function respondSignedIn(res, user) {
  const sess = auth.createSession(user.id);
  setSessionCookie(res, sess.token, sess.expiresAt);
  sendJson(res, 200, { user: sanitizeUser(user) });
}

/** POST /api/auth/signup */
async function handleSignup(req, res) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }
  if (!body.email || typeof body.email !== 'string' ||
      !body.password || typeof body.password !== 'string') {
    sendJson(res, 400, { error: 'email and password are required' });
    return;
  }
  // Unlimited signup lets anyone mint accounts and consume capture storage,
  // and each one costs a ~20ms synchronous scrypt on the single event loop.
  if (_slidingLimited(_signupByIp, clientIp(req), SIGNUP_MAX_PER_IP, SIGNUP_WINDOW_MS, false)) {
    res.setHeader('Retry-After', '3600');
    sendJson(res, 429, { error: 'Too many accounts created from here recently. Try again later.' });
    return;
  }
  let user;
  try {
    user = await auth.createUser({
      email: body.email,
      password: body.password,
      name: typeof body.name === 'string' ? body.name : undefined,
    });
  } catch (e) {
    sendJson(res, 400, { error: (e && e.userMessage) || 'could not create the account' });
    return;
  }
  respondSignedIn(res, user);
}

/** POST /api/auth/login */
async function handleLogin(req, res) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }
  if (!body.email || !body.password) {
    sendJson(res, 400, { error: 'email and password are required' });
    return;
  }
  // Checked with peek=true so a legitimate user who signs in successfully
  // never spends their own budget -- only failures below are recorded. The
  // email key is normalised so "A@b.com" and "a@b.com" share one bucket
  // rather than giving an attacker a free bucket per casing.
  const ip = clientIp(req);
  const emailKey = String(body.email).trim().toLowerCase();
  const overEmail = _slidingLimited(_loginByEmail, emailKey, LOGIN_MAX_PER_EMAIL, LOGIN_WINDOW_MS, true);
  const overIp = _slidingLimited(_loginByIp, ip, LOGIN_MAX_PER_IP, LOGIN_WINDOW_MS, true);
  if (overEmail || overIp) {
    res.setHeader('Retry-After', '900');
    // Deliberately the same wording either way: saying WHICH limit tripped
    // tells an attacker whether they have found a real account.
    sendJson(res, 429, { error: 'Too many sign-in attempts. Wait a few minutes and try again.' });
    return;
  }

  const user = await auth.verifyPassword(String(body.email), String(body.password));
  if (!user) {
    // Record on failure only.
    _slidingLimited(_loginByEmail, emailKey, LOGIN_MAX_PER_EMAIL, LOGIN_WINDOW_MS, false);
    _slidingLimited(_loginByIp, ip, LOGIN_MAX_PER_IP, LOGIN_WINDOW_MS, false);
    sendJson(res, 401, { error: 'wrong email or password' });
    return;
  }
  respondSignedIn(res, user);
}

/** POST /api/auth/google */
async function handleGoogleAuth(req, res) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendBodyError(res, e); }
  if (!body.credential || typeof body.credential !== 'string') {
    sendJson(res, 400, { error: 'credential is required' });
    return;
  }
  let claims;
  try {
    claims = await auth.verifyGoogleIdToken(body.credential);
  } catch (e) {
    sendJson(res, 401, { error: (e && e.userMessage) || 'Google sign-in failed' });
    return;
  }
  let user = findUserByEmail(claims.email);
  if (!user) {
    try {
      user = await auth.createUser({
        email: claims.email,
        name: claims.name,
        googleSub: claims.sub,
      });
    } catch (e) {
      // Raced or lookup-shape mismatch: one more lookup before giving up.
      user = findUserByEmail(claims.email);
      if (!user) {
        sendJson(res, 400, { error: (e && e.userMessage) || 'could not sign in with Google' });
        return;
      }
    }
  }
  respondSignedIn(res, user);
}

/** POST /api/auth/logout */
function handleLogout(req, res) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (token) {
    try { auth.destroySession(token); } catch { /* already gone */ }
  }
  clearSessionCookie(res);
  sendJson(res, 200, { ok: true });
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/**
 * Main request dispatcher. Every route answers JSON under /api/*; everything
 * else falls through to the static server.
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 */
async function handle(req, res) {
  const url = req.url || '/';
  const qIdx = url.indexOf('?');
  const pathname = qIdx === -1 ? url : url.slice(0, qIdx);
  const method = req.method;

  // --- public, no auth ---
  if (pathname === '/api/status' && method === 'GET') {
    sendJson(res, 200, {
      app: 'hiccup',
      version: VERSION,
      uptime: Math.round(process.uptime()),
      llm: llm.getLlmStatus(),
    });
    return;
  }
  if (pathname === '/api/config/public' && method === 'GET') {
    sendJson(res, 200, {
      appName: 'hiccup',
      googleClientId: config.googleClientId || null,
      freeBeta: true,
      // Facts about THIS deployment that /settings states to the user. Public
      // because they describe how the box treats data, which is precisely what
      // someone deciding whether to upload a trace needs to know up front.
      captureRetentionDays: Number(config.captureRetentionDays) || 0,
      maskNumbersByDefault: config.maskNumbersByDefault !== false,
    });
    return;
  }

  // --- auth ---
  if (pathname === '/api/auth/signup' && method === 'POST') return handleSignup(req, res);
  if (pathname === '/api/auth/login' && method === 'POST') return handleLogin(req, res);
  if (pathname === '/api/auth/google' && method === 'POST') return handleGoogleAuth(req, res);
  if (pathname === '/api/auth/logout' && method === 'POST') return handleLogout(req, res);

  if (pathname === '/api/me' && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) return;
    sendJson(res, 200, { user: sanitizeUser(user) });
    return;
  }

  // --- GDPR subject rights ---
  if (pathname === '/api/me/export' && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    req.resume();
    return handleMeExport(req, res, user);
  }

  if (pathname === '/api/me' && method === 'DELETE') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    return handleMeDelete(req, res, user);
  }

  if (pathname === '/api/me/data' && method === 'DELETE') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    return handleMeDataDelete(req, res, user);
  }

  // --- team (Wave 3) --- two routes are public (accepting an invite happens
  // before the invitee necessarily has a session); the rest require auth.
  if (pathname === '/api/team/accept' && method === 'POST') {
    return handleTeamAccept(req, res);
  }
  const inviteInfoMatch = pathname.match(/^\/api\/team\/invite-info\/([A-Za-z0-9]{1,128})$/);
  if (inviteInfoMatch && method === 'GET') {
    return handleInviteInfo(req, res, inviteInfoMatch[1]);
  }
  if (pathname === '/api/team' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    return handleTeamCreate(req, res, user);
  }
  if (pathname === '/api/team' && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) return;
    return handleTeamGet(req, res, user);
  }
  if (pathname === '/api/team/invite' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    return handleTeamInvite(req, res, user);
  }
  if (pathname === '/api/team/transfer-ownership' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    return handleTeamTransfer(req, res, user);
  }
  if (pathname === '/api/team/leave' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    return handleTeamLeave(req, res, user);
  }
  if (pathname === '/api/team/recovery' && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) return;
    return handleTeamRecoveryGet(req, res, user);
  }
  if (pathname === '/api/team/claim-ownership' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    return handleTeamClaim(req, res, user);
  }
  const teamMemberMatch = pathname.match(/^\/api\/team\/members\/([A-Za-z0-9_-]{1,64})$/);
  if (teamMemberMatch) {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    if (method === 'PATCH') return handleTeamMemberPatch(req, res, user, teamMemberMatch[1]);
    if (method === 'DELETE') return handleTeamMemberDelete(req, res, user, teamMemberMatch[1]);
    sendJson(res, 404, { error: 'not found' });
    return;
  }

  // --- projects (Wave 3) ---
  if (pathname === '/api/projects' && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) return;
    return handleProjectsList(req, res, user);
  }
  if (pathname === '/api/projects' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    return handleProjectsCreate(req, res, user);
  }
  const projectMatch = pathname.match(/^\/api\/projects\/([A-Za-z0-9_-]{1,64})$/);
  if (projectMatch) {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    if (method === 'PATCH') return handleProjectsPatch(req, res, user, projectMatch[1]);
    if (method === 'DELETE') return handleProjectsDelete(req, res, user, projectMatch[1]);
    sendJson(res, 404, { error: 'not found' });
    return;
  }

  // --- captures ---
  if (pathname === '/api/captures' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    return handleUpload(req, res, user);
  }
  if (pathname === '/api/captures' && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) return;
    const uid = resolveAccountUid(user.id);
    let list = store.listCaptures(DATA_DIR, uid);
    const projectParam = queryParams(req).get('project');
    if (projectParam === 'unfiled') {
      list = list.filter((m) => !m.projectId);
    } else if (projectParam) {
      list = list.filter((m) => m.projectId === projectParam);
    }
    sendJson(res, 200, list);
    return;
  }

  const capMatch = pathname.match(
    /^\/api\/captures\/([A-Za-z0-9_-]{1,64})(\/analysis|\/advice)?$/);
  if (capMatch) {
    const user = requireAuth(req, res);
    if (!user) return;
    const uid = resolveAccountUid(user.id);
    const captureId = capMatch[1];
    if (capMatch[2] === '/advice' && method === 'GET') {
      return handleAdvice(req, res, user, captureId);
    }
    if (capMatch[2] === '/analysis' && method === 'GET') {
      const dir = findCaptureDir(uid, captureId);
      const file = dir ? path.join(dir, 'analysis.json') : null;
      if (!file || !fs.existsSync(file)) {
        sendJson(res, 404, { error: 'capture not found' });
        return;
      }
      // analysis.json is already JSON — stream it without re-parsing
      const data = fs.readFileSync(file);
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': data.length,
      });
      res.end(data);
      return;
    }
    if (!capMatch[2] && method === 'DELETE') {
      const removed = store.deleteCapture(DATA_DIR, uid, captureId);
      if (!removed) {
        sendJson(res, 404, { error: 'capture not found' });
        return;
      }
      sendJson(res, 200, { ok: true });
      return;
    }
    sendJson(res, 404, { error: 'not found' });
    return;
  }

  // --- chat ---
  if (pathname === '/api/chat' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    return handleChat(req, res, user);
  }

  // --- hmr: SBC config manipulation rules (Wave 2) ---
  if (pathname === '/api/hmr/analyze' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    return handleHmrAnalyze(req, res, user);
  }

  if (pathname === '/api/hmr/generate' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    return handleHmrGenerate(req, res);
  }

  // --- kb: the user's config-guide library (Wave 2) ---
  if (pathname === '/api/kb/docs' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    return handleKbAdd(req, res, user);
  }
  if (pathname === '/api/kb/link' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    return handleKbAddLink(req, res, user);
  }
  if (pathname === '/api/kb/docs' && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) return;
    return handleKbList(req, res, user);
  }
  const kbDocMatch = pathname.match(/^\/api\/kb\/docs\/([A-Za-z0-9_-]{1,64})$/);
  if (kbDocMatch && method === 'DELETE') {
    const user = requireAuth(req, res);
    if (!user) return;
    return handleKbDelete(req, res, user, kbDocMatch[1]);
  }
  if (pathname === '/api/kb/search' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    return handleKbSearch(req, res, user);
  }

  // --- Wave 6: feedback ---
  if (pathname === '/api/feedback' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    return handleFeedbackSubmit(req, res, user);
  }

  if (pathname === '/api/admin/status' && method === 'GET') {
    const user = requireSiteAdmin(req, res);
    if (!user) { req.resume(); return; }
    req.resume();
    return handleAdminStatus(req, res, user);
  }

  if (pathname === '/api/admin/users' && method === 'GET') {
    const user = requireSiteAdmin(req, res);
    if (!user) { req.resume(); return; }
    req.resume();
    return handleAdminUsers(req, res, user);
  }

  const adminUserMatch = pathname.match(/^\/api\/admin\/users\/([A-Za-z0-9_-]{1,64})$/);
  if (adminUserMatch && method === 'PATCH') {
    const user = requireSiteAdmin(req, res);
    if (!user) { req.resume(); return; }
    return handleAdminUserSet(req, res, user, adminUserMatch[1]);
  }

  if (pathname === '/api/admin/server/control' && method === 'POST') {
    const user = requireSiteAdmin(req, res);
    if (!user) { req.resume(); return; }
    return handleServerControl(req, res, user);
  }

  if (pathname === '/api/admin/feedback' && method === 'GET') {
    const user = requireSiteAdmin(req, res);
    if (!user) { req.resume(); return; }
    return handleFeedbackList(req, res);
  }

  const fbReadMatch = pathname.match(/^\/api\/admin\/feedback\/([A-Za-z0-9_]+)\/read$/);
  if (fbReadMatch && method === 'POST') {
    const user = requireSiteAdmin(req, res);
    if (!user) { req.resume(); return; }
    return handleFeedbackRead(req, res, fbReadMatch[1]);
  }

  if (pathname === '/api/admin/feedback/digest/send' && method === 'POST') {
    const user = requireSiteAdmin(req, res);
    if (!user) { req.resume(); return; }
    return handleFeedbackDigestSend(req, res);
  }

  // --- anything else under /api is a JSON 404 ---
  if (pathname.startsWith('/api/')) {
    sendJson(res, 404, { error: 'not found' });
    return;
  }

  // --- pages + static ---
  if (method === 'GET' || method === 'HEAD') {
    if (pathname === '/robots.txt') return handleRobots(res);
    if (pathname === '/sitemap.xml') return handleSitemap(res);
    // The landing page and the /sip reference: one table, shared with the
    // sitemap (see PUBLIC_PAGES).
    const publicPage = PUBLIC_PAGES.get(pathname);
    if (publicPage) return servePublicFile(res, publicPage);
    if (pathname === '/app') return servePublicFile(res, 'app.html');
    if (pathname === '/hmr') return servePublicPage(res, 'hmr.html');
    if (pathname === '/kb') return servePublicPage(res, 'kb.html');
    if (pathname === '/team') return servePublicPage(res, 'team.html');
    if (pathname === '/accept-invite') return servePublicPage(res, 'accept-invite.html');
    // The page itself is served to anyone signed in; every /api/admin/* call it
    // makes is separately gated, so an ordinary user just gets an empty shell
    // and 403s rather than a leak.
    if (pathname === '/settings') return servePublicPage(res, 'settings.html');
    if (pathname === '/admin/feedback') return servePublicPage(res, 'admin-feedback.html');
    if (pathname === '/admin/status') return servePublicPage(res, 'admin-status.html');
    return serveStatic(res, pathname);
  }

  notFoundText(res);
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/**
 * Content-Security-Policy.
 *
 * script-src is 'self' with NO 'unsafe-inline', which is the whole point: a
 * policy that keeps the escape hatch open stops the injected-<script> attack
 * class it exists to stop, and is decoration. Reaching it meant lifting all 32
 * inline blocks out of the 17 HTML pages into real files (boot-theme.js,
 * boot-lang.js, index-auth.js, app-boot.js, admin-status.js, admin-feedback.js).
 * There were no inline event handlers and no javascript: URLs to deal with,
 * which is why 'self' was reachable at all.
 *
 * accounts.google.com is listed in script-src/frame-src/connect-src because
 * the landing page loads Google Identity Services -- but only when a
 * googleClientId is configured, so on a default install nothing is fetched
 * from it. Naming it unconditionally keeps the header static and cacheable.
 *
 * style-src DOES keep 'unsafe-inline', deliberately and not by oversight: nine
 * pages carry <style> blocks and the CSS-injection class is far weaker than
 * script injection (no execution). Hashing them would not help either, since
 * style-src hashes do not cover the one style= attribute without also adding
 * 'unsafe-hashes'. Worth revisiting if those blocks ever move to files.
 *
 * ld+json is untouched by script-src in every current browser -- it is a data
 * block, not executed -- so the structured data on the landing and /sip pages
 * keeps working.
 */
const CSP = [
  "default-src 'self'",
  "script-src 'self' https://accounts.google.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self' https://accounts.google.com",
  "frame-src https://accounts.google.com",
  "form-action 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "frame-ancestors 'none'",
].join('; ');

/**
 * Security headers, set once here rather than in each of sendJson/serveStatic/
 * servePublicFile so an error path or a future response helper cannot quietly
 * miss them.
 *
 * No Content-Security-Policy yet, and that omission is deliberate rather than
 * forgotten: index.html, app.js's host page and admin-status.html all carry
 * inline <script>, and the landing page loads Google Identity Services from
 * accounts.google.com. A CSP strict enough to be worth having would break all
 * of them today; shipping a permissive one with 'unsafe-inline' would just be
 * decoration. It needs the inline scripts lifted into files first -- tracked,
 * not silently dropped.
 *
 * HSTS is sent ONLY on requests that reached us over HTTPS, detected via
 * X-Forwarded-Proto. This is not pedantry -- sending it unconditionally is an
 * own goal that a browser finds instantly and curl never will:
 *
 *   hiccup binds 127.0.0.1 and Cloudflare terminates TLS, so the ORIGIN
 *   connection is always plain HTTP. Chrome treats 127.0.0.1 as a secure
 *   context, so it honours an HSTS header served over http://127.0.0.1:PORT
 *   and thereafter force-upgrades to https://127.0.0.1:PORT -- which nothing
 *   is listening on. Local access dies, and it stays dead for max-age.
 *
 * Through the tunnel X-Forwarded-Proto is https, so hiccup.monster still gets
 * HSTS exactly as intended. NOT preloaded: preload is effectively irreversible
 * and is the site owner's call, not a default.
 */
function setSecurityHeaders(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // /admin/status hosts the superuser control and the restart button; DENY
  // rather than SAMEORIGIN because nothing here is ever legitimately framed.
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  const proto = String((req.headers && req.headers['x-forwarded-proto']) || '').split(',')[0].trim();
  if (proto === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  }
  // A trace analyser has no business reading a camera or a location.
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
  res.setHeader('Content-Security-Policy', CSP);
}

const server = http.createServer((req, res) => {
  const startedAt = Date.now();
  setSecurityHeaders(req, res);
  res.on('finish', () => {
    console.log(req.method + ' ' + (req.url || '/') + ' ' + res.statusCode + ' ' +
      (Date.now() - startedAt) + 'ms');
  });
  Promise.resolve(handle(req, res)).catch((err) => {
    console.error('hiccup: unhandled route error:', err && (err.stack || err.message || err));
    if (!res.headersSent) {
      sendJson(res, 500, { error: (err && err.message) || 'internal error' });
    } else {
      try { res.end(); } catch { /* socket already gone */ }
    }
  });
});

server.on('error', (err) => {
  if (err && err.code === 'EADDRINUSE') {
    console.error('hiccup: port ' + PORT + ' is already in use.');
    console.error('Is another hiccup (or something else) running there? Stop it, or start');
    console.error('hiccup with a different port:  set PORT=8401 && node server.js');
    process.exit(1);
  }
  throw err;
});

/**
 * Start listening. Guarded by require.main so this file can be REQUIRED by a
 * test without a side effect that binds a port and arms three timers.
 *
 * That side effect is why 43 API routes had no automated coverage, and the
 * cost was concrete: /subscribe 404'd on the live site for four and a half
 * hours because nothing anywhere asserts that a page listed in PUBLIC_PAGES
 * actually resolves. test/http.js now spawns this file as a child process
 * against a scratch HICCUP_DATA_DIR and exercises the real routes.
 */
function start() {
  server.listen(PORT, HOST, () => {
    console.log('hiccup v' + VERSION + ' listening on http://' + HOST + ':' + PORT +
      '  (data: ' + DATA_DIR + ')');
    if (!analyzeCapture) {
      console.log('hiccup: NOTE — running without the analysis engine; uploads return 501');
    }
    startFeedbackDigestTimer();
    startRetentionTimer();
    startI18nRefreshTimer();
  });
  return server;
}

if (require.main === module) start();

module.exports = { server, start, handle, PORT, HOST, DATA_DIR, VERSION };

/**
 * GDPR Art. 5(1)(e): delete captures past config.captureRetentionDays.
 *
 * Polled hourly rather than daily for the same reason the digest is polled:
 * the schedule decision lives in lib/retention.js as "has today's sweep run
 * yet?", so a restart at any hour still gets exactly one sweep that day.
 * Disabled (0) is the default and is announced at boot — an unenforced
 * retention policy should be visible in the log, not silent.
 */
function startRetentionTimer() {
  const days = Number(config.captureRetentionDays) || 0;
  if (days <= 0) {
    console.log('hiccup: capture retention disabled (captureRetentionDays: 0) — captures are kept until deleted');
    return;
  }
  let retention;
  try { retention = require('./lib/retention'); } catch {
    console.error('hiccup: captureRetentionDays is set but lib/retention.js is missing — nothing will be deleted');
    return;
  }
  const tick = () => {
    try {
      const out = retention.sweepIfDue(DATA_DIR, days);
      if (out && out.removed) {
        console.log('hiccup: retention sweep removed ' + out.removed + ' capture(s) older than ' + days + ' days');
      }
      if (out && out.skippedUndated) {
        console.log('hiccup: retention sweep skipped ' + out.skippedUndated +
          ' capture(s) with no readable upload date (kept, not guessed at)');
      }
    } catch (e) {
      console.error('hiccup: retention sweep failed: ' + ((e && e.message) || e));
    }
  };
  const timer = setInterval(tick, 3600 * 1000);
  if (typeof timer.unref === 'function') timer.unref();
  tick();
  console.log('hiccup: capture retention armed — deleting captures older than ' + days + ' days');
}

/**
 * Wave 6: weekly feedback digest.
 *
 * Polls every 15 minutes rather than sleeping a week, because the schedule
 * decision lives in lib/feedback.js's digestDue() — which is written as "this
 * week's digest has not gone out yet", not "it is exactly Monday 09:00". That
 * matters on this box specifically: it reboots for Windows updates, so a
 * setInterval(7 days) would drift on every restart and could skip a week
 * entirely if the reboot landed on a Monday morning.
 */
function startFeedbackDigestTimer() {
  const to = String(config.digestRecipient || '').trim();
  if (!to) {
    console.log('hiccup: feedback digest disabled (no digestRecipient in config.json)');
    return;
  }
  const mail = getMail();
  if (!mail || !mail.isConfigured(DATA_DIR)) {
    console.log('hiccup: feedback digest recipient set, but data/email-config.json is ' +
      'missing or incomplete — feedback is still collected at /admin/feedback');
    return;
  }
  const tick = () => {
    sendFeedbackDigest({}).then((out) => {
      if (out && out.sent) console.log('hiccup: feedback digest sent to ' + out.to + ' (' + out.count + ' items)');
      else if (out && !out.ok) console.error('hiccup: feedback digest problem: ' + out.error);
    }).catch((e) => {
      console.error('hiccup: feedback digest threw: ' + ((e && e.message) || e));
    });
  };
  const timer = setInterval(tick, 15 * 60 * 1000);
  if (typeof timer.unref === 'function') timer.unref();   // never hold shutdown open
  tick();
  console.log('hiccup: feedback digest armed — Mondays 09:00 local, to ' + to);
}

/**
 * Nightly UI-translation refresh (midnight local).
 *
 * Re-scans public/*.html, public/*.js and this file for English UI strings and
 * records the ones whose hash has no entry in locales/fr|es|de.json into
 * `<dataDir>/i18n-missing.json`. It RECORDS rather than machine-translates:
 * generated text written into the repo unattended is text nobody reviewed, and
 * an untranslated string already renders as correct English, which is a much
 * better failure than a confident mistranslation. See lib/i18n.js.
 *
 * Polled every 15 minutes against lib/i18n.js's refreshDue() — the same shape as
 * startFeedbackDigestTimer() above, and for the same reason: a setInterval(24h)
 * on a box that reboots for Windows updates drifts by the boot time every
 * restart and skips the day entirely if the reboot straddles midnight. "Today's
 * refresh has not run yet" can do neither.
 *
 * Writes only inside DATA_DIR. Regenerating locales/ and public/i18n/ is a
 * deploy step (`npm run i18n`), never something the live service does to its own
 * source tree.
 */
function startI18nRefreshTimer() {
  let i18n;
  try { i18n = require('./lib/i18n'); } catch {
    console.log('hiccup: i18n refresh disabled (lib/i18n.js is not deployed)');
    return;
  }
  const tick = () => {
    try {
      const out = i18n.refreshIfDue(DATA_DIR);
      if (!out.ran) return;
      for (const line of out.lines) console.log('hiccup: i18n ' + line);
    } catch (e) {
      // A broken catalogue must never take the server down with it: the UI
      // falls back to English on its own and the report is not load-bearing.
      console.error('hiccup: i18n refresh failed: ' + ((e && e.message) || e));
    }
  };
  const timer = setInterval(tick, 15 * 60 * 1000);
  if (typeof timer.unref === 'function') timer.unref();
  tick();
  console.log('hiccup: i18n refresh armed — midnight local, report in ' + i18n.reportFile(DATA_DIR));
}

let shuttingDown = false;
/**
 * Close the listener and exit; forced after 3s if sockets linger.
 * @param {string} signal
 */
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log('hiccup: ' + signal + ' received, shutting down');
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
