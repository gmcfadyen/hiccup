// server.js — hiccup HTTP server: routes, auth glue, capture upload/analysis,
// chat proxy, static files. Plain node http, zero runtime dependencies.
// Contract: ARCHITECTURE.md §HTTP API. Windows-safe paths throughout.
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const store = require('./lib/store');
const auth = require('./lib/auth');
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
  return sess.user;
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
    res.writeHead(200, { 'Content-Type': STATIC_TYPES['.html'] });
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
    res.writeHead(200, { 'Content-Type': STATIC_TYPES[ext] });
    res.end(data);
  });
}

/** @param {http.ServerResponse} res plain-text 404 */
function notFoundText(res) {
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('not found');
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
 * Resolve a capture directory for this user, or null when the id is invalid
 * or the capture does not exist (ownership is structural: captures live under
 * the owner's directory only).
 * @param {object} user
 * @param {string} captureId
 * @returns {string|null}
 */
function findCaptureDir(user, captureId) {
  let dir;
  try {
    dir = store.captureDir(DATA_DIR, String(user.id), String(captureId || ''));
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
  let filename = String(req.headers['x-filename'] || '').trim();
  filename = filename.replace(/^.*[\\/]/, '').replace(/[ -]/g, '').slice(0, 200);
  if (!filename) filename = 'capture.bin';

  const id = store.newCaptureId();
  const dir = store.captureDir(DATA_DIR, String(user.id), id);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'original.bin'), buf);

  let analysis;
  try {
    analysis = await analyzeCapture(buf);
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
    stats: analysis.stats,
    findingCounts: countFindings(analysis.findings),
  };
  store.saveJson(path.join(dir, 'meta.json'), meta);
  store.saveJson(path.join(dir, 'analysis.json'), analysis);
  sendJson(res, 200, { id, meta });
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
 * Build the /api/chat system prompt: persona + capture stats + findings
 * summary + scope serialization.
 * @param {object} analysis AnalysisJSON
 * @param {{type:string,id:string}|undefined} scope
 * @returns {string}
 */
function buildSystemPrompt(analysis, scope) {
  const parts = [];
  parts.push(
    'You are hiccup, an expert SIP/SBC/H.323 engineer explaining a capture to an ' +
    'SBC-curious engineer. Be precise and practical: reference message/leg/call ids ' +
    'and timestamps from the capture when relevant, explain protocol concepts clearly, ' +
    'and say plainly when the capture does not contain the answer. Phone-number and ' +
    'credential material in the capture is already redacted; never invent replacements.'
  );
  parts.push('Capture stats: ' + JSON.stringify(analysis.stats || {}));
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
  const scopeText = buildScopeText(analysis, scope);
  if (scopeText) parts.push(scopeText);
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
  const dir = findCaptureDir(user, body.captureId);
  if (!dir) {
    sendJson(res, 404, { error: 'capture not found' });
    return;
  }
  const analysis = store.loadJson(path.join(dir, 'analysis.json'), null);
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
  const system = buildSystemPrompt(analysis, body.scope);
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
  const user = await auth.verifyPassword(String(body.email), String(body.password));
  if (!user) {
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

  // --- captures ---
  if (pathname === '/api/captures' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) { req.resume(); return; }
    return handleUpload(req, res, user);
  }
  if (pathname === '/api/captures' && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) return;
    sendJson(res, 200, store.listCaptures(DATA_DIR, String(user.id)));
    return;
  }

  const capMatch = pathname.match(/^\/api\/captures\/([A-Za-z0-9_-]{1,64})(\/analysis)?$/);
  if (capMatch) {
    const user = requireAuth(req, res);
    if (!user) return;
    const captureId = capMatch[1];
    if (capMatch[2] && method === 'GET') {
      const dir = findCaptureDir(user, captureId);
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
      const removed = store.deleteCapture(DATA_DIR, String(user.id), captureId);
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

  // --- anything else under /api is a JSON 404 ---
  if (pathname.startsWith('/api/')) {
    sendJson(res, 404, { error: 'not found' });
    return;
  }

  // --- pages + static ---
  if (method === 'GET' || method === 'HEAD') {
    if (pathname === '/') return servePublicFile(res, 'index.html');
    if (pathname === '/app') return servePublicFile(res, 'app.html');
    return serveStatic(res, pathname);
  }

  notFoundText(res);
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const server = http.createServer((req, res) => {
  const startedAt = Date.now();
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

server.listen(PORT, HOST, () => {
  console.log('hiccup v' + VERSION + ' listening on http://' + HOST + ':' + PORT +
    '  (data: ' + DATA_DIR + ')');
  if (!analyzeCapture) {
    console.log('hiccup: NOTE — running without the analysis engine; uploads return 501');
  }
});

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
