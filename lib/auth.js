// lib/auth.js — accounts, sessions, Google sign-in verification.
// Zero dependencies (crypto, https); state persisted via lib/store.js to
// data/users.json + data/sessions.json.
'use strict';

const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { loadJson, saveJson } = require('./store');

// scrypt parameters — frozen in the stored-hash format string.
const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 64;

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days, sliding
const SESSION_SAVE_DEBOUNCE_MS = 5000;
const SESSION_SWEEP_MS = 60 * 60 * 1000; // hourly
const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const JWKS_CACHE_MS = 12 * 60 * 60 * 1000; // 12h
const JWKS_TIMEOUT_MS = 5000;

// ── module state (populated by initAuth) ────────────────────────────────────
let _dataDir = null;
let _config = {};
let _users = [];          // array of user records
let _sessions = {};       // token -> { userId, createdAt, expiresAt }
let _usersFile = null;
let _sessionsFile = null;
let _sessionSaveTimer = null;
let _sweepTimer = null;
let _dummyHash = null;    // precomputed hash for timing-safe unknown-email path
let _jwksCache = { ts: 0, keys: null };

/** Build an Error carrying a user-safe message. */
function _err(userMessage, detail) {
  const e = new Error(detail || userMessage);
  e.userMessage = userMessage;
  return e;
}

function _ensureInit() {
  if (!_dataDir) throw new Error('auth: initAuth(dataDir, config) not called');
}

/** scrypt-hash a password into 'scrypt:N:r:p:saltHex:hashHex'. */
function _hashPassword(password, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, 'hex') : crypto.randomBytes(16);
  const key = crypto.scryptSync(String(password), salt, SCRYPT_KEYLEN,
    { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
  return ['scrypt', SCRYPT_N, SCRYPT_R, SCRYPT_P,
    salt.toString('hex'), key.toString('hex')].join(':');
}

/** Timing-safe check of a password against a stored 'scrypt:...' string. */
function _checkPassword(password, stored) {
  const parts = String(stored || '').split(':');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const N = parseInt(parts[1], 10), r = parseInt(parts[2], 10), p = parseInt(parts[3], 10);
  if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p)) return false;
  let key;
  try {
    key = crypto.scryptSync(String(password), Buffer.from(parts[4], 'hex'),
      SCRYPT_KEYLEN, { N, r, p });
  } catch {
    return false;
  }
  const expected = Buffer.from(parts[5], 'hex');
  if (expected.length !== key.length) return false;
  return crypto.timingSafeEqual(key, expected);
}

/** Public (client-safe) view of a user record — never leaks passwordHash. */
function _publicUser(u) {
  return {
    id: u.id, email: u.email, name: u.name, role: u.role,
    createdAt: u.createdAt, lastLoginAt: u.lastLoginAt,
  };
}

function _saveUsers() {
  saveJson(_usersFile, _users);
}

/** Debounced (5s) write-behind persist of sessions.json. */
function _scheduleSessionSave() {
  if (_sessionSaveTimer) return;
  _sessionSaveTimer = setTimeout(() => {
    _sessionSaveTimer = null;
    try { saveJson(_sessionsFile, _sessions); } catch { /* retry on next change */ }
  }, SESSION_SAVE_DEBOUNCE_MS);
  if (_sessionSaveTimer.unref) _sessionSaveTimer.unref();
}

/** Remove expired sessions; persist if anything changed. */
function _sweepSessions() {
  const now = Date.now();
  let changed = false;
  for (const token of Object.keys(_sessions)) {
    const s = _sessions[token];
    if (!s || typeof s.expiresAt !== 'number' || s.expiresAt <= now) {
      delete _sessions[token];
      changed = true;
    }
  }
  if (changed) _scheduleSessionSave();
}

/**
 * Initialise the auth module: load data/users.json + data/sessions.json from
 * `dataDir`, precompute the dummy-verify hash, and start the hourly sweep of
 * expired sessions. Safe to call again (re-reads from disk, restarts timers).
 * @param {string} dataDir directory holding users.json / sessions.json
 * @param {object} config app config (uses config.googleClientId)
 */
function initAuth(dataDir, config) {
  _dataDir = dataDir;
  _config = config || {};
  _usersFile = path.join(dataDir, 'users.json');
  _sessionsFile = path.join(dataDir, 'sessions.json');

  const users = loadJson(_usersFile, []);
  _users = Array.isArray(users) ? users : [];
  const sessions = loadJson(_sessionsFile, {});
  _sessions = (sessions && typeof sessions === 'object' && !Array.isArray(sessions)) ? sessions : {};

  // Burn the same scrypt cost for unknown emails as for real ones.
  if (!_dummyHash) _dummyHash = _hashPassword('hiccup-dummy-password-for-timing');

  if (_sweepTimer) clearInterval(_sweepTimer);
  _sweepTimer = setInterval(_sweepSessions, SESSION_SWEEP_MS);
  if (_sweepTimer.unref) _sweepTimer.unref();
  if (_sessionSaveTimer) { clearTimeout(_sessionSaveTimer); _sessionSaveTimer = null; }

  _sweepSessions();
}

/**
 * Create a user account. Email is lowercased+trimmed and must be unique;
 * password (when given) must be >= 8 chars. The first user ever created gets
 * role 'admin'. Google special case: when called with a `googleSub` and the
 * email already exists, the existing account is linked to that sub (if not
 * already linked to a different one) and returned — that is Google sign-in to
 * an existing account, not a duplicate signup.
 * @param {{email:string, password?:string, name?:string, googleSub?:string}} opts
 * @returns {object} public user {id,email,name,role,createdAt,lastLoginAt}
 * @throws {Error} with .userMessage on invalid email/password or duplicate email
 */
function createUser({ email, password, name, googleSub } = {}) {
  _ensureInit();
  const em = String(email || '').trim().toLowerCase();
  if (!em || em.indexOf('@') < 1) throw _err('A valid email address is required.');

  const existing = _users.find(u => u.email === em);
  if (existing) {
    if (googleSub) {
      if (existing.googleSub && existing.googleSub !== googleSub) {
        throw _err('This email is already linked to a different Google account.');
      }
      if (!existing.googleSub) { existing.googleSub = googleSub; _saveUsers(); }
      return _publicUser(existing);
    }
    throw _err('An account with that email already exists.');
  }

  if (!googleSub) {
    if (typeof password !== 'string' || password.length < 8) {
      throw _err('Password must be at least 8 characters.');
    }
  } else if (password != null && String(password).length > 0 && String(password).length < 8) {
    throw _err('Password must be at least 8 characters.');
  }

  const user = {
    id: crypto.randomBytes(8).toString('hex'),
    email: em,
    name: (name && String(name).trim()) || em.split('@')[0],
    passwordHash: (typeof password === 'string' && password.length >= 8)
      ? _hashPassword(password) : null,
    googleSub: googleSub || null,
    role: _users.length === 0 ? 'admin' : 'user',
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  };
  _users.push(user);
  _saveUsers();
  return _publicUser(user);
}

/**
 * Verify an email+password pair. Timing-safe: unknown emails and accounts
 * without a password still burn a full scrypt before returning null.
 * Updates lastLoginAt on success.
 * @param {string} email
 * @param {string} password
 * @returns {object|null} public user on success, null otherwise
 */
function verifyPassword(email, password) {
  _ensureInit();
  const em = String(email || '').trim().toLowerCase();
  const user = _users.find(u => u.email === em);
  if (!user || !user.passwordHash) {
    _checkPassword(String(password || ''), _dummyHash); // dummy verify — no existence leak
    return null;
  }
  if (!_checkPassword(String(password || ''), user.passwordHash)) return null;
  user.lastLoginAt = new Date().toISOString();
  _saveUsers();
  return _publicUser(user);
}

/**
 * Create a session for a user: 32-byte random hex token, 30-day sliding
 * expiry. Persisted write-behind (5s debounce). Also stamps lastLoginAt
 * (a new session is a login, whichever flow produced it).
 * @param {string} userId
 * @returns {{token:string, expiresAt:number}} expiresAt = epoch ms
 */
function createSession(userId) {
  _ensureInit();
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  _sessions[token] = { userId, createdAt: now, expiresAt: now + SESSION_TTL_MS };
  const user = _users.find(u => u.id === userId);
  if (user) { user.lastLoginAt = new Date(now).toISOString(); _saveUsers(); }
  _scheduleSessionSave();
  return { token, expiresAt: _sessions[token].expiresAt };
}

/**
 * Resolve a session token to its user. Sliding expiry: a valid lookup
 * touches the session, extending it 30 days from now (persisted write-behind).
 * @param {string} token
 * @returns {{user: object}|null} public user, or null when missing/expired
 */
function getSession(token) {
  _ensureInit();
  if (typeof token !== 'string' || !token) return null;
  const s = _sessions[token];
  if (!s) return null;
  const now = Date.now();
  if (typeof s.expiresAt !== 'number' || s.expiresAt <= now) {
    delete _sessions[token];
    _scheduleSessionSave();
    return null;
  }
  const user = _users.find(u => u.id === s.userId);
  if (!user) {
    delete _sessions[token];
    _scheduleSessionSave();
    return null;
  }
  s.expiresAt = now + SESSION_TTL_MS; // touch
  _scheduleSessionSave();
  return { user: _publicUser(user) };
}

/**
 * Destroy one session (logout). No-op when the token is unknown.
 * @param {string} token
 */
function destroySession(token) {
  _ensureInit();
  if (_sessions[token]) {
    delete _sessions[token];
    _scheduleSessionSave();
  }
}

/**
 * Number of user accounts.
 * @returns {number}
 */
function countUsers() {
  _ensureInit();
  return _users.length;
}

/**
 * Look up a user by email (lowercased+trimmed). Convenience export beyond the
 * frozen contract — handy for the Google sign-in route.
 * @param {string} email
 * @returns {object|null} public user or null
 */
function findUserByEmail(email) {
  _ensureInit();
  const em = String(email || '').trim().toLowerCase();
  const user = _users.find(u => u.email === em);
  return user ? _publicUser(user) : null;
}

/**
 * Look up a user by id. Convenience export beyond the frozen contract —
 * handy for admin routes that address a user by id rather than email.
 * @param {string} userId
 * @returns {object|null} public user or null
 */
function findUserById(userId) {
  _ensureInit();
  const id = String(userId == null ? '' : userId);
  const user = _users.find(u => u.id === id);
  return user ? _publicUser(user) : null;
}

/**
 * Every user account, newest first. Public-view only (never leaks
 * passwordHash/googleSub) — for the site-admin user-management panel.
 * @returns {object[]}
 */
function listUsers() {
  _ensureInit();
  return _users
    .slice()
    .sort((a, b) => (Date.parse(b.createdAt || '') || 0) - (Date.parse(a.createdAt || '') || 0))
    .map(_publicUser);
}

// ── Google ID token verification ────────────────────────────────────────────

/** Fetch Google's JWKS over https with a 5s timeout. */
function _fetchJwks() {
  return new Promise((resolve, reject) => {
    const req = https.get(JWKS_URL, res => {
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error('JWKS HTTP ' + res.statusCode));
      }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const keys = JSON.parse(Buffer.concat(chunks).toString('utf8')).keys;
          if (!Array.isArray(keys)) return reject(new Error('JWKS: no keys array'));
          resolve(keys);
        } catch (e) { reject(e); }
      });
    });
    req.setTimeout(JWKS_TIMEOUT_MS, () => req.destroy(new Error('JWKS fetch timeout')));
    req.on('error', reject);
  });
}

/** JWKS with a 12h cache; `force` bypasses the cache (unknown kid → rotation). */
async function _getJwks(force) {
  const now = Date.now();
  if (!force && _jwksCache.keys && now - _jwksCache.ts < JWKS_CACHE_MS) {
    return _jwksCache.keys;
  }
  const keys = await _fetchJwks();
  _jwksCache = { ts: now, keys };
  return keys;
}

/** base64url segment -> JSON object, or null. */
function _b64urlJson(seg) {
  try {
    return JSON.parse(Buffer.from(String(seg), 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

/**
 * Verify a Google Identity Services ID token (JWT). Checks the RS256
 * signature against Google's JWKS (cached 12h, refetched once on unknown
 * kid), then iss (accounts.google.com | https://accounts.google.com),
 * aud === config.googleClientId, and exp. Every failure path rejects with an
 * Error carrying `.userMessage`.
 * @param {string} credential the ID token from GIS
 * @returns {Promise<{sub:string, email:string, name:string, picture:string|null}>}
 */
async function verifyGoogleIdToken(credential) {
  _ensureInit();
  const fail = (detail) => {
    throw _err('Google sign-in failed. Please try again.', 'google id token: ' + detail);
  };
  if (!_config.googleClientId) {
    throw _err('Google sign-in is not configured on this server.');
  }
  if (typeof credential !== 'string') fail('credential not a string');
  const parts = credential.split('.');
  if (parts.length !== 3) fail('not a JWT (expected 3 segments)');

  const header = _b64urlJson(parts[0]);
  const payload = _b64urlJson(parts[1]);
  if (!header || !payload) fail('undecodable header/payload');
  if (header.alg !== 'RS256') fail('alg is ' + header.alg + ', expected RS256');
  if (!header.kid) fail('missing kid');

  let sig;
  try { sig = Buffer.from(parts[2], 'base64url'); } catch { sig = null; }
  if (!sig || !sig.length) fail('undecodable signature');

  let keys;
  try {
    keys = await _getJwks(false);
  } catch (e) {
    throw _err('Could not reach Google to verify the sign-in. Please try again.',
      'JWKS fetch: ' + e.message);
  }
  let jwk = keys.find(k => k.kid === header.kid && k.kty === 'RSA');
  if (!jwk) {
    // Key rotation: refresh the cache once before giving up.
    try { keys = await _getJwks(true); } catch { keys = []; }
    jwk = keys.find(k => k.kid === header.kid && k.kty === 'RSA');
  }
  if (!jwk) fail('no JWKS key matches kid ' + header.kid);

  let publicKey;
  try {
    publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  } catch (e) {
    fail('bad JWK: ' + e.message);
  }
  const signedPart = Buffer.from(parts[0] + '.' + parts[1], 'utf8');
  let ok = false;
  try {
    ok = crypto.verify('RSA-SHA256', signedPart, publicKey, sig);
  } catch (e) {
    fail('signature verify threw: ' + e.message);
  }
  if (!ok) fail('signature invalid');

  if (payload.iss !== 'accounts.google.com' && payload.iss !== 'https://accounts.google.com') {
    fail('bad iss ' + payload.iss);
  }
  if (payload.aud !== _config.googleClientId) fail('aud mismatch');
  if (typeof payload.exp !== 'number' || payload.exp * 1000 <= Date.now()) {
    fail('token expired');
  }
  if (!payload.sub || !payload.email) fail('missing sub/email claim');

  return {
    sub: String(payload.sub),
    email: String(payload.email),
    name: payload.name ? String(payload.name) : String(payload.email).split('@')[0],
    picture: payload.picture ? String(payload.picture) : null,
  };
}

/**
 * Erase a user record and every session it owns (GDPR Art. 17).
 *
 * Sessions are destroyed too, not just the record: leaving a live session
 * behind would let a "deleted" account keep making authenticated requests
 * until its token happened to expire.
 *
 * @param {string} userId
 * @returns {boolean} true when a record was found and removed
 */
function deleteUser(userId) {
  _ensureInit();
  const i = _users.findIndex((u) => u && u.id === userId);
  if (i === -1) return false;
  _users.splice(i, 1);
  _saveUsers();
  let killed = 0;
  for (const token of Object.keys(_sessions)) {
    const s = _sessions[token];
    if (s && s.userId === userId) { delete _sessions[token]; killed++; }
  }
  if (killed) _scheduleSessionSave();
  return true;
}

module.exports = {
  initAuth,
  createUser,
  deleteUser,
  verifyPassword,
  createSession,
  getSession,
  destroySession,
  verifyGoogleIdToken,
  countUsers,
  findUserByEmail, // extra convenience beyond the frozen contract
  findUserById,
  listUsers,
};
