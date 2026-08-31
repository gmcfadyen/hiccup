'use strict';
// tokens.js — long-lived API tokens for the MCP endpoint.
//
// Sessions cannot serve here: MCP clients (Claude Code, Claude Desktop,
// Cursor) send a static Authorization header from a config file, not cookies
// from a login flow. So: per-user revocable bearer tokens.
//
// Two deliberate differences from how sessions are stored:
//
//   1. Only a SHA-256 HASH of the token is persisted. A session lasts 30 days;
//      these live until revoked, sit in editor config files on laptops, and a
//      leaked data/api-tokens.json must not be a leaked credential. The full
//      token is shown exactly once, at creation — the same contract Stripe
//      and GitHub trained everyone on.
//   2. Verification compares digests with timingSafeEqual. Needless for a
//      32-byte random secret in practice, but it costs one line and removes
//      the class of question entirely.
//
// Zero dependencies beyond node:crypto and lib/store. No knowledge of HTTP or
// MCP — server.js owns "which header", this module owns "is it valid".

const crypto = require('crypto');
const path = require('path');
const store = require('./store');

const TOKEN_PREFIX = 'hk_';           // hiccup key
const TOKEN_BYTES = 32;
const MAX_TOKENS_PER_USER = 10;       // plenty for real use, a lid on abuse
const MAX_NAME_LEN = 60;
// lastUsedAt is nice to have in the UI but not worth a disk write per MCP
// call — throttle to once a minute per token.
const TOUCH_INTERVAL_MS = 60 * 1000;

let _file = null;
let _tokens = [];                     // [{id,userId,name,prefix,hash,createdAt,lastUsedAt}]

function _err(userMessage, detail) {
  const e = new Error(detail || userMessage);
  e.userMessage = userMessage;
  return e;
}

function _sha256Hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

/**
 * Load (or create) data/api-tokens.json.
 * @param {string} dataDir
 */
function initTokens(dataDir) {
  _file = path.join(dataDir, 'api-tokens.json');
  const raw = store.loadJson(_file, { tokens: [] });
  _tokens = Array.isArray(raw.tokens) ? raw.tokens.filter((t) => t && t.id && t.hash) : [];
}

function _save() {
  store.saveJson(_file, { tokens: _tokens });
}

function _ensureInit() {
  if (!_file) throw new Error('tokens not initialised — call initTokens(dataDir) first');
}

/** The caller-safe view: everything except the hash. */
function _publicToken(t) {
  return {
    id: t.id, name: t.name, prefix: t.prefix,
    createdAt: t.createdAt, lastUsedAt: t.lastUsedAt || null,
  };
}

/**
 * Mint a token for a user. The `token` in the result is the ONLY time the
 * full value exists outside the caller's hands — it is not stored.
 *
 * @param {string} userId
 * @param {string} name a label the user will recognise ("laptop — Claude Code")
 * @returns {{token: string, record: object}}
 */
function createToken(userId, name) {
  _ensureInit();
  const label = String(name || '').trim().slice(0, MAX_NAME_LEN);
  if (!label) throw _err('Give the token a name so you can recognise it later.');
  const mine = _tokens.filter((t) => t.userId === userId);
  if (mine.length >= MAX_TOKENS_PER_USER) {
    throw _err('Token limit reached (' + MAX_TOKENS_PER_USER + '). Revoke one you no longer use first.');
  }
  const secret = TOKEN_PREFIX + crypto.randomBytes(TOKEN_BYTES).toString('hex');
  const rec = {
    id: crypto.randomBytes(8).toString('hex'),
    userId,
    name: label,
    prefix: secret.slice(0, TOKEN_PREFIX.length + 6),
    hash: _sha256Hex(secret),
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
  };
  _tokens.push(rec);
  _save();
  return { token: secret, record: _publicToken(rec) };
}

/**
 * @param {string} userId
 * @returns {Array<object>} this user's tokens, hashes never included
 */
function listTokens(userId) {
  _ensureInit();
  return _tokens.filter((t) => t.userId === userId).map(_publicToken);
}

/**
 * Revoke one of the user's own tokens. Revoking someone else's id is a clean
 * false, not an oracle for which ids exist.
 * @returns {boolean} true when something was actually removed
 */
function revokeToken(userId, id) {
  _ensureInit();
  const before = _tokens.length;
  _tokens = _tokens.filter((t) => !(t.userId === userId && t.id === String(id)));
  if (_tokens.length === before) return false;
  _save();
  return true;
}

/** Every token a user has, gone — for account deletion. */
function revokeAllFor(userId) {
  _ensureInit();
  const before = _tokens.length;
  _tokens = _tokens.filter((t) => t.userId !== userId);
  if (_tokens.length !== before) _save();
  return before - _tokens.length;
}

/**
 * Resolve a presented bearer token to its owner.
 * @param {string} presented the raw "hk_..." value from the header
 * @returns {{userId: string, tokenId: string}|null}
 */
function verifyToken(presented) {
  _ensureInit();
  const s = String(presented || '');
  if (!s.startsWith(TOKEN_PREFIX)) return null;
  const digest = Buffer.from(_sha256Hex(s), 'hex');
  for (const t of _tokens) {
    const stored = Buffer.from(t.hash, 'hex');
    if (stored.length === digest.length && crypto.timingSafeEqual(stored, digest)) {
      const now = Date.now();
      const last = t.lastUsedAt ? Date.parse(t.lastUsedAt) : 0;
      if (!Number.isFinite(last) || now - last > TOUCH_INTERVAL_MS) {
        t.lastUsedAt = new Date(now).toISOString();
        try { _save(); } catch { /* a failed touch must never fail auth */ }
      }
      return { userId: t.userId, tokenId: t.id };
    }
  }
  return null;
}

module.exports = {
  initTokens, createToken, listTokens, revokeToken, revokeAllFor, verifyToken,
  TOKEN_PREFIX, MAX_TOKENS_PER_USER,
};
