'use strict';
// lib/sso.js — enterprise SSO orchestration: the HTTP calls to a team's IdP,
// the platform-wide kill switch, the ephemeral login-flow state, and the
// account-linking policy. lib/oidc.js has the protocol math (PKCE, claims
// validation); lib/teams.js has the persisted per-team config; this module
// is what turns "a browser lands on /api/auth/sso/callback" into a session.
//
// New attack surface worth naming up front: this is the only place in
// hiccup that makes an HTTP request to a host an ADMIN CONFIGURED rather
// than one hardcoded in the app (Stripe's api.stripe.com, Google's fixed
// JWKS URL). A team owner names an issuer; hiccup then fetches whatever
// that issuer's discovery document points at. Left unguarded, that is a
// standing SSRF primitive: a malicious or compromised team owner could
// point "issuer" at http://127.0.0.1:11434 (hiccup's own Ollama), at
// 169.254.169.254 (a cloud metadata endpoint), or at any address on the
// operator's LAN, and use hiccup's own server as the network vantage point
// to probe or attack it. _safeFetch() below is the guard against that --
// see its own comment for the specifics.

const https = require('https');
const dns = require('dns');
const crypto = require('crypto');
const oidc = require('./oidc');
const auth = require('./auth');
const teams = require('./teams');

const DISCOVERY_TIMEOUT_MS = 8000;
const TOKEN_TIMEOUT_MS = 8000;
const MAX_RESPONSE_BYTES = 512 * 1024; // discovery docs and token responses are small; a giant body is not legitimate
const STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes to complete the round trip at the IdP

let _dataDir = null;
let _ssoSettingsFile = null;

/** {state -> {teamId, nonce, pkceVerifier, next, expires}}. Process memory
 * only, deliberately not persisted: a restart mid-login simply means that
 * one in-flight attempt has to start over, which is a fair trade for never
 * having a CSRF state token survive on disk. */
const _states = new Map();

function initSso(dataDir) {
  _dataDir = dataDir;
  _ssoSettingsFile = require('path').join(dataDir, 'sso-settings.json');
}

function _ensureInit() {
  if (!_dataDir) throw new Error('sso: initSso(dataDir) not called');
}

/** Build an Error carrying a user-safe message (same convention as lib/auth.js, lib/teams.js). */
function _err(userMessage, detail) {
  const e = new Error(detail || userMessage);
  e.userMessage = userMessage;
  return e;
}

// ── platform-wide kill switch ────────────────────────────────────────────────
// Deliberately NOT part of data/config.json, which is read once at boot --
// this needs to take effect on the very next request, so a site admin can
// react to a live problem without an elevated service restart. Read fresh
// from disk on every check rather than cached; the file is tiny and this is
// only consulted on SSO-specific routes; the load-mutate-save-atomic-rename
// pattern (via lib/store.js's saveJson) makes concurrent access safe.

const { loadJson, saveJson } = require('./store');

/** True unless a site admin has explicitly turned SSO off. Fails OPEN
 * (missing/corrupt file reads as enabled) -- the opposite of team-sso.json's
 * fail-closed default, because the two failure directions have opposite
 * costs: a missing team config should never grant sign-in, but a missing
 * kill-switch file should never silently lock every SSO-enforced team out. */
function isSsoGloballyEnabled() {
  _ensureInit();
  const s = loadJson(_ssoSettingsFile, { enabled: true });
  return !s || s.enabled !== false;
}

/** Flip the platform-wide switch. Site-admin only -- enforced by the caller. */
function setSsoGloballyEnabled(enabled, actingUserId) {
  _ensureInit();
  const s = { enabled: !!enabled, updatedAt: new Date().toISOString(), updatedBy: actingUserId };
  saveJson(_ssoSettingsFile, s);
  return s;
}

// ── SSRF-guarded HTTPS ────────────────────────────────────────────────────────

/**
 * Is this IP address in a private, loopback, link-local, or otherwise
 * non-public range? Deliberately conservative (a false positive just means
 * a legitimate IdP has to use a public address, which every real IdP
 * already does) -- the failure mode that matters is a false NEGATIVE, an
 * internal address that slips through.
 * @param {string} ip a dotted IPv4 or colon IPv6 address (already resolved,
 *   not a hostname)
 * @param {'IPv4'|'IPv6'} family
 * @returns {boolean}
 */
function _isPrivateIp(ip, family) {
  if (family === 'IPv6') {
    const s = ip.toLowerCase();
    if (s === '::1') return true; // loopback
    if (s === '::') return true; // unspecified
    if (/^fe[89ab][0-9a-f]:/.test(s)) return true; // fe80::/10 link-local
    if (/^f[cd][0-9a-f]{2}:/.test(s)) return true; // fc00::/7 unique local
    if (/^ff/.test(s)) return true; // ff00::/8 multicast
    // IPv4-mapped (::ffff:a.b.c.d) -- unwrap and re-check as IPv4, because
    // this is exactly how an IPv4-only blocklist gets bypassed over IPv6.
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(s);
    if (mapped) return _isPrivateIp(mapped[1], 'IPv4');
    return false;
  }
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) {
    return true; // unparsable -- refuse rather than guess
  }
  const [a, b] = parts;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 127) return true; // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local (cloud metadata lives here)
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 0 && parts[2] === 0) return true; // 192.0.0.0/24
  if (a === 192 && b === 0 && parts[2] === 2) return true; // 192.0.2.0/24 TEST-NET-1
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmarking
  if (a === 198 && b === 51 && parts[2] === 100) return true; // 198.51.100.0/24 TEST-NET-2
  if (a === 203 && b === 0 && parts[2] === 113) return true; // 203.0.113.0/24 TEST-NET-3
  if (a >= 224) return true; // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved + 255.255.255.255
  return false;
}

/**
 * Fetch a URL, refusing anything that is not https or that resolves to a
 * non-public address -- see the module header for why this exists at all.
 *
 * Two things make this actually safe rather than just look safe:
 *
 * 1. DNS is resolved ONCE, up front, and the connection is made directly to
 *    that resolved IP (via https.request's own `lookup` override) rather
 *    than letting Node re-resolve the hostname when it connects. Without
 *    this, an attacker controlling DNS for their own issuer domain could
 *    pass the check against one IP (a public one, on the first lookup) and
 *    then have the actual TCP connection resolve to a different, internal
 *    one moments later -- "DNS rebinding", the standard way naive SSRF
 *    guards get bypassed. TLS servername/Host still use the original
 *    hostname, so certificate validation is unaffected.
 * 2. No redirects are followed. A 3xx response is treated as a failure.
 *    Real discovery/token/userinfo endpoints do not redirect in practice,
 *    and redirect-following is itself a well-known way to smuggle a
 *    request past an SSRF check that only validated the first hop.
 *
 * @param {string} url must be https
 * @param {{method?:string, headers?:object, body?:string, timeoutMs?:number}} o
 * @returns {Promise<{status:number, body:string}>}
 */
function _safeFetch(url, o) {
  const opts = o || {};
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(url); } catch { return reject(_err('Not a valid URL.', 'sso: bad url ' + url)); }
    if (parsed.protocol !== 'https:') {
      return reject(_err('The identity provider must be reachable over https.', 'sso: non-https url ' + url));
    }
    const hostname = parsed.hostname;

    dns.lookup(hostname, { all: true, verbatim: true }, (dnsErr, addresses) => {
      if (dnsErr || !addresses || !addresses.length) {
        return reject(_err(
          "Could not resolve your identity provider's address.",
          'sso: dns lookup failed for ' + hostname + ': ' + (dnsErr && dnsErr.message)
        ));
      }
      const bad = addresses.find((a) => _isPrivateIp(a.address, a.family === 6 ? 'IPv6' : 'IPv4'));
      if (bad) {
        return reject(_err(
          'Your identity provider must be reachable on the public internet.',
          'sso: refused private address ' + bad.address + ' for ' + hostname
        ));
      }
      // Pin the connection to the address we just checked (see doc comment).
      const pinnedIp = addresses[0].address;

      const req = https.request({
        hostname: pinnedIp,
        servername: hostname, // SNI + certificate validation still use the real name
        port: parsed.port || 443,
        path: parsed.pathname + parsed.search,
        method: opts.method || 'GET',
        headers: Object.assign({ Host: hostname }, opts.headers || {}),
        // Do not let Node re-resolve the hostname at connect time -- we
        // already resolved it above and that is the address being used.
        lookup: (_h, _o2, cb) => cb(null, pinnedIp, a2family(pinnedIp)),
      }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400) {
          res.resume();
          return reject(_err(
            "Your identity provider's response was unexpected.",
            'sso: unexpected redirect ' + res.statusCode + ' from ' + url
          ));
        }
        const chunks = [];
        let bytes = 0;
        res.on('data', (c) => {
          bytes += c.length;
          if (bytes > MAX_RESPONSE_BYTES) {
            req.destroy();
            return reject(_err('Your identity provider sent an unexpectedly large response.', 'sso: response too large from ' + url));
          }
          chunks.push(c);
        });
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      });
      req.on('error', (e) => reject(_err(
        "Could not reach your identity provider.", 'sso: request error to ' + url + ': ' + e.message
      )));
      req.setTimeout(opts.timeoutMs || DISCOVERY_TIMEOUT_MS, () => {
        req.destroy();
        reject(_err("Your identity provider did not respond in time.", 'sso: timeout fetching ' + url));
      });
      if (opts.body) req.write(opts.body);
      req.end();
    });
  });
}

function a2family(ip) { return ip.indexOf(':') === -1 ? 4 : 6; }

/**
 * Fetch and validate an issuer's discovery document.
 * @param {string} issuer
 * @returns {Promise<object>} the validated discovery shape (see oidc.validateDiscovery)
 * @throws {Error} with .userMessage on any network or validation failure
 */
async function discover(issuer) {
  const res = await _safeFetch(oidc.wellKnownUrl(issuer), { timeoutMs: DISCOVERY_TIMEOUT_MS });
  if (res.status !== 200) {
    throw _err("Could not read your identity provider's configuration.", 'sso: discovery HTTP ' + res.status);
  }
  let doc;
  try { doc = JSON.parse(res.body); } catch {
    throw _err("Your identity provider's configuration response was not valid JSON.", 'sso: discovery not JSON');
  }
  const v = oidc.validateDiscovery(doc, issuer);
  if (!v.ok) throw _err("Your identity provider's configuration looks wrong: " + v.error, 'sso: ' + v.error);
  return v;
}

/**
 * Exchange an authorization code for tokens.
 * @param {object} doc the validated discovery document (from discover())
 * @param {{clientId:string, clientSecret:string, code:string, redirectUri:string, codeVerifier:string}} o
 * @returns {Promise<object>} the parsed token response
 * @throws {Error} with .userMessage on any failure -- the IdP's own error
 *   text is NEVER included in the message (it can echo attacker-influenced
 *   strings back through this exact path), only logged by the caller.
 */
async function exchangeCode(doc, o) {
  const auth2 = oidc.tokenAuth(doc.tokenAuthMethods, o.clientId, o.clientSecret);
  const params = Object.assign({
    grant_type: 'authorization_code',
    code: o.code,
    redirect_uri: o.redirectUri,
    code_verifier: o.codeVerifier,
  }, auth2.extraParams);
  const body = new URLSearchParams(params).toString();
  const res = await _safeFetch(doc.token_endpoint, {
    method: 'POST',
    timeoutMs: TOKEN_TIMEOUT_MS,
    headers: Object.assign(
      { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      auth2.headers
    ),
    body,
  });
  let td = null;
  try { td = JSON.parse(res.body); } catch { /* handled below */ }
  if (!td || td.error || !td.id_token) {
    const detail = (td && (td.error_description || td.error)) || ('HTTP ' + res.status + ', no id_token');
    throw _err('Sign-in failed at your identity provider.', 'sso: token exchange failed: ' + detail);
  }
  return td;
}

/**
 * Fetch userinfo, only ever used as a fallback when the id_token itself
 * carries no email claim. The result is trusted only if its `sub` matches
 * the id_token's `sub` (OIDC Core s5.3.2) -- otherwise a userinfo endpoint
 * that returned the WRONG person's claims would silently sign someone in as
 * someone else.
 * @param {object} doc
 * @param {string} accessToken
 * @param {string} expectedSub
 * @returns {Promise<object|null>} the userinfo claims, or null on any failure
 */
async function fetchUserinfo(doc, accessToken, expectedSub) {
  if (!doc.userinfo_endpoint || !accessToken) return null;
  try {
    const res = await _safeFetch(doc.userinfo_endpoint, {
      timeoutMs: TOKEN_TIMEOUT_MS,
      headers: { Authorization: 'Bearer ' + accessToken, Accept: 'application/json' },
    });
    const ui = JSON.parse(res.body);
    if (!ui || ui.sub !== expectedSub) return null;
    return ui;
  } catch {
    return null;
  }
}

// ── login-flow state (CSRF state, nonce, PKCE verifier) ─────────────────────

function _sweepStates() {
  const now = Date.now();
  for (const [k, v] of _states) if (v.expires < now) _states.delete(k);
}

/**
 * Mint and store the state for one login attempt.
 * @param {{teamId:string, next:string}} o
 * @returns {{state:string, nonce:string, verifier:string, challenge:string}}
 */
function beginState(o) {
  _sweepStates();
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  const { verifier, challenge } = oidc.makePkce();
  _states.set(state, { teamId: o.teamId, nonce, pkceVerifier: verifier, next: o.next, expires: Date.now() + STATE_TTL_MS });
  return { state, nonce, verifier, challenge };
}

/**
 * Consume a state token: single-use, deleted here BEFORE the caller does
 * anything else with it (in particular, before the token exchange), so a
 * replayed callback URL -- the same `code`+`state` submitted twice -- can
 * never complete twice. Expired entries are treated as already-gone.
 * @param {string} state
 * @returns {{teamId:string, nonce:string, pkceVerifier:string, next:string}|null}
 */
function consumeState(state) {
  const st = _states.get(state);
  if (!st) return null;
  _states.delete(state);
  if (st.expires < Date.now()) return null;
  return st;
}

// ── account-linking policy ───────────────────────────────────────────────────

/**
 * Given a validated OIDC identity, decide who signs in -- creating or
 * linking an account as needed. Four branches, evaluated in order, mirroring
 * a threat model worth stating plainly: an identity provider asserting an
 * email address must never be able to capture an account it does not own.
 *
 *   (a) Known SSO identity (this exact team+sub signed in before) -> sign in.
 *   (b) Email matches a user ALREADY ON this team -> link (first SSO login
 *       for someone who joined normally).
 *   (c) Email matches a user NOT on this team -> REFUSE. Never auto-link
 *       across teams -- unlike Google sign-in's email-match linking
 *       elsewhere in this file, which is deliberately not reused here for
 *       exactly this reason.
 *   (d) No match at all -> JIT-provision a new member, if the domain is
 *       claimed and the team has room.
 *
 * @param {object} cfg the team's SSO config (from teams.getTeamSso)
 * @param {{sub:string, iss:string, email:string, name:string}} claims
 * @returns {Promise<{user:object, jit:boolean}|{error:string}>}
 */
async function resolveSignIn(cfg, claims) {
  const teamId = cfg.teamId;

  // (a) returning SSO user
  const known = auth.findUserBySso(teamId, claims.sub);
  if (known) {
    if (teams.getTeamIdFor(known.id) !== teamId) {
      // Removed from the team since their last SSO login.
      return { error: 'Your account is no longer on this team. Contact your administrator.' };
    }
    return { user: auth.findUserByEmail(known.email), jit: false };
  }

  const domain = oidc.emailDomain(claims.email);
  const existing = auth.findRawUserByEmail(claims.email);

  // (b) existing member of THIS team, first time through SSO
  if (existing && teams.getTeamIdFor(existing.id) === teamId) {
    if (!domain || !Array.isArray(cfg.domains) || !cfg.domains.includes(domain)) {
      return { error: "Your email is outside this workspace's SSO domains. Sign in with your password instead." };
    }
    const linked = auth.linkUserSso(existing.id, { teamId, sub: claims.sub, iss: claims.iss });
    return { user: linked, jit: false };
  }

  // (c) existing account, but not on this team -- hard refuse, never link
  if (existing) {
    return { error: 'An account already exists for this email. Ask your team owner to invite it, or sign in with your existing credentials.' };
  }

  // (d) nobody by this email at all -- JIT provision, if the domain is claimed
  if (!domain || !Array.isArray(cfg.domains) || !cfg.domains.includes(domain)) {
    return { error: 'Single sign-on is not configured for this email domain.' };
  }
  let created;
  try {
    created = await auth.createUser({
      email: claims.email,
      name: claims.name || claims.email.split('@')[0],
      sso: { teamId, sub: claims.sub, iss: claims.iss },
    });
  } catch (e) {
    // Raced with something else creating the same email between the lookup
    // above and here -- one more lookup rather than a confusing 500.
    const raced = auth.findRawUserByEmail(claims.email);
    if (!raced) return { error: (e && e.userMessage) || 'Could not sign in.' };
    if (teams.getTeamIdFor(raced.id) === teamId) return { user: auth.findUserByEmail(raced.email), jit: false };
    return { error: 'An account already exists for this email. Ask your team owner to invite it, or sign in with your existing credentials.' };
  }
  try {
    teams.addMemberForSso(created.id, teamId);
  } catch (e) {
    // The account now exists but could not be seated (team full, or somehow
    // already on a team from the same race). Leave the account -- it is
    // real and the person can be invited properly -- and report clearly.
    return { error: (e && e.userMessage) || 'Could not add you to this team.' };
  }
  return { user: created, jit: true };
}

/**
 * Should a password (or Google) sign-in be refused because this user's team
 * requires SSO? Checked ONLY after the password has already verified, by
 * the caller -- so a wrong-password attempt against an SSO-enforced account
 * still gets the ordinary "invalid credentials" message, not a tell that
 * reveals SSO enforcement to someone who has not proven they own the
 * account.
 *
 * Two break-glass exceptions, both deliberate: the team owner always keeps
 * password access (a broken IdP must never lock the paying customer's own
 * owner out of their own team), and so does a hiccup site admin. Enforcement
 * also disengages whenever the platform kill switch is off, so flipping
 * that switch during an incident cannot strand every enforced team at once.
 * @param {string} userId
 * @param {boolean} isSiteAdmin
 * @returns {string|null} a user-facing refusal message, or null to allow
 */
function ssoLoginBlocked(userId, isSiteAdmin) {
  if (!isSsoGloballyEnabled()) return null;
  if (isSiteAdmin) return null;
  const teamId = teams.getTeamIdFor(userId);
  if (!teamId) return null;
  const cfg = teams.getTeamSso(teamId);
  if (!cfg || cfg.enabled === false || !cfg.enforced) return null;
  if (teams.getAccountRole(userId) === 'owner') return null;
  return 'Your team requires single sign-on. Use "Continue with SSO" on the sign-in page.';
}

module.exports = {
  initSso,
  isSsoGloballyEnabled,
  setSsoGloballyEnabled,
  discover,
  exchangeCode,
  fetchUserinfo,
  beginState,
  consumeState,
  resolveSignIn,
  ssoLoginBlocked,
  // Exported for test/selftest.js only -- not part of the app's own surface.
  _isPrivateIp,
};
