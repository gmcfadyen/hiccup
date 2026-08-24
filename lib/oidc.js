'use strict';
// lib/oidc.js — OIDC Authorization Code + PKCE, protocol logic only.
//
// Zero dependencies beyond node:crypto. No fs, no network — every function
// here is pure (same input, same output, no I/O) so test/selftest.js can
// exercise every branch without a server, a real IdP, or a mock HTTP layer.
// The functions that actually talk to an IdP (discovery fetch, token
// exchange, userinfo) live in lib/sso.js, through the app's own SSRF-guarded
// request helper — this module only builds the URLs/bodies they send and
// validates the responses they hand back.
//
// Signature verification note: an id_token's RS256 signature is deliberately
// NOT checked here. OIDC Core 1.0 s3.1.3.7 rule 6 allows this for the
// Authorization Code flow specifically, because TLS server validation
// substitutes for it -- PROVIDED the token is obtained directly from the
// token_endpoint over TLS and never accepted from any other channel (a URL
// fragment, a request body from the browser, anything front-channel). That
// invariant is enforced in lib/sso.js, not here: id_token only ever comes
// back as the JSON response of the app's own server-to-server POST to the
// discovered token_endpoint. If that ever changes, this note is wrong and a
// JWKS signature check has to be added.

const crypto = require('crypto');

/**
 * Trim and drop exactly one trailing slash. IdPs are inconsistent about
 * whether their issuer URL carries one, and every comparison in this module
 * (discovery's own `issuer` field, an id_token's `iss` claim) has to treat
 * "https://idp.example.com" and "https://idp.example.com/" as the same
 * value or every real IdP would fail validation half the time.
 * @param {string} s
 * @returns {string}
 */
function normalizeIssuer(s) {
  return String(s || '').trim().replace(/\/+$/, '');
}

/** The RFC 8414 / OIDC discovery document URL for an issuer. */
function wellKnownUrl(issuer) {
  return normalizeIssuer(issuer) + '/.well-known/openid-configuration';
}

/**
 * Validate a fetched discovery document against the issuer we configured.
 *
 * The issuer check is the important one: without it, an attacker who can
 * make the discovery fetch land somewhere else (a compromised DNS entry, an
 * open redirect, a typo'd issuer) could hand back a document naming THEIR
 * OWN token endpoint, and every following step would happily authenticate
 * against it. Requiring `doc.issuer` to exactly equal what we configured is
 * the check that makes discovery trustworthy rather than just convenient.
 * @param {object} doc parsed discovery JSON
 * @param {string} configuredIssuer the issuer the team admin entered
 * @returns {{ok:true, issuer:string, authorization_endpoint:string,
 *   token_endpoint:string, userinfo_endpoint:(string|null),
 *   tokenAuthMethods:(string[]|null)} | {ok:false, error:string}}
 */
function validateDiscovery(doc, configuredIssuer) {
  if (!doc || typeof doc !== 'object') {
    return { ok: false, error: 'discovery document was not a JSON object' };
  }
  const issuer = normalizeIssuer(doc.issuer);
  if (!issuer) return { ok: false, error: 'discovery document has no issuer' };
  if (issuer !== normalizeIssuer(configuredIssuer)) {
    return { ok: false, error: 'discovery issuer does not match the configured issuer' };
  }
  const authEp = typeof doc.authorization_endpoint === 'string' ? doc.authorization_endpoint : '';
  if (!authEp || !/^https:/.test(authEp)) {
    return { ok: false, error: 'discovery is missing a valid https authorization_endpoint' };
  }
  const tokenEp = typeof doc.token_endpoint === 'string' ? doc.token_endpoint : '';
  if (!tokenEp || !/^https:/.test(tokenEp)) {
    return { ok: false, error: 'discovery is missing a valid https token_endpoint' };
  }
  let userinfoEp = null;
  if (doc.userinfo_endpoint != null) {
    if (typeof doc.userinfo_endpoint !== 'string' || !/^https:/.test(doc.userinfo_endpoint)) {
      return { ok: false, error: 'discovery userinfo_endpoint is present but not https' };
    }
    userinfoEp = doc.userinfo_endpoint;
  }
  const methods = Array.isArray(doc.token_endpoint_auth_methods_supported)
    ? doc.token_endpoint_auth_methods_supported.filter((m) => typeof m === 'string')
    : null;
  return {
    ok: true,
    issuer,
    authorization_endpoint: authEp,
    token_endpoint: tokenEp,
    userinfo_endpoint: userinfoEp,
    tokenAuthMethods: methods,
  };
}

/** RFC 7636 S256 code_challenge from a code_verifier. Only S256 -- "plain" is not offered. */
function pkceChallenge(verifier) {
  return crypto.createHash('sha256').update(String(verifier)).digest('base64url');
}

/** A fresh PKCE pair: a 43-character verifier (32 random bytes, base64url) and its S256 challenge. */
function makePkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  return { verifier, challenge: pkceChallenge(verifier) };
}

/**
 * Build the `/authorize` redirect URL.
 * @param {string} authEndpoint the IdP's authorization_endpoint
 * @param {{clientId:string, redirectUri:string, state:string, nonce:string,
 *   challenge:string, loginHint?:string}} o
 * @returns {string}
 */
function buildAuthUrl(authEndpoint, o) {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: o.clientId,
    redirect_uri: o.redirectUri,
    scope: 'openid email profile',
    state: o.state,
    nonce: o.nonce,
    code_challenge: o.challenge,
    code_challenge_method: 'S256',
  });
  if (o.loginHint) params.set('login_hint', o.loginHint);
  // Some IdPs (Okta custom authorization servers, among others) have their
  // own query string already on authorization_endpoint -- join with & rather
  // than blindly appending a second "?" and producing an invalid URL.
  const sep = authEndpoint.indexOf('?') === -1 ? '?' : '&';
  return authEndpoint + sep + params.toString();
}

/**
 * Choose how to authenticate the token-endpoint request.
 *
 * RFC 6749's default, when an IdP's discovery document does not say
 * otherwise, is HTTP Basic -- so that is what a missing/absent
 * `methods` list falls back to. `client_secret_post` (credentials in the
 * form body instead) is used only when the IdP's own discovery document
 * explicitly lists it as supported.
 * @param {string[]|null} methods discovery's token_endpoint_auth_methods_supported
 * @param {string} clientId
 * @param {string} clientSecret
 * @returns {{headers:object, extraParams:object}}
 */
function tokenAuth(methods, clientId, clientSecret) {
  if (Array.isArray(methods) && methods.includes('client_secret_post')) {
    return { headers: {}, extraParams: { client_id: clientId, client_secret: clientSecret } };
  }
  // HTTP Basic per RFC 6749 s2.3.1: both the id and secret are
  // application/x-www-form-urlencoded BEFORE being joined and base64'd --
  // otherwise a secret containing ':' or '%' corrupts the header, and it is
  // exactly the kind of value a generated client secret can contain.
  const basic = Buffer.from(
    encodeURIComponent(clientId) + ':' + encodeURIComponent(clientSecret)
  ).toString('base64');
  return { headers: { Authorization: 'Basic ' + basic }, extraParams: {} };
}

/**
 * Decode a JWT's payload segment without verifying its signature (see the
 * module header for why that is safe here). Returns null on anything
 * malformed rather than throwing, so every caller gets one uniform "this
 * token is junk" outcome instead of a try/catch per call site.
 * @param {string} jwt
 * @returns {object|null}
 */
function decodeJwtPayload(jwt) {
  if (typeof jwt !== 'string') return null;
  const parts = jwt.split('.');
  if (parts.length !== 3) return null;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  return payload;
}

const CLOCK_SKEW_MS_DEFAULT = 120 * 1000;

/**
 * The mandatory OIDC Core s3.1.3.7 id_token claims check. Fails closed on
 * anything missing or malformed -- an absent claim is never treated as "not
 * applicable", it is treated as "invalid".
 * @param {object} claims decoded id_token payload
 * @param {{issuer:string, clientId:string, nonce:string, nowMs:number, skewMs?:number}} o
 * @returns {{ok:true} | {ok:false, error:string}}
 */
function validateIdTokenClaims(claims, o) {
  if (!claims || typeof claims !== 'object') return { ok: false, error: 'no claims' };
  const skew = typeof o.skewMs === 'number' ? o.skewMs : CLOCK_SKEW_MS_DEFAULT;

  if (normalizeIssuer(claims.iss) !== normalizeIssuer(o.issuer)) {
    return { ok: false, error: 'iss mismatch' };
  }
  const aud = claims.aud;
  const audOk = aud === o.clientId || (Array.isArray(aud) && aud.includes(o.clientId));
  if (!audOk) return { ok: false, error: 'aud mismatch' };
  // azp is optional, but if the IdP sent one it must name us -- a token
  // issued primarily for a different client that merely lists us in aud is
  // not one we should accept.
  if (claims.azp != null && claims.azp !== o.clientId) return { ok: false, error: 'azp mismatch' };

  if (typeof claims.exp !== 'number' || claims.exp * 1000 <= o.nowMs - skew) {
    return { ok: false, error: 'token expired' };
  }
  if (typeof claims.iat !== 'number' || claims.iat * 1000 > o.nowMs + skew) {
    return { ok: false, error: 'iat is in the future' };
  }
  // An empty EXPECTED nonce is not "skip the check" -- it fails closed. The
  // only way to reach this function without a real nonce to compare against
  // would be a bug in the caller, and that bug should not silently disable
  // replay protection.
  if (!o.nonce || claims.nonce !== o.nonce) return { ok: false, error: 'nonce mismatch' };

  if (!claims.sub || typeof claims.sub !== 'string') return { ok: false, error: 'missing sub' };

  return { ok: true };
}

/**
 * The domain half of an email address, lowercased. Splits on the LAST '@'
 * specifically -- `a@b@corp.com` is a legal (if unusual) local part, and
 * splitting on the first '@' would read its domain as "b", not "corp.com".
 * @param {string} email
 * @returns {string|null} null if there is no '@' or the domain has no dot
 */
function emailDomain(email) {
  const s = String(email || '').trim().toLowerCase();
  const at = s.lastIndexOf('@');
  if (at < 1 || at === s.length - 1) return null;
  const domain = s.slice(at + 1);
  return domain.indexOf('.') === -1 ? null : domain;
}

/**
 * Consumer email providers that must never be claimable as an SSO domain.
 * If a team could claim gmail.com, that team's IdP could assert identity for
 * any Gmail address on Earth -- the whole point of domain-claiming is that
 * an organisation's IdP can only vouch for people at that organisation.
 * Not exhaustive by design (an unlisted provider is still just one team's
 * problem if it slips through); covers the large global and regional
 * providers actually likely to be typed into this field.
 */
const PUBLIC_EMAIL_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
  'yahoo.com', 'yahoo.co.uk', 'yahoo.fr', 'ymail.com', 'icloud.com', 'me.com', 'mac.com',
  'aol.com', 'protonmail.com', 'proton.me', 'pm.me', 'gmx.com', 'gmx.net', 'gmx.de',
  'zoho.com', 'yandex.com', 'yandex.ru', 'mail.ru', 'qq.com', '163.com', '126.com',
  'naver.com', 'daum.net', 'web.de', 't-online.de', 'orange.fr', 'laposte.net',
  'free.fr', 'wanadoo.fr', 'btinternet.com', 'sky.com', 'virginmedia.com',
  'comcast.net', 'verizon.net', 'att.net', 'sbcglobal.net', 'cox.net',
  'fastmail.com', 'hey.com', 'tutanota.com', 'mailfence.com',
]);

/** Case-insensitive membership check against PUBLIC_EMAIL_DOMAINS. */
function isPublicEmailDomain(domain) {
  return PUBLIC_EMAIL_DOMAINS.has(String(domain || '').toLowerCase());
}

const _DOMAIN_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

/** A syntactically valid domain name: at least one dot, no leading/trailing hyphen per label. */
function isValidDomainName(s) {
  const d = String(s || '').trim().toLowerCase();
  return d.length > 0 && d.length <= 253 && _DOMAIN_RE.test(d);
}

/**
 * The post-login redirect allowlist. Must start with exactly one '/' (the
 * negative lookahead blocks a protocol-relative "//evil.com"), and the
 * character class blocks anything that could smuggle a scheme
 * ("javascript:", "data:") through. Shared with the plain password-login
 * "next" parameter -- one allowlist, not a second one invented for SSO.
 */
const SAFE_NEXT_RE = /^\/(?!\/)[A-Za-z0-9/_?=&.%-]*$/;

module.exports = {
  normalizeIssuer,
  wellKnownUrl,
  validateDiscovery,
  pkceChallenge,
  makePkce,
  buildAuthUrl,
  tokenAuth,
  decodeJwtPayload,
  validateIdTokenClaims,
  emailDomain,
  PUBLIC_EMAIL_DOMAINS,
  isPublicEmailDomain,
  isValidDomainName,
  SAFE_NEXT_RE,
};
