'use strict';
/**
 * lib/stripe.js — Stripe Checkout + webhooks, with no SDK.
 *
 * WHY NO stripe PACKAGE
 *
 * hiccup's contract is zero runtime dependencies (ARCHITECTURE.md:14). Stripe's
 * API is plain HTTPS with form-encoded requests and JSON responses, and webhook
 * verification is one HMAC — none of that needs an SDK. This module is the same
 * shape as lib/mail.js (SMTP by hand) for the same reason.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO
 *
 *   - It never sees a card number. Checkout is hosted BY Stripe: hiccup creates
 *     a session and redirects, and the customer types their card on stripe.com.
 *     That keeps hiccup out of PCI scope entirely, which for a solo-run service
 *     is the only sane choice.
 *   - It never takes a price or an amount from the client. The browser asks for
 *     monthly or annual, and the SERVER maps that to a configured price id. A
 *     client that could name its own price could name its own price.
 *
 * CONFIGURATION (data/config.json, which is gitignored — keys never enter git):
 *   stripeSecretKey     sk_test_/sk_live_   server-side only, never sent to a browser
 *   stripeWebhookSecret whsec_              signing secret for THIS endpoint
 *   stripePriceMonthly  price_              recurring, EUR 20/month
 *   stripePriceAnnual   price_              recurring, EUR 200/year
 *
 * With any of those unset, isConfigured() is false and the routes degrade to
 * the manual Buy Me a Coffee flow rather than half-working.
 */

const https = require('https');
const crypto = require('crypto');

const API_HOST = 'api.stripe.com';
const API_VERSION = '2024-06-20';    // pinned: an API upgrade is a decision, not a surprise
const WEBHOOK_TOLERANCE_S = 300;     // Stripe's own default; never 0, which disables the check
const REQUEST_TIMEOUT_MS = 20000;

let _cfg = {};

/** @param {object} config the loaded data/config.json */
function initStripe(config) {
  _cfg = config && typeof config === 'object' ? config : {};
}

function _str(v) { return typeof v === 'string' ? v.trim() : ''; }

function _err(userMessage, detail) {
  const e = new Error(detail || userMessage);
  e.userMessage = userMessage;
  return e;
}

/** Every piece present? Missing config disables the feature rather than half-enabling it. */
function isConfigured() {
  return !!(_str(_cfg.stripeSecretKey) && _str(_cfg.stripeWebhookSecret) &&
    _str(_cfg.stripePriceMonthly) && _str(_cfg.stripePriceAnnual));
}

/** True when the configured key is a live (real money) key rather than a test one. */
function isLiveMode() {
  return _str(_cfg.stripeSecretKey).indexOf('sk_live_') === 0;
}

/** The price id for a plan name, or null. The client never supplies this. */
function priceIdFor(plan) {
  if (plan === 'monthly') return _str(_cfg.stripePriceMonthly) || null;
  if (plan === 'annual') return _str(_cfg.stripePriceAnnual) || null;
  return null;
}

/**
 * Form-encode a nested object the way Stripe expects: a[b]=c, and a[0][b]=c
 * for arrays.
 * @param {object} obj
 * @returns {string}
 */
function _form(obj, prefix, out) {
  out = out || [];
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    if (v === undefined || v === null) continue;
    const key = prefix ? prefix + '[' + k + ']' : k;
    if (typeof v === 'object') _form(v, key, out);
    else out.push(encodeURIComponent(key) + '=' + encodeURIComponent(String(v)));
  }
  return out.join('&');
}

/**
 * One Stripe API call.
 * @param {string} method
 * @param {string} path e.g. /v1/checkout/sessions
 * @param {object|null} body
 * @returns {Promise<object>} parsed JSON
 */
function _api(method, path, body) {
  const secret = _str(_cfg.stripeSecretKey);
  if (!secret) return Promise.reject(_err('Payments are not configured on this server.', 'stripe: no secret key'));
  const payload = body ? _form(body) : null;

  return new Promise((resolve, reject) => {
    const req = https.request({
      host: API_HOST,
      path,
      method,
      headers: Object.assign({
        // Basic auth with the secret as username and empty password is Stripe's
        // documented scheme; it keeps the key out of the query string and so out
        // of any intermediary's logs.
        Authorization: 'Basic ' + Buffer.from(secret + ':').toString('base64'),
        'Stripe-Version': API_VERSION,
      }, payload ? {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(payload),
      } : {}),
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch { /* handled below */ }
        if (res.statusCode >= 200 && res.statusCode < 300 && json) return resolve(json);
        const msg = (json && json.error && json.error.message) || ('Stripe returned ' + res.statusCode);
        reject(_err('Payment setup failed. Nothing has been charged.', 'stripe: ' + msg));
      });
    });
    req.on('error', (e) => reject(_err('Could not reach Stripe. Nothing has been charged.', 'stripe: ' + e.message)));
    req.setTimeout(REQUEST_TIMEOUT_MS, () => {
      req.destroy();
      reject(_err('Stripe timed out. Nothing has been charged.', 'stripe: timeout'));
    });
    if (payload) req.write(payload);
    req.end();
  });
}

/**
 * Create a hosted Checkout session for a subscription.
 *
 * client_reference_id carries hiccup's own user id through Stripe and back on
 * the webhook. That, not the email, is what the webhook resolves the account
 * by: an email can be changed on Stripe's side mid-flow, and matching on it
 * would mean a payment could land on the wrong hiccup account.
 *
 * @param {{userId:string, email:string, plan:string, baseUrl:string,
 *          customerId?:string|null}} opts
 * @returns {Promise<{id:string, url:string}>}
 */
async function createCheckoutSession(opts) {
  const o = opts || {};
  const price = priceIdFor(o.plan);
  if (!price) throw _err('Choose a monthly or annual plan.', 'stripe: unknown plan ' + o.plan);
  if (!o.userId) throw _err('Sign in again, then try subscribing.', 'stripe: no userId');

  const base = String(o.baseUrl || '').replace(/\/+$/, '');
  const body = {
    mode: 'subscription',
    line_items: { 0: { price: price, quantity: 1 } },
    client_reference_id: o.userId,
    success_url: base + '/subscribe?checkout=success',
    cancel_url: base + '/subscribe?checkout=cancelled',
    // Duplicated onto the subscription so a later lapse event can be traced to
    // an account without another API round trip.
    subscription_data: { metadata: { hiccup_user_id: o.userId } },
    metadata: { hiccup_user_id: o.userId },
    allow_promotion_codes: 'true',
  };
  if (o.customerId) body.customer = o.customerId;
  else if (o.email) body.customer_email = o.email;

  const s = await _api('POST', '/v1/checkout/sessions', body);
  return { id: s.id, url: s.url };
}

/** Retrieve a Checkout session. */
function getCheckoutSession(id) {
  return _api('GET', '/v1/checkout/sessions/' + encodeURIComponent(String(id)), null);
}

/**
 * Verify a webhook signature and return the parsed event.
 *
 * Stripe's documented scheme, by hand:
 *   signed_payload = timestamp + "." + RAW request body
 *   expected       = HMAC-SHA256(signed_payload, endpoint signing secret)
 *
 * Three things here are load-bearing and easy to get subtly wrong:
 *   1. The body must be the RAW bytes. Parsing and re-serialising JSON changes
 *      key order and whitespace, and the signature covers the exact bytes.
 *   2. Only the v1 scheme is accepted. Stripe also sends a fake v0 on test
 *      events, and accepting unknown schemes is a downgrade attack.
 *   3. Comparison is timing-safe, and the timestamp is checked against a
 *      tolerance so a captured-and-replayed payload eventually stops working.
 *
 * @param {Buffer} rawBody exact bytes as received
 * @param {string} sigHeader the Stripe-Signature header
 * @returns {object} the parsed event
 * @throws {Error} with .userMessage on any failure
 */
function verifyWebhook(rawBody, sigHeader) {
  const secret = _str(_cfg.stripeWebhookSecret);
  if (!secret) throw _err('Webhooks are not configured.', 'stripe: no webhook secret');
  if (!Buffer.isBuffer(rawBody)) throw _err('Bad webhook body.', 'stripe: raw body must be a Buffer');

  let timestamp = null;
  const provided = [];
  for (const part of String(sigHeader || '').split(',')) {
    const i = part.indexOf('=');
    if (i === -1) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k === 't') timestamp = v;
    else if (k === 'v1') provided.push(v);   // v0 and anything else deliberately ignored
  }
  if (!timestamp || !provided.length) throw _err('Bad webhook signature.', 'stripe: malformed Stripe-Signature');

  const age = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
  if (!Number.isFinite(age) || age > WEBHOOK_TOLERANCE_S) {
    throw _err('Bad webhook signature.', 'stripe: timestamp outside tolerance (' + age + 's)');
  }

  const expected = crypto.createHmac('sha256', secret)
    .update(timestamp + '.' + rawBody.toString('utf8'), 'utf8')
    .digest('hex');
  const exp = Buffer.from(expected, 'utf8');
  let matched = false;
  for (const p of provided) {
    const got = Buffer.from(p, 'utf8');
    // Length check first: timingSafeEqual throws on a length mismatch, and a
    // wrong-length signature is a mismatch, not an error worth surfacing.
    if (got.length === exp.length && crypto.timingSafeEqual(got, exp)) { matched = true; break; }
  }
  if (!matched) throw _err('Bad webhook signature.', 'stripe: no v1 signature matched');

  try {
    return JSON.parse(rawBody.toString('utf8'));
  } catch {
    throw _err('Bad webhook body.', 'stripe: signature ok but body is not JSON');
  }
}

module.exports = {
  initStripe,
  isConfigured,
  isLiveMode,
  priceIdFor,
  createCheckoutSession,
  getCheckoutSession,
  verifyWebhook,
};
