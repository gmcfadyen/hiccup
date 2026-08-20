'use strict';
/*
 * test/http.js — HTTP-level integration tests against a REAL server process.
 *
 * WHY THIS EXISTS
 *
 * test/selftest.js tests the libs. Nothing tested server.js, because it used to
 * call server.listen() at module scope with no require.main guard, so merely
 * requiring it bound a port and armed three timers. The result was 43 API routes
 * and 17 page routes with zero automated coverage.
 *
 * That was not theoretical. /subscribe shipped in PUBLIC_PAGES, the landing page
 * shipped a primary CTA pointing at it, and the route 404'd on the live site for
 * four and a half hours -- because public/ is served straight from the working
 * tree (live on save) while server.js only changes on restart. One assertion that
 * "every page route resolves" would have caught it the moment it was written.
 *
 * So this spawns server.js as a CHILD PROCESS against a scratch HICCUP_DATA_DIR
 * and a scratch port, and talks to it over real HTTP. A child process rather than
 * an in-process require, because that is what production actually runs: it proves
 * boot works, config loads, and the routing table is wired -- not just that some
 * functions exist.
 *
 * Run: npm run test:http   (or `npm test` for this plus the selftest)
 */

const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const PORT = 8400 + 90 + Math.floor(process.pid % 50);   // avoid a fixed-port clash
const HOST = '127.0.0.1';
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'hiccup-http-'));

// All four Stripe values, because the webhook now REFUSES to act unless Stripe
// is fully configured -- a box with a leftover signing secret and nothing else
// must not hand out paid plans. The key is sk_test_, so isLiveMode() is false
// and any event claiming livemode:true has to be refused.
//
// Nothing here reaches Stripe: the tests below exercise the webhook (inbound,
// no network) and only ever hit checkout in states that short-circuit before
// the API call.
const WEBHOOK_SECRET = 'whsec_http_harness';
fs.writeFileSync(path.join(DATA_DIR, 'config.json'), JSON.stringify({
  stripeWebhookSecret: WEBHOOK_SECRET,
  stripeSecretKey: 'sk_test_harness_not_a_real_key',
  stripePriceMonthly: 'price_harness_monthly',
  stripePriceAnnual: 'price_harness_annual',
  // This suite legitimately creates a handful of accounts from one IP, which
  // the production default (5/hour) is meant to stop. Raised here rather than
  // weakened there.
  signupMaxPerHour: 100,
}, null, 2));

/** A signed Stripe-Signature header for a body, as Stripe would send it. */
function stripeSig(rawBody, secret) {
  const ts = Math.floor(Date.now() / 1000);
  const mac = crypto.createHmac('sha256', secret || WEBHOOK_SECRET)
    .update(ts + '.' + rawBody.toString('utf8'), 'utf8').digest('hex');
  return 't=' + ts + ',v1=' + mac;
}

const results = [];
let child = null;

function ok(cond, msg) { if (!cond) throw new Error(msg); }
function eq(a, b, label) {
  if (a !== b) throw new Error(label + ': expected ' + JSON.stringify(b) + ', got ' + JSON.stringify(a));
}

async function t(name, fn) {
  try {
    await fn();
    results.push({ name, ok: true });
    console.log('PASS ' + name);
  } catch (e) {
    results.push({ name, ok: false, err: (e && e.message) || String(e) });
    console.log('FAIL ' + name + ' — ' + ((e && e.message) || e));
  }
}

/** Minimal HTTP client that keeps a cookie jar, so auth flows can be tested. */
function makeClient() {
  let cookie = '';
  return function req(method, pathname, body, headers) {
    return new Promise((resolve, reject) => {
      const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
      const h = Object.assign({}, headers);
      if (payload) {
        h['Content-Type'] = 'application/json';
        h['Content-Length'] = payload.length;
      }
      if (cookie) h.Cookie = cookie;
      const r = http.request({ host: HOST, port: PORT, method, path: pathname, headers: h }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const set = res.headers['set-cookie'];
          if (set && set.length) cookie = set.map((s) => s.split(';')[0]).join('; ');
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try { json = JSON.parse(text); } catch { /* not JSON, fine */ }
          resolve({ status: res.statusCode, headers: res.headers, text, json });
        });
      });
      r.on('error', reject);
      if (payload) r.write(payload);
      r.end();
    });
  };
}

/** Poll until the child answers, so the suite never races the listener. */
async function waitForBoot(client, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const r = await client('GET', '/api/status');
      if (r.status === 200) return;
    } catch { /* not up yet */ }
    if (Date.now() > deadline) throw new Error('server did not start within ' + timeoutMs + 'ms');
    await new Promise((r) => setTimeout(r, 150));
  }
}

async function main() {
  const client = makeClient();

  child = spawn(process.execPath, [path.join(ROOT, 'server.js')], {
    cwd: ROOT,
    env: Object.assign({}, process.env, {
      HICCUP_DATA_DIR: DATA_DIR,
      PORT: String(PORT),
      HOST,
    }),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  child.stdout.on('data', (d) => { serverLog += d.toString(); });
  child.stderr.on('data', (d) => { serverLog += d.toString(); });
  child.on('exit', (code) => {
    if (code !== 0 && code !== null) console.log('server exited early (' + code + '):\n' + serverLog);
  });

  await waitForBoot(client, 20000);

  // ---------------------------------------------------------------- routing
  // The regression that motivated this file. Every page a user can be sent to
  // must resolve -- a 404 here means a link in the UI is dead in production.
  await t('every public page route resolves', async () => {
    const pages = ['/', '/subscribe', '/privacy', '/team', '/app', '/sip', '/settings'];
    for (const p of pages) {
      const r = await client('GET', p);
      ok(r.status === 200, p + ' returned ' + r.status + ' (expected 200)');
    }
  });

  await t('sitemap lists /subscribe', async () => {
    const r = await client('GET', '/sitemap.xml');
    eq(r.status, 200, 'sitemap status');
    ok(r.text.includes('/subscribe'), 'sitemap does not list /subscribe');
  });

  // A gated route must answer 401, NOT 404. A 404 means the route is missing
  // entirely -- which is exactly how the stale-deploy outage presented, and is
  // indistinguishable from "not deployed" without this distinction.
  await t('protected routes are gated (401), not missing (404)', async () => {
    const anon = makeClient();
    for (const p of ['/api/me', '/api/team', '/api/admin/users', '/api/team/recovery']) {
      const r = await anon('GET', p);
      eq(r.status, 401, p + ' should be 401 for an anonymous caller');
    }
  });

  await t('security headers are set on every response', async () => {
    for (const p of ['/', '/api/status']) {
      const r = await client('GET', p);
      eq(r.headers['x-content-type-options'], 'nosniff', p + ' nosniff');
      eq(r.headers['x-frame-options'], 'DENY', p + ' X-Frame-Options');
      ok(r.headers['referrer-policy'], p + ' Referrer-Policy missing');
      ok(r.headers['permissions-policy'], p + ' Permissions-Policy missing');
    }
  });

  // Regression test for a bug found only by opening a browser: HSTS sent over
  // plain HTTP. Chrome treats 127.0.0.1 as a secure context, so it HONOURS the
  // header and then force-upgrades to https://127.0.0.1:PORT, where nothing is
  // listening -- local access dies for the whole max-age. curl is perfectly
  // happy throughout, which is exactly why this needs an assertion.
  await t('HSTS is sent only over HTTPS, never over plain HTTP', async () => {
    const plain = await client('GET', '/');
    ok(!plain.headers['strict-transport-security'],
      'HSTS was sent over plain HTTP — this bricks http://127.0.0.1 in Chrome');

    const fwd = await client('GET', '/', undefined, { 'X-Forwarded-Proto': 'https' });
    ok(fwd.headers['strict-transport-security'],
      'HSTS missing when X-Forwarded-Proto is https — production loses it');
  });

  // The CSP is only worth having if script-src has no escape hatch. Reaching
  // that meant lifting 32 inline blocks out of 17 HTML files, so this asserts
  // the payoff is still there -- re-adding one inline <script> plus an
  // 'unsafe-inline' to make it work would silently undo the whole exercise.
  await t("CSP forbids inline script and keeps no 'unsafe-inline' escape hatch", async () => {
    const r = await client('GET', '/');
    const csp = r.headers['content-security-policy'];
    ok(csp, 'no Content-Security-Policy header');
    const script = (csp.split(';').map((d) => d.trim()).find((d) => d.startsWith('script-src')) || '');
    ok(script, 'CSP has no script-src directive');
    ok(!script.includes("'unsafe-inline'"), "script-src allows 'unsafe-inline': " + script);
    ok(!script.includes("'unsafe-eval'"), "script-src allows 'unsafe-eval': " + script);
    for (const d of ['object-src', 'base-uri', 'frame-ancestors']) {
      ok(csp.includes(d), 'CSP is missing ' + d);
    }
  });

  // Every executable inline block was moved to a file; a new one would be
  // refused at runtime by the policy above, so catch it here instead.
  await t('no page ships an executable inline <script>', async () => {
    for (const p of ['/', '/subscribe', '/team', '/app', '/settings', '/admin/status']) {
      const r = await client('GET', p);
      const blocks = r.text.match(new RegExp("<script\\b[^>]*>[^]*?</script>", "gi")) || [];
      for (const b of blocks) {
        const open = b.slice(0, b.indexOf('>'));
        if (open.indexOf("src=") !== -1) continue;                   // external, fine
        if (open.indexOf("ld+json") !== -1) continue;              // data, not executed
        ok(false, p + ' still has an executable inline <script>: ' + open);
      }
    }
  });
  // ------------------------------------------------------------------- auth
  const me = { email: 'harness-' + process.pid + '@example.test', password: 'correct-horse-8' };

  await t('signup -> /api/me round trip, and plan is on the wire', async () => {
    const r = await client('POST', '/api/auth/signup', me);
    eq(r.status, 200, 'signup status');
    const m = await client('GET', '/api/me');
    eq(m.status, 200, '/api/me status');
    eq(m.json.user.email, me.email, '/api/me email');
    // sanitizeUser() dropped `plan` once already, silently telling a paid
    // account it was free. Assert it, so that cannot recur unnoticed.
    ok(m.json.user.plan === 'free' || m.json.user.plan === 'paid', '/api/me is missing plan');
  });

  await t('a free account cannot create a team, over real HTTP', async () => {
    const r = await client('POST', '/api/team', { name: 'Harness Team' });
    ok(r.status >= 400, 'a free user created a team (status ' + r.status + ')');
    ok(/paid/i.test((r.json && r.json.error) || ''), 'refusal did not mention a paid account: ' + JSON.stringify(r.json));
  });

  await t('login rate limiting returns 429 after repeated failures', async () => {
    const anon = makeClient();
    let saw429 = false;
    // The per-email budget is the smaller of the two, so it trips first.
    for (let i = 0; i < 12; i++) {
      const r = await anon('POST', '/api/auth/login', { email: me.email, password: 'wrong-password' });
      if (r.status === 429) {
        saw429 = true;
        ok(r.headers['retry-after'], '429 without a Retry-After header');
        break;
      }
      eq(r.status, 401, 'attempt ' + i + ' should be 401 before the limit trips');
    }
    ok(saw429, 'never got a 429 after 12 failed sign-ins');
  });

  await t('rate-limit message does not reveal whether the account exists', async () => {
    const anon = makeClient();
    let known = null;
    let unknown = null;
    for (let i = 0; i < 12 && !known; i++) {
      const r = await anon('POST', '/api/auth/login', { email: me.email, password: 'nope' });
      if (r.status === 429) known = (r.json && r.json.error) || '';
    }
    const anon2 = makeClient();
    for (let i = 0; i < 12 && !unknown; i++) {
      const r = await anon2('POST', '/api/auth/login', { email: 'nobody-' + process.pid + '@example.test', password: 'nope' });
      if (r.status === 429) unknown = (r.json && r.json.error) || '';
    }
    ok(known && unknown, 'did not trip both limiters (known=' + known + ', unknown=' + unknown + ')');
    eq(known, unknown, 'the 429 wording differs for a real vs unknown account');
  });

  // The access log records the caller. An IP is personal data, so it is
  // coarsened before being written -- and this asserts the coarsening really
  // happens, because the failure mode is silent: a broken regex logs the full
  // address and nothing looks wrong. It broke exactly that way once already.
  await t("access log anonymises the caller IP", async () => {
    const mark = 'ualog-' + Date.now();
    await client('GET', '/api/status', undefined, {
      'CF-Connecting-IP': '203.0.113.47',
      'User-Agent': mark,
    });
    await new Promise((r) => setTimeout(r, 150));   // let the finish handler write
    const line = serverLog.split('\n').find((l) => l.indexOf(mark) !== -1);
    ok(line, 'no access-log line carried the marker user-agent');
    ok(line.indexOf('203.0.113.0') !== -1, 'IP was not truncated to /24: ' + line);
    ok(line.indexOf('203.0.113.47') === -1, 'FULL IP leaked into the log: ' + line);
    ok(/^\d{4}-\d{2}-\d{2}T/.test(line), 'log line has no leading timestamp: ' + line);
  });


  // ----------------------------------------------------------- billing
  // The webhook is the one unauthenticated route that can grant a paid plan.
  // Its signature IS its authentication, so these are attacks, not niceties.
  await t('stripe webhook rejects an unsigned or badly signed POST', async () => {
    const anon = makeClient();
    const body = { id: 'evt_bad', type: 'checkout.session.completed' };
    const r1 = await anon('POST', '/api/stripe/webhook', body);
    eq(r1.status, 400, 'an unsigned webhook must be refused');
    const r2 = await anon('POST', '/api/stripe/webhook', body, { 'Stripe-Signature': 't=1,v1=deadbeef' });
    eq(r2.status, 400, 'a bogus signature must be refused');
    // 400 and not 401 matters: a 401 would mean it had been put behind
    // requireAuth, which would break every real delivery from Stripe.
    ok(r2.status !== 401, 'the webhook must not sit behind requireAuth');
  });

  await t('a correctly signed webhook upgrades the account end to end', async () => {
    const meRes = await client('GET', '/api/me');
    eq(meRes.status, 200, 'need a signed-in user for this test');
    const userId = meRes.json.user.id;
    eq(meRes.json.user.plan, 'free', 'user should start on the free plan');

    const event = {
      id: 'evt_http_' + Date.now(),
      type: 'checkout.session.completed',
      livemode: false,
      data: { object: {
        id: 'cs_test_1',
        mode: 'subscription',
        payment_status: 'paid',
        client_reference_id: userId,
        metadata: { hiccup_user_id: userId },
        customer: 'cus_test_1',
        subscription: 'sub_test_1',
      } },
    };
    const raw = Buffer.from(JSON.stringify(event));
    const sig = stripeSig(raw);

    const r = await client('POST', '/api/stripe/webhook', event, { 'Stripe-Signature': sig });
    eq(r.status, 200, 'a valid webhook should be accepted');

    const after = await client('GET', '/api/me');
    eq(after.json.user.plan, 'paid', 'the webhook did not upgrade the account');

    // Stripe retries on any non-2xx, so the same event id must be a no-op.
    const again = await client('POST', '/api/stripe/webhook', event, { 'Stripe-Signature': sig });
    eq(again.status, 200, 'a retried webhook should still be 200');
    ok(again.json && again.json.duplicate === true, 'a retried event was not detected as a duplicate');
  });

  await t('an unpaid checkout session does NOT grant the plan', async () => {
    const anon = makeClient();
    await anon('POST', '/api/auth/signup', { email: 'unpaid-' + process.pid + '@example.test', password: 'correct-horse-8' });
    const who = await anon('GET', '/api/me');
    const event = {
      id: 'evt_unpaid_' + Date.now(),
      type: 'checkout.session.completed',
      livemode: false,
      data: { object: { id: 'cs_2', mode: 'subscription', subscription: 'sub_2',
        payment_status: 'unpaid', metadata: { hiccup_user_id: who.json.user.id } } },
    };
    const r = await anon('POST', '/api/stripe/webhook', event,
      { 'Stripe-Signature': stripeSig(Buffer.from(JSON.stringify(event))) });
    eq(r.status, 200, 'webhook should still be accepted');
    const after = await anon('GET', '/api/me');
    eq(after.json.user.plan, 'free', 'an UNPAID session granted the paid plan');
  });

  await t('checkout requires sign-in, and refuses a second subscription', async () => {
    const anon = makeClient();
    const a = await anon('POST', '/api/billing/checkout', { plan: 'monthly' });
    eq(a.status, 401, 'checkout must require sign-in');

    // This client is already paid from the webhook test above, so the guard
    // short-circuits before any Stripe call -- no network in the test suite.
    const r = await client('POST', '/api/billing/checkout', { plan: 'monthly' });
    eq(r.status, 409, 'an already-subscribed user must not be sent to checkout again');

    const bad = await client('POST', '/api/billing/checkout', { plan: 'price_evil' });
    ok(bad.status >= 400, 'an arbitrary plan string must be refused');
  });

  // Pasting TEST keys and poking the real site is how anyone tries this out.
  // Without a livemode check that hands a genuine paid plan to whoever pays
  // with 4242 4242 4242 4242, and every signal looks like a real sale.
  await t('a live-mode event is refused when the configured key is test-mode', async () => {
    const anon = makeClient();
    await anon('POST', '/api/auth/signup', { email: 'livemode-' + process.pid + '@example.test', password: 'correct-horse-8' });
    const who = await anon('GET', '/api/me');
    const event = {
      id: 'evt_live_' + Date.now(),
      type: 'checkout.session.completed',
      livemode: true,
      data: { object: { id: 'cs_live', mode: 'subscription', subscription: 'sub_live',
        payment_status: 'paid', metadata: { hiccup_user_id: who.json.user.id } } },
    };
    const r = await anon('POST', '/api/stripe/webhook', event,
      { 'Stripe-Signature': stripeSig(Buffer.from(JSON.stringify(event))) });
    eq(r.status, 200, 'the event is validly signed, so it is accepted and ignored');
    const after = await anon('GET', '/api/me');
    eq(after.json.user.plan, 'free', 'a LIVE event granted a plan on a TEST-mode key');
  });

  // A webhook endpoint sees every event on the account. A one-off payment link
  // or tip jar must not be able to buy a hiccup subscription.
  await t('a non-subscription session does not grant the plan', async () => {
    const anon = makeClient();
    await anon('POST', '/api/auth/signup', { email: 'oneoff-' + process.pid + '@example.test', password: 'correct-horse-8' });
    const who = await anon('GET', '/api/me');
    const event = {
      id: 'evt_oneoff_' + Date.now(),
      type: 'checkout.session.completed',
      livemode: false,
      data: { object: { id: 'cs_oneoff', mode: 'payment', payment_status: 'paid',
        client_reference_id: who.json.user.id } },
    };
    const r = await anon('POST', '/api/stripe/webhook', event,
      { 'Stripe-Signature': stripeSig(Buffer.from(JSON.stringify(event))) });
    eq(r.status, 200, 'accepted and ignored');
    const after = await anon('GET', '/api/me');
    eq(after.json.user.plan, 'free', 'a one-off payment session granted a subscription plan');
  });


  // A lapsed team goes READ-ONLY: reads and deletes keep working, writes do not.
  // The two limits matter as much as the gate -- a teamless free account must
  // never be frozen (analysis is free), and nobody may be locked away from data
  // they already own.
  await t('a lapsed team is frozen for writes but not for reads', async () => {
    const anon = makeClient();
    const em = 'frozen-' + process.pid + '@example.test';
    await anon('POST', '/api/auth/signup', { email: em, password: 'correct-horse-8' });
    const who = await anon('GET', '/api/me');
    const uid = who.json.user.id;

    // Upgrade via a signed webhook, make a team, then let it lapse.
    const paid = {
      id: 'evt_frz_' + Date.now(), type: 'checkout.session.completed', livemode: false,
      data: { object: { id: 'cs_frz', mode: 'subscription', subscription: 'sub_frz',
        payment_status: 'paid', metadata: { hiccup_user_id: uid }, customer: 'cus_frz' } },
    };
    await anon('POST', '/api/stripe/webhook', paid,
      { 'Stripe-Signature': stripeSig(Buffer.from(JSON.stringify(paid))) });
    const made = await anon('POST', '/api/team', { name: 'Frozen Team' });
    eq(made.status, 200, 'a paid user should be able to create a team');

    // While paid, a write is allowed through the gate.
    const okWrite = await anon('POST', '/api/projects', { name: 'Before lapse' });
    ok(okWrite.status < 400, 'a paid team should accept a write, got ' + okWrite.status);

    // Now cancel, exactly as Stripe would.
    const gone = {
      id: 'evt_frz_del_' + Date.now(), type: 'customer.subscription.deleted', livemode: false,
      data: { object: { id: 'sub_frz', status: 'canceled', customer: 'cus_frz',
        metadata: { hiccup_user_id: uid } } },
    };
    const d = await anon('POST', '/api/stripe/webhook', gone,
      { 'Stripe-Signature': stripeSig(Buffer.from(JSON.stringify(gone))) });
    eq(d.status, 200, 'cancellation webhook should be accepted');
    const nowFree = await anon('GET', '/api/me');
    eq(nowFree.json.user.plan, 'free', 'cancellation did not downgrade the plan');

    // WRITES are refused...
    const w = await anon('POST', '/api/projects', { name: 'After lapse' });
    eq(w.status, 402, 'a write on a lapsed team should be 402 Payment Required');
    ok(w.json && w.json.frozen === true, 'the refusal should be flagged as frozen');

    // ...but READS still work. Being unable to reach your own data would be a
    // worse failure than the one this is preventing.
    const readProjects = await anon('GET', '/api/projects');
    eq(readProjects.status, 200, 'reading projects must still work when frozen');
    const readCaps = await anon('GET', '/api/captures');
    eq(readCaps.status, 200, 'reading captures must still work when frozen');

    // And inviting is refused too, so a lapsed team cannot grow.
    const inv = await anon('POST', '/api/team/invite', { email: 'x-' + process.pid + '@example.test' });
    ok(inv.status >= 400, 'a lapsed team should not be able to invite, got ' + inv.status);
  });

  await t('a teamless free account is never frozen', async () => {
    const anon = makeClient();
    await anon('POST', '/api/auth/signup', { email: 'solo-' + process.pid + '@example.test', password: 'correct-horse-8' });
    const me2 = await anon('GET', '/api/me');
    eq(me2.json.user.plan, 'free', 'this account should be free');
    // Analysis and storage are free for individuals; the paid tier is teams.
    const w = await anon('POST', '/api/projects', { name: 'Solo project' });
    ok(w.status < 400, 'a free solo account must not be frozen, got ' + w.status);
  });

  // ------------------------------------------------------------------ teams
  await t('team recovery endpoint answers for a teamless user', async () => {
    const r = await client('GET', '/api/team/recovery');
    eq(r.status, 200, 'recovery status');
    eq(r.json.claimable, false, 'a teamless user must not be able to claim');
    eq(r.json.reason, 'not-on-a-team', 'recovery reason');
  });

  await t('leaving when you are on no team fails cleanly', async () => {
    const r = await client('POST', '/api/team/leave', {});
    ok(r.status >= 400 && r.status < 500, 'expected a 4xx, got ' + r.status);
    ok(r.json && r.json.error, 'no error message returned');
  });

  // --------------------------------------------------------------- teardown
  const failed = results.filter((r) => !r.ok);
  console.log('\nHTTP: ' + (results.length - failed.length) + '/' + results.length + ' passed');
  if (failed.length) {
    console.log('\nserver log:\n' + serverLog);
  }
  return failed.length === 0;
}

function cleanup() {
  if (child && !child.killed) { try { child.kill(); } catch { /* already gone */ } }
  try { fs.rmSync(DATA_DIR, { recursive: true, force: true }); } catch { /* best effort */ }
}

main()
  .then((pass) => { cleanup(); process.exit(pass ? 0 : 1); })
  .catch((e) => {
    console.error('HTTP harness error: ' + ((e && e.stack) || e));
    cleanup();
    process.exit(1);
  });
