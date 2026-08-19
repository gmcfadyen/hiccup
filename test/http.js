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

const ROOT = path.join(__dirname, '..');
const PORT = 8400 + 90 + Math.floor(process.pid % 50);   // avoid a fixed-port clash
const HOST = '127.0.0.1';
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'hiccup-http-'));

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
