#!/usr/bin/env node
'use strict';
// test/selftest.js — hiccup end-to-end selftest (ARCHITECTURE.md §Selftest).
//
// Runs test/make-fixtures.js first, then feeds every fixture listed in
// test/fixtures/expected.json through lib/analyze.analyzeCapture, asserting
// ONLY the keys present in each entry (generic assertion engine). Then runs
// the auth, store, and llm degradation passes. Uses a throwaway data dir at
// test/tmp-data (removed before and after). No network beyond 127.0.0.1, and
// only to dead loopback ports. Zero dependencies. CommonJS.
//
// Output: one PASS/FAIL line per test, a failure recap, then the final line
//   SELFTEST: k/n passed
// Exit code 1 on any failure. While other modules are still being built this
// script fails GRACEFULLY: clear one-line messages, no stack traces.

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const FIXTURES_DIR = path.join(__dirname, 'fixtures');
const EXPECTED_FILE = path.join(FIXTURES_DIR, 'expected.json');
const MAKE_FIXTURES = path.join(__dirname, 'make-fixtures.js');
const TMP_DATA = path.join(__dirname, 'tmp-data');

// Dead loopback ports for the llm degradation pass. Nothing listens on the
// discard/chargen ports on a Windows box, so connections are refused fast —
// this must NOT touch the real Ollama (11434) or RFPlex (3001).
const DEAD_OLLAMA_URL = 'http://127.0.0.1:9';
const DEAD_RFPLEX_URL = 'http://127.0.0.1:19/api/status/llm';

const results = []; // { name, ok, err? }

/**
 * Extract a short, human-readable message from any thrown value.
 * Prefers `userMessage` (the contract's user-facing error property) and keeps
 * only the first line so require-stack noise never reaches the output.
 * @param {*} e thrown value
 * @returns {string}
 */
function errMsg(e) {
  if (!e) return 'unknown error';
  if (e.userMessage) return String(e.userMessage).split('\n')[0];
  if (e.message) return String(e.message).split('\n')[0];
  return String(e).split('\n')[0];
}

/**
 * Run one named test, recording and printing PASS/FAIL. Never throws.
 * @param {string} name test name
 * @param {function(): (void|Promise<void>)} fn test body; throws on failure
 * @returns {Promise<boolean>} whether the test passed
 */
async function t(name, fn) {
  try {
    await fn();
    results.push({ name, ok: true });
    console.log('PASS ' + name);
    return true;
  } catch (e) {
    results.push({ name, ok: false, err: errMsg(e) });
    console.log('FAIL ' + name + ' — ' + errMsg(e));
    return false;
  }
}

/**
 * Throw with `msg` unless `cond` is truthy.
 * @param {*} cond condition
 * @param {string} msg failure message
 */
function ok(cond, msg) {
  if (!cond) throw new Error(msg);
}

/**
 * Throw unless `actual` strictly equals `expected`.
 * @param {*} actual observed value
 * @param {*} expected required value
 * @param {string} label what is being compared
 */
function eq(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(label + ': expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual));
  }
}

/**
 * Await `promise` but fail if it does not settle within `ms`.
 * Timeout errors carry `__selftestTimeout` so expectReject can tell a real
 * rejection from a hang.
 * @param {*} promise promise (or plain value)
 * @param {number} ms timeout in milliseconds
 * @param {string} label used in the timeout message
 * @returns {Promise<*>}
 */
function within(promise, ms, label) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      const e = new Error(label + ' did not settle within ' + Math.round(ms / 1000) + 's');
      e.__selftestTimeout = true;
      reject(e);
    }, ms);
    Promise.resolve(promise).then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); }
    );
  });
}

/**
 * Await `promise` expecting rejection; resolving is a failure, and a hang
 * (timeout) is a failure too.
 * @param {*} promise the promise that must reject
 * @param {number} ms max time to wait
 * @param {string} label used in failure messages
 * @returns {Promise<*>} the rejection error
 */
async function expectReject(promise, ms, label) {
  let value; let resolved = false; let rejection = null;
  try {
    value = await within(promise, ms, label);
    resolved = true;
  } catch (e) {
    if (e && e.__selftestTimeout) throw e;
    rejection = e;
  }
  if (resolved) {
    let shown = '';
    try { shown = String(JSON.stringify(value)).slice(0, 120); } catch { shown = String(value); }
    throw new Error(label + ': expected a rejection, but it resolved with ' + shown);
  }
  return rejection;
}

/**
 * Remove a directory tree, ignoring errors and missing paths.
 * @param {string} dir directory to remove
 */
function rimraf(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

/**
 * Lazily require a hiccup module, mapping load failures to one-line messages.
 * @param {string} relPath repo-relative path, e.g. 'lib/auth.js'
 * @param {string} [missingMsg] message when the module itself does not exist
 * @returns {{mod?: *, err?: string}}
 */
function tryRequire(relPath, missingMsg) {
  const label = relPath.replace(/\\/g, '/');
  try {
    return { mod: require(path.join(ROOT, relPath)) };
  } catch (e) {
    if (e && e.code === 'MODULE_NOT_FOUND') {
      const m = /Cannot find module '([^']+)'/.exec(e.message || '');
      const what = m ? m[1] : '';
      const base = path.basename(relPath, '.js');
      if (what && path.basename(what, '.js').toLowerCase() === base.toLowerCase()) {
        return { err: missingMsg || (label + ' not present yet (its agent has not delivered)') };
      }
      return { err: label + ' exists but a module it requires is missing: ' + (what || errMsg(e)) };
    }
    return { err: label + ' failed to load: ' + errMsg(e) };
  }
}

/**
 * Generic assertion engine: check one expected.json entry against its
 * AnalysisJSON. Only keys present in `expect` are asserted. All mismatches
 * are collected and thrown together.
 * @param {object} expect the entry's `expect` object
 * @param {object} analysis AnalysisJSON from analyzeCapture
 */
function assertFixture(expect, analysis) {
  const problems = [];
  const stats = (analysis && analysis.stats) || {};
  const calls = (analysis && analysis.calls) || [];

  function count(label, actual, wanted) {
    if (actual !== wanted) problems.push(label + ': expected ' + JSON.stringify(wanted) + ', got ' + JSON.stringify(actual));
  }

  if ('format' in expect) count('format', stats.format, expect.format);
  if ('sipMessages' in expect) count('sipMessages', stats.sipMessages, expect.sipMessages);
  if ('h323Messages' in expect) count('h323Messages', stats.h323Messages, expect.h323Messages);
  if ('legs' in expect) count('legs', stats.legs, expect.legs);
  if ('calls' in expect) count('calls', stats.calls, expect.calls);

  if (expect.callStates) {
    for (const state of Object.keys(expect.callStates)) {
      const got = calls.filter((c) => c && c.state === state).length;
      count('callStates.' + state, got, expect.callStates[state]);
    }
  }

  if (expect.callTypes) {
    for (const type of Object.keys(expect.callTypes)) {
      const got = calls.filter((c) => c && c.type === type).length;
      count('callTypes.' + type, got, expect.callTypes[type]);
    }
  }

  if (expect.retransCodes) {
    const collapses = ((analysis && analysis.retrans) || {}).collapses || [];
    const codes = [];
    for (const col of collapses) {
      if (col && col.classification && col.classification.code) codes.push(col.classification.code);
    }
    for (const code of expect.retransCodes) {
      if (codes.indexOf(code) === -1) {
        problems.push("retransCodes: '" + code + "' not among collapse classifications [" + codes.join(', ') + ']');
      }
    }
  }

  if (expect.diffTags) {
    const tags = [];
    for (const call of calls) {
      for (const d of (call && call.diffs) || []) {
        const cats = (d && d.diff && d.diff.categories) || [];
        for (const cat of cats) {
          for (const item of (cat && cat.items) || []) {
            if (item && item.tag && tags.indexOf(item.tag) === -1) tags.push(item.tag);
          }
        }
      }
    }
    for (const tag of expect.diffTags) {
      if (tags.indexOf(tag) === -1) {
        problems.push("diffTags: '" + tag + "' not present (saw: " + (tags.join(', ') || 'none') + ')');
      }
    }
  }

  if (expect.findingsInclude) {
    const findings = (analysis && analysis.findings) || [];
    for (const want of expect.findingsInclude) {
      const hit = findings.some((f) => f && f.severity === want.severity && f.category === want.category);
      if (!hit) {
        problems.push('findingsInclude: no finding with severity=' + want.severity + ' category=' + want.category);
      }
    }
  }

  if (expect.absentStrings) {
    const blob = JSON.stringify(analysis);
    for (const s of expect.absentStrings) {
      if (blob.indexOf(s) !== -1) problems.push("absentStrings: '" + s + "' leaked into the serialized analysis");
    }
  }

  if (problems.length) throw new Error(problems.join('; '));
}

async function main() {
  rimraf(TMP_DATA);
  fs.mkdirSync(TMP_DATA, { recursive: true });

  // ---------------------------------------------------------------- fixtures
  let fixturesOk = false;
  await t('fixtures: make-fixtures.js runs', () => {
    if (!fs.existsSync(MAKE_FIXTURES)) {
      throw new Error('test/make-fixtures.js not present yet (fixtures module not delivered)');
    }
    const r = spawnSync(process.execPath, [MAKE_FIXTURES], { stdio: 'inherit', cwd: ROOT });
    if (r.error) throw new Error('could not spawn node: ' + r.error.message);
    if (r.status !== 0) throw new Error('make-fixtures.js exited with code ' + r.status);
    fixturesOk = true;
  });

  let analyze = null;
  await t('analyze: lib/analyze.js loads', () => {
    const r = tryRequire(path.join('lib', 'analyze.js'), 'integrator has not written lib/analyze.js yet');
    if (r.err) throw new Error(r.err);
    if (typeof r.mod.analyzeCapture !== 'function') {
      throw new Error('lib/analyze.js does not export analyzeCapture()');
    }
    analyze = r.mod;
  });

  let entries = null;
  if (fixturesOk) {
    await t('fixtures: expected.json parses', () => {
      if (!fs.existsSync(EXPECTED_FILE)) {
        throw new Error('test/fixtures/expected.json missing (make-fixtures.js did not write it)');
      }
      const parsed = JSON.parse(fs.readFileSync(EXPECTED_FILE, 'utf8'));
      ok(Array.isArray(parsed) && parsed.length > 0, 'expected.json is empty or not an array');
      entries = parsed;
    });
  } else {
    console.log('SKIP fixture assertions — fixtures were not generated');
  }

  if (entries && analyze) {
    for (const entry of entries) {
      await t('fixture: ' + (entry.name || entry.file || '?'), async () => {
        ok(entry.file, 'entry has no file');
        const buf = fs.readFileSync(path.join(FIXTURES_DIR, entry.file));
        const analysis = await analyze.analyzeCapture(buf);
        assertFixture(entry.expect || {}, analysis);
      });
    }
  } else if (entries && !analyze) {
    console.log('SKIP ' + entries.length + ' fixture assertion(s) — lib/analyze.js unavailable');
  }

  // -------------------------------------------------------------------- auth
  let auth = null;
  let authUser = null;
  await t('auth: init', async () => {
    const r = tryRequire(path.join('lib', 'auth.js'));
    if (r.err) throw new Error(r.err);
    const authDir = path.join(TMP_DATA, 'auth');
    fs.mkdirSync(authDir, { recursive: true });
    await within(Promise.resolve(r.mod.initAuth(authDir, {
      baseUrl: 'http://127.0.0.1:8400',
      googleClientId: null,
    })), 10000, 'initAuth');
    auth = r.mod;
  });

  await t('auth: signup', async () => {
    ok(auth, 'auth module unavailable (init failed)');
    authUser = await auth.createUser({ email: 'alice@example.com', password: 'correct-horse-8', name: 'Alice' });
    ok(authUser && authUser.id, 'createUser did not return a user with an id');
  });

  await t('auth: login with correct password', async () => {
    ok(auth && authUser, 'no signed-up user to test against');
    const u = await auth.verifyPassword('alice@example.com', 'correct-horse-8');
    ok(u && u.id === authUser.id, 'verifyPassword rejected the correct password');
  });

  await t('auth: wrong password rejected', async () => {
    ok(auth && authUser, 'no signed-up user to test against');
    const u = await auth.verifyPassword('alice@example.com', 'wrong-password-8');
    ok(!u, 'verifyPassword accepted a wrong password');
  });

  await t('auth: duplicate email rejected', async () => {
    ok(auth && authUser, 'no signed-up user to test against');
    let threw = false;
    try {
      await auth.createUser({ email: 'alice@example.com', password: 'another-pass-8', name: 'Alice Again' });
    } catch (e) {
      threw = true;
      ok(errMsg(e), 'duplicate-email rejection carries no message');
    }
    ok(threw, 'createUser accepted a duplicate email');
  });

  await t('auth: session create/get/destroy', async () => {
    ok(auth && authUser, 'no signed-up user to test against');
    const sess = await auth.createSession(authUser.id);
    ok(sess && typeof sess.token === 'string' && sess.token.length >= 32, 'createSession did not return a usable {token}');
    ok(sess.expiresAt, 'createSession did not return expiresAt');
    const got = await auth.getSession(sess.token);
    ok(got && got.user && got.user.id === authUser.id, 'getSession did not return the session user');
    await auth.destroySession(sess.token);
    const gone = await auth.getSession(sess.token);
    ok(!gone, 'getSession still returns a destroyed session');
  });

  await t('auth: garbage Google ID token rejects', async () => {
    ok(auth, 'auth module unavailable (init failed)');
    let p;
    try {
      p = auth.verifyGoogleIdToken('garbage-not-a-jwt');
    } catch {
      return; // synchronous throw is an acceptable rejection
    }
    await expectReject(p, 5000, 'verifyGoogleIdToken(garbage)');
  });

  // ------------------------------------------------------------------- store
  await t('store: saveJson/loadJson atomic round-trip', async () => {
    const r = tryRequire(path.join('lib', 'store.js'));
    if (r.err) throw new Error(r.err);
    const store = r.mod;
    const dir = path.join(TMP_DATA, 'store');
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, 'roundtrip.json');

    const fallback = { fell: 'back' };
    eq(JSON.stringify(await store.loadJson(file, fallback)), JSON.stringify(fallback), 'loadJson fallback for a missing file');

    const obj = { n: 1, s: 'unicode — ✓ émoji', arr: [1, 2, 3], nested: { deep: true } };
    await store.saveJson(file, obj);
    eq(JSON.stringify(await store.loadJson(file, null)), JSON.stringify(obj), 'loadJson after save');

    const obj2 = { n: 2, replaced: true };
    await store.saveJson(file, obj2); // overwrite path (Windows rename-over-existing)
    eq(JSON.stringify(await store.loadJson(file, null)), JSON.stringify(obj2), 'loadJson after overwrite');

    const leftovers = fs.readdirSync(dir).filter((f) => f !== 'roundtrip.json');
    ok(leftovers.length === 0, 'saveJson left temp files behind: ' + leftovers.join(', '));
  });

  // --------------------------------------------------------------------- llm
  await t('llm: degrades cleanly with Ollama down', async () => {
    const r = tryRequire(path.join('lib', 'llm.js'));
    if (r.err) throw new Error(r.err);
    const llm = r.mod;
    await within(Promise.resolve(llm.initLlm({
      ollamaUrl: DEAD_OLLAMA_URL,
      rfplexStatusUrl: DEAD_RFPLEX_URL,
      preferredModels: ['qwen3.5:9b', 'qwen3.5:2b'],
    })), 15000, 'initLlm');

    const status = await within(Promise.resolve(llm.getLlmStatus()), 15000, 'getLlmStatus');
    ok(status && status.available === false,
      'getLlmStatus().available should be false with Ollama unreachable, got ' + JSON.stringify(status && status.available));

    let p;
    try {
      p = llm.askLlm({ system: 'hiccup selftest', messages: [{ role: 'user', content: 'ping' }] });
    } catch {
      return; // synchronous throw is an acceptable clean rejection
    }
    const err = await expectReject(p, 30000, 'askLlm with Ollama down');
    ok(err && (err.message || err.userMessage || err.code), 'askLlm rejected without any error information');
  });

  // ------------------------------------------------------- cleanup + summary
  try {
    rimraf(TMP_DATA);
  } catch (e) {
    console.log('note: could not remove test/tmp-data: ' + errMsg(e));
  }

  const failedTests = results.filter((x) => !x.ok);
  if (failedTests.length) {
    console.log('');
    console.log('FAILURES:');
    for (const f of failedTests) console.log('  - ' + f.name + ': ' + f.err);
  }
  const passedCount = results.length - failedTests.length;
  console.log('SELFTEST: ' + passedCount + '/' + results.length + ' passed');
  process.exit(failedTests.length ? 1 : 0);
}

main().catch((e) => {
  // Should be unreachable (t never throws), but never vomit a stack trace.
  console.error('selftest harness error: ' + errMsg(e));
  const passedCount = results.filter((x) => x.ok).length;
  console.log('SELFTEST: ' + passedCount + '/' + results.length + ' passed');
  process.exit(1);
});
