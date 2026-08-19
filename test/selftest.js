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
 * Build a minimal, structurally valid single-page PDF carrying `lines` as real
 * extractable text. Hand-rolled rather than committed as a binary fixture so
 * the KB test needs no checked-in .pdf and no third-party generator, and so it
 * is obvious what the bytes are. xref offsets are computed, because a PDF with
 * wrong offsets is exactly the kind of "test passes on junk" trap worth avoiding.
 * @param {string[]} lines
 * @returns {Buffer}
 */
function makeMinimalPdf(lines) {
  const text = lines
    .map((l, i) => 'BT /F1 12 Tf 72 ' + (720 - i * 18) + ' Td (' + String(l).replace(/[()\\]/g, '\\$&') + ') Tj ET')
    .join('\n');
  const objs = [
    '<</Type/Catalog/Pages 2 0 R>>',
    '<</Type/Pages/Kids[3 0 R]/Count 1>>',
    '<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>',
    '<</Length ' + Buffer.byteLength(text) + '>>\nstream\n' + text + '\nendstream',
    '<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>',
  ];
  let pdf = '%PDF-1.4\n';
  const offsets = [];
  objs.forEach((body, i) => {
    offsets.push(Buffer.byteLength(pdf));
    pdf += (i + 1) + ' 0 obj\n' + body + '\nendobj\n';
  });
  const xrefAt = Buffer.byteLength(pdf);
  pdf += 'xref\n0 ' + (objs.length + 1) + '\n0000000000 65535 f \n';
  offsets.forEach((o) => { pdf += String(o).padStart(10, '0') + ' 00000 n \n'; });
  pdf += 'trailer\n<</Size ' + (objs.length + 1) + '/Root 1 0 R>>\nstartxref\n' + xrefAt + '\n%%EOF\n';
  return Buffer.from(pdf, 'latin1');
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
 * Wave-3 addition: call `fn`, expecting either a synchronous throw or a
 * rejected promise. lib/teams.js/lib/projects.js are documented with plain
 * "throws {userMessage}" language (matching lib/auth.js's synchronous
 * style), but this hedges the same way the existing verifyGoogleIdToken test
 * below already does, in case an implementation returns a promise instead.
 * @param {function(): *} fn call under test
 * @param {string} label used in failure messages
 * @returns {Promise<*>} the thrown/rejected error
 */
async function expectThrowsOrRejects(fn, label) {
  let p;
  try {
    p = fn();
  } catch (e) {
    return e; // synchronous throw — acceptable
  }
  if (p && typeof p.then === 'function') {
    return await expectReject(p, 5000, label);
  }
  throw new Error(label + ': expected a throw or a rejection, got a plain return value ' + JSON.stringify(p));
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

  // ---------------------------------------------------------------------- kb
  // Regression test for a bug that shipped silently: lib/kb.js was written
  // against pdf-parse v1 (`module.exports = fn`), but package.json asks for
  // ^2.4.5, and v2 is a rewrite exporting a namespace with a PDFParse class.
  // v2 ships a CJS build, so `require()` SUCCEEDED and only the call failed --
  // which surfaced to the user as "PDF support needs an optional dependency"
  // even with pdf-parse correctly installed. Every PDF upload was rejected,
  // and PDFs are the exact artefact /kb exists to ingest.
  //
  // Skips (rather than fails) when pdf-parse is absent, because it is a real
  // optionalDependency and a core install is meant to work without it.
  await t('kb: ingests a PDF and finds its text, with page numbers', async () => {
    const r = tryRequire(path.join('lib', 'kb.js'));
    if (r.err) throw new Error(r.err);
    const kb = r.mod;

    let havePdfParse = true;
    try { require('pdf-parse'); } catch { havePdfParse = false; }
    if (!havePdfParse) {
      console.log('  (skipped: pdf-parse not installed — optional dependency)');
      return;
    }

    // initKb FIRST: without it kb.js falls back to process.cwd()/data, i.e.
    // the real library. Isolation here is not optional.
    const dir = path.join(TMP_DATA, 'kb');
    fs.mkdirSync(dir, { recursive: true });
    kb.initKb(dir);

    const uid = 'a1b2c3d4e5f6';
    const line = 'To strip the P-Asserted-Identity header towards the carrier, use StripPAI.';
    const pdf = makeMinimalPdf([
      'AudioCodes Mediant SBC Configuration Guide',
      'Section 4.2 Message Manipulation',
      line,
    ]);

    const doc = await kb.addDoc({ userId: uid, filename: 'guide.pdf', buffer: pdf });
    ok(doc && doc.chunks > 0, 'addDoc returned no chunks for a text-bearing PDF');
    eq(doc.pages, 1, 'kb: page count from the PDF');

    const hits = kb.searchKb(uid, 'strip P-Asserted-Identity carrier', 3);
    ok(hits.length > 0, 'searchKb found nothing in an ingested PDF');
    ok(/P-Asserted-Identity/.test(hits[0].text), 'top hit did not contain the searched text');
    // The \f-joined page split is what makes a citation say "page 3" — assert it
    // rather than trusting that extraction alone is enough.
    eq(hits[0].page, 1, 'kb: page number carried through to the search hit');
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

  // ==================================================== wave3: teams & projects
  // ARCHITECTURE.md "# Wave 3 — Teams & Projects" (grep that heading for the
  // full spec). lib/teams.js and lib/projects.js are being built by another
  // agent in parallel and may not exist yet when this runs -- every test
  // below fails gracefully via tryRequire()/an ok(modVar, ...) guard, exactly
  // like the passes above, rather than crashing.
  //
  // Isolation: this whole block uses its own subdirectory (test/tmp-data/
  // wave3) and its own users/teams, and re-initialises the auth/teams/
  // projects singletons against that subdirectory as its first step. That
  // re-init call is what makes this section independent of run order with
  // respect to the Wave-1/Wave-2 auth pass above: whichever section
  // initialises last "wins" for calls made after that point, but each
  // section only reads module state immediately after its OWN init call, so
  // the two never observe each other's data. Cleanup is covered by the
  // existing rimraf(TMP_DATA) at the end of this file (wave3/ lives under it).

  const W3_DIR = path.join(TMP_DATA, 'wave3');
  let w3auth = null;
  let w3teams = null;
  let w3projects = null;
  let uA = null, uB = null, uC = null, uD = null;
  let team1 = null;
  let uidAForProjects = null;
  let brandNewInviteToken = null;
  let w3SharedCaptureId = null;
  let realProjectA = null, realProjectC = null;

  function needTeams() { ok(w3teams, 'lib/teams.js unavailable (see load test above)'); }
  function needProjects() { ok(w3projects, 'lib/projects.js unavailable (see load test above)'); }
  // Team participation is a paid feature (see lib/teams.js's _isPaid()) —
  // this suite is about team ROLE mechanics, not the paid gate itself (that
  // has its own dedicated tests below), so every user this suite creates
  // through the normal path is paid by construction.
  function mkUser(email, name) {
    const u = w3auth.createUser({ email, password: 'correct-horse-8', name });
    w3auth.setUserPlan(u.id, 'paid');
    return u;
  }

  await t('wave3: lib/teams.js loads with the documented exports', () => {
    const r = tryRequire(path.join('lib', 'teams.js'));
    if (r.err) throw new Error(r.err);
    const need = ['initTeams', 'accountUid', 'getTeamIdFor', 'getAccountRole', 'canManageMembers',
      'isSuspended', 'createTeam', 'getTeamView', 'createInvite', 'getInviteInfo', 'acceptInvite',
      'setMemberRole', 'setMemberSuspended', 'removeMember', 'transferOwnership'];
    const missing = need.filter((k) => typeof r.mod[k] !== 'function');
    ok(missing.length === 0, 'lib/teams.js missing export(s): ' + missing.join(', '));
    w3teams = r.mod;
  });

  await t('wave3: lib/projects.js loads with the documented exports', () => {
    const r = tryRequire(path.join('lib', 'projects.js'));
    if (r.err) throw new Error(r.err);
    const need = ['initProjects', 'listProjects', 'createProject', 'getProject', 'renameProject', 'deleteProject'];
    const missing = need.filter((k) => typeof r.mod[k] !== 'function');
    ok(missing.length === 0, 'lib/projects.js missing export(s): ' + missing.join(', '));
    w3projects = r.mod;
  });

  await t('wave3: init auth+teams+projects against a dedicated dir', async () => {
    needTeams();
    needProjects();
    fs.mkdirSync(W3_DIR, { recursive: true });
    const r = tryRequire(path.join('lib', 'auth.js'));
    if (r.err) throw new Error(r.err);
    w3auth = r.mod;
    // lib/auth.js keeps its state in module-level singletons (see the
    // Wave-1/2 auth pass above), so this re-points that singleton at W3_DIR
    // for the rest of this section -- necessary because lib/teams.js's
    // acceptInvite calls into ./auth internally and both need to agree on
    // one initialised instance.
    await within(Promise.resolve(w3auth.initAuth(W3_DIR, {
      baseUrl: 'http://127.0.0.1:8400',
      googleClientId: null,
    })), 10000, 'wave3 initAuth');
    await within(Promise.resolve(w3teams.initTeams(W3_DIR)), 10000, 'initTeams');
    await within(Promise.resolve(w3projects.initProjects(W3_DIR)), 10000, 'initProjects');
  });

  await t('wave3: create users A, B, C', () => {
    ok(w3auth, 'auth unavailable');
    uA = mkUser('w3-a@example.com', 'Alice A');
    uB = mkUser('w3-b@example.com', 'Bob B');
    uC = mkUser('w3-c@example.com', 'Carol C');
    ok(uA && uA.id && uB && uB.id && uC && uC.id, 'user creation did not return usable ids');
  });

  // -------------------------------------------------- core sharing behavior

  await t('wave3: A creates a team; accountUid(A) becomes the team\'s dataRootId', () => {
    needTeams();
    team1 = w3teams.createTeam(uA.id, 'Team Alpha');
    ok(team1 && team1.dataRootId, 'createTeam did not return a Team with dataRootId');
    uidAForProjects = w3teams.accountUid(uA.id);
    // dataRootId is fixed at the CREATOR's own id (matching RFPlex's actual
    // behaviour, and ARCHITECTURE.md only requires it stay fixed thereafter,
    // not that it differ from the creator) -- so accountUid(A) === A.id here
    // is correct, zero-migration design, not a bug. It only diverges from a
    // user's own id for someone who JOINS an existing team (see the next
    // test, B accepting A's invite) -- that's what's actually asserted below.
    ok(w3teams.getTeamIdFor(uA.id), 'A is not recognized as being on a team right after createTeam');
    eq(uidAForProjects, team1.dataRootId, 'accountUid(A) vs team1.dataRootId');
    eq(w3teams.getAccountRole(uA.id), 'owner', 'A\'s role right after createTeam');
  });

  await t('wave3: A invites B\'s email; B accepts via the already-authenticated branch; accountUid(A) === accountUid(B)', async () => {
    needTeams();
    const inv = w3teams.createInvite(uA.id, uB.email);
    ok(inv && typeof inv.token === 'string' && inv.token, 'createInvite did not return a usable token');
    ok(inv.expiresAt, 'createInvite did not return expiresAt');
    ok(inv.inviteUrl, 'createInvite did not return inviteUrl');

    // Simulate "B is already logged in" the way server.js would see it: a
    // real session for B, even though acceptInvite's frozen signature takes
    // sessionUserId directly rather than a raw token.
    const sess = await within(Promise.resolve(w3auth.createSession(uB.id)), 5000, 'createSession(B)');
    const got = await within(Promise.resolve(w3auth.getSession(sess.token)), 5000, 'getSession(B)');
    ok(got && got.user && got.user.id === uB.id, 'B\'s session did not resolve back to B');

    const res = await within(Promise.resolve(
      w3teams.acceptInvite(inv.token, { sessionUserId: uB.id })
    ), 5000, 'acceptInvite(B, already-authenticated branch)');
    ok(res && res.userId === uB.id, 'acceptInvite did not return {userId: B.id}');

    eq(w3teams.accountUid(uA.id), w3teams.accountUid(uB.id), 'accountUid(A) vs accountUid(B) after join');
    eq(w3teams.getTeamIdFor(uB.id), team1.teamId, 'B\'s teamId after accepting');
    eq(w3teams.getAccountRole(uB.id), 'member', 'B\'s role after accepting (should be plain member)');
  });

  await t('wave3: getTeamView(A) reflects the team, both members, and manage flags', () => {
    needTeams();
    const view = w3teams.getTeamView(uA.id);
    ok(view && view.team && view.team.teamId === team1.teamId, 'getTeamView(A).team mismatch');
    ok(Array.isArray(view.members), 'getTeamView(A).members not an array');
    eq(view.members.length, 2, 'getTeamView(A).members.length (expected just A + B at this point)');
    const ids = view.members.map((m) => m.userId);
    ok(ids.includes(uA.id) && ids.includes(uB.id), 'A and/or B missing from getTeamView(A).members');
    const aEntry = view.members.find((m) => m.userId === uA.id);
    ok(aEntry && aEntry.role === 'owner', 'A\'s role in the members list');
    eq(view.myRole, 'owner', 'getTeamView(A).myRole');
    eq(view.myCanManage, true, 'getTeamView(A).myCanManage');
  });

  await t('wave3: acceptInvite branch 3 — brand-new email creates a real account even when not paid, but does not join', async () => {
    // Team participation needs plan:'paid' (see the paid-gate tests below),
    // checked AFTER a branch-3 account is created and BEFORE the invite
    // token is consumed — on purpose, so a genuinely new person can sign up,
    // subscribe, then reopen the exact same link. First attempt here must
    // fail without wasting the invite; the follow-up test completes it once paid.
    needTeams();
    const email = 'w3-brandnew@example.com';
    ok(!w3auth.findUserByEmail(email), 'sanity: this email must not already have an account');
    const inv = w3teams.createInvite(uA.id, email);
    brandNewInviteToken = inv.token;

    const e = await expectThrowsOrRejects(
      () => w3teams.acceptInvite(inv.token, { createAccount: { password: 'correct-horse-8', name: 'Brand New' } }),
      'acceptInvite branch 3 (new account, not yet paid)'
    );
    ok(/paid/i.test(errMsg(e)), 'rejection should explain a paid account is needed: ' + errMsg(e));

    const created = w3auth.findUserByEmail(email);
    ok(created, 'branch 3 must still create the account even though joining was refused');
    eq(w3teams.getTeamIdFor(created.id), null, 'the unpaid account must not have been joined to the team');
    eq(w3teams.accountUid(created.id), created.id, 'accountUid must be untouched — still the new account\'s own id');
  });

  await t('wave3: acceptInvite branch 3 — the SAME token still works once the new account is marked paid', async () => {
    // The whole point of refusing rather than consuming the token above is
    // that the identical link still works — so this reuses brandNewInviteToken
    // rather than a fresh invite, which would only prove a WEAKER claim
    // (re-inviting works) and not that nothing was wasted by the refusal.
    needTeams();
    ok(brandNewInviteToken, 'prerequisite: the previous test must have captured the invite token');
    const email = 'w3-brandnew@example.com';
    const created = w3auth.findUserByEmail(email);
    ok(created, 'prerequisite: the previous test must have created this account');
    w3auth.setUserPlan(created.id, 'paid');

    const info = w3teams.getInviteInfo(brandNewInviteToken);
    ok(info, 'the invite token must still be valid after the earlier paid-refusal — it must not have been consumed');

    const res = await within(Promise.resolve(
      w3teams.acceptInvite(brandNewInviteToken, { sessionUserId: created.id })
    ), 5000, 'acceptInvite branch 3 retry (now paid, same token)');
    ok(res && res.userId === created.id, 'acceptInvite (paid retry) did not return {userId}');
    eq(w3teams.accountUid(res.userId), w3teams.accountUid(uA.id), 'new user\'s accountUid after the paid retry');
    eq(w3teams.getAccountRole(res.userId), 'member', 'new user\'s role after the paid retry');
  });

  await t('wave3 paid-gate: a free user cannot create a team', () => {
    needTeams();
    const free = w3auth.createUser({ email: 'w3-free-create@example.com', password: 'correct-horse-8', name: 'Free' });
    eq(free.plan, 'free', 'sanity: a freshly created account must default to plan:"free"');
    let threw = null;
    try { w3teams.createTeam(free.id, 'Should Not Exist'); } catch (e) { threw = e; }
    ok(threw, 'createTeam must refuse a free account');
    ok(/paid/i.test(errMsg(threw)), 'rejection should explain a paid account is needed: ' + errMsg(threw));
    eq(w3teams.getTeamIdFor(free.id), null, 'no team must have been created for the free account');
  });

  await t('wave3 paid-gate: a free user cannot accept an invite (branch 1, already-authenticated), and the invite survives', async () => {
    needTeams();
    const free = w3auth.createUser({ email: 'w3-free-accept@example.com', password: 'correct-horse-8', name: 'Free' });
    const inv = w3teams.createInvite(uA.id, free.email);

    const e = await expectThrowsOrRejects(
      () => w3teams.acceptInvite(inv.token, { sessionUserId: free.id }),
      'acceptInvite branch 1 for a free account'
    );
    ok(/paid/i.test(errMsg(e)), 'rejection should explain a paid account is needed: ' + errMsg(e));
    eq(w3teams.getTeamIdFor(free.id), null, 'the free account must not have been joined to the team');
    ok(w3teams.getInviteInfo(inv.token), 'the invite must still be valid — refusing must not consume it');

    // Now pay, and the identical token works.
    w3auth.setUserPlan(free.id, 'paid');
    const res = await within(Promise.resolve(
      w3teams.acceptInvite(inv.token, { sessionUserId: free.id })
    ), 5000, 'acceptInvite branch 1 retry (now paid)');
    eq(res.userId, free.id, 'paid retry did not join the expected account');
    eq(w3teams.getAccountRole(free.id), 'member', 'role after the paid retry');
  });

  await t('wave3: acceptInvite branch 2 — existing account, correct password, not pre-authenticated', async () => {
    needTeams();
    const email = 'w3-existing-ok@example.com';
    const existing = mkUser(email, 'Existing Ok');
    const inv = w3teams.createInvite(uA.id, email);

    const res = await within(Promise.resolve(
      w3teams.acceptInvite(inv.token, { password: 'correct-horse-8' })
    ), 5000, 'acceptInvite branch 2 (correct password)');
    ok(res && res.userId === existing.id, 'acceptInvite (branch 2) did not resolve to the existing account');
    eq(w3teams.accountUid(existing.id), w3teams.accountUid(uA.id), 'accountUid after branch-2 join');
  });

  await t('wave3: acceptInvite branch 2 — wrong password is rejected and does not join', async () => {
    needTeams();
    const email = 'w3-existing-badpw@example.com';
    const existing = mkUser(email, 'Existing BadPw');
    const inv = w3teams.createInvite(uA.id, email);

    // This is the exact attack the spec's identity-verification step exists
    // to stop: someone has the token (forwarded/logged) but not the password.
    const e = await expectThrowsOrRejects(
      () => w3teams.acceptInvite(inv.token, { password: 'totally-wrong-password' }),
      'acceptInvite branch 2 with the wrong password'
    );
    ok(errMsg(e), 'wrong-password rejection carries no message');
    eq(w3teams.getTeamIdFor(existing.id), null, 'wrong password still joined the account to the team');
    eq(w3teams.accountUid(existing.id), existing.id, 'accountUid changed despite a rejected wrong-password accept');
  });

  await t('wave3: acceptInvite branch 2 — Google-only account (no password) rejects clearly', async () => {
    needTeams();
    const email = 'w3-google-only@example.com';
    const existing = w3auth.createUser({ email, googleSub: 'fake-google-sub-w3-1', name: 'Google Only' });
    const inv = w3teams.createInvite(uA.id, email);

    const e = await expectThrowsOrRejects(
      () => w3teams.acceptInvite(inv.token, { password: 'anything-at-all' }),
      'acceptInvite branch 2 against a Google-only account'
    );
    ok(errMsg(e), 'Google-only rejection carries no message (spec wants a "sign in first"-style userMessage)');
    eq(w3teams.getTeamIdFor(existing.id), null, 'Google-only account joined despite having no password to verify against');
  });

  await t('wave3: createInvite supersedes a prior pending invite; PendingInvite never carries the token', () => {
    needTeams();
    const email = 'w3-superseded@example.com';
    const inv1 = w3teams.createInvite(uA.id, email);
    const inv2 = w3teams.createInvite(uA.id, email);
    ok(inv2.token !== inv1.token, 'second createInvite for the same email+team returned the same token');

    // "Supersedes" is read here as: the old token stops resolving at all.
    // If the real implementation instead lets the old token keep working
    // until its own natural expiry (also a defensible reading, as long as
    // only one PENDING invite is ever tracked per email), this specific
    // assertion is the one to revisit with the integrator -- everything
    // else in this test is interpretation-independent.
    eq(w3teams.getInviteInfo(inv1.token), null, 'superseded (first) token should no longer resolve');
    ok(w3teams.getInviteInfo(inv2.token), 'current (second) token should still resolve');

    const pending = w3teams.getTeamView(uA.id).pendingInvites.find((p) => p.email === email);
    ok(pending, 'pendingInvites should contain the invite for ' + email);
    ok(!('token' in pending), 'PendingInvite leaked a `token` field (spec: "never includes the token itself")');
    ok(JSON.stringify(pending).indexOf(inv2.token) === -1, 'PendingInvite JSON contains the raw token string');
  });

  await t('wave3: createTeam throws if the caller is already on a team (owner and plain member alike)', async () => {
    needTeams();
    await expectThrowsOrRejects(() => w3teams.createTeam(uA.id, 'A Second Team For A'), 'owner A creating a 2nd team');
    await expectThrowsOrRejects(() => w3teams.createTeam(uB.id, 'A Second Team For B'), 'member B creating a 2nd team');
  });

  await t('wave3: uninvited C keeps their own accountUid; getTeamView(C) is the normal solo response', () => {
    needTeams();
    eq(w3teams.accountUid(uC.id), uC.id, 'accountUid(C) should equal C\'s own id (never invited)');
    ok(w3teams.accountUid(uC.id) !== w3teams.accountUid(uA.id), 'accountUid(C) collides with the team\'s accountUid');
    const view = w3teams.getTeamView(uC.id);
    ok(view, 'getTeamView(C) returned nothing');
    eq(view.team, null, 'getTeamView(C).team should be null (solo user — normal, not an error)');
    ok(Array.isArray(view.members) && view.members.length === 0, 'getTeamView(C).members should be empty');
    ok(Array.isArray(view.pendingInvites) && view.pendingInvites.length === 0, 'getTeamView(C).pendingInvites should be empty');
  });

  await t('wave3: a capture stored under accountUid(A) is reachable via accountUid(B) (real store.js calls)', () => {
    needTeams();
    const storeR = tryRequire(path.join('lib', 'store.js'));
    if (storeR.err) throw new Error(storeR.err);
    const store = storeR.mod;

    const uidA = w3teams.accountUid(uA.id);
    const uidB = w3teams.accountUid(uB.id);
    const captureId = store.newCaptureId();
    const dirViaA = store.captureDir(W3_DIR, uidA, captureId);
    fs.mkdirSync(dirViaA, { recursive: true });
    fs.writeFileSync(path.join(dirViaA, 'meta.json'), JSON.stringify({
      id: captureId, filename: 'wave3.pcap', uploadedAt: new Date().toISOString(), projectId: null,
    }));

    // The concrete assertion the task calls for: B's resolved directory for
    // the SAME capture id is the exact same path on disk as A's.
    const dirViaB = store.captureDir(W3_DIR, uidB, captureId);
    eq(dirViaB, dirViaA, 'captureDir(accountUid(B), captureId) !== captureDir(accountUid(A), captureId)');
    ok(fs.existsSync(path.join(dirViaB, 'meta.json')), 'meta.json not visible via accountUid(B)\'s resolved dir');

    const listedForB = store.listCaptures(W3_DIR, uidB);
    ok(listedForB.some((m) => m.id === captureId), 'listCaptures(accountUid(B)) does not include A\'s capture');

    w3SharedCaptureId = captureId;
  });

  await t('wave3: C (never invited) cannot reach the team\'s capture via accountUid resolution — the CVE-class check', () => {
    needTeams();
    ok(w3SharedCaptureId, 'prerequisite capture-sharing test did not run/pass');
    const storeR = tryRequire(path.join('lib', 'store.js'));
    if (storeR.err) throw new Error(storeR.err);
    const store = storeR.mod;

    const uidA = w3teams.accountUid(uA.id);
    const uidC = w3teams.accountUid(uC.id);
    ok(uidC !== uidA, 'accountUid(C) equals accountUid(A) — cross-tenant isolation is broken');

    const dirViaA = store.captureDir(W3_DIR, uidA, w3SharedCaptureId);
    const dirViaC = store.captureDir(W3_DIR, uidC, w3SharedCaptureId);
    ok(dirViaC !== dirViaA, 'captureDir resolves to the SAME directory for C as for A/B — cross-tenant leak');
    ok(!fs.existsSync(path.join(dirViaC, 'meta.json')),
      'C\'s resolved directory unexpectedly contains the team\'s capture meta.json');

    const listedForC = store.listCaptures(W3_DIR, uidC);
    ok(!listedForC.some((m) => m.id === w3SharedCaptureId),
      'listCaptures(accountUid(C)) leaks the team\'s capture to an uninvited user');
  });

  // ----------------------------------------------------- permission boundaries

  await t('wave3: plain member B cannot createInvite (owner/admin only)', async () => {
    needTeams();
    eq(w3teams.getAccountRole(uB.id), 'member', 'B\'s role before promotion');
    const e = await expectThrowsOrRejects(
      () => w3teams.createInvite(uB.id, 'w3-nobody@example.com'),
      'createInvite by a plain member'
    );
    ok(errMsg(e), 'rejection carries no message');
  });

  await t('wave3: promoting B to admin allows B to createInvite', async () => {
    needTeams();
    await within(Promise.resolve(w3teams.setMemberRole(uA.id, uB.id, 'admin')), 5000, 'setMemberRole(B, admin)');
    eq(w3teams.getAccountRole(uB.id), 'admin', 'B\'s role after promotion');
    ok(w3teams.canManageMembers(uB.id), 'canManageMembers(B) is false after promotion to admin');
    const inv = w3teams.createInvite(uB.id, 'w3-via-b@example.com');
    ok(inv && inv.token, 'createInvite by admin B did not succeed');
  });

  await t('wave3: nobody can remove the owner — not the owner themselves, not an admin', async () => {
    needTeams();
    await expectThrowsOrRejects(() => w3teams.removeMember(uA.id, uA.id), 'owner removing self');
    await expectThrowsOrRejects(() => w3teams.removeMember(uB.id, uA.id), 'admin B removing the owner');
    eq(w3teams.getAccountRole(uA.id), 'owner', 'A is no longer owner after rejected removal attempts');
  });

  await t('wave3: create + onboard a second admin, D', async () => {
    needTeams();
    uD = mkUser('w3-d@example.com', 'Dana D');
    const inv = w3teams.createInvite(uA.id, uD.email);
    const res = await within(Promise.resolve(
      w3teams.acceptInvite(inv.token, { sessionUserId: uD.id })
    ), 5000, 'acceptInvite(D)');
    ok(res && res.userId === uD.id, 'D failed to join the team');
    await within(Promise.resolve(w3teams.setMemberRole(uA.id, uD.id, 'admin')), 5000, 'setMemberRole(D, admin)');
    eq(w3teams.getAccountRole(uD.id), 'admin', 'D\'s role after promotion');
  });

  await t('wave3: an admin cannot remove another admin; the owner can', async () => {
    needTeams();
    ok(uD, 'prerequisite onboarding test did not run/pass');
    await expectThrowsOrRejects(() => w3teams.removeMember(uB.id, uD.id), 'admin B removing admin D');
    eq(w3teams.getAccountRole(uD.id), 'admin', 'D was removed by a fellow admin');

    await within(Promise.resolve(w3teams.removeMember(uA.id, uD.id)), 5000, 'owner A removing admin D');
    eq(w3teams.getAccountRole(uD.id), null, 'D still has a team role after the owner removed them');
    eq(w3teams.getTeamIdFor(uD.id), null, 'D still resolves to the team after removal');
  });

  await t('wave3: setMemberSuspended takes effect immediately, decoupled from lib/auth.js sessions', async () => {
    needTeams();
    const e2 = mkUser('w3-e@example.com', 'Eve E');
    const inv = w3teams.createInvite(uA.id, e2.email);
    await within(Promise.resolve(w3teams.acceptInvite(inv.token, { sessionUserId: e2.id })), 5000, 'acceptInvite(E)');
    eq(w3teams.isSuspended(e2.id), false, 'E suspended immediately after joining');

    await within(Promise.resolve(w3teams.setMemberSuspended(uA.id, e2.id, true)), 5000, 'setMemberSuspended(E, true)');
    eq(w3teams.isSuspended(e2.id), true, 'isSuspended(E) not true immediately after setMemberSuspended');

    // Spec: "lib/auth.js is untouched" — suspension enforcement belongs in
    // server.js's requireAuth, not in auth.js itself. Confirm the
    // decoupling: E's session still resolves fine at the auth layer even
    // though E is now suspended at the team layer.
    const sess = await within(Promise.resolve(w3auth.createSession(e2.id)), 5000, 'createSession(E)');
    const got = await within(Promise.resolve(w3auth.getSession(sess.token)), 5000, 'getSession(E) after suspension');
    ok(got && got.user && got.user.id === e2.id,
      'auth.getSession stopped resolving a suspended user directly — suspension enforcement belongs in server.js, not lib/auth.js');
  });

  await t('wave3: one-team-per-user — accepting a 2nd team\'s invite is rejected, 1st membership untouched', async () => {
    needTeams();
    const f2 = mkUser('w3-f@example.com', 'Frank F');
    const team2 = w3teams.createTeam(f2.id, 'Team Beta');
    ok(team2 && team2.teamId !== team1.teamId, 'team2 did not get its own teamId');

    const beforeUid = w3teams.accountUid(uB.id);
    const beforeTeamId = w3teams.getTeamIdFor(uB.id);
    eq(beforeTeamId, team1.teamId, 'B not on team1 before the cross-team-invite attempt');

    const inv2 = w3teams.createInvite(f2.id, uB.email); // B is already on team1
    const e = await expectThrowsOrRejects(
      () => w3teams.acceptInvite(inv2.token, { sessionUserId: uB.id }),
      'B accepting a 2nd team\'s invite while already on team1'
    );
    ok(errMsg(e), 'rejection carries no userMessage');

    eq(w3teams.getTeamIdFor(uB.id), beforeTeamId, 'B\'s teamId changed after the rejected cross-team accept');
    eq(w3teams.accountUid(uB.id), beforeUid, 'accountUid(B) changed after the rejected cross-team accept');
  });

  await t('wave3: re-inviting an email already on the team is rejected (no dangling duplicate invite)', async () => {
    needTeams();
    await expectThrowsOrRejects(
      () => w3teams.createInvite(uA.id, uB.email),
      'inviting an email that is already a team member'
    );
  });

  await t('wave3: transferOwnership moves the owner role but NEVER moves dataRootId', async () => {
    needTeams();
    const uidA_before = w3teams.accountUid(uA.id);
    const uidB_before = w3teams.accountUid(uB.id);
    eq(w3teams.getAccountRole(uA.id), 'owner', 'A is not owner before transfer');

    await within(Promise.resolve(w3teams.transferOwnership(uA.id, uB.id)), 5000, 'transferOwnership(A -> B)');

    eq(w3teams.getAccountRole(uB.id), 'owner', 'B is not owner after transferOwnership');
    ok(w3teams.getAccountRole(uA.id) !== 'owner', 'A is still owner after transferring ownership away');
    eq(w3teams.accountUid(uA.id), uidA_before, 'accountUid(A) moved after transferOwnership — dataRootId must never move');
    eq(w3teams.accountUid(uB.id), uidB_before, 'accountUid(B) moved after transferOwnership — dataRootId must never move');
    eq(w3teams.accountUid(uA.id), w3teams.accountUid(uB.id), 'A and B no longer share an accountUid after ownership transfer');
  });

  // ------------------------------------------- leaving, and owner recovery
  //
  // Account deletion used to call removeMember(self, self) under a comment
  // claiming "removing yourself is a leave". removeMember refuses a plain
  // member AND refuses acting on yourself, so it ALWAYS threw; server.js
  // swallowed it with a bare catch and deleted the account anyway, leaving a
  // member row pointing at a user that no longer existed. leaveTeam() is the
  // operation that was missing.

  await t('wave3: a member can leave, and the row actually goes', () => {
    needTeams();
    const owner = mkUser('leave-owner@example.test', 'Leave Owner');
    const leaver = mkUser('leave-member@example.test', 'Leaver');
    w3teams.createTeam(owner.id, 'Team Leave');
    const inv = w3teams.createInvite(owner.id, leaver.email);
    w3teams.acceptInvite(inv.token, { sessionUserId: leaver.id });
    eq(w3teams.getAccountRole(leaver.id), 'member', 'sanity: leaver joined');

    const out = w3teams.leaveTeam(leaver.id);
    ok(out && out.ok, 'leaveTeam did not report success');
    eq(w3teams.getTeamIdFor(leaver.id), null, 'leaver still has a teamId');
    eq(w3teams.getAccountRole(leaver.id), null, 'leaver still has a role');
    // Back to their own storage, not the team's shared root.
    eq(w3teams.accountUid(leaver.id), leaver.id, 'leaver accountUid did not revert to their own id');
  });

  await t('wave3: an owner with other members cannot leave (must transfer first)', () => {
    needTeams();
    const owner = mkUser('stuck-owner@example.test', 'Stuck Owner');
    const other = mkUser('stuck-member@example.test', 'Other');
    w3teams.createTeam(owner.id, 'Team Stuck');
    const inv = w3teams.createInvite(owner.id, other.email);
    w3teams.acceptInvite(inv.token, { sessionUserId: other.id });

    let threw = null;
    try { w3teams.leaveTeam(owner.id); } catch (e) { threw = e; }
    ok(threw, 'the owner was allowed to abandon a team with members');
    ok(/transfer/i.test(threw.userMessage || ''), 'refusal should point at transferring ownership: ' + threw.userMessage);
    eq(w3teams.getAccountRole(owner.id), 'owner', 'owner lost their role on a failed leave');
  });

  await t('wave3: a sole owner leaving dissolves the team rather than trapping them', () => {
    needTeams();
    const solo = mkUser('solo-owner@example.test', 'Solo');
    w3teams.createTeam(solo.id, 'Team Solo');
    const out = w3teams.leaveTeam(solo.id);
    ok(out && out.dissolved, 'a sole owner leaving should dissolve the team');
    eq(w3teams.getTeamIdFor(solo.id), null, 'solo owner still on a team after dissolving it');
  });

  await t('wave3: an active owner means the team cannot be taken over', () => {
    needTeams();
    const owner = mkUser('active-owner@example.test', 'Active Owner');
    const member = mkUser('patient-member@example.test', 'Member');
    w3teams.createTeam(owner.id, 'Team Active');
    const inv = w3teams.createInvite(owner.id, member.email);
    w3teams.acceptInvite(inv.token, { sessionUserId: member.id });

    const st = w3teams.getRecoveryState(member.id);
    eq(st.claimable, false, 'a team with a fresh owner must not be claimable');
    eq(st.reason, 'owner-active', 'recovery reason for an active owner');
    let threw = null;
    try { w3teams.claimOwnership(member.id); } catch (e) { threw = e; }
    ok(threw, 'claimOwnership succeeded against an ACTIVE owner — that is a takeover');
    eq(w3teams.getAccountRole(owner.id), 'owner', 'owner was displaced despite being active');
  });

  await t('wave3: a suspended member can never claim the team', () => {
    needTeams();
    const owner = mkUser('susp-owner@example.test', 'Owner');
    const bad = mkUser('susp-member@example.test', 'Suspended');
    w3teams.createTeam(owner.id, 'Team Susp');
    const inv = w3teams.createInvite(owner.id, bad.email);
    w3teams.acceptInvite(inv.token, { sessionUserId: bad.id });
    w3teams.setMemberSuspended(owner.id, bad.id, true);

    // Even with the owner erased -- the most claimable state there is.
    const raw = JSON.parse(fs.readFileSync(path.join(W3_DIR, 'users.json'), 'utf8'));
    fs.writeFileSync(path.join(W3_DIR, 'users.json'),
      JSON.stringify(raw.filter((u) => u.id !== owner.id), null, 2));
    w3auth.initAuth(W3_DIR);

    const st = w3teams.getRecoveryState(bad.id);
    eq(st.claimable, false, 'a SUSPENDED member must never be able to claim');
    eq(st.reason, 'suspended', 'recovery reason for a suspended member');
    let threw = null;
    try { w3teams.claimOwnership(bad.id); } catch (e) { threw = e; }
    ok(threw, 'a suspended member seized the team — they could then un-suspend themselves');

    fs.writeFileSync(path.join(W3_DIR, 'users.json'), JSON.stringify(raw, null, 2));
    w3auth.initAuth(W3_DIR);
  });

  await t('wave3: an orphaned team can be recovered by its remaining member', () => {
    needTeams();
    const owner = mkUser('gone-owner@example.test', 'Gone');
    const heir = mkUser('heir@example.test', 'Heir');
    w3teams.createTeam(owner.id, 'Team Orphan');
    const inv = w3teams.createInvite(owner.id, heir.email);
    w3teams.acceptInvite(inv.token, { sessionUserId: heir.id });
    const sharedUid = w3teams.accountUid(heir.id);

    // Delete the owner's USER record, leaving the team pointing at a ghost.
    const raw = JSON.parse(fs.readFileSync(path.join(W3_DIR, 'users.json'), 'utf8'));
    fs.writeFileSync(path.join(W3_DIR, 'users.json'),
      JSON.stringify(raw.filter((u) => u.id !== owner.id), null, 2));
    w3auth.initAuth(W3_DIR);

    const st = w3teams.getRecoveryState(heir.id);
    eq(st.claimable, true, 'an orphaned team should be claimable');
    eq(st.reason, 'orphaned', 'recovery reason for a deleted owner');

    w3teams.claimOwnership(heir.id);
    eq(w3teams.getAccountRole(heir.id), 'owner', 'heir did not become owner');
    // The whole point: the shared library must not move, or every capture and
    // guide the team owns is orphaned along with the account.
    eq(w3teams.accountUid(heir.id), sharedUid, 'dataRootId moved during recovery — the team lost its data');

    fs.writeFileSync(path.join(W3_DIR, 'users.json'), JSON.stringify(raw, null, 2));
    w3auth.initAuth(W3_DIR);
  });

  // -------------------------------------------------------- invite token edges

  await t('wave3: getInviteInfo(garbage token) returns null, does not throw', () => {
    needTeams();
    const res = w3teams.getInviteInfo('not-a-real-token-' + 'f'.repeat(40));
    eq(res, null, 'getInviteInfo(garbage) result');
  });

  await t('wave3: expired invite token is rejected (getInviteInfo null, acceptInvite throws)', async () => {
    needTeams();
    const storeR = tryRequire(path.join('lib', 'store.js'));
    if (storeR.err) throw new Error(storeR.err);
    const store = storeR.mod;

    // Dedicated owner/invitee, used only by this test: this is deliberately
    // the LAST test in this file that mutates lib/teams.js state, because it
    // forces a full re-init (see below) whose blast radius we don't want to
    // reason about relative to team1/A/B/D's already-asserted state.
    const owner = mkUser('w3-expowner@example.com', 'Owner Exp');
    const invitee = mkUser('w3-expinvitee@example.com', 'Invitee Exp');
    w3teams.createTeam(owner.id, 'Team Expiry');
    const inv = w3teams.createInvite(owner.id, invitee.email);
    ok(w3teams.getInviteInfo(inv.token), 'sanity: fresh invite not visible via getInviteInfo before we expire it');

    // Directly edit data/invitations.json's expiresAt into the past rather
    // than sleeping 7 days. Per ARCHITECTURE.md this is a plain store.js
    // JSON object keyed by token. IF lib/teams.js caches invitations in
    // memory the way lib/auth.js caches users/sessions (loaded once at
    // init, mutated only through its own API — see auth.initAuth's own
    // "safe to call again, re-reads from disk" doc comment), this on-disk
    // edit alone won't be visible until something forces a reload — so we
    // call initTeams() again on the assumption teams.js follows the same
    // convention. If that assumption is wrong and teams.js re-reads the
    // file on every call instead, the extra initTeams() call is harmless.
    const invFile = path.join(W3_DIR, 'invitations.json');
    const all = store.loadJson(invFile, null);
    ok(all && all[inv.token],
      'invitations.json does not contain the token just created — check the file name/shape against the spec ' +
      '(expected data/invitations.json, an object keyed by the 32-byte-hex token)');
    all[inv.token].expiresAt = Date.now() - 1000;
    store.saveJson(invFile, all);
    await within(Promise.resolve(w3teams.initTeams(W3_DIR)), 10000, 're-init teams to pick up the hand-edited expiry');

    eq(w3teams.getInviteInfo(inv.token), null, 'getInviteInfo on an expired token');

    const e = await expectThrowsOrRejects(
      () => w3teams.acceptInvite(inv.token, { sessionUserId: invitee.id }),
      'acceptInvite on an expired token'
    );
    ok(errMsg(e), 'expired-token rejection carries no message');
  });

  // ---------------------------------------------- path-safety / id validation

  await t('wave3: createProject rejects an empty name and an over-long (81-char) name', async () => {
    needProjects();
    ok(uidAForProjects, 'prerequisite team-creation test did not run/pass');
    await expectThrowsOrRejects(
      () => w3projects.createProject(uidAForProjects, { name: '' }),
      'createProject with an empty name'
    );
    await expectThrowsOrRejects(
      () => w3projects.createProject(uidAForProjects, { name: 'x'.repeat(81) }),
      'createProject with an 81-char name (documented limit is 80)'
    );
  });

  await t('wave3: create real projects for A and C (fixtures for the id-validation tests below)', () => {
    needProjects();
    needTeams();
    const uidC = w3teams.accountUid(uC.id);
    realProjectA = w3projects.createProject(uidAForProjects, { name: 'Wave3 Project A' });
    realProjectC = w3projects.createProject(uidC, { name: 'Wave3 Project C' });
    ok(realProjectA && /^[a-f0-9]{12}$/.test(realProjectA.id), 'createProject(A) did not return a 12-hex id');
    ok(realProjectC && /^[a-f0-9]{12}$/.test(realProjectC.id), 'createProject(C) did not return a 12-hex id');
  });

  // server.js does not define resolveOwnedProjectId yet as of this writing
  // (confirmed by grep: no "resolveOwnedProjectId"/"teams"/"projects"
  // anywhere in server.js), and server.js has no module.exports at all — it
  // calls server.listen() unconditionally at module scope with no
  // `require.main === module` guard and registers SIGINT handlers, so
  // require()-ing it here would start a real HTTP listener as a side effect
  // of running this selftest, which must never happen. So the tests below
  // exercise a LOCAL, byte-for-byte mirror of ARCHITECTURE.md's documented
  // function body against the REAL lib/projects.js:
  //   function resolveOwnedProjectId(accountUid, rawId) {
  //     if (typeof rawId !== 'string' || !/^[a-f0-9]{12}$/.test(rawId)) return null;
  //     return projects.getProject(accountUid, rawId) ? rawId : null;
  //   }
  // INTEGRATOR: once server.js actually defines this (name/location TBD),
  // please confirm it matches this body exactly, ideally by pointing these
  // tests at the real export instead of the mirror.
  function mirrorResolveOwnedProjectId(getProjectFn, accountUid, rawId) {
    if (typeof rawId !== 'string' || !/^[a-f0-9]{12}$/.test(rawId)) return null;
    return getProjectFn(accountUid, rawId) ? rawId : null;
  }

  await t('wave3: resolveOwnedProjectId (mirror) rejects malformed ids BEFORE any getProject lookup', () => {
    needProjects();
    ok(realProjectA, 'prerequisite project-creation test did not run/pass');
    let calls = 0;
    const spy = (uid, id) => { calls++; return w3projects.getProject(uid, id); };

    const malformed = [
      ['path traversal (..)', '../../etc'],
      ['path traversal to a sibling account', '../../../' + w3teams.accountUid(uC.id)],
      ['backslash traversal', '..\\..\\etc\\passwd'],
      ['URL-encoded traversal', '..%2f..%2fetc'],
      ['UNC path', '\\\\server\\share\\x'],
      ['Windows absolute path', 'C:\\Windows\\x'],
      ['too short (11 chars)', 'a'.repeat(11)],
      ['too long (13 chars)', 'a'.repeat(13)],
      ['uppercase hex', 'ABCDEF123456'],
      ['mixed-case hex', 'aBcDef123456'],
      ['non-hex letters', 'zzzzzzzzzzzz'],
      ['empty string', ''],
      ['leading whitespace', ' ' + realProjectA.id.slice(1)],
      ['trailing newline', realProjectA.id.slice(0, 11) + '\n'],
      ['embedded null byte', 'abcdef\u000012345'],
      ['null', null],
      ['undefined', undefined],
      ['number, not string', 123456789012],
      ['array', ['a', 'b']],
      ['object', { id: 'abcdef123456' }],
      ['very long string', 'a'.repeat(10000)],
    ];

    const problems = [];
    for (const [label, rawId] of malformed) {
      const result = mirrorResolveOwnedProjectId(spy, uidAForProjects, rawId);
      if (result !== null) problems.push(label + ': expected null, got ' + JSON.stringify(result));
    }
    if (calls !== 0) problems.push('getProject was called ' + calls + ' time(s) for malformed ids — the shape check did not short-circuit');
    if (problems.length) throw new Error(problems.join('; '));
  });

  await t('wave3: a 12-digit numeric STRING is valid hex shape (0-9 are valid hex digits — not a gap)', () => {
    needProjects();
    // Distinguishes from the "number, not string" case above: a JS `number`
    // is rejected by the `typeof rawId !== 'string'` guard, but a STRING of
    // 12 decimal digits legally matches /^[a-f0-9]{12}$/. Noted explicitly
    // so nobody mistakes the absence of a rejection here for a missed case —
    // ownership (getProject) is still what ultimately gates access.
    const digitsOnly = '123456789012';
    ok(/^[a-f0-9]{12}$/.test(digitsOnly), 'sanity: the documented regex accepts a 12-digit numeric string');
    let calls = 0;
    const spy = (uid, id) => { calls++; return w3projects.getProject(uid, id); };
    const result = mirrorResolveOwnedProjectId(spy, uidAForProjects, digitsOnly);
    eq(result, null, 'a well-shaped but nonexistent id should resolve null via the ownership check');
    eq(calls, 1, 'getProject should have been called exactly once for a well-shaped id');
  });

  await t('wave3: a nonexistent id and another tenant\'s real id resolve IDENTICALLY (no information leak)', () => {
    needProjects();
    ok(realProjectC, 'prerequisite project-creation test did not run/pass');

    const nonexistentId = 'deadbeef0000';
    ok(/^[a-f0-9]{12}$/.test(nonexistentId), 'sanity: nonexistentId is well-shaped');
    const r1 = mirrorResolveOwnedProjectId(w3projects.getProject, uidAForProjects, nonexistentId);
    const r2 = mirrorResolveOwnedProjectId(w3projects.getProject, uidAForProjects, realProjectC.id);

    eq(r1, null, 'resolveOwnedProjectId(A, nonexistent-id)');
    eq(r2, null, 'resolveOwnedProjectId(A, C\'s real project id) — must be null, not a leak of C\'s project');
    eq(r1, r2, 'a nonexistent id and another tenant\'s real id must be indistinguishable to the caller');

    // Confirmed directly against the real getProject too, not just the mirror.
    eq(w3projects.getProject(uidAForProjects, realProjectC.id), null, 'projects.getProject(A, C\'s project id) leaked C\'s project to A');

    // Positive control: A's own real project resolves fine, proving the
    // rejections above are a genuine ownership check, not e.g. getProject
    // always returning null regardless of input.
    const r3 = mirrorResolveOwnedProjectId(w3projects.getProject, uidAForProjects, realProjectA.id);
    eq(r3, realProjectA.id, 'resolveOwnedProjectId(A, A\'s own real project id) should resolve to that id');
  });

  await t('wave3: projects.getProject itself never throws on hostile ids (defense in depth beneath the shape gate)', () => {
    needProjects();
    // Not a strict spec requirement (resolveOwnedProjectId is the mandated
    // gate) — this checks the layer underneath doesn't also need to be
    // perfectly trusted. A failure here is a hardening opportunity, not
    // necessarily a spec violation; call it out as such when reporting.
    const hostile = ['../../etc', '..\\..\\x', '\u0000', '', null, undefined, 123, ['x'], { x: 1 }, 'a'.repeat(10000)];
    const problems = [];
    for (const rawId of hostile) {
      try {
        const res = w3projects.getProject(uidAForProjects, rawId);
        if (res) problems.push('getProject(' + JSON.stringify(rawId) + ') returned a truthy value: ' + JSON.stringify(res));
      } catch (e) {
        problems.push('getProject(' + JSON.stringify(rawId) + ') threw: ' + errMsg(e));
      }
    }
    if (problems.length) throw new Error(problems.join('; '));
  });

  // ---------------------------------------------------------------- wave 6
  // The privacy boundary from ARCHITECTURE.md "Wave 6". These are the tests
  // that matter most in this file: sanitizeContext() is the single thing
  // standing between a feedback submission and a phone number leaving the box,
  // so it is tested against a deliberately hostile payload, not a tidy one.

  await t('wave6: lib/feedback.js and lib/mail.js load', () => {
    const f = require(path.join(ROOT, 'lib', 'feedback.js'));
    const m = require(path.join(ROOT, 'lib', 'mail.js'));
    for (const fn of ['save', 'list', 'setRead', 'since', 'sanitizeContext',
      'buildDigest', 'digestDue', 'isoWeek', 'getDigestState', 'setDigestSent']) {
      ok(typeof f[fn] === 'function', 'feedback.' + fn + ' missing');
    }
    for (const fn of ['send', 'isConfigured', 'loadConfig']) {
      ok(typeof m[fn] === 'function', 'mail.' + fn + ' missing');
    }
  });

  await t('wave6: sanitizeContext keeps structural context', () => {
    const f = require(path.join(ROOT, 'lib', 'feedback.js'));
    const c = f.sanitizeContext({
      page: '/app',
      counts: { sip: 88, calls: 12 },
      scopeIds: { callId: 'c4', legId: 'd4' },
      selectedRow: { kind: 'msg', method: 'REFER', status: 486 },
      lamps: [{ key: 'refer-transfer', state: 'issue' }],
      adviceRuleIds: ['indicator-issue'],
    });
    eq(c.page, '/app', 'page');
    eq(c.counts.sip, 88, 'counts.sip');
    eq(c.scopeIds.callId, 'c4', 'scopeIds.callId');
    eq(c.selectedRow.method, 'REFER', 'selectedRow.method');
    eq(c.selectedRow.status, 486, 'selectedRow.status');
    eq(c.lamps[0].key, 'refer-transfer', 'lamps[0].key');
    eq(c.adviceRuleIds[0], 'indicator-issue', 'adviceRuleIds[0]');
  });

  await t('wave6: sanitizeContext strips EVERY forbidden field (the privacy boundary)', () => {
    const f = require(path.join(ROOT, 'lib', 'feedback.js'));
    const c = f.sanitizeContext({
      page: '/app',
      filename: 'acme-corp-outage.pcap',   // carries customer names
      searchTerm: '+33610000303',          // users search by phone number
      raw: 'INVITE sip:+33610000303@pbx SIP/2.0',
      fromUser: '+33612345678',
      toUser: '+33900001111',
      srcIp: '198.51.100.10',
      headers: [{ name: 'To', value: 'sip:+33900001111@x' }],
      sdp: 'c=IN IP4 198.51.100.10',
    });
    const json = JSON.stringify(c);
    const banned = ['acme-corp', '+33610000303', '+33612345678', '+33900001111',
      '198.51.100.10', 'INVITE sip:', 'c=IN IP4'];
    for (const b of banned) {
      ok(json.indexOf(b) === -1, 'forbidden value leaked into context: ' + b);
    }
    const allowed = ['page', 'appVersion', 'theme', 'userAgent', 'viewport',
      'captureFormat', 'captureBytes', 'counts', 'scenario', 'scopeType',
      'scopeIds', 'selectedRow', 'lamps', 'adviceRuleIds'];
    for (const k of Object.keys(c)) {
      ok(allowed.indexOf(k) !== -1, 'unexpected key survived the allow-list: ' + k);
    }
  });

  await t('wave6: sanitizeContext bounds strings and strips control characters', () => {
    const f = require(path.join(ROOT, 'lib', 'feedback.js'));
    const c = f.sanitizeContext({
      page: 'a\x00b\x1fc\x7fd',
      scopeIds: { callId: 'x'.repeat(500) },
    });
    ok(!/[\x00-\x1f\x7f]/.test(c.page), 'control chars survived: ' + JSON.stringify(c.page));
    ok(c.scopeIds.callId.length <= 40, 'oversized id not bounded');
    eq(f.sanitizeContext('not-an-object'), null, 'non-object');
    eq(f.sanitizeContext({ evil: 'x' }), null, 'nothing allowed survives');
  });

  await t('wave6: save/list/setRead round-trip, with sanitising applied on save', () => {
    const f = require(path.join(ROOT, 'lib', 'feedback.js'));
    const dir = path.join(TMP_DATA, 'wave6-' + Date.now());
    fs.mkdirSync(dir, { recursive: true });
    const rec = f.save(dir, {
      userId: 'u1', email: 'a@b.c', kind: 'bug', rating: 4,
      comment: '  the ladder is confusing  ',
      context: { page: '/app', filename: 'acme-corp.pcap' },
    });
    ok(/^fb_[0-9a-f]{12}$/.test(rec.id), 'bad id: ' + rec.id);
    eq(rec.comment, 'the ladder is confusing', 'comment trimmed');
    eq(rec.read, false, 'starts unread');
    ok(JSON.stringify(rec.context).indexOf('acme-corp') === -1, 'save() did not sanitise');

    f.save(dir, { userId: 'u2', email: 'd@e.f', kind: 'bogus', rating: 99, comment: 'second' });
    const all = f.list(dir);
    eq(all.length, 2, 'record count');
    eq(all[0].comment, 'second', 'newest first');
    eq(all[0].kind, 'other', 'unknown kind coerced');
    eq(all[0].rating, 5, 'rating clamped');

    let threw = false;
    try { f.save(dir, { comment: '   ' }); } catch { threw = true; }
    ok(threw, 'empty comment was accepted');
    eq(f.setRead(dir, rec.id, true).read, true, 'setRead');
    eq(f.setRead(dir, 'fb_nope', true), null, 'setRead unknown id');
  });

  await t('wave6: digest is null when empty, escapes HTML when not', () => {
    const f = require(path.join(ROOT, 'lib', 'feedback.js'));
    eq(f.buildDigest([]), null, 'empty digest');
    const d = f.buildDigest([{ ts: Date.now(), kind: 'bug', comment: '<script>x</script>', email: 'a@b' }]);
    ok(d && d.subject && d.text && d.html, 'digest incomplete');
    ok(d.html.indexOf('<script>') === -1, 'digest html not escaped');
  });

  await t('wave6: digestDue is restart-safe (no double-send, no skipped week)', () => {
    const f = require(path.join(ROOT, 'lib', 'feedback.js'));
    const dir = path.join(TMP_DATA, 'wave6-digest-' + Date.now());
    fs.mkdirSync(dir, { recursive: true });
    const monEarly = new Date('2026-08-17T08:00:00');
    const monLate = new Date('2026-08-17T10:00:00');
    const wed = new Date('2026-08-19T03:00:00');
    const sun = new Date('2026-08-23T12:00:00');
    eq(f.digestDue(dir, monEarly), false, 'Monday before 09:00');
    eq(f.digestDue(dir, monLate), true, 'Monday after 09:00');
    // The box is a home-lab machine that reboots for Windows updates: a digest
    // whose moment passed while the service was down must still go out.
    eq(f.digestDue(dir, wed), true, 'missed Monday still due midweek');
    eq(f.digestDue(dir, sun), false, 'Sunday belongs to the closing week');
    f.setDigestSent(dir, f.isoWeek(monLate));
    eq(f.digestDue(dir, wed), false, 'resent in the same week after a restart');
    eq(f.digestDue(dir, new Date('2026-08-24T10:00:00')), true, 'next week');
  });

  await t('wave6: mail degrades to a no-op when unconfigured (never takes the box down)', async () => {
    const m = require(path.join(ROOT, 'lib', 'mail.js'));
    const dir = path.join(TMP_DATA, 'wave6-mail-' + Date.now());
    fs.mkdirSync(dir, { recursive: true });
    eq(m.isConfigured(dir), false, 'isConfigured with no config file');
    eq(m.loadConfig(dir), null, 'loadConfig with no config file');
    const r = await m.send(dir, { to: 'x@y.z', subject: 's', text: 't', html: '<p>t</p>' });
    eq(r.sent, false, 'send() reported a send');
    ok(typeof r.reason === 'string' && r.reason, 'send() gave no reason');
    // A config missing the password is unusable and must be treated as absent.
    fs.writeFileSync(path.join(dir, 'email-config.json'), JSON.stringify({ user: 'a@b.c' }), 'utf8');
    eq(m.isConfigured(dir), false, 'partial config treated as configured');
  });

  // ------------------------------------------------------- retention sweep
  // An irreversible bulk delete on a timer. The tests that matter are the ones
  // proving it does NOT delete: disabled, dry-run, boundary, and undated.

  await t('retention: 0/negative/non-numeric all disable the sweep entirely', () => {
    const r = require(path.join(ROOT, 'lib', 'retention.js'));
    for (const v of [0, -5, 'soon', null, undefined, NaN]) {
      eq(r.sweep(TMP_DATA, v).enabled, false, 'days=' + JSON.stringify(v));
    }
    eq(r.sweepIfDue(TMP_DATA, 0).skipped, 'disabled', 'sweepIfDue at 0');
  });

  await t('retention: deletes only what is past the limit, keeps the rest', () => {
    const r = require(path.join(ROOT, 'lib', 'retention.js'));
    const st = require(path.join(ROOT, 'lib', 'store.js'));
    const dir = path.join(TMP_DATA, 'ret-' + Date.now());
    const DAY = 86400000;
    const mk = (uid, id, ageDays, undated) => {
      const d = st.captureDir(dir, uid, id);
      fs.mkdirSync(d, { recursive: true });
      const meta = { id, filename: id + '.pcap' };
      if (!undated) meta.uploadedAt = new Date(Date.now() - ageDays * DAY).toISOString();
      st.saveJson(path.join(d, 'meta.json'), meta);
      fs.writeFileSync(path.join(d, 'original.bin'), 'x');
    };
    mk('user_a', 'recent', 1);
    mk('user_a', 'ancient', 40);
    mk('user_a', 'boundary', 30);
    mk('user_a', 'undated', 99, true);
    // A team's shared library lives under the TEAM's accountUid, which is not
    // a user id — the sweep must find it by walking the filesystem, not users.
    mk('team_b', 'teamold', 60);

    const dry = r.sweep(dir, 30, { dry: true });
    eq(dry.removed, 2, 'dry run count');
    ok(fs.existsSync(st.captureDir(dir, 'user_a', 'ancient')), 'dry run actually deleted something');

    const out = r.sweep(dir, 30);
    eq(out.removed, 2, 'removed count');
    eq(out.accounts, 2, 'walked both accounts (incl. the team library)');
    ok(!fs.existsSync(st.captureDir(dir, 'user_a', 'ancient')), 'over-limit capture survived');
    ok(!fs.existsSync(st.captureDir(dir, 'team_b', 'teamold')), 'over-limit team capture survived');
    ok(fs.existsSync(st.captureDir(dir, 'user_a', 'recent')), 'recent capture was deleted');
    // "Keep for 30 days" must not delete on day 30 — see the whole-day note in
    // retention.js. This errs toward keeping, which is the safe side.
    ok(fs.existsSync(st.captureDir(dir, 'user_a', 'boundary')), 'boundary capture deleted on day 30');
    // Deleting something whose age cannot be established is worse than keeping it.
    ok(fs.existsSync(st.captureDir(dir, 'user_a', 'undated')), 'undated capture deleted on a guess');
    eq(out.skippedUndated, 1, 'undated not reported as skipped');
  });

  await t('retention: scheduling is restart-safe (once a day, no skipped day)', () => {
    const r = require(path.join(ROOT, 'lib', 'retention.js'));
    const dir = path.join(TMP_DATA, 'retsched-' + Date.now());
    fs.mkdirSync(dir, { recursive: true });
    eq(r.sweepDue(dir), true, 'due before the first run');
    r.sweepIfDue(dir, 30);
    eq(r.sweepDue(dir), false, 'still due right after a run');
    eq(r.sweepIfDue(dir, 30).skipped, 'already swept today', 'ran twice in one day');
    eq(r.sweepIfDue(dir, 30, { force: true }).enabled, true, 'force did not override');
    // A dry run must not consume the day, or the real sweep never happens.
    const d2 = path.join(TMP_DATA, 'retdry-' + Date.now());
    fs.mkdirSync(d2, { recursive: true });
    r.sweepIfDue(d2, 30, { dry: true });
    eq(r.sweepDue(d2), true, 'dry run stamped the day');
  });

  // hmr-generate: plain-English -> HMR rule. The tests that matter are the
  // two regressions found while building it (a greedy value capture, and
  // plural SIP method names not matching), plus one case per intent so a
  // future edit to the shared BOUNDARY/INTENTS table cannot silently break
  // one of them without a red test.

  await t('hmr-generate: delete-header intent, direction and plural method name', () => {
    const g = require(path.join(ROOT, 'lib', 'hmr-generate.js'));
    const out = g.generateRule('strip the P-Asserted-Identity header on outbound INVITEs');
    eq(out.ok, true, 'ok');
    eq(out.matchedIntent, 'delete-header', 'matchedIntent');
    eq(out.rule.target.header, 'P-Asserted-Identity', 'target.header');
    eq(out.rule.operation, 'delete', 'operation');
    eq(out.rule.scope.direction, 'out', 'scope.direction');
    ok(out.rule.scope.methods.indexOf('INVITE') !== -1, 'plural "INVITEs" did not match method INVITE');
  });

  await t('hmr-generate: add-header value stops at the trailing clause, not the rest of the sentence', () => {
    const g = require(path.join(ROOT, 'lib', 'hmr-generate.js'));
    // Regression: this used to capture "id on outbound calls" as the value
    // instead of stopping at " on" — see BOUNDARY in lib/hmr-generate.js.
    const out = g.generateRule('add a Privacy header set to id on outbound calls');
    eq(out.ok, true, 'ok');
    eq(out.matchedIntent, 'add-header', 'matchedIntent');
    eq(out.rule.target.header, 'Privacy', 'target.header');
    ok(!!out.rule.value, 'value was not extracted at all');
    eq(out.rule.value.text, 'id', 'value text (greedy capture regression)');
  });

  await t('hmr-generate: replace-in-header and store-header intents', () => {
    const g = require(path.join(ROOT, 'lib', 'hmr-generate.js'));
    const rep = g.generateRule('replace the From display name with "Anonymous"');
    eq(rep.ok, true, 'replace ok');
    eq(rep.matchedIntent, 'replace-in-header', 'replace matchedIntent');
    eq(rep.rule.value.text, 'Anonymous', 'replace value');

    const store = g.generateRule('store the Diversion header for later');
    eq(store.ok, true, 'store ok');
    eq(store.matchedIntent, 'store-header', 'store matchedIntent');
    eq(store.rule.operation, 'store', 'store operation');
  });

  await t('hmr-generate: no header/action recognised asks instead of guessing', () => {
    const g = require(path.join(ROOT, 'lib', 'hmr-generate.js'));
    const out = g.generateRule('make calls sound better somehow');
    eq(out.ok, false, 'ok must be false with nothing to build');
    eq(out.rule, null, 'no rule fabricated');
    ok(out.questions.length > 0, 'must ask rather than guess');
  });

  await t('hmr-generate: empty description is rejected, not thrown', () => {
    const g = require(path.join(ROOT, 'lib', 'hmr-generate.js'));
    const out = g.generateRule('');
    eq(out.ok, false, 'ok');
    ok(out.warnings.length > 0, 'warnings');
  });

  await t('hmr-generate: buildRegex reads a "starts with" condition and tests its own example', () => {
    const g = require(path.join(ROOT, 'lib', 'hmr-generate.js'));
    const r = g.buildRegex('the calling number starts with "0033", e.g. "0033123456789"');
    eq(r.pattern, '^0033', 'pattern');
    eq(r.tested.length, 1, 'tested one embedded example');
    eq(r.tested[0].matched, true, 'the pattern must match its own worked example');
  });

  await t('hmr-generate: a valid rule renders on every vendor without throwing', () => {
    const g = require(path.join(ROOT, 'lib', 'hmr-generate.js'));
    const out = g.generateRule('strip the P-Asserted-Identity header on outbound INVITEs');
    eq(out.ok, true, 'ok');
    for (const v of ['oracle-acme', 'audiocodes', 'ribbon', 'generic']) {
      ok(typeof out.drafts[v] === 'string' && out.drafts[v].length > 0, v + ' draft is empty');
    }
    ok(!!out.explain && !!out.explain.intent, 'explainRule produced no summary');
  });

  // lib/adminlist.js: the site-admin allow-list edit logic. Every case below
  // maps to a specific bug an adversarial review found in the first version
  // of this feature (grant/revoke was inline in server.js's HTTP handler,
  // untestable and untested) — see ARCHITECTURE.md for the full writeup.
  // This module was extracted from that handler specifically so these rules
  // could be pinned down here.

  await t('adminlist: grants and revokes normally when the list already has another live admin', () => {
    const al = require(path.join(ROOT, 'lib', 'adminlist.js'));
    const exists = (e) => ['owner@example.com', 'alice@example.com'].indexOf(e) !== -1;

    const granted = al.applyChange({
      currentEmails: ['owner@example.com'], targetEmail: 'alice@example.com',
      wantSuperuser: true, actorEmail: 'owner@example.com', accountExists: exists,
    });
    eq(granted.ok, true, 'grant ok');
    eq(granted.adminEmails.join(','), 'owner@example.com,alice@example.com', 'grant result');

    const revoked = al.applyChange({
      currentEmails: granted.adminEmails, targetEmail: 'alice@example.com',
      wantSuperuser: false, actorEmail: 'owner@example.com', accountExists: exists,
    });
    eq(revoked.ok, true, 'revoke ok');
    eq(revoked.adminEmails.join(','), 'owner@example.com', 'revoke result');
  });

  await t('adminlist: granting while the list is empty (role-fallback) seeds the actor, not just the target', () => {
    // Regression: the first version made the list non-empty with ONLY the
    // target in it, which isSiteAdmin() then treats as authoritative over
    // role — silently locking the acting admin out mid-action.
    const al = require(path.join(ROOT, 'lib', 'adminlist.js'));
    const out = al.applyChange({
      currentEmails: [], targetEmail: 'bob@example.com',
      wantSuperuser: true, actorEmail: 'owner@example.com', accountExists: () => true,
    });
    eq(out.ok, true, 'ok');
    ok(out.adminEmails.indexOf('owner@example.com') !== -1, 'actor was not seeded — actor would be locked out');
    ok(out.adminEmails.indexOf('bob@example.com') !== -1, 'target was not granted');
    eq(out.adminEmails.length, 2, 'exactly actor + target, no duplicates');
  });

  await t('adminlist: granting yourself while the list is empty does not duplicate your own email', () => {
    const al = require(path.join(ROOT, 'lib', 'adminlist.js'));
    const out = al.applyChange({
      currentEmails: [], targetEmail: 'owner@example.com',
      wantSuperuser: true, actorEmail: 'owner@example.com', accountExists: () => true,
    });
    eq(out.ok, true, 'ok');
    eq(out.adminEmails.join(','), 'owner@example.com', 'actor === target must appear once');
  });

  await t('adminlist: revoking while the list is empty is refused, not a lying "success"', () => {
    // Regression: the first version computed already=false (nothing to
    // remove from an empty list) and skipped both branches, returning
    // {ok:true, isSuperuser:false} while the actor's real access — via role
    // fallback — was completely unchanged.
    const al = require(path.join(ROOT, 'lib', 'adminlist.js'));
    const out = al.applyChange({
      currentEmails: [], targetEmail: 'owner@example.com',
      wantSuperuser: false, actorEmail: 'owner@example.com', accountExists: () => true,
    });
    eq(out.ok, false, 'must refuse, not silently succeed');
    ok(/empty/i.test(out.error), 'error should explain the list is empty: ' + out.error);
  });

  await t('adminlist: revoking a target not currently listed is an idempotent no-op success', () => {
    const al = require(path.join(ROOT, 'lib', 'adminlist.js'));
    const out = al.applyChange({
      currentEmails: ['owner@example.com'], targetEmail: 'nobody@example.com',
      wantSuperuser: false, actorEmail: 'owner@example.com', accountExists: () => true,
    });
    eq(out.ok, true, 'ok');
    eq(out.adminEmails.join(','), 'owner@example.com', 'list unchanged');
  });

  await t('adminlist: the last-admin guard counts LIVE accounts, not raw list length', () => {
    // Regression: a stale entry (e.g. the default seed email before that
    // account has ever signed up, or left behind after deletion) made
    // allow.length look like 2 when only one entry was a real account —
    // the old guard (`allow.length <= 1`) let the real last admin be removed.
    const al = require(path.join(ROOT, 'lib', 'adminlist.js'));
    const exists = (e) => e === 'owner@example.com'; // 'ghost@example.com' has no account
    const out = al.applyChange({
      currentEmails: ['owner@example.com', 'ghost@example.com'], targetEmail: 'owner@example.com',
      wantSuperuser: false, actorEmail: 'owner@example.com', accountExists: exists,
    });
    eq(out.ok, false, 'must refuse — removing the only LIVE admin');
    ok(/last superuser/i.test(out.error), 'error should name the last-superuser guard: ' + out.error);
  });

  await t('adminlist: the last-admin guard allows removal when a live admin remains', () => {
    const al = require(path.join(ROOT, 'lib', 'adminlist.js'));
    const exists = (e) => e === 'owner@example.com' || e === 'alice@example.com';
    const out = al.applyChange({
      currentEmails: ['owner@example.com', 'alice@example.com'], targetEmail: 'owner@example.com',
      wantSuperuser: false, actorEmail: 'owner@example.com', accountExists: exists,
    });
    eq(out.ok, true, 'ok — alice is still live');
    eq(out.adminEmails.join(','), 'alice@example.com', 'owner removed, alice remains');
  });

  await t('adminlist: input is normalised and deduplicated regardless of case/whitespace', () => {
    const al = require(path.join(ROOT, 'lib', 'adminlist.js'));
    const out = al.applyChange({
      currentEmails: [' Owner@Example.com ', 'owner@example.com', 'OWNER@EXAMPLE.COM'],
      targetEmail: '  Alice@Example.COM  ',
      wantSuperuser: true, actorEmail: 'owner@example.com', accountExists: () => true,
    });
    eq(out.ok, true, 'ok');
    eq(out.adminEmails.join(','), 'owner@example.com,alice@example.com',
      'three case/whitespace variants of the same address must collapse to one');
  });

  await t('adminlist: pruneEmail removes a deleted account\'s email, case-insensitively, and never refuses', () => {
    const al = require(path.join(ROOT, 'lib', 'adminlist.js'));
    const removed = al.pruneEmail(['owner@example.com', 'bob@example.com'], 'BOB@example.com');
    eq(removed.changed, true, 'changed');
    eq(removed.adminEmails.join(','), 'owner@example.com', 'bob removed');

    // Pruning the SOLE remaining admin must still succeed (never refuse) —
    // GDPR erasure is the account holder's right regardless of admin status.
    const soleAdmin = al.pruneEmail(['owner@example.com'], 'owner@example.com');
    eq(soleAdmin.changed, true, 'changed');
    eq(soleAdmin.adminEmails.length, 0, 'list may end up empty — that is accepted, not refused');

    const noop = al.pruneEmail(['owner@example.com'], 'nobody@example.com');
    eq(noop.changed, false, 'absent email is a no-op');
  });

  // lib/textlog.js: SIP text-log ingest. Every test below pins a specific way
  // the parser used to lose messages SILENTLY — the worst possible failure for
  // this product, because a trace missing half its messages still produces a
  // confident (and wrong) diagnosis. ARCHITECTURE.md's contract for this
  // module is "skip malformed input WITH a warning string", so a quiet miss is
  // a contract violation, not just a parse miss.
  //
  //  - The Content-Length tests cover the bug that motivated the pass: a
  //    declared Content-Length larger than the body actually captured (RFC
  //    4475 `clerr`, and routine in truncated sipmsg.log exports and elided
  //    SDP) made the body loop consume the entire rest of the file.
  //  - The two "not split" tests are the counterweight: bounding the body by
  //    the next start line is only safe if a start line is recognised
  //    accurately, since a false positive truncates the message it lands in
  //    AND invents a phantom one. message/sipfrag is the case that matters in
  //    the field — every REFER-based transfer trace carries a real status line
  //    inside a NOTIFY body.
  //  - The RFC 4475 start-line tests cover the other two known gaps that were
  //    fixed in the same pass (%-escaped method tokens, non-2.0 versions and
  //    out-of-range status codes), and the chatter test pins the false-positive
  //    boundary those relaxations had to respect.

  const CRLF = '\r\n';

  /**
   * Build a SIP message with an explicitly chosen Content-Length, so a test
   * can declare a length that does NOT match the body it supplies.
   * @param {string} startLine request-line or status-line
   * @param {string[]} headers header lines, in wire order
   * @param {string} body body text (already CRLF-terminated), '' for none
   * @param {number} [declaredLen] Content-Length to declare; defaults to the
   *   real body length
   * @returns {string}
   */
  function textlogMsg(startLine, headers, body, declaredLen) {
    const b = body || '';
    const len = declaredLen === undefined ? Buffer.byteLength(b) : declaredLen;
    return [startLine].concat(headers, ['Content-Length: ' + len], ['', '']).join(CRLF) + b;
  }

  const TL_SDP = [
    'v=0', 'o=- 1 1 IN IP4 198.51.100.10', 's=-', 'c=IN IP4 198.51.100.10',
    't=0 0', 'm=audio 40000 RTP/AVP 0', 'a=rtpmap:0 PCMU/8000',
  ].join(CRLF) + CRLF;

  const TL_OK = textlogMsg('SIP/2.0 200 OK', [
    'Via: SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-1',
    'From: <sip:alice@example.com>;tag=a1',
    'To: <sip:bob@example.net>;tag=b1',
    'Call-ID: tl-1@example.com',
    'CSeq: 1 INVITE',
  ], '');

  const TL_BYE = textlogMsg('BYE sip:bob@example.net SIP/2.0', [
    'Via: SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-3',
    'From: <sip:alice@example.com>;tag=a1',
    'To: <sip:bob@example.net>;tag=b1',
    'Call-ID: tl-1@example.com',
    'CSeq: 2 BYE',
  ], '');

  /**
   * Body text of a parsed packet (everything after the header/body CRLFCRLF).
   * @param {object} pkt packet from parseTextLog
   * @returns {string}
   */
  function bodyOf(pkt) {
    const s = pkt.payload.toString('utf8');
    const at = s.indexOf(CRLF + CRLF);
    return at === -1 ? '' : s.slice(at + 4);
  }

  /**
   * Start line of a parsed packet.
   * @param {object} pkt packet from parseTextLog
   * @returns {string}
   */
  function startOf(pkt) {
    return pkt.payload.toString('utf8').split(CRLF)[0];
  }

  await t('textlog: an over-declared Content-Length no longer swallows every later message', () => {
    const r = tryRequire(path.join('lib', 'textlog.js'));
    if (r.err) throw new Error(r.err);
    const invite = textlogMsg('INVITE sip:bob@example.net SIP/2.0', [
      'Via: SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-1',
      'From: <sip:alice@example.com>;tag=a1',
      'To: <sip:bob@example.net>',
      'Call-ID: tl-1@example.com',
      'CSeq: 1 INVITE',
      'Content-Type: application/sdp',
    ], TL_SDP, 9999);
    const out = r.mod.parseTextLog(invite + TL_OK + TL_BYE);
    // Before the fix this was 1: the 9999 was never satisfied, so the loop ran
    // to end-of-file and ate the 200 OK and the BYE as "body".
    eq(out.packets.length, 3, 'messages parsed');
    eq(startOf(out.packets[1]), 'SIP/2.0 200 OK', 'second message');
    eq(startOf(out.packets[2]), 'BYE sip:bob@example.net SIP/2.0', 'third message');
    // The body that WAS captured is kept whole — the fix bounds it, not trims it.
    eq(bodyOf(out.packets[0]), TL_SDP, 'captured body of the truncated message');
  });

  await t('textlog: a short body is reported as a warning, not silently accepted', () => {
    const r = tryRequire(path.join('lib', 'textlog.js'));
    if (r.err) throw new Error(r.err);
    const invite = textlogMsg('INVITE sip:bob@example.net SIP/2.0', [
      'Call-ID: tl-1@example.com', 'CSeq: 1 INVITE', 'Content-Type: application/sdp',
    ], TL_SDP, 9999);
    const out = r.mod.parseTextLog(invite + TL_OK);
    const hit = out.warnings.filter((w) => /declared Content-Length 9999 exceeds captured body/.test(w));
    eq(hit.length, 1, 'warnings naming the shortfall (got: ' + JSON.stringify(out.warnings) + ')');
    ok(/\(\d+ bytes\)/.test(hit[0]), 'warning does not state how much body was actually captured: ' + hit[0]);
    ok(/^line \d+:/.test(hit[0]), 'warning does not carry the line prefix this module uses: ' + hit[0]);
  });

  await t('textlog: a correctly declared Content-Length still parses byte-exactly', () => {
    const r = tryRequire(path.join('lib', 'textlog.js'));
    if (r.err) throw new Error(r.err);
    // Includes a blank line INSIDE the body: with a declared length that is
    // the thing the old loop got right, and the regression most at risk.
    const body = 'v=0' + CRLF + CRLF + 's=-' + CRLF;
    const invite = textlogMsg('INVITE sip:bob@example.net SIP/2.0', [
      'Call-ID: tl-2@example.com', 'CSeq: 1 INVITE', 'Content-Type: application/sdp',
    ], body);
    const out = r.mod.parseTextLog(invite + TL_OK);
    eq(out.packets.length, 2, 'messages parsed');
    eq(bodyOf(out.packets[0]), body, 'body is not byte-identical');
    eq(out.warnings.length, 0, 'a well-formed message must warn about nothing: ' + JSON.stringify(out.warnings));
    const cl = /Content-Length: (\d+)/.exec(out.packets[0].payload.toString('utf8'));
    eq(cl && cl[1], String(Buffer.byteLength(body)), 'Content-Length header');
  });

  await t('textlog: body text that merely resembles a SIP start line does not split the message', () => {
    const r = tryRequire(path.join('lib', 'textlog.js'));
    if (r.err) throw new Error(r.err);
    const body = [
      'This trace shows INVITE sip:bob@example.com SIP/2.0 arriving late.',
      'SIP/2.0 is the version we speak.',
      'Ref: SIP/2.0 200 OK was expected here',
      'RETRANSMIT INVITE SIP/2.0',
    ].join(CRLF) + CRLF;
    const message = textlogMsg('MESSAGE sip:bob@example.net SIP/2.0', [
      'Call-ID: tl-3@example.com', 'CSeq: 1 MESSAGE', 'Content-Type: text/plain',
    ], body);
    const out = r.mod.parseTextLog(message + TL_OK);
    eq(out.packets.length, 2, 'a body line was mistaken for the next message');
    eq(bodyOf(out.packets[0]), body, 'body was cut short at a false start line');
  });

  await t('textlog: a message/sipfrag body containing a real status line is not split', () => {
    const r = tryRequire(path.join('lib', 'textlog.js'));
    if (r.err) throw new Error(r.err);
    // RFC 3420: the NOTIFY for a REFER carries "SIP/2.0 200 OK" as its whole
    // body. Bounding bodies at start lines must not shred the commonest
    // transfer trace in the product's own problem domain.
    const frag = 'SIP/2.0 200 OK' + CRLF;
    const notify = textlogMsg('NOTIFY sip:alice@example.com SIP/2.0', [
      'Call-ID: tl-4@example.com', 'CSeq: 3 NOTIFY', 'Event: refer',
      'Content-Type: message/sipfrag;version=2.0',
    ], frag);
    const out = r.mod.parseTextLog(notify + TL_OK);
    eq(out.packets.length, 2, 'the sipfrag body was split off as a phantom message');
    eq(bodyOf(out.packets[0]), frag, 'sipfrag body');
  });

  await t('textlog: RFC 4475 start lines (%-escaped method, SIP/7.0, 10-digit status) are recognised', () => {
    const r = tryRequire(path.join('lib', 'textlog.js'));
    if (r.err) throw new Error(r.err);
    const esc = textlogMsg('RE%47IST%45R sip:sip.example.com SIP/2.0',
      ['Call-ID: tl-esc@example.com', 'CSeq: 1 RE%47IST%45R'], '');
    const badvers = textlogMsg('OPTIONS sip:t.example.com SIP/7.0',
      ['Call-ID: tl-badvers@example.com', 'CSeq: 1 OPTIONS'], '');
    const bigcode = textlogMsg('SIP/2.0 4294967296 better not break the receiver',
      ['Call-ID: tl-bigcode@example.com', 'CSeq: 1 OPTIONS'], '');
    const out = r.mod.parseTextLog(esc + badvers + bigcode);
    eq(out.packets.length, 3, 'all three used to be invisible to the parser');
    eq(startOf(out.packets[0]), 'RE%47IST%45R sip:sip.example.com SIP/2.0', 'esc02 method token');
    eq(startOf(out.packets[1]), 'OPTIONS sip:t.example.com SIP/7.0', 'badvers version');
    eq(startOf(out.packets[2]), 'SIP/2.0 4294967296 better not break the receiver', 'bigcode status');
    // sniffText decides whether analyze.js routes the file here at all, so it
    // must agree with the parser about what a start line is.
    ok(r.mod.sniffText(Buffer.from(badvers, 'utf8')), 'sniffText rejected a file the parser can read');
  });

  await t('textlog: uppercase log chatter ending in SIP/2.0 is not mistaken for a request line', () => {
    const r = tryRequire(path.join('lib', 'textlog.js'));
    if (r.err) throw new Error(r.err);
    // The cost of relaxing REQ_LINE: `WORD WORD SIP/2.0` chatter must still be
    // noise. A false start line here would both truncate the message before it
    // and invent one that never existed.
    const chatter = 'RETRANSMIT INVITE SIP/2.0' + CRLF + 'DROP OPTIONS SIP/2.0' + CRLF;
    const out = r.mod.parseTextLog(chatter);
    eq(out.packets.length, 0, 'log chatter was parsed as SIP messages');
    eq(r.mod.sniffText(Buffer.from(chatter, 'utf8')), false, 'sniffText accepted pure chatter as a SIP log');
  });

  console.log('NOTE (wave3): HTTP-route-level behavior — a malformed X-Project-Id header or ?project=' +
    ' filter degrading to a clean 4xx, and a suspended member\'s existing session 401ing on the next ' +
    'request — is NOT exercised by this file. server.js has no module.exports and calls server.listen() ' +
    'unconditionally at module scope, so requiring it here would start a real HTTP listener as a side ' +
    'effect. That needs a subprocess-based HTTP integration test once server.js stabilises; see the report ' +
    'to the integrator for details.');

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
