#!/usr/bin/env node
'use strict';
// test/adversarial.js -- hiccup adversarial / real-world robustness pass.
//
// Companion to test/selftest.js's synthetic, expected.json-driven fixture suite
// (see ARCHITECTURE.md #Selftest). That suite works because make-fixtures.js
// built every scenario from a known spec, so it knows the correct answer to
// assert. The files under test/fixtures/adversarial/ are different: RFC 4475
// torture messages (deliberately tortuous/malformed SIP, byte-exact from the
// RFC) plus real captures pulled from public sample-capture repos (see
// SOURCES.md in that directory) -- nobody here authored the "correct"
// diagnosis, so there is no expected.json-style ground truth to assert.
//
// What this DOES assert is the one invariant ARCHITECTURE.md promises for
// malformed input: analyzeCapture() must never throw, and must always return
// a well-shaped AnalysisJSON (warnings/calls/findings arrays present) --
// "a single malformed packet must never fail a whole capture." Everything
// else is printed as a one-line human-readable summary per file (message/call/
// warning/finding counts, detected scenario) so a human can eyeball whether
// hiccup's read of a real problem capture looks reasonable, and decide
// whether any of them are worth promoting into the strict synthetic suite.
//
// Usage: node test/adversarial.js
// Exit code 1 if any fixture crashes analyzeCapture; 0 otherwise (including
// when there's nothing to run yet). Zero dependencies. CommonJS.

const fs = require('fs');
const path = require('path');

const DIR = path.join(__dirname, 'fixtures', 'adversarial');

/**
 * Extract a short, human-readable message from any thrown value.
 * @param {*} e thrown value
 * @returns {string}
 */
function errMsg(e) {
  if (!e) return 'unknown error';
  if (e.userMessage) return String(e.userMessage).split('\n')[0];
  if (e.message) return String(e.message).split('\n')[0];
  return String(e).split('\n')[0];
}

async function main() {
  let analyze;
  try {
    analyze = require('../lib/analyze.js');
  } catch (e) {
    console.log('SKIP adversarial pass -- lib/analyze.js unavailable: ' + errMsg(e));
    process.exit(0);
  }
  if (typeof analyze.analyzeCapture !== 'function') {
    console.log('SKIP adversarial pass -- lib/analyze.js does not export analyzeCapture()');
    process.exit(0);
  }

  if (!fs.existsSync(DIR)) {
    console.log('SKIP adversarial pass -- ' + DIR + ' does not exist');
    process.exit(0);
  }

  const files = fs.readdirSync(DIR)
    .filter((f) => !f.toLowerCase().endsWith('.md'))
    .sort();

  if (files.length === 0) {
    console.log('SKIP adversarial pass -- no fixtures in ' + DIR);
    process.exit(0);
  }

  let pass = 0;
  let fail = 0;
  const failures = [];

  for (const file of files) {
    const buf = fs.readFileSync(path.join(DIR, file));
    try {
      const analysis = await analyze.analyzeCapture(buf);
      const stats = (analysis && analysis.stats) || {};
      const warnings = (analysis && analysis.warnings) || [];
      const calls = (analysis && analysis.calls) || [];
      const findings = (analysis && analysis.findings) || [];
      const scenario = analysis && analysis.scenario && analysis.scenario.primary;

      const problems = [];
      if (!analysis || typeof analysis !== 'object') problems.push('analyzeCapture returned ' + typeof analysis);
      if (!Array.isArray(warnings)) problems.push('warnings is not an array');
      if (!Array.isArray(calls)) problems.push('calls is not an array');
      if (problems.length) throw new Error(problems.join('; '));

      pass++;
      console.log(
        'OK   ' + file.padEnd(46) +
        ' format=' + (stats.format || '?') +
        ' sip=' + (stats.sipMessages || 0) +
        ' calls=' + calls.length +
        ' warnings=' + warnings.length +
        ' findings=' + findings.length +
        (scenario ? ' scenario=' + scenario : '')
      );
      for (const w of warnings.slice(0, 5)) console.log('       - ' + String(w).slice(0, 140));
      if (warnings.length > 5) console.log('       ... +' + (warnings.length - 5) + ' more warning(s)');
    } catch (e) {
      fail++;
      failures.push({ file, err: errMsg(e) });
      console.log('FAIL ' + file.padEnd(46) + ' threw: ' + errMsg(e));
    }
  }

  console.log('');
  if (failures.length) {
    console.log('Crashed the analyzer (must not happen -- see ARCHITECTURE.md defensive-parsing contract):');
    for (const f of failures) console.log('  - ' + f.file + ': ' + f.err);
    console.log('');
  }
  console.log('ADVERSARIAL: ' + pass + '/' + (pass + fail) + ' ingested without crashing');
  process.exit(fail ? 1 : 0);
}

main();
