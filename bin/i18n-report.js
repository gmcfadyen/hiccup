#!/usr/bin/env node
// bin/i18n-report.js — run the nightly refresh by hand.
//
//   node bin/i18n-report.js            respects the once-a-day marker
//   node bin/i18n-report.js --force    runs regardless (what you want when testing)
//
// Same code path the server's midnight timer takes, so a manual run is a real
// rehearsal of the scheduled one rather than a lookalike.
'use strict';

const path = require('path');
const i18n = require('../lib/i18n');

const DATA_DIR = process.env.HICCUP_DATA_DIR || path.join(__dirname, '..', 'data');
const force = process.argv.indexOf('--force') !== -1;

const out = i18n.refreshIfDue(DATA_DIR, { force });
if (!out.ran) {
  console.log('i18n refresh: skipped (' + out.skipped + ') — use --force to run anyway');
  process.exit(0);
}
for (const line of out.lines) console.log('i18n refresh: ' + line);
console.log('i18n refresh: report written to ' + i18n.reportFile(DATA_DIR));

for (const lang of i18n.TARGET_LANGS) {
  const miss = out.report.languages[lang].missing;
  if (!miss.length) continue;
  console.log('\n--- ' + lang + ': ' + miss.length + ' string(s) needing translation ---');
  for (const m of miss.slice(0, 40)) console.log('  ' + m.where[0] + '  ' + JSON.stringify(m.text));
  if (miss.length > 40) console.log('  … and ' + (miss.length - 40) + ' more (see the report)');
}
