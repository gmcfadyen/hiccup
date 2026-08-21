#!/usr/bin/env node
'use strict';
/*
 * bin/traffic.js — summarise hiccup's access log.
 *
 * The parsing and the bot heuristic live in lib/metrics.js, which
 * /api/admin/status uses too. That is deliberate: when the CLI owned its own
 * copy, the same day's traffic could be classified differently here and on the
 * dashboard, with nothing to say which was right.
 *
 * Usage:  npm run traffic
 *         node bin/traffic.js --days 30
 */

const path = require('path');
const metrics = require('../lib/metrics');

const args = process.argv.slice(2);
let days = 7;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--days') days = parseInt(args[++i], 10) || 7;
}

const dataDir = process.env.HICCUP_DATA_DIR
  ? path.resolve(process.env.HICCUP_DATA_DIR)
  : path.join(__dirname, '..', 'data');

const t = metrics.readAccessLogs(path.join(dataDir, 'logs'), days);

if (!t.available) {
  console.error('no logs directory under ' + dataDir);
  process.exit(1);
}

console.log('hiccup traffic - last ' + days + ' day(s)');
if (t.legacyLines) {
  console.log('  (' + t.legacyLines + ' older lines skipped: written before the log carried a timestamp)');
}
if (!t.requests) { console.log('  no requests in this window'); process.exit(0); }

console.log('');
console.log('  requests            ' + t.requests);
console.log('  automated           ' + t.bot + '  (' + t.botShare + '%)  of which ' + t.probes + ' vulnerability probes');
console.log('  not obviously bots  ' + t.human + '  (' + (100 - t.botShare) + '%)');
console.log('  distinct networks   ' + t.networks + ' non-bot, ' + t.botNetworks + ' bot');
console.log('');
console.log('  page views (non-bot, non-asset)  ' + t.pageViews);
console.log('  stylesheet fetches               ' + t.cssHits);
if (t.cssRatio !== null) {
  console.log('  -> ' + t.cssRatio + '% of page views also pulled CSS.');
  console.log('     A real browser always does. A low number means most of what is');
  console.log('     counted above as "not obviously bots" still never rendered.');
}

const days_ = Object.entries(t.byDay).sort();
if (days_.length) {
  console.log('');
  console.log('  non-bot requests per day');
  for (const [d, n] of days_) {
    console.log('    ' + d + '  ' + String(n).padStart(5) + '  ' + '#'.repeat(Math.min(50, Math.ceil(n / 5))));
  }
}

if (t.topPaths.length) {
  console.log('');
  console.log('  most-viewed pages (non-bot)');
  for (const p of t.topPaths) console.log('    ' + String(p.views).padStart(5) + '  ' + p.path);
}

for (const s of t.signals) console.log('\n  ! ' + s);
