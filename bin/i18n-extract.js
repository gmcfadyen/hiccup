#!/usr/bin/env node
// bin/i18n-extract.js — rebuild locales/en.json from the working tree.
//
// Run after touching any UI string:  npm run i18n
//
// The output is the English INVENTORY, not a translation file: hash -> the
// source text, which category it came from, and where it lives. Every other
// locale file is checked against it, and the nightly refresh diffs against it.
// Nothing here is hand-edited — edit the HTML or the _t() call instead and
// re-run, which is the point of keying on the source string.
'use strict';

const fs = require('fs');
const path = require('path');
const i18n = require('../lib/i18n');

const inv = i18n.buildInventory();

// A collision would silently serve one string's translation for another's, and
// unlike a miss that failure is invisible. 64-bit over ~1k strings makes it
// vanishingly unlikely — checking makes it impossible.
const seen = new Map();
for (const key of inv.order) {
  const text = inv.strings[key].text;
  if (seen.has(key) && seen.get(key) !== text) {
    console.error('hash collision on ' + key + ':\n  ' + seen.get(key) + '\n  ' + text);
    process.exit(1);
  }
  seen.set(key, text);
}

const byCat = {};
const out = {};
for (const key of inv.order) {
  const e = inv.strings[key];
  byCat[e.cat] = (byCat[e.cat] || 0) + 1;
  out[key] = { text: e.text, cat: e.cat, where: e.where };
}

fs.mkdirSync(i18n.LOCALES_DIR, { recursive: true });
fs.writeFileSync(i18n.inventoryFile(), JSON.stringify(out, null, 2) + '\n');

// Seed any missing translation file so a new language starts as a reviewable
// English-to-English list rather than an empty object nobody can diff.
for (const lang of i18n.TARGET_LANGS) {
  const file = i18n.translationsFile(lang);
  if (!fs.existsSync(file)) fs.writeFileSync(file, '{}\n');
}

console.log('i18n: ' + inv.order.length + ' source strings -> ' +
  path.relative(process.cwd(), i18n.inventoryFile()));
console.log('i18n: by category ' + JSON.stringify(byCat));
for (const line of i18n.summaryLines(i18n.audit(inv))) console.log('i18n: ' + line);
