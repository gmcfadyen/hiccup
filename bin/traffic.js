#!/usr/bin/env node
'use strict';
/*
 * bin/traffic.js — summarise hiccup's access log.
 *
 * The log had no timestamp, no caller and no user-agent until v0.3.2, which
 * meant the only questions anyone asks of an access log -- is traffic growing,
 * and is this people or scanners -- could not be answered at all. It now has
 * all three, and this turns those lines back into an answer.
 *
 * Bot classification is deliberately conservative and stated rather than
 * hidden: a hit counts as automated if the user-agent self-identifies as a
 * bot/crawler/spider, OR the path is a known vulnerability probe. Anything
 * else counts as a browser, so the "people" number is an OVER-estimate, not a
 * flattering one. The second signal below is the honest one: a real browser
 * always pulls the stylesheet, so page-views-without-assets is the giveaway.
 *
 * Usage:  node bin/traffic.js [logfile ...]        (defaults to data/logs/*.log)
 *         node bin/traffic.js --days 7
 */

const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
let days = 0;
const files = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--days') { days = parseInt(args[++i], 10) || 0; continue; }
  files.push(args[i]);
}

if (!files.length) {
  const dir = path.join(__dirname, '..', 'data', 'logs');
  if (!fs.existsSync(dir)) { console.error('no data/logs directory; pass a file path'); process.exit(1); }
  for (const n of fs.readdirSync(dir)) if (n.endsWith('.log')) files.push(path.join(dir, n));
}

// "<iso> <ip> <METHOD> <path> <status> <ms>ms "<ua>""
const LINE = /^(\S+) (\S+) ([A-Z]+) (\S+) (\d{3}) (\d+)ms(?: "(.*)")?$/;
const BOT_UA = /bot|crawler|spider|slurp|bingpreview|headless|curl|wget|python-requests|go-http|scrapy|masscan|zgrab|nmap/i;
const PROBE = /wp-admin|wp-login|xmlrpc|\.env|phpmyadmin|\.git\/|admin\.php|autodiscover|\.aws|cgi-bin|\.php$|\/shell|vendor\/phpunit/i;
const ASSET = /\.(css|js|png|jpg|jpeg|svg|ico|webmanifest|woff2?)$/i;

const cutoff = days ? Date.now() - days * 86400000 : 0;
const stat = {
  total: 0, legacy: 0, botHits: 0, humanHits: 0,
  pageViews: 0, cssHits: 0, probes: 0,
  byDay: new Map(), nets: new Set(), botNets: new Set(),
  paths: new Map(), uas: new Map(), statuses: new Map(),
};

for (const f of files) {
  let text;
  try { text = fs.readFileSync(f, 'utf8'); } catch { continue; }
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const m = LINE.exec(line);
    if (!m) { if (/^[A-Z]+ \//.test(line)) stat.legacy++; continue; }
    const [, iso, ip, method, p, status, , ua] = m;
    const t = Date.parse(iso);
    if (cutoff && !(t >= cutoff)) continue;
    stat.total++;

    const isProbe = PROBE.test(p);
    const isBot = isProbe || BOT_UA.test(ua || '');
    if (isProbe) stat.probes++;
    if (isBot) { stat.botHits++; if (ip !== '-') stat.botNets.add(ip); }
    else {
      stat.humanHits++;
      if (ip !== '-') stat.nets.add(ip);
      const day = iso.slice(0, 10);
      stat.byDay.set(day, (stat.byDay.get(day) || 0) + 1);
      if (!ASSET.test(p)) {
        stat.pageViews++;
        stat.paths.set(p, (stat.paths.get(p) || 0) + 1);
      }
      if (/\.css$/i.test(p)) stat.cssHits++;
      if (ua) stat.uas.set(ua, (stat.uas.get(ua) || 0) + 1);
    }
    stat.statuses.set(status, (stat.statuses.get(status) || 0) + 1);
  }
}

const pct = (n, d) => (d ? Math.round((100 * n) / d) : 0);
const top = (map, n) => [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);

console.log('hiccup traffic — ' + files.length + ' log file(s)' + (days ? ', last ' + days + ' day(s)' : ''));
if (stat.legacy) {
  console.log('  (' + stat.legacy + ' older lines skipped: written before the log carried a timestamp)');
}
if (!stat.total) { console.log('  no parseable lines'); process.exit(0); }

console.log('');
console.log('  requests            ' + stat.total);
console.log('  automated           ' + stat.botHits + '  (' + pct(stat.botHits, stat.total) + '%)  of which ' + stat.probes + ' vulnerability probes');
console.log('  not obviously bots  ' + stat.humanHits + '  (' + pct(stat.humanHits, stat.total) + '%)');
console.log('  distinct networks   ' + stat.nets.size + ' non-bot, ' + stat.botNets.size + ' bot');
console.log('');
console.log('  page views (non-bot, non-asset)  ' + stat.pageViews);
console.log('  stylesheet fetches               ' + stat.cssHits);
if (stat.pageViews) {
  const ratio = pct(stat.cssHits, stat.pageViews);
  console.log('  -> ' + ratio + '% of page views also pulled CSS.');
  console.log('     A real browser always does. A low number means most of what is');
  console.log('     counted above as "not obviously bots" still never rendered.');
}

if (stat.byDay.size) {
  console.log('');
  console.log('  non-bot requests per day');
  for (const [d, n] of [...stat.byDay.entries()].sort()) {
    console.log('    ' + d + '  ' + String(n).padStart(5) + '  ' + '#'.repeat(Math.min(50, Math.ceil(n / 5))));
  }
}

const paths = top(stat.paths, 8);
if (paths.length) {
  console.log('');
  console.log('  most-viewed pages (non-bot)');
  for (const [p, n] of paths) console.log('    ' + String(n).padStart(5) + '  ' + p);
}

const uas = top(stat.uas, 5);
if (uas.length) {
  console.log('');
  console.log('  top non-bot user-agents');
  for (const [u, n] of uas) console.log('    ' + String(n).padStart(5) + '  ' + u.slice(0, 78));
}
