'use strict';
/**
 * lib/metrics.js — the numbers a solo operator actually needs.
 *
 * Two consumers share this file on purpose: bin/traffic.js (the CLI) and
 * server.js's /api/admin/status (the dashboard). If the bot heuristic lived in
 * both, the CLI and the admin page would quietly report different numbers for
 * the same day and there would be no way to tell which was right.
 *
 * HONESTY RULES, because a vanity dashboard is worse than no dashboard:
 *
 *   1. A hit counts as automated only when the user-agent SAYS it is a bot, or
 *      the path is a known vulnerability probe. Everything ambiguous counts as
 *      human, so the "people" number is an over-estimate, never a flattering
 *      guess dressed up as a measurement.
 *   2. The CSS ratio is published next to it as the corrective. A real browser
 *      always fetches the stylesheet, so a page-view count with a low CSS ratio
 *      is mostly crawlers that did not render. That ratio is the number to
 *      trust, and hiding it would make the page views a lie.
 *   3. Anything that cannot be computed honestly is reported as null and
 *      rendered as "—", never as a zero. Zero and unknown are different facts.
 *
 * Zero dependencies. CommonJS.
 */

const fs = require('fs');
const path = require('path');

// "<iso> <ip> <METHOD> <path> <status> <ms>ms "<ua>"" -- the format server.js
// has written since v0.3.2. Older lines have no timestamp and are skipped.
const LINE = /^(\S+) (\S+) ([A-Z]+) (\S+) (\d{3}) (\d+)ms(?: "(.*)")?$/;
const BOT_UA = /bot|crawler|spider|slurp|bingpreview|headless|curl|wget|python-requests|go-http|scrapy|masscan|zgrab|nmap|healthcheck/i;
const PROBE = /wp-admin|wp-login|xmlrpc|\.env|phpmyadmin|\.git\/|admin\.php|autodiscover|\.aws|cgi-bin|\.php$|\/shell|vendor\/phpunit/i;
const ASSET = /\.(css|js|png|jpg|jpeg|svg|ico|webmanifest|woff2?|xml|txt)$/i;

/** Read at most `maxBytes` from the END of a file, on a line boundary. */
function tailFile(file, maxBytes) {
  const st = fs.statSync(file);
  if (st.size <= maxBytes) return fs.readFileSync(file, 'utf8');
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.alloc(maxBytes);
    fs.readSync(fd, buf, 0, maxBytes, st.size - maxBytes);
    const s = buf.toString('utf8');
    return s.slice(s.indexOf('\n') + 1);   // drop the partial first line
  } finally {
    fs.closeSync(fd);
  }
}

/** Per-file read cap. Keeps /admin/status cheap however big the logs get. */
const MAX_BYTES_PER_LOG = 2 * 1024 * 1024;

/**
 * Parse the access logs into traffic counters.
 * @param {string} logDir usually <dataDir>/logs
 * @param {number} days window, counted back from now
 * @returns {object} counters, or nulls when there is nothing parseable
 */
function readAccessLogs(logDir, days) {
  const out = {
    windowDays: days,
    requests: 0, bot: 0, human: 0, probes: 0,
    pageViews: 0, cssHits: 0,
    networks: 0, botNetworks: 0,
    legacyLines: 0,
    // Declared up front so the SHAPE is identical whether or not any logs
    // exist. The early return for a missing log directory used to skip the
    // block that sets these, so callers saw a different object depending on
    // deployment state -- which is exactly the kind of thing a consumer
    // discovers at runtime rather than in review.
    botShare: null, cssRatio: null,
    byDay: {}, topPaths: [],
    signals: [],
  };
  let files = [];
  try {
    files = fs.readdirSync(logDir)
      .filter((n) => n.endsWith('.log'))
      .map((n) => path.join(logDir, n));
  } catch {
    return Object.assign(out, { available: false });
  }
  out.available = true;

  const cutoffMs = Date.now() - days * 86400000;
  const nets = new Set(), botNets = new Set(), paths = new Map();

  for (const f of files) {
    let st;
    try { st = fs.statSync(f); } catch { continue; }
    // A file untouched since before the window cannot contain a line inside it.
    if (st.mtimeMs < cutoffMs) continue;
    let text;
    try { text = tailFile(f, MAX_BYTES_PER_LOG); } catch { continue; }

    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line) continue;
      const m = LINE.exec(line);
      if (!m) { if (/^[A-Z]+ \//.test(line)) out.legacyLines++; continue; }
      const [, iso, ip, , p, , , ua] = m;
      const t = Date.parse(iso);
      if (!Number.isFinite(t) || t < cutoffMs) continue;
      out.requests++;

      const isProbe = PROBE.test(p);
      const isBot = isProbe || BOT_UA.test(ua || '');
      if (isProbe) out.probes++;
      if (isBot) { out.bot++; if (ip !== '-') botNets.add(ip); continue; }

      out.human++;
      if (ip !== '-') nets.add(ip);
      const day = iso.slice(0, 10);
      out.byDay[day] = (out.byDay[day] || 0) + 1;
      if (/\.css$/i.test(p)) out.cssHits++;
      if (!ASSET.test(p)) {
        out.pageViews++;
        const clean = p.split('?')[0];
        paths.set(clean, (paths.get(clean) || 0) + 1);
      }
    }
  }

  out.networks = nets.size;
  out.botNetworks = botNets.size;
  out.topPaths = [...paths.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8)
    .map(([p, n]) => ({ path: p, views: n }));
  out.botShare = out.requests ? Math.round((100 * out.bot) / out.requests) : null;
  // The corrective metric. A real browser always pulls the stylesheet, so this
  // is what says whether "page views" means people or crawlers that did not
  // render. Null rather than 0 when there is nothing to divide.
  out.cssRatio = out.pageViews ? Math.round((100 * out.cssHits) / out.pageViews) : null;
  if (out.cssRatio !== null && out.cssRatio < 40 && out.pageViews >= 20) {
    out.signals.push('Low CSS ratio (' + out.cssRatio + '%): most counted page views never rendered.');
  }
  return out;
}

/** Count captures per storage account, and how many are recent. */
function captureStats(dataDir, sinceMs) {
  const root = path.join(dataDir, 'captures');
  const out = { accounts: 0, total: 0, recent: 0, withCaptures: new Set() };
  let accounts = [];
  try { accounts = fs.readdirSync(root); } catch { return out; }
  out.accounts = accounts.length;
  for (const a of accounts) {
    let ids = [];
    try { ids = fs.readdirSync(path.join(root, a)); } catch { continue; }
    if (ids.length) out.withCaptures.add(a);
    out.total += ids.length;
    for (const id of ids) {
      try {
        const st = fs.statSync(path.join(root, a, id));
        if (st.mtimeMs >= sinceMs) out.recent++;
      } catch { /* skip */ }
    }
  }
  return out;
}

/**
 * The business-side KPIs: who signed up, who actually used it, who paid.
 *
 * ACTIVATION is the one worth staring at. Signups are easy and meaningless on
 * their own; the question that decides whether hiccup works is whether someone
 * who registered ever uploaded a single trace. For a team member the storage
 * account is the team's shared root, so accountUidFor maps a user to the id
 * their captures actually live under -- counting raw user ids would under-report
 * every team member as inactive.
 *
 * @param {object} opts {dataDir, users, accountUidFor, teamCount, days}
 */
function productKpis(opts) {
  const o = opts || {};
  const users = Array.isArray(o.users) ? o.users : [];
  const days = o.days || 7;
  const now = Date.now();
  const since = now - days * 86400000;
  const since30 = now - 30 * 86400000;

  const caps = captureStats(o.dataDir, since);
  const uidFor = typeof o.accountUidFor === 'function' ? o.accountUidFor : ((id) => id);

  let activated = 0;
  for (const u of users) {
    let uid = u.id;
    try { uid = uidFor(u.id) || u.id; } catch { /* fall back to own id */ }
    if (caps.withCaptures.has(uid)) activated++;
  }

  const paid = users.filter((u) => u.plan === 'paid').length;
  const signups7 = users.filter((u) => Date.parse(u.createdAt || '') >= since).length;
  const signups30 = users.filter((u) => Date.parse(u.createdAt || '') >= since30).length;
  const active7 = users.filter((u) => Date.parse(u.lastLoginAt || '') >= since).length;

  const pct = (n, d) => (d ? Math.round((100 * n) / d) : null);
  const signals = [];
  if (users.length >= 5 && pct(activated, users.length) !== null && pct(activated, users.length) < 40) {
    signals.push('Activation is ' + pct(activated, users.length) + '%: most people who sign up never upload a trace.');
  }

  return {
    users: {
      total: users.length,
      signups7d: signups7,
      signups30d: signups30,
      activeLast7d: active7,
    },
    activation: {
      // "Signed up AND uploaded at least one capture" -- the only engagement
      // fact this app can honestly measure.
      uploaded: activated,
      rate: pct(activated, users.length),
    },
    paid: {
      accounts: paid,
      conversionRate: pct(paid, users.length),
      // Deliberately no MRR: the user record stores plan:'paid' but not which
      // interval was bought, so any revenue figure here would be invented.
      // Splitting it needs the price id stored at checkout.
      mrrNote: 'interval not stored per account; see Stripe for revenue',
    },
    teams: { total: o.teamCount == null ? null : o.teamCount },
    captures: { total: caps.total, last7d: caps.recent, accounts: caps.accounts },
    signals,
  };
}

module.exports = { readAccessLogs, productKpis, captureStats };
