'use strict';
// feedback.js — in-app feedback storage, context sanitising and the weekly
// digest. See ARCHITECTURE.md "Wave 6 — In-app feedback with structural
// context", which is the authority for the allow-list below.

const path = require('path');
const crypto = require('crypto');
const store = require('./store');

const MAX_COMMENT = 4000;
const MAX_RECORDS = 5000;          // hard cap; oldest are dropped past this
const KINDS = ['bug', 'idea', 'confusing', 'praise', 'other'];

function dir(dataDir) { return path.join(dataDir, 'feedback'); }
function file(dataDir) { return path.join(dir(dataDir), 'feedback.json'); }
function digestStateFile(dataDir) { return path.join(dir(dataDir), 'digest-state.json'); }

function str(v) { return typeof v === 'string' ? v : ''; }
function num(v) { return typeof v === 'number' && isFinite(v) ? v : null; }
function arr(v) { return Array.isArray(v) ? v : []; }

// ---------------------------------------------------------------- sanitising

/** Bounded, printable string — also strips control chars so nothing odd lands in an email. */
function clean(v, max) {
  return str(v).replace(/[\x00-\x1f\x7f]/g, ' ').trim().slice(0, max || 200);
}

/**
 * Build a fresh context object from KNOWN keys only.
 *
 * This is an ALLOW-LIST on purpose. Anything the client sends that is not
 * named here is dropped silently, so a future UI change cannot widen the
 * privacy boundary by accident — widening it requires editing this function
 * and ARCHITECTURE.md's table, deliberately.
 *
 * Deliberately NOT accepted, though the client could easily supply them and
 * they would genuinely help reproduction: the capture FILENAME (routinely
 * carries customer names) and the current SEARCH TERM (users search by phone
 * number). Also never: raw message text, header values, SDP, numbers, IPs,
 * ports, or capture bytes.
 *
 * @param {any} raw whatever the browser posted
 * @returns {object|null} sanitised context, or null when nothing survived
 */
function sanitizeContext(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const out = {};

  if (raw.page) out.page = clean(raw.page, 120);
  if (raw.appVersion) out.appVersion = clean(raw.appVersion, 40);
  if (raw.theme) out.theme = clean(raw.theme, 20);
  if (raw.userAgent) out.userAgent = clean(raw.userAgent, 300);

  if (raw.viewport && typeof raw.viewport === 'object') {
    const w = num(raw.viewport.w);
    const h = num(raw.viewport.h);
    if (w !== null && h !== null) out.viewport = { w: Math.round(w), h: Math.round(h) };
  }

  if (raw.captureFormat) out.captureFormat = clean(raw.captureFormat, 20);
  if (num(raw.captureBytes) !== null) out.captureBytes = Math.round(raw.captureBytes);

  if (raw.counts && typeof raw.counts === 'object') {
    const counts = {};
    for (const k of ['sip', 'h323', 'calls', 'legs', 'media', 'aux']) {
      const n = num(raw.counts[k]);
      if (n !== null) counts[k] = Math.round(n);
    }
    if (Object.keys(counts).length) out.counts = counts;
  }

  if (raw.scenario && typeof raw.scenario === 'object') {
    const key = clean(raw.scenario.key, 60);
    const conf = num(raw.scenario.confidence);
    if (key || conf !== null) {
      out.scenario = {};
      if (key) out.scenario.key = key;
      if (conf !== null) out.scenario.confidence = conf;
    }
  }

  if (raw.scopeType) out.scopeType = clean(raw.scopeType, 20);

  if (raw.scopeIds && typeof raw.scopeIds === 'object') {
    const ids = {};
    // hiccup-generated ids ("c4", "d4", "s29") — meaningless outside this
    // capture, so they identify nothing about a real person. Tightly bounded
    // anyway so a hostile client cannot smuggle a payload through them.
    for (const k of ['callId', 'legId', 'txKey']) {
      const v = clean(raw.scopeIds[k], 40);
      if (v) ids[k] = v;
    }
    if (Object.keys(ids).length) out.scopeIds = ids;
  }

  if (raw.selectedRow && typeof raw.selectedRow === 'object') {
    const row = {};
    const kind = clean(raw.selectedRow.kind, 20);
    // Method/status are SIP verbs and numbers ("INVITE", 486) — protocol
    // vocabulary, not user content.
    const method = clean(raw.selectedRow.method, 30);
    const status = num(raw.selectedRow.status);
    if (kind) row.kind = kind;
    if (method) row.method = method;
    if (status !== null) row.status = Math.round(status);
    if (Object.keys(row).length) out.selectedRow = row;
  }

  const lamps = arr(raw.lamps)
    .map((l) => (l && typeof l === 'object')
      ? { key: clean(l.key, 40), state: clean(l.state, 20) }
      : null)
    .filter((l) => l && l.key)
    .slice(0, 40);
  if (lamps.length) out.lamps = lamps;

  const ruleIds = arr(raw.adviceRuleIds)
    .map((r) => clean(r, 60))
    .filter(Boolean)
    .slice(0, 40);
  if (ruleIds.length) out.adviceRuleIds = ruleIds;

  return Object.keys(out).length ? out : null;
}

// ------------------------------------------------------------------ storage

function readAll(dataDir) {
  const list = store.loadJson(file(dataDir), []);
  return Array.isArray(list) ? list : [];
}

function writeAll(dataDir, list) {
  store.saveJson(file(dataDir), list.slice(-MAX_RECORDS));
}

/**
 * Persist one submission.
 * @param {string} dataDir
 * @param {{userId:string, email:string, kind:string, rating:any, comment:string, context:any}} input
 * @returns {object} the stored Feedback record
 */
function save(dataDir, input) {
  const comment = str(input && input.comment).trim().slice(0, MAX_COMMENT);
  if (!comment) throw new Error('comment is required');

  const kind = KINDS.indexOf(str(input && input.kind)) !== -1 ? input.kind : 'other';
  let rating = num(input && input.rating);
  if (rating !== null) rating = Math.min(5, Math.max(1, Math.round(rating)));

  const rec = {
    id: 'fb_' + crypto.randomBytes(6).toString('hex'),
    ts: Date.now(),
    userId: str(input && input.userId),      // caller supplies from the session
    email: str(input && input.email),
    kind,
    rating,
    comment,
    context: sanitizeContext(input && input.context),
    read: false,
  };

  const list = readAll(dataDir);
  list.push(rec);
  writeAll(dataDir, list);
  return rec;
}

/**
 * All submissions, newest first.
 *
 * Ties on `ts` are broken by insertion order (records are appended, so a
 * higher index is genuinely newer). Without this, two submissions landing in
 * the same millisecond sort as a no-op and surface OLDEST first — which is
 * both wrong and intermittent, since it depends on where the millisecond
 * boundary happens to fall.
 */
function list(dataDir) {
  return readAll(dataDir)
    .map((rec, i) => ({ rec, i }))
    .sort((a, b) => ((b.rec.ts || 0) - (a.rec.ts || 0)) || (b.i - a.i))
    .map((x) => x.rec);
}

/** Mark one record read/unread. Returns the updated record, or null. */
function setRead(dataDir, id, read) {
  const all = readAll(dataDir);
  const rec = all.find((r) => r && r.id === id);
  if (!rec) return null;
  rec.read = !!read;
  writeAll(dataDir, all);
  return rec;
}

/**
 * Strip the personal data from one record, keeping the observation (GDPR
 * Art. 17). The comment is operationally valuable — "the ladder is confusing"
 * stays true after its author leaves — but who said it is not, so userId and
 * email go and the record is flagged so nobody mistakes it for a live user.
 *
 * @returns {object|null} the anonymised record, or null when not found
 */
function anonymise(dataDir, id) {
  const all = readAll(dataDir);
  const rec = all.find((r) => r && r.id === id);
  if (!rec) return null;
  rec.userId = '';
  rec.email = '';
  rec.anonymisedAt = Date.now();
  writeAll(dataDir, all);
  return rec;
}

/** Submissions in the last `sinceMs` window, newest first. */
function since(dataDir, sinceMs) {
  const cut = Date.now() - sinceMs;
  return list(dataDir).filter((r) => (r.ts || 0) >= cut);
}

// ------------------------------------------------------------------- digest

function esc(s) {
  return str(s).replace(/[&<>"]/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]
  ));
}

/**
 * Build the weekly digest body from a set of records.
 * Returns null when there is nothing to report — the caller then sends
 * nothing at all rather than a cheerful empty email every Monday.
 *
 * @param {Array} records
 * @returns {{subject:string, text:string, html:string}|null}
 */
function buildDigest(records) {
  const recs = arr(records);
  if (!recs.length) return null;

  const byKind = {};
  for (const r of recs) byKind[r.kind] = (byKind[r.kind] || 0) + 1;
  const kindSummary = Object.keys(byKind).sort()
    .map((k) => k + ' ' + byKind[k]).join(' · ');

  const rated = recs.map((r) => num(r.rating)).filter((n) => n !== null);
  const avg = rated.length
    ? (rated.reduce((a, b) => a + b, 0) / rated.length).toFixed(1)
    : null;

  const subject = 'hiccup feedback — ' + recs.length +
    ' this week (' + kindSummary + ')';

  const textLines = [
    subject,
    avg ? ('average rating: ' + avg + '/5 from ' + rated.length) : 'no ratings given',
    '',
  ];
  const htmlParts = [
    '<h2>' + esc(subject) + '</h2>',
    '<p>' + (avg ? ('Average rating <b>' + avg + '/5</b> from ' + rated.length + '.')
      : 'No ratings given.') + '</p>',
  ];

  for (const r of recs) {
    const when = new Date(r.ts || 0).toISOString().replace('T', ' ').slice(0, 16);
    const head = '[' + r.kind + (r.rating ? ' ' + r.rating + '/5' : '') + '] ' +
      when + ' — ' + (r.email || r.userId || 'unknown');
    textLines.push(head, r.comment, '');
    htmlParts.push(
      '<div style="margin:14px 0;padding:10px 12px;border-left:3px solid #f5a623;background:#faf7f2">' +
      '<div style="font:12px/1.4 monospace;color:#666">' + esc(head) + '</div>' +
      '<div style="margin-top:6px;white-space:pre-wrap">' + esc(r.comment) + '</div>'
    );
    if (r.context) {
      const c = r.context;
      const bits = [];
      if (c.page) bits.push(c.page);
      if (c.scenario && c.scenario.key) bits.push('scenario ' + c.scenario.key);
      if (c.counts) bits.push((c.counts.sip || 0) + ' SIP · ' + (c.counts.calls || 0) + ' calls');
      if (c.scopeType) bits.push('scope ' + c.scopeType);
      if (c.selectedRow && c.selectedRow.method) bits.push('on ' + c.selectedRow.method);
      if (bits.length) {
        textLines.push('    context: ' + bits.join(' | '), '');
        htmlParts.push('<div style="margin-top:6px;font:12px/1.4 monospace;color:#888">' +
          esc(bits.join(' | ')) + '</div>');
      }
    }
    htmlParts.push('</div>');
  }

  return { subject, text: textLines.join('\n'), html: htmlParts.join('\n') };
}

// ------------------------------------------------------- digest scheduling

/** ISO-8601 week stamp, e.g. "2026-W34" — the unit the digest dedupes on. */
function isoWeek(d) {
  const t = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  // Thursday of the current week decides the year, per ISO-8601.
  t.setUTCDate(t.getUTCDate() + 4 - (t.getUTCDay() || 7));
  const yearStart = new Date(Date.UTC(t.getUTCFullYear(), 0, 1));
  const week = Math.ceil((((t - yearStart) / 86400000) + 1) / 7);
  return t.getUTCFullYear() + '-W' + String(week).padStart(2, '0');
}

function getDigestState(dataDir) {
  const s = store.loadJson(digestStateFile(dataDir), {});
  return (s && typeof s === 'object') ? s : {};
}

function setDigestSent(dataDir, week) {
  store.saveJson(digestStateFile(dataDir), { lastSentWeek: week, lastSentTs: Date.now() });
}

/**
 * Should the weekly digest fire right now?
 *
 * True from Monday 09:00 local onwards, once per ISO week. Phrased as
 * "this week's digest has not gone yet" rather than "it is exactly Monday
 * 09:00" on purpose: the box is a home-lab machine that reboots for Windows
 * updates, so a digest whose moment passed while the service was down must
 * still go when it comes back. Equally, a mid-week restart must not re-send.
 *
 * @param {string} dataDir
 * @param {Date} [now]
 */
function digestDue(dataDir, now) {
  const d = now || new Date();
  const week = isoWeek(d);
  if (getDigestState(dataDir).lastSentWeek === week) return false;
  const day = d.getDay();                    // 0 Sun, 1 Mon
  if (day === 0) return false;               // Sunday belongs to the week just ending
  if (day === 1 && d.getHours() < 9) return false;
  return true;
}

module.exports = {
  save, list, setRead, since, anonymise,
  sanitizeContext, buildDigest,
  digestDue, isoWeek, getDigestState, setDigestSent,
  KINDS, MAX_COMMENT,
};
