'use strict';
// retention.js — storage limitation (GDPR Art. 5(1)(e)).
//
// config.captureRetentionDays says how long an uploaded capture may live.
// This module is what actually enforces it; without it the setting is a
// statement of intent rather than a control.
//
// Scheduling mirrors lib/feedback.js's digestDue(): a persisted marker plus a
// "has today's sweep run yet?" question, rather than setInterval(24h). On a
// box that reboots for Windows updates a bare interval drifts on every restart
// and can skip a day entirely; asking whether today's sweep has happened
// survives any restart pattern.

const fs = require('fs');
const path = require('path');
const store = require('./store');

const DAY_MS = 24 * 3600 * 1000;

function dir(dataDir) { return path.join(dataDir, 'retention'); }
function stateFile(dataDir) { return path.join(dir(dataDir), 'state.json'); }

/** Local calendar day, e.g. "2026-08-18" — the unit the sweep dedupes on. */
function today(now) {
  const d = now || new Date();
  const p2 = (n) => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + p2(d.getMonth() + 1) + '-' + p2(d.getDate());
}

function getState(dataDir) {
  const s = store.loadJson(stateFile(dataDir), {});
  return (s && typeof s === 'object') ? s : {};
}

function setSwept(dataDir, day, removed) {
  store.saveJson(stateFile(dataDir), {
    lastSweptDay: day,
    lastSweptTs: Date.now(),
    lastRemoved: removed,
  });
}

/**
 * Has today's sweep already run?
 *
 * Phrased as "not yet today" rather than "it is exactly 03:00" on purpose —
 * see the note at the top about restarts. Being a day late is fine; skipping a
 * day silently is not.
 *
 * @param {string} dataDir
 * @param {Date} [now]
 */
function sweepDue(dataDir, now) {
  return getState(dataDir).lastSweptDay !== today(now);
}

/**
 * Every account id that owns captures. Read off the filesystem rather than the
 * user list because a TEAM's shared library is stored under the team's
 * accountUid, which is not a user id at all — walking users would miss it.
 */
function accountIds(dataDir) {
  try {
    return fs.readdirSync(store.capturesRoot(dataDir), { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name);
  } catch {
    return [];
  }
}

/** Age of a capture in ms, from its recorded upload time. */
function ageOf(meta) {
  const t = Date.parse((meta && meta.uploadedAt) || '');
  return Number.isFinite(t) ? (Date.now() - t) : null;
}

/**
 * Delete captures older than `days`.
 *
 * @param {string} dataDir
 * @param {number} days 0 or less disables the sweep entirely
 * @param {{dry?:boolean}} [opts] dry:true reports what WOULD go, deletes nothing
 * @returns {{enabled:boolean, removed:number, kept:number, accounts:number,
 *            skippedUndated:number, items:Array}}
 */
function sweep(dataDir, days, opts) {
  const o = opts || {};
  const n = Number(days);
  if (!Number.isFinite(n) || n <= 0) {
    return { enabled: false, removed: 0, kept: 0, accounts: 0, skippedUndated: 0, items: [] };
  }

  const out = { enabled: true, removed: 0, kept: 0, accounts: 0, skippedUndated: 0, items: [] };

  for (const uid of accountIds(dataDir)) {
    out.accounts++;
    let caps;
    try { caps = store.listCaptures(dataDir, uid); } catch { continue; }
    for (const meta of caps) {
      if (!meta || !meta.id) continue;
      const age = ageOf(meta);
      if (age === null) {
        // No parseable uploadedAt. Deleting on a guess is worse than keeping:
        // retention is about not holding data too long, not about deleting
        // something whose age is unknown.
        out.skippedUndated++;
        continue;
      }
      // Compare WHOLE DAYS, not raw milliseconds. A capture uploaded exactly
      // `n` days ago is `n` days and a few ms old by the time the sweep runs,
      // so a strict `age > n * DAY` deletes it on the very day the user would
      // say it is still within the window. Flooring to whole days means "keep
      // for 30 days" deletes on day 31, which is what people mean — and when
      // this is wrong it errs toward keeping data, which is the safe side for
      // an irreversible delete.
      const ageDays = Math.floor(age / DAY_MS);
      if (ageDays <= n) { out.kept++; continue; }
      if (!o.dry) {
        try {
          if (!store.deleteCapture(dataDir, uid, meta.id)) continue;
        } catch { continue; }
      }
      out.removed++;
      if (out.items.length < 200) {
        out.items.push({
          accountId: uid,
          id: meta.id,
          filename: meta.filename || '',
          uploadedAt: meta.uploadedAt || null,
          ageDays,
        });
      }
    }
  }
  return out;
}

/**
 * Run the sweep if it has not run today. Stamps the day even when nothing was
 * removed, so a quiet box does not re-scan every poll.
 *
 * @param {string} dataDir
 * @param {number} days
 * @param {{force?:boolean, dry?:boolean, now?:Date}} [opts]
 */
function sweepIfDue(dataDir, days, opts) {
  const o = opts || {};
  const n = Number(days);
  if (!Number.isFinite(n) || n <= 0) return { enabled: false, skipped: 'disabled' };
  if (!o.force && !sweepDue(dataDir, o.now)) return { enabled: true, skipped: 'already swept today' };
  const result = sweep(dataDir, n, { dry: !!o.dry });
  if (!o.dry) setSwept(dataDir, today(o.now), result.removed);
  return result;
}

module.exports = { sweep, sweepIfDue, sweepDue, today, getState, setSwept };
