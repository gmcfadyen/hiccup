'use strict';
// drain.js — "is anyone using the site right now?", and a restart that waits
// until the answer is no.
//
// WHY
//
// The /admin/status restart button exits the process so NSSM relaunches it on
// new code. That is fine at 3am and rude at 11am: it drops whatever is in
// flight. The expensive cases are not page loads — they are a 50 MB pcap
// being analysed synchronously inside its own request, and a chat answer
// mid-agent-loop (up to 150s of model calls). Killing either loses real work
// the user cannot cheaply redo.
//
// HOW BUSY IS MEASURED — in-flight work, never "recent activity"
//
// A timestamp-based idle check cannot work here: public/app.js polls
// /api/status every 60s from EVERY open workbench tab, so "no requests in the
// last minute" is never true while one tab sits open on a desk. So busyness
// is the set of requests actually being served right now, plus the LLM
// queue, minus traffic that is not a person doing something:
//
//   - the gavbot2 health check (hits / every ~2 minutes, forever)
//   - GET /api/status (that same background poller, and the restart waiter)
//   - /api/admin/server/control (the drain's own status polling)
//
// Everything else counts. Static assets count on purpose: a page load in
// progress IS someone using the site.
//
// THE DEADLINE, AND WHY IT IS TWO-TIER
//
// Waiting forever means the deploy never lands and the admin has walked away.
// Restarting anyway at the deadline defeats the point if a capture is being
// analysed at that exact moment. So: at the deadline restart IF only light
// work is in flight, and if something heavy is running extend to a hard cap
// and then go regardless. Bounded either way, and the destructive case is the
// one that gets the extra grace.
//
// Zero dependencies. The clock and the LLM-status probe are injectable, so
// the whole state machine is testable with no server and no waiting.

const DEFAULTS = {
  quietMs: 5000,        // continuous idle needed before firing (settles a page load)
  maxWaitMs: 300000,    // 5 min: give up waiting, restart if only light work
  heavyGraceMs: 300000, // +5 min more, but only while heavy work is in flight
  tickMs: 1000,
};

/** Requests that are background noise rather than a person using the site. */
function isIgnorable(info) {
  if (!info) return true;
  const ua = String(info.ua || '');
  if (/healthcheck/i.test(ua)) return true;
  const p = String(info.path || '');
  if (p === '/api/status') return true;
  if (p === '/api/admin/server/control') return true;
  return false;
}

/**
 * Work that must not be interrupted: it is long, and losing it costs the user
 * something they cannot cheaply redo. Capture upload runs the whole analysis
 * synchronously inside the request; chat can be a multi-call agent loop; KB
 * ingest parses PDFs.
 */
function isHeavy(info) {
  if (!info) return false;
  const m = String(info.method || '').toUpperCase();
  const p = String(info.path || '');
  if (m !== 'POST') return false;
  return p === '/api/captures' || p === '/api/chat' || p === '/api/kb/docs' ||
    p === '/api/kb/link';
}

/** A short human label for one in-flight request. */
function labelFor(info) {
  const m = String(info.method || '?').toUpperCase();
  const p = String(info.path || '?');
  if (m === 'POST' && p === '/api/captures') return 'a capture being analysed';
  if (m === 'POST' && p === '/api/chat') return 'a chat answer';
  if (m === 'POST' && (p === '/api/kb/docs' || p === '/api/kb/link')) return 'a guide being ingested';
  return m + ' ' + p;
}

function createDrain(opts) {
  const o = opts || {};
  const now = typeof o.now === 'function' ? o.now : () => Date.now();
  const llmStatus = typeof o.llmStatus === 'function' ? o.llmStatus : () => null;
  const setTimer = typeof o.setTimer === 'function' ? o.setTimer : ((fn, ms) => setTimeout(fn, ms));
  const clearTimer = typeof o.clearTimer === 'function' ? o.clearTimer : ((h) => clearTimeout(h));

  const inFlight = new Map();
  let nextId = 1;
  let pending = null;   // the in-progress drain, or null
  let timer = null;

  /** Record the start of a request. Returns an id, or null when ignorable. */
  function beginRequest(info) {
    if (isIgnorable(info)) return null;
    const id = nextId++;
    inFlight.set(id, {
      method: String((info && info.method) || '?'),
      path: String((info && info.path) || '?'),
      heavy: isHeavy(info),
      startedAt: now(),
    });
    return id;
  }

  function endRequest(id) {
    if (id != null) inFlight.delete(id);
  }

  /** What is happening right now. */
  function snapshot() {
    let heavy = 0;
    let light = 0;
    const items = [];
    for (const rec of inFlight.values()) {
      if (rec.heavy) heavy++; else light++;
      if (items.length < 8) {
        items.push({ label: labelFor(rec), heavy: rec.heavy, ms: now() - rec.startedAt });
      }
    }
    let llmJobs = 0;
    try {
      const s = llmStatus();
      if (s && s.queue) llmJobs = (Number(s.queue.active) || 0) + (Number(s.queue.depth) || 0);
    } catch (e) { llmJobs = 0; }
    return {
      busy: heavy + light + llmJobs > 0,
      heavy, light, llmJobs, items,
      // The LLM queue is heavy work too — a queued chat answer is exactly the
      // thing the grace period exists to protect.
      heavyBusy: heavy + llmJobs > 0,
    };
  }

  function stopTimer() {
    if (timer != null) { try { clearTimer(timer); } catch (e) { /* already gone */ } timer = null; }
  }

  /** One evaluation of the drain state machine. */
  function tick() {
    timer = null;
    if (!pending) return;
    const t = now();
    const snap = snapshot();
    pending.lastSnapshot = snap;

    const idleNow = !snap.busy;
    if (idleNow) {
      if (pending.idleSince == null) pending.idleSince = t;
    } else {
      pending.idleSince = null;
    }
    const pastDeadline = t >= pending.deadline;

    // Genuinely idle is always reported as 'idle', deadline or not — the
    // settle window exists to avoid restarting between two requests of one
    // page load, and once we have stopped being patient there is nothing
    // left to settle for. Reserving 'deadline' for "gave up despite traffic"
    // keeps the log line honest about which of the two actually happened.
    if (idleNow && (pastDeadline || t - pending.idleSince >= pending.quietMs)) {
      return fire('idle');
    }

    if (pastDeadline) {
      if (!snap.heavyBusy) return fire('deadline');
      if (t >= pending.hardDeadline) return fire('deadline-forced');
    }
    arm();
  }

  function arm() {
    stopTimer();
    timer = setTimer(tick, pending ? pending.tickMs : DEFAULTS.tickMs);
    if (timer && typeof timer.unref === 'function') timer.unref();
  }

  function fire(reason) {
    const p = pending;
    stopTimer();
    if (!p) return;
    pending = null;
    p.firedReason = reason;
    try { p.onRestart(reason, p.lastSnapshot || snapshot()); }
    catch (e) { /* the caller's problem; the drain is done either way */ }
  }

  /**
   * Ask for a restart once the site is idle.
   *
   * @param {object} req
   * @param {Function} req.onRestart (reason, snapshot) — called exactly once
   * @param {string} [req.by] who asked (for the status report)
   * @param {number} [req.quietMs] @param {number} [req.maxWaitMs]
   * @param {number} [req.heavyGraceMs] @param {number} [req.tickMs]
   * @returns {object} the state, as getState() would report it
   */
  function requestRestart(req) {
    const r = req || {};
    if (typeof r.onRestart !== 'function') throw new Error('requestRestart needs onRestart');
    if (pending) return getState(); // already draining — idempotent, not an error
    const t = now();
    const quietMs = Number(r.quietMs) >= 0 ? Number(r.quietMs) : DEFAULTS.quietMs;
    const maxWaitMs = Number(r.maxWaitMs) > 0 ? Number(r.maxWaitMs) : DEFAULTS.maxWaitMs;
    const heavyGraceMs = Number(r.heavyGraceMs) >= 0 ? Number(r.heavyGraceMs) : DEFAULTS.heavyGraceMs;
    pending = {
      startedAt: t, by: r.by || null, quietMs, maxWaitMs, heavyGraceMs,
      tickMs: Number(r.tickMs) > 0 ? Number(r.tickMs) : DEFAULTS.tickMs,
      deadline: t + maxWaitMs,
      hardDeadline: t + maxWaitMs + heavyGraceMs,
      idleSince: null, lastSnapshot: null, onRestart: r.onRestart,
    };
    // Evaluate immediately: an already-idle site should not sit through a
    // whole tick before starting its quiet window.
    tick();
    return getState();
  }

  /** Cancel a pending drain. Returns true if one was actually cancelled. */
  function cancelRestart() {
    if (!pending) return false;
    stopTimer();
    pending = null;
    return true;
  }

  /** Current drain state — what the admin page polls. */
  function getState() {
    const snap = snapshot();
    if (!pending) return { pending: false, site: snap };
    const t = now();
    return {
      pending: true,
      by: pending.by,
      waitedMs: t - pending.startedAt,
      quietMs: pending.quietMs,
      quietForMs: pending.idleSince == null ? 0 : t - pending.idleSince,
      deadlineInMs: Math.max(0, pending.deadline - t),
      hardDeadlineInMs: Math.max(0, pending.hardDeadline - t),
      site: snap,
    };
  }

  return {
    beginRequest, endRequest, snapshot,
    requestRestart, cancelRestart, getState,
    // exported for tests
    _isHeavy: isHeavy, _isIgnorable: isIgnorable, _labelFor: labelFor,
    _defaults: DEFAULTS,
  };
}

module.exports = { createDrain, DEFAULTS, isHeavy, isIgnorable };
