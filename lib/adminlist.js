// lib/adminlist.js — pure logic for editing the site-admin (config.adminEmails)
// allow-list. Kept separate from server.js and framework-free specifically so
// the tricky safety rules here — the ones an adversarial review found real
// bugs in on the first version of this feature — can be unit tested directly,
// without server.js's inability to be require()'d (it calls listen() at
// module scope as a side effect of loading).
'use strict';

/** @param {*} e @returns {string} */
function normalise(e) {
  return String(e == null ? '' : e).trim().toLowerCase();
}

/**
 * Normalise + dedupe a raw admin-emails array. Order-preserving on first
 * occurrence.
 * @param {*} raw
 * @returns {string[]}
 */
function cleanList(raw) {
  const seen = new Set();
  const out = [];
  for (const e of (Array.isArray(raw) ? raw : [])) {
    const n = normalise(e);
    if (n && !seen.has(n)) { seen.add(n); out.push(n); }
  }
  return out;
}

/**
 * Compute the new config.adminEmails list for one grant/revoke action, or an
 * error — without touching config/session/disk state, so every rule below
 * can be exercised directly in a unit test.
 *
 * Every rule here exists because of a specific bug an adversarial review
 * found in the first version of this feature (see ARCHITECTURE.md for the
 * full writeup):
 *
 *   - GRANT while the list is empty (the acting admin is authorised only via
 *     lib/auth.js's role:'admin' first-signup fallback) seeds the ACTOR's own
 *     email alongside the target. Without this, the first grant makes the
 *     list non-empty — which isSiteAdmin() then treats as authoritative over
 *     role — silently locking the actor out of the very panel they just used
 *     to promote someone else.
 *   - REVOKE while the list is empty is refused outright, not silently
 *     accepted as a no-op. The list has nothing to remove from (the actor's
 *     access comes from role, not the list), so a "success" response would
 *     be a lie: the target's real authorization is completely unchanged.
 *   - The "don't remove the last admin" guard counts entries that resolve to
 *     a REAL, CURRENTLY-EXISTING account (via `accountExists`), not raw list
 *     length. A stale entry (a deployment's default seed email before that
 *     account has ever signed up, or left behind after the account holding
 *     it was deleted — see pruneEmail()) must not be able to make the guard
 *     believe the box has one more live admin than it actually does.
 *
 * @param {object} opts
 * @param {*} opts.currentEmails config.adminEmails as currently stored (any shape; cleaned here)
 * @param {string} opts.targetEmail the account being granted/revoked
 * @param {boolean} opts.wantSuperuser true to grant, false to revoke
 * @param {string} opts.actorEmail the acting admin's own email
 * @param {function(string): boolean} opts.accountExists given a normalised email, true if a real account currently holds it
 * @returns {{ok: true, adminEmails: string[]}|{ok: false, error: string}}
 */
function applyChange(opts) {
  const o = opts || {};
  const target = normalise(o.targetEmail);
  const actor = normalise(o.actorEmail);
  const current = cleanList(o.currentEmails);
  const accountExists = typeof o.accountExists === 'function' ? o.accountExists : () => true;

  if (!target) return { ok: false, error: 'no target email' };

  if (o.wantSuperuser) {
    const next = current.slice();
    if (next.indexOf(target) === -1) next.push(target);
    // The list was empty, i.e. the actor's own access came from the role
    // fallback alone — making the list non-empty without the actor in it
    // would silently revoke the actor's own access mid-action.
    if (current.length === 0 && actor && next.indexOf(actor) === -1) next.push(actor);
    return { ok: true, adminEmails: next };
  }

  // Revoke.
  if (current.length === 0) {
    return {
      ok: false,
      error: 'the admin list is currently empty (access is via the first-signup fallback) — ' +
        'grant yourself explicit superuser access first, then revoke from there',
    };
  }
  const idx = current.indexOf(target);
  if (idx === -1) return { ok: true, adminEmails: current }; // already not listed — idempotent success
  const next = current.slice();
  next.splice(idx, 1);
  const liveRemaining = next.filter(accountExists).length;
  if (liveRemaining === 0) {
    return {
      ok: false,
      error: 'cannot remove the last superuser — add another one first, or edit ' +
        'data/config.json on the server if you are truly locking everyone out',
    };
  }
  return { ok: true, adminEmails: next };
}

/**
 * Remove one email from an admin-emails list, e.g. when the account holding
 * it is deleted. Unlike applyChange() this never refuses — GDPR erasure is
 * the account holder's right regardless of admin status, and leaving a
 * deleted account's email in the list is exactly the reclaimable-admin-slot
 * bug this module exists to prevent (anyone could re-register that exact
 * email and inherit admin access). It CAN leave the list with zero live
 * admins in the rare case where the sole admin deletes their own account;
 * that is an accepted, documented tradeoff (see server.js's handleMeDelete),
 * not an oversight — the alternative is a phantom, unowned admin slot.
 * @param {*} currentEmails
 * @param {string} email
 * @returns {{changed: boolean, adminEmails: string[]}}
 */
function pruneEmail(currentEmails, email) {
  const target = normalise(email);
  const current = cleanList(currentEmails);
  const idx = current.indexOf(target);
  if (idx === -1) return { changed: false, adminEmails: current };
  const next = current.slice();
  next.splice(idx, 1);
  return { changed: true, adminEmails: next };
}

module.exports = { normalise, cleanList, applyChange, pruneEmail };
