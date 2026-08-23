'use strict';
/**
 * lib/plans.js — what each tier is allowed to do. One table, one place.
 *
 * WHY THIS EXISTS
 *
 * The plan field used to be binary: 'free' or 'paid', with `plan === 'paid'`
 * spelled out in eight places across auth, teams and server. Adding a third
 * tier that way would have meant eight more chances for two files to disagree
 * about what somebody bought. Every capability question now goes through this
 * table instead.
 *
 * THE LADDER
 *
 *   free  Every analysis feature, no card, no time limit. That promise is on
 *         the landing page and it stays true: Pro adds CAPACITY and PRIORITY,
 *         never a feature that free used to have. Nothing was taken away to
 *         create the paid individual tier, which matters both ethically and
 *         because the free tier is the top of the funnel.
 *   pro   For one engineer. Bigger captures, and priority when the analysis
 *         queue is busy.
 *   team  Everything in Pro, plus the shared library, roles and invites.
 *
 * LEGACY: accounts created before the three-tier split carry plan:'paid',
 * which granted team access. They normalise to 'team' -- never to 'pro', which
 * would silently downgrade a paying customer.
 */

/** Uploads on the free tier, in MB. Overridable by config.maxUploadMb. */
const FREE_UPLOAD_MB = 50;
/** Uploads on any paid tier. */
const PAID_UPLOAD_MB = 250;

const PLANS = {
  free: {
    id: 'free',
    label: 'Free',
    uploadMb: FREE_UPLOAD_MB,
    teams: false,
    // Higher runs first in lib/llm.js's queue. Equal priority stays FIFO, so
    // free users are never starved -- they queue behind paid users who arrived
    // first, not behind every paid user forever.
    queuePriority: 0,
  },
  pro: {
    id: 'pro',
    label: 'Pro',
    uploadMb: PAID_UPLOAD_MB,
    teams: false,
    queuePriority: 1,
  },
  team: {
    id: 'team',
    label: 'Team',
    uploadMb: PAID_UPLOAD_MB,
    teams: true,
    queuePriority: 1,
  },
};

/**
 * Coerce anything stored, sent or guessed into a real tier id.
 * @param {*} plan
 * @returns {'free'|'pro'|'team'}
 */
function normalise(plan) {
  const p = typeof plan === 'string' ? plan.trim().toLowerCase() : '';
  if (p === 'pro') return 'pro';
  if (p === 'team') return 'team';
  // Pre-split accounts. 'paid' meant team access, so it must not become 'pro'.
  if (p === 'paid') return 'team';
  return 'free';
}

/** The capability row for a plan. Always returns a row, never undefined. */
function capabilities(plan) {
  return PLANS[normalise(plan)];
}

/** May this plan create or join a team? */
function canUseTeams(plan) {
  return capabilities(plan).teams;
}

/** Is this a paying tier at all? */
function isPaid(plan) {
  return normalise(plan) !== 'free';
}

/**
 * Upload ceiling in MB. config.maxUploadMb, when set, moves the FREE tier only
 * -- an operator lowering it for their own box should not silently also cap
 * what a paying customer was sold.
 * @param {string} plan
 * @param {number} [configFreeMb]
 */
function uploadLimitMb(plan, configFreeMb) {
  const cap = capabilities(plan);
  if (cap.id === 'free') {
    const n = Number(configFreeMb);
    return Number.isFinite(n) && n > 0 ? n : cap.uploadMb;
  }
  return cap.uploadMb;
}

/** Queue priority; higher jumps the line. */
function queuePriority(plan) {
  return capabilities(plan).queuePriority;
}

/** Every tier id, in ladder order. */
function all() {
  return ['free', 'pro', 'team'];
}

module.exports = {
  PLANS, normalise, capabilities, canUseTeams, isPaid,
  uploadLimitMb, queuePriority, all,
  FREE_UPLOAD_MB, PAID_UPLOAD_MB,
};
