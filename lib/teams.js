// lib/teams.js — teams, memberships, invitations. Wave 3 (ARCHITECTURE.md
// "Wave 3 — Teams & Projects"). Zero dependencies; state persisted via
// lib/store.js to data/teams.json + data/team-members.json +
// data/invitations.json.
//
// The core idea: a team shares ALL captures and KB docs equally. Storage is
// keyed by one canonical id per account — accountUid(userId) — instead of by
// the individual user. accountUid() must be resolved from the authenticated
// session ONLY, never from anything a client sends (see server.js's
// resolveAccountUid + the hard rule in ARCHITECTURE.md's Wave 3 section).
'use strict';

const path = require('path');
const crypto = require('crypto');
const { loadJson, saveJson } = require('./store');
const auth = require('./auth');

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const MAX_TEAM_MEMBERS = 50; // sanity bound only -- hiccup has no billing/seat cap
const MAX_TEAM_NAME_LEN = 80; // no cap given in the spec; mirrors projects' name cap

// ── module state (populated by initTeams) ───────────────────────────────────
let _dataDir = null;
let _teamsFile = null;
let _membersFile = null;
let _invitesFile = null;
let _usersFile = null; // read-only: name/email/passwordHash lookups by id/email
let _teams = {};        // teamId -> Team
let _members = {};      // userId -> {teamId, role, joinedAt, suspended}
let _invites = {};      // token -> {teamId, invitedBy, email, createdAt, expiresAt}

/** Build an Error carrying a user-safe message (same convention as lib/auth.js). */
function _err(userMessage, detail) {
  const e = new Error(detail || userMessage);
  e.userMessage = userMessage;
  return e;
}

function _ensureInit() {
  if (!_dataDir) throw new Error('teams: initTeams(dataDir) not called');
}

/**
 * Initialise the teams module: load data/teams.json, data/team-members.json
 * and data/invitations.json from `dataDir`. Safe to call again (re-reads
 * from disk).
 * @param {string} dataDir directory holding teams.json / team-members.json /
 *   invitations.json (the same dataDir passed to auth.initAuth/store)
 */
function initTeams(dataDir) {
  _dataDir = dataDir;
  _teamsFile = path.join(dataDir, 'teams.json');
  _membersFile = path.join(dataDir, 'team-members.json');
  _invitesFile = path.join(dataDir, 'invitations.json');
  _usersFile = path.join(dataDir, 'users.json');

  const teams = loadJson(_teamsFile, {});
  _teams = (teams && typeof teams === 'object' && !Array.isArray(teams)) ? teams : {};
  const members = loadJson(_membersFile, {});
  _members = (members && typeof members === 'object' && !Array.isArray(members)) ? members : {};
  const invites = loadJson(_invitesFile, {});
  _invites = (invites && typeof invites === 'object' && !Array.isArray(invites)) ? invites : {};

  _sweepInvites();
}

function _saveTeams() { saveJson(_teamsFile, _teams); }
function _saveMembers() { saveJson(_membersFile, _members); }
function _saveInvites() { saveJson(_invitesFile, _invites); }

/**
 * Drop expired invitations from memory + disk. Called at the top of every
 * function that reads `_invites` ("swept lazily on read" per the spec — no
 * timer, unlike auth.js's hourly session sweep).
 */
function _sweepInvites() {
  const now = Date.now();
  let changed = false;
  for (const token of Object.keys(_invites)) {
    const inv = _invites[token];
    if (!inv || typeof inv.expiresAt !== 'number' || inv.expiresAt <= now) {
      delete _invites[token];
      changed = true;
    }
  }
  if (changed) _saveInvites();
}

// ── raw user lookups (name/email/passwordHash) ──────────────────────────────
// lib/auth.js exports no by-id lookup and its by-email lookup strips
// passwordHash (the public projection) -- acceptInvite's branch 2 needs to
// know whether a password hash exists at all (Google-only accounts have
// none), and getTeamView's Member shape needs name/email per user id. Both
// are read directly from data/users.json (the same file auth.js maintains),
// via store.js's loadJson, fresh on every call (auth.js writes synchronously,
// so this is never stale within one process).

function _loadUsersRaw() {
  const users = loadJson(_usersFile, []);
  return Array.isArray(users) ? users : [];
}

function _userById(userId) {
  return _loadUsersRaw().find((u) => u && u.id === userId) || null;
}

/**
 * Team participation — creating or joining — is a paid feature. A free
 * account has no way to be a team owner, admin or member; see
 * ARCHITECTURE.md for why this lives here rather than in server.js's route
 * handlers (teams.js already reads user records directly for identity
 * verification, so this is one more field on the same read, not new coupling).
 * @param {object|null} user a raw user record (from _userById/_userByEmail)
 * @returns {boolean}
 */
function _isPaid(user) {
  return !!(user && user.plan === 'paid');
}

function _userByEmail(email) {
  const em = String(email || '').trim().toLowerCase();
  return _loadUsersRaw().find((u) => u && u.email === em) || null;
}

// ── config (for building an absolute invite URL) ────────────────────────────

function _baseUrl() {
  const cfg = loadJson(path.join(_dataDir, 'config.json'), {});
  return (cfg && typeof cfg.baseUrl === 'string' && cfg.baseUrl) || 'http://127.0.0.1:8400';
}

function _inviteUrl(token) {
  // Clean URL, matching every other page in the app (/app /hmr /kb /team,
  // never a .html suffix) -- server.js maps this to public/accept-invite.html.
  return _baseUrl().replace(/\/+$/, '') + '/accept-invite?token=' + token;
}

// ── core accessors ───────────────────────────────────────────────────────────

/**
 * The team a user belongs to, or null.
 * @param {string} userId
 * @returns {string|null} teamId
 */
function getTeamIdFor(userId) {
  _ensureInit();
  const m = _members[userId];
  return m ? m.teamId : null;
}

/**
 * Resolve the storage account id for a user: the team's shared dataRootId
 * when the user is on a team, otherwise the user's own id unchanged. This is
 * the ONLY id every storage call (captures/KB docs/projects) may use -- see
 * the hard rule in ARCHITECTURE.md's Wave 3 section.
 * @param {string} userId
 * @returns {string}
 */
function accountUid(userId) {
  _ensureInit();
  const teamId = getTeamIdFor(userId);
  if (!teamId) return userId;
  const team = _teams[teamId];
  return team ? team.dataRootId : userId;
}

/**
 * A user's role on their team, or null when teamless.
 * @param {string} userId
 * @returns {'owner'|'admin'|'member'|null}
 */
function getAccountRole(userId) {
  _ensureInit();
  const m = _members[userId];
  return m ? m.role : null;
}

/**
 * Whether a user can manage team membership (invite/suspend/remove).
 * @param {string} userId
 * @returns {boolean} true for owner or admin
 */
function canManageMembers(userId) {
  const role = getAccountRole(userId);
  return role === 'owner' || role === 'admin';
}

/**
 * Whether a user's team membership is currently suspended. server.js's
 * requireAuth calls this after resolving the session and 401s (clearing the
 * cookie) when true -- see ARCHITECTURE.md's "Suspension enforcement".
 * @param {string} userId
 * @returns {boolean}
 */
function isSuspended(userId) {
  _ensureInit();
  const m = _members[userId];
  return !!(m && m.suspended);
}

function _teamMemberCount(teamId) {
  let n = 0;
  for (const uid of Object.keys(_members)) {
    if (_members[uid] && _members[uid].teamId === teamId) n++;
  }
  return n;
}

// ── team lifecycle ───────────────────────────────────────────────────────────

/**
 * Create a team owned by `userId`. The team's shared storage root
 * (dataRootId) is fixed at the creator's own id forever, including across
 * ownership transfers -- this is what makes a solo user's existing captures
 * become the team's shared captures with zero migration.
 * @param {string} userId the creator, who becomes owner
 * @param {string} name team name (required, <= 80 chars)
 * @returns {object} Team
 * @throws {Error} with .userMessage when userId is already on a team, or the
 *   name is empty/too long
 */
function createTeam(userId, name) {
  _ensureInit();
  if (getTeamIdFor(userId)) throw _err('You are already on a team.');
  if (!_isPaid(_userById(userId))) {
    throw _err('Creating a team needs a paid account. Subscribe, then try again.');
  }
  const nm = String(name || '').trim();
  if (!nm) throw _err('A team name is required.');
  if (nm.length > MAX_TEAM_NAME_LEN) {
    throw _err('Team name must be ' + MAX_TEAM_NAME_LEN + ' characters or fewer.');
  }

  const teamId = crypto.randomBytes(8).toString('hex');
  const now = new Date().toISOString();
  const team = { teamId, ownerId: userId, dataRootId: userId, name: nm, createdAt: now };
  _teams[teamId] = team;
  _members[userId] = { teamId, role: 'owner', joinedAt: now, suspended: false };
  _saveTeams();
  _saveMembers();
  return team;
}

/**
 * The full team view for a user: their team (or null), its members, its
 * pending invites, and this user's own role/manage-capability.
 * @param {string} userId
 * @returns {{team:object|null, members:object[], pendingInvites:object[],
 *   myRole:string|null, myCanManage:boolean}}
 */
function getTeamView(userId) {
  _ensureInit();
  const teamId = getTeamIdFor(userId);
  const team = teamId ? _teams[teamId] : null;
  if (!team) {
    // Teamless is the normal solo-user response, not an error.
    return { team: null, members: [], pendingInvites: [], myRole: null, myCanManage: false };
  }

  const roleRank = { owner: 0, admin: 1, member: 2 };
  const members = Object.keys(_members)
    .filter((uid) => _members[uid] && _members[uid].teamId === teamId)
    .map((uid) => {
      const m = _members[uid];
      const u = _userById(uid);
      return {
        userId: uid,
        name: u ? u.name : null,
        email: u ? u.email : null,
        role: m.role,
        suspended: !!m.suspended,
        joinedAt: m.joinedAt,
      };
    })
    .sort((a, b) => (roleRank[a.role] - roleRank[b.role]) ||
      String(a.joinedAt).localeCompare(String(b.joinedAt)));

  _sweepInvites();
  const pendingInvites = Object.keys(_invites)
    .map((token) => _invites[token])
    .filter((inv) => inv && inv.teamId === teamId)
    .map((inv) => ({ email: inv.email, createdAt: inv.createdAt, expiresAt: inv.expiresAt }))
    .sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));

  const myRole = getAccountRole(userId);
  return { team, members, pendingInvites, myRole, myCanManage: myRole === 'owner' || myRole === 'admin' };
}

// ── invitations ───────────────────────────────────────────────────────────

/**
 * Create (or supersede) an invitation to join the inviter's team.
 * @param {string} inviterUserId must be able to manage members (owner/admin)
 * @param {string} email the invitee's email
 * @returns {{token:string, expiresAt:number, inviteUrl:string}}
 * @throws {Error} with .userMessage when the inviter cannot manage members,
 *   the email is invalid, the email already belongs to a member of this
 *   team, or the team is already at the 50-member sanity cap
 */
function createInvite(inviterUserId, email) {
  _ensureInit();
  if (!canManageMembers(inviterUserId)) {
    throw _err('Only a team owner or admin can invite members.');
  }
  const teamId = getTeamIdFor(inviterUserId); // non-null: canManageMembers implies membership

  const em = String(email || '').trim().toLowerCase();
  if (!em || em.indexOf('@') < 1) throw _err('A valid email address is required.');

  const memberEmails = new Set();
  for (const uid of Object.keys(_members)) {
    if (_members[uid] && _members[uid].teamId === teamId) {
      const u = _userById(uid);
      if (u && u.email) memberEmails.add(String(u.email).toLowerCase());
    }
  }
  if (memberEmails.has(em)) throw _err('That email already belongs to a member of this team.');

  if (_teamMemberCount(teamId) >= MAX_TEAM_MEMBERS) {
    throw _err('This team already has the maximum of ' + MAX_TEAM_MEMBERS + ' members.');
  }

  _sweepInvites();
  // Supersede any prior pending invite to the same email+team.
  for (const token of Object.keys(_invites)) {
    const inv = _invites[token];
    if (inv && inv.teamId === teamId && String(inv.email).toLowerCase() === em) {
      delete _invites[token];
    }
  }

  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  const expiresAt = now + INVITE_TTL_MS;
  _invites[token] = {
    teamId,
    invitedBy: inviterUserId,
    email: em,
    createdAt: new Date(now).toISOString(),
    expiresAt,
  };
  _saveInvites();
  return { token, expiresAt, inviteUrl: _inviteUrl(token) };
}

/**
 * Public info about a pending invite, for the accept-invite page to decide
 * which of the three acceptInvite branches to render.
 * @param {string} token
 * @returns {{email:string, teamName:string, emailExists:boolean,
 *   hasPassword:boolean}|null} null for an unknown/expired token (server.js
 *   maps that to 404)
 */
function getInviteInfo(token) {
  _ensureInit();
  _sweepInvites();
  const inv = _invites[String(token || '')];
  if (!inv) return null;
  const team = _teams[inv.teamId];
  if (!team) return null;
  const existing = _userByEmail(inv.email);
  return {
    email: inv.email,
    teamName: team.name,
    emailExists: !!existing,
    hasPassword: !!(existing && existing.passwordHash),
  };
}

/**
 * Accept an invitation. Three branches (see ARCHITECTURE.md Wave 3 for why
 * identity verification is mandatory here -- an invite token travels by
 * email and must never by itself be enough to join someone else's account):
 *   1. sessionUserId's own email === the invited email -> join immediately.
 *   2. Invited email belongs to an existing account, caller not
 *      authenticated as it -> requires `password`, verified via
 *      auth.verifyPassword. A Google-only account (no password hash) rejects
 *      with a clear userMessage.
 *   3. Invited email is new -> requires `createAccount: {password, name}`,
 *      calls auth.createUser then joins.
 * A user may belong to exactly one team; joining while already on a team
 * (this one or another) throws. Consumes the token on success.
 * @param {string} token
 * @param {{sessionUserId?:string|null, password?:string,
 *   createAccount?:{password:string, name?:string}}} opts
 * @returns {{userId:string}}
 * @throws {Error} with .userMessage on an invalid/expired token, failed
 *   identity verification, or a team-membership conflict
 */
function acceptInvite(token, opts) {
  _ensureInit();
  opts = opts || {};
  _sweepInvites();
  const tok = String(token || '');
  const inv = _invites[tok];
  if (!inv) throw _err('This invite link is invalid or has expired.');
  const team = _teams[inv.teamId];
  if (!team) throw _err('This invite link is invalid or has expired.');

  const invitedEmail = inv.email; // already lowercased+trimmed at creation
  const sessionUser = opts.sessionUserId ? _userById(opts.sessionUserId) : null;

  let userId;
  if (sessionUser && String(sessionUser.email).toLowerCase() === invitedEmail) {
    // Branch 1: already authenticated as the invited email.
    userId = sessionUser.id;
  } else {
    const existing = _userByEmail(invitedEmail);
    if (existing) {
      // Branch 2: existing account, caller not currently authenticated as it.
      if (!existing.passwordHash) {
        throw _err('That account signs in with Google — sign in first, then open this link again.');
      }
      const pw = opts.password;
      if (typeof pw !== 'string' || !pw) {
        throw _err('Enter the password for ' + invitedEmail + ' to accept this invite.');
      }
      const verified = auth.verifyPassword(invitedEmail, pw);
      if (!verified) throw _err('Wrong password.');
      userId = verified.id;
    } else {
      // Branch 3: brand-new account.
      const ca = opts.createAccount;
      if (!ca || typeof ca !== 'object' || typeof ca.password !== 'string' || !ca.password) {
        throw _err('Choose a password to create your account and accept this invite.');
      }
      const created = auth.createUser({
        email: invitedEmail,
        password: ca.password,
        name: typeof ca.name === 'string' ? ca.name : undefined,
      });
      userId = created.id;
    }
  }

  if (getTeamIdFor(userId)) throw _err('You are already on a team.');
  // Checked AFTER a brand-new account (branch 3) is created, deliberately:
  // the account itself is real and usable either way, so a not-yet-paid
  // invitee can sign in and subscribe, then reopen this exact link — the
  // token is not consumed below this point, so nothing here is wasted.
  if (!_isPaid(_userById(userId))) {
    throw _err('Joining a team needs a paid account. Subscribe, then open this invite link again — it stays valid.');
  }
  if (_teamMemberCount(inv.teamId) >= MAX_TEAM_MEMBERS) {
    throw _err('This team already has the maximum of ' + MAX_TEAM_MEMBERS + ' members.');
  }

  _members[userId] = { teamId: inv.teamId, role: 'member', joinedAt: new Date().toISOString(), suspended: false };
  _saveMembers();

  delete _invites[tok];
  _saveInvites();

  return { userId };
}

// ── membership management ───────────────────────────────────────────────────
// Every function here independently re-checks the actor's permission
// server-side, even though a well-behaved UI would never show the button to
// an unauthorized user -- the API is the actual enforcement, not the UI.

/**
 * Change a member's role. Owner-only; the owner role itself can only change
 * via transferOwnership (targeting the owner, or the owner acting on
 * themselves, is rejected here).
 * @param {string} actingUserId must be the team owner
 * @param {string} targetUserId
 * @param {'admin'|'member'} role
 * @returns {{ok:true}}
 * @throws {Error} with .userMessage on a permission or validation failure
 */
function setMemberRole(actingUserId, targetUserId, role) {
  _ensureInit();
  if (getAccountRole(actingUserId) !== 'owner') {
    throw _err('Only the team owner can change member roles.');
  }
  if (role !== 'admin' && role !== 'member') throw _err('role must be "admin" or "member".');
  const teamId = getTeamIdFor(actingUserId);
  const target = _members[targetUserId];
  if (!target || target.teamId !== teamId) throw _err('That user is not a member of your team.');
  if (target.role === 'owner') throw _err('Use "transfer ownership" to change the team owner.');

  target.role = role;
  _saveMembers();
  return { ok: true };
}

/**
 * Suspend or restore a member. Owner/admin; nobody can suspend the owner,
 * and an admin cannot suspend another admin.
 * @param {string} actingUserId must be owner or admin
 * @param {string} targetUserId
 * @param {boolean} suspended
 * @returns {{ok:true}}
 * @throws {Error} with .userMessage on a permission or validation failure
 */
function setMemberSuspended(actingUserId, targetUserId, suspended) {
  _ensureInit();
  if (!canManageMembers(actingUserId)) throw _err('Only a team owner or admin can suspend members.');
  const actingRole = getAccountRole(actingUserId);
  const teamId = getTeamIdFor(actingUserId);
  const target = _members[targetUserId];
  if (!target || target.teamId !== teamId) throw _err('That user is not a member of your team.');
  if (target.role === 'owner') throw _err('The team owner cannot be suspended.');
  if (actingRole === 'admin' && target.role === 'admin') {
    throw _err('An admin cannot suspend another admin.');
  }

  target.suspended = !!suspended;
  _saveMembers();
  return { ok: true };
}

/**
 * Remove a member from the team. Owner/admin; not self, not the owner, and
 * an admin cannot remove another admin.
 * @param {string} actingUserId must be owner or admin
 * @param {string} targetUserId
 * @returns {{ok:true}}
 * @throws {Error} with .userMessage on a permission or validation failure
 */
function removeMember(actingUserId, targetUserId) {
  _ensureInit();
  if (!canManageMembers(actingUserId)) throw _err('Only a team owner or admin can remove members.');
  if (targetUserId === actingUserId) throw _err('You cannot remove yourself from the team.');
  const actingRole = getAccountRole(actingUserId);
  const teamId = getTeamIdFor(actingUserId);
  const target = _members[targetUserId];
  if (!target || target.teamId !== teamId) throw _err('That user is not a member of your team.');
  if (target.role === 'owner') throw _err('The team owner cannot be removed.');
  if (actingRole === 'admin' && target.role === 'admin') {
    throw _err('An admin cannot remove another admin.');
  }

  delete _members[targetUserId];
  _saveMembers();
  return { ok: true };
}

/**
 * Transfer team ownership. Owner-only. dataRootId NEVER changes on transfer
 * (would orphan the team's storage under the old owner's id) -- only
 * Team.ownerId and the two members' roles change. The outgoing owner is
 * demoted to admin (not member), so the team is never left without someone
 * who can still manage membership.
 * @param {string} actingUserId must be the current team owner
 * @param {string} targetUserId the member becoming the new owner
 * @returns {{ok:true}}
 * @throws {Error} with .userMessage on a permission or validation failure
 */
function transferOwnership(actingUserId, targetUserId) {
  _ensureInit();
  if (getAccountRole(actingUserId) !== 'owner') {
    throw _err('Only the team owner can transfer ownership.');
  }
  if (targetUserId === actingUserId) throw _err('You are already the owner.');
  const teamId = getTeamIdFor(actingUserId);
  const target = _members[targetUserId];
  if (!target || target.teamId !== teamId) throw _err('That user is not a member of your team.');
  if (target.suspended) throw _err('Cannot transfer ownership to a suspended member.');

  const team = _teams[teamId];
  team.ownerId = targetUserId; // dataRootId is untouched
  target.role = 'owner';
  _members[actingUserId].role = 'admin';
  _saveTeams();
  _saveMembers();
  return { ok: true };
}

module.exports = {
  initTeams,
  accountUid,
  getTeamIdFor,
  getAccountRole,
  canManageMembers,
  isSuspended,
  createTeam,
  getTeamView,
  createInvite,
  getInviteInfo,
  acceptInvite,
  setMemberRole,
  setMemberSuspended,
  removeMember,
  transferOwnership,
};
