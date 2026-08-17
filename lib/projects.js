// lib/projects.js — named projects (folders) within an account's shared
// capture space. Wave 3 (ARCHITECTURE.md "Wave 3 — Teams & Projects"). Zero
// dependencies beyond lib/store.js; state persisted to
// data/projects/<accountUid>.json (one array file per account).
'use strict';

const path = require('path');
const store = require('./store');

const MAX_NAME_LEN = 80;
const MAX_PROJECTS = 100;

// ── module state (populated by initProjects) ────────────────────────────────
let _dataDir = null;

/** Build an Error carrying a user-safe message (same convention as lib/auth.js). */
function _err(userMessage, detail) {
  const e = new Error(detail || userMessage);
  e.userMessage = userMessage;
  return e;
}

function _ensureInit() {
  if (!_dataDir) throw new Error('projects: initProjects(dataDir) not called');
}

/**
 * Initialise the projects module.
 * @param {string} dataDir the app data directory (same one passed to
 *   store.js's capture helpers)
 */
function initProjects(dataDir) {
  _dataDir = dataDir;
}

/** @returns {boolean} true when accountUid is safe to use as a file-name component */
function _safeAccountUid(accountUid) {
  return typeof accountUid === 'string' && /^[A-Za-z0-9_-]+$/.test(accountUid);
}

function _projectsFile(accountUid) {
  if (!_safeAccountUid(accountUid)) {
    throw new Error('projects: invalid accountUid ' + JSON.stringify(accountUid));
  }
  return path.join(_dataDir, 'projects', accountUid + '.json');
}

function _load(accountUid) {
  const arr = store.loadJson(_projectsFile(accountUid), []);
  return Array.isArray(arr) ? arr : [];
}

function _save(accountUid, list) {
  store.saveJson(_projectsFile(accountUid), list);
}

/** Per-project capture count for a single project (getProject/createProject/renameProject). */
function _captureCountFor(accountUid, projectId) {
  const metas = store.listCaptures(_dataDir, accountUid);
  let n = 0;
  for (const m of metas) if (m && m.projectId === projectId) n++;
  return n;
}

/** Capture counts for every project in one pass (listProjects). */
function _captureCountMap(accountUid) {
  const metas = store.listCaptures(_dataDir, accountUid);
  const counts = new Map();
  for (const m of metas) {
    const pid = m && m.projectId;
    if (!pid) continue; // unfiled captures don't count toward any project
    counts.set(pid, (counts.get(pid) || 0) + 1);
  }
  return counts;
}

/** Stored record -> client-facing Project (adds the derived captureCount). */
function _view(record, captureCount) {
  return {
    id: record.id,
    name: record.name,
    description: record.description != null ? record.description : '',
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    captureCount: captureCount || 0,
  };
}

/**
 * List an account's projects, newest first, each with its live captureCount.
 * @param {string} accountUid
 * @returns {object[]} Project[]
 */
function listProjects(accountUid) {
  _ensureInit();
  const list = _load(accountUid);
  const counts = _captureCountMap(accountUid);
  return list
    .map((p) => _view(p, counts.get(p.id) || 0))
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
}

/**
 * Create a project.
 * @param {string} accountUid
 * @param {{name:string, description?:string}} opts
 * @returns {object} Project
 * @throws {Error} with .userMessage on an empty/too-long name or >100
 *   existing projects
 */
function createProject(accountUid, opts) {
  _ensureInit();
  opts = opts || {};
  const name = String(opts.name || '').trim();
  if (!name) throw _err('A project name is required.');
  if (name.length > MAX_NAME_LEN) {
    throw _err('Project name must be ' + MAX_NAME_LEN + ' characters or fewer.');
  }
  const description = opts.description != null ? String(opts.description).trim() : '';

  const list = _load(accountUid);
  if (list.length >= MAX_PROJECTS) {
    throw _err('This account already has the maximum of ' + MAX_PROJECTS + ' projects.');
  }

  const now = new Date().toISOString();
  const record = { id: store.newCaptureId(), name, description, createdAt: now, updatedAt: now };
  list.push(record);
  _save(accountUid, list);
  return _view(record, 0);
}

/**
 * Look up one project.
 * @param {string} accountUid
 * @param {string} projectId
 * @returns {object|null} Project, or null when not found
 */
function getProject(accountUid, projectId) {
  _ensureInit();
  const record = _load(accountUid).find((p) => p && p.id === projectId);
  if (!record) return null;
  return _view(record, _captureCountFor(accountUid, record.id));
}

/**
 * Rename/redescribe a project. Only the fields present in `opts` are changed.
 * @param {string} accountUid
 * @param {string} projectId
 * @param {{name?:string, description?:string}} opts
 * @returns {object} Project
 * @throws {Error} with .userMessage when the project doesn't exist or the
 *   new name is empty/too long
 */
function renameProject(accountUid, projectId, opts) {
  _ensureInit();
  opts = opts || {};
  const list = _load(accountUid);
  const record = list.find((p) => p && p.id === projectId);
  if (!record) throw _err('Project not found.');

  if (opts.name !== undefined) {
    const name = String(opts.name || '').trim();
    if (!name) throw _err('A project name is required.');
    if (name.length > MAX_NAME_LEN) {
      throw _err('Project name must be ' + MAX_NAME_LEN + ' characters or fewer.');
    }
    record.name = name;
  }
  if (opts.description !== undefined) {
    record.description = opts.description != null ? String(opts.description).trim() : '';
  }
  record.updatedAt = new Date().toISOString();
  _save(accountUid, list);
  return _view(record, _captureCountFor(accountUid, record.id));
}

/**
 * Delete a project. Deliberately does NOT cascade-delete its captures (a
 * divergence from a naive port that DOES cascade-delete): a capture-analysis
 * tool's uploads (pcaps) are not cheaply re-creatable the way a re-uploaded
 * document is, so deleting a folder must never destroy what's inside it.
 * Every capture in the project is unassigned instead (projectId -> null /
 * "Unfiled").
 * @param {string} accountUid
 * @param {string} projectId
 * @returns {boolean} true when the project existed and was removed
 */
function deleteProject(accountUid, projectId) {
  _ensureInit();
  const list = _load(accountUid);
  const idx = list.findIndex((p) => p && p.id === projectId);
  if (idx === -1) return false;
  list.splice(idx, 1);
  _save(accountUid, list);

  const metas = store.listCaptures(_dataDir, accountUid);
  for (const m of metas) {
    if (!m || m.projectId !== projectId) continue;
    try {
      const dir = store.captureDir(_dataDir, accountUid, m.id);
      m.projectId = null;
      store.saveJson(path.join(dir, 'meta.json'), m);
    } catch {
      /* best-effort unassign; a missing/corrupt capture is skipped */
    }
  }
  return true;
}

module.exports = {
  initProjects,
  listProjects,
  createProject,
  getProject,
  renameProject,
  deleteProject,
};
