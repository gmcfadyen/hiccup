// lib/store.js — JSON persistence + capture directory helpers.
// Zero dependencies; Windows-safe (atomic writes handle EEXIST/EPERM on rename).
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

let _tmpCounter = 0;

/**
 * Load a JSON file, returning `fallback` when the file is missing or unparsable.
 * @param {string} file absolute or relative path to a .json file
 * @param {*} fallback value returned on any read/parse failure
 * @returns {*} parsed JSON or `fallback`
 */
function loadJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

/**
 * Atomically save `obj` as pretty-printed JSON: write to a unique tmp file in
 * the same directory, then rename over the target. On Windows, rename onto an
 * existing file can throw EEXIST/EPERM — in that case the target is unlinked
 * first and the rename retried. Parent directories are created on demand.
 * @param {string} file target path
 * @param {*} obj JSON-serialisable value
 */
function saveJson(file, obj) {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = file + '.' + process.pid + '.' + (_tmpCounter++) + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2));
  try {
    fs.renameSync(tmp, file);
  } catch (e) {
    if (e && (e.code === 'EEXIST' || e.code === 'EPERM')) {
      try { fs.unlinkSync(file); } catch { /* target may be gone already */ }
      try {
        fs.renameSync(tmp, file);
      } catch (e2) {
        try { fs.unlinkSync(tmp); } catch { /* best-effort cleanup */ }
        throw e2;
      }
    } else {
      try { fs.unlinkSync(tmp); } catch { /* best-effort cleanup */ }
      throw e;
    }
  }
}

/**
 * Root directory holding all users' captures: `<dataDir>/captures`.
 * @param {string} dataDir the app data directory
 * @returns {string}
 */
function capturesRoot(dataDir) {
  return path.join(dataDir, 'captures');
}

/**
 * Directory for one capture: `<dataDir>/captures/<userId>/<captureId>`.
 * Throws on ids containing path separators or dots (traversal guard).
 * @param {string} dataDir
 * @param {string} userId
 * @param {string} captureId
 * @returns {string}
 */
function captureDir(dataDir, userId, captureId) {
  if (!_safeId(userId) || !_safeId(captureId)) {
    throw new Error('invalid id for captureDir: ' + userId + '/' + captureId);
  }
  return path.join(capturesRoot(dataDir), userId, captureId);
}

/** @returns {boolean} true when id is a plain token safe to use as a dir name */
function _safeId(id) {
  return typeof id === 'string' && /^[A-Za-z0-9_-]+$/.test(id);
}

/**
 * New opaque capture id: 12 lowercase hex chars.
 * @returns {string}
 */
function newCaptureId() {
  return crypto.randomBytes(6).toString('hex');
}

/**
 * List a user's captures by reading each capture's meta.json, newest first
 * (by meta.uploadedAt, falling back to directory mtime). Captures whose
 * meta.json is missing or unreadable are skipped.
 * @param {string} dataDir
 * @param {string} userId
 * @returns {object[]} array of meta.json objects
 */
function listCaptures(dataDir, userId) {
  if (!_safeId(userId)) return [];
  const root = path.join(capturesRoot(dataDir), userId);
  let entries;
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return []; // no captures yet
  }
  const metas = [];
  for (const ent of entries) {
    if (!ent.isDirectory()) continue;
    const metaFile = path.join(root, ent.name, 'meta.json');
    const meta = loadJson(metaFile, null);
    if (!meta || typeof meta !== 'object') continue;
    let sortTs = Date.parse(meta.uploadedAt || '');
    if (!Number.isFinite(sortTs)) {
      try { sortTs = fs.statSync(metaFile).mtimeMs; } catch { sortTs = 0; }
    }
    metas.push({ meta, sortTs });
  }
  metas.sort((a, b) => b.sortTs - a.sortTs); // newest first
  return metas.map(m => m.meta);
}

/**
 * Delete one capture directory (original.bin, meta.json, analysis.json)
 * recursively. Best-effort; invalid ids are treated as not-found.
 * @param {string} dataDir
 * @param {string} userId
 * @param {string} captureId
 * @returns {boolean} true if the capture existed and was removed
 */
function deleteCapture(dataDir, userId, captureId) {
  if (!_safeId(userId) || !_safeId(captureId)) return false;
  const dir = path.join(capturesRoot(dataDir), userId, captureId);
  if (!fs.existsSync(dir)) return false;
  fs.rmSync(dir, { recursive: true, force: true });
  return true;
}

module.exports = {
  loadJson,
  saveJson,
  capturesRoot,
  captureDir,
  newCaptureId,
  listCaptures,
  deleteCapture,
};
