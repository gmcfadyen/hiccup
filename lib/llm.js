'use strict';
/**
 * lib/llm.js — hiccup's shared-Ollama client (RFPlex-deferential).
 *
 * hiccup shares GAVINPC's Ollama with RFPlex (port 3001), which is the GPU's
 * PRIORITY TENANT. This module's whole job is to borrow the GPU politely:
 *
 *  - Model choice: ask RFPlex (`GET /api/status/llm`) and prefer its `smart`
 *    model when installed, else its `fast`. If RFPlex is unreachable, use
 *    whatever `/api/ps` says is already loaded (skipping embedding models).
 *    Else the first of config.preferredModels present in `/api/tags`.
 *  - NEVER pull a model. NEVER trigger a load of a different model while
 *    `/api/ps` shows any generation model loaded (that would evict RFPlex's) —
 *    in that situation use the loaded one.
 *  - keep_alive: if `/api/ps` shows the chosen model pinned (expires_at
 *    absent, "never", or year > 2100 — RFPlex pins with keep_alive:-1), pass
 *    keep_alive:-1 to PRESERVE the pin. Otherwise pass '5m' — hiccup never
 *    extends GPU residency beyond that itself.
 *  - Yield: before dispatching each queued request, if RFPlex reports
 *    engine_reachable && accepting_jobs === false (its GPU gate is closed),
 *    wait 3s and re-check, up to 10 times, then proceed anyway.
 *  - Concurrency 1, FIFO queue, max depth 8 (err.code='busy' beyond),
 *    120s request timeout, one retry on 5xx/ECONNREFUSED after 2s.
 *  - LLM is garnish: every hiccup feature works with Ollama down. All
 *    failures surface as clean rejections with a friendly err.userMessage.
 *
 * Prompts must never contain Digest credentials — analyze.js redacts them
 * before anything reaches this module; nothing here re-introduces raw input.
 *
 * Zero runtime dependencies: plain node http/https. CommonJS.
 */

const http = require('http');
const https = require('https');

// ── Tunables (from the architecture contract §LLM) ─────────────────────────
const MODEL_CACHE_MS = 30 * 1000;   // model-choice view freshness
const YIELD_CACHE_MS = 5 * 1000;    // RFPlex gate check freshness
const RFPLEX_TIMEOUT_MS = 1500;     // RFPlex status fetch timeout
const OLLAMA_STATUS_TIMEOUT_MS = 2500; // /api/tags & /api/ps timeout
const CHAT_TIMEOUT_MS = 120 * 1000; // one /api/chat attempt
const QUEUE_MAX = 8;                // max in-flight + queued requests
const YIELD_WAIT_MS = 3000;
const YIELD_MAX_CHECKS = 10;
const RETRY_DELAY_MS = 2000;

const DEFAULTS = {
  ollamaUrl: 'http://127.0.0.1:11434',
  rfplexStatusUrl: 'http://127.0.0.1:3001/api/status/llm',
  preferredModels: ['qwen3.5:9b', 'qwen3.5:2b', 'qwen3:8b', 'llama3.1:8b'],
};

// ── Module state ───────────────────────────────────────────────────────────
let cfg = null;                              // set by initLlm
let rfplexCache = { ts: 0, val: null };      // val = parsed status JSON | null (unreachable)
let rfplexInFlight = null;                   // shared in-flight fetch promise
let psCache = { ts: 0, entries: null };      // last good /api/ps models array
let view = null;                             // last computed model-choice view
let viewTs = 0;
let refreshing = null;                       // in-flight refresh promise (never rejects)
const queue = [];                            // FIFO of pending askLlm jobs
let active = 0;                              // 0 or 1 (concurrency 1)

// ── Small helpers ──────────────────────────────────────────────────────────

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Heuristic: embedding models never count as "generation model loaded". */
function isEmbeddingName(name) {
  return /embed/i.test(String(name || ''));
}

/**
 * Pin detection per the contract: expires_at absent, "never", or year > 2100
 * means pinned (RFPlex's keep_alive:-1 shows up as a far-future year).
 * A value that fails to parse as a date is treated as NOT pinned.
 */
function isPinned(entry) {
  if (!entry) return false;
  const e = entry.expires_at;
  if (e === undefined || e === null) return true;
  if (String(e).trim().toLowerCase() === 'never') return true;
  const d = new Date(e);
  if (isNaN(d.getTime())) return false; // parse failure → not pinned
  return d.getUTCFullYear() > 2100;
}

/** Extract RFPlex's smart/fast model names from its status JSON (or nulls). */
function rfplexModelNames(rf) {
  const out = { smart: null, fast: null };
  if (rf && Array.isArray(rf.models)) {
    for (const m of rf.models) {
      if (!m || typeof m.name !== 'string') continue;
      if (m.role === 'smart' && !out.smart) out.smart = m.name;
      if (m.role === 'fast' && !out.fast) out.fast = m.name;
    }
  }
  return out;
}

/** Resolve an API path against a configured base URL. */
function apiUrl(base, p) {
  return new URL(p, base).toString();
}

/** Plain-node HTTP GET returning parsed JSON; rejects on error/timeout/4xx+. */
function httpGetJson(urlStr, timeoutMs) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(urlStr); } catch (e) { return reject(e); }
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request({
      hostname: u.hostname,
      port: u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      method: 'GET',
    }, (res) => {
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode >= 400) {
          const e = new Error('HTTP ' + res.statusCode + ' from ' + u.pathname);
          e.statusCode = res.statusCode;
          return reject(e);
        }
        try { resolve(JSON.parse(text)); }
        catch (e2) { reject(new Error('unparseable JSON from ' + u.pathname)); }
      });
    });
    req.setTimeout(timeoutMs, () => {
      const e = new Error('timeout after ' + timeoutMs + 'ms on ' + u.pathname);
      e.code = 'ETIMEDOUT';
      req.destroy(e);
    });
    req.on('error', reject);
    req.end();
  });
}

/**
 * Fetch RFPlex's public LLM status, cached. Accepts a max cache age so the
 * model-choice path (30s) and the yield check (5s) share one cache.
 * NEVER rejects — resolves the parsed JSON, or null when RFPlex is unreachable.
 */
function fetchRfplexStatus(maxAgeMs) {
  if (!cfg) return Promise.resolve(null);
  if (rfplexCache.ts && Date.now() - rfplexCache.ts < maxAgeMs) {
    return Promise.resolve(rfplexCache.val);
  }
  if (rfplexInFlight) return rfplexInFlight;
  rfplexInFlight = httpGetJson(cfg.rfplexStatusUrl, RFPLEX_TIMEOUT_MS)
    .then((j) => (j && typeof j === 'object') ? j : null)
    .catch(() => null)
    .then((val) => {
      rfplexCache = { ts: Date.now(), val };
      rfplexInFlight = null;
      return val;
    });
  return rfplexInFlight;
}

/**
 * Fetch /api/ps (loaded models), cached. On fetch failure returns the last
 * good (stale) entries if any — a stale pin reading beats none — else throws.
 */
async function fetchPs(maxAgeMs) {
  if (psCache.entries && Date.now() - psCache.ts < maxAgeMs) return psCache.entries;
  try {
    const j = await httpGetJson(apiUrl(cfg.ollamaUrl, '/api/ps'), OLLAMA_STATUS_TIMEOUT_MS);
    psCache = { ts: Date.now(), entries: Array.isArray(j.models) ? j.models : [] };
    return psCache.entries;
  } catch (e) {
    if (psCache.entries) return psCache.entries;
    throw e;
  }
}

/**
 * Given the currently loaded generation models, pick the one hiccup should
 * defer to: RFPlex's smart, then its fast, then preferred order, else first.
 */
function pickLoadedModel(loadedGen) {
  const names = [];
  for (const e of loadedGen) {
    const n = e.name || e.model;
    if (n && names.indexOf(n) === -1) names.push(n);
  }
  if (!names.length) return null;
  const rfNames = rfplexModelNames(rfplexCache.val);
  const prefs = [rfNames.smart, rfNames.fast]
    .concat((cfg && cfg.preferredModels) || [])
    .filter(Boolean);
  for (const p of prefs) if (names.indexOf(p) !== -1) return p;
  return names[0];
}

/** The honestly-offline view used before/without a successful refresh. */
function makeOfflineView() {
  const names = rfplexModelNames(rfplexCache.val);
  return {
    available: false,
    model: null,
    source: null,
    rfplexModel: names.smart || names.fast || null,
    rfplexReachable: rfplexCache.val != null,
  };
}

/**
 * Compute the model-choice view. Never throws — degrades to an offline view.
 * Order (contract §LLM policy 1): RFPlex's smart-if-installed → fast-if-
 * installed → currently-loaded generation model → first preferred installed.
 * Then the eviction guard: if the choice is not loaded while some generation
 * model IS loaded, use the loaded one instead (never evict RFPlex's model).
 */
async function computeModelChoice() {
  const rf = await fetchRfplexStatus(MODEL_CACHE_MS);
  const rfNames = rfplexModelNames(rf);
  const base = {
    rfplexModel: rfNames.smart || rfNames.fast || null,
    rfplexReachable: rf != null,
  };

  let tagsJson = null;
  try {
    tagsJson = await httpGetJson(apiUrl(cfg.ollamaUrl, '/api/tags'), OLLAMA_STATUS_TIMEOUT_MS);
  } catch (e) { /* Ollama unreachable */ }
  if (!tagsJson || !Array.isArray(tagsJson.models)) {
    return Object.assign({ available: false, model: null, source: null }, base);
  }
  const installed = new Set(tagsJson.models.map((m) => m && m.name).filter(Boolean));

  let psEntries = [];
  try { psEntries = await fetchPs(0); } catch (e) { psEntries = []; }
  const loadedGen = psEntries.filter((e) => e && !isEmbeddingName(e.name || e.model));
  const loadedNames = new Set();
  for (const e of loadedGen) {
    if (e.name) loadedNames.add(e.name);
    if (e.model) loadedNames.add(e.model);
  }

  let model = null;
  let source = null;
  if (rf) {
    if (rfNames.smart && installed.has(rfNames.smart)) { model = rfNames.smart; source = 'rfplex'; }
    else if (rfNames.fast && installed.has(rfNames.fast)) { model = rfNames.fast; source = 'rfplex'; }
  }
  if (!model && loadedGen.length) {
    model = pickLoadedModel(loadedGen);
    source = model ? 'loaded' : null;
  }
  if (!model) {
    for (const p of cfg.preferredModels) {
      if (installed.has(p)) { model = p; source = 'preferred'; break; }
    }
  }
  // Eviction guard: never trigger a load of a different model while any
  // generation model is loaded — use the loaded one.
  if (model && loadedGen.length && !loadedNames.has(model)) {
    const loaded = pickLoadedModel(loadedGen);
    if (loaded) { model = loaded; source = 'loaded'; }
  }

  return Object.assign({ available: !!model, model, source: model ? source : null }, base);
}

/**
 * Refresh the cached model-choice view. Shared in-flight; NEVER rejects.
 */
function refreshModelChoice() {
  if (refreshing) return refreshing;
  refreshing = computeModelChoice()
    .catch(() => makeOfflineView())
    .then((v) => {
      view = v;
      viewTs = Date.now();
      refreshing = null;
      return v;
    });
  return refreshing;
}

/**
 * Yield to RFPlex: while its status says engine_reachable && accepting_jobs
 * === false, wait 3s and re-check, up to 10 times, then proceed anyway.
 */
async function yieldToRfplex() {
  for (let i = 0; i < YIELD_MAX_CHECKS; i++) {
    const rf = await fetchRfplexStatus(YIELD_CACHE_MS);
    if (!rf || !rf.engine_reachable || rf.accepting_jobs !== false) return;
    await sleep(YIELD_WAIT_MS);
  }
  // Gate stayed closed for ~30s of checks — proceed anyway per the contract.
}

/**
 * Dispatch-time re-check against /api/ps: re-apply the eviction guard with
 * fresh data and decide keep_alive for the model we actually use.
 * Returns { model, keepAlive } — keepAlive -1 preserves an RFPlex pin,
 * '5m' otherwise (hiccup never extends residency beyond that).
 */
async function pickAtDispatch(model) {
  let entries = null;
  try { entries = await fetchPs(YIELD_CACHE_MS); } catch (e) { entries = null; }
  if (!entries) return { model, keepAlive: '5m' };
  const loadedGen = entries.filter((e) => e && !isEmbeddingName(e.name || e.model));
  const loadedNames = new Set();
  for (const e of loadedGen) {
    if (e.name) loadedNames.add(e.name);
    if (e.model) loadedNames.add(e.model);
  }
  let chosen = model;
  if (loadedGen.length && !loadedNames.has(model)) {
    chosen = pickLoadedModel(loadedGen) || model;
  }
  const entry = entries.find((e) => e && (e.name === chosen || e.model === chosen)) || null;
  return { model: chosen, keepAlive: isPinned(entry) ? -1 : '5m' };
}

/** Build the non-streaming /api/chat body (contract §LLM policy 4-5). */
function buildChatBody(model, system, messages, keepAlive) {
  const msgs = [];
  if (system) msgs.push({ role: 'system', content: String(system) });
  for (const m of messages) {
    msgs.push({ role: m && m.role === 'assistant' ? 'assistant' : 'user',
                content: String((m && m.content) || '') });
  }
  const body = {
    model,
    messages: msgs,
    stream: false,
    keep_alive: keepAlive,
    options: { num_ctx: 8192, temperature: 0.2, num_predict: 700 },
  };
  // qwen3* models think by default — 2-5× more verbose; RFPlex disables it too.
  if (/^qwen3/.test(model)) body.think = false;
  return body;
}

/** One non-streaming POST /api/chat attempt. Resolves {text, model}. */
function chatOnce(body) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL('/api/chat', cfg.ollamaUrl); } catch (e) { return reject(e); }
    const lib = u.protocol === 'https:' ? https : http;
    const data = JSON.stringify(body);
    const req = lib.request({
      hostname: u.hostname,
      port: u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
    }, (res) => {
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode >= 400) {
          const e = new Error('Ollama HTTP ' + res.statusCode + ': ' + text.slice(0, 200));
          e.statusCode = res.statusCode;
          return reject(e);
        }
        let j;
        try { j = JSON.parse(text); }
        catch (e2) { return reject(new Error('Ollama returned an unparseable response')); }
        if (j && j.error) return reject(new Error('Ollama error: ' + String(j.error).slice(0, 200)));
        const content = (j && j.message && typeof j.message.content === 'string')
          ? j.message.content : '';
        resolve({ text: content, model: (j && j.model) || body.model });
      });
    });
    req.setTimeout(CHAT_TIMEOUT_MS, () => {
      const e = new Error('LLM request timed out after ' + (CHAT_TIMEOUT_MS / 1000) + 's');
      e.code = 'ETIMEDOUT';
      req.destroy(e);
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

/** Retry only on 5xx or connection-refused (contract §LLM policy 4). */
function isRetryable(e) {
  return !!e && (e.code === 'ECONNREFUSED' || (typeof e.statusCode === 'number' && e.statusCode >= 500));
}

/** Ensure the error carries a friendly userMessage before it leaves askLlm. */
function withUserMessage(e) {
  const err = (e instanceof Error) ? e : new Error(String(e));
  if (err.userMessage) return err;
  if (err.code === 'ETIMEDOUT') {
    err.userMessage = 'The local AI model took too long to answer — it may be busy with RFPlex work. Try again in a minute.';
  } else if (err.code === 'ECONNREFUSED' || err.code === 'EHOSTUNREACH' || err.code === 'ENOTFOUND') {
    err.userMessage = 'Could not reach the local AI engine, so chat is offline. Everything else in hiccup still works.';
  } else if (typeof err.statusCode === 'number') {
    err.userMessage = 'The local AI engine returned an error — try again in a moment.';
  } else {
    err.userMessage = 'The AI assistant hit an unexpected error — try again in a moment.';
  }
  return err;
}

/** Run one queued job: model choice → yield → keep_alive → chat (+1 retry). */
async function runJob(item) {
  if (!cfg) {
    const e = new Error('llm not initialised — call initLlm(config) first');
    e.code = 'not-initialized';
    e.userMessage = 'The AI assistant is not set up yet — try again shortly.';
    throw e;
  }
  const v = (view && Date.now() - viewTs < MODEL_CACHE_MS) ? view : await refreshModelChoice();
  if (!v || !v.available || !v.model) {
    const e = new Error('no usable LLM (Ollama unreachable or no acceptable model)');
    e.code = 'unavailable';
    e.userMessage = 'No local AI model is available right now, so chat is offline. All analysis features still work.';
    throw e;
  }
  await yieldToRfplex();
  const pick = await pickAtDispatch(v.model);
  const body = buildChatBody(pick.model, item.system, item.messages, pick.keepAlive);
  try {
    return await chatOnce(body);
  } catch (e) {
    if (isRetryable(e)) {
      await sleep(RETRY_DELAY_MS);
      try { return await chatOnce(body); }
      catch (e2) { throw withUserMessage(e2); }
    }
    throw withUserMessage(e);
  }
}

/** FIFO drain, concurrency 1. Settlement of one job never blocks the next. */
function drain() {
  if (active || !queue.length) return;
  const item = queue.shift();
  active = 1;
  runJob(item)
    .then(
      (r) => { try { item.resolve(r); } catch (e) { /* consumer threw */ } },
      (e) => { try { item.reject(withUserMessage(e)); } catch (e2) { /* consumer threw */ } }
    )
    .then(() => { active = 0; drain(); });
}

// ── Exports ────────────────────────────────────────────────────────────────

/**
 * Initialise (or re-initialise) the LLM client.
 * Resets caches and kicks off a background model-choice refresh; safe to call
 * with Ollama/RFPlex down — nothing here throws or leaves an unhandled
 * rejection.
 *
 * @param {object} config - app config; the keys used here:
 * @param {string} [config.ollamaUrl='http://127.0.0.1:11434']
 * @param {string} [config.rfplexStatusUrl='http://127.0.0.1:3001/api/status/llm']
 * @param {string[]} [config.preferredModels] - fallback model order when
 *   RFPlex is unreachable and nothing is loaded.
 */
function initLlm(config) {
  const c = config || {};
  cfg = {
    ollamaUrl: (typeof c.ollamaUrl === 'string' && c.ollamaUrl) ? c.ollamaUrl : DEFAULTS.ollamaUrl,
    rfplexStatusUrl: (typeof c.rfplexStatusUrl === 'string' && c.rfplexStatusUrl) ? c.rfplexStatusUrl : DEFAULTS.rfplexStatusUrl,
    preferredModels: (Array.isArray(c.preferredModels) && c.preferredModels.length)
      ? c.preferredModels.slice() : DEFAULTS.preferredModels.slice(),
  };
  rfplexCache = { ts: 0, val: null };
  rfplexInFlight = null;
  psCache = { ts: 0, entries: null };
  view = null;
  viewTs = 0;
  refreshing = null;
  refreshModelChoice().catch(() => { /* never rejects, belt and braces */ });
}

/**
 * Current LLM status, synchronous-fast: returns the last cached view
 * immediately and kicks off a background refresh when the cache is stale.
 * Before the first refresh completes it returns {available:false, ...}
 * honestly marked — it never blocks and never throws.
 *
 * @returns {{available: boolean, model: string|null,
 *   source: 'rfplex'|'loaded'|'preferred'|null, rfplexModel: string|null,
 *   rfplexReachable: boolean, queue: {depth: number, active: number, max: number}}}
 */
function getLlmStatus() {
  const q = { depth: queue.length, active, max: QUEUE_MAX };
  if (!cfg) {
    return { available: false, model: null, source: null, rfplexModel: null, rfplexReachable: false, queue: q };
  }
  if (!view || Date.now() - viewTs >= MODEL_CACHE_MS) {
    refreshModelChoice().catch(() => {});
  }
  const v = view || makeOfflineView();
  return {
    available: v.available,
    model: v.model,
    source: v.source,
    rfplexModel: v.rfplexModel,
    rfplexReachable: v.rfplexReachable,
    queue: q,
  };
}

/**
 * Ask the shared local LLM one question, non-streaming, via Ollama /api/chat.
 * Queued FIFO with concurrency 1; the queue holds at most 8 requests —
 * beyond that it rejects immediately with err.code='busy'. Yields to RFPlex
 * before dispatch (see module header). Every rejection carries a friendly
 * err.userMessage; there are no unhandled rejections on any path.
 *
 * @param {object} opts
 * @param {string} [opts.system] - system prompt (already-redacted content only).
 * @param {Array<{role: 'user'|'assistant', content: string}>} opts.messages
 * @returns {Promise<{text: string, model: string}>}
 */
function askLlm(opts) {
  return new Promise((resolve, reject) => {
    const o = opts || {};
    const messages = Array.isArray(o.messages) ? o.messages : null;
    if (!messages || !messages.length) {
      const e = new Error('askLlm requires a non-empty messages array');
      e.code = 'bad-request';
      e.userMessage = 'Nothing to ask — type a question first.';
      return reject(e);
    }
    if (active + queue.length >= QUEUE_MAX) {
      const e = new Error('LLM queue full (' + QUEUE_MAX + ' requests in flight)');
      e.code = 'busy';
      e.userMessage = 'The assistant is answering too many questions at once — try again in a few seconds.';
      return reject(e);
    }
    queue.push({ system: o.system || null, messages, resolve, reject });
    drain();
  });
}

module.exports = { initLlm, getLlmStatus, askLlm };
