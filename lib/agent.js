'use strict';
// agent.js — agentic chat over ONE capture: the model reads the analysis
// through tools instead of having a truncated summary stuffed into its prompt.
//
// WHY
//
// The one-shot prompt shows the model 20 findings and then TELLS it how many
// more exist that it cannot see ("and 40 more") — at num_ctx 8192 that cannot
// be fixed by raising the cap. Every tool here is a thin read-only accessor
// over the AnalysisJSON the deterministic pipeline already computed, so the
// model retrieves exactly what the question needs and nothing else. The HMR
// tools close a second loop: draft a rule, RUN it against the real failing
// message (lib/hmr-sim.js), read back what actually changed, revise.
//
// BOUNDARIES (the same ones the one-shot path promises)
//
//   - Read-only. No tool mutates the capture, the analysis, or any file.
//   - Citations still come only from the deterministic Advice objects and KB
//     excerpts — now via get_advice / search_kb results instead of a prompt
//     block, which gives the model somewhere to look instead of a reason to
//     guess.
//   - GPU budget: the loop makes at most MAX_MODEL_CALLS model calls and
//     LOOP_WALL_MS wall-clock total; each queued call competes in llm.js's
//     FIFO like any other, so one agentic question cannot hold the single
//     Ollama slot hostage between iterations.
//   - Degrades to nothing: a model with no tool template (err.code
//     'no-tools') reports fellBack and the caller uses the one-shot path.
//
// Dependency shape: `ask` (llm.askLlm) and `kbSearch` are INJECTED per call,
// so the whole loop is testable with a scripted fake and no server. The two
// HMR modules are required lazily inside their tools — if either is missing
// the other eight tools still work.

// 8, not 6: a real question ("diagnose this AND draft the fix AND verify it")
// legitimately spends 1 orient + 3-4 evidence + 1 draft + 1 simulate + 1 final.
// At 6 the model was observed live promising a simulation it no longer had
// budget to run. Warm calls are ~2s each; the wall clamp below still bounds
// the whole loop.
const MAX_MODEL_CALLS = 8;      // model asks per question, final answer included
const LOOP_WALL_MS = 150000;    // whole-loop budget on top of llm.js's per-call 120s
const MAX_CALLS_PER_TURN = 5;   // tool calls executed from one model turn
const TOOL_RESULT_MAX = 4000;   // chars of serialized result handed back per call
const RAW_MESSAGE_MAX = 8000;   // chars of raw SIP accepted/returned in one tool

function clampJson(obj) {
  let s;
  try { s = JSON.stringify(obj); } catch (e) { s = JSON.stringify({ error: 'unserialisable result' }); }
  if (s.length > TOOL_RESULT_MAX) {
    s = s.slice(0, TOOL_RESULT_MAX) +
      '"...[truncated — ask again with a narrower filter or a specific id]';
  }
  return s;
}

function shortTs(ts) {
  if (ts == null) return null;
  const s = String(ts);
  // keep ISO timestamps readable but compact: time part only when same-day noise
  return s.length > 24 ? s.slice(0, 24) : s;
}

/** One-line row for a SIP/H.323 message. */
function messageRow(m, legOf) {
  const line = m.isRequest
    ? (m.method || '?') + ' ' + (m.requestUri || '')
    : String(m.status || '?') + ' ' + (m.reason || '') + (m.method ? ' (' + m.method + ')' : '');
  return {
    id: m.id, ts: shortTs(m.ts), leg: legOf[m.id] || null,
    line: line.trim().slice(0, 120),
    from: m.fromUri ? String(m.fromUri).slice(0, 60) : undefined,
    to: m.toUri ? String(m.toUri).slice(0, 60) : undefined,
    retransOf: m.retransOf || undefined,
  };
}

function legSummary(leg) {
  if (!leg) return null;
  return {
    id: leg.id, protocol: leg.protocol, kind: leg.kind,
    from: leg.from, to: leg.to, state: leg.state,
    failCode: leg.failCode != null ? leg.failCode : undefined,
    startTs: shortTs(leg.startTs), endTs: shortTs(leg.endTs),
    transport: leg.transport,
    path: (leg.src || '?') + ':' + (leg.sport || '?') + ' -> ' + (leg.dst || '?') + ':' + (leg.dport || '?'),
    messages: Array.isArray(leg.msgIds) ? leg.msgIds.length : 0,
  };
}

/**
 * Build the tool registry, closed over one capture's analysis.
 * Every run() returns a plain object; throwing is allowed (the loop catches
 * and reports the message to the model as {error}).
 */
function buildTools(analysis, kbSearch) {
  const legOf = {};
  for (const leg of analysis.legs || []) {
    for (const mid of leg.msgIds || []) legOf[mid] = leg.id;
  }
  const adviceOf = {}; // findingId -> [adviceId]
  for (const a of analysis.advice || []) {
    for (const fid of a.findingIds || []) (adviceOf[fid] = adviceOf[fid] || []).push(a.id);
  }
  const msgById = new Map((analysis.messages || []).map((m) => [m.id, m]));

  const tools = [];
  const add = (name, description, properties, required, run) => {
    tools.push({
      def: {
        type: 'function',
        function: { name, description, parameters: { type: 'object', properties, required: required || [] } },
      },
      run,
    });
  };

  add('list_findings',
    'Every finding in this capture (the prompt shows only counts). Optional severity filter: crit|warn|notice|info.',
    { severity: { type: 'string', description: 'crit, warn, notice or info — omit for all' } },
    [],
    (args) => {
      const sev = args && args.severity ? String(args.severity) : null;
      const list = (analysis.findings || [])
        .filter((f) => f && (!sev || f.severity === sev))
        .map((f) => ({
          id: f.id, severity: f.severity, title: f.title,
          detail: f.detail ? String(f.detail).slice(0, 200) : undefined,
          callIds: (f.callIds || []).slice(0, 4),
          msgIds: (f.msgIds || []).slice(0, 6),
          adviceIds: adviceOf[f.id] || undefined,
        }));
      return { count: list.length, findings: list };
    });

  add('get_advice',
    'Full detail of one deterministic Advice object by id: what is wrong, why it matters, the mechanism, vendor fixes, and the ONLY citations you may quote.',
    { id: { type: 'string', description: 'advice id, e.g. a1 (see adviceIds on findings)' } },
    ['id'],
    (args) => {
      const id = String((args && args.id) || '');
      const a = (analysis.advice || []).find((x) => x && x.id === id);
      if (!a) {
        return { error: 'no advice with id ' + id, available: (analysis.advice || []).map((x) => x && x.id) };
      }
      return a;
    });

  add('list_calls',
    'Every correlated call with its legs: who called whom, state, failure code, pairing confidence.',
    {}, [],
    () => {
      const legById = new Map((analysis.legs || []).map((l) => [l.id, l]));
      const calls = (analysis.calls || []).map((c) => ({
        id: c.id, type: c.type, state: c.state, confidence: c.confidence,
        legs: (c.legIds || []).map((lid) => legSummary(legById.get(lid)) || { id: lid }),
      }));
      return { count: calls.length, calls };
    });

  add('get_call',
    'One call in depth: legs, the message sequence, and the ingress/egress differences (what the SBC changed between legs).',
    { id: { type: 'string', description: 'call id, e.g. c1' } },
    ['id'],
    (args) => {
      const id = String((args && args.id) || '');
      const c = (analysis.calls || []).find((x) => x && x.id === id);
      if (!c) return { error: 'no call with id ' + id, available: (analysis.calls || []).map((x) => x && x.id) };
      const legById = new Map((analysis.legs || []).map((l) => [l.id, l]));
      const rows = [];
      for (const lid of c.legIds || []) {
        const leg = legById.get(lid);
        for (const mid of (leg && leg.msgIds) || []) {
          const m = msgById.get(mid);
          if (m) rows.push(messageRow(m, legOf));
        }
      }
      rows.sort((a, b) => String(a.ts).localeCompare(String(b.ts)));
      const diffs = [];
      for (const d of c.diffs || []) {
        for (const cat of (d.diff && d.diff.categories) || []) {
          for (const it of cat.items || []) {
            diffs.push({
              between: d.a + '->' + d.b, category: cat.key, tag: it.tag,
              label: it.label,
              ingress: it.ingress != null ? String(it.ingress).slice(0, 120) : null,
              egress: it.egress != null ? String(it.egress).slice(0, 120) : null,
            });
            if (diffs.length >= 25) break;
          }
          if (diffs.length >= 25) break;
        }
        if (diffs.length >= 25) break;
      }
      return {
        id: c.id, type: c.type, state: c.state, confidence: c.confidence,
        pairings: c.pairings, legs: (c.legIds || []).map((lid) => legSummary(legById.get(lid)) || { id: lid }),
        messages: rows.slice(0, 60),
        truncatedMessages: rows.length > 60 ? rows.length - 60 : 0,
        diffs,
      };
    });

  add('search_messages',
    'Find SIP messages. Filters combine with AND: text (case-insensitive substring over the raw message), method (INVITE, BYE...; responses match their CSeq method), status (exact like 486, or a class like 4xx), callId, legId.',
    {
      text: { type: 'string', description: 'substring to find in the raw message' },
      method: { type: 'string' },
      status: { type: 'string', description: 'e.g. "486" or "4xx"' },
      callId: { type: 'string' }, legId: { type: 'string' },
    },
    [],
    (args) => {
      const a = args || {};
      const text = a.text ? String(a.text).toLowerCase() : null;
      const method = a.method ? String(a.method).toUpperCase() : null;
      const status = a.status != null && a.status !== '' ? String(a.status) : null;
      const legId = a.legId ? String(a.legId) : null;
      let msgIdSet = null;
      if (a.callId) {
        const c = (analysis.calls || []).find((x) => x && x.id === String(a.callId));
        if (!c) return { error: 'no call with id ' + a.callId };
        msgIdSet = new Set();
        const legById = new Map((analysis.legs || []).map((l) => [l.id, l]));
        for (const lid of c.legIds || []) {
          for (const mid of (legById.get(lid) || {}).msgIds || []) msgIdSet.add(mid);
        }
      }
      const rows = [];
      let matched = 0;
      for (const m of analysis.messages || []) {
        if (!m || m.protocol !== 'sip') continue;
        if (msgIdSet && !msgIdSet.has(m.id)) continue;
        if (legId && legOf[m.id] !== legId) continue;
        if (method && String(m.method || '').toUpperCase() !== method) continue;
        if (status) {
          if (m.isRequest) continue;
          const s = String(m.status || '');
          const cls = status.match(/^([1-6])xx$/i);
          if (cls) { if (s.charAt(0) !== cls[1]) continue; }
          else if (s !== status) continue;
        }
        if (text && String(m.raw || '').toLowerCase().indexOf(text) === -1) continue;
        matched++;
        if (rows.length < 30) rows.push(messageRow(m, legOf));
      }
      return { matched, shown: rows.length, messages: rows };
    });

  add('get_message',
    'The full raw text of one message by id (credentials already redacted).',
    { id: { type: 'string', description: 'message id, e.g. s12' } },
    ['id'],
    (args) => {
      const id = String((args && args.id) || '');
      const m = msgById.get(id);
      if (!m) return { error: 'no message with id ' + id };
      let raw = String(m.raw || '');
      let truncated = false;
      if (raw.length > RAW_MESSAGE_MAX) { raw = raw.slice(0, RAW_MESSAGE_MAX); truncated = true; }
      return {
        id: m.id, ts: shortTs(m.ts), leg: legOf[m.id] || null,
        transport: m.transport, retransOf: m.retransOf || undefined,
        raw, truncated: truncated || undefined,
      };
    });

  add('get_media_quality',
    'RTP/RTCP quality per stream (loss, jitter, gaps, estimated MOS, one-way audio) plus DNS/ICE/Diameter observations. Optional callId filter.',
    { callId: { type: 'string' } },
    [],
    (args) => {
      const callId = args && args.callId ? String(args.callId) : null;
      const media = analysis.media || {};
      const streams = (media.streams || [])
        .filter((s) => s && (!callId || (s.callIds || []).indexOf(callId) !== -1))
        .slice(0, 12)
        .map((s) => ({
          id: s.id, kind: s.kind, codec: s.codec,
          path: (s.src || '?') + ':' + (s.sport != null ? s.sport : '?') + ' -> ' + (s.dst || '?') + ':' + (s.dport != null ? s.dport : '?'),
          packets: s.packets, lossPct: s.lossPct,
          meanJitterMs: s.meanJitterMs, maxJitterMs: s.maxJitterMs, maxGapMs: s.maxGapMs,
          mos: s.mos, mosNote: s.mos != null ? 'simplified-E-model ESTIMATE' : undefined,
          oneWay: s.oneWay || undefined, legIds: s.legIds, callIds: s.callIds,
        }));
      const aux = (analysis.aux || [])
        .filter((x) => x && (!callId || (x.callIds || []).indexOf(callId) !== -1))
        .slice(0, 12)
        .map((x) => ({ id: x.id, protocol: x.protocol, ts: shortTs(x.ts), summary: x.summary }));
      return { streams, rtcpReports: ((media.rtcp || []).length), aux };
    });

  if (typeof kbSearch === 'function') {
    add('search_kb',
      "Keyword search over the account's own uploaded vendor configuration guides. Use for vendor-specific config questions; excerpts returned here are citable as guide references.",
      { query: { type: 'string' } },
      ['query'],
      (args) => {
        const q = String((args && args.query) || '').trim();
        if (!q) return { error: 'empty query' };
        const hits = kbSearch(q, 4) || [];
        return {
          hits: hits.map((h) => ({
            docTitle: h.docTitle, page: h.page, heading: h.heading,
            text: String(h.text || '').slice(0, 400),
          })),
        };
      });
  }

  add('generate_hmr_rule',
    'Draft a header-manipulation rule from a plain-English description (deterministic parser — no guessing). Returns the rule IR plus vendor config drafts, or questions when the description is ambiguous. Call it AT MOST ONCE: if the draft comes back with questions or a blank value, do not retry with rephrasings — take the returned rule object, fill in the missing value/conditions yourself, and pass it straight to simulate_hmr.',
    { description: { type: 'string', description: 'e.g. "strip the P-Asserted-Identity header on outbound INVITE requests"' } },
    ['description'],
    (args) => {
      let gen;
      try { gen = require('./hmr-generate'); }
      catch (e) { return { error: 'the rule generator is not deployed on this server' }; }
      const r = gen.generateRule(String((args && args.description) || ''));
      // Drafts for all three vendors are large; return the rule + one generic
      // draft here and let simulate_hmr render the target vendor on demand.
      return {
        ok: r.ok, rule: r.rule, matchedIntent: r.matchedIntent,
        assumptions: r.assumptions, warnings: r.warnings, questions: r.questions,
        genericDraft: r.drafts && r.drafts.generic ? String(r.drafts.generic).slice(0, 1200) : null,
      };
    });

  add('simulate_hmr',
    'Run a header-manipulation rule against a REAL message and see exactly what changes: scope check, each condition pass/fail, before/after of every touched header. Use it to VERIFY a rule before presenting it. Pass the rule IR (from generate_hmr_rule, or hand-built) plus a message_id from this capture (or raw_message text). Optional vendor (oracle-acme|audiocodes|ribbon) adds a config draft.',
    {
      rule: { type: 'object', description: 'the rule IR: {operation, target:{header,element}, value:{kind:"literal",text}, conditions:[{element,comparison,value}], scope:{msgType,methods}}' },
      message_id: { type: 'string', description: 'a message id from this capture, e.g. s12' },
      raw_message: { type: 'string', description: 'a full SIP message pasted as text (alternative to message_id)' },
      vendor: { type: 'string', description: 'oracle-acme, audiocodes or ribbon — adds a rendered config draft' },
    },
    ['rule'],
    (args) => {
      const a = args || {};
      let sim;
      try { sim = require('./hmr-sim'); }
      catch (e) { return { error: 'the simulator is not deployed on this server' }; }
      let raw = null;
      if (a.message_id) {
        const m = msgById.get(String(a.message_id));
        if (!m) return { error: 'no message with id ' + a.message_id };
        if (m.protocol !== 'sip') return { error: a.message_id + ' is not a SIP message' };
        raw = String(m.raw || '');
      } else if (a.raw_message) {
        raw = String(a.raw_message).slice(0, RAW_MESSAGE_MAX);
      } else {
        return { error: 'pass message_id (preferred) or raw_message' };
      }
      const result = sim.applyRule(a.rule, raw);
      // The full before text is already known to the model (it fetched or
      // wrote the message); returning after + per-action before/after is
      // enough and keeps the result inside the size cap.
      const compact = {
        ok: result.ok, problems: result.problems, parseError: result.parseError,
        inScope: result.inScope, scopeNotes: result.scopeNotes,
        matched: result.matched, conditions: result.conditions,
        actions: result.actions, changed: result.changed,
        stored: result.stored, warnings: result.warnings,
        after: result.changed ? String(result.after).slice(0, 2500) : undefined,
      };
      if (a.vendor) {
        try {
          const hmr = require('./hmr');
          compact.vendorDraft = String(hmr.renderRule(a.rule, String(a.vendor))).slice(0, 1500);
        } catch (e) {
          compact.vendorDraftError = 'could not render for ' + a.vendor;
        }
      }
      return compact;
    });

  return tools;
}

/** The system prompt: persona + orientation. Depth comes through tools. */
function buildAgentSystem(analysis) {
  const parts = [];
  parts.push(
    'You are hiccup, an expert SIP/SBC/H.323 engineer explaining a capture to an ' +
    'SBC-curious engineer. You have TOOLS that read this capture — the analysis is ' +
    'ground truth, so look things up rather than guessing; quote real message/leg/' +
    'call ids and timestamps. Phone-number and credential material is already ' +
    'redacted; never invent replacements. Keep answers precise and practical.'
  );
  const stats = analysis.stats || {};
  parts.push('Capture stats: ' + JSON.stringify(stats));
  const s = analysis.scenario;
  if (s && s.primary) {
    parts.push('Scenario: ' + s.primary +
      (typeof s.confidence === 'number' ? ' (confidence ' + s.confidence.toFixed(2) + ')' : '') +
      (s.detail ? '\n' + String(s.detail).slice(0, 500) : ''));
  }
  const findings = analysis.findings || [];
  const counts = { crit: 0, warn: 0, notice: 0, info: 0 };
  for (const f of findings) if (f && counts[f.severity] != null) counts[f.severity]++;
  parts.push('Findings: ' + findings.length + ' total (crit ' + counts.crit + ', warn ' +
    counts.warn + ', notice ' + counts.notice + ', info ' + counts.info +
    ') — use list_findings to read them.');
  const notable = (analysis.indicators || [])
    .filter((i) => i && (i.state === 'issue' || i.state === 'partial'))
    .map((i) => i.key + '=' + i.state);
  if (notable.length) parts.push('Indicators flagged: ' + notable.join(', '));
  parts.push(
    'Citation rules (strict): the ONLY protocol citations you may give are the ones ' +
    'returned by get_advice (citations field) and search_kb excerpts. Never invent, ' +
    'guess or recall an RFC number, section number, 3GPP TS or ITU-T reference — if ' +
    'no tool result carries the reference, explain the mechanism in your own words ' +
    'and name the document to look it up in, without a section number. Any vendor ' +
    'configuration you produce is a reviewable draft, never a verified change; when ' +
    'you draft a header-manipulation rule, verify it with simulate_hmr against the ' +
    'real message before presenting it, and show what changed.'
  );
  return parts.join('\n\n');
}

/**
 * Run the agentic loop for one question.
 *
 * @param {object} opts
 * @param {object} opts.analysis   AnalysisJSON (ground truth, read-only)
 * @param {Array<{role:string,content:string}>} opts.messages chat history,
 *   most recent last (the same shape handleChat already builds)
 * @param {Function} opts.ask      llm.askLlm (injected for testability)
 * @param {Function} [opts.kbSearch] (query, k) -> hits, account-scoped
 * @param {string} [opts.scopeHint] one sentence naming the UI element the
 *   user has focused (a call/message/finding id) — steers the first tool call
 * @param {number} [opts.priority] llm queue priority for every call
 * @param {number} [opts.maxCalls] override MAX_MODEL_CALLS (tests)
 * @param {number} [opts.wallMs]   override LOOP_WALL_MS (tests)
 * @returns {Promise<{reply:string, model:string|null, calls:number,
 *   trace:Array<{tool:string,ok:boolean,ms:number,args:string}>, fellBack:boolean}>}
 */
async function runAgent(opts) {
  const o = opts || {};
  const analysis = o.analysis || {};
  const ask = o.ask;
  if (typeof ask !== 'function') throw new Error('runAgent needs an injected ask()');
  const maxCalls = Number(o.maxCalls) > 0 ? Number(o.maxCalls) : MAX_MODEL_CALLS;
  const wallMs = Number(o.wallMs) > 0 ? Number(o.wallMs) : LOOP_WALL_MS;
  const started = Date.now();

  const registry = buildTools(analysis, o.kbSearch);
  const byName = new Map(registry.map((t) => [t.def.function.name, t]));
  const toolDefs = registry.map((t) => t.def);
  let system = buildAgentSystem(analysis);
  if (o.scopeHint) system += '\n\n' + String(o.scopeHint).slice(0, 300);

  const convo = (o.messages || []).map((m) => ({
    role: m && m.role === 'assistant' ? 'assistant' : 'user',
    content: String((m && m.content) || ''),
  }));
  const trace = [];
  const verifiedCitations = new Set();
  const toolUse = {}; // per-tool call counts, for the circling nudge below
  let model = null;
  let calls = 0;
  let recovered = false;

  const FINAL_NOTICE = '\n\nTool budget for this question is exhausted — give your ' +
    'complete final answer now from what you already retrieved. Do not promise or ' +
    'announce further inspection.';

  let finalNudged = false;
  while (true) {
    const budgetLeft = !recovered && calls < maxCalls - 1 && (Date.now() - started) < wallMs;
    if (!budgetLeft && !finalNudged) {
      // The system-suffix notice alone is not enough — observed live, the
      // model still emitted a one-line lead-in to a tool call it could no
      // longer make. A user-turn instruction is what qwen actually obeys.
      finalNudged = true;
      convo.push({
        role: 'user',
        content: '(no further tool use is possible — write your complete final answer ' +
          'now from the evidence gathered above; if something could not be verified, ' +
          'say so plainly instead of promising to check)',
      });
    }
    let out;
    try {
      // The final call is forced tool-free AND told so — without the notice
      // the model narrates as if it could keep digging ("let's inspect...")
      // and the answer trails off mid-plan (seen live on qwen3.5:9b).
      out = await ask({
        system: budgetLeft ? system : system + FINAL_NOTICE,
        messages: convo,
        tools: budgetLeft ? toolDefs : undefined,
        // A synthesis that stitches several tool results together clips
        // mid-sentence at the default 700 (seen live). num_predict is a CAP,
        // not a target — tool-request turns stop early anyway, so the higher
        // ceiling costs nothing except on the one turn that needs it. 1200 is
        // llm.js's hard clamp.
        numPredict: 1200,
        priority: o.priority,
      });
    } catch (e) {
      if (e && e.code === 'no-tools') {
        return { reply: '', model: null, calls, trace, fellBack: true };
      }
      // Mid-loop model failure with evidence already gathered — seen live as
      // Ollama 500 "XML syntax error" when qwen3.5 garbles its own tool-call
      // markup. Don't throw the gathered tool results away: ONE recovery
      // attempt without tools (no tools offered → the model cannot emit the
      // markup that broke). busy/unavailable still propagate — the route
      // maps those to 429/503 — and a recovery failure rethrows.
      const salvageable = !recovered && calls > 0 &&
        convo.some((m) => m.role === 'tool') &&
        !(e && (e.code === 'busy' || e.code === 'unavailable' || e.code === 'not-initialized'));
      if (!salvageable) throw e;
      recovered = true;
      continue;
    }
    calls++;
    model = out.model || model;
    const toolCalls = Array.isArray(out.toolCalls) ? out.toolCalls : [];

    if (!toolCalls.length || !budgetLeft) {
      // An empty answer with nothing left to do is a dead end: the caller can
      // only fall back to the one-shot path, which throws away every tool
      // result gathered here and re-asks from the truncated summary. Seen live
      // on qwen3.5:9b, which occasionally returns empty content instead of a
      // first tool call. One tool-free retry costs a single model call and
      // keeps the evidence; the same one-shot fallback still catches it if
      // this comes back empty too.
      if (!String(out.text || '').trim() && !recovered) {
        recovered = true;
        continue;
      }
      const guarded = stripUnverifiedCitations(String(out.text || ''), verifiedCitations);
      return {
        reply: guarded.text, model, calls, trace, fellBack: false,
        citationsStripped: guarded.stripped,
      };
    }

    // Echo the assistant turn (with its tool_calls) then answer each call.
    convo.push({ role: 'assistant', content: String(out.text || ''), tool_calls: toolCalls });
    for (const tc of toolCalls.slice(0, MAX_CALLS_PER_TURN)) {
      const fn = tc && tc.function ? tc.function : {};
      const name = String(fn.name || '');
      let args = fn.arguments;
      if (typeof args === 'string') { try { args = JSON.parse(args); } catch (e) { args = {}; } }
      if (!args || typeof args !== 'object') args = {};
      const t0 = Date.now();
      let result;
      const tool = byName.get(name);
      if (!tool) {
        result = { error: 'unknown tool: ' + name + '. Available: ' + registry.map((t) => t.def.function.name).join(', ') };
      } else {
        try { result = tool.run(args); }
        catch (e) { result = { error: 'tool failed: ' + ((e && e.message) || 'unknown error') }; }
      }
      let content = clampJson(result);
      collectRfcSections(content, verifiedCitations);
      collectStructuredCitations(result, verifiedCitations);
      // A model circling one tool (observed live: four generate_hmr_rule
      // rephrasings) burns the whole budget on nothing. From the third call
      // to the same tool, say so in the result it reads.
      toolUse[name] = (toolUse[name] || 0) + 1;
      if (toolUse[name] >= 3) {
        content += ' [NOTE: this is call #' + toolUse[name] + ' to ' + name +
          ' — if it is not producing what you need, use a different tool or answer with what you have]';
      }
      trace.push({
        tool: name, ok: !(result && result.error), ms: Date.now() - t0,
        args: clampArgs(args),
      });
      convo.push({ role: 'tool', content, tool_name: name });
    }
    if (toolCalls.length > MAX_CALLS_PER_TURN) {
      convo.push({
        role: 'tool', tool_name: 'system',
        content: JSON.stringify({ note: (toolCalls.length - MAX_CALLS_PER_TURN) + ' further tool call(s) in that turn were not executed — make fewer, more targeted calls' }),
      });
    }
  }
}

function clampArgs(args) {
  let s;
  try { s = JSON.stringify(args); } catch (e) { s = '{}'; }
  return s.length > 200 ? s.slice(0, 200) + '…' : s;
}

// ── citation guard ─────────────────────────────────────────────────────────
// hiccup's promise is that RFC section numbers are never invented. The system
// prompt says so, but a 9B model breaks the rule at the margin (observed live:
// a plausible-but-wrong "RFC 3261 §10.2"). So it is enforced deterministically,
// the way RFPlex filters invented prices: every RFC+section pair that appears
// in ANY tool result this request (advice citations, KB excerpts, raw
// messages) is "verified"; any other section number in the reply is stripped
// down to the bare RFC number, which is never wrong to say.

// Strict form for the REPLY side (prose) — this is what gets rewritten, so it
// must never grab across unrelated text.
const RFC_SECTION_RE = /RFC\s*(\d{3,5})\s*(?:[,:]\s*)?(?:§+|section)\s*([0-9]+(?:\.[0-9]+)*)/gi;
// Loose form for the COLLECTOR side — tool results are JSON, so quotes and
// key names sit between the RFC number and its section
// ("source":"RFC 3261","section":"Section 21.4.24").
const RFC_SECTION_LOOSE_RE = /RFC\s*(\d{3,5})[^0-9]{0,40}?(?:§+|section)[^0-9]{0,20}([0-9]+(?:\.[0-9]+)*)/gi;

/** Add every RFC+section pair found in `text` to `set` as 'nnnn|s.s.s'. */
function collectRfcSections(text, set) {
  const s = String(text == null ? '' : text);
  let m;
  RFC_SECTION_LOOSE_RE.lastIndex = 0;
  while ((m = RFC_SECTION_LOOSE_RE.exec(s)) !== null) {
    set.add(m[1] + '|' + m[2].replace(/\.$/, ''));
  }
}

/** Collect from a structured Citation list (get_advice results), no regex. */
function collectStructuredCitations(result, set) {
  if (!result || !Array.isArray(result.citations)) return;
  for (const c of result.citations) {
    if (!c || !c.source) continue;
    const rfc = /RFC\s*(\d{3,5})/i.exec(String(c.source));
    const sec = /([0-9]+(?:\.[0-9]+)*)/.exec(String(c.section || ''));
    if (rfc && sec) set.add(rfc[1] + '|' + sec[1].replace(/\.$/, ''));
  }
}

/**
 * Strip section numbers the tool results never carried; keep the RFC number.
 * Returns {text, stripped} — stripped counts how many were cut.
 */
function stripUnverifiedCitations(reply, verified) {
  let stripped = 0;
  const text = String(reply == null ? '' : reply).replace(RFC_SECTION_RE, (whole, rfc, section) => {
    if (verified.has(rfc + '|' + section.replace(/\.$/, ''))) return whole;
    stripped++;
    return 'RFC ' + rfc;
  });
  return { text, stripped };
}

module.exports = {
  runAgent,
  // exported for tests
  _buildTools: buildTools,
  _buildAgentSystem: buildAgentSystem,
  _collectRfcSections: collectRfcSections,
  _stripUnverifiedCitations: stripUnverifiedCitations,
  _limits: { MAX_MODEL_CALLS, LOOP_WALL_MS, MAX_CALLS_PER_TURN, TOOL_RESULT_MAX },
};
