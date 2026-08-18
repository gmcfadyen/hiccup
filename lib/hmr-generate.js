'use strict';
// hmr-generate.js — plain English -> an HMR rule in hiccup's vendor-neutral IR.
//
// WHY THIS IS BUILT THE WAY IT IS
//
// The output of this module becomes configuration someone pastes into a
// production SBC. A rule that is subtly wrong does not throw — it silently
// strips the wrong header on live calls. So the design is defensive in three
// specific ways, and none of them are decoration:
//
//   1. A DETERMINISTIC parser handles the common intents outright. "strip the
//      P-Asserted-Identity header on requests" does not need a language model,
//      and involving one introduces failure modes a lookup table does not have.
//
//   2. Nothing here writes vendor syntax. The generator only ever produces the
//      IR; lib/hmr.js's renderRule() turns it into Acme/AudioCodes/Ribbon
//      config — the same reviewed path a PARSED rule already goes through.
//      So a generated rule cannot emit syntax that a parsed rule could not.
//
//   3. Every result is round-tripped through explainRule(), so the caller can
//      show what hiccup UNDERSTOOD, in English, beside what the user asked for.
//      A mismatch there is the thing a human spots instantly and a confidence
//      score never surfaces.
//
// Unrecognised input produces QUESTIONS, never a guess. A confidently wrong
// rule is worse than an admission that the description was ambiguous.

const hmr = require('./hmr');

/** Operations lib/hmr.js's renderers actually implement. A closed set. */
const OPERATIONS = ['add', 'delete', 'modify', 'replace', 'store', 'none'];

/** Comparisons the condition renderers implement. */
const COMPARISONS = ['equals', 'contains', 'notcontains', 'exists', 'notexists', 'matches'];

const MSG_TYPES = ['request', 'reply', 'any'];

const SIP_METHODS = ['INVITE', 'ACK', 'BYE', 'CANCEL', 'OPTIONS', 'REGISTER',
  'INFO', 'PRACK', 'SUBSCRIBE', 'NOTIFY', 'UPDATE', 'MESSAGE', 'REFER', 'PUBLISH'];

/**
 * Headers worth recognising, with canonical casing. Compact forms are included
 * because engineers write "PAI" far more often than "P-Asserted-Identity".
 */
const HEADERS = {
  'p-asserted-identity': 'P-Asserted-Identity',
  'pai': 'P-Asserted-Identity',
  'p-preferred-identity': 'P-Preferred-Identity',
  'ppi': 'P-Preferred-Identity',
  'remote-party-id': 'Remote-Party-ID',
  'rpid': 'Remote-Party-ID',
  'from': 'From',
  'to': 'To',
  'contact': 'Contact',
  'via': 'Via',
  'diversion': 'Diversion',
  'history-info': 'History-Info',
  'referred-by': 'Referred-By',
  'refer-to': 'Refer-To',
  'user-agent': 'User-Agent',
  'server': 'Server',
  'call-info': 'Call-Info',
  'privacy': 'Privacy',
  'supported': 'Supported',
  'require': 'Require',
  'allow': 'Allow',
  'session-expires': 'Session-Expires',
  'min-se': 'Min-SE',
  'max-forwards': 'Max-Forwards',
  'record-route': 'Record-Route',
  'route': 'Route',
  'subject': 'Subject',
  'reason': 'Reason'
};

/** URI sub-parts a rule can target instead of the whole header. */
const ELEMENTS = {
  'user part': 'uri-user',
  'username': 'uri-user',
  'user': 'uri-user',
  'hostname': 'uri-host',
  'host': 'uri-host',
  'domain': 'uri-host',
  'port': 'uri-port',
  'display name': 'display-name',
  'parameter': 'uri-param',
  'param': 'uri-param'
};

function str(v) { return typeof v === 'string' ? v : ''; }
function lc(v) { return str(v).toLowerCase(); }
function escapeRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

/**
 * A value capture stops before a following clause word rather than running to
 * end-of-string, so "to X on outbound calls" does not pull "on outbound calls"
 * into the value. Shared by the add and replace intents via BOUNDARY.source.
 *
 * Built as a genuine regex LITERAL, not a hand-escaped string passed to `new
 * RegExp()` — a string literal's OWN escape processing turns `\b` into an
 * actual backspace character and silently drops the backslash from `\s`
 * (there is no \s string escape, so it decays to a literal "s"), which is
 * exactly backwards for building regex source text. `.source` sidesteps that
 * whole class of bug by reading the pattern back out verbatim.
 */
const BOUNDARY = /(?=\s+\b(?:on|when|if|for|unless|only|where)\b|[,.]|$)/i;

/**
 * Canonical header name from free text, or null. Longest match wins so "to"
 * cannot beat "history-info", and word boundaries stop "to" firing inside
 * "topology".
 */
function findHeader(text) {
  const t = lc(text);
  let best = null;
  let bestLen = 0;
  for (const key of Object.keys(HEADERS)) {
    const re = new RegExp('(^|[^a-z0-9-])' + escapeRe(key) + '($|[^a-z0-9-])', 'i');
    if (re.test(t) && key.length > bestLen) { best = HEADERS[key]; bestLen = key.length; }
  }
  if (!best) {
    // An X- header this table cannot know about.
    const m = t.match(/\b(x-[a-z0-9-]+)\b/i);
    if (m) best = m[1].replace(/\b\w/g, (c) => c.toUpperCase());
  }
  return best;
}

function findElement(text) {
  const t = lc(text);
  for (const key of Object.keys(ELEMENTS)) {
    if (new RegExp('\\b' + escapeRe(key) + '\\b').test(t)) return ELEMENTS[key];
  }
  return null;
}

function findMethods(text) {
  const t = str(text).toUpperCase();
  return SIP_METHODS.filter((m) => new RegExp('\\b' + m + '\\b').test(t));
}

/**
 * Message type and direction.
 *
 * Direction is the field engineers most often leave unstated, and a rule bound
 * to no interface NEVER RUNS — so an unstated direction becomes a recorded
 * assumption the caller must show, not a silent default.
 */
function findScope(text, assumptions) {
  const t = lc(text);
  const wantsReq = /\brequests?\b/.test(t);
  const wantsRes = /\bresponses?\b|\brepl(y|ies)\b/.test(t);

  let msgType = 'any';
  if (wantsReq && !wantsRes) msgType = 'request';
  else if (wantsRes && !wantsReq) msgType = 'reply';

  let direction = null;
  if (/\b(inbound|incoming|ingress)\b/.test(t)) direction = 'in';
  else if (/\b(outbound|outgoing|egress)\b/.test(t)) direction = 'out';
  if (!direction) {
    assumptions.push('No direction was stated, so the draft leaves it unbound. You must attach it to ' +
      'the right realm, session-agent or trunk group yourself — an unbound rule never runs.');
  }
  return { direction, msgType, methods: findMethods(text) };
}

/**
 * Turn a described pattern into a regex, and TEST it against any quoted
 * examples in the same sentence.
 *
 * A regex that silently fails to match is the commonest way an HMR rule looks
 * right and does nothing, so this reports what it tried and whether each
 * example matched, rather than handing back a bare pattern to be trusted.
 */
function buildRegex(text) {
  const t = str(text);
  const out = { pattern: null, explanation: null, tested: [] };

  let m = t.match(/\b(?:start(?:s|ing)? with|begin(?:s|ning)? with|prefixed with)\s+["']?(\+?[0-9]{1,15})["']?/i);
  if (m) {
    out.pattern = '^' + escapeRe(m[1]);
    out.explanation = 'matches a value beginning with ' + m[1];
  }

  if (!out.pattern) {
    m = t.match(/\b(?:end(?:s|ing)? with|suffixed with)\s+["']?([0-9]{1,15})["']?/i);
    if (m) {
      out.pattern = escapeRe(m[1]) + '$';
      out.explanation = 'matches a value ending with ' + m[1];
    }
  }

  if (!out.pattern) {
    m = t.match(/\bexactly\s+(\d{1,2})\s+digits?\b/i);
    if (m) {
      out.pattern = '^[0-9]{' + m[1] + '}$';
      out.explanation = 'matches exactly ' + m[1] + ' digits';
    }
  }

  if (!out.pattern && /\b(any|all|every)\b/.test(lc(t)) && !/\bexcept\b/.test(lc(t))) {
    out.pattern = '.*';
    out.explanation = 'matches anything';
  }

  if (out.pattern) {
    const examples = (t.match(/["'](\+?[0-9][0-9 ()-]{4,})["']/g) || [])
      .map((s) => s.replace(/["']/g, ''));
    for (const ex of examples.slice(0, 6)) {
      let matched = false;
      try { matched = new RegExp(out.pattern).test(ex); } catch (e) { matched = false; }
      out.tested.push({ input: ex, matched });
    }
  }
  return out;
}

/**
 * Deterministic intent table. Each entry recognises one common request
 * outright, keeping the common path entirely free of guesswork.
 *
 * Order matters: 'replace' is tested before 'add', because "replace the From
 * user with X" contains "with" and would otherwise be read as an add.
 */
const INTENTS = [
  {
    id: 'delete-header',
    test: (t) => /\b(strip|remove|delete|drop|get rid of|take out)\b/.test(t),
    build: (text) => {
      const header = findHeader(text);
      if (!header) return null;
      return { operation: 'delete', target: { header, element: null, index: null }, value: null };
    }
  },
  {
    id: 'replace-in-header',
    test: (t) => /\b(replace|rewrite|change|swap|substitute|overwrite|anonymi[sz]e)\b/.test(t),
    build: (text, ctx) => {
      const header = findHeader(text);
      if (!header) return null;
      const element = findElement(text);
      const m = text.match(new RegExp(/\b(?:with|to)\s+["']?([^"'\n,.]{1,120}?)["']?/.source + BOUNDARY.source, 'i'));
      const val = m ? m[1].trim() : null;
      if (!val) {
        ctx.warnings.push('No replacement value could be read from the description, so the draft leaves ' +
          'it blank. Fill it in before use.');
      }
      return {
        operation: element ? 'modify' : 'replace',
        target: { header, element, index: null },
        value: val ? { kind: 'literal', text: val } : null
      };
    }
  },
  {
    id: 'add-header',
    test: (t) => /\b(add|insert|set|stamp|put)\b/.test(t),
    build: (text, ctx) => {
      const header = findHeader(text);
      if (!header) return null;
      const m = text.match(new RegExp(/\b(?:to|=|:|with(?: the)? value)\s+["']?([^"'\n,.]{1,120}?)["']?/.source + BOUNDARY.source, 'i'));
      const val = m ? m[1].trim() : null;
      if (!val) {
        ctx.warnings.push('No value was given for the header to add, so the draft leaves it blank. ' +
          'Fill it in before use.');
      }
      return {
        operation: 'add',
        target: { header, element: null, index: null },
        value: val ? { kind: 'literal', text: val } : null
      };
    }
  },
  {
    id: 'store-header',
    test: (t) => /\b(store|save|remember|capture|stash)\b/.test(t),
    build: (text) => {
      const header = findHeader(text);
      if (!header) return null;
      return { operation: 'store', target: { header, element: findElement(text), index: null }, value: null };
    }
  }
];

/** Conditions read out of an "if/when/where ..." clause. */
function findConditions(text) {
  const conditions = [];
  const m = str(text).match(/\b(?:if|when|where|only for|for calls? (?:where|with))\b(.{3,160})/i);
  if (!m) return conditions;
  const clause = m[1];
  const header = findHeader(clause);
  if (!header) return conditions;

  let comparison = 'contains';
  let negate = false;
  if (/\bdoes\s*n[o']?t\s+(contain|include|have)\b|\bwithout\b|\bmissing\b/i.test(clause)) {
    comparison = 'notcontains';
    negate = true;
  } else if (/\bexists?\b|\bis present\b/i.test(clause)) {
    comparison = 'exists';
  } else if (/\bis\s+(?:exactly\s+)?["']/i.test(clause)) {
    comparison = 'equals';
  }

  const rx = buildRegex(clause);
  const lit = clause.match(/["']([^"'\n]{1,80})["']/);
  const value = rx.pattern || (lit ? lit[1] : null);
  if (!value) return conditions;
  if (rx.pattern) comparison = 'matches';

  conditions.push({
    element: header,
    comparison,
    value,
    negate,
    raw: 'derived from: ' + clause.trim().slice(0, 80)
  });
  return conditions;
}

/**
 * Reject anything outside the closed vocabulary.
 *
 * Exported because it is also the gate any future LLM-assisted path must pass
 * its output through — an LLM may fill in the IR, never widen it.
 *
 * @param {object} rule
 * @returns {string[]} problems; empty means valid
 */
function validateRule(rule) {
  const problems = [];
  if (!rule || typeof rule !== 'object') return ['not an object'];
  if (OPERATIONS.indexOf(rule.operation) === -1) problems.push('unknown operation: ' + rule.operation);
  const t = rule.target || {};
  if (rule.operation !== 'none' && !t.header) problems.push('no target header');
  if (t.header && !/^[A-Za-z][A-Za-z0-9-]{0,60}$/.test(String(t.header))) {
    problems.push('implausible header name: ' + t.header);
  }
  const sc = rule.scope || {};
  if (sc.msgType && MSG_TYPES.indexOf(sc.msgType) === -1) problems.push('unknown msgType: ' + sc.msgType);
  for (const c of (rule.conditions || [])) {
    if (c && c.comparison && COMPARISONS.indexOf(c.comparison) === -1) {
      problems.push('unknown comparison: ' + c.comparison);
    }
  }
  return problems;
}

function suggestName(intent, header) {
  const h = lc(header).replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
  const verb = {
    'delete-header': 'strip',
    'add-header': 'add',
    'replace-in-header': 'rewrite',
    'store-header': 'store'
  }[intent] || 'rule';
  return (verb + '_' + (h || 'header')).slice(0, 40);
}

/**
 * Build an HMR rule from a plain-English description.
 *
 * @param {string} description what the rule should do, in English
 * @param {{name?: string, vendors?: string[]}} [opts]
 * @returns {{ok: boolean, rule: object|null, drafts: object, explain: object|null,
 *   regex: object|null, assumptions: string[], warnings: string[],
 *   questions: string[], matchedIntent: string|null}}
 */
function generateRule(description, opts) {
  const o = opts || {};
  const text = str(description).trim();
  const assumptions = [];
  const warnings = [];
  const questions = [];
  const ctx = { assumptions, warnings, questions };

  if (!text) {
    return {
      ok: false, rule: null, drafts: {}, explain: null, regex: null,
      assumptions, warnings: ['Describe what the rule should do.'], questions, matchedIntent: null
    };
  }

  const t = lc(text);
  let matched = null;
  let partial = null;
  for (const intent of INTENTS) {
    if (!intent.test(t)) continue;
    const built = intent.build(text, ctx);
    if (built) { matched = intent.id; partial = built; break; }
  }

  if (!partial) {
    // Deliberately no guess — ask. Naming the two things it needs is more
    // useful to the user than a confident wrong rule.
    questions.push('Which header should this act on? Name it explicitly, e.g. "P-Asserted-Identity".');
    questions.push('What should happen to it — add, remove, replace, or store?');
    return {
      ok: false, rule: null, drafts: {}, explain: null, regex: null,
      assumptions,
      warnings: ['Could not identify both a header and an action in that description.'],
      questions, matchedIntent: null
    };
  }

  const scope = findScope(text, assumptions);
  const conditions = findConditions(text);
  const regex = buildRegex(text);

  const rule = {
    id: null,
    name: str(o.name) || suggestName(matched, partial.target && partial.target.header),
    vendor: 'generic',
    setName: null,
    parentName: null,
    scope,
    conditions,
    target: partial.target,
    operation: partial.operation,
    subOperation: null,
    value: partial.value,
    bindings: [],
    enabled: true,
    elementRaw: null
  };

  const problems = validateRule(rule);
  if (problems.length) {
    return {
      ok: false, rule: null, drafts: {}, explain: null, regex,
      assumptions, warnings: warnings.concat(problems), questions, matchedIntent: matched
    };
  }

  if (scope.msgType === 'any') {
    assumptions.push('The description did not say requests or responses, so this applies to both.');
  }
  if (!conditions.length) {
    assumptions.push('No condition was given, so this acts on every message in scope.');
  }
  if (regex.pattern && regex.tested.some((x) => !x.matched)) {
    warnings.push('The generated pattern did not match one of the examples in your description — ' +
      'check it before use.');
  }

  const vendors = (Array.isArray(o.vendors) && o.vendors.length)
    ? o.vendors
    : ['oracle-acme', 'audiocodes', 'ribbon'];
  const drafts = {};
  for (const v of vendors) {
    try { drafts[v] = hmr.renderRule(rule, v); } catch (e) { drafts[v] = null; }
  }
  try { drafts.generic = hmr.renderRule(rule, 'generic'); } catch (e) { /* optional */ }

  let explain = null;
  try { explain = hmr.explainRule(rule); } catch (e) { explain = null; }

  return {
    ok: true, rule, drafts, explain,
    regex: regex.pattern ? regex : null,
    assumptions, warnings, questions, matchedIntent: matched
  };
}

module.exports = {
  generateRule,
  validateRule,
  buildRegex,
  OPERATIONS,
  COMPARISONS,
  HEADERS
};
