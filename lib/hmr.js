'use strict';

/**
 * lib/hmr.js — SBC header-manipulation rules (HMR): three vendor dialects parsed
 * into ONE intermediate representation, explained in plain English with a real
 * correctness check list, rendered back out as reviewable drafts, and joined
 * against what a capture actually shows.
 *
 * DESIGN_1 core feature 5: "the intermediate representation is the asset;
 * translation is then a rendering problem". So:
 *
 *   parseConfig(text)              -> { vendor, confidence, rules: [HmrRule], warnings }
 *   explainRule(rule, opts?)       -> { intent, correctness, improvements }
 *   renderRule(rule, vendor)       -> string   (DRAFT config, never applied)
 *   matchAgainstAnalysis(rules, a) -> { matches: [...] }
 *
 * Parsers: Oracle/Acme running-config `sip-manipulation` -> `header-rule` ->
 * `element-rule` (plus in-manipulationid / out-manipulationid bindings found on
 * session-agent / sip-interface / realm-config); AudioCodes `.ini`
 * MessageManipulations table rows (plus IPGroup / IPProfile / SIPInterface
 * binding by ManSetID); Ribbon SMM rule text (criterion / token / operation,
 * bound inbound|outbound on a Signaling Group / trunk group).
 *
 * Zero dependencies. Nothing here throws on malformed input: every parser is
 * wrapped, every accessor is guarded, and anything unparseable becomes a warning
 * string plus an honest 'unknown' vendor rather than a wrong answer.
 *
 * Additive fields on HmrRule (beyond the frozen shape in ARCHITECTURE.md — all
 * optional, safe to ignore, used by explainRule/renderRule/matchAgainstAnalysis):
 *   setName, parentName, order, enabled, subOperation, elementRaw, rowRole,
 *   sourceLine, and per-condition `raw` / `negate`.
 */

// ===========================================================================
// header naming
// ===========================================================================

var COMPACT = {
  f: 'from', t: 'to', i: 'call-id', m: 'contact', v: 'via', c: 'content-type',
  l: 'content-length', k: 'supported', s: 'subject', e: 'content-encoding',
  x: 'session-expires', o: 'event', r: 'refer-to', b: 'referred-by', u: 'allow-events'
};

var DISPLAY = {
  'call-id': 'Call-ID', 'cseq': 'CSeq', 'www-authenticate': 'WWW-Authenticate',
  'mime-version': 'MIME-Version', 'min-se': 'Min-SE', 'rack': 'RAck', 'rseq': 'RSeq',
  'sip-etag': 'SIP-ETag', 'sip-if-match': 'SIP-If-Match', 'request-uri': 'Request-URI',
  'p-asserted-identity': 'P-Asserted-Identity', 'p-preferred-identity': 'P-Preferred-Identity',
  'p-charging-vector': 'P-Charging-Vector', 'p-charging-function-addresses': 'P-Charging-Function-Addresses',
  'p-early-media': 'P-Early-Media', 'p-access-network-info': 'P-Access-Network-Info',
  'p-visited-network-id': 'P-Visited-Network-ID', 'p-called-party-id': 'P-Called-Party-ID',
  'p-associated-uri': 'P-Associated-URI', 'history-info': 'History-Info',
  'refer-to': 'Refer-To', 'referred-by': 'Referred-By', 'user-agent': 'User-Agent',
  'session-expires': 'Session-Expires', 'record-route': 'Record-Route',
  'max-forwards': 'Max-Forwards', 'content-length': 'Content-Length',
  'content-type': 'Content-Type', 'remote-party-id': 'Remote-Party-ID'
};

/** Normalize a header name: trim, lowercase, expand SIP compact forms. */
function normHeader(name) {
  var n = String(name == null ? '' : name).trim().toLowerCase();
  n = n.replace(/^header\./, '').replace(/:$/, '');
  if (n === 'requesturi' || n === 'request uri' || n === 'ruri' || n === 'req-uri') n = 'request-uri';
  return COMPACT[n] || n;
}

/** Human display form of a header name ('p-asserted-identity' -> 'P-Asserted-Identity'). */
function displayHeader(name) {
  var n = normHeader(name);
  if (!n) return null;
  if (DISPLAY[n]) return DISPLAY[n];
  return n.split('-').map(function (part) {
    if (!part) return part;
    if (part.length === 1) return part.toUpperCase();
    return part.charAt(0).toUpperCase() + part.slice(1);
  }).join('-');
}

// ===========================================================================
// tiny text utilities (all defensive)
// ===========================================================================

/** Split any text into lines, normalizing CRLF/CR. */
function lines(text) {
  return String(text == null ? '' : text).replace(/\r\n?/g, '\n').split('\n');
}

/** Strip one layer of matching surrounding single/double quotes. */
function unquote(s) {
  var v = String(s == null ? '' : s).trim();
  while (v.length >= 2 &&
    ((v.charAt(0) === '"' && v.charAt(v.length - 1) === '"') ||
     (v.charAt(0) === "'" && v.charAt(v.length - 1) === "'"))) {
    v = v.slice(1, -1).trim();
  }
  return v;
}

/** Leading-whitespace width of a line (tab = 8). */
function indentOf(line) {
  var n = 0;
  for (var i = 0; i < line.length; i++) {
    var c = line.charAt(i);
    if (c === ' ') n += 1;
    else if (c === '\t') n += 8;
    else break;
  }
  return n;
}

/** Split a comma-separated row, honouring quoted cells (quotes kept in the cell). */
function splitCsvQuoted(line) {
  var out = [], cur = '', q = null;
  var s = String(line == null ? '' : line);
  for (var i = 0; i < s.length; i++) {
    var ch = s.charAt(i);
    if (q) { cur += ch; if (ch === q) q = null; continue; }
    if (ch === '"' || ch === "'") { q = ch; cur += ch; continue; }
    if (ch === ',') { out.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  out.push(cur.trim());
  return out;
}

/** Whitespace tokenizer that keeps quoted runs together (quotes removed). */
function tokenize(line) {
  var out = [], cur = '', q = null, started = false;
  var s = String(line == null ? '' : line);
  for (var i = 0; i < s.length; i++) {
    var ch = s.charAt(i);
    if (q) {
      if (ch === q) { q = null; out.push(cur); cur = ''; started = false; }
      else cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") { if (started && cur) { out.push(cur); cur = ''; } q = ch; started = true; continue; }
    if (/\s/.test(ch)) { if (cur) { out.push(cur); cur = ''; } started = false; continue; }
    cur += ch; started = true;
  }
  if (cur) out.push(cur);
  return out;
}

/** Split a boolean expression on top-level `and`/`or` (outside quotes/brackets). */
function splitLogical(expr) {
  var s = String(expr == null ? '' : expr);
  var parts = [], cur = '', q = null, depth = 0;
  for (var i = 0; i < s.length; i++) {
    var ch = s.charAt(i);
    if (q) { cur += ch; if (ch === q) q = null; continue; }
    if (ch === '"' || ch === "'") { q = ch; cur += ch; continue; }
    if (ch === '(' || ch === '[') { depth++; cur += ch; continue; }
    if (ch === ')' || ch === ']') { if (depth > 0) depth--; cur += ch; continue; }
    if (depth === 0) {
      var rest = s.slice(i);
      var m = rest.match(/^(\s+)(and|or|AND|OR|And|Or)(\s+)/);
      if (m) { parts.push({ text: cur, join: m[2].toLowerCase() }); cur = ''; i += m[0].length - 1; continue; }
      if (rest.charAt(0) === '&' && rest.charAt(1) === '&') { parts.push({ text: cur, join: 'and' }); cur = ''; i += 1; continue; }
      if (rest.charAt(0) === '|' && rest.charAt(1) === '|') { parts.push({ text: cur, join: 'or' }); cur = ''; i += 1; continue; }
    }
    cur += ch;
  }
  parts.push({ text: cur, join: null });
  // the `join` on part i describes how part i connects to part i+1
  var out = [];
  for (var j = 0; j < parts.length; j++) {
    var t = String(parts[j].text || '').trim();
    if (!t) continue;
    out.push({ text: t, joinToNext: parts[j].join });
  }
  return out;
}

/** true when a value string plausibly holds a private (RFC 1918) IPv4 address. */
function hasPrivateIp(s) {
  var v = String(s == null ? '' : s);
  return /(^|[^0-9.])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})([^0-9.]|$)/.test(v);
}

/** Is this text an expression (references other fields / concatenates) or a literal? */
function valueKind(text) {
  var s = String(text == null ? '' : text);
  var bare = s.replace(/'[^']*'/g, '').replace(/"[^"]*"/g, '');
  if (/[$]/.test(bare)) return 'expression';
  if (/\+/.test(bare) && /[A-Za-z]/.test(bare)) return 'expression';
  if (/\b(header|param|var)\./i.test(bare)) return 'expression';
  return 'literal';
}

/** Build the frozen `value` object, or null for an empty value. */
function makeValue(text) {
  if (text == null) return null;
  var raw = String(text).trim();
  if (!raw) return null;
  var kind = valueKind(raw);
  if (kind === 'literal') {
    var lit = unquote(raw);
    if (!lit) return null;          // an empty quoted cell means "no value"
    return { kind: 'literal', text: lit };
  }
  return { kind: 'expression', text: raw };
}

/** Uppercase, de-duplicated SIP method list from a comma/space separated string. */
function parseMethods(s) {
  var out = [], seen = {};
  var parts = String(s == null ? '' : s).split(/[,\s;|]+/);
  for (var i = 0; i < parts.length; i++) {
    var t = parts[i].trim().toUpperCase();
    if (!t) continue;
    if (t === 'RE-INVITE' || t === 'REINVITE') t = 'INVITE';
    if (t === 'ANY' || t === 'ALL' || t === '*') continue;
    if (!/^[A-Z]{3,12}$/.test(t)) continue;
    if (!seen[t]) { seen[t] = true; out.push(t); }
  }
  return out;
}

/** Map a vendor msg-type token onto the IR's 'request'|'response'|'any'. */
function normMsgType(s) {
  var t = String(s == null ? '' : s).trim().toLowerCase();
  if (!t) return 'any';
  if (t.indexOf('request') === 0 || t === 'req') return 'request';
  if (t.indexOf('reply') === 0 || t.indexOf('response') === 0 || t === 'resp') return 'response';
  if (t === 'out-of-dialog' || t === 'ood') return 'request';
  return 'any';
}

/** Merge two directions ('in' + 'out' -> 'both'). */
function mergeDirection(a, b) {
  if (!a) return b || null;
  if (!b) return a || null;
  if (a === b) return a;
  return 'both';
}

/** Empty HmrRule with every frozen key present. */
function blankRule(vendor) {
  return {
    id: null,
    name: null,
    vendor: vendor || 'unknown',
    raw: '',
    scope: { direction: null, msgType: 'any', methods: [] },
    conditions: [],
    target: { header: null, element: null, index: null },
    operation: 'none',
    value: null,
    bindings: [],
    // additive, optional
    setName: null,
    parentName: null,
    order: 0,
    enabled: true,
    subOperation: null,
    elementRaw: null,
    rowRole: null,
    sourceLine: null
  };
}

/** Build a condition object (frozen keys + additive raw/negate). */
function makeCondition(element, comparison, value, raw, negate) {
  return {
    element: element == null ? null : String(element),
    comparison: comparison || 'exists',
    value: value == null ? null : String(value),
    raw: raw == null ? null : String(raw),
    negate: !!negate
  };
}

// ===========================================================================
// vendor detection
// ===========================================================================

var VENDOR_TOKENS = {
  'oracle-acme': [
    /^\s*sip-manipulation\b/mi, /^\s*header-rule\b/mi, /^\s*element-rule\b/mi,
    /\bin-manipulationid\b/i, /\bout-manipulationid\b/i, /^\s*session-agent\b/mi,
    /^\s*realm-config\b/mi, /\bmatch-val-type\b/i, /\bcomparison-type\b/i,
    /\bnew-value\b/i, /\bheader-name\b/i, /\bmsg-type\b/i, /\bpattern-rule\b/i,
    /^\s*sip-interface\b/mi, /\blast-modified-by\b/i
  ],
  'audiocodes': [
    /\[\s*\\?MessageManipulations?\s*\]/i, /\bMessageManipulations?_[A-Za-z]/,
    /\bManipulationName\b/i, /\bManSetID\b/i, /\bActionSubject\b/i,
    /\bActionType\b/i, /\bRowRole\b/i, /^\s*FORMAT\s+\w+_Index\s*=/mi,
    /\bheader\.[a-z-]+\.url\.(user|host)\b/i, /\[\s*\\?IPGroup\s*\]/i,
    /\[\s*\\?IPProfile\s*\]/i, /\bIPGroup_(In|Out)boundManSet\b/i,
    /\bIpProfile_[A-Za-z]/
  ],
  'ribbon': [
    /\bsipAdaptorProfile\b/i, /\bmessageManipulation\b/i,
    /\b(input|output)AdapterProfile\b/i, /\bapplyMatchHeader\b/i,
    /^\s*criterion\b/mi, /\bcriterion\s+(messageType|header|sipMessageBody)\b/i,
    /\boperation\s+header\b/i, /\bmethodTypes?\b/i, /\btokenValue\b/i,
    /\bsipTrunkGroup\b/i, /\bsignaling\s+group\b/i, /\baddressContext\b/i,
    /\bsmm\b/i
  ]
};

/**
 * Detect the SBC vendor from distinctive tokens.
 * @param {string} text raw config text
 * @returns {{vendor: string, confidence: number, scores: object}} vendor is
 *   'oracle-acme'|'audiocodes'|'ribbon'|'unknown'; confidence 0..1.
 */
function detectVendor(text) {
  var t = String(text == null ? '' : text);
  var scores = { 'oracle-acme': 0, 'audiocodes': 0, 'ribbon': 0 };
  var keys = Object.keys(VENDOR_TOKENS);
  for (var k = 0; k < keys.length; k++) {
    var pats = VENDOR_TOKENS[keys[k]];
    for (var i = 0; i < pats.length; i++) {
      try { if (pats[i].test(t)) scores[keys[k]] += 1; } catch (e) { /* ignore */ }
    }
  }
  var best = 'unknown', bestScore = 0, second = 0;
  for (var j = 0; j < keys.length; j++) {
    if (scores[keys[j]] > bestScore) { second = bestScore; best = keys[j]; bestScore = scores[keys[j]]; }
    else if (scores[keys[j]] > second) second = scores[keys[j]];
  }
  if (bestScore === 0) return { vendor: 'unknown', confidence: 0, scores: scores };
  var conf = 0.35 + 0.12 * bestScore;
  var margin = bestScore - second;
  if (margin <= 0) conf = Math.min(conf, 0.4);
  else if (margin === 1) conf = Math.min(conf, 0.65);
  if (bestScore === 1) conf = Math.min(conf, 0.45);
  return { vendor: best, confidence: Math.round(Math.min(0.95, conf) * 100) / 100, scores: scores };
}

// ===========================================================================
// parser 1 — Oracle / Acme Packet running config
//   sip-manipulation -> header-rule -> element-rule, plus the
//   in-manipulationid / out-manipulationid bindings on session-agent,
//   sip-interface and realm-config blocks.
// ===========================================================================

var ACME_L0 = {
  'sip-manipulation': 1, 'session-agent': 1, 'sip-interface': 1, 'realm-config': 1,
  'session-group': 1, 'sip-config': 1, 'sip-monitoring': 1, 'local-policy': 1,
  'media-profile': 1, 'codec-policy': 1, 'network-interface': 1, 'steering-pool': 1,
  'translation-rules': 1, 'session-translation': 1, 'sip-feature': 1, 'sip-profile': 1
};
var ACME_L1 = { 'header-rule': 1, 'mime-rule': 1, 'mime-header-rule': 1, 'mime-isup-rule': 1 };
var ACME_L2 = { 'element-rule': 1, 'mime-sdp-rule': 1, 'sdp-session-rule': 1, 'sdp-media-rule': 1, 'isup-param-rule': 1 };

/** Header-rule-only field names (used to disambiguate flat indentation). */
var ACME_HR_ONLY = { 'header-name': 1, 'msg-type': 1, 'methods': 1 };

/** Map an Acme element-rule `type` onto the IR element path. */
function acmeElement(type, paramName) {
  var t = String(type == null ? '' : type).trim().toLowerCase();
  var p = String(paramName == null ? '' : paramName).trim();
  switch (t) {
    case 'uri-user': case 'uri-user-only': return 'uri.user';
    case 'uri-host': return 'uri.host';
    case 'uri-port': return 'uri.port';
    case 'uri-display': case 'header-value-display': return 'display';
    case 'uri-param': case 'uri-user-param': return p ? 'param.' + p : 'uri.param';
    case 'header-param': case 'param': return p ? (p.toLowerCase() === 'tag' ? 'param.tag' : 'param.' + p) : 'param';
    case 'header-value': case 'value': return 'value';
    case 'uri': case 'uri-all': return 'uri';
    case 'status-code': return 'status-code';
    case 'reason-phrase': return 'reason';
    default: return t ? t.replace(/-/g, '.') : null;
  }
}

/** Map an Acme action keyword onto the IR operation + subOperation. */
function acmeOperation(action) {
  var a = String(action == null ? '' : action).trim().toLowerCase();
  switch (a) {
    case 'add': return { op: 'add', sub: null };
    case 'delete': return { op: 'delete', sub: null };
    case 'manipulate': return { op: 'modify', sub: null };
    case 'replace': return { op: 'replace', sub: null };
    case 'store': return { op: 'store', sub: null };
    case 'find-replace-all': return { op: 'modify', sub: 'find-replace-all' };
    case 'sip-manip': return { op: 'none', sub: 'sip-manip' };
    case 'monitor': return { op: 'none', sub: 'monitor' };
    case 'none': case '': return { op: 'none', sub: null };
    default: return { op: 'none', sub: a };
  }
}

/**
 * Map an Acme comparison-type onto the IR comparison. A `boolean`
 * comparison-type holds an expression rather than a value, so a leading `!`
 * means "this element must be absent".
 */
function acmeComparison(cmp, value) {
  var c = String(cmp == null ? '' : cmp).trim().toLowerCase();
  if (c === 'pattern-rule' || c === 'refer-pattern-rule') return 'matches';
  if (c === 'boolean') return /^\s*!/.test(String(value == null ? '' : value)) ? 'absent' : 'exists';
  return 'equals';
}

/**
 * Parse an Oracle/Acme (Net-Net / OS SCX) running config.
 * @param {string} text config text
 * @param {string[]} warnings collector
 * @returns {object[]} HmrRule-shaped objects (ids assigned by parseConfig)
 */
function parseAcme(text, warnings) {
  var all = lines(text);
  var manips = [];
  var binders = [];      // { kind, name, inId, outId }
  var stack = [];        // { level, kind, obj, fieldIndent }
  var curManip = null, curBinder = null;

  function closeTo(level) {
    while (stack.length && stack[stack.length - 1].level >= level) stack.pop();
  }

  for (var i = 0; i < all.length; i++) {
    var rawLine = all[i];
    var line = rawLine.replace(/\s+$/, '');
    if (!line.trim()) continue;
    var trimmed = line.trim();
    if (/^[#!;]/.test(trimmed)) continue;
    var ind = indentOf(line);
    var sp = trimmed.match(/^([A-Za-z0-9_][A-Za-z0-9_.\-]*)\s*(.*)$/);
    if (!sp) continue;
    var key = sp[1].toLowerCase();
    var val = sp[2] == null ? '' : sp[2].trim();

    if (ACME_L0[key]) {
      stack.length = 0;
      curManip = null; curBinder = null;
      if (key === 'sip-manipulation') {
        curManip = { name: null, description: null, headerRules: [], startLine: i + 1, raw: [line] };
        manips.push(curManip);
        stack.push({ level: 0, kind: 'manip', obj: curManip, fieldIndent: null });
      } else if (key === 'session-agent' || key === 'sip-interface' || key === 'realm-config') {
        curBinder = { kind: key === 'realm-config' ? 'realm' : key, name: null, inId: null, outId: null, fields: {} };
        binders.push(curBinder);
        stack.push({ level: 0, kind: 'binder', obj: curBinder, fieldIndent: null });
      }
      continue;
    }

    if (ACME_L1[key] && curManip) {
      closeTo(1);
      var hr = { name: null, kind: key, fields: {}, elementRules: [], startLine: i + 1, raw: [line] };
      curManip.headerRules.push(hr);
      curManip.raw.push(line);
      stack.push({ level: 1, kind: 'headerRule', obj: hr, fieldIndent: null });
      continue;
    }

    if (ACME_L2[key] && curManip) {
      closeTo(2);
      var parentHr = null;
      for (var s = stack.length - 1; s >= 0; s--) { if (stack[s].kind === 'headerRule') { parentHr = stack[s].obj; break; } }
      if (!parentHr) {
        // element-rule without a header-rule: tolerate by synthesising one
        parentHr = { name: null, kind: 'header-rule', fields: {}, elementRules: [], startLine: i + 1, raw: [] };
        curManip.headerRules.push(parentHr);
        stack.push({ level: 1, kind: 'headerRule', obj: parentHr, fieldIndent: null });
        warnings.push('acme: element-rule at line ' + (i + 1) + ' has no enclosing header-rule');
      }
      var er = { name: null, kind: key, fields: {}, startLine: i + 1, raw: [line] };
      parentHr.elementRules.push(er);
      parentHr.raw.push(line);
      curManip.raw.push(line);
      stack.push({ level: 2, kind: 'elementRule', obj: er, fieldIndent: null });
      continue;
    }

    // plain "key value" field: attach to the deepest sensible open frame
    if (!stack.length) continue;
    var frame = stack[stack.length - 1];
    // a field less indented than fields already seen on this frame closes it
    while (stack.length > 1 && frame.fieldIndent != null && ind < frame.fieldIndent) {
      stack.pop();
      frame = stack[stack.length - 1];
    }
    if (ACME_HR_ONLY[key] && frame.kind === 'elementRule') {
      for (var h = stack.length - 1; h >= 0; h--) { if (stack[h].kind === 'headerRule') { frame = stack[h]; break; } }
    }
    if (frame.fieldIndent == null) frame.fieldIndent = ind;
    if (frame.kind === 'manip') {
      if (key === 'name') frame.obj.name = unquote(val);
      else if (key === 'description') frame.obj.description = unquote(val);
      frame.obj.raw.push(line);
    } else if (frame.kind === 'binder') {
      frame.obj.fields[key] = unquote(val);
      if (key === 'in-manipulationid') frame.obj.inId = unquote(val);
      else if (key === 'out-manipulationid') frame.obj.outId = unquote(val);
    } else if (frame.kind === 'headerRule' || frame.kind === 'elementRule') {
      if (key === 'name') frame.obj.name = unquote(val);
      frame.obj.fields[key] = val;
      frame.obj.raw.push(line);
      if (curManip) curManip.raw.push(line);
    }
  }

  // binder names
  for (var b = 0; b < binders.length; b++) {
    var bd = binders[b];
    var f = bd.fields || {};
    if (bd.kind === 'session-agent') bd.name = f['hostname'] || f['ip-address'] || f['name'] || 'session-agent';
    else if (bd.kind === 'sip-interface') bd.name = f['realm-id'] || f['description'] || f['name'] || 'sip-interface';
    else bd.name = f['identifier'] || f['name'] || 'realm';
  }

  // manipulation name -> bindings + direction
  var bindIndex = {};
  function addBind(id, kind, name, dir) {
    var k = String(id == null ? '' : id).trim();
    if (!k) return;
    if (!bindIndex[k]) bindIndex[k] = { bindings: [], direction: null, seen: {} };
    var sig = kind + '|' + name;
    if (!bindIndex[k].seen[sig]) { bindIndex[k].seen[sig] = true; bindIndex[k].bindings.push({ kind: kind, name: String(name) }); }
    bindIndex[k].direction = mergeDirection(bindIndex[k].direction, dir);
  }
  for (var bb = 0; bb < binders.length; bb++) {
    if (binders[bb].inId) addBind(binders[bb].inId, binders[bb].kind, binders[bb].name, 'in');
    if (binders[bb].outId) addBind(binders[bb].outId, binders[bb].kind, binders[bb].name, 'out');
  }

  // flatten manipulations into IR rules
  var rules = [];
  for (var m = 0; m < manips.length; m++) {
    var mp = manips[m];
    var setName = mp.name || ('sip-manipulation@' + mp.startLine);
    var bind = bindIndex[setName] || null;
    var order = 0;
    for (var r = 0; r < mp.headerRules.length; r++) {
      var hrO = mp.headerRules[r];
      var hf = hrO.fields || {};
      var headerName = unquote(hf['header-name'] || '') || null;
      var hrAct = acmeOperation(hf['action']);
      var hrCmp = acmeComparison(hf['comparison-type'], unquote(hf['match-value'] || ''));
      var hrMatch = unquote(hf['match-value'] || '');
      var msgType = normMsgType(hf['msg-type']);
      var methods = parseMethods(hf['methods']);
      var ers = hrO.elementRules || [];

      function baseRule() {
        var rule = blankRule('oracle-acme');
        rule.setName = setName;
        rule.parentName = hrO.name || null;
        rule.scope.direction = bind ? bind.direction : null;
        rule.scope.msgType = msgType;
        rule.scope.methods = methods;
        rule.target.header = headerName ? displayHeader(headerName) : null;
        rule.bindings = bind ? bind.bindings.slice() : [];
        rule.order = order++;
        rule.sourceLine = hrO.startLine;
        if (hrMatch) rule.conditions.push(makeCondition(
          (headerName ? displayHeader(headerName) : 'header'), hrCmp, hrMatch,
          'header-rule match-value ' + hrMatch, false));
        return rule;
      }

      if (!ers.length) {
        var only = baseRule();
        only.name = hrO.name || (headerName ? displayHeader(headerName) + ' ' + hrAct.op : 'header-rule');
        only.operation = hrAct.op;
        only.subOperation = hrAct.sub;
        only.target.element = (hrAct.op === 'modify' || hrAct.op === 'replace') ? 'value' : null;
        only.elementRaw = null;
        only.value = makeValue(hf['new-value']);
        only.raw = (hrO.raw || []).join('\n');
        if (mp.description) only.setName = setName;
        rules.push(only);
        continue;
      }

      for (var e = 0; e < ers.length; e++) {
        var erO = ers[e];
        var ef = erO.fields || {};
        var erAct = acmeOperation(ef['action'] || hf['action']);
        var rule2 = baseRule();
        rule2.name = erO.name || hrO.name || 'element-rule';
        rule2.operation = erAct.op;
        rule2.subOperation = erAct.sub;
        rule2.elementRaw = unquote(ef['type'] || '') || null;
        rule2.target.element = acmeElement(ef['type'], ef['parameter-name']);
        rule2.value = makeValue(ef['new-value']);
        var erMatch = unquote(ef['match-value'] || '');
        if (erMatch) {
          rule2.conditions.push(makeCondition(
            (rule2.target.header || 'header') + (rule2.target.element ? '.' + rule2.target.element : ''),
            acmeComparison(ef['comparison-type'] || hf['comparison-type'], erMatch), erMatch,
            'element-rule match-value ' + erMatch, false));
        }
        rule2.raw = ((hrO.raw || []).concat(erO.raw || [])).join('\n');
        rules.push(rule2);
      }
    }
    if (!mp.headerRules.length) {
      warnings.push('acme: sip-manipulation "' + setName + '" has no header-rule blocks');
    }
  }
  return rules;
}

// ===========================================================================
// parser 2 — AudioCodes .ini MessageManipulations table
// ===========================================================================

var AC_MM_FIELDS = ['ManipulationName', 'ManSetID', 'MessageType', 'Condition', 'ActionSubject', 'ActionType', 'ActionValue', 'RowRole'];

var AC_ACTION_TYPES = {
  '0': { op: 'add', sub: null, label: 'add' },
  '1': { op: 'delete', sub: null, label: 'remove' },
  '2': { op: 'modify', sub: null, label: 'modify' },
  '3': { op: 'modify', sub: 'add-prefix', label: 'add-prefix' },
  '4': { op: 'modify', sub: 'add-suffix', label: 'add-suffix' },
  '5': { op: 'modify', sub: 'remove-suffix', label: 'remove-suffix' },
  '6': { op: 'modify', sub: 'remove-prefix', label: 'remove-prefix' }
};

/** Map an AudioCodes ActionType (numeric or textual) onto the IR operation. */
function acActionType(v) {
  var s = unquote(v).trim();
  if (/^\d+$/.test(s) && AC_ACTION_TYPES[s]) return AC_ACTION_TYPES[s];
  var t = s.toLowerCase().replace(/[\s_]+/g, '-');
  switch (t) {
    case 'add': return AC_ACTION_TYPES['0'];
    case 'remove': case 'delete': return AC_ACTION_TYPES['1'];
    case 'modify': case 'replace': return AC_ACTION_TYPES['2'];
    case 'add-prefix': case 'addprefix': return AC_ACTION_TYPES['3'];
    case 'add-suffix': case 'addsuffix': return AC_ACTION_TYPES['4'];
    case 'remove-suffix': case 'removesuffix': return AC_ACTION_TYPES['5'];
    case 'remove-prefix': case 'removeprefix': return AC_ACTION_TYPES['6'];
    default: return { op: 'none', sub: t || null, label: t || 'unknown' };
  }
}

/**
 * Map an AudioCodes ActionSubject / condition subject onto {header, element}.
 * e.g. 'header.from.url.user' -> { header:'From', element:'uri.user' }
 */
function acSubject(subject) {
  var raw = unquote(subject).trim();
  var out = { header: null, element: null, elementRaw: raw || null, index: null };
  if (!raw) return out;
  var parts = raw.split('.').map(function (p) { return p.trim(); }).filter(function (p) { return p !== ''; });
  if (!parts.length) return out;
  var head = parts[0].toLowerCase();
  if (head === 'header') {
    var hname = parts[1] || '';
    var idx = hname.match(/^(.*)\.(\d+)$/);
    if (idx) hname = idx[1];
    var mIdx = hname.match(/^(.+)\[(\d+)\]$/);
    if (mIdx) { hname = mIdx[1]; out.index = parseInt(mIdx[2], 10); }
    out.header = displayHeader(hname);
    var rest = parts.slice(2).map(function (p) { return p.toLowerCase(); });
    if (!rest.length) { out.element = null; return out; }
    if (rest.length === 1 && /^\d+$/.test(rest[0])) { out.index = parseInt(rest[0], 10); out.element = null; return out; }
    var j = rest.join('.');
    if (j === 'url.user' || j === 'uri.user' || j === 'user') out.element = 'uri.user';
    else if (j === 'url.host' || j === 'uri.host' || j === 'host') out.element = 'uri.host';
    else if (j === 'url.port' || j === 'uri.port' || j === 'port') out.element = 'uri.port';
    else if (j === 'url' || j === 'uri') out.element = 'uri';
    else if (j === 'name' || j === 'display' || j === 'displayname') out.element = 'display';
    else if (/^(url\.)?param\.tag$/.test(j) || j === 'tag') out.element = 'param.tag';
    else if (/^(url\.)?param\./.test(j)) out.element = 'param.' + j.replace(/^(url\.)?param\./, '');
    else if (j === 'value' || j === 'headervalue') out.element = 'value';
    else out.element = j;
    return out;
  }
  if (head === 'body' || head === 'sdp') {
    out.header = 'SDP body';
    out.element = parts.slice(1).join('.') || null;
    return out;
  }
  if (head === 'var') { out.header = raw; out.element = null; return out; }
  if (head === 'param') { out.header = raw; out.element = null; return out; }
  out.header = displayHeader(raw);
  return out;
}

/** Parse one AudioCodes condition expression into IR conditions. */
function acConditions(condText) {
  var out = [];
  var text = unquote(condText).trim();
  if (!text) return out;
  var parts = splitLogical(text);
  for (var i = 0; i < parts.length; i++) {
    var seg = parts[i].text.replace(/^\(+|\)+$/g, '').trim();
    if (!seg) continue;
    var m = seg.match(/^(.*?)\s*(==|!=|=~|~=|>=|<=|>|<|\bcontains\b|\b!contains\b|\bnotcontains\b|\bexists\b|\b!exists\b|\bnot\s+exists\b)\s*(.*)$/i);
    if (!m) {
      out.push(makeCondition(acSubject(seg).elementRaw || seg, 'exists', null, seg, false));
      continue;
    }
    var subj = m[1].trim();
    var op = m[2].trim().toLowerCase().replace(/\s+/g, ' ');
    var val = m[3] == null ? '' : m[3].trim();
    var subjInfo = acSubject(subj);
    var elementPath = subjInfo.header
      ? (subjInfo.header + (subjInfo.element ? '.' + subjInfo.element : ''))
      : subj;
    var comparison = 'equals', negate = false;
    if (op === '==') comparison = 'equals';
    else if (op === '!=') { comparison = 'equals'; negate = true; }
    else if (op === '=~' || op === '~=') comparison = 'matches';
    else if (op === 'contains') comparison = 'matches';
    else if (op === '!contains' || op === 'notcontains') { comparison = 'matches'; negate = true; }
    else if (op === 'exists') comparison = 'exists';
    else if (op === '!exists' || op === 'not exists') comparison = 'absent';
    else comparison = 'matches';
    if (comparison === 'equals' && /[*?]/.test(unquote(val))) comparison = 'matches';
    out.push(makeCondition(elementPath, comparison,
      (comparison === 'exists' || comparison === 'absent') ? null : unquote(val), seg, negate));
  }
  return out;
}

/** Parse an AudioCodes MessageType token ('invite.response.200') into scope + extra conditions. */
function acMessageType(mt) {
  var raw = unquote(mt).trim().toLowerCase();
  var scope = { msgType: 'any', methods: [] };
  var extra = [];
  if (!raw || raw === 'any' || raw === 'all') return { scope: scope, extra: extra, raw: raw };
  var parts = raw.split('.').filter(function (p) { return p !== ''; });
  var first = parts[0] || '';
  if (first && first !== 'any' && first !== 'all') {
    var meths = parseMethods(first);
    if (meths.length) scope.methods = meths;
  }
  for (var i = 1; i < parts.length; i++) {
    var p = parts[i];
    if (p === 'request') scope.msgType = 'request';
    else if (p === 'response') scope.msgType = 'response';
    else if (/^\d{3}$/.test(p) || /^\d?x{1,2}$/.test(p) || /^\d[\dx]{2}$/.test(p)) {
      scope.msgType = 'response';
      extra.push(makeCondition('response.status', 'matches', p, 'msg-type ' + raw, false));
    }
  }
  if (scope.msgType === 'any' && /^(invite|re-invite|reinvite|register|bye|cancel|options|subscribe|notify|refer|update|prack|info|message|publish)$/.test(first)) {
    scope.msgType = 'any';
  }
  return { scope: scope, extra: extra, raw: raw };
}

/**
 * Parse an AudioCodes `.ini` export.
 * @param {string} text ini text
 * @param {string[]} warnings collector
 * @returns {object[]} HmrRule-shaped objects
 */
function parseAudioCodes(text, warnings) {
  var all = lines(text);
  var formats = {};     // table -> [fieldName,...]
  var tables = {};      // table -> [{ index, cells:[], byField:{} }]
  var section = null;

  for (var i = 0; i < all.length; i++) {
    var line = all[i].replace(/\s+$/, '');
    var t = line.trim();
    if (!t || /^[;#]/.test(t)) continue;
    var sec = t.match(/^\[\s*(\\?)\s*([A-Za-z0-9_ ]+?)\s*\]$/);
    if (sec) { section = sec[1] === '\\' ? null : sec[2].trim(); continue; }
    var fmt = t.match(/^FORMAT\s+([A-Za-z0-9_]+)_Index\s*=\s*(.*?);?\s*$/i);
    if (fmt) {
      var tbl = fmt[1];
      var fields = fmt[2].split(',').map(function (f) {
        return f.trim().replace(new RegExp('^' + tbl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '_', 'i'), '').trim();
      }).filter(function (f) { return f !== ''; });
      formats[tbl.toLowerCase()] = fields;
      continue;
    }
    var row = t.match(/^([A-Za-z0-9_]+)\s+(\d+)\s*=\s*(.*?);?\s*$/);
    if (row) {
      var name = row[1], idx = parseInt(row[2], 10), body = row[3];
      var key = name.toLowerCase();
      if (!tables[key]) tables[key] = { name: name, rows: [] };
      tables[key].rows.push({ index: idx, cells: splitCsvQuoted(body), line: i + 1, raw: t });
      continue;
    }
    // scalar "Table_Field = value" lines (single-row tables in some exports)
    var scalar = t.match(/^([A-Za-z0-9_]+)_([A-Za-z0-9_]+)\s*=\s*(.*?);?\s*$/);
    if (scalar) {
      var sk = scalar[1].toLowerCase();
      if (!tables[sk]) tables[sk] = { name: scalar[1], rows: [] };
      var scalarRows = tables[sk].rows;
      var target = null;
      for (var q = 0; q < scalarRows.length; q++) { if (scalarRows[q].scalar) { target = scalarRows[q]; break; } }
      if (!target) { target = { index: 0, cells: [], byField: {}, scalar: true, line: i + 1, raw: t }; scalarRows.push(target); }
      target.byField = target.byField || {};
      target.byField[scalar[2].toLowerCase()] = unquote(scalar[3]);
      continue;
    }
    if (section) { /* unrecognized line inside a section — ignore quietly */ }
  }

  // resolve field names for every table row
  var tkeys = Object.keys(tables);
  for (var tk = 0; tk < tkeys.length; tk++) {
    var tdef = tables[tkeys[tk]];
    var fnames = formats[tkeys[tk]] || null;
    for (var rr = 0; rr < tdef.rows.length; rr++) {
      var rw = tdef.rows[rr];
      rw.byField = rw.byField || {};
      if (!rw.cells || !rw.cells.length) continue;
      var names = fnames;
      if (!names && /^messagemanipulations?$/.test(tkeys[tk])) names = AC_MM_FIELDS;
      if (!names) continue;
      for (var c = 0; c < rw.cells.length && c < names.length; c++) {
        rw.byField[String(names[c]).toLowerCase()] = rw.cells[c];
      }
    }
  }

  // manipulation-set bindings from IPGroup / IPProfile / SIPInterface tables
  var BIND_TABLES = {
    'ipgroup': 'ip-group', 'ipgroups': 'ip-group',
    'ipprofile': 'ip-profile', 'ipprofiles': 'ip-profile',
    'sipinterface': 'sip-interface', 'sipinterfaces': 'sip-interface'
  };
  var bindBySet = {};   // setId -> { bindings:[], direction }
  function addAcBind(setId, kind, name, dir) {
    var k = String(setId).trim();
    if (!k || k === '-1') return;
    if (!bindBySet[k]) bindBySet[k] = { bindings: [], direction: null, seen: {} };
    var sig = kind + '|' + name;
    if (!bindBySet[k].seen[sig]) { bindBySet[k].seen[sig] = true; bindBySet[k].bindings.push({ kind: kind, name: String(name) }); }
    bindBySet[k].direction = mergeDirection(bindBySet[k].direction, dir);
  }
  var btk = Object.keys(BIND_TABLES);
  for (var bt = 0; bt < btk.length; bt++) {
    var bTable = tables[btk[bt]];
    if (!bTable) continue;
    for (var br = 0; br < bTable.rows.length; br++) {
      var brow = bTable.rows[br];
      var bf = brow.byField || {};
      var rowName = bf['name'] || bf['profilename'] || bf['interfacename'] || bf['groupname'] ||
        (bTable.name + ' ' + brow.index);
      var fkeys = Object.keys(bf);
      for (var fk = 0; fk < fkeys.length; fk++) {
        var fname = fkeys[fk];
        if (!/manset|manipulationset/.test(fname)) continue;
        var v = unquote(bf[fname]).trim();
        if (!/^-?\d+$/.test(v)) continue;
        var dir = /inbound|inputmessage|^in/.test(fname) ? 'in' : (/outbound|outputmessage|^out/.test(fname) ? 'out' : null);
        addAcBind(v, BIND_TABLES[btk[bt]], unquote(rowName), dir);
      }
    }
  }

  // the manipulation rows themselves
  var mmTable = tables['messagemanipulations'] || tables['messagemanipulation'] || null;
  if (!mmTable) return [];
  var rows = mmTable.rows.slice().sort(function (a, b) { return a.index - b.index; });
  var rules = [], prev = null;
  for (var m = 0; m < rows.length; m++) {
    var rowM = rows[m];
    var fld = rowM.byField || {};
    if (!Object.keys(fld).length && rowM.cells && rowM.cells.length) {
      for (var cc = 0; cc < rowM.cells.length && cc < AC_MM_FIELDS.length; cc++) {
        fld[AC_MM_FIELDS[cc].toLowerCase()] = rowM.cells[cc];
      }
    }
    var setId = unquote(fld['mansetid'] || fld['manipulationsetid'] || '0').trim() || '0';
    var act = acActionType(fld['actiontype']);
    var subj = acSubject(fld['actionsubject']);
    var mt = acMessageType(fld['messagetype']);
    var rowRole = unquote(fld['rowrole'] || '0').trim();
    var rule = blankRule('audiocodes');
    rule.name = unquote(fld['manipulationname'] || '') || (mmTable.name + ' ' + rowM.index);
    rule.setName = 'Manipulation Set ' + setId;
    rule.order = rowM.index;
    rule.sourceLine = rowM.line;
    rule.rowRole = /^\d+$/.test(rowRole) ? parseInt(rowRole, 10) : 0;
    rule.raw = rowM.raw;
    rule.operation = act.op;
    rule.subOperation = act.sub;
    rule.target.header = subj.header;
    rule.target.element = subj.element;
    rule.target.index = subj.index == null ? null : subj.index;
    rule.elementRaw = subj.elementRaw;
    rule.value = makeValue(fld['actionvalue']);
    rule.scope.msgType = mt.scope.msgType;
    rule.scope.methods = mt.scope.methods;
    var conds = acConditions(fld['condition']).concat(mt.extra);
    if (rule.rowRole === 1 && prev) {
      // "use previous condition": this row continues the previous rule's match
      if (!conds.length) conds = (prev.conditions || []).slice();
      if (rule.scope.msgType === 'any' && (!rule.scope.methods || !rule.scope.methods.length)) {
        rule.scope.msgType = prev.scope.msgType;
        rule.scope.methods = (prev.scope.methods || []).slice();
      }
      rule.parentName = prev.name;
    }
    rule.conditions = conds;
    var bnd = bindBySet[setId];
    if (setId === '0' && !bnd) {
      // set 0 is the implicit/global set on AudioCodes: applied where no set is named
      rule.bindings = [];
      rule.scope.direction = null;
    } else if (bnd) {
      rule.bindings = bnd.bindings.slice();
      rule.scope.direction = bnd.direction;
    }
    rules.push(rule);
    prev = rule;
  }
  if (!rules.length) warnings.push('audiocodes: MessageManipulations table present but no rows parsed');
  return rules;
}

// ===========================================================================
// parser 3 — Ribbon (Sonus) SMM: sipAdaptorProfile rules
//   criterion / token / operation, bound inbound|outbound on a Signaling Group
//   (SBC Edge) or a sipTrunkGroup (SBC Core, input/outputAdapterProfile).
// ===========================================================================

/** Map a Ribbon SMM actionType onto the IR operation. */
function ribbonOperation(action) {
  var a = String(action == null ? '' : action).trim().toLowerCase();
  switch (a) {
    case 'add': case 'addlast': case 'addfirst': return { op: 'add', sub: a === 'add' ? null : a };
    case 'delete': case 'remove': return { op: 'delete', sub: null };
    case 'modify': case 'replace-value': return { op: 'modify', sub: null };
    case 'replace': return { op: 'replace', sub: null };
    case 'store': case 'copy': return { op: 'store', sub: null };
    case '': return { op: 'none', sub: null };
    default: return { op: 'none', sub: a };
  }
}

/** Map a Ribbon criterion condition keyword onto the IR comparison. */
function ribbonComparison(cond, value) {
  var c = String(cond == null ? '' : cond).trim().toLowerCase();
  if (c === 'exist' || c === 'exists' || c === 'present') return 'exists';
  if (c === 'notexist' || c === 'notexists' || c === 'absent' || c === 'notpresent') return 'absent';
  if (c === 'regexmatch' || c === 'regex' || c === 'match' || c === 'matches' || c === 'pattern') return 'matches';
  if (c === 'value' || c === 'equals' || c === 'is' || c === 'exactmatch') return 'equals';
  if (value != null && /[\^$\[\]\\*+?|()]/.test(String(value))) return 'matches';
  if (value != null && String(value) !== '') return 'equals';
  return 'exists';
}

/** Map a Ribbon operation element keyword onto the IR element path. */
function ribbonElement(kw) {
  var k = String(kw == null ? '' : kw).trim().toLowerCase();
  switch (k) {
    case 'uriuser': case 'user': case 'usernameuri': return 'uri.user';
    case 'urihost': case 'host': case 'hostnameuri': return 'uri.host';
    case 'uriport': case 'port': return 'uri.port';
    case 'displayname': case 'display': return 'display';
    case 'headervalue': case 'value': case 'entirevalue': return 'value';
    case 'tokenvalue': case 'token': return 'value';
    case 'paramvalue': case 'param': case 'parameter': return 'param';
    case 'uri': case 'urivalue': return 'uri';
    default: return k ? k : null;
  }
}

/**
 * Parse Ribbon SMM configuration text (flat `set profiles ...` CLI or an
 * indented export).
 * @param {string} text config text
 * @param {string[]} warnings collector
 * @returns {object[]} HmrRule-shaped objects
 */
function parseRibbon(text, warnings) {
  var all = lines(text);
  var profiles = {}, profileOrder = [];
  var binds = [];            // { profile, kind, name, direction }
  var curProfile = null, curRule = null, curCriterion = null, curOperation = null;
  var lastGroup = null;

  function getProfile(name) {
    var key = String(name);
    if (!profiles[key]) { profiles[key] = { name: key, enabled: true, rules: {}, order: [] }; profileOrder.push(key); }
    return profiles[key];
  }
  function getRule(prof, num) {
    var key = String(num);
    if (!prof.rules[key]) {
      prof.rules[key] = { num: key, methods: [], msgType: 'any', status: [], criteria: [], operations: [], enabled: true, raw: [] };
      prof.order.push(key);
    }
    return prof.rules[key];
  }

  for (var i = 0; i < all.length; i++) {
    var lineRaw = all[i].replace(/\s+$/, '');
    var t = lineRaw.trim();
    if (!t || /^[#!;]/.test(t)) continue;

    // remember the enclosing signaling/trunk group for binding lines
    var gm = t.match(/(?:signaling\s*group|signalinggroup|sipTrunkGroup|trunk\s*group)\s*:?\s*["']?([A-Za-z0-9_.:\-]+)/i);
    if (gm) lastGroup = gm[1];

    // bindings (both CLI and Edge-export phrasing)
    var bm = t.match(/(input|output)AdapterProfile\s+["']?([A-Za-z0-9_.\-]+)/i);
    if (bm) {
      binds.push({
        profile: bm[2], kind: 'signaling-group',
        name: lastGroup || 'signaling group', direction: bm[1].toLowerCase() === 'input' ? 'in' : 'out'
      });
    }
    var bm2 = t.match(/\b(inbound|outbound)\b[^:=]{0,40}(?:profile|adapter|manipulation)\s*[:=]\s*["']?([A-Za-z0-9_.\-]+)/i);
    if (bm2) {
      binds.push({
        profile: bm2[2], kind: 'signaling-group',
        name: lastGroup || 'signaling group', direction: bm2[1].toLowerCase() === 'inbound' ? 'in' : 'out'
      });
    }

    var toks = tokenize(t);
    if (!toks.length) continue;
    var lead = toks[0].toLowerCase();
    if (lead === 'set' || lead === 'configure' || lead === 'admin' || lead === 'request') toks = toks.slice(1);
    if (!toks.length) continue;

    // profile header, either `... sipAdaptorProfile NAME ...` or `SMM profile: NAME`
    var pIdx = -1;
    for (var p = 0; p < toks.length; p++) {
      if (/^sipadaptorprofile$/i.test(toks[p])) { pIdx = p; break; }
    }
    if (pIdx === -1) {
      var pm = t.match(/^(?:signaling\s*manipulation|message\s*manipulation|smm)\s*(?:profile)?\s*[:=]?\s*["']?([A-Za-z0-9_.\-]+)/i);
      if (pm) { curProfile = getProfile(pm[1]); curRule = null; curCriterion = null; curOperation = null; continue; }
    } else {
      var pname = toks[pIdx + 1];
      if (!pname) continue;
      curProfile = getProfile(pname);
      curRule = null; curCriterion = null; curOperation = null;
      toks = toks.slice(pIdx + 2);
    }
    if (!curProfile) continue;
    if (curRule) curRule.raw.push(t);

    // keyword walk over the remaining tokens
    var k = 0;
    while (k < toks.length) {
      var kw = String(toks[k]);
      var low = kw.toLowerCase();
      var next = toks[k + 1] == null ? null : String(toks[k + 1]);
      if (low === 'rule' || low === 'rules') {
        var num = next != null && /^\d+$/.test(next) ? next : String(curProfile.order.length + 1);
        curRule = getRule(curProfile, num);
        curRule.raw.push(t);
        curCriterion = null; curOperation = null;
        k += (next != null && /^\d+$/.test(next)) ? 2 : 1;
        continue;
      }
      if (low === 'criterion' || low === 'criteria') {
        if (!curRule) curRule = getRule(curProfile, String(curProfile.order.length + 1));
        var ck = next == null ? '' : next.toLowerCase();
        if (ck === 'messagetype' || ck === 'message') { curCriterion = { kind: 'messageType' }; k += 2; }
        else if (ck === 'header') {
          curCriterion = { kind: 'header', header: toks[k + 2] == null ? null : String(toks[k + 2]) };
          k += (toks[k + 2] == null ? 2 : 3);
        } else if (ck === 'requesturi' || ck === 'requestline') { curCriterion = { kind: 'header', header: 'Request-URI' }; k += 2; }
        else if (ck === 'sipmessagebody' || ck === 'body' || ck === 'sdp') { curCriterion = { kind: 'header', header: 'SDP body' }; k += 2; }
        else { curCriterion = { kind: ck || 'unknown', header: null }; k += (next == null ? 1 : 2); }
        curRule.criteria.push(curCriterion);
        curOperation = null;
        continue;
      }
      if (low === 'operation' || low === 'operations') {
        if (!curRule) curRule = getRule(curProfile, String(curProfile.order.length + 1));
        var ok = next == null ? '' : next.toLowerCase();
        if (ok === 'header') {
          curOperation = { header: toks[k + 2] == null ? null : String(toks[k + 2]), element: null, index: null, action: null, value: null };
          k += (toks[k + 2] == null ? 2 : 3);
        } else if (ok === 'requesturi' || ok === 'requestline') {
          curOperation = { header: 'Request-URI', element: null, index: null, action: null, value: null }; k += 2;
        } else if (ok === 'sipmessagebody' || ok === 'body' || ok === 'sdp') {
          curOperation = { header: 'SDP body', element: null, index: null, action: null, value: null }; k += 2;
        } else if (ok === 'variable' || ok === 'store') {
          curOperation = { header: toks[k + 2] == null ? 'variable' : String(toks[k + 2]), element: null, index: null, action: 'store', value: null };
          k += (toks[k + 2] == null ? 2 : 3);
        } else {
          curOperation = { header: next || null, element: null, index: null, action: null, value: null };
          k += (next == null ? 1 : 2);
        }
        curRule.operations.push(curOperation);
        curCriterion = null;
        continue;
      }
      if (low === 'methodtypes' || low === 'methodtype' || low === 'methodtypelist' || low === 'method') {
        if (curRule) {
          var mk = k + 1;
          while (mk < toks.length && !/^(type|statuscode|statuscodes|condition|value|operation|criterion|rule|state|actiontype)$/i.test(toks[mk])) {
            var mm = parseMethods(toks[mk]);
            for (var mi = 0; mi < mm.length; mi++) if (curRule.methods.indexOf(mm[mi]) === -1) curRule.methods.push(mm[mi]);
            mk++;
          }
          k = mk; continue;
        }
        k += 1; continue;
      }
      if (low === 'type' || low === 'messagetypeclass') {
        if (curRule && next) curRule.msgType = normMsgType(next);
        k += 2; continue;
      }
      if (low === 'statuscode' || low === 'statuscodes' || low === 'responsecode') {
        if (curRule && next) curRule.status.push(String(next));
        k += 2; continue;
      }
      if (low === 'condition' || low === 'matchtype') {
        if (curCriterion && next) curCriterion.condition = next;
        k += 2; continue;
      }
      if (low === 'value' || low === 'headervalue' || low === 'regexvalue' || low === 'matchvalue' ||
          low === 'regex' || low === 'to' || low === 'newvalue') {
        if (curOperation) { if (next != null) curOperation.value = next; }
        else if (curCriterion) { if (next != null) curCriterion.value = next; }
        k += 2; continue;
      }
      if (low === 'tokenvalue' || low === 'token') {
        var tgt = curOperation || curCriterion;
        if (tgt) {
          tgt.element = 'value';
          if (next != null && /^\d+$/.test(next)) { tgt.index = parseInt(next, 10); k += 2; continue; }
        }
        k += 1; continue;
      }
      if (low === 'paramvalue' || low === 'param' || low === 'parameter') {
        var tgt2 = curOperation || curCriterion;
        if (tgt2) {
          if (next != null && !/^(actiontype|value|condition|operation|criterion|rule)$/i.test(next)) {
            tgt2.element = (String(next).toLowerCase() === 'tag') ? 'param.tag' : 'param.' + next;
            k += 2; continue;
          }
          tgt2.element = 'param';
        }
        k += 1; continue;
      }
      if (low === 'uriuser' || low === 'urihost' || low === 'uriport' || low === 'user' || low === 'host' ||
          low === 'displayname' || low === 'display' || low === 'uri' || low === 'entirevalue') {
        var tgt3 = curOperation || curCriterion;
        if (tgt3) tgt3.element = ribbonElement(low);
        k += 1; continue;
      }
      if (low === 'actiontype' || low === 'action') {
        if (curOperation && next) curOperation.action = next;
        k += 2; continue;
      }
      if (low === 'valuetype' || low === 'from' || low === 'applymatchheader' || low === 'advancedsmm' ||
          low === 'description' || low === 'sequence') {
        k += 2; continue;
      }
      if (low === 'state' || low === 'adminstate') {
        var on = next != null && /^(enabled|enable|true|on)$/i.test(next);
        if (curRule) curRule.enabled = on; else curProfile.enabled = on;
        k += 2; continue;
      }
      k += 1;
    }
  }

  // profile -> bindings/direction
  var bindByProfile = {};
  for (var bi = 0; bi < binds.length; bi++) {
    var bd = binds[bi];
    if (!profiles[bd.profile]) continue;   // ignore bindings to profiles we never saw
    if (!bindByProfile[bd.profile]) bindByProfile[bd.profile] = { bindings: [], direction: null, seen: {} };
    var sig = bd.kind + '|' + bd.name;
    if (!bindByProfile[bd.profile].seen[sig]) {
      bindByProfile[bd.profile].seen[sig] = true;
      bindByProfile[bd.profile].bindings.push({ kind: bd.kind, name: String(bd.name) });
    }
    bindByProfile[bd.profile].direction = mergeDirection(bindByProfile[bd.profile].direction, bd.direction);
  }

  // build IR
  var rules = [];
  for (var pi = 0; pi < profileOrder.length; pi++) {
    var prof = profiles[profileOrder[pi]];
    var pb = bindByProfile[prof.name] || null;
    for (var ri = 0; ri < prof.order.length; ri++) {
      var rl = prof.rules[prof.order[ri]];
      var conds = [];
      for (var ci = 0; ci < rl.criteria.length; ci++) {
        var cr = rl.criteria[ci];
        if (cr.kind === 'messageType') continue;
        var hdr = cr.header ? (cr.header === 'SDP body' ? 'SDP body' : displayHeader(cr.header)) : null;
        var cmp = ribbonComparison(cr.condition, cr.value);
        var el = cr.element ? '.' + cr.element : '';
        conds.push(makeCondition((hdr || 'header') + el, cmp,
          (cmp === 'exists' || cmp === 'absent') ? null : (cr.value == null ? null : String(cr.value)),
          'criterion header ' + (cr.header || '?') + ' ' + (cr.condition || '') + ' ' + (cr.value == null ? '' : cr.value), false));
      }
      for (var si = 0; si < rl.status.length; si++) {
        conds.push(makeCondition('response.status', 'matches', String(rl.status[si]), 'statusCode ' + rl.status[si], false));
      }
      var ops = rl.operations.length ? rl.operations : [null];
      for (var oi = 0; oi < ops.length; oi++) {
        var op = ops[oi];
        var rule = blankRule('ribbon');
        rule.name = prof.name + ' rule ' + rl.num + (ops.length > 1 ? ' op ' + (oi + 1) : '');
        rule.setName = prof.name;
        rule.order = /^\d+$/.test(rl.num) ? parseInt(rl.num, 10) : ri;
        rule.enabled = prof.enabled !== false && rl.enabled !== false;
        rule.scope.msgType = rl.msgType || 'any';
        rule.scope.methods = (rl.methods || []).slice();
        rule.scope.direction = pb ? pb.direction : null;
        rule.bindings = pb ? pb.bindings.slice() : [];
        rule.conditions = conds.slice();
        rule.raw = (rl.raw || []).join('\n');
        if (op) {
          var mapped = ribbonOperation(op.action);
          rule.operation = mapped.op;
          rule.subOperation = mapped.sub;
          rule.target.header = op.header ? (op.header === 'SDP body' ? 'SDP body' : displayHeader(op.header)) : null;
          rule.target.element = op.element || null;
          rule.target.index = op.index == null ? null : op.index;
          rule.elementRaw = op.element || null;
          rule.value = makeValue(op.value);
          if (op.action === 'store') rule.operation = 'store';
        } else {
          warnings.push('ribbon: ' + rule.name + ' has criteria but no operation');
        }
        rules.push(rule);
      }
    }
  }
  return rules;
}

// ===========================================================================
// parseConfig
// ===========================================================================

var PARSERS = {
  'oracle-acme': parseAcme,
  'audiocodes': parseAudioCodes,
  'ribbon': parseRibbon
};
var VENDOR_ORDER = ['oracle-acme', 'audiocodes', 'ribbon'];
var MAX_RULES = 2000;
var MAX_TEXT = 4 * 1024 * 1024;

/**
 * Parse an SBC configuration excerpt into the vendor-neutral HmrRule IR.
 *
 * Detects the vendor from distinctive tokens, runs that vendor's parser, and
 * falls back to the other parsers when the detected one finds no rules (the
 * result then says so in `warnings` and carries a lower confidence). Never
 * throws: unparseable input yields `vendor:'unknown'`, `rules: []` and warnings.
 *
 * @param {string} text raw configuration text (running config, .ini export, SMM text)
 * @returns {{vendor: ('oracle-acme'|'audiocodes'|'ribbon'|'unknown'), confidence: number,
 *   rules: Array<object>, warnings: string[]}} parsed rules in configuration order
 */
function parseConfig(text) {
  var warnings = [];
  var result = { vendor: 'unknown', confidence: 0, rules: [], warnings: warnings };
  var src = typeof text === 'string' ? text : (text && typeof text.toString === 'function' ? String(text) : '');
  if (!src || !src.trim()) {
    warnings.push('No configuration text supplied.');
    return result;
  }
  if (src.length > MAX_TEXT) {
    src = src.slice(0, MAX_TEXT);
    warnings.push('Configuration truncated at 4 MB for analysis.');
  }

  var det;
  try { det = detectVendor(src); } catch (e) { det = { vendor: 'unknown', confidence: 0 }; }
  var candidates = det.vendor === 'unknown'
    ? VENDOR_ORDER.slice()
    : [det.vendor].concat(VENDOR_ORDER.filter(function (v) { return v !== det.vendor; }));

  var chosen = null, rules = [];
  for (var i = 0; i < candidates.length; i++) {
    var v = candidates[i];
    var got = [];
    try {
      got = PARSERS[v](src, warnings) || [];
    } catch (e) {
      warnings.push(v + ' parser failed: ' + (e && e.message ? e.message : String(e)));
      got = [];
    }
    if (got.length) { chosen = v; rules = got; break; }
  }

  if (!chosen) {
    result.vendor = det.vendor;
    result.confidence = det.vendor === 'unknown' ? 0 : Math.min(det.confidence, 0.4);
    warnings.push(det.vendor === 'unknown'
      ? 'Could not identify the SBC vendor and found no manipulation rules. Paste an Oracle/Acme sip-manipulation block, an AudioCodes MessageManipulations table, or Ribbon SMM rule text.'
      : 'Looks like ' + det.vendor + ' configuration, but no header-manipulation rules were found in it.');
    return result;
  }

  result.vendor = chosen;
  if (chosen === det.vendor) {
    result.confidence = Math.max(det.confidence, 0.5);
  } else {
    result.confidence = 0.45;
    warnings.push('Vendor tokens suggested ' + (det.vendor === 'unknown' ? 'nothing definite' : det.vendor) +
      ', but only the ' + chosen + ' parser found rules — treating this as ' + chosen + ' with reduced confidence.');
  }

  if (rules.length > MAX_RULES) {
    warnings.push('Config contains ' + rules.length + ' rules; only the first ' + MAX_RULES + ' are analysed.');
    rules = rules.slice(0, MAX_RULES);
  }

  for (var r = 0; r < rules.length; r++) {
    var rule = rules[r];
    rule.id = 'h' + (r + 1);
    rule.vendor = chosen;
    if (!rule.name) rule.name = 'rule ' + (r + 1);
    if (!rule.scope) rule.scope = { direction: null, msgType: 'any', methods: [] };
    if (!Array.isArray(rule.scope.methods)) rule.scope.methods = [];
    if (!rule.target) rule.target = { header: null, element: null, index: null };
    if (!Array.isArray(rule.conditions)) rule.conditions = [];
    if (!Array.isArray(rule.bindings)) rule.bindings = [];
    if (typeof rule.raw !== 'string') rule.raw = '';
  }
  // Non-enumerable back-reference so explainRule can do cross-rule checks
  // (precedence, delete-then-add, store-before-use) without changing the
  // serialized shape.
  for (var s = 0; s < rules.length; s++) {
    try {
      Object.defineProperty(rules[s], '_siblings', { value: rules, enumerable: false, configurable: true, writable: true });
    } catch (e) { /* non-fatal */ }
  }
  result.rules = rules;
  return result;
}

// ===========================================================================
// citations — hand-written, only references we are confident are correct.
// Where the exact section number is not certain, the section is omitted (and
// with it the URL anchor), per the ARCHITECTURE rule.
// ===========================================================================

/**
 * Build a Citation object.
 * @param {string} source e.g. 'RFC 3261'
 * @param {?string} section e.g. 'Section 8.1.1.7' (null when uncertain)
 * @param {string} title short title of the cited passage
 * @param {string} note why this reference applies to the rule
 * @returns {{source: string, section: ?string, title: string, url: ?string, note: string}}
 */
function rfc(source, section, title, note) {
  var m = String(source).match(/^RFC\s*(\d+)$/i);
  var url = null;
  if (m) {
    url = 'https://www.rfc-editor.org/rfc/rfc' + m[1];
    if (section) {
      var num = String(section).replace(/^Section\s*/i, '').trim();
      if (/^[\d.]+$/.test(num)) url += '#section-' + num;
    }
  }
  return { source: String(source), section: section || null, title: String(title), url: url, note: String(note) };
}

var CITE = {
  via: function () {
    return rfc('RFC 3261', 'Section 8.1.1.7', 'Via',
      'The Via branch is a transaction identifier computed by the element that sends the request; rewriting Via or its branch breaks transaction matching, loop detection and response routing.');
  },
  proxyVia: function () {
    return rfc('RFC 3261', 'Section 16.6', 'Request Forwarding',
      'A proxy or B2BUA inserts its own Via and decrements Max-Forwards as it forwards; anything a manipulation rule writes into those fields is replaced by the box itself.');
  },
  maxForwards: function () {
    return rfc('RFC 3261', 'Section 8.1.1.6', 'Max-Forwards',
      'Max-Forwards is a hop counter maintained by each forwarding element, not a policy field.');
  },
  callId: function () {
    return rfc('RFC 3261', 'Section 8.1.1.4', 'Call-ID',
      'Call-ID identifies the dialog and must stay the same for the life of that dialog on that leg.');
  },
  cseq: function () {
    return rfc('RFC 3261', 'Section 8.1.1.5', 'CSeq',
      'CSeq orders transactions inside a dialog; changing it desynchronises the peer\'s transaction state.');
  },
  contact: function () {
    return rfc('RFC 3261', 'Section 8.1.1.8', 'Contact',
      'Contact is the direct route to the sending UA for subsequent in-dialog requests; the SBC rewrites it to its own address for topology hiding, so hand-written values are usually overwritten or unroutable.');
  },
  dialog: function () {
    return rfc('RFC 3261', 'Section 12', 'Dialogs',
      'The dialog is identified by Call-ID plus the local and remote tags; rewriting a tag mid-dialog makes in-dialog requests unmatchable.');
  },
  mandatory: function () {
    return rfc('RFC 3261', 'Section 8.1.1', 'Generating the Request',
      'To, From, Call-ID, CSeq, Max-Forwards and Via are mandatory in every SIP request; deleting one produces a malformed message the peer should reject with a 400.');
  },
  recordRoute: function () {
    return rfc('RFC 3261', 'Section 12.1.1', 'UAS behavior',
      'The Record-Route set captured at dialog setup determines how ACK, re-INVITE and BYE are routed; changing or removing it after the fact leaves those requests with nowhere to go.');
  },
  rr5658: function () {
    return rfc('RFC 5658', null, 'Addressing Record-Route Issues in SIP',
      'Record-Route rewriting at a multi-homed or topology-hiding element is exactly the area this RFC exists to constrain — double Record-Route, not hand edits, is the supported pattern.');
  },
  ack: function () {
    return rfc('RFC 3261', 'Section 13.2.2.4', 'The ACK Request',
      'ACK for a 2xx is sent to the Contact/route set from the answer; a manipulation that alters those makes the ACK undeliverable and the call drops when the retransmit timer expires.');
  },
  response: function () {
    return rfc('RFC 3261', 'Section 8.2.6', 'Generating the Response',
      'A UAS copies To, From, Call-ID, CSeq and Via from the request into the response; a rule with no msg-type restriction also rewrites them there, so the response no longer matches the transaction the peer sent.');
  },
  requestUri: function () {
    return rfc('RFC 3261', 'Section 8.1.1.1', 'Request-URI',
      'Only requests carry a Request-URI; a response has a status line instead, so a condition or target naming the Request-URI on a response can never apply.');
  },
  mtu: function () {
    return rfc('RFC 3261', 'Section 18.1.1', 'Sending Requests',
      'A request within 200 bytes of the path MTU (practically ~1300 bytes on Ethernet) must be sent over a congestion-controlled transport; adding headers pushes UDP INVITEs over that line and the fragments are commonly dropped.');
  },
  privateIp: function () {
    return rfc('RFC 1918', 'Section 3', 'Private Address Space',
      'Addresses in 10/8, 172.16/12 and 192.168/16 are not routable on the public Internet; writing one into a signalling header sends the far end somewhere it can never reach.');
  },
  pai: function () {
    return rfc('RFC 3325', null, 'P-Asserted-Identity',
      'P-Asserted-Identity is only meaningful inside a trust domain, and must be removed when a message leaves it — asserting an identity toward an untrusted peer is a spoofing risk, and toward a carrier it is usually rejected or ignored.');
  },
  privacy: function () {
    return rfc('RFC 3323', null, 'A Privacy Mechanism for SIP',
      'Privacy handling ties together the identity headers; changing one of them without the Privacy header leaves an inconsistent request.');
  },
  prack: function () {
    return rfc('RFC 3262', 'Section 3', 'UAC Behavior',
      'Reliable provisional responses are negotiated with the 100rel option tag in Supported/Require; manipulating those tags on one leg only creates a PRACK mismatch the SBC then has to absorb.');
  },
  timers: function () {
    return rfc('RFC 4028', 'Section 3', 'Session-Expires Header Field',
      'Session-Expires must not be below Min-SE, and the refresher choice has to survive to the answerer; rewriting either value without the other invites a 422 or a mid-call teardown.');
  },
  dtmf: function () {
    return rfc('RFC 4733', null, 'RTP Payload for DTMF Digits',
      'The telephone-event payload type is negotiated per leg in SDP; changing it in signalling without changing what the media plane actually sends produces silent DTMF.');
  },
  sdpOffer: function () {
    return rfc('RFC 3264', 'Section 6.1', 'Unicast Streams',
      'An answer must correspond to the offer stream by stream; editing SDP with a header-manipulation rule bypasses the offer/answer state machine the SBC is running.');
  },
  historyInfo: function () {
    return rfc('RFC 7044', null, 'An Extension to the SIP for Request History Information',
      'History-Info is the standards-track way to carry redirection history; Diversion (RFC 5806) is historic and only kept for interop with equipment that predates it.');
  },
  diversion: function () {
    return rfc('RFC 5806', null, 'Diversion Indication in SIP',
      'Diversion is an informational, historic header retained for interop — if the far end accepts History-Info, prefer it.');
  },
  telUri: function () {
    return rfc('RFC 3966', null, 'The tel URI for Telephone Numbers',
      'A global telephone number in a tel or sip URI has to start with + and carry only digits and visual separators; hand-built values that skip the + are read as local numbers.');
  }
};

// ===========================================================================
// description helpers for the explanation layer
// ===========================================================================

/** Headers the SBC regenerates or owns itself, with why manipulating them is a problem. */
var REGENERATED = {
  'via': { severity: 'crit', cite: CITE.via, why: 'Via is a hop-by-hop transaction header. The SBC writes its own Via when it forwards, and the branch parameter is a transaction identifier — a rule that edits it either has no effect or breaks response routing and loop detection.' },
  'max-forwards': { severity: 'notice', cite: CITE.maxForwards, why: 'Max-Forwards is a hop counter the SBC decrements itself as it forwards, so a configured value is overwritten.' },
  'content-length': { severity: 'warn', cite: function () { return rfc('RFC 3261', null, 'Content-Length', 'Content-Length must equal the actual body length; the SBC recomputes it after any body change, and a stale value makes the message unparseable on a stream transport.'); }, why: 'Content-Length is recomputed by the SBC after every body change — manipulating it can only make it wrong.' },
  'record-route': { severity: 'warn', cite: CITE.recordRoute, why: 'The Record-Route set is built by the boxes in the path and is what routes ACK, re-INVITE and BYE. Editing it by rule is how mid-call requests end up with nowhere to go.' },
  'route': { severity: 'warn', cite: CITE.recordRoute, why: 'The Route set comes from the peer\'s Record-Route; overwriting it sends in-dialog requests to an address the peer never advertised.' },
  'call-id': { severity: 'crit', cite: CITE.callId, why: 'Call-ID identifies the dialog on this leg. The SBC generates its own on the egress leg, and changing it mid-dialog orphans everything that follows.' },
  'cseq': { severity: 'crit', cite: CITE.cseq, why: 'CSeq is transaction state, not policy. Rewriting it desynchronises the peer.' },
  'contact': { severity: 'notice', cite: CITE.contact, why: 'The SBC writes its own Contact for topology hiding, so a configured host is normally overwritten; only the user part usually survives.' }
};

var MANDATORY_HEADERS = { 'to': 1, 'from': 1, 'call-id': 1, 'cseq': 1, 'via': 1, 'max-forwards': 1 };

/** Plain-English description of a regex/wildcard match value, or null. */
function describePattern(p) {
  var s = String(p == null ? '' : p).trim();
  if (!s) return null;
  var m = s.match(/^\^?\\?\[?0-9\]?\{(\d+)\}\$?$/) || s.match(/^\^\\d\{(\d+)\}\$$/) || s.match(/^\^\[0-9\]\{(\d+)\}\$$/);
  if (m) return 'a ' + m[1] + '-digit number, which on an enterprise trunk is an internal extension';
  if (/^\^\\?\+/.test(s)) return 'a number already in +E.164 form';
  if (/^\^00/.test(s)) return 'a number in 00 international form';
  if (/^\^0[^0]/.test(s)) return 'a number in national 0 form';
  if (/^\^\d+/.test(s)) return 'a value starting with ' + (s.match(/^\^(\d+)/) || [])[1];
  if (/sip:/i.test(s)) return 'a SIP URI';
  if (/^\.\*$/.test(s) || /^\*$/.test(s)) return 'anything at all';
  return null;
}

/** Describe the target of a rule ('the user part of the From header'). */
function describeTarget(rule) {
  var t = (rule && rule.target) || {};
  var header = t.header ? String(t.header) : null;
  var el = t.element ? String(t.element) : null;
  var raw = rule && rule.elementRaw ? String(rule.elementRaw) : null;
  var elName = null;
  if (el === 'uri.user') elName = 'the user part';
  else if (el === 'uri.host') elName = 'the host part';
  else if (el === 'uri.port') elName = 'the port';
  else if (el === 'uri') elName = 'the URI';
  else if (el === 'display') elName = 'the display name';
  else if (el === 'param.tag') elName = 'the tag parameter';
  else if (el && el.indexOf('param.') === 0) elName = 'the ' + el.slice(6) + ' parameter';
  else if (el === 'param') elName = 'a parameter';
  else if (el === 'value') elName = 'the value';
  else if (el === 'status-code') elName = 'the status code';
  else if (el === 'reason') elName = 'the reason phrase';
  else if (el) elName = 'the ' + el.replace(/\./g, ' ') + ' element' + (raw && raw !== el ? ' (' + raw + ')' : '');
  if (header && elName) return elName + ' of the ' + header + ' header';
  if (header) return 'the ' + header + ' header';
  if (elName) return elName;
  return 'an unspecified target';
}

/** Verb phrase for the operation (+ AudioCodes-style prefix/suffix variants). */
function describeOperation(rule) {
  var op = rule && rule.operation;
  var sub = rule && rule.subOperation;
  if (sub === 'add-prefix') return 'prepends';
  if (sub === 'add-suffix') return 'appends';
  if (sub === 'remove-prefix') return 'strips a leading';
  if (sub === 'remove-suffix') return 'strips a trailing';
  if (sub === 'find-replace-all') return 'find-and-replaces inside';
  switch (op) {
    case 'add': return 'adds';
    case 'delete': return 'removes';
    case 'modify': return 'rewrites';
    case 'replace': return 'replaces';
    case 'store': return 'stores';
    case 'none': default: return 'inspects (no change to)';
  }
}

/** One-clause description of a single condition. */
function describeCondition(cond) {
  if (!cond) return null;
  var el = cond.element ? String(cond.element) : 'the message';
  var val = cond.value == null ? '' : String(cond.value);
  var not = cond.negate ? 'does not ' : '';
  switch (cond.comparison) {
    case 'exists': return cond.negate ? el + ' is absent' : el + ' is present';
    case 'absent': return el + ' is absent';
    case 'equals': return el + ' ' + (cond.negate ? 'is not ' : 'is exactly ') + (val || '(empty)');
    case 'matches': {
      var d = describePattern(val);
      return el + ' ' + not + 'matches ' + (val || '(empty)') + (d ? ' (' + d + ')' : '');
    }
    default: return el + ' ' + (cond.comparison || 'matches') + ' ' + val;
  }
}

/** Describe the scope (msg-type + methods) as an adverbial clause. */
function describeScope(rule) {
  var sc = (rule && rule.scope) || {};
  var methods = Array.isArray(sc.methods) ? sc.methods : [];
  var mList = methods.length ? methods.join('/') : null;
  if (sc.msgType === 'request') return 'on ' + (mList ? mList + ' requests' : 'requests');
  if (sc.msgType === 'response') return 'on ' + (mList ? 'responses to ' + mList : 'responses');
  return 'on ' + (mList ? 'any ' + mList + ' request or response' : 'every request and response');
}

/** Describe the direction clause, naming the bound interfaces when known. */
function describeDirection(rule) {
  var dir = rule && rule.scope ? rule.scope.direction : null;
  var binds = (rule && Array.isArray(rule.bindings)) ? rule.bindings : [];
  var names = binds.map(function (b) { return (b && b.kind ? b.kind + ' ' : '') + (b && b.name ? b.name : ''); })
    .filter(function (s) { return s.trim() !== ''; });
  var where = names.length ? ' (' + names.slice(0, 3).join(', ') + (names.length > 3 ? ', +' + (names.length - 3) + ' more' : '') + ')' : '';
  if (dir === 'out') return 'On egress' + (names.length ? ' to ' + names.slice(0, 2).join(' and ') : '');
  if (dir === 'in') return 'On ingress' + (names.length ? ' from ' + names.slice(0, 2).join(' and ') : '');
  if (dir === 'both') return 'In both directions' + where;
  return 'In no direction yet — this rule is not bound to any interface, so as configured it never runs';
}

/** Describe the value being written. */
function describeValue(rule) {
  var v = rule && rule.value;
  if (!v || !v.text) return null;
  if (v.kind === 'expression') return 'the expression ' + v.text;
  var t = String(v.text);
  if (/^\+?\d{6,}$/.test(t.replace(/[\s().-]/g, ''))) return 'the fixed number ' + t;
  return t;
}

// ===========================================================================
// explainRule — intent, correctness check list, improvements
// ===========================================================================

/** One plain-English sentence: direction, trigger and effect. */
function buildIntent(rule) {
  var dir = describeDirection(rule);
  var verb = describeOperation(rule);
  var tgt = describeTarget(rule);
  var val = describeValue(rule);
  var sub = rule.subOperation;
  var conds = [];
  for (var i = 0; i < (rule.conditions || []).length; i++) {
    var d = describeCondition(rule.conditions[i]);
    if (d) conds.push(d);
  }
  var trigger = conds.length ? 'when ' + conds.join(' and ') : 'with no condition attached';
  var effect;
  if (sub === 'add-prefix' || sub === 'add-suffix') effect = verb + ' ' + (val || 'a value') + ' to ' + tgt;
  else if (sub === 'remove-prefix' || sub === 'remove-suffix') effect = verb + ' ' + (val || 'value') + ' from ' + tgt;
  else if (rule.operation === 'store') effect = verb + ' ' + tgt + ' for a later rule to reference';
  else if (rule.operation === 'delete') effect = verb + ' ' + tgt;
  else if (rule.operation === 'add') effect = verb + ' ' + tgt + (val ? ' with ' + (/^the /.test(val) ? val : 'the value ' + val) : ' with no value configured');
  else if (rule.operation === 'none') effect = 'matches ' + tgt + ' without changing it' + (rule.subOperation === 'sip-manip' && val ? ', chaining the manipulation ' + val : '');
  else if (rule.operation === 'replace') effect = 'sets ' + tgt + (val ? ' to ' + val : ', with no new value configured');
  else effect = verb + ' ' + tgt + (val ? ' to ' + val : ', with no new value configured');
  var sentence = dir + ', ' + effect + ' ' + describeScope(rule) + ', ' + trigger;
  if (rule.enabled === false) sentence = 'Administratively disabled: ' + sentence;
  return sentence.replace(/\s+/g, ' ').trim().replace(/\s+\./g, '.') + '.';
}

/** Store references made by a rule ('$RULE.$ER.$0', 'var.session.0'). */
function storeRefs(rule) {
  // Only the written value is inspected: vendor condition grammars use $-tokens
  // of their own ($HEADER, boolean operators), and treating those as store
  // references produces false alarms.
  var texts = [], refs = [], seen = {}, m;
  var IGNORE = {
    ORIGINAL: 1, REMAINDER: 1, NULL: 1, HEADER: 1, TRUE: 1, FALSE: 1,
    SELF: 1, ANY: 1, VALUE: 1
  };
  if (rule.value && rule.value.text) texts.push(String(rule.value.text));
  for (var t = 0; t < texts.length; t++) {
    var re = /\$([A-Za-z_][A-Za-z0-9_]*)/g;
    while ((m = re.exec(texts[t])) !== null) {
      var n = m[1];
      if (IGNORE[n.toUpperCase()]) continue;
      if (!seen['$' + n.toLowerCase()]) { seen['$' + n.toLowerCase()] = 1; refs.push(n); }
    }
    var re2 = /\bvar\.(session|call|global)\.(\d+)/gi;
    while ((m = re2.exec(texts[t])) !== null) {
      var key = 'var.' + m[1].toLowerCase() + '.' + m[2];
      if (!seen[key]) { seen[key] = 1; refs.push(key); }
    }
  }
  return refs;
}

/** Names/slots a rule makes available to later rules. */
function storeProvides(rule) {
  var out = [];
  if (rule.operation === 'store') {
    if (rule.name) out.push(String(rule.name).toLowerCase());
    if (rule.parentName) out.push(String(rule.parentName).toLowerCase());
  }
  var h = rule.target && rule.target.header ? String(rule.target.header) : '';
  if (/^var\./i.test(h) && rule.operation !== 'none' && rule.operation !== 'delete') out.push(h.toLowerCase());
  return out;
}

/** Could these two rules ever act on the same message? */
function scopesOverlap(a, b) {
  var sa = a.scope || {}, sb = b.scope || {};
  if (sa.msgType && sb.msgType && sa.msgType !== 'any' && sb.msgType !== 'any' && sa.msgType !== sb.msgType) return false;
  var ma = Array.isArray(sa.methods) ? sa.methods : [];
  var mb = Array.isArray(sb.methods) ? sb.methods : [];
  if (ma.length && mb.length) {
    for (var i = 0; i < ma.length; i++) if (mb.indexOf(ma[i]) !== -1) return true;
    return false;
  }
  return true;
}

/** Same target header + element? */
function sameTarget(a, b) {
  var ta = a.target || {}, tb = b.target || {};
  if (normHeader(ta.header) !== normHeader(tb.header)) return false;
  return String(ta.element || '') === String(tb.element || '');
}

var WRITE_OPS = { add: 1, modify: 1, replace: 1, delete: 1 };

/** Vendor-specific sentence about how to bind a manipulation. */
function bindingAdvice(vendor) {
  if (vendor === 'oracle-acme') return 'assign the sip-manipulation with in-manipulationid or out-manipulationid on the session-agent, sip-interface or realm-config that carries this traffic';
  if (vendor === 'audiocodes') return 'set the IP Group\'s (or IP Profile\'s) Inbound/Outbound Message Manipulation Set to this set\'s ManSetID — a -1 there means no set is applied';
  if (vendor === 'ribbon') return 'attach the profile as the inputAdapterProfile (inbound) or outputAdapterProfile (outbound) on the Signaling Group / trunk group';
  return 'attach the rule set to the interface, IP group or signalling group that carries this traffic';
}

/** Vendor-specific sentence about rule evaluation order. */
function precedenceNote(vendor) {
  if (vendor === 'oracle-acme') return 'Acme runs the header-rules of a sip-manipulation in configured order, so the later rule writes last';
  if (vendor === 'audiocodes') return 'AudioCodes runs the rows of a manipulation set in row-index order, so the higher index writes last';
  if (vendor === 'ribbon') return 'Ribbon runs SMM rules in rule-number order, so the higher rule number writes last';
  return 'rules in one set run in configured order, so the later rule writes last';
}

/**
 * Explain a rule: what it is for, whether it is correct, and how to improve it.
 *
 * `correctness.ok` is true only when no `crit` or `warn` issue was found.
 * Cross-rule checks (store-before-use, delete-then-add, precedence) use the
 * sibling rules from the same parseConfig() result — pass `opts.rules` to supply
 * them explicitly.
 *
 * @param {object} rule an HmrRule from parseConfig
 * @param {{rules?: object[]}} [opts] optional sibling context
 * @returns {{intent: string, correctness: {ok: boolean, issues: Array<{severity: string,
 *   detail: string, citation: ?object}>}, improvements: Array<{detail: string, rationale: string}>}}
 */
function explainRule(rule, opts) {
  var issues = [], improvements = [];
  if (!rule || typeof rule !== 'object') {
    return {
      intent: 'No rule supplied, so there is nothing to explain.',
      correctness: { ok: false, issues: [{ severity: 'warn', detail: 'explainRule was called without a rule object.', citation: null }] },
      improvements: []
    };
  }
  var r = {
    id: rule.id || null,
    name: rule.name || 'unnamed rule',
    vendor: rule.vendor || 'unknown',
    scope: rule.scope || { direction: null, msgType: 'any', methods: [] },
    conditions: Array.isArray(rule.conditions) ? rule.conditions : [],
    target: rule.target || { header: null, element: null, index: null },
    operation: rule.operation || 'none',
    value: rule.value || null,
    bindings: Array.isArray(rule.bindings) ? rule.bindings : [],
    setName: rule.setName || null,
    parentName: rule.parentName || null,
    order: typeof rule.order === 'number' ? rule.order : 0,
    enabled: rule.enabled !== false,
    subOperation: rule.subOperation || null,
    elementRaw: rule.elementRaw || null
  };
  var siblings = [];
  if (opts && Array.isArray(opts.rules)) siblings = opts.rules;
  else if (rule._siblings && Array.isArray(rule._siblings)) siblings = rule._siblings;
  var others = siblings.filter(function (s) { return s && s !== rule && s.id !== r.id; });

  function issue(sev, detail, citation) {
    issues.push({ severity: sev, detail: String(detail), citation: citation || null });
  }
  function improve(detail, rationale) {
    improvements.push({ detail: String(detail), rationale: String(rationale) });
  }

  var intent;
  try { intent = buildIntent(r); } catch (e) { intent = 'This rule could not be summarised (' + (e && e.message) + ').'; }

  try {
    var hNorm = normHeader(r.target.header);
    var hDisp = r.target.header ? String(r.target.header) : 'the target header';
    var el = r.target.element;
    var writes = !!WRITE_OPS[r.operation];
    var valText = r.value && r.value.text ? String(r.value.text) : '';
    var msgAny = !r.scope.msgType || r.scope.msgType === 'any';

    // --- target we could not resolve ---------------------------------------
    if (!r.target.header && r.operation !== 'none') {
      issue('warn', 'hiccup could not work out which header this rule targets, so the checks below are incomplete — the action subject was "' +
        (r.elementRaw || 'empty') + '". Treat the explanation as partial.', null);
    }

    // --- disabled ----------------------------------------------------------
    if (!r.enabled) {
      issue('warn', 'This rule (or the profile holding it) is administratively disabled, so nothing in it is applied to live traffic.', null);
    }

    // --- bound nowhere -----------------------------------------------------
    if (!r.bindings.length) {
      issue('warn', 'This rule is not bound to anything in the configuration supplied, so it never runs. To make it live, ' + bindingAdvice(r.vendor) + '.', null);
      improve('Bind the rule set: ' + bindingAdvice(r.vendor) + '.',
        'An unbound manipulation is the single most common reason a "configured" change is invisible in a trace — the rule reads correctly and simply never executes.');
    }

    // --- conditions: contradictions and impossible scopes ------------------
    var byElement = {};
    for (var i = 0; i < r.conditions.length; i++) {
      var c = r.conditions[i] || {};
      var celem = String(c.element || '').toLowerCase();
      var isStatusCond = /^response\.status/.test(celem) || /status/.test(celem);
      var key = String(c.element == null ? '' : c.element).toLowerCase();
      if (c.comparison === 'equals' && !c.negate && c.value != null) {
        if (byElement[key] && byElement[key] !== String(c.value)) {
          issue('crit', 'The conditions contradict each other: ' + (c.element || 'the same element') + ' is required to be exactly "' +
            byElement[key] + '" and exactly "' + c.value + '" at the same time, so this rule can never match anything.', null);
        }
        byElement[key] = String(c.value);
      }
      if (c.comparison === 'matches' && c.value) {
        try { new RegExp(String(c.value)); } catch (e) {
          issue('warn', 'The match value "' + c.value + '" is not a valid regular expression, so depending on the release the SBC either treats it as a literal string or refuses the rule — either way it will not match what you intended.', null);
        }
        var descAll = describePattern(String(c.value));
        if (descAll === 'anything at all') {
          issue('notice', 'The condition on ' + (c.element || 'the message') + ' matches anything, which is the same as having no condition at all — it is worth stating what you actually mean to catch.', null);
        }
        var v = String(c.value);
        var anchoredStart = v.charAt(0) === '^';
        var anchoredEnd = v.charAt(v.length - 1) === '$';
        if ((!anchoredStart || !anchoredEnd) && descAll !== 'anything at all' && !isStatusCond && /[0-9A-Za-z]/.test(v)) {
          var dirClause = (r.scope.direction === 'both' || !r.scope.direction)
            ? ' Because this rule is ' + (r.scope.direction === 'both' ? 'bound in both directions' : 'not bound to one direction') + ', an unanchored pattern can also fire on traffic travelling the other way, rewriting values that were already normalised.'
            : ' An unanchored pattern also matches the already-rewritten form, so the rule can fire a second time on its own output if the set is re-applied.';
          var example = /^[0-9]+$/.test(v)
            ? ' — a pattern of "' + v + '" also matches any longer number containing those digits, so +44' + v + '567890 matches too.'
            : ' — it also matches any value that merely contains "' + v.replace(/^\^/, '').replace(/\$$/, '') + '" somewhere.';
          issue('warn', 'The pattern "' + v + '" is not anchored (' +
            (anchoredStart ? 'no closing $' : (anchoredEnd ? 'no leading ^' : 'no ^ or $')) +
            '), so it matches anywhere inside the value' + example + dirClause, null);
          improve('Anchor the match value as ^' + v.replace(/^\^/, '').replace(/\$$/, '') + '$.',
            'Anchoring is what separates "this value is a 4-digit extension" from "this value contains four digits somewhere", and it is the difference between rewriting only internal callers and mangling carrier numbers.');
        }
      }
      // condition that cannot be evaluated in the configured scope
      if (/request-uri/.test(celem) && r.scope.msgType === 'response') {
        issue('crit', 'The condition tests the Request-URI but the rule is scoped to responses, and a response has a status line rather than a Request-URI — this condition can never match, so the rule never fires.', CITE.requestUri());
      }
      if (/^response\.status/.test(celem) && r.scope.msgType === 'request') {
        issue('crit', 'The condition tests a response status code but the rule is scoped to requests, so it can never match.', null);
      }
      // condition vs the rule's own target
      if (hNorm && normHeader(c.element ? String(c.element).split('.')[0] : '') === hNorm) {
        var wantsAbsent = c.comparison === 'absent' || (c.comparison === 'exists' && c.negate);
        var wantsPresent = c.comparison === 'exists' && !c.negate;
        if (wantsAbsent && (r.operation === 'modify' || r.operation === 'replace' || r.operation === 'delete' || r.operation === 'store')) {
          var opVerb = { modify: 'modifies', replace: 'replaces', delete: 'deletes', store: 'stores', add: 'adds' }[r.operation] || (r.operation + 's');
          issue('crit', 'The condition requires ' + hDisp + ' to be absent, but the action ' + opVerb + ' that same header — there is nothing to act on when the condition is true, so this rule can never do anything. If the intent was "insert it when it is missing", the action should be add.', null);
        }
        if (wantsPresent && r.operation === 'add') {
          issue('warn', 'The condition requires ' + hDisp + ' to be present and the action adds it, so a successful match produces a second ' + hDisp + ' rather than changing the existing one. Most peers read only the first instance, and some reject the duplicate.', null);
          improve('Use modify/manipulate on the existing ' + hDisp + ' instead of add.',
            'Add always inserts; only modify edits in place, which keeps one instance of the header and preserves its position and parameters.');
        }
      }
    }
    if (/request-uri/i.test(String(r.target.header || '')) && r.scope.msgType === 'response') {
      issue('crit', 'The rule targets the Request-URI on responses, which do not have one — as written this rule can never apply.', CITE.requestUri());
    }

    // --- headers the SBC owns / regenerates --------------------------------
    if (hNorm && REGENERATED[hNorm] && r.operation !== 'none') {
      var reg = REGENERATED[hNorm];
      var skip = (hNorm === 'contact' && (el === 'uri.user' || el === 'display'));
      if (!skip) {
        issue(reg.severity, 'This rule manipulates ' + hDisp + ', which the SBC generates itself on the outgoing leg. ' + reg.why +
          ' Expect either no visible effect in the trace or a broken transaction — check the capture before assuming the rule worked.',
          (typeof reg.cite === 'function' ? reg.cite() : null));
        if (hNorm === 'contact' || hNorm === 'via' || hNorm === 'record-route') {
          improve('Achieve this with the box\'s own topology/NAT settings rather than a header rule (Acme: realm + sip-interface; AudioCodes: IP Profile / SIP Interface; Ribbon: Signaling Group NAT and Record-Route handling).',
            'Those settings run inside the SBC\'s own routing logic, so the value survives; a header rule fights the code that rewrites the field a moment later.');
        }
      }
    }
    if (hNorm === 'via' && (el === 'param.branch' || /branch/i.test(String(r.elementRaw || '')) || /branch/i.test(valText))) {
      issue('crit', 'This rule touches the Via branch parameter. The branch is the transaction identifier: change it and responses stop matching the request, retransmission detection breaks, and loop detection is defeated.', CITE.via());
    }
    if (el === 'param.tag' && (hNorm === 'from' || hNorm === 'to')) {
      issue('crit', 'This rule manipulates the ' + hDisp + ' tag. Tags plus Call-ID identify the dialog, and the SBC allocates its own — rewriting a tag makes every in-dialog request (ACK, re-INVITE, BYE) unmatchable.', CITE.dialog());
    }

    // --- deleting mandatory headers ---------------------------------------
    if (r.operation === 'delete' && hNorm && MANDATORY_HEADERS[hNorm] && !el) {
      issue('crit', 'This rule deletes ' + hDisp + ', which is mandatory in every SIP request. The peer should answer 400 Bad Request; some stacks simply drop the message with no response at all, which looks like a network fault in a trace.', CITE.mandatory());
    }
    if (r.operation === 'delete' && hNorm === 'contact' && !el) {
      issue('crit', 'This rule deletes Contact. Without it the peer has no target for in-dialog requests, so the call typically answers and then fails at the ACK or the first re-INVITE/BYE.', CITE.contact());
    }
    if (r.operation === 'delete' && hNorm === 'record-route') {
      issue('crit', 'Deleting Record-Route removes the route set the peer needs for ACK, re-INVITE and BYE. The classic symptom is a call that answers, then drops around 32 seconds later when the 200 OK retransmissions give up.', CITE.ack());
    }

    // --- msg-type discipline ----------------------------------------------
    if (msgAny && r.operation !== 'none') {
      var identity = { from: 1, to: 1, contact: 1, 'request-uri': 1, 'p-asserted-identity': 1, 'p-preferred-identity': 1, 'remote-party-id': 1, 'call-id': 1, via: 1, diversion: 1, 'history-info': 1 };
      var isIdent = !!(hNorm && identity[hNorm]);
      var msgDetail = isIdent
        ? 'No message type is set, so this rule fires on responses as well as requests. The peer copies ' + hDisp +
          ' straight from the request into its responses, so changing it there leaves the response no longer matching the transaction it answers.'
        : 'No message type is set, so this rule fires on responses as well as requests. For a diagnostic or vendor header that is often harmless, but it doubles the traffic the rule touches and hides which direction the change was meant for.';
      issue(isIdent ? 'warn' : 'notice', msgDetail +
        ((!r.scope.methods || !r.scope.methods.length) ? ' With no method list either, it also runs on OPTIONS keepalives and REGISTER traffic.' : ''),
        CITE.response());
      improve('Restrict the scope to requests' + ((!r.scope.methods || !r.scope.methods.length) ? ' and to the methods you mean (usually INVITE)' : '') +
        ' — Acme: msg-type request; AudioCodes: MessageType invite.request; Ribbon: criterion messageType type request.',
        'A rule that only fires where it is needed is a rule you can reason about later; the "fires on everything" version is how a CLI fix quietly breaks OPTIONS keepalives and REGISTER refreshes.');
    }

    // --- stored values -----------------------------------------------------
    var refs = storeRefs(r);
    if (refs.length) {
      var matched = null;
      for (var o = 0; o < others.length && !matched; o++) {
        var provides = storeProvides(others[o]);
        for (var p = 0; p < provides.length; p++) {
          for (var q = 0; q < refs.length; q++) {
            if (provides[p] === String(refs[q]).toLowerCase()) { matched = others[o]; break; }
          }
          if (matched) break;
        }
      }
      if (!others.length) {
        issue('notice', 'The value references a stored element (' + refs.join(', ') + '). hiccup was given only this one rule, so it could not confirm that something earlier actually stores it — check that the store rule exists and runs first.', null);
      } else if (!matched) {
        issue('crit', 'The value references a stored element (' + refs.join(', ') +
          ') but no rule in this configuration stores it. On Acme an unresolved reference evaluates to empty, so the rule writes an empty value instead of failing visibly.', null);
      } else {
        var sameSet = String(matched.setName || '') === String(r.setName || '');
        var mOrder = typeof matched.order === 'number' ? matched.order : 0;
        if (sameSet && mOrder > r.order) {
          issue('crit', 'This rule reads the value stored by "' + (matched.name || matched.id) + '", but that rule is configured after this one in the same set. ' +
            precedenceNote(r.vendor) + ', so at the moment this rule runs the stored value is still empty (or holds the previous message\'s value).', null);
          improve('Move the store rule ahead of this one in the set.',
            'Store-then-use is strictly ordered; the reference is resolved at execution time, not at commit time, so configuration order is the execution contract.');
        } else if (!sameSet) {
          issue('notice', 'The stored value comes from a different manipulation set ("' + (matched.setName || 'unnamed') +
            '"). That works only if the other set is applied to the same message first — verify the binding order, because a cross-set reference is silent when it fails.', null);
        }
      }
    }
    if (r.operation === 'store' && others.length) {
      var consumed = false;
      var mine = storeProvides(r);
      for (var oo = 0; oo < others.length && !consumed; oo++) {
        var oRefs = storeRefs(others[oo]);
        for (var m2 = 0; m2 < oRefs.length; m2++) {
          for (var n2 = 0; n2 < mine.length; n2++) {
            if (String(oRefs[m2]).toLowerCase() === mine[n2]) { consumed = true; break; }
          }
          if (consumed) break;
        }
      }
      if (!consumed) {
        issue('notice', 'This rule stores a value but no other rule in the configuration reads it, so it does nothing on its own.', null);
        improve('Either reference the stored value from a later rule or delete this rule.',
          'A store with no consumer is dead configuration: it survives upgrades, confuses the next engineer, and costs a rule evaluation on every message.');
      }
    }

    // --- delete-then-add across siblings -----------------------------------
    if ((r.operation === 'delete' || r.operation === 'add') && hNorm) {
      var pair = null;
      for (var d2 = 0; d2 < others.length; d2++) {
        var ot = others[d2];
        if (String(ot.setName || '') !== String(r.setName || '')) continue;
        if (normHeader(ot.target && ot.target.header) !== hNorm) continue;
        if (r.operation === 'delete' && ot.operation === 'add') { pair = ot; break; }
        if (r.operation === 'add' && ot.operation === 'delete') { pair = ot; break; }
      }
      if (pair) {
        issue('notice', 'This rule and "' + (pair.name || pair.id) + '" delete and re-add ' + hDisp +
          ' in the same set. That works, but it moves the header to the end of the message, drops any parameters you did not re-state, and leaves a window in which later rules in the same set see no ' + hDisp + ' at all.', null);
        improve('Replace the delete + add pair with a single manipulate/modify on ' + hDisp + '.',
          'One in-place edit keeps header order and parameters, halves the rule count, and removes the ordering dependency between the two rules.');
      }
    }

    // --- precedence conflicts inside the set -------------------------------
    if (writes && others.length) {
      for (var pc = 0; pc < others.length; pc++) {
        var op2 = others[pc];
        if (String(op2.setName || '') !== String(r.setName || '')) continue;
        if (!WRITE_OPS[op2.operation]) continue;
        if (!sameTarget(r, op2)) continue;
        if (!scopesOverlap(r, op2)) continue;
        if (op2.operation === r.operation && r.operation === 'add') continue;
        var o2Order = typeof op2.order === 'number' ? op2.order : 0;
        var later = o2Order > r.order ? (op2.name || op2.id) : (r.name || r.id);
        var sev2 = (op2.operation === 'delete' || r.operation === 'delete') ? 'warn' : 'notice';
        issue(sev2, 'Precedence conflict: "' + (op2.name || op2.id) + '" also writes ' + describeTarget(r) +
          ' with an overlapping scope. ' + precedenceNote(r.vendor) + ', so "' + later + '" is what the far end actually sees.' +
          (o2Order === r.order ? ' Both are at the same configured position, which makes the outcome release-dependent — do not rely on it.' : ''), null);
        improve('Make the two conditions mutually exclusive, or merge them into one rule.',
          'Two rules writing the same element is the classic "I fixed it and it came back" bug: the trace shows the second rule\'s value and the first rule looks innocent.');
        break;
      }
    }

    // --- values -------------------------------------------------------------
    if ((r.operation === 'add' || r.operation === 'modify' || r.operation === 'replace') && !valText) {
      issue('warn', 'No new value is configured for a ' + r.operation + ' action, so the rule writes an empty ' +
        (el ? 'element' : 'header') + '. An empty header is worse than a missing one: it is syntactically present and many stacks reject it.', null);
    }
    if (valText && hasPrivateIp(valText)) {
      issue('crit', 'The value written contains a private (RFC 1918) address: ' + valText +
        '. If this leaves the enterprise, the far end is being told to send signalling or media to an address it cannot route — the usual symptom is one-way audio or an unanswered ACK.', CITE.privateIp());
    }
    if (valText && valText.length >= 100 && r.operation === 'add') {
      issue('notice', 'This rule adds about ' + valText.length + ' bytes to every matching message. On UDP that pushes a large INVITE toward the ~1300-byte fragmentation line, and fragmented INVITEs are the retransmit-with-no-response pattern.', CITE.mtu());
    }
    if (r.value && r.value.kind === 'literal' && /^\d{9,}$/.test(valText) &&
        (el === 'uri.user' || el === 'value' || el === null) &&
        (hNorm === 'from' || hNorm === 'to' || hNorm === 'p-asserted-identity' || hNorm === 'request-uri')) {
      issue('info', 'The number written (' + valText + ') has no leading +, so it is presented as a local/national number. That is right for many trunks and wrong for others — confirm which format this carrier expects.', CITE.telUri());
    }

    // --- header-specific interop knowledge ---------------------------------
    if ((hNorm === 'p-asserted-identity' || hNorm === 'p-preferred-identity') && (r.operation === 'add' || r.operation === 'modify' || r.operation === 'replace')) {
      issue('notice', 'This rule asserts an identity with ' + hDisp + '. That header only means anything inside a trust domain: toward a carrier it is usually ignored or rejected unless they have agreed to trust you, and it must be stripped when leaving the trust domain.', CITE.pai());
      improve('Set the Privacy header consistently with the identity you assert (Privacy: id when the identity must not be passed on, Privacy: none when it may).',
        'Identity and privacy are read together; asserting an identity without saying how it may be used is the most common reason a carrier drops or overrides PAI.');
    }
    if (hNorm === 'diversion' && r.operation !== 'none') {
      issue('notice', 'Diversion is a historic, informational header kept for interop with older equipment. If the peer understands History-Info, that is the standards-track carrier of redirection information.', CITE.historyInfo());
    }
    if ((hNorm === 'session-expires' || hNorm === 'min-se') && r.operation !== 'none') {
      issue('notice', 'This rule changes session-timer negotiation. Session-Expires must stay at or above Min-SE and the refresher has to survive to the answerer; editing one value in isolation is how you get a 422 Session Interval Too Small, or a mid-call BYE at half the expected interval.', CITE.timers());
    }
    if ((hNorm === 'require' || hNorm === 'supported' || hNorm === 'unsupported') && /100rel|precondition|timer/i.test(valText + ' ' + (r.conditions.map(function (c) { return c && c.value; }).join(' ')))) {
      issue('warn', 'This rule edits option tags (' + valText + '). Removing 100rel on one leg only leaves the two legs with different reliability rules, and the SBC then has to absorb PRACK on one side and not the other — a common cause of missing ringback and stuck early media.', CITE.prack());
    }
    if (String(r.target.header || '') === 'SDP body' || /telephone-event|rtpmap|ptime|m=audio/i.test(valText)) {
      issue('notice', 'This rule edits the message body / SDP with a header-manipulation rule. The SBC runs its own offer/answer state machine over that SDP, so a text-level edit here can contradict what the media plane has already negotiated.',
        /telephone-event/i.test(valText) ? CITE.dtmf() : CITE.sdpOffer());
      improve('Express this with the media configuration instead (Acme: codec-policy / media-profile; AudioCodes: Coder Group + IP Profile; Ribbon: Media List / Packet Service Profile).',
        'The media configuration is what actually drives the transcoder and the SDP the SBC emits; an SDP text edit changes the message without changing the box\'s intent, and the two then disagree.');
    }
    if (r.subOperation === 'sip-manip') {
      issue('info', 'This header-rule chains another sip-manipulation rather than editing a header itself (' + (valText || 'target not resolved') +
        '). Check that the chained manipulation exists and is not also bound directly, or it runs twice.', null);
    }
    if (r.operation === 'none' && r.subOperation && r.subOperation !== 'sip-manip' && r.subOperation !== 'monitor') {
      issue('notice', 'hiccup did not recognise the action "' + r.subOperation + '", so it is treated as no-operation here. Parameter names drift between releases — check this one against the guide for your software version.', null);
    }

    // --- generic improvements ---------------------------------------------
    if (!r.conditions.length && writes) {
      improve('Add a match condition so the rule only fires on the messages you mean (for example, only when ' + describeTarget(r) + ' looks like the value you intend to change).',
        'An unconditional write applies to every message in scope, including the ones already in the right format — that is what turns a normalisation rule into a double-prefixing bug.');
    }
    if (r.scope.msgType === 'request' && (!r.scope.methods || !r.scope.methods.length)) {
      improve('List the methods this rule applies to (usually INVITE, sometimes plus REGISTER or UPDATE).',
        'Without a method list the rule also rewrites OPTIONS keepalives and in-dialog requests, which is how a trunk starts failing its monitoring while calls still work.');
    }
    if (r.subOperation === 'add-prefix' || r.subOperation === 'add-suffix' || r.subOperation === 'remove-prefix' || r.subOperation === 'remove-suffix') {
      improve('If this is a dial-plan transform rather than header semantics, do it in the number-manipulation layer (AudioCodes Number Manipulation tables, Acme session-translation / translation-rules, Ribbon Transformation Tables).',
        'Digit work kept in the dial-plan layer is visible to routing decisions and to the next engineer reading the routing table; the same change hidden in an SMM rule is invisible until someone diffs a trace.');
    }
    if (/^(rule\s*\d+|messagemanipulations?\s+\d+|element-rule|header-rule|unnamed rule)/i.test(String(r.name))) {
      improve('Give the rule a name that states its purpose, e.g. "' +
        (r.operation === 'delete' ? 'strip-' : (r.operation === 'add' ? 'add-' : 'rewrite-')) +
        String(r.target.header || 'header').toLowerCase().replace(/[^a-z0-9]+/g, '-') + '".',
        'Names are the only documentation a running config carries, and they are what a trace-side finding can point at when hiccup matches this rule to an observed change.');
    }
  } catch (e) {
    issues.push({ severity: 'notice', detail: 'The correctness pass stopped early on this rule (' + (e && e.message ? e.message : e) + '); the checks above are what completed.', citation: null });
  }

  if (issues.length > 24) issues = issues.slice(0, 24);
  if (improvements.length > 12) improvements = improvements.slice(0, 12);
  var ok = true;
  for (var z = 0; z < issues.length; z++) {
    if (issues[z].severity === 'crit' || issues[z].severity === 'warn') { ok = false; break; }
  }
  return { intent: intent, correctness: { ok: ok, issues: issues }, improvements: improvements };
}

// ===========================================================================
// renderRule — reviewable DRAFT config in each vendor's dialect
// ===========================================================================

var VENDOR_ALIASES = {
  'oracle-acme': 'oracle-acme', 'oracle': 'oracle-acme', 'acme': 'oracle-acme',
  'acmepacket': 'oracle-acme', 'acme-packet': 'oracle-acme', 'net-net': 'oracle-acme', 'esbc': 'oracle-acme',
  'audiocodes': 'audiocodes', 'audiocode': 'audiocodes', 'ac': 'audiocodes', 'mediant': 'audiocodes',
  'ribbon': 'ribbon', 'sonus': 'ribbon', 'smm': 'ribbon', 'sbc-edge': 'ribbon',
  'generic': 'generic', 'unknown': 'generic', '': 'generic'
};

/** Normalize a vendor label onto a renderer key. */
function normVendor(v) {
  var k = String(v == null ? '' : v).trim().toLowerCase();
  return VENDOR_ALIASES[k] || 'generic';
}

/** Sanitize a name for a vendor CLI (alphanumeric + underscore, length capped). */
function safeName(s, max) {
  var n = String(s == null ? '' : s).trim().replace(/[^A-Za-z0-9_]+/g, '_').replace(/^_+|_+$/g, '');
  if (!n) n = 'HICCUP_DRAFT';
  return n.slice(0, max || 24);
}

/** `key   value` line padded to an Acme-style column. */
function kv(indent, key, val) {
  var pad = new Array(indent + 1).join(' ');
  var k = String(key);
  var text = val == null ? '' : String(val);
  if (!text) return pad + k;                     // block openers and empty fields
  var spaces = (39 - indent) - k.length;         // align values at column 39
  if (spaces < 1) spaces = 1;
  return pad + k + new Array(spaces + 1).join(' ') + text;
}

/** Reverse map: IR element -> Acme element-rule `type` (+ parameter-name). */
function acmeTypeFor(element) {
  var el = String(element == null ? '' : element);
  if (el === 'uri.user') return { type: 'uri-user', param: '' };
  if (el === 'uri.host') return { type: 'uri-host', param: '' };
  if (el === 'uri.port') return { type: 'uri-port', param: '' };
  if (el === 'display') return { type: 'uri-display', param: '' };
  if (el === 'uri') return { type: 'uri', param: '' };
  if (el === 'value') return { type: 'header-value', param: '' };
  if (el === 'param.tag') return { type: 'header-param', param: 'tag' };
  if (el.indexOf('param.') === 0) return { type: 'header-param', param: el.slice(6) };
  if (!el) return null;
  return { type: 'header-value', param: '', unsure: el };
}

/** Reverse map: IR element -> AudioCodes ActionSubject suffix. */
function acSubjectFor(rule) {
  var h = rule.target && rule.target.header ? String(rule.target.header) : '';
  var el = rule.target && rule.target.element ? String(rule.target.element) : '';
  if (/^var\./i.test(h) || /^param\./i.test(h)) return h.toLowerCase();
  if (h === 'SDP body') return 'body.sdp' + (el ? '.' + el : '');
  var base = 'header.' + normHeader(h);
  if (!el) return base;
  if (el === 'uri.user') return base + '.url.user';
  if (el === 'uri.host') return base + '.url.host';
  if (el === 'uri.port') return base + '.url.port';
  if (el === 'uri') return base + '.url';
  if (el === 'display') return base + '.name';
  if (el === 'value') return base;
  if (el === 'param.tag') return base + '.param.tag';
  if (el.indexOf('param.') === 0) return base + '.param.' + el.slice(6);
  return base + '.' + el;
}

/** Reverse map: IR element -> Ribbon operation keyword. */
function ribbonKeywordFor(element) {
  var el = String(element == null ? '' : element);
  if (el === 'uri.user') return 'uriUser';
  if (el === 'uri.host') return 'uriHost';
  if (el === 'uri.port') return 'uriPort';
  if (el === 'display') return 'displayName';
  if (el === 'value' || el === '') return 'headerValue';
  if (el === 'uri') return 'uriValue';
  if (el === 'param.tag') return 'paramValue tag';
  if (el.indexOf('param.') === 0) return 'paramValue ' + el.slice(6);
  return 'headerValue';
}

/** Normalize an arbitrary object into the fields the renderers need. */
function safeRule(rule) {
  var r = rule && typeof rule === 'object' ? rule : {};
  var sc = r.scope || {};
  var tg = r.target || {};
  return {
    id: r.id || null,
    name: r.name || 'hiccup_rule',
    vendor: r.vendor || 'unknown',
    setName: r.setName || null,
    parentName: r.parentName || null,
    scope: {
      direction: sc.direction || null,
      msgType: sc.msgType || 'any',
      methods: Array.isArray(sc.methods) ? sc.methods.slice() : []
    },
    conditions: Array.isArray(r.conditions) ? r.conditions : [],
    target: { header: tg.header || null, element: tg.element || null, index: tg.index == null ? null : tg.index },
    operation: r.operation || 'none',
    subOperation: r.subOperation || null,
    value: r.value && r.value.text ? { kind: r.value.kind || 'literal', text: String(r.value.text) } : null,
    bindings: Array.isArray(r.bindings) ? r.bindings : [],
    enabled: r.enabled !== false,
    elementRaw: r.elementRaw || null
  };
}

/** Draft banner shared by every renderer. */
function banner(cmt, r, target) {
  var src = normVendor(r.vendor);
  var out = [];
  out.push(cmt + ' ---------------------------------------------------------------');
  out.push(cmt + ' hiccup DRAFT — for review only. This is NOT applied anywhere and');
  out.push(cmt + ' has NOT been validated against your release.');
  out.push(cmt + ' rule: ' + r.name + '   source dialect: ' + (src === 'generic' ? 'unknown' : src) +
    '   rendered for: ' + (target === 'generic' ? 'vendor-neutral' : target));
  if (src !== target && src !== 'generic') {
    out.push(cmt + ' Rule-level translation only. What does NOT translate: the topology');
    out.push(cmt + ' model (Acme realms vs AudioCodes IP Groups vs Ribbon trunk groups and');
    out.push(cmt + ' Transformation Tables), HA, licensing, steering pools, TLS/SRTP');
    out.push(cmt + ' profiles, and vendor escape hatches such as Acme SPL.');
  }
  out.push(cmt + ' Parameter names drift between releases — check each one against the');
  out.push(cmt + ' guide for your software version before pasting anything.');
  out.push(cmt + ' ---------------------------------------------------------------');
  return out;
}

/** Comments about concepts that do not survive the translation. */
function translationNotes(r, target, cmt) {
  var out = [];
  var src = normVendor(r.vendor);
  var sub = r.subOperation;
  if (sub === 'sip-manip') {
    out.push(cmt + ' DOES NOT TRANSLATE: this rule chains another sip-manipulation (an Acme');
    out.push(cmt + ' construct). No equivalent exists on ' + (target === 'generic' ? 'other vendors' : target) + ' — flatten the chained');
    out.push(cmt + ' rules into this set/profile instead.');
  }
  if (sub === 'find-replace-all' && target !== 'oracle-acme') {
    out.push(cmt + ' PARTIAL TRANSLATION: Acme find-replace-all substitutes every occurrence.');
    out.push(cmt + ' The draft below performs a single substitution; repeat the rule or use a');
    out.push(cmt + ' regex with a global sense if your release supports one.');
  }
  if ((sub === 'add-prefix' || sub === 'add-suffix' || sub === 'remove-prefix' || sub === 'remove-suffix') && target === 'oracle-acme') {
    out.push(cmt + ' PARTIAL TRANSLATION: Acme has no single-step ' + sub + '. It needs a store');
    out.push(cmt + ' rule for the original value and then a replace whose new-value');
    out.push(cmt + ' concatenates the literal with the stored reference. The draft shows the');
    out.push(cmt + ' shape; the store rule name must be confirmed by hand.');
  }
  if ((sub === 'add-prefix' || sub === 'add-suffix' || sub === 'remove-prefix' || sub === 'remove-suffix') && target === 'ribbon') {
    out.push(cmt + ' PARTIAL TRANSLATION: express prefix/suffix work as a regex substitution');
    out.push(cmt + ' in the operation value, or (better) in a Transformation Table where');
    out.push(cmt + ' Ribbon expects digit manipulation to live.');
  }
  if (r.operation === 'store' && target === 'audiocodes') {
    out.push(cmt + ' PARTIAL TRANSLATION: AudioCodes has no store action; the nearest');
    out.push(cmt + ' equivalent is writing the value into var.session.<n> with a modify row and');
    out.push(cmt + ' reading it back in a later row of the same set.');
  }
  if (r.operation === 'store' && target === 'ribbon') {
    out.push(cmt + ' PARTIAL TRANSLATION: Ribbon SMM has no cross-rule store. Capture the');
    out.push(cmt + ' value with a regex group inside the same rule, or use a variable if your');
    out.push(cmt + ' release supports one.');
  }
  if (String(r.target.header || '') === 'SDP body') {
    out.push(cmt + ' CAUTION: this rule edits the message body / SDP. Every one of these');
    out.push(cmt + ' products prefers you change media behaviour in the media configuration');
    out.push(cmt + ' (codec policy / coder group / media list) rather than by editing SDP text.');
  }
  var el = String(r.target.element || '');
  if (el && !/^(uri\.user|uri\.host|uri\.port|uri|display|value|param(\..*)?)$/.test(el)) {
    out.push(cmt + ' UNMAPPED ELEMENT: "' + (r.elementRaw || el) + '" has no clean equivalent here;');
    out.push(cmt + ' the draft falls back to the whole header value. Verify by hand.');
  }
  if (r.value && r.value.kind === 'expression' && src !== target && src !== 'generic') {
    out.push(cmt + ' EXPRESSION NOT TRANSLATED: "' + r.value.text + '" uses ' + src + ' syntax.');
    out.push(cmt + ' Rewrite it in the target dialect — expression grammars do not correspond.');
  }
  return out;
}

/** Binding comments, mapped onto the target vendor's topology vocabulary. */
function bindingNotes(r, target, cmt, setLabel) {
  var out = [];
  var dir = r.scope.direction;
  var dirWord = dir === 'in' ? 'inbound' : (dir === 'out' ? 'outbound' : 'the correct direction (the source config did not say)');
  if (!r.bindings.length) {
    out.push(cmt + ' NOT BOUND: the source config binds this rule nowhere, so it never ran there.');
  } else {
    var names = r.bindings.map(function (b) { return (b.kind || '?') + ' "' + (b.name || '?') + '"'; }).join(', ');
    out.push(cmt + ' source binding: ' + names + ' (' + dirWord + ').');
  }
  if (target === 'oracle-acme') {
    out.push(cmt + ' bind with: session-agent / sip-interface / realm-config ->');
    out.push(cmt + '   ' + (dir === 'in' ? 'in-manipulationid' : 'out-manipulationid') + ' ' + setLabel);
  } else if (target === 'audiocodes') {
    out.push(cmt + ' bind with: IPGroup_' + (dir === 'in' ? 'Inbound' : 'Outbound') + 'ManSet = ' + setLabel +
      ' (or the equivalent field on IPProfile / SIPInterface). A -1 there means no set is applied.');
  } else if (target === 'ribbon') {
    out.push(cmt + ' bind with: set addressContext default zone <ZONE> sipTrunkGroup <TG>');
    out.push(cmt + '   signaling messageManipulation ' + (dir === 'in' ? 'inputAdapterProfile' : 'outputAdapterProfile') + ' ' + setLabel);
    out.push(cmt + ' (SBC Edge: Signaling Group -> Message Manipulation -> ' + (dir === 'in' ? 'Inbound' : 'Outbound') + ').');
  }
  if (!dir) {
    out.push(cmt + ' Direction unknown: pick inbound or outbound deliberately — the same rule');
    out.push(cmt + ' applied the wrong way round rewrites traffic that was already correct.');
  }
  return out;
}

/** Render the IR as an Oracle/Acme sip-manipulation draft. */
function renderAcme(r) {
  var cmt = '#';
  var out = banner(cmt, r, 'oracle-acme').concat(translationNotes(r, 'oracle-acme', cmt));
  var setName = safeName(r.setName || r.name, 24);
  var hrName = safeName(r.parentName || r.name, 24);
  var erName = safeName(r.name + '_e', 24);
  var opMap = { add: 'add', delete: 'delete', modify: 'manipulate', replace: 'manipulate', store: 'store', none: 'none' };
  var hrAction = opMap[r.operation] || 'none';
  var msgType = r.scope.msgType === 'response' ? 'reply' : (r.scope.msgType === 'request' ? 'request' : 'any');
  var elInfo = acmeTypeFor(r.target.element);
  var headerCond = null, elemCond = null;
  for (var i = 0; i < r.conditions.length; i++) {
    var c = r.conditions[i] || {};
    if (c.comparison === 'exists' || c.comparison === 'absent') continue;
    var cel = String(c.element || '');
    if (elInfo && cel.indexOf('.') !== -1 && !elemCond) elemCond = c;
    else if (!headerCond) headerCond = c;
  }
  if (!elemCond && elInfo && headerCond) { elemCond = headerCond; headerCond = null; }
  var comparisonFor = function (c) { return c && c.comparison === 'matches' ? 'pattern-rule' : 'case-sensitive'; };
  var valText = r.value ? r.value.text : '';
  if ((r.subOperation === 'add-prefix' || r.subOperation === 'add-suffix') && valText) {
    valText = r.subOperation === 'add-prefix'
      ? '"' + valText + '"+$ORIGINAL'
      : '$ORIGINAL+"' + valText + '"';
    out.push(cmt + ' NOTE: $ORIGINAL is a placeholder — replace it with the reference to your');
    out.push(cmt + ' store rule, e.g. $storeRule.$storeElem.$0');
  } else if (valText && r.value && r.value.kind === 'literal') {
    valText = '"' + valText + '"';
  }
  out.push('sip-manipulation');
  out.push(kv(8, 'name', setName));
  out.push(kv(8, 'description', 'hiccup draft: ' + r.operation + ' ' + (r.target.header || 'header')));
  out.push(kv(8, 'header-rule', ''));
  out.push(kv(16, 'name', hrName));
  out.push(kv(16, 'header-name', r.target.header || 'X-Undetermined'));
  out.push(kv(16, 'action', hrAction));
  out.push(kv(16, 'comparison-type', comparisonFor(headerCond)));
  out.push(kv(16, 'msg-type', msgType));
  out.push(kv(16, 'methods', r.scope.methods.join(',')));
  out.push(kv(16, 'match-value', headerCond && headerCond.value != null ? headerCond.value : ''));
  out.push(kv(16, 'new-value', elInfo ? '' : valText));
  if (elInfo) {
    out.push(kv(16, 'element-rule', ''));
    out.push(kv(24, 'name', erName));
    out.push(kv(24, 'parameter-name', elInfo.param || ''));
    out.push(kv(24, 'type', elInfo.type));
    out.push(kv(24, 'action', r.operation === 'modify' || r.operation === 'replace' ? 'replace' :
      (r.operation === 'store' ? 'store' : (r.operation === 'delete' ? 'delete' : (r.operation === 'add' ? 'add' : 'none')))));
    out.push(kv(24, 'match-val-type', 'any'));
    out.push(kv(24, 'comparison-type', comparisonFor(elemCond)));
    out.push(kv(24, 'match-value', elemCond && elemCond.value != null ? elemCond.value : ''));
    out.push(kv(24, 'new-value', valText));
  }
  if (r.conditions.length > 2) {
    out.push(cmt + ' NOTE: the source rule had ' + r.conditions.length + ' conditions. Acme allows one');
    out.push(cmt + ' match-value per rule level, so the extra conditions need their own');
    out.push(cmt + ' header-rules (or a store + boolean rule). Not invented here.');
  }
  out = out.concat(bindingNotes(r, 'oracle-acme', cmt, setName));
  out.push(cmt + ' Acme ACLI does not accept comment lines — strip every ' + cmt + ' line before pasting.');
  return out.join('\n');
}

/** Render the IR as an AudioCodes MessageManipulations row draft. */
function renderAudioCodes(r) {
  var cmt = ';';
  var out = banner(cmt, r, 'audiocodes').concat(translationNotes(r, 'audiocodes', cmt));
  var setId = '1';
  var mSet = String(r.setName || '').match(/(\d+)/);
  if (mSet) setId = mSet[1];
  else out.push(cmt + ' ManSetID 1 chosen by hiccup — the source set had no numeric id.');
  var subject = acSubjectFor(r);
  var acOp = { add: 0, delete: 1, modify: 2, replace: 2, store: 2, none: 2 };
  var actionType = acOp[r.operation];
  if (r.subOperation === 'add-prefix') actionType = 3;
  else if (r.subOperation === 'add-suffix') actionType = 4;
  else if (r.subOperation === 'remove-suffix') actionType = 5;
  else if (r.subOperation === 'remove-prefix') actionType = 6;
  var atLabel = { 0: 'add', 1: 'remove', 2: 'modify', 3: 'add-prefix', 4: 'add-suffix', 5: 'remove-suffix', 6: 'remove-prefix' };
  if (r.operation === 'none') out.push(cmt + ' NOTE: the source action was a no-op; rendered as modify so the row is visible. Review it.');
  if (r.operation === 'store') subject = 'var.session.0';
  var conds = [];
  for (var i = 0; i < r.conditions.length; i++) {
    var c = r.conditions[i] || {};
    var celem = String(c.element || '');
    var subj;
    if (/^response\.status/i.test(celem)) subj = 'header.response.status';
    else {
      var partsC = celem.split('.');
      var hdrC = partsC.shift();
      subj = acSubjectFor({ target: { header: hdrC, element: partsC.join('.') || null } });
    }
    if (c.comparison === 'exists') conds.push(subj + (c.negate ? ' !exists' : ' exists'));
    else if (c.comparison === 'absent') conds.push(subj + ' !exists');
    else if (c.comparison === 'matches') conds.push(subj + (c.negate ? " !contains '" : " =~ '") + String(c.value == null ? '' : c.value) + "'");
    else conds.push(subj + (c.negate ? " != '" : " == '") + String(c.value == null ? '' : c.value) + "'");
  }
  var methods = r.scope.methods;
  var msgType;
  if (!methods.length) {
    msgType = r.scope.msgType === 'any' ? 'any' : ('any.' + (r.scope.msgType === 'response' ? 'response' : 'request'));
    if (r.scope.msgType !== 'any') out.push(cmt + ' NOTE: verify "' + msgType + '" is accepted on your release; if not, one row per method is needed.');
  } else {
    msgType = methods[0].toLowerCase() + (r.scope.msgType === 'any' ? '' : '.' + (r.scope.msgType === 'response' ? 'response' : 'request'));
    if (methods.length > 1) out.push(cmt + ' NOTE: MessageType takes one method — the other methods (' + methods.slice(1).join(', ') + ') need their own rows.');
  }
  var av = '';
  if (r.value) av = r.value.kind === 'literal' ? "'" + r.value.text + "'" : r.value.text;
  out.push('[ MessageManipulations ]');
  out.push('');
  out.push('FORMAT MessageManipulations_Index = MessageManipulations_ManipulationName, ' +
    'MessageManipulations_ManSetID, MessageManipulations_MessageType, MessageManipulations_Condition, ' +
    'MessageManipulations_ActionSubject, MessageManipulations_ActionType, MessageManipulations_ActionValue, ' +
    'MessageManipulations_RowRole;');
  out.push('MessageManipulations 0 = "' + String(r.name).replace(/"/g, '') + '", ' + setId + ', "' + msgType + '", "' +
    conds.join(' and ').replace(/"/g, '') + '", "' + subject + '", ' + actionType + ', "' + av.replace(/"/g, '') + '", 0;');
  out.push('');
  out.push('[ \\MessageManipulations ]');
  out.push(cmt + ' ActionType ' + actionType + ' = ' + (atLabel[actionType] || 'modify') + '.');
  out.push(cmt + ' RowRole 0 = this row carries its own condition; use 1 on a following row to reuse it.');
  out = out.concat(bindingNotes(r, 'audiocodes', cmt, setId));
  return out.join('\n');
}

/** Render the IR as Ribbon SMM CLI draft. */
function renderRibbon(r) {
  var cmt = '#';
  var out = banner(cmt, r, 'ribbon').concat(translationNotes(r, 'ribbon', cmt));
  var prof = safeName(r.setName || r.name, 32);
  var pre = 'set profiles signaling sipAdaptorProfile ' + prof;
  var ruleNo = 1;
  var actMap = { add: 'add', delete: 'delete', modify: 'modify', replace: 'replace', store: 'store', none: 'modify' };
  var act = actMap[r.operation] || 'modify';
  out.push(pre + ' state enabled');
  var mt = pre + ' rule ' + ruleNo + ' criterion messageType';
  if (r.scope.methods.length) mt += ' methodTypes ' + r.scope.methods.map(function (m) { return m.toLowerCase(); }).join(',');
  if (r.scope.msgType !== 'any') mt += ' type ' + (r.scope.msgType === 'response' ? 'response' : 'request');
  out.push(mt);
  for (var i = 0; i < r.conditions.length; i++) {
    var c = r.conditions[i] || {};
    var celem = String(c.element || '');
    var partsC = celem.split('.');
    var hdrC = partsC.shift() || (r.target.header || 'From');
    var elC = partsC.join('.');
    var line = pre + ' rule ' + ruleNo + ' criterion header ' + hdrC;
    if (elC) line += ' ' + ribbonKeywordFor(elC);
    if (c.comparison === 'exists') line += c.negate ? ' condition notExist' : ' condition exist';
    else if (c.comparison === 'absent') line += ' condition notExist';
    else if (c.comparison === 'matches') line += ' condition regexMatch value "' + String(c.value == null ? '' : c.value) + '"';
    else line += ' condition value value "' + String(c.value == null ? '' : c.value) + '"';
    out.push(line);
    if (c.negate && c.comparison !== 'exists' && c.comparison !== 'absent') {
      out.push(cmt + ' DOES NOT TRANSLATE: the source condition was negated. Ribbon SMM has no NOT');
      out.push(cmt + ' on a value criterion — invert it with a negative-lookahead regex or split');
      out.push(cmt + ' the logic into two rules. The line above is the un-negated form.');
    }
  }
  var opLine = pre + ' rule ' + ruleNo + ' operation header ' + (r.target.header || 'X-Undetermined') +
    ' ' + ribbonKeywordFor(r.target.element) + ' actionType ' + act;
  if (r.value) opLine += ' value "' + r.value.text + '"';
  out.push(opLine);
  out.push('commit');
  if (r.target.index != null) out.push(cmt + ' NOTE: the source rule targeted instance/token index ' + r.target.index + ' — set the token index explicitly.');
  out = out.concat(bindingNotes(r, 'ribbon', cmt, prof));
  out.push(cmt + ' Ribbon SMM keyword spelling varies by release (SBC Core vs SBC Edge differ');
  out.push(cmt + ' considerably). Treat this as a shape to verify, not a paste-ready command.');
  return out.join('\n');
}

/** Render the IR itself, for when no vendor dialect is requested. */
function renderGeneric(r) {
  var cmt = '#';
  var out = banner(cmt, r, 'generic');
  out.push('rule            ' + r.name);
  out.push('set             ' + (r.setName || '(none)'));
  out.push('direction       ' + (r.scope.direction || 'unbound'));
  out.push('applies-to      ' + r.scope.msgType + (r.scope.methods.length ? ' [' + r.scope.methods.join(',') + ']' : ' [all methods]'));
  for (var i = 0; i < r.conditions.length; i++) {
    var c = r.conditions[i] || {};
    out.push('condition       ' + (c.element || '?') + ' ' + (c.negate ? 'NOT ' : '') + (c.comparison || '?') +
      (c.value == null ? '' : ' ' + c.value));
  }
  if (!r.conditions.length) out.push('condition       (none — fires on everything in scope)');
  out.push('target          ' + (r.target.header || '?') + (r.target.element ? ' / ' + r.target.element : '') +
    (r.target.index == null ? '' : ' [' + r.target.index + ']'));
  out.push('operation       ' + r.operation + (r.subOperation ? ' (' + r.subOperation + ')' : ''));
  out.push('value           ' + (r.value ? r.value.kind + ': ' + r.value.text : '(none)'));
  for (var b = 0; b < r.bindings.length; b++) {
    out.push('binding         ' + (r.bindings[b].kind || '?') + ' ' + (r.bindings[b].name || '?'));
  }
  if (!r.bindings.length) out.push('binding         (none — this rule never runs)');
  out.push(cmt + ' No vendor dialect was requested, so this is the intermediate');
  out.push(cmt + ' representation itself rather than invented syntax.');
  return out.join('\n');
}

/**
 * Render a rule into a vendor dialect as a reviewable DRAFT.
 *
 * Never emits invented syntax for a concept that does not translate: those get
 * an explicit comment saying so (see DESIGN_1's "does not translate at all"
 * list). The output is always a draft for a human to review — nothing here is
 * applied to any device.
 *
 * @param {object} rule an HmrRule
 * @param {string} [vendor] 'oracle-acme'|'audiocodes'|'ribbon' (aliases accepted).
 *   Omit it to render in the rule's own dialect; an unrecognised vendor renders
 *   the vendor-neutral IR rather than guessing at syntax.
 * @returns {string} draft configuration text with comments
 */
function renderRule(rule, vendor) {
  try {
    var r = safeRule(rule);
    var target = normVendor(vendor == null || vendor === '' ? r.vendor : vendor);
    if (target === 'oracle-acme') return renderAcme(r);
    if (target === 'audiocodes') return renderAudioCodes(r);
    if (target === 'ribbon') return renderRibbon(r);
    return renderGeneric(r);
  } catch (e) {
    return '# hiccup could not render this rule (' + (e && e.message ? e.message : e) + ').\n' +
      '# Nothing was invented to fill the gap — inspect the parsed rule instead.';
  }
}

// ===========================================================================
// matchAgainstAnalysis — do the configured rules explain the observed diffs?
// ===========================================================================

/** Diff tags a manipulation rule could plausibly be responsible for. */
var MANIP_TAGS = {
  'header-added': 1, 'header-stripped': 1, 'header-rewritten': 1,
  'from-rewritten': 1, 'to-rewritten': 1, 'private-ip-leak': 1,
  'dtmf-pt-mismatch': 1, 'session-timer-changed': 1, 'session-timer-conflict': 1,
  '100rel-asymmetry': 1, 'codec-narrowed': 1
};

/** The header a diff item is about, or null when the tag is not header-shaped. */
function itemHeader(item) {
  var label = String((item && item.label) || '');
  var m = label.match(/^header\s+(?:stripped|added|rewritten):\s*(.+)$/i);
  if (m) return normHeader(m[1]);
  if (item && item.tag === 'from-rewritten') return 'from';
  if (item && item.tag === 'to-rewritten') return 'to';
  return null;
}

/** Diff tags this rule would produce if it fired between the two legs. */
function expectedTags(rule) {
  var tags = [], seen = {};
  function add(t) { if (t && !seen[t]) { seen[t] = 1; tags.push(t); } }
  var h = normHeader(rule.target && rule.target.header);
  var el = rule.target ? rule.target.element : null;
  var val = rule.value && rule.value.text ? String(rule.value.text) : '';
  var condVals = '';
  for (var i = 0; i < (rule.conditions || []).length; i++) {
    var c = rule.conditions[i];
    if (c && c.value) condVals += ' ' + c.value;
  }
  switch (rule.operation) {
    case 'add': add('header-added'); break;
    case 'delete': add('header-stripped'); break;
    case 'modify': case 'replace': add('header-rewritten'); break;
    default: break;
  }
  var writesValue = rule.operation === 'modify' || rule.operation === 'replace';
  if (h === 'from' && writesValue && (el === null || el === 'uri.user' || el === 'value' || el === 'uri')) add('from-rewritten');
  if ((h === 'to' || h === 'request-uri') && writesValue && (el === null || el === 'uri.user' || el === 'value' || el === 'uri')) add('to-rewritten');
  if (h === 'session-expires' || h === 'min-se') { add('session-timer-changed'); add('session-timer-conflict'); }
  if ((h === 'require' || h === 'supported' || h === 'unsupported') && /100rel/i.test(val + condVals)) add('100rel-asymmetry');
  if (val && hasPrivateIp(val)) add('private-ip-leak');
  if (/telephone-event/i.test(val + condVals)) add('dtmf-pt-mismatch');
  if (String(rule.target && rule.target.header) === 'SDP body' || /rtpmap|m=audio/i.test(val)) {
    add('codec-narrowed'); add('dtmf-pt-mismatch');
  }
  return tags;
}

/**
 * Join configured rules to the manipulations a capture actually shows.
 *
 * Reads `analysis.calls[].diffs[].diff.categories[].items[]` (the frozen diff
 * shape) and returns one entry per rule plus one entry per observed change that
 * no rule accounts for (those carry `ruleId: null`).
 *
 * @param {Array<object>|{rules: Array<object>}} rules HmrRules (or a parseConfig result)
 * @param {object} analysis an AnalysisJSON
 * @returns {{matches: Array<{ruleId: ?string, callIds: string[], diffTags: string[],
 *   verdict: ('observed-as-configured'|'configured-not-observed'|'observed-not-configured'),
 *   detail: string}>}}
 */
function matchAgainstAnalysis(rules, analysis) {
  var out = { matches: [] };
  try {
    var list = Array.isArray(rules) ? rules : (rules && Array.isArray(rules.rules) ? rules.rules : []);
    var calls = analysis && Array.isArray(analysis.calls) ? analysis.calls : [];
    var observed = [], pairCount = 0;
    for (var ci = 0; ci < calls.length; ci++) {
      var call = calls[ci] || {};
      var diffs = Array.isArray(call.diffs) ? call.diffs : [];
      for (var di = 0; di < diffs.length; di++) {
        var d = diffs[di] && diffs[di].diff;
        if (!d) continue;
        pairCount++;
        var cats = Array.isArray(d.categories) ? d.categories : [];
        for (var cx = 0; cx < cats.length; cx++) {
          var items = cats[cx] && Array.isArray(cats[cx].items) ? cats[cx].items : [];
          for (var ix = 0; ix < items.length; ix++) {
            var it = items[ix];
            if (!it || !it.tag) continue;
            observed.push({
              callId: call.id || null, tag: String(it.tag), item: it,
              header: itemHeader(it), claimed: false
            });
          }
        }
      }
    }

    for (var ri = 0; ri < list.length; ri++) {
      var rule = list[ri];
      if (!rule || typeof rule !== 'object') continue;
      var exp = expectedTags(rule);
      var ruleHeader = normHeader(rule.target && rule.target.header);
      var hitCalls = {}, hitTags = {}, examples = [];
      for (var oi = 0; oi < observed.length; oi++) {
        var ob = observed[oi];
        if (exp.indexOf(ob.tag) === -1) continue;
        if (ob.header && ruleHeader && ob.header !== ruleHeader) continue;
        if (ob.header && !ruleHeader) continue;
        ob.claimed = true;
        if (ob.callId) hitCalls[ob.callId] = 1;
        hitTags[ob.tag] = 1;
        if (examples.length < 2) {
          examples.push(String(ob.item.label || ob.tag) +
            (ob.item.ingress != null || ob.item.egress != null
              ? ' (' + (ob.item.ingress == null ? '(absent)' : ob.item.ingress) + ' -> ' +
                (ob.item.egress == null ? '(absent)' : ob.item.egress) + ')'
              : ''));
        }
      }
      var callIds = Object.keys(hitCalls);
      var tagList = Object.keys(hitTags);
      var nameLabel = '"' + (rule.name || rule.id || 'rule') + '"';
      if (tagList.length) {
        var dirNote = '';
        if (!rule.bindings || !rule.bindings.length) {
          dirNote = ' Note that this rule is not bound to anything in the config supplied, so something else on the box is probably making the same change — do not assume this rule is the cause.';
        } else if (rule.scope && rule.scope.direction === 'in') {
          dirNote = ' The rule is bound inbound, and the change is visible between the ingress and egress legs — consistent, but confirm which side you meant to edit.';
        }
        out.matches.push({
          ruleId: rule.id || null,
          callIds: callIds,
          diffTags: tagList,
          verdict: 'observed-as-configured',
          detail: 'Rule ' + nameLabel + ' explains ' + tagList.join(', ') + ' on ' +
            (callIds.length ? callIds.length + ' call' + (callIds.length === 1 ? '' : 's') + ' (' + callIds.slice(0, 5).join(', ') + ')' : 'this capture') +
            (examples.length ? ': ' + examples.join('; ') + '.' : '.') + dirNote
        });
      } else {
        var why;
        if (!pairCount) {
          why = 'This capture has no correlated ingress/egress leg pair, so there is no diff to confirm the rule against — that is a property of the capture, not evidence against the rule.';
        } else if (!rule.bindings || !rule.bindings.length) {
          why = 'The rule is bound nowhere in the config supplied, which is the most likely reason the capture shows no sign of it.';
        } else if (!exp.length) {
          why = 'This rule\'s action (' + (rule.operation || 'none') + ') does not produce a change the leg diff can see, so the capture can neither confirm nor contradict it.';
        } else {
          why = 'The capture shows no ' + exp.join('/') + ' change on ' + (rule.target && rule.target.header ? rule.target.header : 'that header') +
            '. Either no message met the rule\'s condition, the rule is on an interface this capture did not cross, or it is not doing what it looks like it does.';
        }
        out.matches.push({
          ruleId: rule.id || null, callIds: [], diffTags: [],
          verdict: 'configured-not-observed',
          detail: 'Rule ' + nameLabel + ' is configured but not observed. ' + why
        });
      }
    }

    // observed changes nothing in the config explains
    var groups = {}, order = [];
    for (var ox = 0; ox < observed.length; ox++) {
      var o2 = observed[ox];
      if (o2.claimed) continue;
      if (!MANIP_TAGS[o2.tag]) continue;
      var key = o2.tag + '|' + (o2.header || '');
      if (!groups[key]) {
        groups[key] = { tag: o2.tag, header: o2.header, callIds: {}, example: o2.item };
        order.push(key);
      }
      if (o2.callId) groups[key].callIds[o2.callId] = 1;
    }
    for (var gx = 0; gx < order.length && gx < 40; gx++) {
      var g = groups[order[gx]];
      var gCalls = Object.keys(g.callIds);
      var what = g.header ? displayHeader(g.header) : g.tag;
      out.matches.push({
        ruleId: null,
        callIds: gCalls,
        diffTags: [g.tag],
        verdict: 'observed-not-configured',
        detail: 'The capture shows ' + (g.example && g.example.label ? g.example.label : g.tag) +
          (g.example && (g.example.ingress != null || g.example.egress != null)
            ? ' (' + (g.example.ingress == null ? '(absent)' : g.example.ingress) + ' -> ' + (g.example.egress == null ? '(absent)' : g.example.egress) + ')'
            : '') +
          ' on ' + (gCalls.length ? gCalls.length + ' call' + (gCalls.length === 1 ? '' : 's') : 'this capture') +
          ', and no rule in the configuration supplied accounts for it. It may come from another manipulation set, an interop/IP profile, a codec or topology-hiding setting, or a rule set that was not pasted in.' +
          (what !== g.tag ? ' Header involved: ' + what + '.' : '')
      });
    }
    if (order.length > 40) {
      out.matches.push({
        ruleId: null, callIds: [], diffTags: [],
        verdict: 'observed-not-configured',
        detail: 'A further ' + (order.length - 40) + ' observed change groups were not listed (output capped).'
      });
    }
  } catch (e) {
    out.matches.push({
      ruleId: null, callIds: [], diffTags: [],
      verdict: 'observed-not-configured',
      detail: 'hiccup could not complete the rule-to-capture comparison (' + (e && e.message ? e.message : e) + ').'
    });
  }
  return out;
}

module.exports = {
  parseConfig: parseConfig,
  explainRule: explainRule,
  renderRule: renderRule,
  matchAgainstAnalysis: matchAgainstAnalysis
};
