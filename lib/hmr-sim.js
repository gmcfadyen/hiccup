'use strict';
// hmr-sim.js — apply an HMR rule (hiccup's vendor-neutral IR) to ONE real SIP
// message and show exactly what would change.
//
// WHY THIS EXISTS
//
// lib/hmr-generate.js drafts rules and lib/hmr.js renders them as vendor
// config, but nothing executed a rule — so "does this rule actually fix the
// failing INVITE in my capture" was answered by eyeball. That gap matters
// twice over: an engineer wants to see the transformed message before pasting
// config into a production SBC, and the chat agent needs ground truth to
// iterate against — a draft→simulate→revise loop is only worth having if the
// simulate step is real.
//
// WHAT THIS IS, AND IS NOT
//
// It simulates the ABSTRACT rule, one message at a time. Vendors differ in
// evaluation order, regex dialect and variable handling; those differences are
// surfaced as notes, never silently guessed. Three honesty rules:
//
//   1. Direction ('in'/'out') cannot be judged from a single message — it is
//      reported as a note, never used to claim the rule would not run.
//   2. Anything the simulator cannot faithfully model (cross-message stored
//      variables, vendor regex extensions, SBC-recomputed headers) produces a
//      warning on the result instead of a plausible-looking wrong answer.
//   3. Nothing here throws on malformed input. A bad rule returns problems;
//      a bad message parses as far as it can.
//
// Zero dependencies, no I/O — exhaustively testable with no server.

// ── header naming (mirrors lib/hmr.js, which does not export these) ────────

var COMPACT = {
  f: 'from', t: 'to', i: 'call-id', m: 'contact', v: 'via', c: 'content-type',
  l: 'content-length', k: 'supported', s: 'subject', e: 'content-encoding',
  x: 'session-expires', o: 'event', r: 'refer-to', b: 'referred-by', u: 'allow-events'
};

function normHeader(name) {
  var n = String(name == null ? '' : name).trim().toLowerCase();
  n = n.replace(/^header\./, '').replace(/:$/, '');
  if (n === 'requesturi' || n === 'request uri' || n === 'ruri' || n === 'req-uri') n = 'request-uri';
  return COMPACT[n] || n;
}

/**
 * Normalise the target element across the spellings the IR carries:
 * parseConfig emits 'uri.user' / 'uri.host' / 'param.tag' / 'value';
 * hmr-generate emits 'uri-user' / 'uri-host' / 'uri-port' / 'display-name' /
 * 'uri-param'. Returns {kind, param} where kind is one of
 * 'value'|'user'|'host'|'port'|'display'|'param'|'unknown'.
 */
function normElement(el) {
  var e = String(el == null ? '' : el).trim().toLowerCase();
  if (!e || e === 'value' || e === 'header' || e === 'uri') return { kind: 'value', param: null };
  e = e.replace(/^uri[.-]/, '');
  if (e === 'user' || e === 'username') return { kind: 'user', param: null };
  if (e === 'host' || e === 'hostname' || e === 'domain') return { kind: 'host', param: null };
  if (e === 'port') return { kind: 'port', param: null };
  if (e === 'display-name' || e === 'display.name' || e === 'display') return { kind: 'display', param: null };
  var m = e.match(/^param(?:[.-](.+))?$/);
  if (m) return { kind: 'param', param: m[1] || null };
  return { kind: 'unknown', param: null };
}

// ── SIP message parsing (tolerant, round-trippable) ────────────────────────

/**
 * Parse one SIP message. Accepts CRLF or LF line endings (remembered for the
 * rebuild), unfolds folded headers (RFC 3261 §7.3.1), and treats everything
 * after the first blank line as an opaque body.
 *
 * @param {string} raw
 * @returns {{ok:boolean, error:string|null, isRequest:boolean, method:string|null,
 *   requestUri:string|null, sipVersion:string|null, status:number|null,
 *   reason:string|null, startLine:string, headers:Array<{name:string,value:string}>,
 *   body:string, eol:string, hadFolds:boolean}}
 */
function parseSipMessage(raw) {
  var out = {
    ok: false, error: null, isRequest: false, method: null, requestUri: null,
    sipVersion: null, status: null, reason: null, startLine: '',
    headers: [], body: '', eol: '\r\n', hadFolds: false
  };
  var text = String(raw == null ? '' : raw);
  if (!text.trim()) { out.error = 'empty message'; return out; }
  out.eol = text.indexOf('\r\n') !== -1 ? '\r\n' : '\n';

  // Head/body split on the first blank line, tolerant of either ending.
  var m = text.match(/\r?\n\r?\n/);
  var head = m ? text.slice(0, m.index) : text;
  out.body = m ? text.slice(m.index + m[0].length) : '';

  var lines = head.split(/\r?\n/);
  // Skip leading blank chatter (a pasted message often starts with one).
  while (lines.length && !lines[0].trim()) lines.shift();
  if (!lines.length) { out.error = 'no start line'; return out; }
  out.startLine = lines.shift();

  var req = out.startLine.match(/^([A-Za-z]+)\s+(\S+)\s+(SIP\/\d\.\d)\s*$/);
  var res = out.startLine.match(/^(SIP\/\d\.\d)\s+(\d{3})\s*(.*)$/);
  if (req) {
    out.isRequest = true;
    out.method = req[1].toUpperCase();
    out.requestUri = req[2];
    out.sipVersion = req[3];
  } else if (res) {
    out.isRequest = false;
    out.sipVersion = res[1];
    out.status = parseInt(res[2], 10);
    out.reason = res[3] || '';
  } else {
    out.error = 'unrecognised start line: ' + out.startLine.slice(0, 60);
    return out;
  }

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (!line.trim()) continue;
    if (/^[ \t]/.test(line)) {
      // Folded continuation — unfold onto the previous header.
      out.hadFolds = true;
      if (out.headers.length) {
        out.headers[out.headers.length - 1].value += ' ' + line.trim();
      }
      continue;
    }
    var c = line.indexOf(':');
    if (c === -1) continue; // junk line; keep going rather than fail the parse
    out.headers.push({ name: line.slice(0, c).trim(), value: line.slice(c + 1).trim() });
  }
  out.ok = true;
  return out;
}

/** Rebuild the raw message from a parsed one, preserving its line-ending style. */
function serializeSipMessage(msg) {
  var eol = msg.eol || '\r\n';
  var lines = [msg.startLine];
  for (var i = 0; i < msg.headers.length; i++) {
    lines.push(msg.headers[i].name + ': ' + msg.headers[i].value);
  }
  return lines.join(eol) + eol + eol + (msg.body || '');
}

// ── name-addr / URI surgery ────────────────────────────────────────────────

/**
 * Split a header value that may carry a name-addr:
 *   "Alice" <sip:alice@a.com:5060;user=phone>;tag=1
 * or an addr-spec:
 *   sip:alice@a.com;tag=1
 * In the addr-spec form, params after ';' formally belong to the URI, not the
 * header (RFC 3261 §20.10) — noted by the caller when it matters.
 */
function splitNameAddr(value) {
  var v = String(value == null ? '' : value);
  var lt = v.indexOf('<');
  var gt = v.indexOf('>');
  if (lt !== -1 && gt > lt) {
    return {
      hasAngles: true,
      display: v.slice(0, lt).trim(),
      uri: v.slice(lt + 1, gt),
      after: v.slice(gt + 1)
    };
  }
  var sc = v.indexOf(';');
  if (sc === -1) return { hasAngles: false, display: '', uri: v.trim(), after: '' };
  return { hasAngles: false, display: '', uri: v.slice(0, sc).trim(), after: v.slice(sc) };
}

function joinNameAddr(parts) {
  if (parts.hasAngles) {
    return (parts.display ? parts.display + ' ' : '') + '<' + parts.uri + '>' + parts.after;
  }
  return parts.uri + parts.after;
}

/** scheme:user@host:port;rest — every piece optional except scheme+host. */
function splitUri(uri) {
  var m = String(uri == null ? '' : uri)
    .match(/^([A-Za-z][A-Za-z0-9+.-]*):(?:([^@;?]*)@)?(\[[^\]]+\]|[^:;?]+)(?::(\d+))?(.*)$/);
  if (!m) return null;
  return { scheme: m[1], user: m[2] != null ? m[2] : null, host: m[3], port: m[4] || null, rest: m[5] || '' };
}

function joinUri(u) {
  return u.scheme + ':' + (u.user != null && u.user !== '' ? u.user + '@' : '') +
    u.host + (u.port ? ':' + u.port : '') + (u.rest || '');
}

/**
 * Read or rewrite one element of a header value. `newText === undefined`
 * means read-only. Returns {ok, text, value, note}: `text` is the (possibly
 * rewritten) whole value, `value` the element's current text.
 */
function elementOp(value, el, newText) {
  var parts = splitNameAddr(value);
  var note = null;
  if (el.kind === 'value') {
    return { ok: true, text: newText !== undefined ? String(newText) : value, value: value, note: null };
  }
  if (el.kind === 'display') {
    var cur = parts.display.replace(/^"|"$/g, '');
    if (newText === undefined) return { ok: true, text: value, value: cur, note: null };
    parts.display = newText === '' ? '' : '"' + String(newText).replace(/"/g, '') + '"';
    if (!parts.hasAngles && parts.display) {
      // A display name forces the angle-bracket form.
      parts.hasAngles = true;
      note = 'adding a display name required the <...> form';
    }
    return { ok: true, text: joinNameAddr(parts), value: cur, note: note };
  }
  var u = splitUri(parts.uri);
  if (!u) return { ok: false, text: value, value: null, note: 'no URI found in this value' };
  if (!parts.hasAngles && parts.after && (el.kind === 'user' || el.kind === 'host' || el.kind === 'port')) {
    note = 'value has no <> — the ;-params formally belong to the URI (RFC 3261 §20.10)';
  }
  var curVal = el.kind === 'user' ? u.user : el.kind === 'host' ? u.host :
    el.kind === 'port' ? u.port : null;
  if (el.kind === 'param') {
    if (!el.param) return { ok: false, text: value, value: null, note: 'the rule names no parameter — cannot simulate a param edit without one' };
    var re = new RegExp('(;' + el.param.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')(=([^;]*))?', 'i');
    var pm = (u.rest || '').match(re);
    curVal = pm ? (pm[3] != null ? pm[3] : '') : null;
    if (newText === undefined) return { ok: true, text: value, value: curVal, note: note };
    if (newText === null) { // delete the param
      u.rest = (u.rest || '').replace(re, '');
    } else if (pm) {
      u.rest = (u.rest || '').replace(re, ';' + el.param + '=' + newText);
    } else {
      u.rest = (u.rest || '') + ';' + el.param + '=' + newText;
    }
    parts.uri = joinUri(u);
    return { ok: true, text: joinNameAddr(parts), value: curVal, note: note };
  }
  if (newText === undefined) return { ok: true, text: value, value: curVal, note: note };
  if (newText === null) { // delete the element
    if (el.kind === 'user') u.user = null;
    else if (el.kind === 'port') u.port = null;
    else return { ok: false, text: value, value: curVal, note: 'cannot delete the ' + el.kind + ' of a URI' };
  } else {
    if (el.kind === 'user') u.user = String(newText);
    else if (el.kind === 'host') u.host = String(newText);
    else if (el.kind === 'port') u.port = String(newText).replace(/[^0-9]/g, '') || null;
  }
  parts.uri = joinUri(u);
  return { ok: true, text: joinNameAddr(parts), value: curVal, note: note };
}

// ── condition evaluation ───────────────────────────────────────────────────

/**
 * Evaluate one IR condition against the parsed message.
 * Condition element forms seen in the wild IR: a bare header name ('From',
 * 'P-Asserted-Identity'), a dotted path ('from.uri.user'), or
 * 'response.status'. Comparisons: equals | contains | notcontains | exists |
 * notexists | absent | matches (+ per-condition negate).
 */
function evalCondition(cond, msg) {
  var r = { element: cond && cond.element, comparison: cond && cond.comparison,
    value: cond && cond.value, negate: !!(cond && cond.negate),
    passed: false, actual: null, note: null };
  if (!cond || !cond.element) { r.note = 'condition has no element — ignored as always-true'; r.passed = true; return r; }

  var elStr = String(cond.element);
  var actual = null;
  if (/^response\.status/i.test(elStr)) {
    actual = msg.isRequest ? null : String(msg.status);
  } else {
    var dotAt = elStr.indexOf('.');
    var hdrName = dotAt === -1 ? elStr : elStr.slice(0, dotAt);
    var sub = dotAt === -1 ? null : elStr.slice(dotAt + 1);
    var hn = normHeader(hdrName);
    var hv = null;
    if (hn === 'request-uri') hv = msg.requestUri;
    else {
      for (var i = 0; i < msg.headers.length; i++) {
        if (normHeader(msg.headers[i].name) === hn) { hv = msg.headers[i].value; break; }
      }
    }
    if (hv != null && sub) {
      var eo = elementOp(hv, normElement(sub));
      actual = eo.ok ? eo.value : null;
    } else {
      actual = hv;
    }
  }
  r.actual = actual;

  var cmp = String(cond.comparison || 'contains');
  var want = cond.value == null ? '' : String(cond.value);
  var passed;
  if (cmp === 'exists') passed = actual != null;
  else if (cmp === 'notexists' || cmp === 'absent') passed = actual == null;
  else if (actual == null) passed = (cmp === 'notcontains'); // nothing to compare against
  else if (cmp === 'equals') passed = actual === want;
  else if (cmp === 'contains') passed = actual.indexOf(want) !== -1;
  else if (cmp === 'notcontains') passed = actual.indexOf(want) === -1;
  else if (cmp === 'matches') {
    try { passed = new RegExp(want).test(actual); }
    catch (e) { passed = false; r.note = 'pattern is not a valid regex here — vendor dialects may still accept it'; }
  } else { passed = false; r.note = 'unknown comparison: ' + cmp; }

  r.passed = r.negate ? !passed : passed;
  return r;
}

// ── the simulator ──────────────────────────────────────────────────────────

/** Apply subOperation prefix/suffix arithmetic to a current text. */
function applySubOp(subOp, current, valText, notes) {
  var cur = current == null ? '' : String(current);
  var v = valText == null ? '' : String(valText);
  if (subOp === 'add-prefix') return v + cur;
  if (subOp === 'add-suffix') return cur + v;
  if (subOp === 'remove-prefix') {
    if (v && cur.indexOf(v) === 0) return cur.slice(v.length);
    notes.push('remove-prefix: the value does not start with "' + v + '" — nothing stripped');
    return cur;
  }
  if (subOp === 'remove-suffix') {
    if (v && cur.length >= v.length && cur.lastIndexOf(v) === cur.length - v.length) {
      return cur.slice(0, cur.length - v.length);
    }
    notes.push('remove-suffix: the value does not end with "' + v + '" — nothing stripped');
    return cur;
  }
  return v; // plain modify/replace: the new text IS the value
}

/**
 * Apply one HMR rule (the IR shape lib/hmr.js parses and lib/hmr-generate.js
 * drafts) to one raw SIP message.
 *
 * @param {object} rule HmrRule IR
 * @param {string} rawMessage full SIP message text (already-redacted capture
 *   raw, or a hand-pasted message)
 * @returns {{ok:boolean, problems:string[], parseError:string|null,
 *   inScope:boolean, scopeNotes:string[], matched:boolean,
 *   conditions:Array<object>, actions:Array<object>, changed:boolean,
 *   before:string, after:string, stored:{name:string,value:string|null}|null,
 *   warnings:string[]}}
 */
function applyRule(rule, rawMessage) {
  var out = {
    ok: false, problems: [], parseError: null,
    inScope: false, scopeNotes: [], matched: false,
    conditions: [], actions: [], changed: false,
    before: String(rawMessage == null ? '' : rawMessage), after: '',
    stored: null, warnings: []
  };
  out.after = out.before;

  // Structural validation first — mirror hmr-generate.validateRule's closed
  // vocabulary without importing it (this module stays dependency-free).
  if (!rule || typeof rule !== 'object') { out.problems.push('rule is not an object'); return out; }
  var OPS = ['add', 'delete', 'modify', 'replace', 'store', 'none'];
  if (OPS.indexOf(rule.operation) === -1) out.problems.push('unknown operation: ' + rule.operation);
  var target = rule.target || {};
  if (rule.operation !== 'none' && !target.header) out.problems.push('no target header');
  if (out.problems.length) return out;

  var msg = parseSipMessage(out.before);
  if (!msg.ok) { out.parseError = msg.error; return out; }
  out.ok = true;

  // ── scope ──
  var scope = rule.scope || {};
  var msgType = scope.msgType === 'response' ? 'reply' : (scope.msgType || 'any');
  if (msgType === 'request' && !msg.isRequest) {
    out.scopeNotes.push('rule applies to requests only; this is a ' + msg.status + ' response');
    return out;
  }
  if (msgType === 'reply' && msg.isRequest) {
    out.scopeNotes.push('rule applies to responses only; this is a ' + msg.method + ' request');
    return out;
  }
  var methods = Array.isArray(scope.methods) ? scope.methods : [];
  if (methods.length) {
    // For a response, the method comes from CSeq — the transaction it answers.
    var mth = msg.isRequest ? msg.method : null;
    if (!mth) {
      for (var ci = 0; ci < msg.headers.length; ci++) {
        if (normHeader(msg.headers[ci].name) === 'cseq') {
          var cm = msg.headers[ci].value.match(/\d+\s+([A-Za-z]+)/);
          if (cm) mth = cm[1].toUpperCase();
          break;
        }
      }
    }
    if (!mth || methods.map(function (x) { return String(x).toUpperCase(); }).indexOf(mth) === -1) {
      out.scopeNotes.push('rule is scoped to ' + methods.join('/') + '; this message is ' +
        (mth || 'method-unknown'));
      return out;
    }
  }
  if (scope.direction === 'in' || scope.direction === 'out') {
    out.scopeNotes.push('direction "' + scope.direction + '" cannot be checked against a single message — simulated as if the rule is attached where this message ' + (scope.direction === 'in' ? 'arrives' : 'leaves'));
  } else {
    out.scopeNotes.push('the rule is unbound to a direction/interface — remember an unbound rule never runs on a real SBC');
  }
  out.inScope = true;

  // ── conditions ──
  var allPassed = true;
  for (var i = 0; i < (rule.conditions || []).length; i++) {
    var cr = evalCondition(rule.conditions[i], msg);
    out.conditions.push(cr);
    if (!cr.passed) allPassed = false;
  }
  out.matched = allPassed;
  if (!allPassed) return out; // in scope, conditions failed — nothing to apply

  // ── the operation ──
  var el = normElement(target.element);
  if (el.kind === 'unknown') {
    out.warnings.push('unrecognised target element "' + target.element + '" — treated as the whole header value');
    el = { kind: 'value', param: null };
  }
  var hn = normHeader(target.header);
  var valText = rule.value && rule.value.text != null ? String(rule.value.text) : null;
  if (rule.value && rule.value.kind === 'expression') {
    out.warnings.push('the value is a vendor expression (' + valText + ') — simulated as literal text; variables and regex back-references are not expanded');
  }
  var op = rule.operation;
  var subOp = rule.subOperation || null;
  var notes = [];

  if (hn === 'content-length') {
    out.warnings.push('SBCs recompute Content-Length on egress — a rule editing it is usually a no-op in production');
  }

  // Request-URI: the start line, not a header.
  if (hn === 'request-uri') {
    if (!msg.isRequest) {
      out.warnings.push('a response has no Request-URI — nothing to do');
      return out;
    }
    if (op === 'add' || op === 'delete') {
      out.warnings.push('a request always has exactly one Request-URI — "' + op + '" is not meaningful; use modify/replace');
      return out;
    }
    var ruEl = (el.kind === 'value') ? { kind: 'value', param: null } : el;
    var before = msg.requestUri;
    var newUri;
    if (ruEl.kind === 'value') {
      newUri = applySubOp(subOp, before, valText, notes);
    } else {
      var cur = elementOp('<' + before + '>', ruEl); // reuse the URI surgery
      var repl = op === 'store' ? undefined : applySubOp(subOp, cur.value, valText, notes);
      if (op === 'store') {
        out.stored = { name: rule.name || 'stored', value: cur.value };
        out.actions.push({ op: 'store', header: 'Request-URI', element: ruEl.kind, before: before, after: null, note: 'captured "' + String(cur.value) + '" — cross-message use of stored values is not simulated' });
        out.after = serializeSipMessage(msg);
        return out;
      }
      var eo2 = elementOp('<' + before + '>', ruEl, repl);
      newUri = eo2.ok ? eo2.text.replace(/^<|>$/g, '') : before;
      if (!eo2.ok) notes.push(eo2.note || 'element edit failed');
    }
    if (op === 'store') {
      out.stored = { name: rule.name || 'stored', value: before };
      out.actions.push({ op: 'store', header: 'Request-URI', element: 'value', before: before, after: null, note: 'captured — cross-message use of stored values is not simulated' });
      out.after = serializeSipMessage(msg);
      return out;
    }
    msg.requestUri = newUri;
    msg.startLine = msg.method + ' ' + newUri + ' ' + (msg.sipVersion || 'SIP/2.0');
    out.actions.push({ op: op, header: 'Request-URI', element: ruEl.kind, before: before, after: newUri, note: notes.join('; ') || null });
    out.changed = newUri !== before;
    out.after = serializeSipMessage(msg);
    if (msg.hadFolds) out.warnings.push('the original message had folded headers — they are unfolded in the rewritten output');
    return out;
  }

  // Ordinary headers.
  var instances = [];
  for (var h = 0; h < msg.headers.length; h++) {
    if (normHeader(msg.headers[h].name) === hn) instances.push(h);
  }
  var idx = (target.index != null && target.index !== '') ? parseInt(target.index, 10) : null;
  if (idx != null && (isNaN(idx) || idx < 0 || idx >= instances.length)) {
    out.warnings.push('target index ' + target.index + ' is out of range — the message has ' + instances.length + ' instance(s) of ' + (target.header || hn));
    idx = null;
  }

  if (op === 'add') {
    if (valText == null) {
      out.warnings.push('the rule has no value to add — nothing changed (fill the value in first)');
      return out;
    }
    if (instances.length) notes.push('the message already had ' + instances.length + ' instance(s); the rule adds another (SIP allows repeated headers)');
    msg.headers.push({ name: target.header, value: valText });
    out.actions.push({ op: 'add', header: target.header, element: 'value', before: null, after: valText, note: notes.join('; ') || null });
    out.changed = true;
  } else if (!instances.length) {
    out.actions.push({ op: op, header: target.header, element: el.kind, before: null, after: null, note: 'the message has no ' + (target.header || hn) + ' header — nothing to ' + op });
  } else if (op === 'delete' && el.kind === 'value') {
    var removed = idx != null ? [instances[idx]] : instances.slice();
    if (idx == null && instances.length > 1) notes.push('all ' + instances.length + ' instances removed (set target.index to remove just one)');
    for (var d = removed.length - 1; d >= 0; d--) {
      out.actions.push({ op: 'delete', header: msg.headers[removed[d]].name, element: 'value', before: msg.headers[removed[d]].value, after: null, note: notes.join('; ') || null });
      msg.headers.splice(removed[d], 1);
    }
    out.actions.reverse(); // report in original order
    out.changed = true;
  } else {
    // modify / replace / store / element-delete act on ONE instance: the
    // indexed one, else the first (with a note when more exist).
    var at = idx != null ? instances[idx] : instances[0];
    if (idx == null && instances.length > 1) {
      notes.push('the message has ' + instances.length + ' instances — only the first is touched (set target.index to pick another)');
    }
    var hv2 = msg.headers[at].value;
    if (op === 'store') {
      var got = elementOp(hv2, el);
      out.stored = { name: rule.name || 'stored', value: got.ok ? got.value : null };
      out.actions.push({ op: 'store', header: msg.headers[at].name, element: el.kind, before: got.ok ? got.value : hv2, after: null, note: 'captured — cross-message use of stored values is not simulated' + (notes.length ? '; ' + notes.join('; ') : '') });
    } else if (op === 'delete') {
      // element-level delete (whole-header delete handled above)
      var del = elementOp(hv2, el, null);
      if (!del.ok) {
        out.warnings.push(del.note || 'could not delete that element');
      } else {
        msg.headers[at].value = del.text;
        out.actions.push({ op: 'delete', header: msg.headers[at].name, element: el.kind, before: hv2, after: del.text, note: (del.note ? del.note + '; ' : '') + (notes.join('; ') || '') || null });
        out.changed = del.text !== hv2;
      }
    } else if (op === 'modify' || op === 'replace') {
      var rd = elementOp(hv2, el);
      if (!rd.ok) {
        out.warnings.push(rd.note || 'no such element in this header value');
      } else if (el.kind !== 'value' && rd.value == null && subOp == null && el.kind !== 'param') {
        out.actions.push({ op: op, header: msg.headers[at].name, element: el.kind, before: hv2, after: hv2, note: 'this value has no ' + el.kind + ' part — nothing changed' });
      } else {
        var newText = applySubOp(subOp, el.kind === 'value' ? hv2 : rd.value, valText, notes);
        if (valText == null && subOp == null) {
          out.warnings.push('the rule has no replacement value — nothing changed (fill the value in first)');
        } else {
          var wr = elementOp(hv2, el, newText);
          if (wr.note) notes.push(wr.note);
          msg.headers[at].value = wr.text;
          out.actions.push({ op: op, header: msg.headers[at].name, element: el.kind, before: hv2, after: wr.text, note: notes.join('; ') || null });
          out.changed = wr.text !== hv2;
        }
      }
    } else if (op === 'none') {
      out.actions.push({ op: 'none', header: target.header, element: el.kind, before: hv2, after: hv2, note: 'no-op rule' });
    }
  }

  out.after = serializeSipMessage(msg);
  if (out.changed && msg.hadFolds) {
    out.warnings.push('the original message had folded headers — they are unfolded in the rewritten output');
  }
  return out;
}

module.exports = {
  applyRule,
  parseSipMessage,
  serializeSipMessage,
  // exported for tests
  _normHeader: normHeader,
  _normElement: normElement,
  _splitNameAddr: splitNameAddr,
  _splitUri: splitUri,
  _elementOp: elementOp,
  _evalCondition: evalCondition
};
