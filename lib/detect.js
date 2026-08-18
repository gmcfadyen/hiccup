'use strict';

/**
 * lib/detect.js — the indicator "lamps" and the capture-scenario classifier.
 *
 * Exports (per ARCHITECTURE.md, frozen contract):
 *   detectIndicators(analysis) -> [Indicator]
 *   detectScenario(analysis)   -> Scenario
 *
 * Both read an AnalysisJSON object that already has messages/legs/calls/retrans
 * and (when their modules ran) media/aux/findings attached. Everything here is
 * deterministic evidence-reading: no LLM, no network, no filesystem.
 *
 * detectIndicators always returns the full fixed key list, in the documented
 * order, with state 'off' for anything absent — the UI lamp strip must never
 * change shape between captures. A detector that throws degrades to its 'off'
 * sentence rather than failing the analysis.
 *
 * Zero dependencies: local header/SDP helpers operate on the frozen
 * SipMessage/Leg/Sdp shapes, so this module requires no siblings.
 */

// ---------------------------------------------------------------------------
// tiny defensive helpers
// ---------------------------------------------------------------------------

/** True for a non-null object. */
function isObj(v) { return !!v && typeof v === 'object'; }
/** Always an array (never null). */
function arr(v) { return Array.isArray(v) ? v : []; }
/** Always a string. */
function str(v) { return v == null ? '' : String(v); }
/** Always a lowercase string. */
function lc(v) { return str(v).toLowerCase(); }
/** Finite number or null. */
function num(v) { return typeof v === 'number' && isFinite(v) ? v : null; }
/** Finite number or a default. */
function numOr(v, d) { var n = num(v); return n === null ? d : n; }
/** Digits only ('+33 6-12' -> '33612'). */
function digits(v) { return str(v).replace(/\D+/g, ''); }
/** Round to 2 decimals. */
function round2(n) { return Math.round((num(n) || 0) * 100) / 100; }

/**
 * De-duplicate and cap an id list so a lamp never carries a huge evidence array.
 * @param {Array<string>} ids
 * @param {number} [max=12]
 * @returns {string[]}
 */
function capIds(ids, max) {
  var limit = max || 12;
  var list = arr(ids);
  var out = [];
  var seen = Object.create(null);
  for (var i = 0; i < list.length && out.length < limit; i++) {
    var id = list[i];
    if (typeof id !== 'string' || !id || seen[id]) continue;
    seen[id] = 1;
    out.push(id);
  }
  return out;
}

/** Message ids of a message list. */
function ids(msgs) {
  var out = [];
  for (var i = 0; i < arr(msgs).length; i++) {
    var m = msgs[i];
    if (m && typeof m.id === 'string') out.push(m.id);
  }
  return out;
}

/** First element matching pred, else null. */
function firstOf(list, pred) {
  var l = arr(list);
  for (var i = 0; i < l.length; i++) {
    try { if (pred(l[i])) return l[i]; } catch (e) { /* skip */ }
  }
  return null;
}

/** All elements matching pred. */
function allOf(list, pred) {
  var out = [];
  var l = arr(list);
  for (var i = 0; i < l.length; i++) {
    try { if (pred(l[i])) out.push(l[i]); } catch (e) { /* skip */ }
  }
  return out;
}

// ---------------------------------------------------------------------------
// header helpers (compact-form aware; mirrors sip.js semantics on the frozen
// headers[] shape without requiring it)
// ---------------------------------------------------------------------------

var COMPACT = {
  f: 'from', t: 'to', i: 'call-id', m: 'contact', v: 'via',
  c: 'content-type', l: 'content-length', k: 'supported', x: 'session-expires'
};

/** Normalize a header name: trim, lowercase, expand SIP compact forms. */
function normName(name) {
  var n = lc(name).trim();
  return COMPACT[n] || n;
}

/** All values of a header on a message, in order (empty array when absent). */
function hdrs(msg, name) {
  var out = [];
  if (!msg || !Array.isArray(msg.headers)) return out;
  var want = normName(name);
  for (var i = 0; i < msg.headers.length; i++) {
    var h = msg.headers[i];
    if (h && normName(h.name) === want) out.push(str(h.value));
  }
  return out;
}

/** First value of a header, or null. */
function hdr(msg, name) {
  var v = hdrs(msg, name);
  return v.length ? v[0] : null;
}

/** True when the header exists with a non-empty value. */
function hasHdr(msg, name) {
  var v = hdrs(msg, name);
  for (var i = 0; i < v.length; i++) if (v[i].trim()) return true;
  return false;
}

/** Comma-separated option tags of a header as lowercase tokens. */
function tokens(msg, name) {
  var out = [];
  var v = hdrs(msg, name);
  for (var i = 0; i < v.length; i++) {
    var parts = v[i].split(',');
    for (var j = 0; j < parts.length; j++) {
      var t = parts[j].trim().toLowerCase();
      if (t) out.push(t);
    }
  }
  return out;
}

/** True when a Supported/Require/Allow/Unsupported/Proxy-Require token is present. */
function hasToken(msg, name, token) {
  return tokens(msg, name).indexOf(token) !== -1;
}

/** User part of a SIP/SIPS/TEL URI (or name-addr), else null. */
function uriUser(uri) {
  if (!uri) return null;
  var s = str(uri);
  var lt = s.indexOf('<');
  if (lt !== -1) {
    var gt = s.indexOf('>', lt);
    s = s.slice(lt + 1, gt === -1 ? s.length : gt);
  }
  var m = /^\s*sips?:([^@;?\s]+)@/i.exec(s);
  if (m) return m[1];
  m = /^\s*tel:([^;?\s]+)/i.exec(s);
  if (m) return m[1];
  return null;
}

// ---------------------------------------------------------------------------
// address helpers
// ---------------------------------------------------------------------------

var DOC_RANGE = /^(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|2001:db8:)/i;
var PRIVATE_RANGE =
  /^(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|::1$|fe80:|fc|fd)/i;

/** True for an RFC 5737 / RFC 3849 documentation address. */
function isDocAddr(a) { return DOC_RANGE.test(str(a)); }
/** True for an RFC 1918 / RFC 6598 / loopback / link-local address. */
function isPrivateAddr(a) { return PRIVATE_RANGE.test(str(a)); }
/** True for an IPv6 literal. */
function isV6Addr(a) { return str(a).indexOf(':') !== -1; }

// ---------------------------------------------------------------------------
// Q.850 / Q.931 cause text (shared by the H.323 and SIP-I lamps)
// ---------------------------------------------------------------------------

var CAUSE_TEXT = {
  1: 'Unallocated number', 3: 'No route to destination', 16: 'Normal call clearing',
  17: 'User busy', 18: 'No user responding', 19: 'No answer from user',
  21: 'Call rejected', 22: 'Number changed', 27: 'Destination out of order',
  28: 'Invalid number format', 31: 'Normal, unspecified',
  34: 'No circuit/channel available', 38: 'Network out of order',
  41: 'Temporary failure', 42: 'Switching equipment congestion',
  44: 'Requested circuit unavailable', 47: 'Resource unavailable',
  50: 'Requested facility not subscribed', 57: 'Bearer capability not authorized',
  58: 'Bearer capability not presently available', 63: 'Service or option not available',
  65: 'Bearer capability not implemented', 79: 'Service or option not implemented',
  88: 'Incompatible destination', 95: 'Invalid message', 97: 'Message type non-existent',
  99: 'Information element non-existent', 102: 'Recovery on timer expiry',
  111: 'Protocol error', 127: 'Interworking, unspecified'
};

// Causes that mean "the network broke", not "the human declined".
var NETWORK_FAULT_CAUSES = {
  3: 1, 27: 1, 34: 1, 38: 1, 41: 1, 42: 1, 44: 1, 47: 1, 58: 1, 63: 1,
  65: 1, 79: 1, 88: 1, 95: 1, 97: 1, 99: 1, 102: 1, 111: 1, 127: 1
};

/** Human text for a Q.850 cause value. */
function causeText(code, fallback) {
  var c = num(code);
  if (c === null) return str(fallback);
  return CAUSE_TEXT[c] || str(fallback) || 'cause ' + c;
}

// ---------------------------------------------------------------------------
// context: everything both exports need, computed once, never throwing
// ---------------------------------------------------------------------------

/**
 * Build the read-only working context from an AnalysisJSON-shaped object.
 * Missing or malformed sections degrade to empty collections.
 * @param {object} analysis
 * @returns {object} context
 */
function buildContext(analysis) {
  var a = isObj(analysis) ? analysis : {};
  var messages = allOf(a.messages, isObj);

  var sip = [], h323 = [];
  for (var i = 0; i < messages.length; i++) {
    var m = messages[i];
    if (m.protocol === 'h323' || m.q931Type) h323.push(m);
    else if (m.protocol === 'sip' || Array.isArray(m.headers)) sip.push(m);
  }

  var legs = allOf(a.legs, isObj);
  var calls = allOf(a.calls, isObj);
  var media = isObj(a.media) ? a.media : {};
  var streams = allOf(media.streams, isObj);
  var rtcp = allOf(media.rtcp, isObj);
  var aux = allOf(a.aux, isObj);
  var findings = allOf(a.findings, isObj);
  var retrans = isObj(a.retrans) ? a.retrans : {};
  var collapses = allOf(retrans.collapses, isObj);
  var stats = isObj(a.stats) ? a.stats : {};

  var msgById = Object.create(null);
  for (i = 0; i < messages.length; i++) {
    if (typeof messages[i].id === 'string') msgById[messages[i].id] = messages[i];
  }
  var legById = Object.create(null);
  for (i = 0; i < legs.length; i++) {
    if (typeof legs[i].id === 'string') legById[legs[i].id] = legs[i];
  }

  // messages per leg, in the leg's own order
  var legMsgs = Object.create(null);
  for (i = 0; i < legs.length; i++) {
    var leg = legs[i];
    var list = [];
    var mids = arr(leg.msgIds);
    for (var j = 0; j < mids.length; j++) {
      var mm = msgById[mids[j]];
      if (mm) list.push(mm);
    }
    if (typeof leg.id === 'string') legMsgs[leg.id] = list;
  }

  // diff items, flattened with their call/leg context
  var diffItems = [];
  var diffTags = Object.create(null);
  for (i = 0; i < calls.length; i++) {
    var call = calls[i];
    var pairs = arr(call.diffs);
    for (j = 0; j < pairs.length; j++) {
      var pair = isObj(pairs[j]) ? pairs[j] : {};
      var cats = arr(isObj(pair.diff) ? pair.diff.categories : null);
      for (var k = 0; k < cats.length; k++) {
        var cat = isObj(cats[k]) ? cats[k] : {};
        var items = allOf(cat.items, isObj);
        for (var q = 0; q < items.length; q++) {
          var entry = {
            tag: str(items[q].tag),
            severity: str(items[q].severity),
            label: str(items[q].label),
            ingress: items[q].ingress == null ? null : str(items[q].ingress),
            egress: items[q].egress == null ? null : str(items[q].egress),
            category: str(cat.key),
            callId: typeof call.id === 'string' ? call.id : null,
            a: typeof pair.a === 'string' ? pair.a : null,
            b: typeof pair.b === 'string' ? pair.b : null
          };
          diffItems.push(entry);
          if (!diffTags[entry.tag]) diffTags[entry.tag] = [];
          diffTags[entry.tag].push(entry);
        }
      }
    }
  }

  var auxByProto = Object.create(null);
  for (i = 0; i < aux.length; i++) {
    var p = lc(aux[i].protocol) || 'unknown';
    if (!auxByProto[p]) auxByProto[p] = [];
    auxByProto[p].push(aux[i]);
  }

  var ctx = {
    analysis: a,
    stats: stats,
    format: lc(stats.format),
    messages: messages,
    sip: sip,
    h323: h323,
    legs: legs,
    sipLegs: allOf(legs, function (l) { return l.protocol !== 'h323'; }),
    h323Legs: allOf(legs, function (l) { return l.protocol === 'h323'; }),
    callLegs: allOf(legs, function (l) { return l.kind === 'call' || l.protocol === 'h323'; }),
    calls: calls,
    streams: streams,
    rtcp: rtcp,
    aux: aux,
    auxByProto: auxByProto,
    findings: findings,
    retrans: retrans,
    collapses: collapses,
    msgById: msgById,
    legById: legById,
    legMsgs: legMsgs,
    diffItems: diffItems,
    diffTags: diffTags,
    _rawLc: new Map(),
    _sdpLc: new Map(),
    _media: new Map(),
    _codecs: new Map()
  };

  // requests / responses split, used all over
  ctx.requests = allOf(sip, function (m) { return m.isRequest === true; });
  ctx.responses = allOf(sip, function (m) { return m.isRequest !== true && num(m.status) !== null; });

  return ctx;
}

// Cached lowercase copies are bounded so a pathological capture cannot double
// its own memory footprint here; 16 KB is far beyond any real SIP message.
var RAW_LC_CAP = 16384;

/** Lowercased full message text (cached, capped at 16 KB). */
function rawLc(ctx, m) {
  if (!m) return '';
  if (ctx._rawLc.has(m)) return ctx._rawLc.get(m);
  var v = '';
  if (typeof m.raw === 'string') {
    v = (m.raw.length > RAW_LC_CAP ? m.raw.slice(0, RAW_LC_CAP) : m.raw).toLowerCase();
  }
  ctx._rawLc.set(m, v);
  return v;
}

/** Lowercased SDP text for a message (SDP body when parsed, else the raw text). */
function sdpLc(ctx, m) {
  if (!m) return '';
  if (ctx._sdpLc.has(m)) return ctx._sdpLc.get(m);
  var v = '';
  if (isObj(m.sdp) && typeof m.sdp.raw === 'string') {
    v = (m.sdp.raw.length > RAW_LC_CAP ? m.sdp.raw.slice(0, RAW_LC_CAP) : m.sdp.raw).toLowerCase();
  }
  if (!v) {
    var raw = rawLc(ctx, m);
    var at = raw.indexOf('\nv=0');
    if (at === -1 && raw.indexOf('v=0') === 0) at = 0;
    if (at !== -1) v = raw.slice(at);
  }
  ctx._sdpLc.set(m, v);
  return v;
}

/** True when a message's SDP (or body text) matches a regex. */
function sdpHas(ctx, m, re) {
  try { return re.test(sdpLc(ctx, m)); } catch (e) { return false; }
}

/**
 * m= lines of a message: parsed Sdp when available, else a regex over the raw
 * body, so hand-built and half-parsed messages still work.
 * @returns {Array<{type:string,port:number,proto:string,attrs:string,fmt:string}>}
 */
function mediaLines(ctx, m) {
  if (!m) return [];
  if (ctx._media.has(m)) return ctx._media.get(m);
  var out = [];
  var parsed = isObj(m.sdp) ? arr(m.sdp.media) : [];
  if (parsed.length) {
    for (var i = 0; i < parsed.length; i++) {
      var mb = isObj(parsed[i]) ? parsed[i] : {};
      out.push({
        type: lc(mb.type),
        port: numOr(mb.port, -1),
        proto: lc(mb.proto),
        attrs: arr(mb.attrs).map(lc).join(' '),
        fmt: arr(mb.payloads).map(function (p) { return isObj(p) ? lc(p.codec) : ''; }).join(' ')
      });
    }
  } else {
    var text = sdpLc(ctx, m);
    var re = /(?:^|\n)m=([a-z]+)\s+(\d+)\s+(\S+)([^\n]*)/g;
    var mt;
    while ((mt = re.exec(text)) !== null) {
      out.push({ type: mt[1], port: parseInt(mt[2], 10) || 0, proto: mt[3], attrs: '', fmt: lc(mt[4]) });
    }
  }
  ctx._media.set(m, out);
  return out;
}

/** Lowercase codec names offered/answered in a message's SDP. */
function codecsOf(ctx, m) {
  if (!m) return [];
  if (ctx._codecs.has(m)) return ctx._codecs.get(m);
  var out = [];
  var seen = Object.create(null);
  var push = function (name) {
    var n = lc(name).trim();
    if (!n || seen[n]) return;
    seen[n] = 1;
    out.push(n);
  };
  var parsed = isObj(m.sdp) ? arr(m.sdp.media) : [];
  for (var i = 0; i < parsed.length; i++) {
    var pl = arr(isObj(parsed[i]) ? parsed[i].payloads : null);
    for (var j = 0; j < pl.length; j++) if (isObj(pl[j]) && pl[j].codec) push(pl[j].codec);
  }
  var text = sdpLc(ctx, m);
  var re = /a=rtpmap:\d+\s+([^\s/]+)/g;
  var mt;
  while ((mt = re.exec(text)) !== null) push(mt[1]);
  ctx._codecs.set(m, out);
  return out;
}

/** Audio m= line of a message (first one), else null. */
function audioLine(ctx, m) {
  var lines = mediaLines(ctx, m);
  for (var i = 0; i < lines.length; i++) if (lines[i].type === 'audio') return lines[i];
  return null;
}

/** telephone-event payload type negotiated in a message, else null. */
function telEventPt(ctx, m) {
  var text = sdpLc(ctx, m);
  var mt = /a=rtpmap:(\d+)\s+telephone-event/i.exec(text);
  return mt ? parseInt(mt[1], 10) : null;
}

/**
 * Final (>=200) responses answering a request's CSeq. Scoped to the leg's own
 * message list when one is supplied, otherwise to every response with the same
 * Call-ID (so an identical CSeq in a different dialog cannot match).
 */
function finalsFor(ctx, req, legMsgList) {
  var out = [];
  if (!req || !isObj(req.cseq)) return out;
  var list = arr(legMsgList).length ? legMsgList : ctx.responses;
  for (var i = 0; i < list.length; i++) {
    var m = list[i];
    if (!m || m.isRequest === true) continue;
    var st = num(m.status);
    if (st === null || st < 200) continue;
    if (!isObj(m.cseq) || m.cseq.num !== req.cseq.num || m.cseq.method !== req.cseq.method) continue;
    if (req.callId && m.callId && req.callId !== m.callId) continue;
    out.push(m);
  }
  return out;
}

/** Every SIP leg's first SDP offer and the first SDP answer to it. */
function offerAnswerPairs(ctx) {
  if (ctx._oa) return ctx._oa;
  var out = [];
  for (var i = 0; i < ctx.sipLegs.length; i++) {
    var leg = ctx.sipLegs[i];
    var list = arr(ctx.legMsgs[leg.id]);
    var offer = firstOf(list, function (m) { return m.isRequest === true && sdpLc(ctx, m); });
    var answer = null;
    if (offer) {
      var cands = allOf(list, function (m) {
        var st = num(m.status);
        return m.isRequest !== true && st !== null && st >= 180 && st < 300 && sdpLc(ctx, m);
      });
      answer = firstOf(cands, function (m) {
        return !isObj(offer.cseq) || !isObj(m.cseq) || m.cseq.num === offer.cseq.num;
      });
    }
    out.push({ leg: leg, msgs: list, offer: offer, answer: answer });
  }
  ctx._oa = out;
  return out;
}

/**
 * Shallow-ish search of an aux `detail` object for a key (normalized name) and
 * a predicate on its value. Aux details come from sibling modules, so nothing
 * about their internals is assumed.
 */
function detailFind(detail, keyRe, valuePred, depth) {
  var d = depth == null ? 4 : depth;
  if (!isObj(detail) || d < 0) return null;
  var keys = Object.keys(detail);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var v = detail[k];
    var norm = k.replace(/[^a-z0-9]/gi, '').toLowerCase();
    if (keyRe.test(norm)) {
      try { if (!valuePred || valuePred(v)) return { key: k, value: v }; } catch (e) { /* skip */ }
    }
    if (isObj(v)) {
      var hit = detailFind(v, keyRe, valuePred, d - 1);
      if (hit) return hit;
    }
  }
  return null;
}

/** Aux entries whose summary or detail matches a regex. */
function auxMatch(list, re) {
  return allOf(list, function (x) {
    if (re.test(lc(x.summary))) return true;
    try { return re.test(lc(JSON.stringify(x.detail))); } catch (e) { return false; }
  });
}

// ---------------------------------------------------------------------------
// IMS marker extraction (DESIGN_1 core feature 4 + 5G markers)
// ---------------------------------------------------------------------------

var ROUTE_ORIG_RE = /(?:^|[;:@?&<])orig(?:[;>,\s)]|$)/;

/**
 * Collect the 3GPP/IMS markers visible in the signalling.
 * @param {object} ctx
 * @returns {{markers: Array<{name:string,detail:string,msgIds:string[]}>, msgIds:string[],
 *            fiveG: Array<string>, hasPath:boolean, hasServiceRoute:boolean,
 *            hasAssociatedUri:boolean, hasIcid:boolean, hasPani:boolean,
 *            paniText:string, hasPrecondition:boolean, hasConfirmed:boolean,
 *            hasDesired:boolean, thirdParty:boolean}}
 */
function imsMarkers(ctx) {
  if (ctx._ims) return ctx._ims;
  var markers = [];
  var all = [];
  var add = function (name, detail, msgs) {
    var mids = capIds(ids(msgs), 6);
    if (!mids.length && !arr(msgs).length) return;
    markers.push({ name: name, detail: detail, msgIds: mids });
    for (var i = 0; i < mids.length; i++) all.push(mids[i]);
  };

  var withHdr = function (name) { return allOf(ctx.sip, function (m) { return hasHdr(m, name); }); };

  var path = withHdr('path');
  if (path.length) add('path', 'Path header present (the P-CSCF records itself in the registration route set)', path);
  var sr = withHdr('service-route');
  if (sr.length) add('service-route', 'Service-Route returned in the REGISTER 200 OK (the route set the UE must use)', sr);
  var pau = withHdr('p-associated-uri');
  if (pau.length) add('p-associated-uri', 'P-Associated-URI present (the other public identities bound to this subscriber)', pau);
  var pcv = allOf(ctx.sip, function (m) { return /icid-value/i.test(str(hdr(m, 'p-charging-vector'))); });
  if (pcv.length) add('p-charging-vector', 'P-Charging-Vector icid-value threads one session across IMS nodes', pcv);
  var pem = withHdr('p-early-media');
  if (pem.length) add('p-early-media', 'P-Early-Media gates whether pre-answer media is authorised', pem);
  var pani = withHdr('p-access-network-info');
  if (pani.length) add('p-access-network-info', 'P-Access-Network-Info reports the access technology the UE is on', pani);
  var pvni = withHdr('p-visited-network-id');
  if (pvni.length) add('p-visited-network-id', 'P-Visited-Network-ID names the roaming/visited network', pvni);
  var pchf = withHdr('p-charging-function-addresses');
  if (pchf.length) add('p-charging-function-addresses', 'P-Charging-Function-Addresses points at the CCF/ECF charging nodes', pchf);
  // NOTE: P-Asserted-Identity is deliberately NOT an IMS marker — it is routine on
  // plain enterprise trunks and would inflate every capture into "IMS".

  var orig = allOf(ctx.sip, function (m) {
    var rs = arr(m.routes).length ? arr(m.routes) : hdrs(m, 'route');
    for (var i = 0; i < rs.length; i++) if (ROUTE_ORIG_RE.test(lc(rs[i]))) return true;
    return false;
  });
  if (orig.length) add('route-orig', 'sip:orig in the Route set marks originating iFC processing at the S-CSCF', orig);

  var thirdParty = allOf(ctx.sip, function (m) {
    if (m.isRequest !== true || m.method !== 'REGISTER') return false;
    var fu = uriUser(m.fromUri), tu = uriUser(m.toUri);
    if (fu && tu && fu !== tu) return true;
    return !!(m.bodyType && /multipart|message\/sip/.test(lc(m.bodyType)));
  });
  if (thirdParty.length) add('third-party-register', 'A third-party REGISTER tells an application server the subscriber is online', thirdParty);

  var precond = allOf(ctx.sip, function (m) { return sdpHas(ctx, m, /a=(?:curr|des|conf):/); });
  if (precond.length) add('preconditions', 'SDP preconditions (a=curr/a=des/a=conf) hold the call until the bearer is ready', precond);

  var paniText = '';
  for (var i = 0; i < pani.length; i++) paniText += ' ' + lc(hdr(pani[i], 'p-access-network-info'));

  var fiveG = [];
  var nr = allOf(pani, function (m) { return /3gpp-nr|5gs|3gpp-5g|nr-fdd|nr-tdd/.test(lc(hdr(m, 'p-access-network-info'))); });
  if (nr.length) { fiveG.push('5G NR access'); add('5g-access', 'P-Access-Network-Info reports 5G NR access', nr); }
  var fc = withHdr('feature-caps');
  if (fc.length) { fiveG.push('Feature-Caps'); add('feature-caps', 'Feature-Caps advertises 5G/IMS media and service capabilities per hop', fc); }
  var gr = allOf(ctx.sip, function (m) {
    var c = lc(str(hdr(m, 'contact')));
    return /;gr=/.test(c) || (/\+sip\.instance/.test(c) && /gr/.test(c));
  });
  if (gr.length) { fiveG.push('GRUU (sip.instance/gr)'); add('gruu', 'A GRUU (sip.instance with a gr parameter) addresses one specific device of the subscriber', gr); }

  var res = {
    markers: markers,
    msgIds: capIds(all, 12),
    fiveG: fiveG,
    hasPath: path.length > 0,
    hasServiceRoute: sr.length > 0,
    hasAssociatedUri: pau.length > 0,
    hasIcid: pcv.length > 0,
    hasPani: pani.length > 0,
    paniText: paniText,
    hasPrecondition: precond.length > 0,
    hasDesired: !!firstOf(ctx.sip, function (m) { return sdpHas(ctx, m, /a=des:/); }),
    hasConfirmed: !!firstOf(ctx.sip, function (m) { return sdpHas(ctx, m, /a=conf:/); }),
    thirdParty: thirdParty.length > 0
  };
  ctx._ims = res;
  return res;
}

// ---------------------------------------------------------------------------
// the indicator detectors — fixed order, fixed keys
// ---------------------------------------------------------------------------

var STATES = { on: 1, off: 1, partial: 1, issue: 1 };

/** Shorthand for a detector result. */
function r(state, detail, msgIds, callIds) {
  return { state: state, detail: detail, msgIds: msgIds, callIds: callIds };
}

/** Call ids that own a set of leg ids. */
function callIdsForLegs(ctx, legIds) {
  var want = Object.create(null);
  for (var i = 0; i < arr(legIds).length; i++) if (legIds[i]) want[legIds[i]] = 1;
  var out = [];
  for (i = 0; i < ctx.calls.length; i++) {
    var c = ctx.calls[i];
    var lids = arr(c.legIds);
    for (var j = 0; j < lids.length; j++) {
      if (want[lids[j]] && typeof c.id === 'string') { out.push(c.id); break; }
    }
  }
  return out;
}

/** Call ids attached to a list of diff items. */
function callIdsOfItems(items) {
  var out = [];
  for (var i = 0; i < arr(items).length; i++) if (items[i] && items[i].callId) out.push(items[i].callId);
  return out;
}

var DETECTORS = [
  // -- sip ------------------------------------------------------------------
  {
    key: 'sip', label: 'SIP',
    fallback: 'No SIP was found in this capture — SIP is the request/response signalling protocol that sets up, modifies and tears down modern voice calls.',
    run: function (ctx) {
      if (!ctx.sip.length) return r('off', this.fallback);
      var dialogs = ctx.sipLegs.length;
      if (ctx.requests.length && !ctx.responses.length) {
        return r('issue',
          ctx.requests.length + ' SIP requests were captured and not one response came back — SIP works as request/response, so a trace with no answers means the far end never replied or only one direction of the conversation was captured.',
          ids(ctx.requests.slice(0, 6)));
      }
      return r('on',
        'SIP signalling is present (' + ctx.sip.length + ' messages in ' + dialogs + ' dialog' + (dialogs === 1 ? '' : 's') +
        ') — this is the request/response protocol that negotiates every call you see in the ladder.',
        ids(ctx.sip.slice(0, 6)));
    }
  },
  // -- h323 -----------------------------------------------------------------
  {
    key: 'h323', label: 'H.323',
    fallback: 'No H.323 was found — H.323 is the older ITU call-control protocol (Q.931 signalling over TCP port 1720) still used by legacy PBXs, gatekeepers and video gateways.',
    run: function (ctx) {
      if (!ctx.h323.length) return r('off', this.fallback);
      var badLeg = firstOf(ctx.h323Legs, function (l) { return l.state === 'failed'; });
      var badMsg = firstOf(ctx.h323, function (m) { return NETWORK_FAULT_CAUSES[num(m.causeCode)]; });
      if (badLeg || badMsg) {
        var code = badMsg ? num(badMsg.causeCode) : num(badLeg && badLeg.failCode);
        return r('issue',
          'H.323 signalling is present but a call segment released abnormally with Q.931 cause ' + code + ' (' +
          causeText(code, badMsg && badMsg.causeText) + ') — the Q.931 cause value is H.323\'s equivalent of a SIP failure status and tells you which side rejected the call.',
          ids(badMsg ? [badMsg] : []).concat(arr(badLeg && badLeg.msgIds).slice(0, 4)),
          callIdsForLegs(ctx, [badLeg && badLeg.id]));
      }
      return r('on',
        'H.323 call signalling is present (' + ctx.h323.length + ' Q.931 messages in ' + ctx.h323Legs.length +
        ' call segment' + (ctx.h323Legs.length === 1 ? '' : 's') + ') — the pre-SIP ITU protocol, decoded here at the Q.931/H.225 layer only.',
        ids(ctx.h323.slice(0, 6)));
    }
  },
  // -- iwf ------------------------------------------------------------------
  {
    key: 'iwf', label: 'SIP↔H.323 IWF',
    fallback: 'Only one signalling protocol is present, so no interworking function (the gateway role that translates SIP to H.323 and back) is involved here.',
    run: function (ctx) {
      if (!ctx.sip.length || !ctx.h323.length) return r('off', this.fallback);
      var iwf = allOf(ctx.calls, function (c) { return c.type === 'sip-h323'; });
      var paired = allOf(iwf, function (c) { return c.state === 'paired'; });
      if (paired.length) {
        var broken = firstOf(paired, function (c) {
          var states = arr(c.legIds).map(function (id) { var l = ctx.legById[id]; return l ? l.state : null; });
          var good = states.indexOf('answered') !== -1 || states.indexOf('completed') !== -1;
          var bad = states.indexOf('failed') !== -1 || states.indexOf('no-answer') !== -1;
          return good && bad;
        });
        if (broken) {
          return r('issue',
            'A SIP leg and an H.323 leg were matched into one call, but the two halves ended differently (one connected, the other failed) — that is an interworking fault: the gateway did not carry the outcome across the protocol boundary.',
            arr(broken.legIds).map(function (id) { var l = ctx.legById[id]; return l && arr(l.msgIds)[0]; }),
            [broken.id]);
        }
        return r('on',
          'Interworking is happening: ' + paired.length + ' call' + (paired.length === 1 ? '' : 's') +
          ' pair a SIP leg with an H.323 leg, so a gateway is translating between the two protocols mid-call.',
          [], ids(paired));
      }
      return r('partial',
        'Both SIP and H.323 are in this capture but no SIP leg could be matched to an H.323 leg with enough confidence — either the gateway is not in the capture path or the numbers and timings did not line up well enough to prove the link.',
        [], []);
    }
  },
  // -- sip-i ----------------------------------------------------------------
  {
    key: 'sip-i', label: 'SIP-I / ISUP',
    fallback: 'No encapsulated ISUP was found — SIP-I carries a full ISUP (SS7) message inside the SIP body so that TDM call detail survives across an IP transit network.',
    run: function (ctx) {
      var decoded = allOf(ctx.sip, function (m) { return isObj(m.isup) && m.isup.messageType; });
      var advertised = allOf(ctx.sip, function (m) {
        if (/application\/isup/.test(lc(hdr(m, 'content-type')))) return true;
        var parts = arr(m.bodyParts);
        for (var i = 0; i < parts.length; i++) if (isObj(parts[i]) && /isup/.test(lc(parts[i].contentType))) return true;
        return /application\/isup/.test(rawLc(ctx, m));
      });
      if (!decoded.length && !advertised.length) return r('off', this.fallback);
      if (!decoded.length) {
        return r('partial',
          'The SIP bodies advertise application/isup but no ISUP could be decoded from them — SIP-I means an SS7 ISUP message travels inside the SIP body, and here the wrapper is visible while its contents are not readable.',
          ids(advertised.slice(0, 6)));
      }
      var bad = firstOf(decoded, function (m) { return NETWORK_FAULT_CAUSES[num(m.isup.causeCode)]; });
      if (bad) {
        return r('issue',
          'ISUP is encapsulated in the SIP bodies and one message carries network-fault cause ' + num(bad.isup.causeCode) + ' (' +
          causeText(bad.isup.causeCode, bad.isup.causeText) + ') — on SIP-I the real release reason lives in this Q.850 cause, and the SIP status code you see is only a mapping of it.',
          ids([bad]));
      }
      var types = [];
      for (var i = 0; i < decoded.length && types.length < 5; i++) {
        var t = str(decoded[i].isup.messageType);
        if (t && types.indexOf(t) === -1) types.push(t);
      }
      return r('on',
        'SIP-I is in use: ' + decoded.length + ' message' + (decoded.length === 1 ? '' : 's') + ' carry encapsulated ISUP (' +
        types.join(', ') + ') — the SS7 call-control message rides inside the SIP body so TDM detail survives the IP hop.',
        ids(decoded.slice(0, 6)));
    }
  },
  // -- ims ------------------------------------------------------------------
  {
    key: 'ims', label: 'IMS',
    fallback: 'No IMS markers were found — IMS is the 3GPP-standardised SIP core operators run (TS 24.229), recognisable from its P-headers and registration route set.',
    run: function (ctx) {
      var ims = imsMarkers(ctx);
      if (!ims.markers.length) return r('off', this.fallback);

      // conformance check: a REGISTER that succeeded but got no Service-Route
      var regOk = allOf(ctx.responses, function (m) {
        var st = num(m.status);
        return st !== null && st >= 200 && st < 300 && isObj(m.cseq) && m.cseq.method === 'REGISTER';
      });
      var missingSr = allOf(regOk, function (m) { return !hasHdr(m, 'service-route'); });
      if (regOk.length && missingSr.length === regOk.length && (ims.hasPath || ims.hasAssociatedUri)) {
        return r('issue',
          'This is IMS signalling but the successful REGISTER carries no Service-Route header, which is exactly the header (RFC 3608) that tells the phone which route set to use afterwards — without it originating requests can bypass the S-CSCF and its services never fire.',
          ids(missingSr.slice(0, 4)));
      }
      if (ims.hasDesired && !ims.hasConfirmed) {
        return r('issue',
          'IMS signalling is present and the SDP asks for preconditions (a=des) that are never confirmed with a=conf — in IMS the call is meant to wait until the radio/bearer resources are actually reserved, so an unconfirmed precondition usually means the session stalls or answers with no media.',
          ims.msgIds);
      }
      var names = ims.markers.map(function (m) { return m.name; });
      var detail = 'IMS/3GPP signalling detected from ' + ims.markers.length + ' marker' + (ims.markers.length === 1 ? '' : 's') +
        ' (' + names.slice(0, 6).join(', ') + ')' + (ims.fiveG.length ? ' including 5G markers (' + ims.fiveG.join(', ') + ')' : '') +
        ' — IMS is the standardised operator SIP core, so these extra P-headers are specified behaviour you can check against 3GPP TS 24.229 rather than vendor quirks.';
      if (ims.markers.length >= 3) return r('on', detail, ims.msgIds);
      return r('partial',
        'A few IMS-style headers are present (' + names.join(', ') +
        ') but not the full 3GPP set, so this is probably one edge of an IMS network or a box that copies IMS headers rather than a real IMS core capture.',
        ims.msgIds);
    }
  },
  // -- rtp ------------------------------------------------------------------
  {
    key: 'rtp', label: 'RTP',
    fallback: 'No RTP media was found — RTP is the protocol that carries the actual audio packets, separately from the SIP signalling that negotiated them.',
    run: function (ctx) {
      var rtpish = allOf(ctx.streams, function (s) { return s.kind !== 't38-udptl'; });
      var sdpAudio = firstOf(ctx.sip, function (m) {
        var al = audioLine(ctx, m);
        return al && al.port > 0;
      });
      if (!rtpish.length) {
        if (sdpAudio) {
          return r('partial',
            'The SDP negotiates an audio stream but this capture contains no RTP packets at all (signalling only), so RTP is the audio path that was agreed here and nothing in this file can confirm or rule out a media fault.',
            ids([sdpAudio]));
        }
        return r('off', this.fallback);
      }
      var oneWay = allOf(rtpish, function (s) { return s.oneWay === true; });
      if (oneWay.length) {
        var s0 = oneWay[0];
        return r('issue',
          'RTP audio is flowing but ' + oneWay.length + ' stream' + (oneWay.length === 1 ? '' : 's') + ' only in one direction (' +
          str(s0.src) + ':' + str(s0.sport) + ' → ' + str(s0.dst) + ':' + str(s0.dport) +
          ' with no return stream) — this is the classic one-way-audio fault, where media is being sent to an address the far end cannot reach or a firewall/NAT is dropping the return path.',
          [], capIds(arr(s0.callIds), 4));
      }
      var lossy = allOf(rtpish, function (s) { return numOr(s.lossPct, 0) >= 5 && numOr(s.packets, 0) > 50; });
      if (lossy.length) {
        return r('issue',
          'RTP is flowing but ' + lossy.length + ' stream' + (lossy.length === 1 ? '' : 's') + ' lost ' + round2(lossy[0].lossPct) +
          '% of packets — RTP carries the audio itself, and loss at this level is audible as clipping or dropouts regardless of how clean the SIP signalling looks.',
          [], capIds(arr(lossy[0].callIds), 4));
      }
      var gappy = allOf(rtpish, function (s) { return numOr(s.maxGapMs, 0) >= 1000; });
      if (gappy.length) {
        return r('issue',
          'RTP is flowing but one stream has a ' + Math.round(numOr(gappy[0].maxGapMs, 0)) +
          ' ms gap with no packets at all — RTP should be a steady 20 ms drumbeat, so a gap that long means the media path died mid-call even though the signalling stayed up.',
          [], capIds(arr(gappy[0].callIds), 4));
      }
      var pkts = 0;
      for (var i = 0; i < rtpish.length; i++) pkts += numOr(rtpish[i].packets, 0);
      return r('on',
        rtpish.length + ' RTP stream' + (rtpish.length === 1 ? '' : 's') + ' carrying ' + pkts +
        ' packets are in this capture — RTP is the actual audio, and seeing it means the media path the SDP negotiated really came up.',
        [], capIds(arr(rtpish[0].callIds), 4));
    }
  },
  // -- rtcp -----------------------------------------------------------------
  {
    key: 'rtcp', label: 'RTCP',
    fallback: 'No RTCP was found — RTCP is the small control stream that rides alongside RTP and reports what each side actually received (loss, jitter, round-trip time).',
    run: function (ctx) {
      if (!ctx.rtcp.length) {
        if (ctx.streams.length) {
          return r('partial',
            'RTP is present but no RTCP reports were captured — RTCP is the companion stream that tells each side how the other is receiving, so without it you lose the far end\'s own view of loss and jitter (it is often on the odd port next to RTP and simply not captured or blocked).',
            []);
        }
        return r('off', this.fallback);
      }
      var worst = null;
      for (var i = 0; i < ctx.rtcp.length; i++) {
        var blocks = arr(ctx.rtcp[i].blocks);
        for (var j = 0; j < blocks.length; j++) {
          var b = isObj(blocks[j]) ? blocks[j] : {};
          var f = numOr(b.fractionLostPct, 0);
          if (!worst || f > worst.f) worst = { f: f, rtt: numOr(b.rttMs, null), report: ctx.rtcp[i] };
        }
      }
      if (worst && worst.f >= 5) {
        return r('issue',
          'RTCP receiver reports admit ' + round2(worst.f) + '% packet loss' + (worst.rtt !== null ? ' at ' + Math.round(worst.rtt) + ' ms round trip' : '') +
          ' — this is the far end grading the media it received, so it is much stronger evidence of a network problem than counting packets at the capture point.',
          []);
      }
      if (worst && worst.rtt !== null && worst.rtt >= 300) {
        return r('issue',
          'RTCP reports a round-trip time of ' + Math.round(worst.rtt) +
          ' ms — RTCP is how each side reports what it is receiving, and a round trip this long is heard as talk-over and awkward pauses even when no packets are lost.',
          []);
      }
      return r('on',
        ctx.rtcp.length + ' RTCP report' + (ctx.rtcp.length === 1 ? '' : 's') +
        ' are present and healthy — RTCP is the control stream beside RTP where each side publishes the loss, jitter and round trip it actually measured.',
        []);
    }
  },
  // -- srtp -----------------------------------------------------------------
  {
    key: 'srtp', label: 'SRTP',
    fallback: 'No SRTP was offered — SRTP is encrypted RTP (profiles RTP/SAVP or RTP/SAVPF, keyed by a=crypto or DTLS), used when the audio itself must be private on the wire.',
    run: function (ctx) {
      var pairs = offerAnswerPairs(ctx);
      var offeredLegs = [], issue = null, savpAnswered = 0, noAnswer = 0;
      for (var i = 0; i < pairs.length; i++) {
        var p = pairs[i];
        if (!p.offer) continue;
        var lines = mediaLines(ctx, p.offer);
        var offerSavp = !!firstOf(lines, function (l) { return /savp/.test(l.proto); }) || sdpHas(ctx, p.offer, /a=crypto:/);
        if (!offerSavp) continue;
        offeredLegs.push(p);
        if (!p.answer) { noAnswer++; continue; }
        var aLines = mediaLines(ctx, p.answer);
        var answerSavp = !!firstOf(aLines, function (l) { return /savp/.test(l.proto); }) || sdpHas(ctx, p.answer, /a=crypto:/);
        var answerAvp = !!firstOf(aLines, function (l) { return /^rtp\/avpf?$/.test(l.proto); });
        if (!answerSavp && answerAvp && !issue) issue = p;
        if (answerSavp) savpAnswered++;
      }
      var srtpStreams = allOf(ctx.streams, function (s) { return s.kind === 'srtp'; });
      if (!offeredLegs.length && !srtpStreams.length) return r('off', this.fallback);
      if (issue) {
        return r('issue',
          'One leg offered encrypted media (RTP/SAVP with a=crypto) and the answer came back as plain RTP/AVP — the offer and answer must agree on the profile, so this call either falls back to unencrypted audio or fails outright with one side sending SRTP the other cannot decode.',
          ids([issue.offer, issue.answer]), callIdsForLegs(ctx, [issue.leg && issue.leg.id]));
      }
      if (noAnswer && !savpAnswered) {
        return r('partial',
          'Encrypted media (SRTP) was offered but no SDP answer in this capture accepts or refuses it — SRTP has to be agreed in the offer/answer exchange, so until the answer arrives you cannot tell whether the audio ended up encrypted.',
          ids(offeredLegs.map(function (p) { return p.offer; })));
      }
      if (offeredLegs.length && offeredLegs.length < pairs.length && savpAnswered) {
        return r('partial',
          'SRTP is negotiated on some legs and plain RTP on others — that is normal at an SBC, which terminates the encryption on the access side and re-originates cleartext RTP towards the trunk, but it does mean the media is only private on part of its path.',
          ids(offeredLegs.map(function (p) { return p.offer; })));
      }
      return r('on',
        'SRTP is negotiated (' + (savpAnswered || offeredLegs.length) + ' leg' + ((savpAnswered || offeredLegs.length) === 1 ? '' : 's') +
        ' using an RTP/SAVP profile' + (srtpStreams.length ? ' with ' + srtpStreams.length + ' encrypted stream(s) seen on the wire' : '') +
        ') — the audio payload is encrypted, so hiccup reports its headers and timing only and never attempts decryption.',
        ids(offeredLegs.map(function (p) { return p.offer; })));
    }
  },
  // -- dtls-srtp ------------------------------------------------------------
  {
    key: 'dtls-srtp', label: 'DTLS-SRTP',
    fallback: 'No DTLS-SRTP was seen — DTLS-SRTP derives the media encryption keys from a TLS handshake run directly between the two media endpoints, the way WebRTC always does it.',
    run: function (ctx) {
      var dtls = arr(ctx.auxByProto['dtls']);
      var signalled = allOf(ctx.sip, function (m) {
        return sdpHas(ctx, m, /a=fingerprint:/) || !!firstOf(mediaLines(ctx, m), function (l) { return /udp\/tls\/rtp\/savp/.test(l.proto); });
      });
      if (!dtls.length && !signalled.length) return r('off', this.fallback);
      if (dtls.length) {
        var stalled = allOf(dtls, function (x) {
          if (isObj(x.detail) && x.detail.stalledAfter) return true;
          return /stall|incomplete|no handshake|timeout/.test(lc(x.summary));
        });
        if (stalled.length) {
          var afterVal = isObj(stalled[0].detail) ? stalled[0].detail.stalledAfter : null;
          return r('issue',
            'A DTLS handshake started on the media path but never completed' + (afterVal ? ' (it stalled after ' + str(afterVal) + ')' :
              '') + ' — DTLS-SRTP is how the two endpoints agree the media keys directly, so an unfinished handshake means no keys, and the call answers with silence however healthy the SIP looks.',
            [], capIds(arr(stalled[0].callIds), 4));
        }
        return r('on',
          'A DTLS-SRTP handshake completed on the media path (' + dtls.length + ' DTLS records seen) — the two media endpoints exchanged certificates directly to derive their SRTP keys, which is the WebRTC way of keying encrypted audio.',
          [], capIds(arr(dtls[0].callIds), 4));
      }
      return r('partial',
        'The SDP offers DTLS-SRTP (a=fingerprint with a UDP/TLS/RTP/SAVP profile) but no DTLS handshake packets are in this capture — the signalling agrees to key the media with a direct TLS handshake, and this file cannot show whether that handshake succeeded.',
        ids(signalled.slice(0, 4)));
    }
  },
  // -- t38 ------------------------------------------------------------------
  {
    key: 't38', label: 'T.38 fax',
    fallback: 'No T.38 fax was seen — T.38 is the fax-over-IP protocol a call switches to (with a re-INVITE to m=image/udptl) when it detects a fax tone instead of speech.',
    run: function (ctx) {
      var t38Reqs = allOf(ctx.sip, function (m) {
        if (m.isRequest !== true) return false;
        return !!firstOf(mediaLines(ctx, m), function (l) { return l.type === 'image' || /udptl/.test(l.proto) || /t38/.test(l.fmt); }) ||
          sdpHas(ctx, m, /m=image|udptl|t38/);
      });
      var t38Streams = allOf(ctx.streams, function (s) { return s.kind === 't38-udptl'; });
      var asym = arr(ctx.diffTags['t38-asymmetry']);
      if (!t38Reqs.length && !t38Streams.length && !asym.length) return r('off', this.fallback);

      // a rejected fax switch-over is the classic T.38 fault
      for (var i = 0; i < t38Reqs.length; i++) {
        var req = t38Reqs[i];
        var legList = null;
        for (var k = 0; k < ctx.sipLegs.length; k++) {
          if (arr(ctx.legMsgs[ctx.sipLegs[k].id]).indexOf(req) !== -1) { legList = ctx.legMsgs[ctx.sipLegs[k].id]; break; }
        }
        var finals = finalsFor(ctx, req, legList);
        var bad = firstOf(finals, function (m) { return numOr(m.status, 0) >= 400; });
        if (bad) {
          return r('issue',
            'The re-INVITE that switches this call to T.38 fax was rejected with ' + num(bad.status) + ' ' + str(bad.reason) +
            ' — T.38 is the fax transport a call must move to mid-call, so a refused switch-over means the fax falls back to G.711 pass-through at best and simply fails at worst.',
            ids([req, bad]));
        }
        var declined = firstOf(finals, function (m) {
          return !!firstOf(mediaLines(ctx, m), function (l) { return l.type === 'image' && l.port === 0; });
        });
        if (declined) {
          return r('issue',
            'The far end answered the T.38 fax offer with m=image port 0, which is SDP for "I refuse this stream" — the call stays up as audio, but the fax negotiation is dead and the pages will not go through.',
            ids([req, declined]));
        }
      }
      if (asym.length) {
        return r('issue',
          'T.38 fax appears on only one leg of the call, or the two legs disagree about it (' + str(asym[0].label) +
          ') — a fax switch-over has to be relayed end to end, so an SBC that accepts T.38 on one side and not the other guarantees the fax fails.',
          [], capIds(callIdsOfItems(asym), 4));
      }
      if (t38Streams.length) {
        return r('on',
          'T.38 fax is running: ' + t38Streams.length + ' UDPTL stream' + (t38Streams.length === 1 ? '' : 's') +
          ' carry the fax images — T.38 replaces the audio stream mid-call so fax tones are sent as data rather than as sound that IP would distort.',
          ids(t38Reqs.slice(0, 4)));
      }
      return r('on',
        'A T.38 fax switch-over was negotiated and accepted — T.38 is the fax-over-IP mode a call re-INVITEs into (m=image with the udptl transport) so the pages travel as data instead of as audio.',
        ids(t38Reqs.slice(0, 4)));
    }
  },
  // -- dtmf-rfc4733 ---------------------------------------------------------
  {
    key: 'dtmf-rfc4733', label: 'DTMF (RFC 4733)',
    fallback: 'No RFC 4733 telephone-event was negotiated — that is the standard way keypad digits travel as named RTP events instead of as audible tones inside the audio.',
    run: function (ctx) {
      var offered = allOf(ctx.sip, function (m) { return telEventPt(ctx, m) !== null; });
      var mismatch = arr(ctx.diffTags['dtmf-pt-mismatch']);
      var missingLeg = arr(ctx.diffTags['dtmf-missing-one-leg']);
      if (!offered.length && !mismatch.length && !missingLeg.length) return r('off', this.fallback);
      if (mismatch.length) {
        return r('issue',
          'The two legs negotiated different payload types for telephone-event (' + str(mismatch[0].ingress) + ' vs ' + str(mismatch[0].egress) +
          ') — RFC 4733 DTMF rides on a dynamic payload type agreed per leg, so when the numbers differ the SBC must renumber every digit and IVRs commonly stop hearing them.',
          [], capIds(callIdsOfItems(mismatch), 4));
      }
      if (missingLeg.length) {
        return r('issue',
          'RFC 4733 telephone-event is offered on one leg of the call and not the other (' + str(missingLeg[0].ingress) + ' vs ' + str(missingLeg[0].egress) +
          ') — one side therefore expects keypad digits as named RTP events and the other as audible tones, which is why DTMF works in one direction only.',
          [], capIds(callIdsOfItems(missingLeg), 4));
      }
      // offer/answer disagreement inside a single leg
      var pairs = offerAnswerPairs(ctx);
      for (var i = 0; i < pairs.length; i++) {
        var p = pairs[i];
        if (!p.offer || !p.answer) continue;
        var op = telEventPt(ctx, p.offer), ap = telEventPt(ctx, p.answer);
        if (op !== null && ap !== null && op !== ap) {
          return r('issue',
            'Within one leg the offer asked for telephone-event on payload type ' + op + ' and the answer came back with ' + ap +
            ' — RFC 4733 digits are carried on the payload type each side agreed, so a mismatch inside a single offer/answer exchange means digits are sent with a number the receiver does not recognise.',
            ids([p.offer, p.answer]));
        }
        if (op !== null && ap === null) {
          return r('partial',
            'Telephone-event was offered (payload type ' + op + ') but the answer does not include it, so the far end will not take DTMF as RFC 4733 events — digits must then survive as inband tones through any transcoding, which is where they usually get mangled.',
            ids([p.offer, p.answer]));
        }
      }
      var dtmfEvents = 0;
      for (i = 0; i < ctx.streams.length; i++) dtmfEvents += arr(ctx.streams[i].dtmfEvents).length;
      return r('on',
        'RFC 4733 telephone-event is negotiated on ' + offered.length + ' message' + (offered.length === 1 ? '' : 's') +
        (dtmfEvents ? ' and ' + dtmfEvents + ' digit event(s) were actually seen in the RTP' : '') +
        ' — this is the modern way keypad digits travel, as named events in the RTP stream rather than as tones mixed into the audio.',
        ids(offered.slice(0, 4)));
    }
  },
  // -- 100rel ---------------------------------------------------------------
  {
    key: '100rel', label: '100rel / PRACK',
    fallback: 'Nothing here uses 100rel — that RFC 3262 extension makes provisional responses like 183 reliable by having them acknowledged with a PRACK, which plain SIP never does.',
    run: function (ctx) {
      var supported = allOf(ctx.sip, function (m) { return hasToken(m, 'supported', '100rel'); });
      var required = allOf(ctx.sip, function (m) { return hasToken(m, 'require', '100rel') || hasToken(m, 'proxy-require', '100rel'); });
      var pracks = allOf(ctx.requests, function (m) { return m.method === 'PRACK'; });
      var rseq = allOf(ctx.responses, function (m) { return hasHdr(m, 'rseq'); });
      var asym = arr(ctx.diffTags['100rel-asymmetry']);
      if (!supported.length && !required.length && !pracks.length && !rseq.length && !asym.length) return r('off', this.fallback);

      var rejected = firstOf(ctx.responses, function (m) {
        return numOr(m.status, 0) === 420 && tokens(m, 'unsupported').indexOf('100rel') !== -1;
      });
      if (rejected) {
        return r('issue',
          'One side required 100rel and the other rejected the request with 420 Bad Extension listing 100rel as unsupported — reliable provisional responses have to be supported by both ends, so this call cannot use reliable 18x (or the precondition flows that depend on it) at all.',
          ids([rejected]));
      }
      var warnAsym = firstOf(asym, function (it) { return it.severity === 'warn' || it.severity === 'crit'; });
      if (warnAsym) {
        return r('issue',
          'The two legs disagree about 100rel (' + str(warnAsym.ingress) + ' vs ' + str(warnAsym.egress) +
          ') — one side demands that provisional responses be acknowledged with PRACK while the other never offers it, so reliable ringing and precondition signalling break across the SBC.',
          [], capIds(callIdsOfItems(asym), 4));
      }
      // required, a 18x arrived, but it was not made reliable and no PRACK exists
      if (required.length && !pracks.length && !rseq.length) {
        var prov = firstOf(ctx.responses, function (m) {
          var st = num(m.status);
          return st !== null && st > 100 && st < 200;
        });
        if (prov) {
          return r('issue',
            'A request required 100rel but the provisional responses came back with no RSeq and no PRACK ever followed — the far end accepted a call that demanded reliable provisional responses and then did not provide them, so early media and precondition state are unacknowledged and can be lost.',
            ids([required[0], prov]));
        }
      }
      if (pracks.length || rseq.length) {
        return r('on',
          '100rel is in use: ' + rseq.length + ' provisional response(s) carried an RSeq and ' + pracks.length +
          ' PRACK request(s) acknowledged them — that is RFC 3262 making a 18x reliable, so early media and precondition state cannot be silently lost.',
          ids(pracks.slice(0, 3).concat(rseq.slice(0, 3))));
      }
      return r('partial',
        '100rel is advertised in Supported/Require but no PRACK or RSeq appears in the capture — the extension for making provisional responses reliable was offered and never actually exercised, which is normal on a call that was answered or rejected immediately.',
        ids(supported.slice(0, 2).concat(required.slice(0, 2))));
    }
  },
  // -- session-timers -------------------------------------------------------
  {
    key: 'session-timers', label: 'Session timers',
    fallback: 'No session timers were negotiated — RFC 4028 Session-Expires makes each side re-INVITE periodically so that a call whose signalling path died does not stay up forever.',
    run: function (ctx) {
      var se = allOf(ctx.sip, function (m) { return hasHdr(m, 'session-expires'); });
      var minse = allOf(ctx.sip, function (m) { return hasHdr(m, 'min-se'); });
      var supported = allOf(ctx.sip, function (m) { return hasToken(m, 'supported', 'timer'); });
      var conflict = arr(ctx.diffTags['session-timer-conflict']);
      if (!se.length && !minse.length && !supported.length && !conflict.length) return r('off', this.fallback);

      var i422 = firstOf(ctx.responses, function (m) { return numOr(m.status, 0) === 422; });
      if (i422) {
        return r('issue',
          'A 422 Session Interval Too Small was returned, so the refresh interval offered was below the far end\'s Min-SE — session timers exist to keep both sides refreshing a live call, and until the interval is renegotiated upward the INVITE keeps being rejected.',
          ids([i422]));
      }
      if (conflict.length) {
        return r('issue',
          'The two legs carry incompatible session timers (' + str(conflict[0].ingress) + ' vs ' + str(conflict[0].egress) +
          ') — one leg\'s minimum acceptable refresh interval is longer than the other leg\'s Session-Expires, so expect 422s or calls torn down at refresh time.',
          [], capIds(callIdsOfItems(conflict), 4));
      }
      var internal = firstOf(ctx.sip, function (m) {
        var s = parseInt(digits(str(hdr(m, 'session-expires')).split(';')[0]), 10);
        var mn = parseInt(digits(str(hdr(m, 'min-se'))), 10);
        return isFinite(s) && isFinite(mn) && mn > s;
      });
      if (internal) {
        return r('issue',
          'One message asks for a Session-Expires shorter than its own Min-SE (' + str(hdr(internal, 'session-expires')) + ' with Min-SE ' + str(hdr(internal, 'min-se')) +
          ') — that is self-contradictory: the refresh interval cannot be below the minimum the same party says it will accept, and the far end is entitled to reject it with 422.',
          ids([internal]));
      }
      if (se.length) {
        var val = str(hdr(se[0], 'session-expires'));
        return r('on',
          'Session timers are negotiated (' + val + ') — RFC 4028 makes one side re-INVITE at that interval to prove the call is still alive, which is what stops "ghost" calls hanging when signalling is lost.',
          ids(se.slice(0, 4)));
      }
      return r('partial',
        'Session timers are advertised in Supported: timer but no Session-Expires interval was actually agreed — the mechanism that periodically re-INVITEs to prove a call is still alive is available here but not in effect, so a stuck call could stay up indefinitely.',
        ids(supported.slice(0, 4)));
    }
  },
  // -- update-method --------------------------------------------------------
  {
    key: 'update-method', label: 'UPDATE method',
    fallback: 'No UPDATE was used — UPDATE (RFC 3311) is the request that changes a session, typically its media, before the call has been answered, which a re-INVITE cannot do.',
    run: function (ctx) {
      var updates = allOf(ctx.requests, function (m) { return m.method === 'UPDATE'; });
      var allowed = allOf(ctx.sip, function (m) {
        return tokens(m, 'allow').indexOf('update') !== -1 || hasToken(m, 'supported', 'update');
      });
      var ims = imsMarkers(ctx);
      if (!updates.length && !allowed.length) return r('off', this.fallback);
      if (updates.length) {
        var bad = null;
        for (var i = 0; i < updates.length && !bad; i++) {
          var finals = finalsFor(ctx, updates[i], null);
          bad = firstOf(finals, function (m) {
            var st = numOr(m.status, 0);
            return st === 405 || st === 501 || st === 488 || st === 420;
          });
          if (bad) {
            return r('issue',
              'An UPDATE was sent and refused with ' + num(bad.status) + ' ' + str(bad.reason) +
              ' — UPDATE is how a session is modified before it is answered (media direction, preconditions, hold), so a far end that rejects it forces the change to wait for a re-INVITE after answer or not happen at all.',
              ids([updates[i], bad]));
          }
        }
        return r('on',
          updates.length + ' UPDATE request' + (updates.length === 1 ? '' : 's') +
          ' were sent — UPDATE modifies a session that is set up but not yet answered, which is how early media, hold and precondition changes are made without disturbing the INVITE transaction.',
          ids(updates.slice(0, 4)));
      }
      if (ims.hasDesired) {
        return r('partial',
          'UPDATE is advertised in Allow but never used even though the SDP requests preconditions — preconditions are normally confirmed with an UPDATE (or a PRACK offer/answer), so its absence is why the resource reservation here is never reported as met.',
          ids(allowed.slice(0, 4)));
      }
      return r('partial',
        'UPDATE appears in Allow/Supported but no UPDATE request was sent — the capability to modify a session before it is answered is advertised and simply was not needed on these calls.',
        ids(allowed.slice(0, 4)));
    }
  },
  // -- precondition ---------------------------------------------------------
  {
    key: 'precondition', label: 'Preconditions',
    fallback: 'No preconditions were used — RFC 3312 preconditions (a=curr/a=des/a=conf in SDP) hold a call from ringing until the network confirms the media resources are actually reserved.',
    run: function (ctx) {
      var ims = imsMarkers(ctx);
      var desired = allOf(ctx.sip, function (m) { return sdpHas(ctx, m, /a=des:/); });
      var confirmed = allOf(ctx.sip, function (m) { return sdpHas(ctx, m, /a=conf:/); });
      var current = allOf(ctx.sip, function (m) { return sdpHas(ctx, m, /a=curr:/); });
      var advertised = allOf(ctx.sip, function (m) {
        return hasToken(m, 'supported', 'precondition') || hasToken(m, 'require', 'precondition');
      });
      if (!desired.length && !confirmed.length && !current.length && !advertised.length) return r('off', this.fallback);

      var failed = firstOf(ctx.responses, function (m) {
        var st = numOr(m.status, 0);
        return st === 580 || (st === 420 && tokens(m, 'unsupported').indexOf('precondition') !== -1);
      });
      if (failed) {
        return r('issue',
          'A precondition negotiation failed with ' + num(failed.status) + ' ' + str(failed.reason) +
          ' — preconditions ask the network to confirm that media resources are reserved before the phone rings, and this response says the far end could not or would not meet them, so the call is refused rather than answered with no media.',
          ids([failed]));
      }
      if (desired.length && !confirmed.length) {
        return r('issue',
          'The SDP requests preconditions (a=des) but nothing ever confirms them with a=conf — preconditions are meant to hold the call until the bearer is genuinely reserved, so an unconfirmed request means either the reservation never completed or the far end ignored the mechanism, and the usual symptom is ringing with no audio.',
          ids(desired.slice(0, 4).concat(ims.msgIds.slice(0, 2))));
      }
      if (desired.length && confirmed.length) {
        return r('on',
          'Preconditions are negotiated and confirmed (a=des requested, a=conf returned in ' + confirmed.length + ' message' + (confirmed.length === 1 ? '' : 's') +
          ') — the call deliberately waited for the network to reserve media resources before alerting, which is standard behaviour on IMS/VoLTE.',
          ids(desired.slice(0, 2).concat(ids(confirmed.slice(0, 2)))));
      }
      return r('partial',
        'Preconditions are advertised or partially described (' + (current.length ? 'a=curr status lines present' : 'option tag only') +
        ') without a full des/conf exchange — the mechanism that makes a call wait for reserved media resources is on the table here but never completed.',
        ids(advertised.slice(0, 2).concat(ids(current.slice(0, 2)))));
    }
  },
  // -- dns ------------------------------------------------------------------
  {
    key: 'dns', label: 'DNS',
    fallback: 'No DNS traffic was captured — SIP uses DNS NAPTR/SRV/A lookups (RFC 3263) to turn a domain in a Request-URI or Route into the address and transport it actually sends to.',
    run: function (ctx) {
      var dns = arr(ctx.auxByProto['dns']);
      if (!dns.length) {
        var inferred = firstOf(ctx.collapses, function (c) { return isObj(c.classification) && c.classification.code === 'dns-blocking'; });
        if (inferred) {
          return r('partial',
            'No DNS packets are in this capture, but the retransmission pattern on egress looks like a name lookup blocking the outbound request — SIP resolves its next hop with NAPTR/SRV/A queries before it can send, so include port 53 in the capture to turn that inference into proof.',
            capIds(arr(inferred.msgIds), 4));
        }
        return r('off', this.fallback);
      }
      var timeouts = allOf(dns, function (x) {
        return (isObj(x.detail) && x.detail.timedOut === true) || /no answer|timed? ?out/.test(lc(x.summary));
      });
      if (timeouts.length) {
        return r('issue',
          timeouts.length + ' DNS quer' + (timeouts.length === 1 ? 'y was' : 'ies were') + ' never answered (' + str(timeouts[0].summary) +
          ') — SIP cannot send a request until the NAPTR/SRV/A lookup for its next hop returns, so an unanswered query stalls the INVITE and looks exactly like a far end that is slow or absent.',
          [], capIds(arr(timeouts[0].callIds), 4));
      }
      var slow = allOf(dns, function (x) {
        return (isObj(x.detail) && (x.detail.slow === true || numOr(x.detail.latencyMs, 0) > 1000));
      });
      if (slow.length) {
        return r('issue',
          slow.length + ' DNS quer' + (slow.length === 1 ? 'y took' : 'ies took') + ' over a second to answer — SIP resolves its next hop before it can send, so slow resolution pushes the first INVITE past the 500 ms retransmission timer and produces retransmissions that look like a network fault but are really a resolver problem.',
          [], capIds(arr(slow[0].callIds), 4));
      }
      var bad = auxMatch(dns, /nxdomain|servfail|refused/);
      if (bad.length) {
        return r('issue',
          'A DNS lookup returned an error response (' + str(bad[0].summary) +
          ') — the name in the Request-URI or Route could not be resolved, so the SIP request had nowhere to go regardless of how the trunk is configured.',
          [], capIds(arr(bad[0].callIds), 4));
      }
      return r('on',
        dns.length + ' DNS quer' + (dns.length === 1 ? 'y' : 'ies') + ' resolved normally alongside the signalling — these are the NAPTR/SRV/A lookups (RFC 3263) SIP uses to turn a domain name into the address, port and transport it sends to.',
        []);
    }
  },
  // -- diameter -------------------------------------------------------------
  {
    key: 'diameter', label: 'Diameter',
    fallback: 'No Diameter was captured — Diameter is the AAA/policy protocol IMS cores use beside SIP (Rx to authorise a media bearer, Cx/Sh for subscriber data).',
    run: function (ctx) {
      var dia = arr(ctx.auxByProto['diameter']);
      if (!dia.length) return r('off', this.fallback);
      var failed = allOf(dia, function (x) {
        var hit = detailFind(x.detail, /^(?:resultcode|experimentalresultcode)$/, function (v) {
          var n = num(v) !== null ? num(v) : parseInt(digits(v), 10);
          return isFinite(n) && n >= 3000;
        });
        if (hit) return true;
        return /diameter_(?:unable|authorization_rejected|error|too_busy|resources|invalid)/.test(lc(x.summary));
      });
      if (failed.length) {
        return r('issue',
          'A Diameter answer carries a failure Result-Code (' + str(failed[0].summary) +
          ') — Diameter is where the IMS core authorises the media bearer and the subscriber\'s policy, so a rejected request there usually explains a SIP call that fails or answers with no media even though the SIP itself looks correct.',
          [], capIds(arr(failed[0].callIds), 4));
      }
      var unanswered = allOf(dia, function (x) {
        if (isObj(x.detail) && (x.detail.unanswered === true || x.detail.timedOut === true)) return true;
        return /no answer|unanswered/.test(lc(x.summary));
      });
      if (unanswered.length) {
        return r('issue',
          'A Diameter request was never answered (' + str(unanswered[0].summary) +
          ') — the SIP session is waiting on a policy or authorisation decision that never came back, which typically shows up as an INVITE that hangs in early state.',
          [], capIds(arr(unanswered[0].callIds), 4));
      }
      var correlated = firstOf(dia, function (x) { return arr(x.legIds).length || arr(x.callIds).length; });
      if (!correlated) {
        return r('partial',
          dia.length + ' Diameter message(s) are present but none could be tied to a SIP call — correlation relies on matching the Rx AF-Charging-Identifier or Session-Id against the SIP P-Charging-Vector icid, so without that thread the policy exchange can only be read on its own.',
          []);
      }
      return r('on',
        dia.length + ' Diameter message(s) run alongside the SIP, and at least one is tied to a call in this capture — that is the IMS core authorising the media bearer and subscriber policy in parallel with the SIP session.',
        [], capIds(arr(correlated.callIds), 4));
    }
  },
  // -- stun-ice -------------------------------------------------------------
  {
    key: 'stun-ice', label: 'STUN / ICE',
    fallback: 'No STUN or ICE was seen — ICE probes every candidate address pair with STUN before sending media, which is how endpoints behind NAT find a path that actually works.',
    run: function (ctx) {
      var stun = arr(ctx.auxByProto['stun']).concat(arr(ctx.auxByProto['ice']));
      var signalled = allOf(ctx.sip, function (m) { return sdpHas(ctx, m, /a=ice-ufrag|a=candidate/); });
      if (!stun.length && !signalled.length) return r('off', this.fallback);
      if (stun.length) {
        var succeeded = false, failedPairs = 0;
        for (var i = 0; i < stun.length; i++) {
          var cl = isObj(stun[i].detail) ? arr(stun[i].detail.checkList) : [];
          for (var j = 0; j < cl.length; j++) {
            var e = isObj(cl[j]) ? cl[j] : {};
            // only trust an explicit boolean or a status *value* — the key name
            // 'succeeded' appears in the serialized entry even when it is false
            var blob = '';
            try { blob = lc(JSON.stringify(e)); } catch (e2) { blob = ''; }
            var okVal = /:\s*"(?:succeeded|success|ok|completed)"/.test(blob);
            var badVal = /:\s*"(?:failed|no-response|noresponse|timeout|timed-out|frozen)"/.test(blob);
            if (e.succeeded === true || okVal) succeeded = true;
            if (e.succeeded === false || badVal) failedPairs++;
          }
        }
        var errs = auxMatch(stun, /error-code|role conflict|unauthorized/);
        if (!succeeded && (failedPairs || errs.length)) {
          return r('issue',
            'ICE connectivity checks are present but none succeeded (' + failedPairs + ' pair(s) failed or went unanswered' +
            (errs.length ? ', with STUN error responses' : '') + ') — ICE has to find one working candidate pair before media can flow, so a check list with no winner means the call connects in SIP and carries no audio at all.',
            [], capIds(arr(stun[0].callIds), 4));
        }
        return r('on',
          stun.length + ' STUN/ICE message(s) were exchanged' + (succeeded ? ' and at least one candidate pair succeeded' : '') +
          ' — ICE probes each possible address pair with STUN before sending media, which is how endpoints behind NAT agree a path that really works.',
          [], capIds(arr(stun[0].callIds), 4));
      }
      return r('partial',
        'The SDP carries ICE attributes (a=ice-ufrag/a=candidate) but no STUN packets are in this capture — the endpoints agreed to probe candidate address pairs before sending media, and this file cannot show whether any pair actually won.',
        ids(signalled.slice(0, 4)));
    }
  },
  // -- tcp-transport --------------------------------------------------------
  {
    key: 'tcp-transport', label: 'TCP transport',
    fallback: 'No SIP over TCP was seen — everything here is datagram-based, which means SIP itself has to handle retransmission rather than leaning on a connection.',
    run: function (ctx) {
      var tcpMsgs = allOf(ctx.messages, function (m) { return m.transport === 'tcp'; });
      var udpMsgs = allOf(ctx.messages, function (m) { return m.transport === 'udp'; });
      if (!tcpMsgs.length) return r('off', this.fallback);
      var tcpLegIds = Object.create(null);
      for (var i = 0; i < ctx.legs.length; i++) if (ctx.legs[i].transport === 'tcp') tcpLegIds[ctx.legs[i].id] = 1;
      var badCollapse = firstOf(ctx.collapses, function (c) { return tcpLegIds[c.legId]; });
      if (badCollapse) {
        return r('issue',
          'A SIP message was retransmitted on a TCP leg (' + str(badCollapse.label) +
          ') — over a reliable transport SIP is not supposed to retransmit at all, because TCP already guarantees delivery, so identical copies here mean the connection was broken or the far-end stack is re-sending on a dead socket.',
          capIds(arr(badCollapse.msgIds), 4));
      }
      if (udpMsgs.length) {
        return r('partial',
          'Transport is mixed: ' + tcpMsgs.length + ' message(s) on TCP and ' + udpMsgs.length +
          ' on UDP — that is usual at a border element, where one side runs a persistent TCP connection (no fragmentation limit, retransmission handled by TCP) and the other stays on classic UDP.',
          ids(tcpMsgs.slice(0, 4)));
      }
      return r('on',
        'All signalling here runs over TCP (' + tcpMsgs.length + ' messages) — a connection-oriented transport, so large messages do not fragment and TCP rather than SIP handles retransmission.',
        ids(tcpMsgs.slice(0, 4)));
    }
  },
  // -- tls-transport --------------------------------------------------------
  {
    key: 'tls-transport', label: 'TLS transport',
    fallback: 'No TLS signalling was indicated — SIP over TLS (sips: URIs, Via SIP/2.0/TLS, port 5061) encrypts the signalling itself so headers and numbers cannot be read on the wire.',
    run: function (ctx) {
      var tlsMsgs = allOf(ctx.messages, function (m) {
        if (numOr(m.sport, 0) === 5061 || numOr(m.dport, 0) === 5061) return true;
        var vias = arr(m.vias);
        for (var i = 0; i < vias.length; i++) if (/sip\/2\.0\/tls/i.test(str(vias[i]))) return true;
        if (/^sips:/i.test(str(m.requestUri))) return true;
        if (/;transport=tls/i.test(str(hdr(m, 'contact')) + ' ' + str(m.requestUri))) return true;
        return false;
      });
      if (!tlsMsgs.length) return r('off', this.fallback);
      var tlsLegs = Object.create(null);
      for (var i = 0; i < ctx.legs.length; i++) {
        var list = arr(ctx.legMsgs[ctx.legs[i].id]);
        for (var j = 0; j < list.length; j++) if (tlsMsgs.indexOf(list[j]) !== -1) { tlsLegs[ctx.legs[i].id] = 1; break; }
      }
      var tlsLegCount = Object.keys(tlsLegs).length;
      if (tlsLegCount && tlsLegCount < ctx.legs.length) {
        return r('partial',
          'TLS signalling appears on ' + tlsLegCount + ' of ' + ctx.legs.length +
          ' legs — the encrypted hop stops at the border element, which decrypts and re-originates the other leg in the clear, so only part of this call\'s signalling was private on the wire.',
          ids(tlsMsgs.slice(0, 4)));
      }
      return r('on',
        'The signalling is marked as TLS (sips:/SIP-2.0-TLS/port 5061 on ' + tlsMsgs.length +
        ' messages) yet readable here, which means this capture was taken inside the box after decryption — TLS protects SIP headers and dialled numbers in transit, and a wire capture would have shown only ciphertext.',
        ids(tlsMsgs.slice(0, 4)));
    }
  },
  // -- ipv6 -----------------------------------------------------------------
  {
    key: 'ipv6', label: 'IPv6',
    fallback: 'No IPv6 was seen — all addressing here is IPv4, so none of the dual-stack pitfalls (mismatched families between signalling and media) apply.',
    run: function (ctx) {
      var v6 = allOf(ctx.messages, function (m) { return isV6Addr(m.src) || isV6Addr(m.dst); });
      var v4 = allOf(ctx.messages, function (m) {
        return (!isV6Addr(m.src) && str(m.src)) || (!isV6Addr(m.dst) && str(m.dst));
      });
      if (!v6.length) return r('off', this.fallback);
      // family mismatch between signalling and the SDP connection address
      var mismatch = firstOf(v6, function (m) {
        var conn = isObj(m.sdp) ? str(m.sdp.connection) : '';
        if (!conn) return false;
        return !isV6Addr(conn) && /\d+\.\d+\.\d+\.\d+/.test(conn);
      });
      if (mismatch) {
        var legOfMsg = firstOf(ctx.legs, function (l) { return arr(l.msgIds).indexOf(mismatch.id) !== -1; });
        var noMedia = !ctx.streams.length;
        var legFailed = !!(legOfMsg && (legOfMsg.state === 'failed' || legOfMsg.state === 'no-answer'));
        if (noMedia || legFailed) {
          return r('issue',
            'The signalling travels over IPv6 while the SDP offers an IPv4 media address (' + str(mismatch.sdp.connection) +
            ') and no media came up — IPv4 and IPv6 endpoints cannot exchange RTP directly, so a mixed-family offer needs a relay or the audio simply has nowhere to go.',
            ids([mismatch]), callIdsForLegs(ctx, [legOfMsg && legOfMsg.id]));
        }
      }
      if (v4.length) {
        return r('partial',
          'This is a dual-stack capture: ' + v6.length + ' message(s) on IPv6 and ' + v4.length +
          ' on IPv4 — worth watching, because signalling and media each pick a family independently and a call that crosses families needs something in the middle to bridge the two.',
          ids(v6.slice(0, 4)));
      }
      return r('on',
        'All signalling here is IPv6 (' + v6.length + ' messages) — addresses appear in SDP and Via in colon notation, and any peer that is IPv4-only will need a translator in the path.',
        ids(v6.slice(0, 4)));
    }
  },
  // -- registration ---------------------------------------------------------
  {
    key: 'registration', label: 'Registration',
    fallback: 'No REGISTER traffic was captured — registration is how an endpoint tells the network where it can be reached, and a static IP trunk does not use it at all.',
    run: function (ctx) {
      var regs = allOf(ctx.requests, function (m) { return m.method === 'REGISTER'; });
      var regResp = allOf(ctx.responses, function (m) { return isObj(m.cseq) && m.cseq.method === 'REGISTER'; });
      if (!regs.length && !regResp.length) return r('off', this.fallback);
      var ok = allOf(regResp, function (m) { var s = num(m.status); return s !== null && s >= 200 && s < 300; });
      var challenged = allOf(regResp, function (m) { var s = numOr(m.status, 0); return s === 401 || s === 407; });
      var denied = allOf(regResp, function (m) { var s = numOr(m.status, 0); return s === 403 || s === 404 || s === 503 || s === 500; });
      if (!ok.length && (challenged.length || denied.length)) {
        var worst = denied.length ? denied[0] : challenged[0];
        return r('issue',
          'Registration was attempted ' + regs.length + ' time(s) and never succeeded — every REGISTER came back ' + num(worst.status) + ' ' + str(worst.reason) +
          ', so the endpoint has no valid binding and no inbound call can be delivered to it (check the credentials, realm and the digest username against what the registrar expects).',
          ids(regs.slice(0, 3).concat(ids([worst]))));
      }
      var nonces = Object.create(null);
      var loop = firstOf(challenged, function (m) {
        var n = /nonce\s*=\s*"([^"]+)"/i.exec(str(hdr(m, 'www-authenticate')) + ' ' + str(hdr(m, 'proxy-authenticate')));
        if (!n) return false;
        if (nonces[n[1]]) return true;
        nonces[n[1]] = 1;
        return false;
      });
      if (loop && !ok.length) {
        return r('issue',
          'The registrar challenged the same REGISTER twice with the same nonce — a digest loop like this means the credentials are being rejected rather than retried, and the endpoint will keep re-registering without ever getting a binding.',
          ids([loop]));
      }
      if (regs.length && !regResp.length) {
        return r('partial',
          regs.length + ' REGISTER request(s) were captured with no response at all — registration is the exchange that tells the network where to reach this endpoint, and without an answer you cannot tell whether the registrar ever heard it.',
          ids(regs.slice(0, 4)));
      }
      if (ok.length) {
        var aors = Object.create(null), n = 0;
        for (var i = 0; i < regs.length; i++) {
          var aor = str(regs[i].toUri || regs[i].fromUri);
          if (aor && !aors[aor]) { aors[aor] = 1; n++; }
        }
        return r('on',
          'Registration succeeded (' + ok.length + ' 200 OK to REGISTER for ' + (n || 1) + ' identit' + ((n || 1) === 1 ? 'y' : 'ies') +
          (challenged.length ? ', after the usual 401 digest challenge' : '') +
          ') — this is the binding that tells the network which address to send this subscriber\'s inbound calls to.',
          ids(regs.slice(0, 2).concat(ids(ok.slice(0, 2)))));
      }
      return r('partial',
        'REGISTER traffic is present but no successful registration is visible in this capture window — the exchange that gives an endpoint its reachable binding is under way and unresolved here.',
        ids(regs.slice(0, 4)));
    }
  },
  // -- topology-hiding ------------------------------------------------------
  {
    key: 'topology-hiding', label: 'Topology hiding',
    fallback: 'No back-to-back rewriting was seen — topology hiding is what a B2BUA does when it replaces your internal addresses and headers so the far end never learns your network layout.',
    run: function (ctx) {
      var leak = arr(ctx.diffTags['private-ip-leak']);
      var multi = allOf(ctx.calls, function (c) {
        var sipLegCount = 0;
        var lids = arr(c.legIds);
        for (var i = 0; i < lids.length; i++) {
          var l = ctx.legById[lids[i]];
          if (l && l.protocol !== 'h323') sipLegCount++;
        }
        return sipLegCount >= 2;
      });
      if (leak.length) {
        return r('issue',
          'A private address survived from the ingress leg into the egress message (' + str(leak[0].label) +
          ') — topology hiding is meant to replace every internal address on the way out, so a leak like this both exposes your internal layout and leaves the far end with an address it can never route to.',
          [], capIds(callIdsOfItems(leak), 4));
      }
      if (!multi.length) return r('off', this.fallback);
      var rewritten = arr(ctx.diffTags['header-rewritten']).length + arr(ctx.diffTags['header-stripped']).length +
        arr(ctx.diffTags['from-rewritten']).length + arr(ctx.diffTags['to-rewritten']).length;
      if (!rewritten) {
        return r('partial',
          multi.length + ' call(s) pass through a back-to-back agent but its two legs carry the same headers unchanged — the box is relaying rather than hiding, so the far end still sees whatever your inside network put in the headers.',
          [], capIds(ids(multi), 4));
      }
      return r('on',
        multi.length + ' call(s) run as two legs through a back-to-back user agent, with ' + rewritten +
        ' header difference(s) between them — that rewriting is topology hiding: the far end is shown the border element\'s identity instead of your internal one.',
        [], capIds(ids(multi), 4));
    }
  },
  // -- transcoding ----------------------------------------------------------
  {
    key: 'transcoding', label: 'Transcoding',
    fallback: 'No transcoding evidence was found — transcoding is when a media box re-encodes audio because the two legs of a call agreed on different codecs.',
    run: function (ctx) {
      var trans = arr(ctx.diffTags['codec-transcoding']);
      var narrowed = arr(ctx.diffTags['codec-narrowed']);
      var i488 = firstOf(ctx.responses, function (m) {
        var s = numOr(m.status, 0);
        return s === 488 || s === 606 || s === 415;
      });
      if (i488) {
        return r('issue',
          'A media negotiation was rejected with ' + num(i488.status) + ' ' + str(i488.reason) +
          ' — the two sides found no codec in common, which is exactly the gap transcoding exists to bridge, so either enable it on the border element or align the codec lists.',
          ids([i488]));
      }
      if (trans.length) {
        return r('on',
          'Transcoding is in force: the two legs answered different codecs (' + str(trans[0].ingress) + ' vs ' + str(trans[0].egress) +
          '), so the border element must re-encode every packet — it costs DSP capacity and adds delay, and it is why codec policy is worth checking before blaming the network.',
          [], capIds(callIdsOfItems(trans), 4));
      }
      if (narrowed.length) {
        return r('partial',
          'A codec policy trimmed the offer between legs (' + str(narrowed[0].ingress) + ' → ' + str(narrowed[0].egress) +
          ') but both sides still answered the same codec, so no re-encoding is needed — the box is filtering choices rather than transcoding audio.',
          [], capIds(callIdsOfItems(narrowed), 4));
      }
      return r('off', this.fallback);
    }
  },
  // -- early-media ----------------------------------------------------------
  {
    key: 'early-media', label: 'Early media',
    fallback: 'No early media was seen — early media is audio (ringback, announcements, network tones) that flows before the call is answered, carried on a 183 Session Progress with SDP.',
    run: function (ctx) {
      var e183 = allOf(ctx.responses, function (m) { return numOr(m.status, 0) === 183; });
      var e183Sdp = allOf(e183, function (m) { return !!sdpLc(ctx, m); });
      var pem = allOf(ctx.sip, function (m) { return hasHdr(m, 'p-early-media'); });
      var asym = arr(ctx.diffTags['early-media-183']);
      if (!e183.length && !pem.length && !asym.length) return r('off', this.fallback);
      if (asym.length) {
        return r('issue',
          'The two legs handle early media differently (' + str(asym[0].ingress) + ' vs ' + str(asym[0].egress) +
          ') — one side opens an early audio path before answer while the other only signals ringing, which is why callers report silence, doubled ringback or announcements that get cut off.',
          [], capIds(callIdsOfItems(asym), 4));
      }
      if (e183Sdp.length && ctx.streams.length) {
        var answerTs = null;
        for (var i = 0; i < ctx.legs.length; i++) {
          var t = num(ctx.legs[i].answerTs);
          if (t !== null && (answerTs === null || t < answerTs)) answerTs = t;
        }
        var early = firstOf(ctx.streams, function (s) {
          var f = num(s.firstTs);
          return f !== null && answerTs !== null && f < answerTs;
        });
        if (!early && answerTs !== null) {
          return r('issue',
            'A 183 Session Progress with SDP promised early media but no RTP arrived before the call was answered — early media is the audio a caller hears before answer, so an empty early path is heard as dead silence where ringback or an announcement should be.',
            ids(e183Sdp.slice(0, 2)));
        }
      }
      if (e183Sdp.length) {
        return r('on',
          e183Sdp.length + ' 183 Session Progress response(s) carry SDP' + (pem.length ? ' alongside P-Early-Media' : '') +
          ' — that opens an audio path before the call is answered, which is how network ringback, announcements and "the number you dialled" messages reach the caller.',
          ids(e183Sdp.slice(0, 4)));
      }
      return r('partial',
        (pem.length ? 'P-Early-Media is present' : '183 Session Progress is present') +
        ' but no early SDP offer/answer completes it, so the pre-answer audio path is only half set up — the caller most likely hears locally generated ringback rather than anything from the far end.',
        ids(pem.slice(0, 2).concat(ids(e183.slice(0, 2)))));
    }
  },
  // -- refer-transfer -------------------------------------------------------
  {
    key: 'refer-transfer', label: 'REFER transfer',
    fallback: 'No transfers were seen — REFER (RFC 3515) is the request one party sends to ask the other to call someone else, which is how blind and attended transfers work.',
    run: function (ctx) {
      var refers = allOf(ctx.requests, function (m) { return m.method === 'REFER'; });
      var notifies = allOf(ctx.requests, function (m) { return m.method === 'NOTIFY'; });
      var advertised = allOf(ctx.sip, function (m) {
        return tokens(m, 'allow').indexOf('refer') !== -1 || hasToken(m, 'supported', 'replaces');
      });
      if (!refers.length) {
        if (advertised.length) {
          return r('partial',
            'REFER/Replaces is advertised in Allow/Supported but no transfer was attempted in this capture — the mechanism for asking the other party to call a third number is available and simply unused here.',
            ids(advertised.slice(0, 4)));
        }
        return r('off', this.fallback);
      }
      var bad = null;
      for (var i = 0; i < refers.length && !bad; i++) {
        var finals = finalsFor(ctx, refers[i], null);
        bad = firstOf(finals, function (m) { return numOr(m.status, 0) >= 400; });
        if (bad) {
          var badLeg = firstOf(ctx.legs, function (l) { return arr(l.msgIds).indexOf(refers[i].id) !== -1; });
          return r('issue',
            'A REFER transfer was rejected with ' + num(bad.status) + ' ' + str(bad.reason) +
            ' — REFER asks the far end to place a new call to the transfer target, so a refusal means the transfer never happens and the caller stays parked on the original leg.',
            ids([refers[i], bad]), callIdsForLegs(ctx, [badLeg && badLeg.id]));
        }
      }
      var failNotify = firstOf(notifies, function (m) {
        if (!/message\/sipfrag/.test(lc(str(m.bodyType)))) return false;
        var mt = /sip\/2\.0\s+([4-6]\d\d)/i.exec(rawLc(ctx, m));
        return !!mt;
      });
      if (failNotify) {
        var failLeg = firstOf(ctx.legs, function (l) { return arr(l.msgIds).indexOf(failNotify.id) !== -1; });
        return r('issue',
          'The NOTIFY reporting the transfer\'s progress carries a failure status in its sipfrag body — REFER progress is reported back as NOTIFY messages containing the new call\'s status line, so this says the transferred-to call itself failed even though the REFER was accepted.',
          ids([failNotify]), callIdsForLegs(ctx, [failLeg && failLeg.id]));
      }
      var relatedNotify = firstOf(notifies, function (m) { return /refer/.test(lc(str(hdr(m, 'event')))); });
      if (!relatedNotify) {
        var hangLeg = firstOf(ctx.legs, function (l) { return arr(l.msgIds).indexOf(refers[0].id) !== -1; });
        return r('issue',
          'A REFER was sent and accepted but no NOTIFY ever reported what happened next — the referring party is left with no idea whether the transfer completed, which is why transfers appear to hang in this state.',
          ids(refers.slice(0, 3)), callIdsForLegs(ctx, [hangLeg && hangLeg.id]));
      }
      return r('on',
        refers.length + ' REFER transfer(s) with NOTIFY progress reports — REFER asks the other party to place a call to the transfer target, and the NOTIFY messages carry that new call\'s status back to whoever started the transfer.',
        ids(refers.slice(0, 2).concat(ids([relatedNotify]))));
    }
  },
  // -- history-info ---------------------------------------------------------
  {
    key: 'history-info', label: 'History-Info',
    fallback: 'No redirection history was carried — History-Info (RFC 7044) and the older Diversion header record each place a call was forwarded from, which is what voicemail and billing read to know who was originally dialled.',
    run: function (ctx) {
      var hi = allOf(ctx.sip, function (m) { return hasHdr(m, 'history-info') || hasHdr(m, 'diversion'); });
      var advertised = allOf(ctx.sip, function (m) { return hasToken(m, 'supported', 'histinfo'); });
      var stripped = allOf(ctx.diffItems, function (it) {
        return (it.tag === 'header-stripped' || it.tag === 'header-rewritten') && /history-info|diversion/.test(lc(it.label));
      });
      if (!hi.length && !advertised.length && !stripped.length) return r('off', this.fallback);
      if (stripped.length) {
        return r('issue',
          'The redirection history was ' + (stripped[0].tag === 'header-stripped' ? 'removed' : 'rewritten') +
          ' between the two legs (' + str(stripped[0].label) +
          ') — that header is the trail of who forwarded the call, so losing it breaks voicemail box selection, "originally dialled number" billing and any downstream routing that keys on it.',
          [], capIds(callIdsOfItems(stripped), 4));
      }
      var fat = firstOf(hi, function (m) {
        return m.isRequest === true && m.transport === 'udp' && numOr(m.size, 0) > 1300;
      });
      if (fat) {
        return r('issue',
          'A request carrying redirection history grew to ' + num(fat.size) +
          ' bytes on UDP — every forwarding hop appends another History-Info entry, and once the message passes about 1300 bytes it fragments at the IP layer, where firewalls routinely drop the pieces and the call silently fails.',
          ids([fat]));
      }
      if (!hi.length) {
        return r('partial',
          'The histinfo option tag is advertised but no History-Info header is actually present — the endpoints agree they can carry a redirection trail, and nothing in this capture was forwarded.',
          ids(advertised.slice(0, 4)));
      }
      return r('on',
        hi.length + ' message(s) carry redirection history (History-Info/Diversion) — each entry records a place the call was forwarded from, which is how the answering side knows which number was originally dialled.',
        ids(hi.slice(0, 4)));
    }
  }
];

/**
 * Derive the indicator "lamps" for a capture.
 *
 * Always returns the complete fixed key set, in the documented order, so the UI
 * lamp strip is stable across captures: `sip, h323, iwf, sip-i, ims, rtp, rtcp,
 * srtp, dtls-srtp, t38, dtmf-rfc4733, 100rel, session-timers, update-method,
 * precondition, dns, diameter, stun-ice, tcp-transport, tls-transport, ipv6,
 * registration, topology-hiding, transcoding, early-media, refer-transfer,
 * history-info`. `state` is 'on' (in use), 'off' (absent), 'partial' (present
 * but incomplete) or 'issue' (present and provably broken). `detail` is one
 * plain sentence written for a reader who may not know the feature.
 *
 * Never throws: a detector that fails degrades to its 'off' sentence.
 *
 * @param {object} analysis AnalysisJSON (messages/legs/calls/retrans plus
 *   media/aux/findings when those modules ran)
 * @returns {Array<{key: string, label: string, state: 'on'|'off'|'partial'|'issue',
 *   detail: string, evidenceMsgIds: string[], evidenceCallIds: string[]}>}
 */
function detectIndicators(analysis) {
  var ctx;
  try {
    ctx = buildContext(analysis);
  } catch (e) {
    ctx = buildContext(null);
  }
  var out = [];
  for (var i = 0; i < DETECTORS.length; i++) {
    var d = DETECTORS[i];
    var res = null;
    try {
      res = d.run(ctx);
    } catch (e) {
      res = null;
    }
    if (!isObj(res)) res = {};
    var state = STATES[res.state] ? res.state : 'off';
    var detail = str(res.detail).trim() || d.fallback;
    out.push({
      key: d.key,
      label: d.label,
      state: state,
      detail: detail,
      evidenceMsgIds: capIds(res.msgIds, 12),
      evidenceCallIds: capIds(res.callIds, 8)
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// scenario detection
// ---------------------------------------------------------------------------

var PBX_UA_RE = /(avaya|cisco|cucm|cube|ios-voice|mitel|3cx|asterisk|freepbx|freeswitch|kamailio|opensips|innovaphone|unify|openscape|panasonic|yeastar|grandstream|alcatel|ericsson-lg|epygi|patton|sangoma|snom|polycom|audiocodes|oracle|acmepacket|ribbon|sonus|metaswitch|broadworks|teams|skype for business|lync)/;
var TEST_UA_RE = /(sipp|pjsua|pjsip-perf|sipsak|sipvicious|friendly-scanner|sipcli|sip-tester|sipexer|voiperf|sipptest)/;
var FAX_UA_RE = /(fax|brooktrout|dialogic|xmedius|hylafax|t38modem|ferrari)/;
var WEBRTC_UA_RE = /(sip\.js|jssip|sipml5|webrtc|jitsi|linphone-web|chrome|firefox|safari)/;

/**
 * Facts the scenario tests read. Every field degrades to a safe default.
 * @param {object} ctx
 * @returns {object}
 */
function scenarioFacts(ctx) {
  var ims = imsMarkers(ctx);
  var f = {
    format: ctx.format,
    isPcap: ctx.format === 'pcap' || ctx.format === 'pcapng',
    messageCount: ctx.messages.length,
    callCount: 0,
    peakConcurrent: 0,
    medianSetupMs: null,
    abandonedPct: 0,
    registerCount: 0,
    registerAors: 0,
    registerAor: null,
    optionsCount: 0,
    referCount: 0,
    subscribeCount: 0,
    distinctCalled: 0,
    topCalled: null,
    topCalledShare: 0,
    calledPrefixes: 0,
    commonCalledPrefix: '',
    e164Called: 0,
    shortNumbers: 0,
    diversionCalls: 0,
    uaText: '',
    uaSample: '',
    imsMarkerCount: ims.markers.length,
    hasPath: ims.hasPath,
    hasServiceRoute: ims.hasServiceRoute,
    hasAssociatedUri: ims.hasAssociatedUri,
    hasIcid: ims.hasIcid,
    hasPrecondition: ims.hasPrecondition,
    paniText: ims.paniText,
    codecs: Object.create(null),
    hasIsup: false,
    hasT38: false,
    sdpOffers: 0,
    streamCount: ctx.streams.length,
    auxProtos: Object.create(null),
    addresses: [],
    docAddrs: 0,
    privateAddrs: 0,
    publicAddrs: 0,
    peerPairs: 0,
    maxViaChain: 0,
    minMaxForwards: null,
    sdpText: '',
    userParts: Object.create(null),
    distinctUserParts: 0
  };

  // ---- calls / concurrency ----
  var intervals = [];
  var callLegs = allOf(ctx.legs, function (l) { return l.kind === 'call' || l.protocol === 'h323'; });
  if (ctx.calls.length) {
    for (var i = 0; i < ctx.calls.length; i++) {
      var lids = arr(ctx.calls[i].legIds);
      var s = null, e = null;
      for (var j = 0; j < lids.length; j++) {
        var l = ctx.legById[lids[j]];
        if (!l) continue;
        var st = num(l.startTs), en = num(l.endTs);
        if (st !== null && (s === null || st < s)) s = st;
        if (en !== null && (e === null || en > e)) e = en;
      }
      if (s !== null) intervals.push({ s: s, e: e === null ? s : e });
    }
    f.callCount = ctx.calls.length;
  } else {
    for (i = 0; i < callLegs.length; i++) {
      var s2 = num(callLegs[i].startTs);
      if (s2 !== null) intervals.push({ s: s2, e: numOr(callLegs[i].endTs, s2) });
    }
    f.callCount = callLegs.length;
  }
  var events = [];
  for (i = 0; i < intervals.length; i++) {
    events.push({ t: intervals[i].s, d: 1 });
    events.push({ t: intervals[i].e + 0.000001, d: -1 });
  }
  events.sort(function (a, b) { return a.t - b.t || a.d - b.d; });
  var cur = 0;
  for (i = 0; i < events.length; i++) {
    cur += events[i].d;
    if (cur > f.peakConcurrent) f.peakConcurrent = cur;
  }

  // ---- setup times / abandon rate ----
  var setups = [], abandoned = 0;
  for (i = 0; i < callLegs.length; i++) {
    var leg = callLegs[i];
    var a = num(leg.answerTs), b = num(leg.startTs);
    if (a !== null && b !== null && a >= b) setups.push((a - b) * 1000);
    if (leg.state === 'canceled' || leg.state === 'no-answer') abandoned++;
  }
  if (setups.length) {
    setups.sort(function (x, y) { return x - y; });
    f.medianSetupMs = Math.round(setups[Math.floor(setups.length / 2)]);
  }
  if (callLegs.length) f.abandonedPct = Math.round((abandoned / callLegs.length) * 100);

  // ---- method counts ----
  for (i = 0; i < ctx.requests.length; i++) {
    var m = ctx.requests[i];
    if (m.method === 'REGISTER') f.registerCount++;
    else if (m.method === 'OPTIONS') f.optionsCount++;
    else if (m.method === 'REFER') f.referCount++;
    else if (m.method === 'SUBSCRIBE') f.subscribeCount++;
  }
  var aors = Object.create(null);
  for (i = 0; i < ctx.requests.length; i++) {
    if (ctx.requests[i].method !== 'REGISTER') continue;
    var aor = str(ctx.requests[i].toUri || ctx.requests[i].fromUri);
    if (aor && !aors[aor]) { aors[aor] = 1; f.registerAors++; if (!f.registerAor) f.registerAor = aor; }
  }

  // ---- called-number profile (one per call, ingress leg) ----
  var calledCounts = Object.create(null);
  var calledList = [];
  var perCallLegs = [];
  if (ctx.calls.length) {
    for (i = 0; i < ctx.calls.length; i++) {
      var first = null;
      var ids2 = arr(ctx.calls[i].legIds);
      for (j = 0; j < ids2.length && !first; j++) first = ctx.legById[ids2[j]] || null;
      if (first) perCallLegs.push(first);
    }
  } else {
    perCallLegs = callLegs;
  }
  for (i = 0; i < perCallLegs.length; i++) {
    var d = digits(perCallLegs[i].toUser || uriUser(perCallLegs[i].to) || perCallLegs[i].to);
    if (!d) continue;
    calledList.push(d);
    calledCounts[d] = (calledCounts[d] || 0) + 1;
  }
  var uniq = Object.keys(calledCounts);
  f.distinctCalled = uniq.length;
  var prefixes = Object.create(null);
  for (i = 0; i < uniq.length; i++) {
    if (uniq[i].length >= 4) prefixes[uniq[i].slice(0, 4)] = 1;
    if (/^\+?[1-9]\d{7,14}$/.test(uniq[i])) f.e164Called++;
    if (uniq[i].length <= 5) f.shortNumbers++;
  }
  f.calledPrefixes = Object.keys(prefixes).length;
  var best = 0;
  for (i = 0; i < uniq.length; i++) {
    if (calledCounts[uniq[i]] > best) { best = calledCounts[uniq[i]]; f.topCalled = uniq[i]; }
  }
  if (calledList.length) f.topCalledShare = best / calledList.length;
  if (uniq.length) {
    var pref = uniq[0];
    for (i = 1; i < uniq.length; i++) {
      var other = uniq[i];
      var k = 0;
      while (k < pref.length && k < other.length && pref[k] === other[k]) k++;
      pref = pref.slice(0, k);
      if (!pref) break;
    }
    f.commonCalledPrefix = pref;
  }

  // ---- headers of interest ----
  var uaSeen = Object.create(null);
  for (i = 0; i < ctx.sip.length; i++) {
    m = ctx.sip[i];
    var uaVals = hdrs(m, 'user-agent').concat(hdrs(m, 'server'));
    for (j = 0; j < uaVals.length; j++) {
      var v = uaVals[j].trim();
      if (!v || uaSeen[v]) continue;
      uaSeen[v] = 1;
      f.uaText += ' ' + v.toLowerCase();
      if (!f.uaSample) f.uaSample = v;
    }
    if (hasHdr(m, 'diversion') || hasHdr(m, 'history-info')) f.diversionCalls++;
    var vias = arr(m.vias).length ? arr(m.vias) : hdrs(m, 'via');
    if (vias.length > f.maxViaChain) f.maxViaChain = vias.length;
    var mf = parseInt(digits(str(hdr(m, 'max-forwards'))), 10);
    if (isFinite(mf) && (f.minMaxForwards === null || mf < f.minMaxForwards)) f.minMaxForwards = mf;
    if (isObj(m.isup) || /application\/isup/.test(lc(hdr(m, 'content-type')))) f.hasIsup = true;
    var sd = sdpLc(ctx, m);
    if (sd) {
      f.sdpOffers++;
      if (f.sdpText.length < 20000) f.sdpText += ' ' + sd;
      var cs = codecsOf(ctx, m);
      for (j = 0; j < cs.length; j++) f.codecs[cs[j]] = 1;
      if (/m=image|udptl|t38/.test(sd)) f.hasT38 = true;
    }
    var fu = digits(m.fromUri && uriUser(m.fromUri));
    if (fu) f.userParts[fu] = 1;
  }
  f.distinctUserParts = Object.keys(f.userParts).length;
  for (i = 0; i < ctx.streams.length; i++) {
    if (ctx.streams[i].kind === 't38-udptl') f.hasT38 = true;
  }

  // ---- aux protocols ----
  var protos = Object.keys(ctx.auxByProto);
  for (i = 0; i < protos.length; i++) f.auxProtos[protos[i]] = arr(ctx.auxByProto[protos[i]]).length;

  // ---- addressing ----
  var addrSeen = Object.create(null);
  for (i = 0; i < ctx.messages.length; i++) {
    var pair = [ctx.messages[i].src, ctx.messages[i].dst];
    for (j = 0; j < 2; j++) {
      var ad = str(pair[j]);
      if (!ad || addrSeen[ad]) continue;
      addrSeen[ad] = 1;
      f.addresses.push(ad);
      if (isDocAddr(ad)) f.docAddrs++;
      else if (isPrivateAddr(ad)) f.privateAddrs++;
      else if (/^\d+\.\d+\.\d+\.\d+$/.test(ad) || isV6Addr(ad)) f.publicAddrs++;
    }
  }
  var pairSeen = Object.create(null);
  for (i = 0; i < callLegs.length; i++) {
    var a1 = str(callLegs[i].src), b1 = str(callLegs[i].dst);
    if (!a1 && !b1) continue;
    var key = a1 < b1 ? a1 + '|' + b1 : b1 + '|' + a1;
    if (!pairSeen[key]) { pairSeen[key] = 1; f.peerPairs++; }
  }

  return f;
}

/** Does the fact set contain any of these codecs? */
function hasCodec(f, names) {
  for (var i = 0; i < names.length; i++) if (f.codecs[names[i]]) return true;
  return false;
}

var SCENARIOS = [
  {
    key: 'call-centre',
    tests: [
      {
        name: 'concurrent-volume', weight: 0.25, run: function (f) {
          if (f.peakConcurrent >= 5) return f.callCount + ' calls with up to ' + f.peakConcurrent + ' running concurrently';
          if (f.callCount >= 20) return f.callCount + ' calls in one capture window';
          return null;
        }
      },
      {
        name: 'short-setups', weight: 0.15, run: function (f) {
          if (f.callCount >= 5 && f.medianSetupMs !== null && f.medianSetupMs < 4000) {
            return 'median answer time ' + f.medianSetupMs + ' ms across ' + f.callCount + ' calls';
          }
          return null;
        }
      },
      {
        name: 'abandoned-calls', weight: 0.15, run: function (f) {
          if (f.callCount >= 5 && f.abandonedPct >= 25) {
            return f.abandonedPct + '% of calls cancelled or never answered, the signature of outbound/predictive dialling';
          }
          return null;
        }
      },
      {
        name: 'one-did-hotspot', weight: 0.15, run: function (f) {
          if (f.callCount >= 4 && f.topCalledShare >= 0.3 && f.topCalled) {
            return Math.round(f.topCalledShare * 100) + '% of calls target the single number ' + f.topCalled + ', typical of a queue DID';
          }
          return null;
        }
      },
      {
        name: 'queue-hops', weight: 0.15, run: function (f) {
          if (f.diversionCalls >= 2) return 'Diversion/History-Info on ' + f.diversionCalls + ' messages, the trail left by queue and hunt-group hops';
          return null;
        }
      },
      {
        name: 'refer-heavy', weight: 0.15, run: function (f) {
          if (f.referCount >= 2) return f.referCount + ' REFER transfers';
          return null;
        }
      }
    ],
    describe: function (f) {
      return 'This looks like a contact-centre or dialer platform: ' + f.callCount + ' calls, peaking at ' + f.peakConcurrent +
        ' at once' + (f.abandonedPct ? ', with ' + f.abandonedPct + '% abandoned before answer' : '') +
        '. Read the retransmission and storm views before the per-call diffs, because on this kind of trunk a fault is far more often box-wide (licence exhaustion, CPU, an unreachable session agent) than specific to one call. Treat correlation confidence carefully too: repeated From/To numbers on a busy dialer trunk make ingress-to-egress pairing genuinely ambiguous, which is why hiccup refuses to guess.';
    }
  },
  {
    key: 'enterprise-trunk',
    tests: [
      {
        name: 'single-trunk-pair', weight: 0.25, run: function (f) {
          if (f.peerPairs >= 1 && f.peerPairs <= 3 && f.callCount <= 50) {
            return 'all call signalling runs between ' + f.peerPairs + ' host pair(s) — a fixed trunk rather than a population of subscribers';
          }
          return null;
        }
      },
      {
        name: 'pbx-user-agent', weight: 0.25, run: function (f) {
          var m = PBX_UA_RE.exec(f.uaText);
          if (m) return 'a PBX/gateway User-Agent is present (' + (f.uaSample || m[1]) + ')';
          return null;
        }
      },
      {
        name: 'e164-ddi-block', weight: 0.15, run: function (f) {
          if (f.e164Called >= 1 && f.commonCalledPrefix.length >= 5) {
            return f.distinctCalled + ' called number(s) sharing the prefix ' + f.commonCalledPrefix + ' — a DDI block on one trunk';
          }
          return null;
        }
      },
      {
        name: 'no-registration', weight: 0.10, run: function (f) {
          if (f.registerCount === 0 && f.callCount >= 1) return 'no REGISTER traffic at all — a static-IP trunk, not registered endpoints';
          return null;
        }
      },
      {
        name: 'options-keepalive', weight: 0.15, run: function (f) {
          if (f.optionsCount >= 2) return f.optionsCount + ' OPTIONS pings, the keepalive each side uses to prove the trunk peer is alive';
          return null;
        }
      },
      {
        name: 'no-ims-markers', weight: 0.10, run: function (f) {
          if (f.imsMarkerCount === 0) return 'none of the 3GPP IMS P-headers are present, so this is plain SIP interop rather than an operator core';
          return null;
        }
      }
    ],
    describe: function (f) {
      return 'This looks like an enterprise SIP trunk: ' + (f.peerPairs ? f.peerPairs + ' signalling host pair(s)' : 'a fixed signalling pair') +
        (f.uaSample ? ' with ' + f.uaSample + ' in the User-Agent' : '') + ', ' + f.callCount + ' call(s)' +
        (f.optionsCount ? ' and ' + f.optionsCount + ' OPTIONS keepalives' : '') +
        '. Expect the useful material in the two-leg diff: header manipulation, codec policy, DTMF payload types and session timers are where PBX-to-carrier trunks actually break. There are no IMS markers, so read the analysis as vendor interop rather than 3GPP conformance.';
    }
  },
  {
    key: 'residential-ims',
    tests: [
      {
        name: 'register-route-set', weight: 0.30, run: function (f) {
          if (f.hasPath && f.hasServiceRoute) return 'REGISTER carries both Path and Service-Route, the IMS registration route set';
          if (f.hasPath) return 'REGISTER carries a Path header inserted by a P-CSCF';
          if (f.hasServiceRoute) return 'the REGISTER 200 OK returns a Service-Route';
          return null;
        }
      },
      {
        name: 'single-subscriber', weight: 0.20, run: function (f) {
          if (f.registerAors === 1) return 'exactly one registering identity (' + str(f.registerAor) + ')';
          return null;
        }
      },
      {
        name: 'fixed-access', weight: 0.20, run: function (f) {
          var m = /(adsl|vdsl|xdsl|ftth|fttb|gpon|docsis|ethernet|ieee-802\.11|wlan)/.exec(f.paniText);
          if (m) return 'P-Access-Network-Info reports fixed/broadband access (' + m[1] + ')';
          return null;
        }
      },
      {
        name: 'p-associated-uri', weight: 0.15, run: function (f) {
          if (f.hasAssociatedUri) return 'P-Associated-URI lists the identities bound to this subscriber';
          return null;
        }
      },
      {
        name: 'single-line', weight: 0.15, run: function (f) {
          if (f.callCount <= 2 && f.peakConcurrent <= 1) return 'never more than one call at a time — a single line, not a trunk';
          return null;
        }
      }
    ],
    describe: function (f) {
      return 'This looks like a residential/fixed-line IMS subscriber trace: the registration carries the IMS route-set headers' +
        (f.registerAor ? ' for ' + str(f.registerAor) : '') + (f.paniText.trim() ? ' and the access network reports ' + f.paniText.trim().split(/[;,]/)[0] : '') +
        '. Read the REGISTER exchange and the P-header chain first — here the analysis can be checked against 3GPP TS 24.229 rather than against vendor habit. Remember that a single capture point sees the same INVITE more than once as the iFC chain fires, so near-identical INVITEs may be S-CSCF loops rather than retransmissions.';
    }
  },
  {
    key: 'volte-5g',
    tests: [
      {
        name: 'ims-core', weight: 0.20, run: function (f) {
          if (f.imsMarkerCount >= 3) return f.imsMarkerCount + ' IMS/3GPP markers present';
          return null;
        }
      },
      {
        name: 'preconditions', weight: 0.20, run: function (f) {
          if (f.hasPrecondition) return 'SDP preconditions (a=curr/a=des/a=conf) gate the call on bearer reservation';
          return null;
        }
      },
      {
        name: '3gpp-access', weight: 0.25, run: function (f) {
          var m = /(3gpp-nr|3gpp-e-utran|3gpp-utran[^;]*|5gs|3gpp-5g)/.exec(f.paniText);
          if (m) return 'P-Access-Network-Info reports mobile access (' + m[1] + ')';
          return null;
        }
      },
      {
        name: 'mobile-codecs', weight: 0.20, run: function (f) {
          if (hasCodec(f, ['amr', 'amr-wb', 'evs', 'evs-wb'])) return 'AMR/AMR-WB/EVS codecs, the mobile voice codec family';
          return null;
        }
      },
      {
        name: 'rx-diameter', weight: 0.15, run: function (f) {
          if (f.auxProtos['diameter']) return f.auxProtos['diameter'] + ' Diameter message(s) alongside the SIP (Rx policy/bearer authorisation)';
          return null;
        }
      }
    ],
    describe: function (f) {
      return 'This looks like a mobile VoLTE/VoNR capture: IMS markers plus ' +
        (f.hasPrecondition ? 'SDP preconditions' : 'mobile access information') +
        (hasCodec(f, ['amr', 'amr-wb', 'evs']) ? ' and mobile codecs' : '') +
        '. Read the precondition exchange (a=curr/a=des/a=conf across 183, PRACK and UPDATE) before anything else: on VoLTE a call that never confirms its preconditions never gets a dedicated bearer, so what looks like a media fault is really a bearer fault. If Diameter is present, the Rx AAR/AAA beside the INVITE tells you whether the policy layer authorised that bearer at all.';
    }
  },
  {
    key: 'carrier-interconnect',
    tests: [
      {
        name: 'sip-i-isup', weight: 0.30, run: function (f) {
          if (f.hasIsup) return 'SIP bodies carry encapsulated ISUP (SIP-I), the hallmark of a TDM-era interconnect';
          return null;
        }
      },
      {
        name: 'no-registration', weight: 0.15, run: function (f) {
          if (f.registerCount === 0 && f.callCount >= 2) return 'no registration at all across ' + f.callCount + ' calls — a peered trunk, not subscribers';
          return null;
        }
      },
      {
        name: 'number-breadth', weight: 0.20, run: function (f) {
          if (f.distinctCalled >= 5 && f.calledPrefixes >= 3) {
            return f.distinctCalled + ' distinct called numbers across ' + f.calledPrefixes + ' number ranges';
          }
          return null;
        }
      },
      {
        name: 'transit-via-chain', weight: 0.20, run: function (f) {
          if (f.maxViaChain >= 3) return 'requests arrive with ' + f.maxViaChain + ' Via headers — several proxies already in the path';
          if (f.minMaxForwards !== null && f.minMaxForwards <= 64) return 'Max-Forwards down to ' + f.minMaxForwards + ', so the request has crossed many hops';
          return null;
        }
      },
      {
        name: 'public-addressing', weight: 0.15, run: function (f) {
          if (f.publicAddrs >= 2 && f.privateAddrs === 0) return 'every signalling address is public — network-to-network rather than inside an enterprise';
          return null;
        }
      }
    ],
    describe: function (f) {
      return 'This looks like a carrier interconnect or transit trunk: ' +
        (f.hasIsup ? 'ISUP is encapsulated in the SIP bodies (SIP-I)' : 'no registration, wide number ranges and long Via chains') +
        ' across ' + f.callCount + ' call(s). Read the ISUP cause values next to the SIP status codes — on SIP-I the real release reason lives in the encapsulated Q.850 cause and the SIP status is only its mapping. Number-range breadth also means leg correlation has to lean on icid and timing rather than on matching user parts, so watch the confidence column.';
    }
  },
  {
    key: 'webrtc-ott',
    tests: [
      {
        name: 'stun-ice', weight: 0.30, run: function (f) {
          var n = (f.auxProtos['stun'] || 0) + (f.auxProtos['ice'] || 0);
          if (n) return n + ' STUN/ICE message(s) probing candidate pairs';
          return null;
        }
      },
      {
        name: 'dtls-srtp', weight: 0.25, run: function (f) {
          if (f.auxProtos['dtls']) return f.auxProtos['dtls'] + ' DTLS record(s) keying the media';
          if (/a=fingerprint:/.test(f.sdpText)) return 'SDP carries a DTLS fingerprint (a=fingerprint)';
          return null;
        }
      },
      {
        name: 'opus-codec', weight: 0.20, run: function (f) {
          if (hasCodec(f, ['opus'])) return 'opus offered, the browser default codec';
          return null;
        }
      },
      {
        name: 'ice-candidates', weight: 0.15, run: function (f) {
          if (/a=ice-ufrag|a=candidate/.test(f.sdpText)) return 'SDP carries ICE attributes (a=ice-ufrag/a=candidate)';
          return null;
        }
      },
      {
        name: 'browser-stack', weight: 0.10, run: function (f) {
          var m = WEBRTC_UA_RE.exec(f.uaText);
          if (m) return 'a browser/WebRTC stack in the User-Agent (' + m[1] + ')';
          return null;
        }
      }
    ],
    describe: function () {
      return 'This looks like a WebRTC or OTT client capture: ICE candidate probing and DTLS-keyed media rather than a classic trunk. Read the ICE check list and the DTLS handshake before the SIP diff, because in WebRTC deployments the signalling usually completes cleanly and the media path is what fails. Expect the SDP to be large and browser-generated, so header-level differences between legs matter less than which candidate pair actually won.';
    }
  },
  {
    key: 'fax-service',
    tests: [
      {
        name: 't38-media', weight: 0.45, run: function (f) {
          if (f.hasT38) return 'T.38/UDPTL fax media is negotiated or carried';
          return null;
        }
      },
      {
        name: 'fax-attributes', weight: 0.25, run: function (f) {
          var m = /(t38faxversion|t38faxmaxdatagram|t38faxratemanagement|a=fax)/.exec(f.sdpText);
          if (m) return 'fax SDP attributes present (' + m[1] + ')';
          return null;
        }
      },
      {
        name: 'g711-passthrough', weight: 0.15, run: function (f) {
          var names = Object.keys(f.codecs);
          var onlyG711 = names.length > 0 && names.every(function (n) {
            return n === 'pcmu' || n === 'pcma' || n === 'telephone-event';
          });
          if (onlyG711 && (f.hasT38 || FAX_UA_RE.test(f.uaText))) return 'only G.711 offered, so fax also has to survive as pass-through audio';
          return null;
        }
      },
      {
        name: 'fax-endpoint', weight: 0.15, run: function (f) {
          var m = FAX_UA_RE.exec(f.uaText);
          if (m) return 'a fax gateway/ATA User-Agent (' + m[1] + ')';
          return null;
        }
      }
    ],
    describe: function () {
      return 'This looks like a fax service capture: the call negotiates T.38 (or carries fax as G.711 pass-through) rather than ordinary speech. Read the re-INVITE that switches audio to image/udptl and both legs\' answers to it, because fax fails far more often in that mid-call switch-over than in the original setup. Codec policy and DTMF settings matter much less here than whether both sides accepted the same fax transport.';
    }
  },
  {
    key: 'lab-test',
    tests: [
      {
        name: 'test-user-agent', weight: 0.35, run: function (f) {
          var m = TEST_UA_RE.exec(f.uaText);
          if (m) return 'a load/test tool User-Agent (' + m[1] + ')';
          return null;
        }
      },
      {
        name: 'documentation-addressing', weight: 0.30, run: function (f) {
          if (f.docAddrs >= 1 && f.publicAddrs === 0) {
            return f.docAddrs + ' address(es) come from the RFC 5737/3849 documentation ranges, which never appear in live traffic';
          }
          return null;
        }
      },
      {
        name: 'synthetic-numbers', weight: 0.20, run: function (f) {
          if (f.distinctCalled >= 2 && f.shortNumbers === f.distinctCalled) {
            return 'all called numbers are short synthetic extensions';
          }
          if (/(sipp|test|user|service)\d*/.test(f.uaText) && f.distinctUserParts <= 2) {
            return 'placeholder identities repeated across calls';
          }
          return null;
        }
      },
      {
        name: 'private-only-addressing', weight: 0.10, run: function (f) {
          if (f.privateAddrs >= 1 && f.publicAddrs === 0 && f.docAddrs === 0) {
            return 'only private (RFC 1918) addressing, so nothing here crossed the public internet';
          }
          return null;
        }
      },
      {
        name: 'no-media-captured', weight: 0.10, run: function (f) {
          if (f.isPcap && f.sdpOffers >= 1 && f.streamCount === 0) {
            return 'SDP negotiates media but the pcap contains no RTP at all';
          }
          return null;
        }
      }
    ],
    describe: function () {
      return 'This looks like a lab or synthetic capture rather than production traffic: documentation/private addressing and test-tool signatures dominate. Read the findings as an exercise of the analyser rather than as a customer fault, and expect topology findings by construction, since documentation and RFC 1918 addresses are exactly what the private-IP checks look for. If this was meant to be a production trace, check that you uploaded the right file.';
    }
  }
];

/**
 * Classify what kind of deployment a capture came from.
 *
 * Weighted, evidence-based scoring over the documented signal lists — no LLM,
 * no network. Each scenario's signals sum to roughly 1.0, so the raw score is
 * used directly as the confidence. When the best score is weak the primary is
 * honestly `'unknown'` rather than a forced label; when the runner-up is close
 * the confidence is reduced and a weight-0 `close-alternative` signal is added
 * so the UI can say so.
 *
 * @param {object} analysis AnalysisJSON (messages/legs/calls plus media/aux
 *   when those modules ran)
 * @returns {{primary: string, confidence: number,
 *   signals: Array<{name: string, detail: string, weight: number}>,
 *   detail: string, alternatives: Array<{primary: string, confidence: number}>}}
 */
function detectScenario(analysis) {
  var ctx, f;
  try {
    ctx = buildContext(analysis);
    f = scenarioFacts(ctx);
  } catch (e) {
    return {
      primary: 'unknown',
      confidence: 0,
      signals: [],
      detail: 'This capture could not be profiled (its analysis object was unreadable), so treat it as a generic SIP trace. Start with the findings list and the retransmission view, then look at each call\'s diff. Nothing about the deployment type is being assumed here.',
      alternatives: []
    };
  }

  var scored = [];
  for (var i = 0; i < SCENARIOS.length; i++) {
    var sc = SCENARIOS[i];
    var matched = [];
    var score = 0;
    for (var j = 0; j < sc.tests.length; j++) {
      var t = sc.tests[j];
      var detail = null;
      try { detail = t.run(f); } catch (e) { detail = null; }
      if (detail) {
        matched.push({ name: t.name, detail: str(detail), weight: t.weight });
        score += t.weight;
      }
    }
    scored.push({ key: sc.key, score: score, matched: matched, scenario: sc });
  }
  scored.sort(function (a, b) { return b.score - a.score; });

  var top = scored[0] || { key: 'unknown', score: 0, matched: [] };
  var second = scored[1] || { key: null, score: 0 };
  var alternatives = [];
  for (i = 1; i < scored.length && alternatives.length < 4; i++) {
    if (scored[i].score <= 0.05) continue;
    alternatives.push({ primary: scored[i].key, confidence: round2(Math.min(0.95, scored[i].score)) });
  }

  // Honest 'unknown' rather than a forced label.
  if (top.score < 0.35) {
    var bits = [];
    if (f.callCount) bits.push(f.callCount + ' call(s)');
    if (f.messageCount) bits.push(f.messageCount + ' signalling messages');
    if (!f.registerCount) bits.push('no registration');
    if (!f.streamCount) bits.push('no media packets');
    return {
      primary: 'unknown',
      confidence: round2(Math.min(0.3, top.score)),
      signals: top.matched.slice(0, 4),
      detail: 'There is not enough distinguishing evidence to say what kind of network this capture came from (' +
        (bits.length ? bits.join(', ') : 'very little signalling') + '), and guessing a label would be worse than admitting that. Read it as a generic SIP trace: start with the findings list and the retransmission view, then work through each call\'s diff. A longer capture, the REGISTER exchange, or the media packets would give hiccup enough to classify the deployment' +
        (alternatives.length ? ' — the closest reading so far is ' + alternatives[0].primary + '.' : '.'),
      alternatives: alternatives
    };
  }

  var confidence = Math.min(0.95, top.score);
  var signals = top.matched.slice();
  if (second.key && (top.score - second.score) < 0.1) {
    confidence = Math.max(0.3, confidence - 0.15);
    signals.push({
      name: 'close-alternative',
      detail: 'the evidence for ' + second.key + ' scores almost as high, so this label is a strong hint rather than a conclusion',
      weight: 0
    });
  }

  var text = '';
  try { text = str(top.scenario.describe(f)); } catch (e) { text = ''; }
  if (!text) {
    text = 'This capture profiles as ' + top.key + ' on the evidence listed in the signals. Read the findings list and the per-call diff with that in mind. Treat the label as a reading aid, not a fact about the network.';
  }

  return {
    primary: top.key,
    confidence: round2(confidence),
    signals: signals,
    detail: text,
    alternatives: alternatives
  };
}

module.exports = {
  detectIndicators: detectIndicators,
  detectScenario: detectScenario
};
