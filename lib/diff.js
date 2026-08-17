'use strict';

/**
 * lib/diff.js — the delta engine for a paired ingress/egress SIP leg pair
 * (SIP↔SIP only; analyze.js calls this per adjacent SIP pair in a call chain).
 *
 * Compares the two initial INVITEs (plus each leg's SDP answer / provisional
 * responses where a category needs them) and emits a structured delta:
 * nine fixed categories, each with items carrying a stable machine tag,
 * a severity, per-leg values and a one-line teaching detail. warn/crit items
 * are promoted into Finding objects (category 'diff', id left null for
 * analyze.js to assign).
 *
 * Zero dependencies; operates only on the frozen SipMessage/Leg shapes from
 * ARCHITECTURE.md, so it never requires other hiccup modules.
 */

// ---------------------------------------------------------------------------
// header helpers (local, compact-form aware — mirrors sip.js semantics on the
// frozen headers[] shape without requiring it)
// ---------------------------------------------------------------------------

var COMPACT = {
  f: 'from', t: 'to', i: 'call-id', m: 'contact', v: 'via',
  c: 'content-type', l: 'content-length', k: 'supported',
  e: 'content-encoding', s: 'subject', x: 'session-expires'
};

/** Normalize a header name: trim, lowercase, expand SIP compact forms. */
function normName(name) {
  var n = String(name == null ? '' : name).trim().toLowerCase();
  return COMPACT[n] || n;
}

/** All values of a header on a message (case-insensitive, compact-aware), in order. */
function getHdrs(msg, name) {
  var out = [];
  if (!msg || !Array.isArray(msg.headers)) return out;
  var want = normName(name);
  for (var i = 0; i < msg.headers.length; i++) {
    var h = msg.headers[i];
    if (h && normName(h.name) === want) out.push(String(h.value == null ? '' : h.value));
  }
  return out;
}

/** First value of a header or null. */
function getHdr(msg, name) {
  var vals = getHdrs(msg, name);
  return vals.length ? vals[0] : null;
}

/** Comma-separated option-tag values -> lowercase token array. */
function tokenList(values) {
  var out = [];
  for (var i = 0; i < values.length; i++) {
    var parts = String(values[i]).split(',');
    for (var j = 0; j < parts.length; j++) {
      var t = parts[j].trim().toLowerCase();
      if (t) out.push(t);
    }
  }
  return out;
}

/** Extract the user part of a SIP/SIPS/TEL URI (or name-addr), else null. */
function uriUser(uri) {
  if (!uri) return null;
  var s = String(uri);
  var lt = s.indexOf('<');
  if (lt !== -1) {
    var gt = s.indexOf('>', lt);
    s = s.slice(lt + 1, gt === -1 ? s.length : gt);
  }
  var m = /^\s*(?:sips?):([^@;?\s]+)@/i.exec(s);
  if (m) return m[1];
  m = /^\s*tel:([^;?\s]+)/i.exec(s);
  if (m) return m[1];
  return null;
}

// ---------------------------------------------------------------------------
// leg / message helpers
// ---------------------------------------------------------------------------

/** Messages belonging to a leg (SIP only), in the leg's capture order. */
function legMessages(leg, byId) {
  var out = [];
  if (!leg || !Array.isArray(leg.msgIds)) return out;
  for (var i = 0; i < leg.msgIds.length; i++) {
    var m = byId[leg.msgIds[i]];
    if (m && m.protocol === 'sip') out.push(m);
  }
  return out;
}

/** The leg's initial INVITE (leg.invite id, else first INVITE request). */
function initialInvite(leg, byId, msgs) {
  if (leg && leg.invite && byId[leg.invite]) return byId[leg.invite];
  for (var i = 0; i < msgs.length; i++) {
    if (msgs[i].isRequest && msgs[i].method === 'INVITE') return msgs[i];
  }
  return null;
}

/** The leg's SDP answer: first 183/200 response to the initial INVITE carrying SDP. */
function sdpAnswer(msgs, invite) {
  for (var i = 0; i < msgs.length; i++) {
    var m = msgs[i];
    if (m.isRequest || !m.sdp) continue;
    if (m.status !== 183 && m.status !== 200) continue;
    if (m.method && m.method !== 'INVITE') continue;
    if (invite && invite.cseq && m.cseq && m.cseq.num !== invite.cseq.num) continue;
    return m;
  }
  return null;
}

/** Canonical codec label for a payload entry, e.g. 'PCMU/8000'. */
function codecLabel(p) {
  var name = p && p.codec ? String(p.codec).toUpperCase() : ('PT' + (p ? p.pt : '?'));
  return p && p.rate ? name + '/' + p.rate : name;
}

function isTelephoneEvent(p) {
  return !!(p && p.codec && String(p.codec).toLowerCase() === 'telephone-event');
}

/** Ordered unique audio codec labels from an SDP offer, telephone-event excluded. */
function audioCodecs(sdp) {
  var out = [];
  if (!sdp || !Array.isArray(sdp.media)) return out;
  for (var i = 0; i < sdp.media.length; i++) {
    var m = sdp.media[i];
    if (!m || m.type !== 'audio' || !Array.isArray(m.payloads)) continue;
    for (var j = 0; j < m.payloads.length; j++) {
      var p = m.payloads[j];
      if (isTelephoneEvent(p)) continue;
      var label = codecLabel(p);
      if (out.indexOf(label) === -1) out.push(label);
    }
  }
  return out;
}

/** telephone-event payload type from an SDP's audio m-lines, or null. */
function dtmfPt(sdp) {
  if (!sdp || !Array.isArray(sdp.media)) return null;
  for (var i = 0; i < sdp.media.length; i++) {
    var m = sdp.media[i];
    if (!m || m.type !== 'audio' || !Array.isArray(m.payloads)) continue;
    for (var j = 0; j < m.payloads.length; j++) {
      if (isTelephoneEvent(m.payloads[j])) return m.payloads[j].pt;
    }
  }
  return null;
}

/** First audio ptime from an SDP, or null. */
function audioPtime(sdp) {
  if (!sdp || !Array.isArray(sdp.media)) return null;
  for (var i = 0; i < sdp.media.length; i++) {
    var m = sdp.media[i];
    if (m && m.type === 'audio' && m.ptime != null) return m.ptime;
  }
  return null;
}

/** 100rel posture of an INVITE: 'required' | 'supported' | 'absent'. */
function rel100State(invite) {
  if (!invite) return 'absent';
  if (tokenList(getHdrs(invite, 'require')).indexOf('100rel') !== -1) return 'required';
  if (tokenList(getHdrs(invite, 'supported')).indexOf('100rel') !== -1) return 'supported';
  return 'absent';
}

/** Session-timer parameters of an INVITE: { se, refresher, minSe } (nulls when absent). */
function timerInfo(invite) {
  var out = { se: null, refresher: null, minSe: null };
  var se = getHdr(invite, 'session-expires');
  if (se) {
    var m = /(\d+)/.exec(se);
    if (m) out.se = parseInt(m[1], 10);
    var r = /refresher\s*=\s*(uac|uas)/i.exec(se);
    if (r) out.refresher = r[1].toLowerCase();
  }
  var minSe = getHdr(invite, 'min-se');
  if (minSe) {
    var m2 = /(\d+)/.exec(minSe);
    if (m2) out.minSe = parseInt(m2[1], 10);
  }
  return out;
}

function timerLabel(t) {
  if (t.se == null && t.minSe == null) return 'no session timer';
  var bits = [];
  if (t.se != null) bits.push('Session-Expires ' + t.se + (t.refresher ? ';refresher=' + t.refresher : ''));
  if (t.minSe != null) bits.push('Min-SE ' + t.minSe);
  return bits.join(', ');
}

// ---------------------------------------------------------------------------
// private-IP (RFC1918 + RFC6598) detection
// ---------------------------------------------------------------------------

var IP_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

/** true for RFC1918 (10/8, 172.16/12, 192.168/16) and RFC6598 (100.64/10) v4 addresses. */
function isPrivateIp(ip) {
  var p = String(ip).split('.');
  if (p.length !== 4) return false;
  var a = +p[0], b = +p[1], c = +p[2], d = +p[3];
  if ([a, b, c, d].some(function (x) { return isNaN(x) || x > 255; })) return false;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // RFC6598 CGNAT space
  return false;
}

/** All private IPv4 addresses appearing in a string. */
function privateIpsIn(text) {
  var out = [];
  if (!text) return out;
  var m;
  IP_RE.lastIndex = 0;
  while ((m = IP_RE.exec(String(text))) !== null) {
    if (isPrivateIp(m[1]) && out.indexOf(m[1]) === -1) out.push(m[1]);
  }
  return out;
}

// ---------------------------------------------------------------------------
// T.38 helpers
// ---------------------------------------------------------------------------

/** true when an SDP carries an image/T.38 media description. */
function sdpHasT38(sdp) {
  if (!sdp) return false;
  if (Array.isArray(sdp.media)) {
    for (var i = 0; i < sdp.media.length; i++) {
      if (sdp.media[i] && sdp.media[i].type === 'image') return true;
    }
  }
  return /\bt38\b/i.test(sdp.raw || '');
}

/**
 * Find T.38 re-INVITE activity on a leg.
 * Returns null, or { msg, outcome, success } for the first T.38 re-INVITE
 * (retransmissions of the same CSeq are ignored).
 */
function t38ReInvite(msgs, invite) {
  var seenCseq = {};
  for (var i = 0; i < msgs.length; i++) {
    var m = msgs[i];
    if (!m.isRequest || m.method !== 'INVITE') continue;
    if (invite && m.id === invite.id) continue;
    if (invite && invite.cseq && m.cseq && m.cseq.num === invite.cseq.num) continue;
    var key = m.cseq ? String(m.cseq.num) : m.id;
    if (seenCseq[key]) continue;
    seenCseq[key] = true;
    if (!sdpHasT38(m.sdp)) continue;
    // final response to this re-INVITE
    var outcome = 'no final response';
    var success = false;
    for (var j = 0; j < msgs.length; j++) {
      var r = msgs[j];
      if (r.isRequest || r.ts < m.ts) continue;
      if (r.status == null || r.status < 200) continue;
      if (r.method && r.method !== 'INVITE') continue;
      if (m.cseq && r.cseq && r.cseq.num !== m.cseq.num) continue;
      success = r.status >= 200 && r.status < 300;
      outcome = success ? 'accepted (' + r.status + ')' : 'rejected (' + r.status + (r.reason ? ' ' + r.reason : '') + ')';
      break;
    }
    return { msg: m, outcome: outcome, success: success };
  }
  return null;
}

// ---------------------------------------------------------------------------
// the diff engine
// ---------------------------------------------------------------------------

// name-set / value comparison skips: hop-by-hop and branch-dependent noise
// (Route/Record-Route are reported under topology only, per the contract).
var NAME_IGNORE = {
  'via': 1, 'max-forwards': 1, 'content-length': 1, 'cseq': 1,
  'call-id': 1, 'route': 1, 'record-route': 1
};
// additionally skipped for VALUE comparison (handled by their own categories,
// or inherently hop-dependent):
var VALUE_IGNORE = {
  'from': 1, 'to': 1, 'contact': 1, 'session-expires': 1, 'min-se': 1
};

/**
 * Diff a paired ingress/egress SIP leg pair.
 *
 * @param {object} ingressLeg  Leg (protocol 'sip') — the earlier-starting side of the pair.
 * @param {object} egressLeg   Leg (protocol 'sip') — the B2BUA's onward side.
 * @param {Array<object>} messages  The full SipMessage/H323Message array (legs reference it via msgIds).
 * @returns {{categories: Array<{key: string, title: string, items: Array<{tag: string, severity: string, label: string, ingress: ?string, egress: ?string, detail: string}>}>, findings: Array<object>}}
 *   Nine fixed categories (headers, sdp, dtmf, reliability, session-timers,
 *   early-media, transport, topology, t38) with stable-tagged items, plus
 *   warn/crit items promoted to Findings (id null — analyze.js assigns).
 */
function diffLegs(ingressLeg, egressLeg, messages) {
  var cats = {
    'headers': { key: 'headers', title: 'Headers', items: [] },
    'sdp': { key: 'sdp', title: 'SDP', items: [] },
    'dtmf': { key: 'dtmf', title: 'DTMF', items: [] },
    'reliability': { key: 'reliability', title: 'Reliability', items: [] },
    'session-timers': { key: 'session-timers', title: 'Session timers', items: [] },
    'early-media': { key: 'early-media', title: 'Early media', items: [] },
    'transport': { key: 'transport', title: 'Transport', items: [] },
    'topology': { key: 'topology', title: 'Topology', items: [] },
    't38': { key: 't38', title: 'T.38', items: [] }
  };
  var order = ['headers', 'sdp', 'dtmf', 'reliability', 'session-timers',
    'early-media', 'transport', 'topology', 't38'];

  function result() {
    var categories = order.map(function (k) { return cats[k]; });
    var findings = [];
    var legIds = [];
    if (ingressLeg && ingressLeg.id) legIds.push(ingressLeg.id);
    if (egressLeg && egressLeg.id) legIds.push(egressLeg.id);
    for (var i = 0; i < categories.length; i++) {
      for (var j = 0; j < categories[i].items.length; j++) {
        var it = categories[i].items[j];
        if (it.severity !== 'warn' && it.severity !== 'crit') continue;
        var evidence = [];
        if (it.ingress != null) evidence.push('ingress: ' + it.ingress);
        if (it.egress != null) evidence.push('egress: ' + it.egress);
        findings.push({
          id: null,
          severity: it.severity,
          category: 'diff',
          title: it.label,
          detail: it.detail + (evidence.length ? ' [' + evidence.join(' | ') + ']' : ''),
          msgIds: inviteIds.slice(),
          legIds: legIds.slice(),
          callIds: []
        });
      }
    }
    return { categories: categories, findings: findings };
  }

  function add(catKey, tag, severity, label, ingress, egress, detail) {
    cats[catKey].items.push({
      tag: tag, severity: severity, label: label,
      ingress: ingress == null ? null : String(ingress),
      egress: egress == null ? null : String(egress),
      detail: detail
    });
  }

  var byId = {};
  if (Array.isArray(messages)) {
    for (var i = 0; i < messages.length; i++) {
      if (messages[i] && messages[i].id) byId[messages[i].id] = messages[i];
    }
  }
  var inMsgs = legMessages(ingressLeg, byId);
  var egMsgs = legMessages(egressLeg, byId);
  var inInv = initialInvite(ingressLeg, byId, inMsgs);
  var egInv = initialInvite(egressLeg, byId, egMsgs);
  var inviteIds = [];
  if (inInv) inviteIds.push(inInv.id);
  if (egInv) inviteIds.push(egInv.id);

  if (!inInv || !egInv) return result(); // not a comparable call pair — empty diff

  // --- headers -------------------------------------------------------------
  function headerMap(inv) {
    var map = {}; var names = [];
    if (Array.isArray(inv.headers)) {
      for (var i = 0; i < inv.headers.length; i++) {
        var h = inv.headers[i];
        if (!h) continue;
        var n = normName(h.name);
        if (NAME_IGNORE[n]) continue;
        if (!map[n]) { map[n] = { display: String(h.name), values: [] }; names.push(n); }
        map[n].values.push(String(h.value == null ? '' : h.value).trim());
      }
    }
    return { map: map, names: names };
  }
  var inH = headerMap(inInv);
  var egH = headerMap(egInv);
  var n, name;

  for (n = 0; n < inH.names.length; n++) {
    name = inH.names[n];
    if (!egH.map[name]) {
      add('headers', 'header-stripped', 'notice',
        'header stripped: ' + inH.map[name].display,
        inH.map[name].values.join(' | '), null,
        'Present on the ingress INVITE but absent from the egress INVITE — an SBC header-manipulation rule or profile deletes it before the message leaves.');
    }
  }
  for (n = 0; n < egH.names.length; n++) {
    name = egH.names[n];
    if (!inH.map[name]) {
      add('headers', 'header-added', 'info',
        'header added: ' + egH.map[name].display,
        null, egH.map[name].values.join(' | '),
        'Absent on ingress, inserted by the SBC on egress — typical of identity assertion (PAI), charging, or vendor policy headers.');
    }
  }
  for (n = 0; n < inH.names.length; n++) {
    name = inH.names[n];
    if (!egH.map[name] || VALUE_IGNORE[name]) continue;
    var a = inH.map[name].values, b = egH.map[name].values;
    var same = a.length === b.length;
    if (same) {
      for (var v = 0; v < a.length; v++) { if (a[v] !== b[v]) { same = false; break; } }
    }
    if (!same) {
      add('headers', 'header-rewritten', 'notice',
        'header rewritten: ' + inH.map[name].display,
        a.join(' | '), b.join(' | '),
        'The SBC changed this header\'s value(s) between legs — a manipulation rule, normalization, or interop profile at work.');
    }
  }

  // From/To user rewrites (tags are branch-dependent and always ignored)
  var inFromUser = uriUser(inInv.fromUri) || (ingressLeg && ingressLeg.fromUser) || null;
  var egFromUser = uriUser(egInv.fromUri) || (egressLeg && egressLeg.fromUser) || null;
  if (inFromUser != null && egFromUser != null && inFromUser !== egFromUser) {
    add('headers', 'from-rewritten', 'warn',
      'From URI user rewritten',
      String(inInv.fromUri || inFromUser), String(egInv.fromUri || egFromUser),
      'The SBC changed the calling-party user part (' + inFromUser + ' → ' + egFromUser + ') — number translation or CLI manipulation; downstream screening and billing see the new identity.');
  }
  var inToUser = uriUser(inInv.toUri) || (ingressLeg && ingressLeg.toUser) || null;
  var egToUser = uriUser(egInv.toUri) || (egressLeg && egressLeg.toUser) || null;
  if (inToUser != null && egToUser != null && inToUser !== egToUser) {
    add('headers', 'to-rewritten', 'warn',
      'To URI user rewritten',
      String(inInv.toUri || inToUser), String(egInv.toUri || egToUser),
      'The SBC changed the called-party user part (' + inToUser + ' → ' + egToUser + ') — digit translation or routing rewrite; the far end is being asked for a different number than the caller dialled.');
  }

  // --- sdp -----------------------------------------------------------------
  var inOffer = inInv.sdp, egOffer = egInv.sdp;
  var inCodecs = audioCodecs(inOffer), egCodecs = audioCodecs(egOffer);
  if (inCodecs.length && egCodecs.length) {
    var egSubset = egCodecs.every(function (c) { return inCodecs.indexOf(c) !== -1; });
    if (egSubset && egCodecs.length < inCodecs.length) {
      add('sdp', 'codec-narrowed', 'info',
        'codec list narrowed on egress',
        inCodecs.join(', '), egCodecs.join(', '),
        'The egress offer is a subset of the ingress offer — a codec policy/allow-list on the SBC; the far end never sees the removed codecs.');
    }
  }
  var inAns = sdpAnswer(inMsgs, inInv), egAns = sdpAnswer(egMsgs, egInv);
  if (inAns && egAns) {
    var inAnsCodecs = audioCodecs(inAns.sdp), egAnsCodecs = audioCodecs(egAns.sdp);
    if (inAnsCodecs.length && egAnsCodecs.length && inAnsCodecs[0] !== egAnsCodecs[0]) {
      add('sdp', 'codec-transcoding', 'warn',
        'transcoding forced — answered codec differs per leg',
        inAnsCodecs[0], egAnsCodecs[0],
        'Each leg answered a different codec, so the SBC must transcode the media — DSP/CPU cost, added latency, and possible quality loss.');
    }
  }
  var inPtime = audioPtime(inOffer), egPtime = audioPtime(egOffer);
  if ((inPtime != null || egPtime != null) && inPtime !== egPtime) {
    add('sdp', 'ptime-mismatch', 'notice',
      'ptime differs between legs',
      inPtime != null ? inPtime + ' ms' : 'not specified',
      egPtime != null ? egPtime + ' ms' : 'not specified',
      'Different packetization intervals per leg mean the SBC repacketizes RTP; endpoints that ignore ptime can cause jitter-buffer and bandwidth surprises.');
  }

  // --- dtmf ----------------------------------------------------------------
  var inDtmf = dtmfPt(inOffer), egDtmf = dtmfPt(egOffer);
  if (inDtmf != null && egDtmf != null) {
    if (inDtmf !== egDtmf) {
      add('dtmf', 'dtmf-pt-mismatch', 'warn',
        'telephone-event payload type differs',
        'PT ' + inDtmf, 'PT ' + egDtmf,
        'RFC 4733 DTMF rides a dynamic payload type; when each leg negotiates a different PT (the perennial 101 vs 96) the SBC must re-map it — a classic cause of one-way or dead DTMF.');
    }
  } else if (inDtmf != null || egDtmf != null) {
    add('dtmf', 'dtmf-missing-one-leg', 'warn',
      'telephone-event offered on one leg only',
      inDtmf != null ? 'PT ' + inDtmf : 'not offered',
      egDtmf != null ? 'PT ' + egDtmf : 'not offered',
      'One leg has no RFC 4733 telephone-event offer, so DTMF must be converted to inband tones or SIP INFO — or it is silently lost mid-call.');
  }

  // --- reliability ---------------------------------------------------------
  var inRel = rel100State(inInv), egRel = rel100State(egInv);
  if (inRel !== egRel) {
    var relSev = (inRel === 'required' && egRel === 'absent') ? 'warn' : 'notice';
    add('reliability', '100rel-asymmetry', relSev,
      '100rel/PRACK posture differs between legs',
      inRel === 'required' ? 'Require: 100rel' : (inRel === 'supported' ? 'Supported: 100rel' : '100rel absent'),
      egRel === 'required' ? 'Require: 100rel' : (egRel === 'supported' ? 'Supported: 100rel' : '100rel absent'),
      'RFC 3262 reliable provisional responses are negotiated per leg; when the ingress side requires 100rel and the egress offer omits it, reliable 18x (and precondition flows) cannot work end-to-end.');
  }

  // --- session-timers ------------------------------------------------------
  var inTimer = timerInfo(inInv), egTimer = timerInfo(egInv);
  var timersPresent = inTimer.se != null || inTimer.minSe != null || egTimer.se != null || egTimer.minSe != null;
  if (timersPresent) {
    if (inTimer.se !== egTimer.se || inTimer.refresher !== egTimer.refresher || inTimer.minSe !== egTimer.minSe) {
      add('session-timers', 'session-timer-changed', 'info',
        'session timer parameters changed',
        timerLabel(inTimer), timerLabel(egTimer),
        'The SBC rewrote the RFC 4028 session timer (interval and/or refresher role) — refresh responsibility now differs per leg, which is normal SBC behavior but worth knowing when refreshes fail.');
    }
    if ((inTimer.minSe != null && egTimer.se != null && inTimer.minSe > egTimer.se) ||
        (egTimer.minSe != null && inTimer.se != null && egTimer.minSe > inTimer.se)) {
      add('session-timers', 'session-timer-conflict', 'warn',
        'Min-SE exceeds Session-Expires across legs',
        timerLabel(inTimer), timerLabel(egTimer),
        'One leg\'s minimum acceptable refresh interval (Min-SE) is larger than the other leg\'s Session-Expires — expect 422 Session Interval Too Small or sessions torn down at refresh time.');
    }
  }

  // --- early-media ---------------------------------------------------------
  function provisionalProfile(msgs, invite) {
    var p = { has183Sdp: false, has180NoSdp: false, pem: null };
    for (var i = 0; i < msgs.length; i++) {
      var m = msgs[i];
      if (p.pem == null) {
        var pemVal = getHdr(m, 'p-early-media');
        if (pemVal != null) p.pem = pemVal;
      }
      if (m.isRequest || m.status == null) continue;
      if (m.method && m.method !== 'INVITE') continue;
      if (invite && invite.cseq && m.cseq && m.cseq.num !== invite.cseq.num) continue;
      if (m.status === 183 && m.sdp) p.has183Sdp = true;
      if (m.status === 180 && !m.sdp) p.has180NoSdp = true;
    }
    return p;
  }
  var inProv = provisionalProfile(inMsgs, inInv);
  var egProv = provisionalProfile(egMsgs, egInv);
  if ((inProv.has183Sdp && egProv.has180NoSdp && !egProv.has183Sdp) ||
      (egProv.has183Sdp && inProv.has180NoSdp && !inProv.has183Sdp)) {
    add('early-media', 'early-media-183', 'notice',
      'early media asymmetry — 183+SDP on one leg, 180 without SDP on the other',
      inProv.has183Sdp ? '183 with SDP' : '180 without SDP',
      egProv.has183Sdp ? '183 with SDP' : '180 without SDP',
      'One leg establishes an early media stream (183 with SDP) while the other only signals local ringback (180) — callers can hear silence, double ringback, or clipped announcements.');
  }
  if (inProv.pem != null || egProv.pem != null) {
    add('early-media', 'early-media-pem', 'info',
      'P-Early-Media present',
      inProv.pem != null ? inProv.pem : 'absent',
      egProv.pem != null ? egProv.pem : 'absent',
      'P-Early-Media (RFC 5009) gates early media authorization in IMS networks — the direction values say which way pre-answer media is allowed to flow.');
  }

  // --- transport -----------------------------------------------------------
  if (inInv.transport === 'udp' && typeof inInv.size === 'number' && inInv.size > 1300) {
    add('transport', 'udp-frag-risk', 'warn',
      'ingress INVITE exceeds safe UDP size',
      inInv.size + ' bytes on UDP', null,
      'A UDP SIP message over ~1300 bytes will IP-fragment, and fragments are routinely dropped by firewalls and NATs — slim the SDP/History-Info or switch the trunk to TCP (RFC 3261 §18.1.1).');
  }
  if (egInv.transport === 'udp' && typeof egInv.size === 'number' && egInv.size > 1300) {
    add('transport', 'udp-frag-risk', 'warn',
      'egress INVITE exceeds safe UDP size',
      null, egInv.size + ' bytes on UDP',
      'A UDP SIP message over ~1300 bytes will IP-fragment, and fragments are routinely dropped by firewalls and NATs — slim the SDP/History-Info or switch the trunk to TCP (RFC 3261 §18.1.1).');
  }

  // --- topology ------------------------------------------------------------
  // private IPs present anywhere in the ingress INVITE (headers/SDP/R-URI) ...
  var ingressPrivate = [];
  function collectPrivate(text) {
    var found = privateIpsIn(text);
    for (var i = 0; i < found.length; i++) {
      if (ingressPrivate.indexOf(found[i]) === -1) ingressPrivate.push(found[i]);
    }
  }
  if (Array.isArray(inInv.headers)) {
    for (i = 0; i < inInv.headers.length; i++) collectPrivate(inInv.headers[i] && inInv.headers[i].value);
  }
  collectPrivate(inInv.requestUri);
  if (inInv.sdp) {
    collectPrivate(inInv.sdp.raw);
    if (inInv.sdp.origin) collectPrivate(inInv.sdp.origin.addr);
    collectPrivate(inInv.sdp.connection);
  }
  // ... surviving in the egress INVITE (o=, c=, Contact, Record-Route, any header value)
  for (i = 0; i < ingressPrivate.length; i++) {
    var ip = ingressPrivate[i];
    var where = [];
    if (Array.isArray(egInv.headers)) {
      for (var hh = 0; hh < egInv.headers.length; hh++) {
        var eh = egInv.headers[hh];
        if (eh && String(eh.value == null ? '' : eh.value).indexOf(ip) !== -1) {
          var dn = String(eh.name);
          if (where.indexOf(dn) === -1) where.push(dn);
        }
      }
    }
    if (egInv.requestUri && String(egInv.requestUri).indexOf(ip) !== -1) where.push('Request-URI');
    if (egInv.sdp) {
      if (egInv.sdp.origin && egInv.sdp.origin.addr === ip) where.push('SDP o=');
      if (egInv.sdp.connection === ip) where.push('SDP c=');
      else if (egInv.sdp.raw && String(egInv.sdp.raw).indexOf(ip) !== -1 &&
               !(egInv.sdp.origin && egInv.sdp.origin.addr === ip)) {
        if (where.indexOf('SDP o=') === -1 && where.indexOf('SDP c=') === -1) where.push('SDP');
      }
    }
    if (where.length) {
      add('topology', 'private-ip-leak', 'crit',
        'private IP leaked through topology hiding: ' + ip,
        ip + ' (present on ingress)', 'survives in ' + where.join(', '),
        'An RFC 1918/6598 address from the ingress leg escaped into the egress INVITE — topology hiding is incomplete: the far end learns internal addressing, and media/signalling aimed at it will be unroutable.');
    }
  }

  // --- t38 -----------------------------------------------------------------
  var inT38 = t38ReInvite(inMsgs, inInv);
  var egT38 = t38ReInvite(egMsgs, egInv);
  if (inT38 || egT38) {
    if (!inT38 || !egT38) {
      add('t38', 't38-asymmetry', 'warn',
        'T.38 re-INVITE seen on one leg only',
        inT38 ? 'image/t38 re-INVITE, ' + inT38.outcome : 'no T.38 re-INVITE',
        egT38 ? 'image/t38 re-INVITE, ' + egT38.outcome : 'no T.38 re-INVITE',
        'A fax switch-over was attempted on one leg but never relayed to the other — the SBC may be blocking T.38 or terminating it locally; the fax will fail unless it falls back to G.711 pass-through.');
    } else if (inT38.success !== egT38.success) {
      add('t38', 't38-asymmetry', 'warn',
        'T.38 re-INVITE outcome differs between legs',
        'image/t38 re-INVITE, ' + inT38.outcome,
        'image/t38 re-INVITE, ' + egT38.outcome,
        'The fax switch-over succeeded on one leg and failed on the other — the SBC now has mismatched media types per leg and the fax will almost certainly fail.');
    }
  }

  return result();
}

module.exports = { diffLegs: diffLegs };
