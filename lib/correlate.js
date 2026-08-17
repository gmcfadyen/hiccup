'use strict';

/*
 * lib/correlate.js — multi-leg call correlation for hiccup.
 *
 * Pairs ingress/egress legs across a B2BUA (SIP<->SIP) or an IWF (SIP<->H.323)
 * with per-signal confidence scoring, greedy highest-confidence-first pairing
 * (threshold 0.5), an explicit `ambiguous` state whenever the best two
 * candidates sit within a 0.15 margin (DESIGN_1 rule: never silently pick),
 * and chain-merging (A-B plus B-C collapse into one call).
 *
 * Zero runtime dependencies; requires no other hiccup module. All shapes per
 * ARCHITECTURE.md (frozen contract).
 */

var PAIR_THRESHOLD = 0.5;        // a pairing needs >= 0.5 to be considered
var AMBIGUITY_MARGIN = 0.15;     // best two candidates within this -> ambiguous
var SIP_TEMPORAL_WINDOW_S = 0.25; // egress INVITE 0-250ms after ingress INVITE
var IWF_TEMPORAL_WINDOW_S = 0.5;  // SETUP vs INVITE within 500ms
var MIN_DIGIT_SUFFIX = 6;         // longest-common-suffix threshold for numbers

// Contract weights (ARCHITECTURE.md §Correlation).
var WEIGHTS = {
  'pcv-icid': 0.45,
  'x-header': 0.45,
  'sdp-origin': 0.30,
  'temporal-sip': 0.15,   // emitted under signal name 'temporal', scaled by proximity
  'user-parts': 0.10,     // halved when only one of To/From survives
  'via-rewrite': 0.05,
  'number-match': 0.45,
  'temporal-iwf': 0.30,   // emitted under signal name 'temporal'
  'guid': 0.25,
};

/* ------------------------------------------------------------------ helpers */

function round3(x) { return Math.round(x * 1000) / 1000; }

/** All values of a header on a parsed SIP message, case-insensitive. */
function headerValues(msg, name) {
  if (!msg || !Array.isArray(msg.headers)) return [];
  var n = String(name).toLowerCase();
  var out = [];
  for (var i = 0; i < msg.headers.length; i++) {
    var h = msg.headers[i];
    if (h && typeof h.name === 'string' && h.name.toLowerCase() === n) {
      out.push(h.value == null ? '' : String(h.value));
    }
  }
  return out;
}

function firstHeader(msg, name) {
  var v = headerValues(msg, name);
  return v.length ? v[0] : null;
}

/** icid-value parsed out of P-Charging-Vector, or null. */
function icidValue(msg) {
  var pcv = firstHeader(msg, 'P-Charging-Vector');
  if (!pcv) return null;
  var m = /icid-value\s*=\s*(?:"([^"]*)"|([^;,\s]+))/i.exec(pcv);
  if (!m) return null;
  var v = (m[1] != null ? m[1] : m[2]).trim();
  return v || null;
}

/** Vendor X-* headers of a message as [{name, origName, value}]. */
function xHeaderEntries(msg) {
  if (!msg || !Array.isArray(msg.headers)) return [];
  var out = [];
  for (var i = 0; i < msg.headers.length; i++) {
    var h = msg.headers[i];
    if (!h || typeof h.name !== 'string') continue;
    if (!/^x-/i.test(h.name)) continue;
    var v = h.value == null ? '' : String(h.value).trim();
    if (!v) continue;
    out.push({ name: h.name.toLowerCase(), origName: h.name, value: v });
  }
  return out;
}

function digitsOf(s) {
  if (s == null) return '';
  var m = String(s).match(/\d/g);
  return m ? m.join('') : '';
}

function commonSuffixLen(a, b) {
  var n = 0, i = a.length - 1, j = b.length - 1;
  while (i >= 0 && j >= 0 && a[i] === b[j]) { n++; i--; j--; }
  return n;
}

/** Canonical digit variants of a number: as-is, minus 00-prefix or single 0-prefix. */
function numberVariants(digits) {
  var out = [digits];
  if (digits.length > 2 && digits.slice(0, 2) === '00') out.push(digits.slice(2));
  else if (digits.length > 1 && digits[0] === '0') out.push(digits.slice(1));
  return out;
}

/**
 * Do two user parts refer to the same party? Exact (case-insensitive) match,
 * or — for number-shaped users — equality/suffix match after +33 / 0033 / 0
 * prefix normalization (suffix must be >= MIN_DIGIT_SUFFIX digits).
 */
function usersMatch(a, b) {
  if (a == null || b == null) return false;
  var sa = String(a).trim(), sb = String(b).trim();
  if (!sa || !sb) return false;
  if (sa.toLowerCase() === sb.toLowerCase()) return true;
  var numish = /^[+0-9()\-. #*]+$/;
  if (!numish.test(sa) || !numish.test(sb)) return false;
  var da = digitsOf(sa), db = digitsOf(sb);
  if (!da || !db) return false;
  var va = numberVariants(da), vb = numberVariants(db);
  for (var i = 0; i < va.length; i++) {
    for (var j = 0; j < vb.length; j++) {
      var x = va[i], y = vb[j];
      if (x === y) return true;
      var shorter = x.length <= y.length ? x : y;
      var longer = x.length <= y.length ? y : x;
      if (shorter.length >= MIN_DIGIT_SUFFIX && longer.slice(-shorter.length) === shorter) return true;
    }
  }
  return false;
}

/** host[:port] -> host (IPv6 brackets handled). */
function stripPort(hp) {
  if (!hp) return null;
  if (hp[0] === '[') {
    var e = hp.indexOf(']');
    return e === -1 ? hp : hp.slice(1, e);
  }
  var c = hp.lastIndexOf(':');
  if (c !== -1 && /^\d+$/.test(hp.slice(c + 1))) return hp.slice(0, c);
  return hp;
}

/** Host of the top Via of a SIP message, or null. */
function viaTopHost(msg) {
  var v = (msg && Array.isArray(msg.vias) && msg.vias.length) ? msg.vias[0] : null;
  if (!v) return null;
  var m = /SIP\s*\/\s*2\.0\s*\/\s*[A-Z0-9]+\s+([^;,\s]+)/i.exec(String(v));
  return m ? stripPort(m[1]) : null;
}

/** Host of the Contact URI of a SIP message, or null. */
function contactHost(msg) {
  var c = (msg && msg.contact) ? String(msg.contact) : firstHeader(msg, 'Contact');
  if (!c) return null;
  var m = /sips?:(?:[^@;>\s]*@)?(\[[^\]]+\]|[^;>,\s:]+)(?::\d+)?/i.exec(c);
  return m ? stripPort(m[1]) : null;
}

/** The initial INVITE of a SIP leg (leg.invite, else first INVITE request). */
function initialSipInvite(leg, msgById) {
  if (leg.invite && msgById[leg.invite]) return msgById[leg.invite];
  var ids = Array.isArray(leg.msgIds) ? leg.msgIds : [];
  for (var i = 0; i < ids.length; i++) {
    var m = msgById[ids[i]];
    if (m && m.isRequest && m.method === 'INVITE') return m;
  }
  return ids.length ? (msgById[ids[0]] || null) : null;
}

/** The SETUP of an H.323 leg (else its first message). */
function h323Setup(leg, msgById) {
  var ids = Array.isArray(leg.msgIds) ? leg.msgIds : [];
  for (var i = 0; i < ids.length; i++) {
    var m = msgById[ids[i]];
    if (m && m.q931Type === 'SETUP') return m;
  }
  return ids.length ? (msgById[ids[0]] || null) : null;
}

/** Id of the leg's anchor message (initial INVITE / SETUP) for findings. */
function anchorMsgId(leg, msgById) {
  var m = leg.protocol === 'h323' ? h323Setup(leg, msgById) : initialSipInvite(leg, msgById);
  return m && m.id ? m.id : null;
}

/* ------------------------------------------------------------------ scoring */

/**
 * Score a SIP<->SIP ingress/egress candidate pairing.
 * Returns { confidence, signals } with only matched signals listed.
 */
function scoreSipSip(ingress, egress, msgById) {
  var inv1 = initialSipInvite(ingress, msgById);
  var inv2 = initialSipInvite(egress, msgById);
  var signals = [];
  var score = 0;
  function add(name, weight, detail) {
    signals.push({ name: name, matched: true, weight: round3(weight), detail: detail });
    score += weight;
  }

  if (inv1 && inv2) {
    // 1. P-Charging-Vector icid-value on both initial INVITEs
    var ic1 = icidValue(inv1), ic2 = icidValue(inv2);
    if (ic1 && ic2 && ic1 === ic2) {
      add('pcv-icid', WEIGHTS['pcv-icid'],
        'P-Charging-Vector icid-value ' + ic1 + ' identical on both initial INVITEs');
    }
    // 2. Any vendor X-* header with identical name+value on both initial INVITEs
    var xs1 = xHeaderEntries(inv1), xs2 = xHeaderEntries(inv2);
    var xm = null;
    for (var i = 0; i < xs1.length && !xm; i++) {
      for (var j = 0; j < xs2.length; j++) {
        if (xs1[i].name === xs2[j].name && xs1[i].value === xs2[j].value) { xm = xs1[i]; break; }
      }
    }
    if (xm) {
      add('x-header', WEIGHTS['x-header'],
        xm.origName + ': ' + xm.value + ' identical on both initial INVITEs');
    }
    // 3. SDP o= sessId + sessVersion
    var o1 = inv1.sdp && inv1.sdp.origin, o2 = inv2.sdp && inv2.sdp.origin;
    if (o1 && o2 && o1.sessId != null && o2.sessId != null &&
        String(o1.sessId) === String(o2.sessId) &&
        String(o1.sessVersion) === String(o2.sessVersion)) {
      add('sdp-origin', WEIGHTS['sdp-origin'],
        'SDP o= session ' + o1.sessId + '/' + o1.sessVersion + ' identical on both legs');
    }
  }

  // 4. Temporal proximity: egress INVITE 0-250ms after ingress, linearly scaled
  var dt = (egress.startTs || 0) - (ingress.startTs || 0);
  if (isFinite(dt) && dt >= 0 && dt < SIP_TEMPORAL_WINDOW_S) {
    var w = WEIGHTS['temporal-sip'] * (1 - dt / SIP_TEMPORAL_WINDOW_S);
    add('temporal', w, 'egress INVITE ' + Math.round(dt * 1000) + 'ms after ingress INVITE');
  }

  // 5. Surviving To/From user parts (with +33 / 0033 / 0 normalization)
  var toM = usersMatch(ingress.toUser, egress.toUser);
  var frM = usersMatch(ingress.fromUser, egress.fromUser);
  if (toM || frM) {
    var w2 = (toM && frM) ? WEIGHTS['user-parts'] : WEIGHTS['user-parts'] / 2;
    var which = (toM && frM) ? 'To and From user parts survive'
      : (toM ? 'To user part ' + JSON.stringify(egress.toUser) + ' survives'
             : 'From user part ' + JSON.stringify(egress.fromUser) + ' survives');
    add('user-parts', w2, which + ' across the two legs');
  }

  // 6. Via/Contact rewrite consistent with SBC topology hiding: the egress
  // INVITE carries the SBC's own egress-side address where the ingress leg
  // had something else.
  if (inv1 && inv2) {
    var vh1 = viaTopHost(inv1), vh2 = viaTopHost(inv2);
    var ch1 = contactHost(inv1), ch2 = contactHost(inv2);
    var egSrc = egress.src || inv2.src || null;
    var contactRewrite = !!(ch1 && ch2 && ch1 !== ch2 && egSrc && ch2 === egSrc);
    var viaRewrite = !!(vh1 && vh2 && vh1 !== vh2 && egSrc && vh2 === egSrc &&
      (!Array.isArray(inv2.vias) || inv2.vias.length === 1));
    if (contactRewrite || viaRewrite) {
      var what = (contactRewrite && viaRewrite) ? 'Via and Contact'
        : (contactRewrite ? 'Contact' : 'Via');
      add('via-rewrite', WEIGHTS['via-rewrite'],
        'egress ' + what + ' rewritten to SBC egress address ' + egSrc);
    }
  }

  return { confidence: round3(Math.min(1, score)), signals: signals };
}

/**
 * Score a SIP<->H.323 (IWF) candidate pairing.
 * Returns { confidence, signals } with only matched signals listed.
 */
function scoreSipH323(sipLeg, hLeg, msgById) {
  var inv = initialSipInvite(sipLeg, msgById);
  var setup = h323Setup(hLeg, msgById);
  var signals = [];
  var score = 0;
  function add(name, weight, detail) {
    signals.push({ name: name, matched: true, weight: round3(weight), detail: detail });
    score += weight;
  }

  // 1. Digit longest-common-suffix >= 6 on called/calling vs To/From users
  var called = hLeg.toUser || (setup && setup.called) || hLeg.to;
  var calling = hLeg.fromUser || (setup && setup.calling) || hLeg.from;
  var cd = digitsOf(called), cg = digitsOf(calling);
  var st = digitsOf(sipLeg.toUser), sf = digitsOf(sipLeg.fromUser);
  var sufTo = (cd && st) ? commonSuffixLen(cd, st) : 0;
  var sufFrom = (cg && sf) ? commonSuffixLen(cg, sf) : 0;
  if (sufTo >= MIN_DIGIT_SUFFIX || sufFrom >= MIN_DIGIT_SUFFIX) {
    var parts = [];
    if (sufTo >= MIN_DIGIT_SUFFIX) {
      parts.push('called/To share a ' + sufTo + '-digit suffix (' + cd.slice(-sufTo) + ')');
    }
    if (sufFrom >= MIN_DIGIT_SUFFIX) {
      parts.push('calling/From share a ' + sufFrom + '-digit suffix');
    }
    add('number-match', WEIGHTS['number-match'], parts.join('; '));
  }

  // 2. Temporal: SETUP vs INVITE within 500ms (either direction)
  var dt = Math.abs((sipLeg.startTs || 0) - (hLeg.startTs || 0));
  if (isFinite(dt) && dt <= IWF_TEMPORAL_WINDOW_S) {
    add('temporal', WEIGHTS['temporal-iwf'],
      'SETUP and INVITE ' + Math.round(dt * 1000) + 'ms apart');
  }

  // 3. H.323 callIdentifier GUID appearing in a SIP header (rare)
  var guid = hLeg.guid || (setup && setup.guid) || null;
  if (guid && inv) {
    var needle = String(guid).toLowerCase().replace(/[^0-9a-f]/g, '');
    if (needle.length >= 16) {
      var hay;
      if (Array.isArray(inv.headers) && inv.headers.length) {
        hay = inv.headers.map(function (h) {
          return (h && h.name ? h.name : '') + ': ' + (h && h.value != null ? h.value : '');
        }).join('\n').toLowerCase();
      } else {
        hay = String(inv.raw || '').toLowerCase();
      }
      if (hay.indexOf(needle) !== -1 || hay.replace(/-/g, '').indexOf(needle) !== -1) {
        add('guid', WEIGHTS['guid'],
          'H.323 callIdentifier ' + guid + ' appears in a SIP header');
      }
    }
  }

  return { confidence: round3(Math.min(1, score)), signals: signals };
}

/* ------------------------------------------------------------------- main */

/**
 * Correlate call legs into calls (SIP<->SIP across a B2BUA, SIP<->H.323
 * across an IWF).
 *
 * Only `kind === 'call'` legs participate. Candidate pairings are scored from
 * the contract signal set, paired greedily highest-confidence-first with a
 * 0.5 threshold; when the best two candidates for one ingress leg fall
 * within a 0.15 margin the call is emitted as `ambiguous` with the competing
 * candidates instead of a guess. Accepted pairings chain-merge (A-B + B-C
 * become one call, legIds ordered by startTs, earliest = ingress). Every
 * unpaired call leg still yields a `single` call entry.
 *
 * @param {Array<object>} legs      Leg objects from groupSipLegs/groupH323Legs.
 * @param {Array<object>} messages  SipMessage|H323Message objects (for header,
 *                                  SDP and GUID inspection via leg.msgIds).
 * @returns {{calls: Array<object>, findings: Array<object>}} calls per the
 *   frozen CorrelatedCall shape (id, type, legIds, state, confidence,
 *   pairings, candidates) plus correlation findings (notice for ambiguous,
 *   info for confident pairings; finding ids left null for analyze.js).
 */
function correlateLegs(legs, messages) {
  var msgById = {};
  (Array.isArray(messages) ? messages : []).forEach(function (m) {
    if (m && m.id) msgById[m.id] = m;
  });
  var callLegs = (Array.isArray(legs) ? legs : []).filter(function (l) {
    return l && l.kind === 'call' && l.id;
  });
  var legById = {};
  callLegs.forEach(function (l) { legById[l.id] = l; });

  // ---- 1. score every eligible pair -----------------------------------
  var pairs = [];
  for (var i = 0; i < callLegs.length; i++) {
    for (var j = i + 1; j < callLegs.length; j++) {
      var A = callLegs[i], B = callLegs[j];
      var ingress = ((A.startTs || 0) <= (B.startTs || 0)) ? A : B;
      var egress = (ingress === A) ? B : A;
      var r = null;
      if (A.protocol === 'sip' && B.protocol === 'sip') {
        r = scoreSipSip(ingress, egress, msgById);
      } else if ((A.protocol === 'sip' && B.protocol === 'h323') ||
                 (A.protocol === 'h323' && B.protocol === 'sip')) {
        var sipLeg = A.protocol === 'sip' ? A : B;
        var hLeg = A.protocol === 'h323' ? A : B;
        r = scoreSipH323(sipLeg, hLeg, msgById);
      } else {
        continue; // H.323<->H.323 pairing has no contract signal set
      }
      if (r.confidence >= PAIR_THRESHOLD) {
        pairs.push({
          ingressId: ingress.id, egressId: egress.id,
          confidence: r.confidence, signals: r.signals,
        });
      }
    }
  }
  pairs.sort(function (p, q) {
    if (q.confidence !== p.confidence) return q.confidence - p.confidence;
    var ta = legById[p.ingressId].startTs || 0, tb = legById[q.ingressId].startTs || 0;
    if (ta !== tb) return ta - tb;
    if (p.ingressId !== q.ingressId) return p.ingressId < q.ingressId ? -1 : 1;
    return p.egressId < q.egressId ? -1 : (p.egressId > q.egressId ? 1 : 0);
  });

  // ---- 2. ambiguity pre-pass per ingress leg --------------------------
  // If the best two egress candidates for one ingress are within the margin,
  // refuse to pick (DESIGN_1's explicit rule).
  var byIngress = {};
  pairs.forEach(function (p) {
    (byIngress[p.ingressId] = byIngress[p.ingressId] || []).push(p);
  });
  // legId -> { role, withinMargin, candidates: [{legId, confidence}], attached }
  var ambiguousInfo = {};
  Object.keys(byIngress).forEach(function (id) {
    var list = byIngress[id]; // already sorted (pairs is sorted, push preserves order)
    if (list.length >= 2 && list[0].confidence - list[1].confidence <= AMBIGUITY_MARGIN) {
      var within = list.filter(function (p) {
        return list[0].confidence - p.confidence <= AMBIGUITY_MARGIN;
      }).length;
      ambiguousInfo[id] = {
        role: 'ingress',
        withinMargin: within,
        candidates: list.map(function (p) {
          return { legId: p.egressId, confidence: p.confidence };
        }),
      };
    }
  });

  // ---- 3. greedy pairing with egress-contention guard -----------------
  var pool = pairs.filter(function (p) { return !ambiguousInfo[p.ingressId]; });
  var usedIngress = {}, usedEgress = {}, vetoedEgress = {};
  var accepted = [];
  for (var k = 0; k < pool.length; k++) {
    var p = pool[k];
    if (usedIngress[p.ingressId] || usedEgress[p.egressId] || vetoedEgress[p.egressId]) continue;
    // Two different ingress legs contending for the same egress within the
    // margin is the same "don't guess" situation seen from the other side.
    var rivals = [];
    for (var m = 0; m < pool.length; m++) {
      var q = pool[m];
      if (q === p || q.egressId !== p.egressId) continue;
      if (usedIngress[q.ingressId]) continue;
      if (p.confidence - q.confidence <= AMBIGUITY_MARGIN) rivals.push(q);
    }
    if (rivals.length) {
      var cands = [{ legId: p.ingressId, confidence: p.confidence }].concat(
        rivals.map(function (q2) { return { legId: q2.ingressId, confidence: q2.confidence }; }));
      ambiguousInfo[p.egressId] = {
        role: 'egress', withinMargin: cands.length, candidates: cands,
      };
      vetoedEgress[p.egressId] = true;
      continue;
    }
    accepted.push(p);
    usedIngress[p.ingressId] = true;
    usedEgress[p.egressId] = true;
  }

  // ---- 4. chain-merge accepted pairings into components ---------------
  var parent = {};
  callLegs.forEach(function (l) { parent[l.id] = l.id; });
  function findRoot(x) {
    while (parent[x] !== x) { parent[x] = parent[parent[x]]; x = parent[x]; }
    return x;
  }
  accepted.forEach(function (pr) {
    var a = findRoot(pr.ingressId), b = findRoot(pr.egressId);
    if (a !== b) parent[b] = a;
  });
  var comps = {}; // root -> [legId]
  var inComp = {};
  accepted.forEach(function (pr) {
    [pr.ingressId, pr.egressId].forEach(function (id) {
      if (inComp[id]) return;
      inComp[id] = true;
      var root = findRoot(id);
      (comps[root] = comps[root] || []).push(id);
    });
  });

  // ---- 5. build call entries ------------------------------------------
  var startOf = function (id) { return legById[id].startTs || 0; };
  var callObjs = [];
  var legHasCall = {};

  Object.keys(comps).forEach(function (root) {
    var ids = comps[root].slice().sort(function (x, y) {
      return startOf(x) - startOf(y) || (x < y ? -1 : 1);
    });
    var prs = accepted
      .filter(function (pr) { return findRoot(pr.ingressId) === root; })
      .sort(function (x, y) { return startOf(x.ingressId) - startOf(y.ingressId); })
      .map(function (pr) {
        return { a: pr.ingressId, b: pr.egressId, confidence: pr.confidence, signals: pr.signals };
      });
    var conf = round3(Math.min.apply(null, prs.map(function (pr) { return pr.confidence; })));
    var type = ids.some(function (id) { return legById[id].protocol === 'h323'; })
      ? 'sip-h323' : 'sip-sip';
    // A member may still carry unresolved onward ambiguity (paired upstream,
    // ambiguous toward further egress candidates): surface those candidates
    // on the call rather than inventing a second call for the leg.
    var cands = [];
    ids.forEach(function (id) {
      if (ambiguousInfo[id]) {
        ambiguousInfo[id].attached = true;
        ambiguousInfo[id].attachedLegId = id;
        cands = cands.concat(ambiguousInfo[id].candidates.filter(function (c) {
          return ids.indexOf(c.legId) === -1;
        }));
      }
      legHasCall[id] = true;
    });
    callObjs.push({
      _startTs: startOf(ids[0]),
      type: type, legIds: ids, state: 'paired', confidence: conf,
      pairings: prs, candidates: cands,
      _ambList: ids.filter(function (id) { return ambiguousInfo[id]; }),
    });
  });

  // Ambiguous calls for flagged legs that joined no component.
  Object.keys(ambiguousInfo).forEach(function (id) {
    var info = ambiguousInfo[id];
    if (info.attached || legHasCall[id]) return;
    var leg = legById[id];
    var best = info.candidates[0];
    var bestLeg = best && legById[best.legId];
    var type = (leg.protocol === 'h323' || (bestLeg && bestLeg.protocol === 'h323'))
      ? 'sip-h323' : 'sip-sip';
    legHasCall[id] = true;
    callObjs.push({
      _startTs: leg.startTs || 0,
      type: type, legIds: [id], state: 'ambiguous',
      confidence: best ? best.confidence : 0,
      pairings: [], candidates: info.candidates,
      _ambList: [id],
    });
  });

  // Unpaired call legs each get a `single` entry (single-leg captures are normal).
  callLegs.forEach(function (l) {
    if (legHasCall[l.id]) return;
    legHasCall[l.id] = true;
    callObjs.push({
      _startTs: l.startTs || 0,
      type: 'single', legIds: [l.id], state: 'unpaired', confidence: 0,
      pairings: [], candidates: [],
      _ambList: [],
    });
  });

  // ---- 6. order + ids --------------------------------------------------
  callObjs.sort(function (a, b) {
    return a._startTs - b._startTs ||
      (a.legIds[0] < b.legIds[0] ? -1 : (a.legIds[0] > b.legIds[0] ? 1 : 0));
  });
  var calls = callObjs.map(function (c, idx) {
    return {
      id: 'c' + (idx + 1),
      type: c.type,
      legIds: c.legIds,
      state: c.state,
      confidence: c.confidence,
      pairings: c.pairings,
      candidates: c.candidates,
    };
  });

  // ---- 7. findings -----------------------------------------------------
  var findings = [];
  callObjs.forEach(function (c, idx) {
    var call = calls[idx];
    // notice per ambiguous leg (state ambiguous, or paired with onward ambiguity)
    c._ambList.forEach(function (legId) {
      var info = ambiguousInfo[legId];
      if (!info) return;
      var otherRole = info.role === 'ingress' ? 'egress' : 'ingress';
      var candList = info.candidates.map(function (cd) {
        return cd.legId + ' (' + cd.confidence.toFixed(2) + ')';
      }).join(', ');
      findings.push({
        id: null,
        severity: 'notice',
        category: 'correlation',
        title: 'Ambiguous correlation for leg ' + legId,
        detail: info.withinMargin + ' candidate ' + otherRole +
          ' legs within margin — refusing to guess. Candidates for ' +
          legId + ': ' + candList + '.',
        msgIds: [],
        legIds: [legId].concat(info.candidates.map(function (cd) { return cd.legId; })),
        callIds: [call.id],
      });
    });
    // info per accepted pairing, listing matched signals
    call.pairings.forEach(function (pr) {
      var sigText = pr.signals.length
        ? pr.signals.map(function (s) { return s.name + ' (' + s.detail + ')'; }).join('; ')
        : 'no individual signals recorded';
      var msgIds = [];
      [pr.a, pr.b].forEach(function (legId) {
        var mid = anchorMsgId(legById[legId], msgById);
        if (mid) msgIds.push(mid);
      });
      findings.push({
        id: null,
        severity: 'info',
        category: 'correlation',
        title: 'Legs ' + pr.a + ' and ' + pr.b + ' paired (confidence ' +
          pr.confidence.toFixed(2) + ')',
        detail: 'Matched signals: ' + sigText + '.',
        msgIds: msgIds,
        legIds: [pr.a, pr.b],
        callIds: [call.id],
      });
    });
  });

  return { calls: calls, findings: findings };
}

module.exports = { correlateLegs: correlateLegs };
