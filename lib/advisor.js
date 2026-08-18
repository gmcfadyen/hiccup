'use strict';

/**
 * hiccup — lib/advisor.js
 *
 * The articulation layer: what is wrong, why it matters, the protocol
 * mechanism, concrete vendor-specific fixes, and real citations.
 *
 * DETERMINISTIC BY DESIGN. Every word of every Advice object comes from the
 * hand-written rule/knowledge base below — never from an LLM. The chat layer
 * may paraphrase an Advice object, but it must never invent one, and above all
 * must never invent a citation.
 *
 * Shape: a table of rule objects
 *   { id, when(analysis, ctx) -> matches[], build(match, analysis, ctx) -> Advice }
 * plus CITATIONS, a map keyed by rule id. Each rule fires off evidence already
 * present in the analysis object (retransmission classifications, diff item
 * tags, findings, media stream stats, aux DNS/Diameter/ICE observations,
 * indicators, Q.850/ISUP cause codes, correlation ambiguity) — the advisor
 * never re-parses packets.
 *
 * Zero runtime dependencies. Never throws: every rule runs inside a try/catch
 * and a rule that blows up is skipped, not fatal.
 *
 * @see ARCHITECTURE.md §Advice (Wave 2)
 */

// lib/sip.js is a Wave-1 sibling; loaded defensively so advisor.js still works
// (with a simpler header lookup) if it is ever absent.
let sipLib = null;
try { sipLib = require('./sip'); } catch (e) { sipLib = null; }

const SEV_RANK = { crit: 0, warn: 1, notice: 2, info: 3 };
const MAX_ADVICE = 60;            // hard cap on returned advice
const MAX_MATCHES_PER_RULE = 8;   // busy trunks must not produce 400 cards
const MAX_FIXES = 6;
const MAX_KB_HITS = 3;

// ---------------------------------------------------------------------------
// Small safe helpers
// ---------------------------------------------------------------------------

function arr(x) { return Array.isArray(x) ? x : []; }
function obj(x) { return x && typeof x === 'object' ? x : {}; }
function txt(x) { return x === null || x === undefined ? '' : String(x); }
function num(x) { return typeof x === 'number' && isFinite(x) ? x : null; }
function uniq(list) { const o = []; for (const v of arr(list)) if (v != null && o.indexOf(v) === -1) o.push(v); return o; }

/** Seconds → short human string ('0.4s', '32s'). */
function fmtS(x) {
  const n = num(x);
  if (n === null) return '?s';
  return (n >= 10 ? String(Math.round(n)) : String(Math.round(n * 10) / 10)) + 's';
}

/** Milliseconds → short human string. */
function fmtMs(x) {
  const n = num(x);
  if (n === null) return '?ms';
  return (n >= 100 ? String(Math.round(n)) : String(Math.round(n * 10) / 10)) + 'ms';
}

/** First value of a SIP header, compact-form aware (falls back to a local scan). */
function hdr(msg, name) {
  if (!msg) return null;
  if (sipLib && typeof sipLib.getHeader === 'function') {
    try { return sipLib.getHeader(msg, name); } catch (e) { /* fall through */ }
  }
  const want = txt(name).toLowerCase();
  for (const h of arr(msg.headers)) {
    if (h && txt(h.name).toLowerCase() === want) return h.value;
  }
  return null;
}

/** All values of a SIP header. */
function hdrs(msg, name) {
  if (!msg) return [];
  if (sipLib && typeof sipLib.getHeaders === 'function') {
    try { return arr(sipLib.getHeaders(msg, name)); } catch (e) { /* fall through */ }
  }
  const want = txt(name).toLowerCase();
  return arr(msg.headers).filter(h => h && txt(h.name).toLowerCase() === want).map(h => h.value);
}

/** Host (or host:port) out of a SIP URI or name-addr. Best effort, never throws. */
function uriHost(v) {
  const s = txt(v);
  if (!s) return null;
  const m = /sips?:(?:[^@>\s]*@)?\[?([^\]>;,\s]+)\]?/i.exec(s);
  if (!m) return null;
  return m[1].replace(/:\d+$/, '') || null;
}

/** RFC 1918 / RFC 6598 / link-local address test (v4 only — that is where leaks live). */
function isPrivateIp(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(txt(ip));
  if (!m) return false;
  const a = +m[1], b = +m[2];
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;   // RFC 6598 shared space
  if (a === 169 && b === 254) return true;             // link-local
  return false;
}

/** 'a.b.c.d:5060' label for a message's destination. */
function dstLabel(msg) {
  if (!msg) return 'the far end';
  return txt(msg.dst) + (msg.dport ? ':' + msg.dport : '');
}

// ---------------------------------------------------------------------------
// Citation catalogue
//
// DISCIPLINE: a section number appears here only where I am confident it is
// correct. Where the section is uncertain the RFC is cited on its own — a
// correct reference with no anchor beats a plausible-looking wrong one.
// Non-RFC standards (ITU-T, 3GPP) carry url:null by contract.
// ---------------------------------------------------------------------------

function rfc(n, section, title) {
  return {
    source: 'RFC ' + n,
    section: section || null,
    title: title || '',
    url: section
      ? 'https://www.rfc-editor.org/rfc/rfc' + n + '#section-' + String(section).replace(/^Section\s+/i, '')
      : 'https://www.rfc-editor.org/rfc/rfc' + n,
  };
}
function std(source, title) {
  return { source: source, section: null, title: title || '', url: null };
}

const REFS = {
  // RFC 3261 — sections below are ones I am confident about.
  sip_contact:       rfc(3261, 'Section 8.1.1.8', 'Contact'),
  sip_cancel_uac:    rfc(3261, 'Section 9.1', 'Client Behavior (CANCEL)'),
  sip_cancel_uas:    rfc(3261, 'Section 9.2', 'Server Behavior (CANCEL)'),
  sip_registrations: rfc(3261, 'Section 10', 'Registrations'),
  sip_dialog_uas:    rfc(3261, 'Section 12.1.1', 'UAS behavior (route set, Record-Route and Contact)'),
  sip_2xx_uac:       rfc(3261, 'Section 13.2.2.4', '2xx Responses (the UAC generates the ACK)'),
  sip_2xx_uas:       rfc(3261, 'Section 13.3.1.4', 'The INVITE is Accepted (2xx retransmitted until ACK)'),
  sip_invite_ct:     rfc(3261, 'Section 17.1.1.2', 'INVITE client transaction — formal description (Timer A / Timer B)'),
  sip_sending:       rfc(3261, 'Section 18.1.1', 'Sending Requests (the 1300-byte MTU rule)'),
  sip_digest:        rfc(3261, 'Section 22.2', 'User-to-User Authentication'),
  sip_base:          rfc(3261, null, 'SIP: Session Initiation Protocol'),

  rel100:            rfc(3262, null, 'Reliability of Provisional Responses in SIP'),
  locating:          rfc(3263, 'Section 4', 'Client Usage (NAPTR → SRV → A resolution)'),
  offans:            rfc(3264, 'Section 6', 'Generating the Answer'),
  offans_base:       rfc(3264, null, 'An Offer/Answer Model with the Session Description Protocol (SDP)'),
  update:            rfc(3311, null, 'The Session Initiation Protocol (SIP) UPDATE Method'),
  precond:           rfc(3312, null, 'Integration of Resource Management and SIP'),
  precond_upd:       rfc(4032, null, 'Update to the SIP Preconditions Framework'),
  sipt:              rfc(3372, null, 'Session Initiation Protocol for Telephones (SIP-T): Context and Architectures'),
  isup_map:          rfc(3398, null, 'ISUP to SIP Mapping'),
  sdp_caps:          rfc(3407, null, 'Session Description Protocol (SDP) Simple Capability Declaration'),
  refer:             rfc(3515, null, 'The Session Initiation Protocol (SIP) Refer Method'),
  refer_clarify:     rfc(7647, null, 'Clarifications for the Use of REFER with RFC 6665'),
  rtp_reports:       rfc(3550, 'Section 6.4.1', 'SR: Sender Report RTP Packet (loss and interarrival jitter fields)'),
  rtp_base:          rfc(3550, null, 'RTP: A Transport Protocol for Real-Time Applications'),
  rtp_av_profile:    rfc(3551, null, 'RTP Profile for Audio and Video Conferences with Minimal Control'),
  srtp:              rfc(3711, null, 'The Secure Real-time Transport Protocol (SRTP)'),
  service_route:     rfc(3608, null, 'SIP Extension Header Field for Service Route Discovery During Registration'),
  early_media:       rfc(3960, null, 'Early Media and Ringing Tone Generation in SIP'),
  pem:               rfc(5009, null, 'Private Header (P-Header) Extension for Authorization of Early Media'),
  session_timers:    rfc(4028, null, 'Session Timers in the Session Initiation Protocol (SIP)'),
  sdp:               rfc(4566, 'Section 6', 'SDP Attributes'),
  dtmf:              rfc(4733, null, 'RTP Payload for DTMF Digits, Telephony Tones, and Telephony Signals'),
  rr_issues:         rfc(5658, null, 'Addressing Record-Route Issues in the Session Initiation Protocol (SIP)'),
  dtls_srtp:         rfc(5764, null, 'DTLS Extension to Establish Keys for SRTP'),
  ice:               rfc(8445, null, 'Interactive Connectivity Establishment (ICE)'),
  nat_reqs:          rfc(4787, null, 'NAT Behavioral Requirements for Unicast UDP'),
  private_addr:      rfc(1918, 'Section 3', 'Private Address Space'),
  shared_addr:       rfc(6598, null, 'IANA-Reserved IPv4 Prefix for Shared Address Space'),
  diameter:          rfc(6733, 'Section 7', 'Error Handling'),
  pheaders_3gpp:     rfc(7315, null, 'P-Header Extensions to SIP for 3GPP (P-Charging-Vector, icid-value)'),
  digest_http:       rfc(7616, null, 'HTTP Digest Access Authentication'),
  session_id:        rfc(7989, null, 'End-to-End Session Identification in IP-Based Multimedia Communication Networks'),
  history_info:      rfc(7044, null, 'An Extension to SIP for Request History Information'),
  ipv6_sip:          rfc(6157, null, 'IPv6 Transition in the Session Initiation Protocol'),
  offans_usage:      rfc(6337, null, 'SIP Usage of the Offer/Answer Model'),

  t38:               std('ITU-T T.38', 'Procedures for real-time Group 3 facsimile communication over IP networks'),
  q850:              std('ITU-T Q.850', 'Usage of cause and location in DSS1 and SS7 ISUP'),
  q931:              std('ITU-T Q.931', 'ISDN user-network interface layer 3 specification for basic call control'),
  h225:              std('ITU-T H.225.0', 'Call signalling protocols and media stream packetization for H.323'),
  h323:              std('ITU-T H.323', 'Packet-based multimedia communications systems'),
  g107:              std('ITU-T G.107', 'The E-model: a computational model for use in transmission planning'),
  ts24229:           std('3GPP TS 24.229', 'IP multimedia call control protocol based on SIP and SDP; Stage 3'),
  ts29214:           std('3GPP TS 29.214', 'Policy and charging control over Rx reference point'),
};

/** Clone a catalogue reference and attach the rule-specific "why this applies" note. */
function cite(ref, note) {
  const r = obj(ref);
  return {
    source: txt(r.source),
    section: r.section || null,
    title: txt(r.title),
    url: r.url || null,
    note: txt(note),
  };
}

// ---------------------------------------------------------------------------
// Analysis context — indexed once, handed to every rule
// ---------------------------------------------------------------------------

const VENDOR_SIGNATURES = [
  [/acme\s*packet|net-net|oracle|oracle-esbc|sd\s*sbc|OS-E/i, 'oracle-acme'],
  [/audiocodes|mediant|mp-1\d{2}|mp-5\d{2}/i, 'audiocodes'],
  [/ribbon|sonus|sbc\s*[57]\d{3}|nbs|sbc\s*swe/i, 'ribbon'],
  [/cisco-?sipgateway|cisco-?cube|cisco\s*ios/i, 'cisco-cube'],
  [/freeswitch/i, 'freeswitch'],
  [/asterisk|freepbx/i, 'asterisk'],
];

/**
 * Which SBC/UA platforms the capture itself names, from User-Agent / Server.
 * Used only to ORDER the fix list — never to claim a vendor's config is wrong.
 * @param {Array<object>} messages
 * @returns {Set<string>} fix target names
 */
function detectVendors(messages) {
  const found = new Set();
  let scanned = 0;
  for (const m of arr(messages)) {
    if (!m || m.protocol !== 'sip' || scanned > 400) break;
    scanned++;
    const s = txt(hdr(m, 'User-Agent')) + ' ' + txt(hdr(m, 'Server'));
    if (!s.trim()) continue;
    for (const [re, target] of VENDOR_SIGNATURES) {
      if (re.test(s)) found.add(target);
    }
  }
  return found;
}

/** Index the analysis object once; tolerates any key being absent. */
function buildContext(analysis) {
  const a = obj(analysis);
  const messages = arr(a.messages);
  const legs = arr(a.legs);
  const msgById = new Map();
  for (const m of messages) if (m && m.id) msgById.set(m.id, m);
  const legById = new Map();
  for (const l of legs) if (l && l.id) legById.set(l.id, l);
  const media = obj(a.media);
  const retrans = obj(a.retrans);
  return {
    analysis: a,
    messages,
    sip: messages.filter(m => m && m.protocol === 'sip'),
    h323: messages.filter(m => m && m.protocol === 'h323'),
    msgById,
    legs,
    legById,
    calls: arr(a.calls),
    findings: arr(a.findings),
    aux: arr(a.aux),
    indicators: arr(a.indicators),
    scenario: obj(a.scenario),
    streams: arr(media.streams),
    rtcp: arr(media.rtcp),
    collapses: arr(retrans.collapses),
    stormWindows: arr(obj(retrans.aggregate).stormWindows),
    vendors: detectVendors(messages),
  };
}

/** Messages of one leg, in capture order, originals and retransmissions. */
function legMsgs(ctx, legOrId) {
  const leg = typeof legOrId === 'string' ? ctx.legById.get(legOrId) : legOrId;
  if (!leg) return [];
  return arr(leg.msgIds).map(id => ctx.msgById.get(id)).filter(Boolean);
}

/** Only first transmissions — retransmitted copies would double-count evidence. */
function originals(list) { return arr(list).filter(m => m && !m.retransOf); }

/** Finding ids matching a predicate, capped so an Advice never carries hundreds. */
function findingIdsBy(ctx, predicate) {
  const out = [];
  for (const f of ctx.findings) {
    if (!f || !f.id) continue;
    let hit = false;
    try { hit = !!predicate(f); } catch (e) { hit = false; }
    if (hit) out.push(f.id);
    if (out.length >= 20) break;
  }
  return out;
}

/** Ids of the legs that own any of these messages — for tagging advice with legIds. */
function legIdsForMsgs(ctx, msgIds) {
  const want = new Set(arr(msgIds));
  const out = [];
  for (const l of ctx.legs) {
    if (l && l.id && arr(l.msgIds).some(id => want.has(id))) out.push(l.id);
  }
  return out;
}

/** True when two id lists intersect. */
function intersects(a, b) {
  const set = new Set(arr(b));
  return arr(a).some(x => set.has(x));
}

/**
 * Group diff items carrying any of `tags` into one match per distinct
 * (tag, label, ingress, egress) — a busy trunk repeats the same delta on every
 * call, and one card that says "seen on 37 calls" beats 37 identical cards.
 */
function diffMatches(ctx, tags) {
  const want = new Set(arr(tags));
  const groups = new Map();
  for (const call of ctx.calls) {
    for (const d of arr(call && call.diffs)) {
      const diff = obj(d && d.diff);
      for (const cat of arr(diff.categories)) {
        for (const item of arr(cat && cat.items)) {
          if (!item || !want.has(item.tag)) continue;
          const key = [item.tag, item.label, item.ingress, item.egress].join('');
          let g = groups.get(key);
          if (!g) {
            g = {
              kind: 'diff', tag: item.tag, item: item,
              categoryKey: txt(cat.key), calls: 0,
              callIds: [], legIds: [], msgIds: [],
            };
            groups.set(key, g);
          }
          g.calls++;
          if (call.id && g.callIds.indexOf(call.id) === -1) g.callIds.push(call.id);
          for (const lid of [d && d.a, d && d.b]) {
            if (!lid) continue;
            if (g.legIds.indexOf(lid) === -1) g.legIds.push(lid);
            const leg = ctx.legById.get(lid);
            if (leg && leg.invite && g.msgIds.indexOf(leg.invite) === -1) g.msgIds.push(leg.invite);
          }
        }
      }
    }
  }
  return Array.from(groups.values()).slice(0, MAX_MATCHES_PER_RULE);
}

/**
 * Group retransmission collapses by (classification code, method/status,
 * destination). Keeps the worst collapse of the group as the quotable sample.
 */
function collapseMatches(ctx, codes) {
  const want = new Set(arr(codes));
  const groups = new Map();
  for (const c of ctx.collapses) {
    const code = txt(obj(c && c.classification).code);
    if (!want.has(code)) continue;
    const first = ctx.msgById.get(arr(c.msgIds)[0]);
    const dst = dstLabel(first);
    const what = c.kind === 'response' ? txt(c.status) + ' response' : txt(c.method || 'request');
    const key = [code, what, dst].join('');
    let g = groups.get(key);
    if (!g) {
      g = {
        kind: 'retrans', code: code, what: what, dst: dst,
        sample: c, collapses: [], legIds: [], msgIds: [], callIds: [],
        transport: first ? txt(first.transport) : 'udp',
        size: first ? num(first.size) : null,
        maxCount: 0, spanS: 0,
      };
      groups.set(key, g);
    }
    g.collapses.push(c);
    if (num(c.count) !== null && c.count > g.maxCount) { g.maxCount = c.count; g.sample = c; }
    const span = num(c.lastTs) !== null && num(c.firstTs) !== null ? c.lastTs - c.firstTs : 0;
    if (span > g.spanS) g.spanS = span;
    if (c.legId && g.legIds.indexOf(c.legId) === -1) g.legIds.push(c.legId);
    for (const id of arr(c.msgIds)) if (g.msgIds.indexOf(id) === -1 && g.msgIds.length < 40) g.msgIds.push(id);
  }
  // attach the calls those legs belong to
  for (const g of groups.values()) {
    for (const call of ctx.calls) {
      if (call && call.id && intersects(arr(call.legIds), g.legIds) && g.callIds.indexOf(call.id) === -1) {
        g.callIds.push(call.id);
      }
    }
  }
  return Array.from(groups.values()).slice(0, MAX_MATCHES_PER_RULE);
}

/** Indicator by key, or null. */
function indicator(ctx, key) {
  for (const i of ctx.indicators) if (i && i.key === key) return i;
  return null;
}

// ---------------------------------------------------------------------------
// Fix helpers — vendor config drafts are ALWAYS marked as drafts
// ---------------------------------------------------------------------------

const DRAFT_ACME = '# DRAFT — Oracle/Acme ACLI shape. Element and parameter names move\n' +
  '# between SCX releases: check the ACLI Configuration Guide for yours.\n';
const DRAFT_AC = '; DRAFT — AudioCodes shape (7.2/7.4 era). Verify each parameter against\n' +
  '; the SBC User\'s Manual for your firmware before applying.\n';
const DRAFT_RIBBON = '# DRAFT — Ribbon SBC CLI shape. Verify the exact leaf names against the\n' +
  '# CLI Reference for your release before applying.\n';

function acme(body) { return DRAFT_ACME + txt(body).trim() + '\n'; }
function audiocodes(body) { return DRAFT_AC + txt(body).trim() + '\n'; }
function ribbon(body) { return DRAFT_RIBBON + txt(body).trim() + '\n'; }

const VENDOR_ORDER = ['oracle-acme', 'audiocodes', 'ribbon', 'cisco-cube', 'freeswitch', 'asterisk'];

/**
 * Order fixes so the platform the capture actually names comes first, then
 * generic advice, then network/endpoint, then the other vendors (kept because
 * translating a fix across dialects is half the point of the tool).
 */
function orderFixes(ctx, fixes) {
  const seen = ctx.vendors;
  const score = (f) => {
    const t = txt(f && f.target);
    if (seen.has(t)) return 0;
    if (t === 'generic') return 1;
    if (t === 'network' || t === 'endpoint') return 2;
    const i = VENDOR_ORDER.indexOf(t);
    return 3 + (i === -1 ? 9 : i);
  };
  return arr(fixes)
    .filter(f => f && txt(f.summary))
    .map((f, i) => ({ f, i }))
    .sort((x, y) => score(x.f) - score(y.f) || x.i - y.i)
    .map(x => x.f)
    .slice(0, MAX_FIXES);
}

// ---------------------------------------------------------------------------
// THE RULE TABLE
//
// One entry per row of the ARCHITECTURE.md §Advice condition table, plus a few
// extras the evidence supports (box-wide storm, slow far end, Q.850/ISUP
// release causes, correlation ambiguity, uncovered indicator faults).
//
// A rule is { id, severityHint, kb, when(analysis, ctx) -> matches[],
//             build(match, analysis, ctx) -> partial Advice }.
// Citations are attached from CITATIONS[rule.id] by buildAdvice; a build() may
// add match-specific ones via `extraCitations`.
// ---------------------------------------------------------------------------

const RULES = [];

// --- 1. INVITE retransmitted to Timer B with no response at all ------------
RULES.push({
  id: 'invite-timer-b-no-100',
  kb: ['INVITE timeout', 'no response', 'access control list', 'session agent unreachable', 'Timer B'],
  when: (analysis, ctx) => collapseMatches(ctx, ['never-arrived']),
  build: (m, analysis, ctx) => {
    const s = obj(m.sample);
    const cls = obj(s.classification);
    const abandoned = m.spanS >= 28;
    const timer = txt(s.method) === 'INVITE' ? 'Timer B' : 'Timer F';
    return {
      severity: 'crit',
      title: txt(s.method || 'Request') + ' retransmitted ×' + (m.maxCount || 2) +
        ' to ' + m.dst + ' with no response at all',
      whatsWrong: 'hiccup collapsed ' + m.collapses.length + ' retransmission group' +
        (m.collapses.length === 1 ? '' : 's') + ' on ' + m.legIds.length + ' leg' +
        (m.legIds.length === 1 ? '' : 's') + ': "' + txt(s.label) + '". ' + txt(cls.detail) +
        ' Not even a 100 Trying came back, which is the strongest single signal in a SIP trace: ' +
        'nothing at the far end ever processed the request.',
      whyItMatters: abandoned
        ? 'The caller hears silence for ' + fmtS(m.spanS) + ' and then a failure tone or announcement, ' +
          'because the transaction is abandoned when ' + timer + ' fires at 32s. From the caller\'s side ' +
          'this is indistinguishable from "the number is dead".'
        : 'Call setup stalls with no progress indication at all; if the pattern continues the transaction ' +
          'will be abandoned at 32s (' + timer + ') and the caller gets a failure they cannot explain.',
      mechanism: 'A client INVITE transaction starts Timer A at T1 (500 ms) and doubles it on every ' +
        'retransmission (500 ms, 1 s, 2 s, 4 s…), while Timer B = 64×T1 = 32 s caps the whole transaction. ' +
        'Any SIP element that receives and parses an INVITE is expected to answer — a proxy or B2BUA emits ' +
        '100 Trying almost immediately. Byte-identical retransmissions with zero responses therefore mean ' +
        'the request is being dropped BEFORE any SIP stack sees it (packet filter, SBC access control, ' +
        'source address not provisioned as a trusted peer, wrong port or transport) or the replies are ' +
        'being dropped on the return path. It is a reachability problem, not a signalling disagreement.',
      fixes: [
        {
          target: 'oracle-acme',
          summary: 'Confirm the destination is a provisioned session-agent in a realm that trusts this source, then check the ACL and OOS state.',
          steps: [
            'ACLI: `show sipd errors` and `show sipd status` — look for rising "Trans Expire" / retransmission counters against this peer.',
            '`show session-agent` (or `show sa stats <hostname>`) — a session agent in an out-of-service state silently swallows traffic.',
            'Verify a session-agent exists for ' + m.dst + ' and that its realm-id matches the egress realm; unprovisioned peers are dropped pre-classification.',
            'Check `access-control` entries and the realm\'s trust level for the SOURCE address if this is the ingress direction.',
          ],
          config: acme(
            'session-agent\n' +
            '  hostname            ' + txt(m.dst).replace(/:\d+$/, '') + '\n' +
            '  ip-address          ' + txt(m.dst).replace(/:\d+$/, '') + '\n' +
            '  realm-id            PEER\n' +
            '  ping-method         OPTIONS;hops=0\n' +
            '  ping-interval       30\n' +
            '  ping-in-service-response-codes  200\n' +
            '  out-service-response-codes      408,503'),
          caution: 'Enabling OPTIONS pings adds keepalive traffic and can mark a peer out of service if it does not answer OPTIONS at all — check with the peer first.',
          confidence: 'possible',
        },
        {
          target: 'audiocodes',
          summary: 'Check the Proxy Set / IP Group for this peer and the firewall (Access List) rules on the SIP interface.',
          steps: [
            'Setup > Signaling & Media > Core Entities > Proxy Sets: confirm the address ' + m.dst + ' and its transport type match what is on the wire.',
            'Enable Proxy Keep-Alive on the Proxy Set so the device tells you the peer is unreachable instead of silently retrying.',
            'Setup > IP Network > Security > Firewall: an Access List entry that does not cover this peer\'s subnet drops the packets before SIP.',
            'Check the Syslog with "SBC" and "Message Manipulation" trace levels raised — a rejected message is logged even when no response is sent.',
          ],
          config: audiocodes(
            '[ ProxySet ]\n' +
            'ProxySet 1 = "PEER_TRUNK", , , 1, 60, 0, 0, 1;\n' +
            '; fields shown positionally for shape only — set via the Web UI or\n' +
            '; the structured CLI: ProxyEnableKeepAlive=1, ProxyKeepAliveTime=60\n' +
            '[ ProxyIP ]\n' +
            'ProxyIP 1 = "' + txt(m.dst) + '", 0, 1;'),
          caution: 'Widening the Access List weakens the device\'s edge protection — scope any new entry to the peer\'s exact prefix.',
          confidence: 'possible',
        },
        {
          target: 'ribbon',
          summary: 'Verify the Signaling Group / SIP Trunk Group accepts this peer and that the far-end IP prefix is federated.',
          steps: [
            '`show table addressContext default zone <ZONE> sipTrunkGroup <TG> status` — check state and the peer\'s reachability.',
            'Confirm the trunk group\'s ingress IP prefix list covers the source address; traffic from an unlisted prefix is discarded before SIP processing.',
            'Check the SIP signalling port\'s state and that the transport (UDP/TCP/TLS) matches the peer.',
          ],
          config: ribbon(
            'set addressContext default zone PEER_ZONE sipTrunkGroup PEER_TG \\\n' +
            '    ingressIpPrefix ' + txt(m.dst).replace(/:\d+$/, '') + ' 32\n' +
            'set addressContext default zone PEER_ZONE sipTrunkGroup PEER_TG state enabled mode inService\n' +
            'commit'),
          caution: 'An over-broad ingressIpPrefix accepts signalling from hosts you did not intend to trust.',
          confidence: 'depends-on-topology',
        },
        {
          target: 'network',
          summary: 'Prove the path in both directions — most "never arrived" cases are a one-way firewall or NAT rule.',
          steps: [
            'Capture simultaneously at the far end (or at the next hop) and confirm whether the INVITE arrives at all.',
            'Check that the firewall permits UDP/TCP ' + (txt(m.dst).split(':')[1] || '5060') + ' in BOTH directions, and that no stateful rule expired.',
            'Look for asymmetric routing: replies leaving via a different interface than the requests arrived on will be dropped by a stateful device.',
            'If a NAT sits in the path, confirm the SBC advertises its public address and that the pinhole is kept alive.',
          ],
          config: null,
          caution: null,
          confidence: 'likely',
        },
      ],
      findingIds: findingIdsBy(ctx, f => f.category === 'retrans' && intersects(f.msgIds, m.msgIds)),
      legIds: m.legIds, callIds: m.callIds, msgIds: m.msgIds.slice(0, 12),
    };
  },
});

// --- 2. Oversized UDP request (fragmentation) ------------------------------
RULES.push({
  id: 'udp-oversize',
  kb: ['UDP fragmentation', 'MTU', '1300 bytes', 'switch to TCP', 'large INVITE SDP'],
  when: (analysis, ctx) => {
    const out = [];
    for (const g of collapseMatches(ctx, ['udp-fragmentation'])) { g.confirmed = true; out.push(g); }
    if (out.length < MAX_MATCHES_PER_RULE) {
      for (const g of diffMatches(ctx, ['udp-frag-risk'])) { g.confirmed = false; out.push(g); }
    }
    return out.slice(0, MAX_MATCHES_PER_RULE);
  },
  build: (m, analysis, ctx) => {
    const confirmed = !!m.confirmed;
    const sample = obj(m.sample);
    const sizeText = confirmed
      ? (m.size !== null ? m.size + ' bytes' : 'over 1300 bytes')
      : txt(obj(m.item).ingress || obj(m.item).egress || 'over 1300 bytes');
    return {
      severity: confirmed ? 'crit' : 'warn',
      title: confirmed
        ? 'Oversized UDP ' + m.what + ' to ' + m.dst + ' gets no response — IP fragmentation'
        : 'SIP request exceeds the safe UDP size (' + sizeText + ') — fragmentation risk',
      whatsWrong: confirmed
        ? 'The ' + m.what + ' is ' + sizeText + ' on UDP and was retransmitted ×' + (m.maxCount || 2) +
          ' to ' + m.dst + ' with no response: "' + txt(sample.label) + '". ' + txt(obj(sample.classification).detail)
        : 'A SIP INVITE on this pair of legs is ' + sizeText + ' — over the 1300-byte limit at which RFC 3261 ' +
          'requires a congestion-controlled transport. ' + txt(obj(m.item).detail) +
          (m.calls > 1 ? ' Seen on ' + m.calls + ' calls.' : ''),
      whyItMatters: confirmed
        ? 'Calls to this destination fail at setup with no error anywhere in the SIP trace, which sends engineers ' +
          'hunting for a signalling fault that does not exist — the message never arrived intact. It usually ' +
          'appears suddenly after a change that grew the INVITE (extra P-headers, a longer codec list, ' +
          'History-Info, or an ISUP body).'
        : 'It works until it does not: the moment a firewall, NAT or tunnel in the path stops passing IP fragments, ' +
          'every call over this trunk fails at setup, and the trace looks like a dead far end.',
      mechanism: 'IP fragments after the first carry no UDP header, so they have no port numbers. Stateful ' +
        'firewalls, NAT devices and load balancers routinely drop them, and many SBCs will not reassemble them ' +
        'either. RFC 3261 §18.1.1 therefore requires a client sending a request within 200 bytes of the path MTU ' +
        '(or larger than 1300 bytes when the MTU is unknown) to use a congestion-controlled transport such as TCP ' +
        'instead. Because the retransmissions are identical, every attempt fragments the same way and fails the ' +
        'same way — the pattern is a flat line of retransmissions with no response at all.',
      fixes: [
        {
          target: 'generic',
          summary: 'Move this trunk to TCP (or TLS) — it is the fix the RFC actually prescribes.',
          steps: [
            'Agree TCP with the peer, then change the trunk/peer transport on both sides.',
            'If the peer only supports UDP, shrink the message instead: remove non-essential P-headers, trim the offered codec list, and drop History-Info/Diversion chains you do not need downstream.',
            'Re-test and confirm the INVITE is now under ~1300 bytes on the wire (hiccup shows the byte size on every message).',
          ],
          config: null,
          caution: 'Switching transport changes NAT/keepalive behaviour and may need new firewall rules; TCP also changes how quickly failures are detected.',
          confidence: 'likely',
        },
        {
          target: 'oracle-acme',
          summary: 'Set the session-agent/sip-interface transport to TCP and trim the egress message with a codec policy plus a manipulation.',
          steps: [
            'Set the session-agent for this peer to `transport-method StaticTCP` (and add a TCP port to the sip-interface).',
            'Apply a `codec-policy` on the egress realm to cut the offered codec list down to what the peer will actually use.',
            'Add an out-manipulation that deletes bulky headers you do not need on this trunk (History-Info, Diversion chains, vendor X-headers).',
            'Re-check with `show sipd status` that retransmissions to this peer stop.',
          ],
          config: acme(
            'session-agent\n' +
            '  hostname            ' + txt(m.dst || 'peer').replace(/:\d+$/, '') + '\n' +
            '  transport-method    StaticTCP\n' +
            '  realm-id            PEER\n' +
            '\n' +
            'codec-policy\n' +
            '  name                TRIM-EGRESS\n' +
            '  allow-codecs        PCMA PCMU telephone-event\n' +
            '  order-codecs        PCMA PCMU'),
          caution: 'A narrower codec policy can force transcoding (DSP load) if the peer does not support what is left in the list.',
          confidence: 'possible',
        },
        {
          target: 'audiocodes',
          summary: 'Change the Proxy Set transport to TCP and reduce the SDP with an Allowed Coders list.',
          steps: [
            'Setup > Signaling & Media > Core Entities > Proxy Sets > this peer: set Transport Type to TCP (and enable a TCP SIP Interface).',
            'Setup > Signaling & Media > Coders & Profiles > Allowed Audio Coders: bind a short list to the IP Profile for this peer.',
            'Use a Message Manipulation rule to remove bulky headers on egress.',
          ],
          config: audiocodes(
            '[ SIPInterface ]\n' +
            '; add a TCP port on the interface used for this peer\n' +
            'SIPInterface 1 = "ITSP", ..., 5060, 5060, 0;   ; UDP, TCP, TLS ports\n' +
            '[ ProxySet ]\n' +
            '; ProxySet_TransportType: 0=UDP 1=TCP 2=TLS\n' +
            'ProxySet 1 = "ITSP_PROXY", , , , , , , 1;\n' +
            '[ IPProfile ]\n' +
            '; bind a short Allowed Coders group to cut SDP size\n' +
            'IPProfile 1 = "ITSP", ..., SBCAllowedAudioCodersList="AC_SHORT";'),
          caution: 'The positional .ini rows differ between firmware versions — set these in the Web UI or structured CLI and use this only as a shape reference.',
          confidence: 'possible',
        },
        {
          target: 'network',
          summary: 'If UDP must stay, make the path fragment-safe.',
          steps: [
            'Confirm whether fragments survive: capture at the far end and look for the second fragment.',
            'Permit IPv4 fragments explicitly on the firewalls in the path, or lower the SBC interface MTU so the message fragments earlier and more predictably.',
            'Check for tunnels (IPsec/GRE) reducing the effective MTU below 1500.',
          ],
          config: null,
          caution: 'Allowing fragments through a firewall reduces its ability to filter; treat it as a stopgap while the trunk moves to TCP.',
          confidence: 'depends-on-topology',
        },
      ],
      findingIds: confirmed
        ? findingIdsBy(ctx, f => f.category === 'retrans' && intersects(f.msgIds, m.msgIds))
        : findingIdsBy(ctx, f => f.category === 'diff' && txt(f.title) === txt(obj(m.item).label)),
      legIds: m.legIds, callIds: m.callIds, msgIds: arr(m.msgIds).slice(0, 12),
    };
  },
});

// --- 3. 200 OK retransmitting, ACK never lands -----------------------------
RULES.push({
  id: 'two-hundred-no-ack',
  kb: ['200 OK retransmission', 'ACK not received', 'Contact', 'Record-Route', 'topology hiding', 'call drops after 32 seconds'],
  when: (analysis, ctx) => collapseMatches(ctx, ['ack-not-landing']),
  build: (m, analysis, ctx) => {
    const s = obj(m.sample);
    const eventuallyAcked = txt(s.outcome) === 'eventually-acked';
    return {
      severity: 'crit',
      title: eventuallyAcked
        ? 'ACK arrives late — the 2xx had to be retransmitted ' + (m.maxCount || 2) + '×'
        : 'Call answers then dies: the 200 OK is retransmitted and the ACK never arrives',
      whatsWrong: '"' + txt(s.label) + '" on leg ' + txt(s.legId) + '. ' + txt(obj(s.classification).detail),
      whyItMatters: eventuallyAcked
        ? 'The answering side keeps resending the 200 OK, so the media path may start late and the caller hears ' +
          'clipped or missing first words. If the loss gets slightly worse, the same fault becomes a call that ' +
          'drops at ~32 seconds.'
        : 'This is the classic "the call answers, we talk for half a minute, then it drops" ticket. The answering ' +
          'side gives up 32 s after the first 200 OK and tears the call down with a BYE, even though audio may ' +
          'have been flowing the whole time — which is exactly why users report it as a "random drop" rather ' +
          'than a setup failure.',
      mechanism: 'A UAS that accepts an INVITE retransmits the 2xx, starting at T1 and doubling up to T2, until ' +
        'it receives an ACK; after 64×T1 it declares the dialog dead and sends a BYE. The ACK for a 2xx is a ' +
        'separate end-to-end transaction: the UAC sends it to the URI in the 2xx Contact header, routed through ' +
        'the Record-Route set collected during setup. So a 2xx that keeps repeating means the ACK is being ' +
        'addressed somewhere it cannot reach — a Contact rewritten to an internal address by topology hiding, ' +
        'a Record-Route entry the far side cannot route to, an SBC that did not insert itself in the route set, ' +
        'or a firewall pinhole that only permits the direction the INVITE travelled.',
      fixes: [
        {
          target: 'generic',
          summary: 'Read the 2xx Contact and the Record-Route set, then check that address is reachable from the side that must send the ACK.',
          steps: [
            'Open the 200 OK in hiccup and note the Contact URI host and every Record-Route entry.',
            'From the ACK sender\'s network, confirm that address is routable and that the port is open (an OPTIONS ping is the quickest test).',
            'If the Contact host is a private address, this is a topology-hiding leak — see the private-IP advice on this capture.',
            'Compare the ACK\'s Request-URI in the trace against the Contact you just read; if they differ, something rewrote one of them.',
          ],
          config: null,
          caution: null,
          confidence: 'likely',
        },
        {
          target: 'oracle-acme',
          summary: 'Make sure the SBC presents its own steering address in Contact and stays in the route set for that realm.',
          steps: [
            'Check any out-manipulation touching Contact or Record-Route — a header-rule that "cleans up" Contact is the usual culprit.',
            'Confirm the sip-interface for the realm has the correct `sip-port` address and that NAT handling advertises the public address on the outside realm.',
            '`show sipd errors` — a rising "no ACK" / transaction-expire count against one realm localises the leg.',
            'If the peer is behind NAT, ensure latching/NAT traversal is enabled so in-dialog requests follow the learned source address.',
          ],
          config: acme(
            'sip-manipulation\n' +
            '  name                  RESTORE-CONTACT\n' +
            '  header-rule\n' +
            '    name                fixContact\n' +
            '    header-name         Contact\n' +
            '    action              manipulate\n' +
            '    msg-type            reply\n' +
            '    element-rule\n' +
            '      name              host\n' +
            '      type              uri-host\n' +
            '      action            replace\n' +
            '      new-value         $LOCAL_SIP_INTERFACE_ADDRESS'),
          caution: 'Rewriting Contact affects every in-dialog request for that leg — test on one trunk before applying at the realm level.',
          confidence: 'depends-on-topology',
        },
        {
          target: 'audiocodes',
          summary: 'Review how the IP Profile represents the remote party and confirm NAT handling on that SIP interface.',
          steps: [
            'Setup > Signaling & Media > Coders & Profiles > IP Profiles: check `SBCRemoteRepresentationMode` for this peer — "Replace Contact" vs "As Is" changes exactly which address the ACK is aimed at.',
            'Verify the SIP Interface\'s NAT settings (and the device\'s public address) if the leg crosses NAT.',
            'Check Message Manipulations for a rule acting on Contact in the response direction.',
          ],
          config: audiocodes(
            '[ IPProfile ]\n' +
            '; SBCRemoteRepresentationMode: 0=Add Routing Headers, 1=Replace Contact, 2=As Is\n' +
            'IPProfile 1 = "ITSP", ..., SBCRemoteRepresentationMode=1;'),
          caution: 'Changing remote representation alters the addresses the peer sees for the whole dialog; coordinate with the peer.',
          confidence: 'possible',
        },
        {
          target: 'ribbon',
          summary: 'Check the trunk group\'s NAT/Contact handling and any SMM rule rewriting Contact or Record-Route on responses.',
          steps: [
            'Inspect the outbound `sipAdaptorProfile` (SMM) bound to this trunk group for rules touching Contact or Record-Route.',
            'Confirm the IP Signaling Profile\'s NAT traversal flags match the topology of that leg.',
            '`show table addressContext default zone <ZONE> sipTrunkGroup <TG> status` for retransmission and transaction-timeout counters.',
          ],
          config: ribbon(
            'show table addressContext default zone PEER_ZONE sipTrunkGroup PEER_TG status\n' +
            '# then review the outbound SMM profile bound to the trunk group:\n' +
            'show profiles signaling sipAdaptorProfile <SMM_NAME>'),
          caution: null,
          confidence: 'depends-on-topology',
        },
        {
          target: 'network',
          summary: 'Open the return path for in-dialog requests.',
          steps: [
            'Confirm the firewall permits SIP from the ACK sender towards the Contact address, not just the original INVITE direction.',
            'Check NAT bindings are still alive at answer time (a 30 s UDP idle timeout is a common cause when setup was slow).',
            'Rule out asymmetric routing between the signalling addresses used at setup and at answer.',
          ],
          config: null,
          caution: null,
          confidence: 'possible',
        },
      ],
      findingIds: findingIdsBy(ctx, f => f.category === 'retrans' && intersects(f.msgIds, m.msgIds)),
      legIds: m.legIds, callIds: m.callIds, msgIds: m.msgIds.slice(0, 12),
    };
  },
});

// --- 4. Route set / Contact mismatch after topology hiding ------------------
RULES.push({
  id: 'route-set-mismatch',
  kb: ['Record-Route', 'route set', 'ACK Request-URI', 'topology hiding', 'in-dialog routing'],
  when: (analysis, ctx) => {
    const out = [];
    for (const leg of ctx.legs) {
      if (!leg || leg.protocol !== 'sip' || leg.kind !== 'call') continue;
      const msgs = originals(legMsgs(ctx, leg));
      let twoxx = null;
      for (const m of msgs) {
        if (!m.isRequest && num(m.status) !== null && m.status >= 200 && m.status < 300 &&
            txt(obj(m.cseq).method) === 'INVITE') { twoxx = m; break; }
      }
      if (twoxx) {
        const contactHost = uriHost(hdr(twoxx, 'Contact'));
        let ack = null;
        for (const m of msgs) {
          if (m.isRequest && txt(m.method) === 'ACK' && obj(m.cseq).num === obj(twoxx.cseq).num) { ack = m; break; }
        }
        const ackHost = ack ? uriHost(ack.requestUri) : null;
        if (contactHost && ackHost && contactHost !== ackHost && arr(ack.routes).length === 0) {
          out.push({
            kind: 'ack-target', legId: leg.id, contactHost, ackHost,
            msgIds: [twoxx.id, ack.id],
          });
        }
      }
      // private address surviving in a Record-Route set on a leg whose peer is public
      for (const m of msgs) {
        const rrs = arr(m.recordRoutes).concat(hdrs(m, 'Record-Route'));
        for (const rr of rrs) {
          const h = uriHost(rr);
          if (h && isPrivateIp(h) && !isPrivateIp(leg.dst) && !isPrivateIp(leg.src)) {
            out.push({ kind: 'rr-private', legId: leg.id, rrHost: h, msgIds: [m.id] });
            break;
          }
        }
        if (out.length >= MAX_MATCHES_PER_RULE) break;
      }
      if (out.length >= MAX_MATCHES_PER_RULE) break;
    }
    // de-duplicate per leg+kind
    const seen = new Set();
    return out.filter(x => {
      const k = x.kind + x.legId;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    }).slice(0, MAX_MATCHES_PER_RULE);
  },
  build: (m, analysis, ctx) => {
    const callIds = ctx.calls.filter(c => arr(c.legIds).indexOf(m.legId) !== -1).map(c => c.id);
    if (m.kind === 'rr-private') {
      return {
        severity: 'warn',
        title: 'Record-Route set carries a private address (' + m.rrHost + ') on a public leg',
        whatsWrong: 'Leg ' + m.legId + ' talks to a public peer, but its Record-Route set contains ' +
          m.rrHost + ', which is not routable outside your network. Topology hiding either did not run on ' +
          'this header or ran before the address was inserted.',
        whyItMatters: 'The far end must send in-dialog requests (ACK, BYE, re-INVITE, UPDATE) through that ' +
          'route set. Pointed at an unroutable address, those requests vanish: calls answer and then drop, ' +
          'or hang after the far end tries to hang up. It also tells the peer more about your internal ' +
          'network than it should know.',
        mechanism: 'Every proxy or B2BUA that wants to stay on the path inserts a Record-Route with an address ' +
          'the NEXT hop can reach; UAs copy that list into the dialog\'s route set and use it for the rest of ' +
          'the dialog. RFC 5658 exists precisely because a device with two interfaces (inside and outside) has ' +
          'to insert a DIFFERENT address per side — the "double Record-Route" pattern. Getting it wrong is one ' +
          'of the most common SBC misconfigurations, and it only shows up after the call is answered.',
        fixes: routeFixes(ctx, m),
        findingIds: findingIdsBy(ctx, f => intersects(f.legIds, [m.legId]) && /record-route|topology|private/i.test(txt(f.title))),
        legIds: [m.legId], callIds, msgIds: m.msgIds,
        extraCitations: [cite(REFS.private_addr, 'The address in the route set is from the private space this section defines; it cannot be reached from the public peer.')],
      };
    }
    return {
      severity: 'warn',
      title: 'ACK is aimed at ' + m.ackHost + ' but the 2xx Contact said ' + m.contactHost,
      whatsWrong: 'On leg ' + m.legId + ' the 200 OK offered Contact host ' + m.contactHost + ', yet the ACK ' +
        'for that transaction was sent to ' + m.ackHost + ' with no Route header present. Something between ' +
        'the two rewrote the target, or the dialog\'s route set was not built from the response.',
      whyItMatters: 'If the ACK does not reach the answering side, that side keeps retransmitting the 200 OK ' +
        'and tears the call down about 32 seconds after answer — audio can be perfectly fine right up to the ' +
        'moment it drops, which is why this fault is so often blamed on the network.',
      mechanism: 'The ACK for a 2xx is sent directly to the Contact URI from the response, traversing the ' +
        'dialog route set built from the Record-Route headers. A B2BUA doing topology hiding must rewrite ' +
        'Contact consistently and record-route with the correct per-interface address, or the two sides end ' +
        'up with route sets that do not agree. A mismatch with no Route header usually means the route set ' +
        'was lost (header stripped, or a manipulation ran on the response) rather than deliberately loose ' +
        'routing.',
      fixes: routeFixes(ctx, m),
      findingIds: findingIdsBy(ctx, f => intersects(f.msgIds, m.msgIds)),
      legIds: [m.legId], callIds, msgIds: m.msgIds,
    };
  },
});

/** Shared fix list for the route-set rule (both flavours want the same actions). */
function routeFixes(ctx, m) {
  return [
    {
      target: 'generic',
      summary: 'Compare the Record-Route/Contact addresses per interface and make each side receive an address it can reach.',
      steps: [
        'For each leg, list the Record-Route entries the peer receives and confirm every one is routable from that peer.',
        'Confirm the B2BUA inserts its INSIDE address towards the inside leg and its OUTSIDE address towards the outside leg (RFC 5658 double Record-Route).',
        'Check for header manipulations acting on Contact or Record-Route in the response direction — they are the usual cause.',
      ],
      config: null,
      caution: null,
      confidence: 'likely',
    },
    {
      target: 'oracle-acme',
      summary: 'Verify the sip-interface addresses per realm and any manipulation touching Contact/Record-Route.',
      steps: [
        'Check each realm\'s sip-interface `sip-port` address — that is what lands in Record-Route for that side.',
        'Review out-manipulations for header-rules on Contact or Record-Route; delete/replace actions there break in-dialog routing.',
        'If a NAT is in front of the outside realm, confirm the interface advertises the public address.',
      ],
      config: acme(
        'sip-interface\n' +
        '  realm-id            OUTSIDE\n' +
        '  sip-port\n' +
        '    address           203.0.113.5\n' +
        '    port              5060\n' +
        '    transport-protocol UDP\n' +
        '# and the inside realm gets its own sip-interface with the inside address'),
      caution: 'Changing a sip-interface address requires the peer\'s ACLs to be updated too.',
      confidence: 'depends-on-topology',
    },
    {
      target: 'audiocodes',
      summary: 'Check the SIP Interface bound to each IP Group and the remote-representation mode.',
      steps: [
        'Setup > Signaling & Media > Core Entities > SIP Interfaces: confirm the interface (and its network interface address) used per leg.',
        'IP Profiles: review `SBCRemoteRepresentationMode` for the peer — it decides whether Contact is replaced or passed through.',
        'Check Message Manipulations acting on Contact / Record-Route for the response direction.',
      ],
      config: null,
      caution: null,
      confidence: 'possible',
    },
    {
      target: 'ribbon',
      summary: 'Review the SMM profile and the trunk group\'s signalling address for the leg.',
      steps: [
        'Inspect the outbound sipAdaptorProfile bound to the trunk group for rules on Contact/Record-Route.',
        'Confirm the SIP signalling port address used per zone is reachable from that zone\'s peers.',
      ],
      config: null,
      caution: null,
      confidence: 'depends-on-topology',
    },
  ];
}

// --- 5. 100rel / PRACK asymmetry -------------------------------------------
RULES.push({
  id: 'prack-100rel-asymmetry',
  kb: ['100rel', 'PRACK', 'reliable provisional response', '420 Bad Extension', 'interworking'],
  when: (analysis, ctx) => diffMatches(ctx, ['100rel-asymmetry']),
  build: (m, analysis, ctx) => {
    const it = obj(m.item);
    return {
      severity: it.severity === 'crit' ? 'crit' : (it.severity === 'warn' ? 'warn' : 'notice'),
      title: '100rel posture differs between the two legs (' + txt(it.ingress) + ' vs ' + txt(it.egress) + ')',
      whatsWrong: 'Ingress leg: ' + txt(it.ingress) + '. Egress leg: ' + txt(it.egress) + '. ' + txt(it.detail) +
        (m.calls > 1 ? ' Seen on ' + m.calls + ' calls.' : ''),
      whyItMatters: 'Reliable provisional responses are what make ringback, early announcements and ' +
        'preconditions dependable. When one leg requires 100rel and the other does not offer it, the SBC has ' +
        'to invent the missing half: either it absorbs PRACKs the far end never sees, or the call is rejected ' +
        'with 420 Bad Extension. The visible symptoms are missing ringback, an early announcement that never ' +
        'plays, or setup failures that only affect one direction.',
      mechanism: 'RFC 3262 negotiates reliability per dialog: a UAC advertises `Supported: 100rel` or insists ' +
        'with `Require: 100rel`, and a UAS that sends a reliable 1xx includes RSeq, which the UAC must ' +
        'acknowledge with PRACK before the dialog moves on. A B2BUA terminates that negotiation on each leg ' +
        'independently, so it must interwork the two: turn a reliable 18x on one side into an unreliable one ' +
        'on the other and locally generate the PRACK. If the box is configured to pass the extension through ' +
        'unchanged, a `Require: 100rel` arriving at a peer that does not support it earns a 420, and a peer ' +
        'that requires it will never see the acknowledgement it is waiting for.',
      fixes: [
        {
          target: 'oracle-acme',
          summary: 'Turn on 100rel interworking on the sip-interface facing the leg that lacks the extension.',
          steps: [
            'Identify which realm lacks 100rel (hiccup shows it per leg above).',
            'Add the `100rel-interworking` option to that sip-interface so the SBC terminates PRACK locally.',
            'Re-test a call and confirm the 18x is reliable on the requiring side and plain on the other.',
          ],
          config: acme(
            'sip-interface\n' +
            '  realm-id            PEER\n' +
            '  options             +100rel-interworking'),
          caution: 'Interworking makes the SBC answer PRACKs itself, so end-to-end reliability guarantees no longer span both legs.',
          confidence: 'likely',
        },
        {
          target: 'audiocodes',
          summary: 'Set the PRACK mode on the IP Profile for the peer that does not support 100rel.',
          steps: [
            'Setup > Signaling & Media > Coders & Profiles > IP Profiles > this peer.',
            'Set `SBCPrackMode` — Optional/Mandatory/Transparent decide whether the device negotiates on the peer\'s behalf or passes the extension straight through.',
            'Use "Transparent" only when both peers genuinely agree on 100rel.',
          ],
          config: audiocodes(
            '[ IPProfile ]\n' +
            '; SBCPrackMode: 1=Optional, 2=Mandatory, 3=Transparent\n' +
            'IPProfile 1 = "ITSP", ..., SBCPrackMode=1;'),
          caution: 'Mandatory mode will reject peers that cannot do 100rel at all.',
          confidence: 'likely',
        },
        {
          target: 'ribbon',
          summary: 'Set the reliable-provisional-response behaviour in the IP Signaling Profile bound to that trunk group.',
          steps: [
            'Locate the ipSignalingProfile bound to the trunk group for the leg lacking 100rel.',
            'Adjust its provisional-response / 100rel flag so the SBC terminates PRACK for that side.',
            'Verify with a test call that the 18x is reliable only on the side that asks for it.',
          ],
          config: ribbon(
            '# path shape — confirm the exact flag name in your release\n' +
            'show profiles signaling ipSignalingProfile IPSP_PEER egressIpAttributes'),
          caution: null,
          confidence: 'depends-on-topology',
        },
      ],
      findingIds: findingIdsBy(ctx, f => f.category === 'diff' && txt(f.title) === txt(it.label)),
      legIds: m.legIds, callIds: m.callIds, msgIds: m.msgIds,
    };
  },
});

// --- 6. Session timer conflict / rewrite -----------------------------------
RULES.push({
  id: 'session-timer-conflict',
  kb: ['Session-Expires', 'Min-SE', '422 Session Interval Too Small', 'refresher', 'session timer'],
  when: (analysis, ctx) => diffMatches(ctx, ['session-timer-conflict', 'session-timer-changed']),
  build: (m, analysis, ctx) => {
    const it = obj(m.item);
    const conflict = m.tag === 'session-timer-conflict';
    return {
      severity: conflict ? 'warn' : 'info',
      title: conflict
        ? 'Session timer conflict across the legs: Min-SE exceeds the other side\'s Session-Expires'
        : 'Session timers rewritten between the legs (' + txt(it.ingress) + ' → ' + txt(it.egress) + ')',
      whatsWrong: 'Ingress: ' + txt(it.ingress) + '. Egress: ' + txt(it.egress) + '. ' + txt(it.detail) +
        (m.calls > 1 ? ' Seen on ' + m.calls + ' calls.' : ''),
      whyItMatters: conflict
        ? 'Expect 422 Session Interval Too Small at setup, or worse, calls that survive setup and then die at ' +
          'the first refresh — typically a clean drop after exactly the refresh interval (half of ' +
          'Session-Expires), which users report as "calls drop after 15 minutes".'
        : 'Not a fault on its own, but it decides who is responsible for keeping the call alive. If the leg that ' +
          'was made refresher stops refreshing (or its re-INVITE/UPDATE is blocked), the call is torn down ' +
          'mid-conversation and each side blames the other.',
      mechanism: 'RFC 4028 gives a session a lifetime: Session-Expires is the interval after which the session ' +
        'is considered dead unless refreshed, `refresher=uac|uas` says which end must refresh (each end refreshes ' +
        'at roughly half the interval), and Min-SE is the smallest interval a party will accept. A UAS or proxy ' +
        'that receives a Session-Expires below its own Min-SE rejects the request with 422 and states its Min-SE ' +
        'in the response, and the UAC is expected to retry with the larger value. A B2BUA negotiates timers ' +
        'separately per leg, so an ingress Min-SE larger than the egress Session-Expires can never be satisfied ' +
        'end-to-end — and a rewritten refresher role means the refresh may be expected from a party that has no ' +
        'intention of sending one.',
      fixes: [
        {
          target: 'oracle-acme',
          summary: 'Use a session-timer-profile per realm so both legs agree, instead of letting the peers negotiate blind.',
          steps: [
            'Create a session-timer-profile with a Session-Expires the far end will accept and a Min-SE no larger than it.',
            'Bind it to the sip-interface or session-agent for each side.',
            'Decide deliberately which side refreshes; if the peer will not refresh, make the SBC the refresher.',
          ],
          config: acme(
            'session-timer-profile\n' +
            '  name                PEER-TIMERS\n' +
            '  session-expires     1800\n' +
            '  min-se              90\n' +
            '  force-reinvite      enabled\n' +
            '  refresher           uac'),
          caution: 'Forcing re-INVITE refreshes doubles mid-call signalling and can disturb peers that answer refreshes badly.',
          confidence: 'likely',
        },
        {
          target: 'audiocodes',
          summary: 'Align the SBC session-expires / Min-SE values with the peer and choose the refresher explicitly.',
          steps: [
            'Setup > Signaling & Media > SIP Definitions > General: set the session-expires and Min-SE the device offers.',
            'Per peer, set the session-expires behaviour on the IP Profile so the value offered to that peer is inside its accepted range.',
            'Prefer UPDATE over re-INVITE for refreshes when the peer supports it (less disruptive).',
          ],
          config: audiocodes(
            '[ SIP Params ]\n' +
            'SBCSESSIONEXPIRES = 1800\n' +
            'MINSE = 90'),
          caution: 'Lowering Min-SE globally allows aggressive peers to force frequent refreshes and raise signalling load.',
          confidence: 'possible',
        },
        {
          target: 'generic',
          summary: 'Pick one interval policy for the trunk and make both sides consistent.',
          steps: [
            'Agree a Session-Expires with the peer (1800 s is the common trunk value) and set Min-SE at or below 90 s on both sides.',
            'Make sure the refresher can actually refresh: mid-call re-INVITE/UPDATE must be permitted by both firewalls and not blocked by a manipulation.',
            'If a leg has no session timer support at all, have the SBC take over refreshing locally rather than passing the headers through.',
          ],
          config: null,
          caution: null,
          confidence: 'likely',
        },
      ],
      findingIds: findingIdsBy(ctx, f => f.category === 'diff' && txt(f.title) === txt(it.label)),
      legIds: m.legIds, callIds: m.callIds, msgIds: m.msgIds,
    };
  },
});

// --- 7. telephone-event payload type mismatch ------------------------------
RULES.push({
  id: 'dtmf-pt-mismatch',
  kb: ['telephone-event', 'RFC 2833', 'RFC 4733', 'DTMF payload type 101 96', 'IVR no response'],
  when: (analysis, ctx) => diffMatches(ctx, ['dtmf-pt-mismatch', 'dtmf-missing-one-leg']),
  build: (m, analysis, ctx) => {
    const it = obj(m.item);
    const missing = m.tag === 'dtmf-missing-one-leg';
    return {
      severity: 'warn',
      title: missing
        ? 'RFC 4733 DTMF offered on one leg only (' + txt(it.ingress) + ' vs ' + txt(it.egress) + ')'
        : 'telephone-event payload type differs across the legs (' + txt(it.ingress) + ' vs ' + txt(it.egress) + ')',
      whatsWrong: 'Ingress: ' + txt(it.ingress) + '. Egress: ' + txt(it.egress) + '. ' + txt(it.detail) +
        (m.calls > 1 ? ' Seen on ' + m.calls + ' calls.' : ''),
      whyItMatters: 'Audio is fine and everybody agrees the call "works", but IVR menus, conference PINs, ' +
        'calling-card digits and voicemail passwords do nothing — or repeat digits. This is one of the most ' +
        'common trunk-interop tickets, and it is invisible unless you compare the two legs side by side.',
      mechanism: 'RFC 4733 carries DTMF as named events in RTP on a DYNAMIC payload type (96–127), agreed ' +
        'per media session through `a=rtpmap:<pt> telephone-event/8000` plus `a=fmtp:<pt> 0-15`. The number ' +
        'itself is local to each session: 101 on one leg and 96 on the other is perfectly legal. But an SBC ' +
        'relaying RTP must then rewrite the payload type on every DTMF packet as it crosses; if it forwards ' +
        'them unchanged, the far end sees a payload type it never negotiated and either discards the packets ' +
        'or decodes them as something else. When one leg has no telephone-event at all, DTMF has to be ' +
        'converted to in-band tones (needs a DSP, and fails through low-bitrate codecs) or to SIP INFO — and ' +
        'if it is configured for neither, the digits are simply dropped.',
      fixes: [
        {
          target: 'oracle-acme',
          summary: 'Set RFC 2833 mode and payload type per session-agent/realm so the SBC re-maps rather than passes through.',
          steps: [
            'Set `rfc2833-mode` to `preferred` (or `dual` where the peer needs both) on the session-agent or sip-interface for the leg that differs.',
            'Set `rfc2833-payload` to the value that peer expects (' + txt(it.egress || it.ingress) + ' here).',
            'If one leg has no telephone-event, allow in-band interworking and make sure a transcoding resource is available.',
          ],
          config: acme(
            'session-agent\n' +
            '  hostname            peer.example.net\n' +
            '  rfc2833-mode        preferred\n' +
            '  rfc2833-payload     101'),
          caution: 'Dual mode sends both in-band and RFC 4733 digits, which some endpoints register twice — use it only where a peer demands it.',
          confidence: 'likely',
        },
        {
          target: 'audiocodes',
          summary: 'Set the RFC 2833 behaviour on the IP Profile and the payload type the peer expects.',
          steps: [
            'Setup > Signaling & Media > Coders & Profiles > IP Profiles > this peer: set `SBCRFC2833Behavior` so the device adds/removes the telephone-event offer as needed.',
            'Set the RFC 2833 payload type used towards that peer (global DTMF & Dialing setting, overridden per IP Profile where supported).',
            'Where one leg lacks telephone-event, set the alternative DTMF method (in-band or SIP INFO) explicitly.',
          ],
          config: audiocodes(
            '[ IPProfile ]\n' +
            '; SBCRFC2833Behavior: 0=As Is, 1=Add, 2=Remove\n' +
            'IPProfile 1 = "ITSP", ..., SBCRFC2833Behavior=1;\n' +
            '[ DTMF Params ]\n' +
            'RFC2833PAYLOADTYPE = 101'),
          caution: 'Changing the global payload type affects every trunk on the device; prefer the per-profile setting.',
          confidence: 'likely',
        },
        {
          target: 'ribbon',
          summary: 'Make the trunk group include telephone-event in SDP and relay digits with the peer\'s payload type.',
          steps: [
            'Check the IP Signaling Profile flags controlling whether 2833 is included in the SDP offer for that trunk.',
            'Confirm the Packet Service Profile allows DTMF relay (not in-band only) for the media path.',
            'Where the peer cannot do 2833, enable the DTMF interworking that generates in-band tones.',
          ],
          config: null,
          caution: null,
          confidence: 'depends-on-topology',
        },
        {
          target: 'endpoint',
          summary: 'If the SBC is only relaying, fix the offer at the source.',
          steps: [
            'Configure the PBX/gateway to offer the same telephone-event payload type the trunk provider expects.',
            'Disable in-band DTMF on the endpoint once RFC 4733 works, so digits are not sent twice.',
          ],
          config: null,
          caution: null,
          confidence: 'possible',
        },
      ],
      findingIds: findingIdsBy(ctx, f => f.category === 'diff' && txt(f.title) === txt(it.label)),
      legIds: m.legIds, callIds: m.callIds, msgIds: m.msgIds,
    };
  },
});

// --- 8. codec narrowing / forced transcoding / ptime mismatch --------------
RULES.push({
  id: 'codec-ptime-renegotiation',
  kb: ['codec policy', 'transcoding', 'ptime', 'packetization', 'allowed coders'],
  when: (analysis, ctx) => diffMatches(ctx, ['codec-transcoding', 'ptime-mismatch', 'codec-narrowed']),
  build: (m, analysis, ctx) => {
    const it = obj(m.item);
    const sev = m.tag === 'codec-transcoding' ? 'warn' : (m.tag === 'ptime-mismatch' ? 'notice' : 'info');
    const title = m.tag === 'codec-transcoding'
      ? 'Transcoding forced: each leg answered a different codec (' + txt(it.ingress) + ' vs ' + txt(it.egress) + ')'
      : (m.tag === 'ptime-mismatch'
        ? 'Packetization differs per leg (' + txt(it.ingress) + ' vs ' + txt(it.egress) + ')'
        : 'Codec list narrowed on egress (' + txt(it.ingress) + ' → ' + txt(it.egress) + ')');
    return {
      severity: sev,
      title: title,
      whatsWrong: 'Ingress: ' + txt(it.ingress) + '. Egress: ' + txt(it.egress) + '. ' + txt(it.detail) +
        (m.calls > 1 ? ' Seen on ' + m.calls + ' calls.' : ''),
      whyItMatters: m.tag === 'codec-transcoding'
        ? 'Every call on this trunk consumes a transcoding resource. That is DSP or CPU capacity you can run out ' +
          'of (calls then fail with 488 or no media at all), it adds packetization delay, and a second ' +
          'compression stage costs measurable quality — the "our calls sound worse since the migration" report.'
        : (m.tag === 'ptime-mismatch'
          ? 'The SBC has to repacketize, which adds delay and defeats some jitter-buffer tuning. Endpoints that ' +
            'ignore the negotiated ptime send at their own rate, and you see unexplained jitter or bandwidth ' +
            'above what was planned.'
          : 'Usually intentional policy, but worth confirming: the far end never learns about the codecs you ' +
            'removed, so a peer that would have chosen a cheaper or wideband codec cannot. If the surviving ' +
            'codec is not supported end-to-end, the call needs transcoding or fails.'),
      mechanism: 'In the offer/answer model the answer must select from what the offer contained, so an SBC that ' +
        'shortens the codec list on egress permanently removes those options from the negotiation. When the two ' +
        'legs settle on different codecs the B2BUA must decode and re-encode in the middle — transcoding — ' +
        'because RTP payloads cannot simply be relabelled. `a=ptime` is an SDP attribute expressing how many ' +
        'milliseconds of audio go in each packet; it is a preference, not a contract, and mismatched values ' +
        'force the media plane to buffer and re-frame, adding delay in both directions.',
      fixes: [
        {
          target: 'oracle-acme',
          summary: 'Shape the negotiation with a codec-policy per realm so both sides can land on the same codec without a DSP.',
          steps: [
            'Define a codec-policy whose allow/order list gives both peers a common codec, and bind it to each realm.',
            'Where transcoding is genuinely required, confirm the transcoding resources (DSP capacity) and monitor usage.',
            'Set ptime deliberately in the media-profile rather than letting each side choose.',
          ],
          config: acme(
            'codec-policy\n' +
            '  name                PEER-CODECS\n' +
            '  allow-codecs        PCMA PCMU telephone-event\n' +
            '  order-codecs        PCMA PCMU\n' +
            '\n' +
            'realm-config\n' +
            '  identifier          PEER\n' +
            '  codec-policy        PEER-CODECS'),
          caution: 'A restrictive allow-list can cause 488 Not Acceptable Here when a peer offers nothing on the list.',
          confidence: 'likely',
        },
        {
          target: 'audiocodes',
          summary: 'Use Coder Groups plus Allowed Audio Coders on the IP Profile, and set the packetization in the coder entry.',
          steps: [
            'Setup > Signaling & Media > Coders & Profiles > Coder Groups: define the coder and its packetization time.',
            'Bind an Allowed Audio Coders list to the IP Profile for each peer so the offered list matches what the peer supports.',
            'Set the Allowed Coders Mode so the device restricts (rather than merely reorders) the offer where needed.',
          ],
          config: audiocodes(
            '[ CodersGroup0 ]\n' +
            'CodersGroup0 0 = "g711Alaw64k", 20, 0, -1, 0;   ; coder, ptime, rate, payload type, silence supp.\n' +
            '[ IPProfile ]\n' +
            'IPProfile 1 = "ITSP", ..., SBCAllowedAudioCodersList="AC_ITSP", SBCAllowedCodersMode=1;'),
          caution: 'Restricting coders can trigger transcoding elsewhere; check DSP resource usage after the change.',
          confidence: 'possible',
        },
        {
          target: 'ribbon',
          summary: 'Align the Packet Service Profile / codec list on both trunk groups.',
          steps: [
            'Review the codec entries and packet size configured for each trunk group\'s media profile.',
            'Where both peers share a codec, prefer pass-through and disable transcoding for that pair.',
            'Confirm DSP/transcoding resource limits if transcoding must stay.',
          ],
          config: null,
          caution: null,
          confidence: 'depends-on-topology',
        },
      ],
      findingIds: findingIdsBy(ctx, f => f.category === 'diff' && txt(f.title) === txt(it.label)),
      legIds: m.legIds, callIds: m.callIds, msgIds: m.msgIds,
      extraCitations: m.tag === 'ptime-mismatch'
        ? [cite(REFS.rtp_av_profile, 'Defines the audio payload formats and their default packetization, which is what a mismatched ptime is deviating from.')]
        : [],
    };
  },
});

// --- 9. Early media asymmetry ---------------------------------------------
RULES.push({
  id: 'early-media-asymmetry',
  kb: ['early media', '183 Session Progress', '180 Ringing', 'P-Early-Media', 'no ringback'],
  when: (analysis, ctx) => {
    const out = diffMatches(ctx, ['early-media-183', 'early-media-pem']);
    const ind = indicator(ctx, 'early-media');
    if (!out.length && ind && ind.state === 'issue') {
      out.push({ kind: 'indicator', tag: 'early-media-indicator', indicator: ind, calls: 0,
        callIds: arr(ind.evidenceCallIds), legIds: [], msgIds: arr(ind.evidenceMsgIds).slice(0, 8) });
    }
    return out;
  },
  build: (m, analysis, ctx) => {
    const it = obj(m.item);
    const fromIndicator = m.kind === 'indicator';
    const pem = m.tag === 'early-media-pem';
    return {
      severity: fromIndicator ? 'warn' : (pem ? 'info' : 'notice'),
      title: fromIndicator
        ? 'Early media detected but something about it is wrong'
        : (pem
          ? 'P-Early-Media present — early media is being explicitly authorized'
          : 'Early media asymmetry: 183 with SDP on one leg, 180 without SDP on the other'),
      whatsWrong: fromIndicator
        ? txt(obj(m.indicator).detail)
        : ('Ingress: ' + txt(it.ingress) + '. Egress: ' + txt(it.egress) + '. ' + txt(it.detail) +
           (m.calls > 1 ? ' Seen on ' + m.calls + ' calls.' : '')),
      whyItMatters: 'This decides what the caller hears between dialling and answer. Get it wrong and you get ' +
        'the two classic complaints: silence where a network announcement ("the number you have dialled...") ' +
        'should play, or ringback that starts, stops and restarts because both the SBC and the far end are ' +
        'generating it. Where the far end plays an announcement and then rejects the call, callers hear nothing ' +
        'and assume the trunk is broken.',
      mechanism: 'A 180 Ringing without SDP tells the caller\'s equipment to generate local ringback. A 183 ' +
        'Session Progress with SDP instead establishes an early media stream so the CALLEE side supplies the ' +
        'audio. RFC 3960 describes both models and why mixing them is hazardous: only one party should be ' +
        'producing the tone. A B2BUA that translates one into the other must also handle the media plane — ' +
        'opening a media path before answer, and cutting it over cleanly at the 200 OK. In IMS the ' +
        'P-Early-Media header (RFC 5009) exists to authorize that pre-answer stream per direction, because ' +
        'otherwise early media is an easy way to carry unbilled audio.',
      fixes: [
        {
          target: 'oracle-acme',
          summary: 'Set early-media policy explicitly for the realm/session-agent rather than relying on defaults.',
          steps: [
            'Set `early-media-allow` on the realm or session-agent for the leg in question (none / both / reverse) so the SBC\'s behaviour is deliberate.',
            'If the peer sends 183+SDP and your side wants 180, add a manipulation that interworks the response, and make sure the SBC generates ringback locally.',
            'Confirm media is anchored before answer so the early stream is not blocked by the media firewall.',
          ],
          config: acme(
            'realm-config\n' +
            '  identifier          PEER\n' +
            '  early-media-allow   both'),
          caution: 'Allowing early media in both directions can let audio (and cost) flow before answer — restrict it if that matters commercially.',
          confidence: 'possible',
        },
        {
          target: 'audiocodes',
          summary: 'Set the remote early-media parameters on the IP Profile for the peer.',
          steps: [
            'Setup > Signaling & Media > Coders & Profiles > IP Profiles > this peer.',
            'Set `SBCRemoteEarlyMediaSupport` (does the peer accept early media at all), `SBCRemoteEarlyMediaRTP` (does it actually send RTP before answer) and `SBCRemoteEarlyMediaResponseType` (should the device present 180 or 183).',
            'Set `SBCRemoteSupportsRFC3960` where the peer follows the gateway model.',
          ],
          config: audiocodes(
            '[ IPProfile ]\n' +
            'IPProfile 1 = "ITSP", ..., SBCRemoteEarlyMediaSupport=1, SBCRemoteEarlyMediaRTP=1,\n' +
            '                          SBCRemoteEarlyMediaResponseType=2;   ; 180 vs 183 presentation'),
          caution: 'If you present 183 to a peer that cannot handle early media, callers hear nothing at all instead of local ringback.',
          confidence: 'likely',
        },
        {
          target: 'generic',
          summary: 'Decide who owns ringback on this trunk and make both sides consistent.',
          steps: [
            'Pick one model: local ringback (180, no SDP) or far-end early media (183 with SDP).',
            'Ensure exactly one party generates tone; disable the other side\'s generator.',
            'If announcements matter (number-unobtainable, out-of-hours), you need the early-media model end to end.',
          ],
          config: null,
          caution: null,
          confidence: 'likely',
        },
      ],
      findingIds: fromIndicator
        ? findingIdsBy(ctx, f => /early media/i.test(txt(f.title)))
        : findingIdsBy(ctx, f => f.category === 'diff' && txt(f.title) === txt(it.label)),
      legIds: arr(m.legIds), callIds: arr(m.callIds), msgIds: arr(m.msgIds),
    };
  },
});

// --- 10. Private IP leaking through topology hiding ------------------------
RULES.push({
  id: 'private-ip-leak',
  kb: ['topology hiding', 'private IP in SDP', 'RFC 1918 leak', 'header manipulation', 'media anchoring'],
  when: (analysis, ctx) => diffMatches(ctx, ['private-ip-leak']),
  build: (m, analysis, ctx) => {
    const it = obj(m.item);
    const ipMatch = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/.exec(txt(it.label) + ' ' + txt(it.ingress));
    const ip = ipMatch ? ipMatch[1] : null;
    const shared = ip ? /^100\.(6[4-9]|7\d|8\d|9\d|1[01]\d|12[0-7])\./.test(ip) : false;
    return {
      severity: 'crit',
      title: 'Private address ' + (ip || '(internal)') + ' survives into the egress leg — topology hiding is incomplete',
      whatsWrong: txt(it.label) + '. ' + txt(it.detail) + ' Ingress value: ' + txt(it.ingress) +
        '; on egress it ' + txt(it.egress) + '.' + (m.calls > 1 ? ' Seen on ' + m.calls + ' calls.' : ''),
      whyItMatters: 'Two separate problems at once. Functionally, anything the far end aims at that address ' +
        'disappears: in-dialog requests (ACK, BYE, re-INVITE) and, when the leak is in the SDP, the RTP itself — ' +
        'which is the textbook cause of one-way or no audio that "only happens with this carrier". Commercially ' +
        'and from a security standpoint, you have just published your internal addressing plan to a third party, ' +
        'which is normally the whole reason the SBC is there.',
      mechanism: 'Private addresses are unrouteable on the public internet: they are reused by every network, ' +
        'so no upstream router will forward traffic to them. A B2BUA doing topology hiding is supposed to ' +
        'replace every internal address with its own on egress — in Contact, Via, Record-Route, PAI, the ' +
        'Request-URI, and inside the SDP `o=` and `c=` lines. A leak means one of those substitutions is ' +
        'missing: often the SDP (because the SBC is not anchoring media for that call, so it forwards the ' +
        'endpoint\'s own address), or a vendor/diagnostic header that no manipulation touches. Contact in ' +
        'particular must be a URI the peer can reach for the lifetime of the dialog.',
      fixes: [
        {
          target: 'oracle-acme',
          summary: 'Anchor media on the egress realm and add an out-manipulation that rewrites the remaining internal addresses.',
          steps: [
            'Confirm the egress realm is not configured for media release/pass-through — if the SBC does not anchor media, the endpoint\'s address stays in the SDP.',
            'Add an out-manipulation with a header-rule for the leaking header, and a mime-sdp-rule for the `o=` and `c=` lines.',
            'Re-run the capture through hiccup and confirm the private-ip-leak item is gone.',
          ],
          config: acme(
            'sip-manipulation\n' +
            '  name                  HIDE-TOPOLOGY\n' +
            '  header-rule\n' +
            '    name                stripInternal\n' +
            '    header-name         X-Internal-Address\n' +
            '    action              delete\n' +
            '    msg-type            any\n' +
            '  mime-sdp-rule\n' +
            '    name                fixConnection\n' +
            '    msg-type            any\n' +
            '    action              manipulate\n' +
            '    sdp-session-rule\n' +
            '      name              origin\n' +
            '      type              origin\n' +
            '      action            replace\n' +
            '      new-value         "IN IP4 203.0.113.5"'),
          caution: 'SDP manipulation collides with media anchoring — if the SBC already rewrites c=, a second rewrite can point media at the wrong address entirely. Test on one trunk.',
          confidence: 'depends-on-topology',
        },
        {
          target: 'audiocodes',
          summary: 'Make sure the peer\'s IP Group anchors media in the right Media Realm, then clean up any remaining header with a manipulation.',
          steps: [
            'Setup > Signaling & Media > Core Entities > IP Groups: check the Media Realm bound to this peer — the device should put its own address in c=.',
            'Confirm the IP Profile is not set to direct/transparent media for that peer.',
            'Add a Message Manipulation that removes or rewrites the leaking header on egress.',
          ],
          config: audiocodes(
            '[ MessageManipulations ]\n' +
            '; name, manipulation set, message type, condition, action subject, action type, action value\n' +
            'MessageManipulations 0 = "StripInternal", 2, "any", "", "header.x-internal-address", 1, "", 0;\n' +
            '; action type 1 = Remove. Bind the set via IPProfile / IPGroup outbound manipulation set.'),
          caution: 'Row ordering in this table is significant and the column layout varies by firmware — build the rule in the Web UI and use this as a shape reference.',
          confidence: 'possible',
        },
        {
          target: 'ribbon',
          summary: 'Add an outbound SMM rule on the egress trunk group and confirm media is not being released.',
          steps: [
            'Create a sipAdaptorProfile rule matching the internal address and replacing it with the SBC\'s public signalling address.',
            'Bind the profile as the outbound (egress) message manipulation on the peer\'s trunk group.',
            'Verify media lockdown/anchoring is enabled so the SDP carries the SBC\'s media address.',
          ],
          config: ribbon(
            'set profiles signaling sipAdaptorProfile HIDE_TOPOLOGY \\\n' +
            '    rule 1 criterion 1 messageBody bodyValue "' + (ip || '10.0.0.0') + '" \\\n' +
            '    rule 1 action 1 operation replace value "203.0.113.5"\n' +
            'set addressContext default zone PEER_ZONE sipTrunkGroup PEER_TG \\\n' +
            '    signaling messageManipulation outputAdapterProfile HIDE_TOPOLOGY\n' +
            'commit'),
          caution: 'A blunt body replace can hit unrelated occurrences of the same string — scope the criterion as tightly as your release allows.',
          confidence: 'depends-on-topology',
        },
      ],
      findingIds: findingIdsBy(ctx, f => f.category === 'diff' && txt(f.title) === txt(it.label)),
      legIds: m.legIds, callIds: m.callIds, msgIds: m.msgIds,
      extraCitations: shared
        ? [cite(REFS.shared_addr, 'The leaked address is in the 100.64/10 shared space used by carrier NAT — equally unrouteable for the peer.')]
        : [],
    };
  },
});

// --- 11. T.38 asymmetry / rejected fax switchover --------------------------
RULES.push({
  id: 't38-asymmetry',
  kb: ['T.38', 'fax re-INVITE', 'udptl', 'fax fallback G.711', 'V.152'],
  when: (analysis, ctx) => {
    const out = diffMatches(ctx, ['t38-asymmetry']);
    const ind = indicator(ctx, 't38');
    if (!out.length && ind && ind.state === 'issue') {
      out.push({ kind: 'indicator', tag: 't38-indicator', indicator: ind, calls: 0,
        callIds: arr(ind.evidenceCallIds), legIds: [], msgIds: arr(ind.evidenceMsgIds).slice(0, 8) });
    }
    return out;
  },
  build: (m, analysis, ctx) => {
    const it = obj(m.item);
    const fromIndicator = m.kind === 'indicator';
    return {
      severity: 'warn',
      title: fromIndicator
        ? 'T.38 present but the fax switchover did not complete'
        : 'T.38 switchover handled differently on each leg',
      whatsWrong: fromIndicator
        ? txt(obj(m.indicator).detail)
        : ('Ingress: ' + txt(it.ingress) + '. Egress: ' + txt(it.egress) + '. ' + txt(it.detail) +
           (m.calls > 1 ? ' Seen on ' + m.calls + ' calls.' : '')),
      whyItMatters: 'Faxes fail silently: the sending machine retries a few times, prints a failure report, and ' +
        'the user reports "faxes do not work" with no SIP error anywhere. Because voice calls on the same trunk ' +
        'are fine, this gets blamed on the fax machine for weeks.',
      mechanism: 'A fax call starts as an ordinary G.711 voice call. When the terminating gateway hears the ' +
        'CED/V.21 preamble it sends a re-INVITE offering `m=image <port> udptl t38`, and the media switches from ' +
        'RTP audio to T.38 packets carrying demodulated fax data. Two things break it in an SBC: the re-INVITE ' +
        'is only relayed onto one leg (so one side thinks it is doing T.38 and the other is still sending G.711), ' +
        'or the peer answers 488/415 and the SBC does not fall back cleanly to G.711 pass-through. Even when ' +
        'fallback works, G.711 pass-through fax is intolerant of jitter, packet loss and any transcoding, so it ' +
        'is not a real substitute.',
      fixes: [
        {
          target: 'audiocodes',
          summary: 'Set the fax behaviour explicitly per peer on the IP Profile.',
          steps: [
            'Setup > Signaling & Media > Coders & Profiles > IP Profiles > this peer.',
            'Set `SBCFaxBehavior`, `SBCFaxCodersGroupName`, `SBCFaxOfferMode` and `SBCFaxAnswerMode` so the device knows whether to negotiate T.38, pass it through, or force G.711.',
            'Enable renegotiation on fax detection where the peer expects the SBC to initiate the switch.',
          ],
          config: audiocodes(
            '[ IPProfile ]\n' +
            'IPProfile 1 = "ITSP", ..., SBCFaxBehavior=1, SBCFaxCodersGroupName="AC_FAX",\n' +
            '                          SBCFaxOfferMode=0, SBCFaxAnswerMode=1,\n' +
            '                          SBCRemoteRenegotiateOnFaxDetection=1;'),
          caution: 'Forcing T.38 towards a peer that does not support it turns working (if fragile) G.711 fax into no fax at all.',
          confidence: 'likely',
        },
        {
          target: 'oracle-acme',
          summary: 'Allow image/t38 in the codec policy for both realms and decide the fallback behaviour deliberately.',
          steps: [
            'Add T.38 to the allowed codecs for both realms so the re-INVITE is not stripped on egress.',
            'Confirm the SBC relays the T.38 re-INVITE end to end rather than answering it locally.',
            'If the peer rejects T.38, verify the SBC re-offers G.711 rather than leaving the call in a half-switched state.',
          ],
          config: acme(
            'codec-policy\n' +
            '  name                FAX-OK\n' +
            '  allow-codecs        PCMA PCMU image:t38 telephone-event'),
          caution: 'Enabling T.38 pass-through requires the UDPTL ports to be open in the media firewall.',
          confidence: 'depends-on-topology',
        },
        {
          target: 'network',
          summary: 'Make the T.38 media path viable.',
          steps: [
            'Confirm the UDPTL port range for the SBC media interface is permitted through the firewall in both directions.',
            'Check for transcoding in the path — T.38 must be relayed, not transcoded.',
            'Where loss is unavoidable, raise T.38 redundancy on the gateways rather than relying on retransmission.',
          ],
          config: null,
          caution: null,
          confidence: 'possible',
        },
      ],
      findingIds: fromIndicator
        ? findingIdsBy(ctx, f => /t\.?38|fax/i.test(txt(f.title)))
        : findingIdsBy(ctx, f => f.category === 'diff' && txt(f.title) === txt(it.label)),
      legIds: arr(m.legIds), callIds: arr(m.callIds), msgIds: arr(m.msgIds),
    };
  },
});

// --- 12. One-way audio ------------------------------------------------------
RULES.push({
  id: 'one-way-audio',
  kb: ['one-way audio', 'no audio', 'media latching', 'NAT', 'RTP direction', 'sendonly recvonly'],
  when: (analysis, ctx) => {
    const out = [];
    for (const s of ctx.streams) {
      if (!s || s.oneWay !== true) continue;
      out.push({ kind: 'stream', stream: s, legIds: arr(s.legIds), callIds: arr(s.callIds) });
      if (out.length >= MAX_MATCHES_PER_RULE) break;
    }
    return out;
  },
  build: (m, analysis, ctx) => {
    const s = obj(m.stream);
    const answered = ctx.calls.some(c => arr(m.callIds).indexOf(c.id) !== -1 && txt(c.state) === 'paired');
    const path = txt(s.src) + ':' + txt(s.sport) + ' → ' + txt(s.dst) + ':' + txt(s.dport);
    return {
      severity: answered ? 'crit' : 'warn',
      title: 'One-way media: ' + txt(s.codec || s.kind) + ' flowing ' + path + ' with nothing coming back',
      whatsWrong: 'Stream ' + txt(s.id) + ' carried ' + txt(s.packets) + ' packets over ' + fmtS(s.durationSec) +
        ' from ' + path + ', and hiccup found no reverse stream for the paired leg. ' +
        (arr(s.legIds).length ? 'Associated legs: ' + arr(s.legIds).join(', ') + '. ' : '') +
        'Note the caveat: if the capture point only sees one direction of the media path, this can be a capture ' +
        'artefact rather than a fault — check where the trace was taken before acting.',
      whyItMatters: 'One party hears the other and not vice versa. Users describe it as "they can hear me but I ' +
        'cannot hear them", the call is otherwise perfect, and the signalling looks completely healthy — which is ' +
        'why this is the single most-escalated SBC symptom.',
      mechanism: 'Media direction is set up by the offer/answer exchange: each side publishes the address and ' +
        'port it will RECEIVE on (`c=` and `m=`), and the direction attributes (`sendrecv`, `sendonly`, ' +
        '`recvonly`, `inactive`) say which way audio may flow. Audio in only one direction therefore means one ' +
        'of: the answer advertised an address the sender cannot reach (a pre-NAT or internal address — see any ' +
        'private-IP advice on this capture); a firewall opened a pinhole only for the direction that sent first; ' +
        'the SBC anchored media on the wrong interface; a direction attribute genuinely asked for one-way media; ' +
        'or the far end is behind NAT and expects the SBC to latch onto the source address it actually sees ' +
        'rather than the one in the SDP.',
      fixes: [
        {
          target: 'oracle-acme',
          summary: 'Enable latching for the realm facing NAT so the SBC sends to where the media actually came from.',
          steps: [
            'Confirm media is anchored (not released) for this call flow.',
            'Enable latching on the realm facing the NATed peer; use restricted latching where you must limit it to the signalling source.',
            'Check the steering pool/media interface for the realm has capacity and the correct address.',
          ],
          config: acme(
            'realm-config\n' +
            '  identifier            ACCESS\n' +
            '  mm-in-realm           enabled\n' +
            '  restricted-latching   sdp'),
          caution: 'Latching accepts media from an address other than the one signalled — restrict it, or it becomes an injection vector.',
          confidence: 'possible',
        },
        {
          target: 'audiocodes',
          summary: 'Check the Media Realm and NAT traversal for the leg, and confirm the device is anchoring media.',
          steps: [
            'Setup > Signaling & Media > Media > Media Realms: confirm the realm bound to this IP Group has the right address and a free port range.',
            'Enable the NAT traversal / media latching behaviour for peers behind NAT so the device learns the real source.',
            'Verify the IP Profile is not set to direct media for this peer.',
          ],
          config: null,
          caution: null,
          confidence: 'possible',
        },
        {
          target: 'network',
          summary: 'Prove the reverse RTP path exists.',
          steps: [
            'Capture on the media interface of the silent direction and confirm whether packets arrive at all.',
            'Permit the SBC media port range in both directions on every firewall in the path; stateful UDP rules must not be direction-locked.',
            'Check for asymmetric routing between the two media addresses, and for a NAT binding that expired during a long ring.',
          ],
          config: null,
          caution: null,
          confidence: 'likely',
        },
        {
          target: 'endpoint',
          summary: 'Rule out the endpoint asking for one-way media.',
          steps: [
            'Read the answer SDP for `a=sendonly` / `a=recvonly` / `a=inactive` — hold, monitoring and some announcement servers legitimately do this.',
            'Confirm the endpoint advertises its reachable address rather than a VPN or loopback interface.',
          ],
          config: null,
          caution: null,
          confidence: 'possible',
        },
      ],
      findingIds: findingIdsBy(ctx, f => /one-way|one way|no audio|media/i.test(txt(f.title)) && (intersects(f.legIds, m.legIds) || !arr(f.legIds).length)),
      legIds: arr(m.legIds), callIds: arr(m.callIds), msgIds: [],
    };
  },
});

// --- 13. RTP loss / jitter / gaps ------------------------------------------
RULES.push({
  id: 'rtp-quality',
  kb: ['packet loss', 'jitter', 'MOS', 'QoS DSCP EF', 'RTP quality'],
  when: (analysis, ctx) => {
    const out = [];
    for (const s of ctx.streams) {
      if (!s) continue;
      const loss = num(s.lossPct), jit = num(s.maxJitterMs), gap = num(s.maxGapMs), mos = num(s.mos);
      const bad = (loss !== null && loss >= 1) || (jit !== null && jit >= 30) ||
                  (gap !== null && gap >= 300) || (mos !== null && mos <= 3.6);
      if (!bad) continue;
      out.push({ kind: 'stream', stream: s, legIds: arr(s.legIds), callIds: arr(s.callIds) });
      if (out.length >= MAX_MATCHES_PER_RULE) break;
    }
    if (!out.length) {
      for (const r of ctx.rtcp) {
        const worst = arr(obj(r).blocks).reduce((mx, b) => Math.max(mx, num(obj(b).fractionLostPct) || 0), 0);
        if (worst >= 5) { out.push({ kind: 'rtcp', report: r, worst, legIds: [], callIds: [] }); break; }
      }
    }
    return out;
  },
  build: (m, analysis, ctx) => {
    const s = obj(m.stream);
    const isRtcp = m.kind === 'rtcp';
    const loss = num(s.lossPct), jit = num(s.maxJitterMs), mean = num(s.meanJitterMs), gap = num(s.maxGapMs);
    const severe = isRtcp ? m.worst >= 10 : ((loss !== null && loss >= 5) || (gap !== null && gap >= 1000));
    const evidence = isRtcp
      ? 'An RTCP report from ' + txt(obj(m.report).src) + ' reports ' + m.worst + '% fraction lost.'
      : [
          'Stream ' + txt(s.id) + ' (' + txt(s.codec || s.kind) + ', ' + txt(s.src) + ':' + txt(s.sport) +
            ' → ' + txt(s.dst) + ':' + txt(s.dport) + ')',
          loss !== null ? 'loss ' + loss + '% (' + txt(s.lost) + ' of ' + txt(s.expected) + ' expected)' : null,
          mean !== null ? 'mean jitter ' + fmtMs(mean) : null,
          jit !== null ? 'peak jitter ' + fmtMs(jit) : null,
          gap !== null ? 'largest gap ' + fmtMs(gap) : null,
          num(s.outOfOrder) ? txt(s.outOfOrder) + ' out of order' : null,
          num(s.mos) !== null ? 'estimated MOS ' + s.mos + ' (' + txt(s.mosMethod) + ' — an ESTIMATE from loss and jitter only, not a measurement)' : null,
        ].filter(Boolean).join('; ') + '.';
    return {
      severity: severe ? 'crit' : 'warn',
      title: isRtcp
        ? 'Far end reports ' + m.worst + '% packet loss in RTCP'
        : 'Media quality degraded: ' + (loss !== null ? loss + '% loss' : 'loss/jitter above threshold') +
          (jit !== null ? ', peak jitter ' + fmtMs(jit) : ''),
      whatsWrong: evidence,
      whyItMatters: severe
        ? 'At this level of loss speech is audibly broken — words dropped, robotic artefacts, and gaps long ' +
          'enough that people talk over each other. Fax and modem traffic on the same path will simply fail.'
        : 'Callers report "crackling", "clipping" or "it sounds like they are underwater". It is usually ' +
          'intermittent and time-of-day dependent, which is why it survives so long as an unresolved ticket.',
      mechanism: 'Loss is derived from the RTP sequence number: the receiver compares packets actually seen ' +
        'against the range the sequence numbers imply, which is also how RTCP receiver reports express fraction ' +
        'lost and cumulative loss. Interarrival jitter is a smoothed estimate of the variation between the RTP ' +
        'timestamp spacing and the actual arrival spacing — a jitter buffer absorbs some of it, then starts ' +
        'discarding late packets, which shows up as additional effective loss. The ITU-T G.107 E-model turns ' +
        'delay, loss and codec impairment into a single rating; hiccup reports a simplified MOS from loss, ' +
        'jitter and codec, with no delay term, so treat it as a comparative indicator and not a verdict.',
      fixes: [
        {
          target: 'network',
          summary: 'Find where the loss happens before touching anything on the SBC — media impairment is almost never a SIP problem.',
          steps: [
            'Mark and honour QoS end to end: DSCP EF (46) for RTP, CS3/AF31 for signalling, and check every hop actually trusts those markings.',
            'Look for a policer or shaper dropping the media class, an over-subscribed WAN link, or a saturated access circuit at the busy hour.',
            'Check interface counters for errors/discards and duplex mismatches on the path (a half-duplex mismatch produces exactly this signature).',
            'If the path crosses the public internet, compare loss against a same-path probe to prove where it starts.',
          ],
          config: null,
          caution: null,
          confidence: 'likely',
        },
        {
          target: 'oracle-acme',
          summary: 'Confirm the SBC marks media correctly and is not itself the bottleneck.',
          steps: [
            'Set the ToS/DSCP values for media and signalling in the media-policy bound to the realm.',
            'Check `show media-ports` / interface statistics for drops on the media interface.',
            'Verify no transcoding resource is overloaded — DSP exhaustion presents as loss and gaps.',
          ],
          config: acme(
            'media-policy\n' +
            '  name                QOS-EF\n' +
            '  tos-settings        media 0xB8   ; DSCP EF\n' +
            '\n' +
            'realm-config\n' +
            '  identifier          PEER\n' +
            '  media-policy        QOS-EF'),
          caution: 'DSCP values only help if every hop honours them; marking alone changes nothing on an untrusted path.',
          confidence: 'possible',
        },
        {
          target: 'audiocodes',
          summary: 'Check the device\'s DiffServ settings and media interface statistics.',
          steps: [
            'Setup > IP Network > Advanced > QoS Settings: confirm the premium media service class DiffServ value (EF/46).',
            'Check Monitor > Performance for RTP loss/jitter counters per media realm.',
            'Confirm the media realm port range is not exhausted at the busy hour.',
          ],
          config: audiocodes(
            '[ QoS Params ]\n' +
            'PREMIUMSERVICECLASSMEDIADIFFSERV = 46\n' +
            'PREMIUMSERVICECLASSCONTROLDIFFSERV = 24'),
          caution: null,
          confidence: 'possible',
        },
        {
          target: 'endpoint',
          summary: 'Reduce sensitivity while the path is being fixed.',
          steps: [
            'Prefer a codec with better loss concealment for the affected path, and avoid low-bitrate codecs over lossy links.',
            'Increase the endpoint/SBC jitter buffer depth if the impairment is jitter rather than loss (it costs delay).',
          ],
          config: null,
          caution: 'A deeper jitter buffer trades one-way delay for smoothness; beyond ~150 ms one-way, conversation becomes awkward.',
          confidence: 'possible',
        },
      ],
      findingIds: findingIdsBy(ctx, f => /loss|jitter|media|quality|mos/i.test(txt(f.title))),
      legIds: arr(m.legIds), callIds: arr(m.callIds), msgIds: [],
    };
  },
});

// --- 14. DNS SRV/NAPTR stall or timeout on egress --------------------------
RULES.push({
  id: 'dns-egress-stall',
  kb: ['DNS SRV NAPTR timeout', 'blocking resolver', 'RFC 3263 locating SIP servers', 'slow call setup'],
  when: (analysis, ctx) => {
    const out = [];
    // Proof: DNS observations in aux (same shape lib/dns.js exports via dnsEvidence).
    const ev = dnsEvidenceFrom(ctx);
    for (const host of Object.keys(ev.byDest)) {
      const e = ev.byDest[host];
      if (!e || (!e.timeouts && !e.slowQueries)) continue;
      out.push({ kind: 'dns-aux', host, evidence: e, legIds: arr(e.legIds), callIds: arr(e.callIds) });
      if (out.length >= MAX_MATCHES_PER_RULE) break;
    }
    // Inference: the retransmission classifier already decided this from timing.
    for (const g of collapseMatches(ctx, ['dns-blocking'])) {
      g.kind = 'dns-inferred';
      out.push(g);
      if (out.length >= MAX_MATCHES_PER_RULE) break;
    }
    return out.slice(0, MAX_MATCHES_PER_RULE);
  },
  build: (m, analysis, ctx) => {
    const proof = m.kind === 'dns-aux';
    const e = obj(m.evidence);
    const s = obj(m.sample);
    return {
      severity: proof && e.timeouts ? 'crit' : 'warn',
      title: proof
        ? 'DNS for ' + m.host + ' ' + (e.timeouts ? 'timed out (' + e.timeouts + ' unanswered ' + (e.timeouts === 1 ? 'query' : 'queries') + ')' : 'is slow (up to ' + fmtMs(e.maxLatencyMs) + ')')
        : 'Blocking DNS suspected on egress towards ' + m.dst,
      whatsWrong: proof
        ? 'The capture contains the DNS traffic itself: ' + (e.timeouts || 0) + ' unanswered ' +
          ((e.timeouts === 1) ? 'query' : 'queries') + ', ' + (e.slowQueries || 0) + ' slow ' +
          ((e.slowQueries === 1) ? 'query' : 'queries') + ' for ' + m.host +
          (num(e.maxLatencyMs) !== null ? ', worst latency ' + fmtMs(e.maxLatencyMs) : '') +
          '. That is direct proof rather than inference from SIP timing.'
        : ('"' + txt(s.label) + '". ' + txt(obj(s.classification).detail) +
           ' There is no DNS traffic in this capture to confirm it, so this is inference from the timing pattern ' +
           'across legs — capture port 53 alongside SIP to turn it into proof.'),
      whyItMatters: 'Call setup stalls for seconds before anything happens, INVITEs retransmit in the meantime, ' +
        'and if resolution never completes the transaction dies with no response at all — a ladder that looks ' +
        'like an unreachable peer when the peer is perfectly healthy. Because it affects every call to that ' +
        'destination equally, it presents as "the trunk is slow" rather than a per-call fault.',
      mechanism: 'Before a request can be sent to a SIP URI with a hostname, the client resolves it: NAPTR to ' +
        'pick a transport, SRV to get targets and ports, then A/AAAA for addresses. Many SBCs perform that ' +
        'lookup synchronously in the signalling path, so a resolver that is slow, unreachable, or answering ' +
        'only for some query types blocks the transaction while SIP\'s own timers keep running — Timer A ' +
        'retransmits the INVITE at 500 ms, 1 s, 2 s while the box waits. The tell-tale is that the delay is ' +
        'identical across unrelated calls to the same destination, which is exactly what distinguishes it from ' +
        'a genuinely slow far end.',
      fixes: [
        {
          target: 'oracle-acme',
          summary: 'Fix the resolver configuration, and where possible take DNS out of the call path entirely.',
          steps: [
            'Check the network-interface\'s DNS servers and timeout, and confirm both resolvers answer NAPTR and SRV, not just A.',
            'For a fixed peer, configure the session-agent with an IP address so no resolution happens per call.',
            'Where the peer really is a DNS-resolved service, verify the SBC caches results and honours TTLs rather than querying per call.',
          ],
          config: acme(
            'network-interface\n' +
            '  name                wancom0\n' +
            '  dns-ip-primary      198.51.100.53\n' +
            '  dns-ip-secondary    198.51.100.54\n' +
            '  dns-timeout         11'),
          caution: 'Hard-coding peer IP addresses removes the provider\'s ability to fail over via DNS — only do it where the provider offers static addresses.',
          confidence: 'likely',
        },
        {
          target: 'audiocodes',
          summary: 'Use explicit addresses in the Proxy Set, or the device\'s internal DNS table, and set the resolve method deliberately.',
          steps: [
            'Setup > Signaling & Media > Core Entities > Proxy Sets: set the DNS resolve method (A record vs SRV) to match what the provider publishes.',
            'Populate the Internal DNS table for critical hostnames so a resolver outage cannot stop calls.',
            'Confirm the device\'s DNS servers under IP Network > IP Interfaces are reachable from that interface.',
          ],
          config: audiocodes(
            '[ Dns2Ip ]\n' +
            '; internal DNS: hostname, first IP, second IP...\n' +
            'Dns2Ip 0 = "' + txt(m.host || 'sip.provider.net') + '", 0, "198.51.100.20", "198.51.100.21";'),
          caution: 'A static internal DNS entry becomes stale silently if the provider changes addresses — review it periodically.',
          confidence: 'possible',
        },
        {
          target: 'ribbon',
          summary: 'Check the DNS Group bound to the zone and its server reachability.',
          steps: [
            'Review the dnsGroup used by the address context and confirm each server answers the query types in use.',
            'Consider a static DNS entry (or IP-addressed peer) for the critical trunk.',
            'Check DNS query statistics for timeouts on that group.',
          ],
          config: ribbon(
            'show table addressContext default dnsGroup\n' +
            'set addressContext default dnsGroup DNS_GRP server 1 ipAddress 198.51.100.53 state enabled\n' +
            'commit'),
          caution: null,
          confidence: 'depends-on-topology',
        },
        {
          target: 'network',
          summary: 'Test the resolver the way the SBC uses it.',
          steps: [
            'From the SBC\'s own signalling interface/VRF, query NAPTR, SRV and A for the peer hostname and time each one.',
            'Confirm UDP 53 AND TCP 53 are permitted — a truncated answer forces TCP, and a firewall that blocks it produces exactly this stall.',
            'Check for EDNS0 or large-response filtering, and for split-horizon DNS answering differently on that interface.',
          ],
          config: null,
          caution: null,
          confidence: 'likely',
        },
      ],
      findingIds: findingIdsBy(ctx, f => /dns/i.test(txt(f.title))),
      legIds: arr(m.legIds), callIds: arr(m.callIds), msgIds: arr(m.msgIds).slice(0, 12),
    };
  },
});

/**
 * DNS evidence in the shape lib/dns.js exports (`{ byDest: { host: { slowQueries,
 * timeouts, maxLatencyMs } } }`), derived locally from analysis.aux so advisor.js
 * never has to require a sibling Wave-2 module. An evidence object supplied by
 * the integrator on `analysis.dnsEvidence` (or opts) wins.
 * @param {object} ctx
 * @returns {{byDest: Object}}
 */
function dnsEvidenceFrom(ctx) {
  const supplied = obj(obj(ctx.analysis).dnsEvidence).byDest;
  if (supplied && typeof supplied === 'object') {
    const out = {};
    for (const k of Object.keys(supplied)) {
      const v = obj(supplied[k]);
      out[k] = {
        slowQueries: num(v.slowQueries) || 0,
        timeouts: num(v.timeouts) || 0,
        maxLatencyMs: num(v.maxLatencyMs),
        legIds: arr(v.legIds), callIds: arr(v.callIds),
      };
    }
    return { byDest: out };
  }
  const byDest = {};
  for (const x of ctx.aux) {
    if (!x || x.protocol !== 'dns') continue;
    const d = obj(x.detail);
    const slow = d.slow === true;
    const timedOut = d.timedOut === true;
    if (!slow && !timedOut) continue;
    // The queried name under any of the plausible field names, else the server IP.
    let host = txt(d.qname || d.name || d.question || d.query || '');
    if (!host) {
      const m = /([A-Za-z0-9_.-]+\.[A-Za-z]{2,})/.exec(txt(x.summary));
      host = m ? m[1] : txt(x.dst) || 'unknown';
    }
    const e = byDest[host] || (byDest[host] = { slowQueries: 0, timeouts: 0, maxLatencyMs: null, legIds: [], callIds: [] });
    if (timedOut) e.timeouts++;
    if (slow) e.slowQueries++;
    const lat = num(d.latencyMs);
    if (lat !== null && (e.maxLatencyMs === null || lat > e.maxLatencyMs)) e.maxLatencyMs = lat;
    for (const id of arr(x.legIds)) if (e.legIds.indexOf(id) === -1) e.legIds.push(id);
    for (const id of arr(x.callIds)) if (e.callIds.indexOf(id) === -1) e.callIds.push(id);
  }
  return { byDest };
}

// --- 15. Missing Service-Route in the REGISTER 200 OK ----------------------
RULES.push({
  id: 'missing-service-route',
  kb: ['Service-Route', 'REGISTER 200 OK', 'S-CSCF', 'preloaded Route', 'sip:orig'],
  when: (analysis, ctx) => {
    const imsish = ctx.sip.some(m => m && (hdr(m, 'Path') || hdr(m, 'P-Associated-URI') ||
      hdr(m, 'P-Charging-Vector') || hdr(m, 'P-Access-Network-Info') || hdr(m, 'P-Visited-Network-ID')));
    const out = [];
    for (const leg of ctx.legs) {
      if (!leg || leg.protocol !== 'sip' || leg.kind !== 'register') continue;
      const msgs = originals(legMsgs(ctx, leg));
      let ok = null;
      for (const m of msgs) {
        if (!m.isRequest && num(m.status) !== null && m.status >= 200 && m.status < 300 &&
            txt(obj(m.cseq).method) === 'REGISTER') { ok = m; break; }
      }
      if (!ok) continue;
      if (hdr(ok, 'Service-Route')) continue;
      const hasPath = msgs.some(m => hdr(m, 'Path'));
      if (!imsish && !hasPath) continue;   // plain non-IMS registrar: Service-Route is not expected
      out.push({ kind: 'register', legId: leg.id, msgIds: [ok.id], hasPath, imsish });
      if (out.length >= MAX_MATCHES_PER_RULE) break;
    }
    return out;
  },
  build: (m, analysis, ctx) => ({
    severity: m.hasPath ? 'warn' : 'notice',
    title: 'REGISTER succeeded but the 200 OK carries no Service-Route',
    whatsWrong: 'Leg ' + m.legId + ' registered successfully and the 200 OK has no Service-Route header, even ' +
      'though this capture shows IMS behaviour' + (m.hasPath ? ' (a Path header is present in the registration flow)' : '') +
      '. The registrar therefore gave the UA no route to use for its own originating requests.',
    whyItMatters: 'Registration looks perfectly healthy — and then originating calls behave oddly: services do ' +
      'not apply, calls bypass the application servers, charging identifiers are missing, or the first INVITE is ' +
      'rejected outright. Because the fault is in the registration response, nobody looks there.',
    mechanism: 'Path and Service-Route are the two halves of IMS registration routing. Path is inserted on the ' +
      'way IN so that requests TOWARDS the subscriber traverse the same P-CSCF; Service-Route is returned by the ' +
      'registrar in the 200 OK so that requests FROM the subscriber traverse the assigned S-CSCF, normally with ' +
      'the `orig` parameter that tells it to apply originating services. The UA pre-loads that value as a Route ' +
      'set for the duration of the registration. Without it the UA has only its outbound proxy to go on, so the ' +
      'S-CSCF is skipped or has to guess, and the initial filter criteria never fire.',
    fixes: [
      {
        target: 'generic',
        summary: 'This fix is on the registrar/S-CSCF, not on the SBC — but first check nothing is stripping the header in transit.',
        steps: [
          'Confirm on the registrar side that Service-Route insertion is enabled for this subscriber/realm.',
          'Search the capture for the header on the other side of each hop: if it is present inbound and absent outbound, a manipulation is removing it.',
          'Check that the P-CSCF/SBC is configured to pass unknown or IMS-specific headers through on the registration response.',
        ],
        config: null,
        caution: null,
        confidence: 'likely',
      },
      {
        target: 'oracle-acme',
        summary: 'If the SBC is acting as an access/IMS edge, enable the IMS feature set on that sip-interface and stop any manipulation touching the header.',
        steps: [
          'Enable the IMS behaviour on the access sip-interface (`sip-ims-feature`) so Path/Service-Route handling follows 3GPP rules.',
          'Review in/out manipulations bound to that realm for header-rules acting on Service-Route or on "all unknown headers".',
          'Verify registration caching is not answering the register locally without the registrar\'s headers.',
        ],
        config: acme(
          'sip-interface\n' +
          '  realm-id            ACCESS\n' +
          '  sip-ims-feature     enabled'),
        caution: 'Turning on the IMS feature set changes several behaviours at once (Path, Service-Route, P-header handling) — stage it.',
        confidence: 'depends-on-topology',
      },
      {
        target: 'audiocodes',
        summary: 'Check that no Message Manipulation removes Service-Route on the registration response and that IMS/Path support is enabled.',
        steps: [
          'Review Message Manipulations acting on REGISTER responses.',
          'Confirm the device is configured to support Path/Service-Route for the access side rather than terminating registrations itself.',
        ],
        config: null,
        caution: null,
        confidence: 'possible',
      },
    ],
    findingIds: findingIdsBy(ctx, f => /service-route|register/i.test(txt(f.title)) && intersects(f.legIds, [m.legId])),
    legIds: [m.legId], callIds: [], msgIds: m.msgIds,
  }),
});

// --- 16. Preconditions requested but never confirmed ------------------------
RULES.push({
  id: 'precondition-unconfirmed',
  kb: ['preconditions', 'a=curr a=des a=conf', 'QoS precondition', '580 Precondition Failure', 'PRACK UPDATE'],
  when: (analysis, ctx) => {
    const ind = indicator(ctx, 'precondition');
    let des = 0, conf = 0;
    const msgIds = [], legIds = [];
    for (const m of ctx.sip) {
      const sdp = obj(m.sdp);
      if (!sdp.raw && !arr(sdp.sessionAttrs).length && !arr(sdp.media).length) continue;
      let attrs = arr(sdp.sessionAttrs).slice();
      for (const md of arr(sdp.media)) attrs = attrs.concat(arr(md.attrs));
      const joined = attrs.join('\n') + '\n' + txt(sdp.raw);
      if (/(^|[\n\r])?a?=?\s*des:/.test(joined) || /\bdes:(qos|sec)/.test(joined)) {
        des++;
        if (msgIds.length < 8) msgIds.push(m.id);
      }
      if (/\bconf:(qos|sec)/.test(joined)) conf++;
    }
    if (des > 0 && conf === 0) {
      for (const leg of ctx.legs) {
        if (leg && intersects(arr(leg.msgIds), msgIds)) legIds.push(leg.id);
      }
      return [{ kind: 'precondition', des, msgIds, legIds: uniq(legIds), indicatorDetail: ind ? txt(ind.detail) : '' }];
    }
    if (ind && ind.state === 'issue') {
      return [{ kind: 'precondition', des: 0, msgIds: arr(ind.evidenceMsgIds).slice(0, 8), legIds: [], indicatorDetail: txt(ind.detail) }];
    }
    return [];
  },
  build: (m, analysis, ctx) => ({
    severity: 'warn',
    title: 'QoS preconditions requested but never confirmed',
    whatsWrong: (m.des
      ? m.des + ' SDP body' + (m.des === 1 ? '' : 'ies') + ' in this capture state a desired precondition ' +
        '(`a=des:`) and no message anywhere confirms it with `a=conf:`.'
      : txt(m.indicatorDetail) || 'The precondition indicator is flagged as faulty.') +
      ' The reservation half of the flow is missing from the trace.',
    whyItMatters: 'Setup hangs before the phone even rings: the originating side is waiting for a confirmation ' +
      'that never comes, so the caller hears silence until something times out, and the call may end with ' +
      '580 Precondition Failure or a plain timeout. On a mobile core this normally means the dedicated bearer ' +
      'for voice was never established.',
    mechanism: 'The preconditions framework makes session establishment wait for resource reservation. Each ' +
      'media stream carries three status lines: `a=curr` (current status), `a=des` (desired status with a ' +
      'strength tag — mandatory or optional) and `a=conf` (the status at which the peer should confirm). The ' +
      'exchange runs over a reliable 183 plus PRACK, and the confirmation typically arrives in an UPDATE once ' +
      'the bearer is up. If the peer strips the attributes, does not support the extension, or the bearer setup ' +
      '(for example over Rx/Gx) fails, nothing ever confirms — and with strength `mandatory` the call is not ' +
      'allowed to proceed. Note that this flow depends on reliable provisional responses, so a 100rel ' +
      'asymmetry anywhere in the path breaks preconditions as a side effect.',
    fixes: [
      {
        target: 'generic',
        summary: 'Decide whether preconditions should apply on this path at all, and make the whole path consistent.',
        steps: [
          'Check whether the far end supports preconditions: `Supported: precondition` (and 100rel) in its messages.',
          'If it does not, the originating side should offer the precondition as optional rather than mandatory, or the border element should remove the requirement rather than pass it through.',
          'If it does, follow the reservation: look for the Rx/Gx (or bearer) transaction in the same window — a failure there is the real cause.',
          'Verify reliable provisional responses work end to end; PRACK failures silently kill precondition flows.',
        ],
        config: null,
        caution: null,
        confidence: 'likely',
      },
      {
        target: 'oracle-acme',
        summary: 'Make the border element interwork the extension instead of forwarding a requirement the peer cannot meet.',
        steps: [
          'Enable 100rel interworking on the peer-facing sip-interface (preconditions cannot work without reliable 1xx).',
          'Where the peer does not support preconditions, use a manipulation to remove `precondition` from Require/Supported and strip the `a=des`/`a=curr` lines on egress.',
          'Confirm the IMS feature set is enabled where the SBC sits on an IMS access edge.',
        ],
        config: acme(
          'sip-interface\n' +
          '  realm-id            PEER\n' +
          '  options             +100rel-interworking'),
        caution: 'Stripping a mandatory precondition silently changes the service guarantee the originating network asked for — get agreement before doing it.',
        confidence: 'depends-on-topology',
      },
      {
        target: 'audiocodes',
        summary: 'Set PRACK handling for the peer and remove the precondition tags where the peer cannot honour them.',
        steps: [
          'Set `SBCPrackMode` on the IP Profile so reliable provisional responses work on the leg that needs them.',
          'Use a Message Manipulation to remove `precondition` from the Require/Supported headers towards a peer that does not implement it.',
        ],
        config: audiocodes(
          '[ IPProfile ]\n' +
          'IPProfile 1 = "PEER", ..., SBCPrackMode=2;   ; reliable 1xx required for precondition flows'),
        caution: null,
        confidence: 'possible',
      },
    ],
    findingIds: findingIdsBy(ctx, f => /precondition/i.test(txt(f.title))),
    legIds: arr(m.legIds), callIds: [], msgIds: arr(m.msgIds),
    extraCitations: [cite(REFS.update, 'The confirmation normally arrives in an UPDATE, defined here — worth checking the peer supports the method at all.')],
  }),
});

// --- 17. ICE connectivity checks fail / DTLS handshake stalls ---------------
RULES.push({
  id: 'ice-dtls-failure',
  kb: ['ICE connectivity check failed', 'STUN binding request', 'DTLS-SRTP handshake', 'TURN relay', 'WebRTC no media'],
  when: (analysis, ctx) => {
    const out = [];
    for (const x of ctx.aux) {
      if (!x) continue;
      const d = obj(x.detail);
      if (x.protocol === 'stun' || x.protocol === 'ice') {
        const list = arr(d.checkList);
        if (!list.length) continue;
        const ok = list.filter(c => txt(obj(c).state || obj(c).result) === 'succeeded').length;
        const bad = list.filter(c => ['failed', 'no-response'].indexOf(txt(obj(c).state || obj(c).result)) !== -1).length;
        if (bad > 0 && ok === 0) {
          out.push({ kind: 'ice', aux: x, bad, total: list.length, legIds: arr(x.legIds), callIds: arr(x.callIds) });
        }
      } else if (x.protocol === 'dtls' && d.stalledAfter) {
        out.push({ kind: 'dtls', aux: x, stalledAfter: txt(d.stalledAfter), srtpProfile: txt(d.srtpProfile),
          legIds: arr(x.legIds), callIds: arr(x.callIds) });
      }
      if (out.length >= MAX_MATCHES_PER_RULE) break;
    }
    return out;
  },
  build: (m, analysis, ctx) => {
    const x = obj(m.aux);
    const isIce = m.kind === 'ice';
    return {
      severity: 'crit',
      title: isIce
        ? 'Every ICE connectivity check failed (' + m.bad + ' of ' + m.total + ' candidate pairs) — no media path'
        : 'DTLS-SRTP handshake stalls after ' + m.stalledAfter + ' — no media keys',
      whatsWrong: isIce
        ? 'hiccup found ' + m.total + ' candidate pair' + (m.total === 1 ? '' : 's') + ' in the STUN check list ' +
          'and not one succeeded (' + m.bad + ' failed or went unanswered). Observed: ' + txt(x.summary) + '.'
        : 'The DTLS handshake progressed no further than ' + m.stalledAfter + ' and never completed' +
          (m.srtpProfile ? ' (offered SRTP protection profile: ' + m.srtpProfile + ')' : '') +
          '. Observed: ' + txt(x.summary) + '.',
      whyItMatters: 'The call sets up in SIP and then has no audio or video at all, in either direction. On ' +
        'WebRTC and Teams-side integrations this is the usual failure mode: signalling is fine, so the fault ' +
        'gets chased in the SIP layer for hours.',
      mechanism: isIce
        ? 'ICE does not trust SDP addresses; it probes them. Each side sends STUN binding requests across every ' +
          'candidate pair and only a pair that answers in both directions can carry media. All pairs failing ' +
          'means either no UDP path exists at all (symmetric NAT on both sides with no relay, or a firewall ' +
          'blocking the high-port range), or the checks are being rejected — a USERNAME/ufrag mismatch, which ' +
          'is what happens when a middlebox rewrites `a=ice-ufrag`/`a=ice-pwd` in the SDP, or an ICE-lite peer ' +
          'that never answers checks it is expected to answer.'
        : 'DTLS-SRTP negotiates the media keys inside the media path itself: ClientHello, ServerHello, ' +
          'Certificate, then Finished, with the SRTP protection profile carried in the use_srtp extension. The ' +
          'endpoints verify each other against the `a=fingerprint` from the SDP, and `a=setup` decides which ' +
          'side is the client. A handshake that stops after the first flight almost always means the packets ' +
          'are not arriving (blocked UDP, or ICE never selected a working pair) or the fingerprint/setup role ' +
          'was altered in the SDP so verification fails silently.',
      fixes: [
        {
          target: 'network',
          summary: 'Give the media a path that survives NAT, and stop anything from rewriting the ICE/DTLS attributes.',
          steps: [
            'Permit the full UDP media port range in both directions, or provide a TURN relay both parties can reach.',
            'Confirm no SBC or firewall ALG modifies the SDP: `a=ice-ufrag`, `a=ice-pwd`, `a=fingerprint` and `a=setup` must arrive byte-for-byte.',
            'Check that the candidates in the SDP are addresses the other side can reach (a host candidate on an internal interface is useless to an internet peer).',
            'Where both ends are behind symmetric NAT, a relay candidate is mandatory — verify TURN credentials and reachability.',
          ],
          config: null,
          caution: null,
          confidence: 'likely',
        },
        {
          target: 'oracle-acme',
          summary: 'Use the WebRTC/DTLS profile objects rather than passing the media security attributes through.',
          steps: [
            'Bind a media-sec-policy with a DTLS-SRTP profile to the realm facing the WebRTC/OTT side, and the appropriate policy (RTP or SDES) on the other.',
            'Confirm ICE handling for that realm (ICE-lite vs full) matches what the peer expects.',
            'Verify no SDP manipulation is touching the ICE or fingerprint attributes.',
          ],
          config: acme(
            'media-sec-policy\n' +
            '  name                WEBRTC-IN\n' +
            '  inbound\n' +
            '    profile           DTLS-SRTP-PROFILE\n' +
            '    mode              srtp\n' +
            '    protocol          dtls'),
          caution: 'Media security policy changes affect every call on the realm; DTLS also requires a valid certificate on the SBC.',
          confidence: 'depends-on-topology',
        },
        {
          target: 'audiocodes',
          summary: 'Set the media security method and the ICE mode on the IP Profile for the WebRTC-facing peer.',
          steps: [
            'Setup > Signaling & Media > Coders & Profiles > IP Profiles: set the media security method to DTLS for that peer.',
            'Set the ICE mode (typically Lite) on the same profile so the device answers connectivity checks.',
            'Ensure the device holds a certificate whose fingerprint matches what it advertises in SDP.',
          ],
          config: null,
          caution: 'DTLS requires certificate management on the device — an expired certificate produces exactly this stall.',
          confidence: 'possible',
        },
      ],
      findingIds: findingIdsBy(ctx, f => /ice|stun|dtls|srtp/i.test(txt(f.title))),
      legIds: arr(m.legIds), callIds: arr(m.callIds), msgIds: [],
      extraCitations: m.kind === 'dtls'
        ? [cite(REFS.srtp, 'The keys DTLS is negotiating are for SRTP as defined here; without a completed handshake there is no session key and no media.')]
        : [],
    };
  },
});

// --- 18. Digest authentication loop ---------------------------------------
RULES.push({
  id: 'digest-auth-loop',
  kb: ['401 Unauthorized loop', '407 Proxy Authentication Required', 'digest realm nonce', 'registration fails'],
  when: (analysis, ctx) => {
    const out = [];
    for (const leg of ctx.legs) {
      if (!leg || leg.protocol !== 'sip') continue;
      const msgs = originals(legMsgs(ctx, leg));
      const byMethod = new Map();
      for (const m of msgs) {
        if (m.isRequest) continue;
        if (num(m.status) === null || (m.status !== 401 && m.status !== 407)) continue;
        const method = txt(obj(m.cseq).method) || txt(m.method);
        const g = byMethod.get(method) || [];
        g.push(m);
        byMethod.set(method, g);
      }
      for (const [method, challenges] of byMethod) {
        if (challenges.length < 2) continue;
        const authed = msgs.filter(m => m.isRequest && txt(obj(m.cseq).method) === method &&
          (hdr(m, 'Authorization') || hdr(m, 'Proxy-Authorization')));
        if (!authed.length) continue;   // two unrelated challenges, not a loop
        out.push({
          kind: 'auth', legId: leg.id, method,
          count: challenges.length,
          status: challenges[0].status,
          realm: (/realm\s*=\s*"([^"]*)"/i.exec(txt(hdr(challenges[0], challenges[0].status === 407 ? 'Proxy-Authenticate' : 'WWW-Authenticate'))) || [, ''])[1],
          msgIds: challenges.slice(0, 4).map(c => c.id).concat(authed.slice(0, 2).map(a => a.id)),
        });
        if (out.length >= MAX_MATCHES_PER_RULE) break;
      }
      if (out.length >= MAX_MATCHES_PER_RULE) break;
    }
    return out;
  },
  build: (m, analysis, ctx) => ({
    severity: 'warn',
    title: m.method + ' challenged ' + m.count + '× — the credentials are never accepted',
    whatsWrong: 'Leg ' + m.legId + ' received ' + m.count + ' × ' + m.status + ' for ' + m.method +
      ' even though the request was re-sent with credentials' +
      (m.realm ? ' (challenge realm "' + m.realm + '")' : '') +
      '. hiccup redacts the digest response value, so the loop is visible but the secret is not.',
    whyItMatters: 'For REGISTER this means the trunk or handset never registers: inbound calls fail and the ' +
      'device retries forever, which on a busy platform is a genuine load problem. For INVITE it means calls ' +
      'are rejected at setup. Either way the ladder shows an endless challenge/retry cycle that looks like a ' +
      'network loop but is an authentication mismatch.',
    mechanism: 'The challenge carries a realm and a nonce. The client hashes username, password, realm, nonce, ' +
      'method and the digest URI into the response value. A second challenge for the same transaction means the ' +
      'server recomputed that hash and got something different, so any one of the inputs disagrees: wrong ' +
      'password; the realm string not matching exactly what the server expects; username sent as a full URI ' +
      'where the bare user part was wanted (or vice versa); an algorithm/qop mismatch (MD5 versus the SHA-256 ' +
      'variants); a nonce that has already been used or expired — in which case a well-behaved server sets ' +
      '`stale=true` and the client should retry without prompting; or a middlebox rewriting the Request-URI ' +
      'AFTER the digest was computed, because the URI is part of the hashed data.',
    fixes: [
      {
        target: 'generic',
        summary: 'Compare the four digest inputs one by one — this is almost never a network fault.',
        steps: [
          'Check the realm in the challenge against the realm configured on the client, character for character.',
          'Confirm the username form the registrar expects (bare user vs user@domain) and the password, ideally by re-entering it rather than trusting the config.',
          'Look for `stale=true` on the second challenge: if present, the client is not handling nonce refresh correctly.',
          'Check whether anything between client and registrar rewrites the Request-URI, To, or the digest URI after authentication is computed.',
          'Check qop and algorithm support on both sides (MD5 vs SHA-256) and the device clock if nonces are time-based.',
        ],
        config: null,
        caution: 'Do not paste credentials into tickets or chat when investigating — hiccup redacts them for a reason.',
        confidence: 'likely',
      },
      {
        target: 'audiocodes',
        summary: 'Fix the credentials in the Accounts table for this served/serving group pair.',
        steps: [
          'Setup > Signaling & Media > SIP Definitions > Accounts: check the User Name, Password, Host Name and Register mode for the account bound to this IP Group.',
          'Confirm the Host Name matches the realm/domain the registrar challenges with.',
          'Watch the Syslog during a re-registration to see which input the registrar rejects.',
        ],
        config: audiocodes(
          '[ Accounts ]\n' +
          'Accounts 0 = "TRUNK_ACCT", 1, 2, "sip.provider.net", "username", "********", 1, 3600;\n' +
          '; served IP Group, serving IP Group, host name, user, password, register, expires'),
        caution: 'Re-registering all accounts at once creates a burst of REGISTER traffic; stagger it on large deployments.',
        confidence: 'possible',
      },
      {
        target: 'oracle-acme',
        summary: 'Check the authentication credentials attached to the session-agent/realm and make sure no manipulation runs after the digest is computed.',
        steps: [
          'Verify the configured auth user and password for the peer, and the realm they are scoped to.',
          'Review out-manipulations for rules that rewrite the Request-URI or To on the authenticated retry.',
          'If the SBC is registering on behalf of endpoints, confirm the registration-caching/pass-through mode matches what the registrar expects.',
        ],
        config: null,
        caution: null,
        confidence: 'possible',
      },
    ],
    findingIds: findingIdsBy(ctx, f => f.category === 'auth' || /auth|401|407/i.test(txt(f.title))),
    legIds: [m.legId], callIds: [], msgIds: m.msgIds,
  }),
});

// --- 19. CANCEL race / missing 487 -----------------------------------------
RULES.push({
  id: 'cancel-race',
  kb: ['CANCEL', '487 Request Terminated', 'race condition', 'stranded call', 'glare'],
  when: (analysis, ctx) => {
    const out = [];
    for (const leg of ctx.legs) {
      if (!leg || leg.protocol !== 'sip' || leg.kind !== 'call') continue;
      const msgs = originals(legMsgs(ctx, leg));
      const cancel = msgs.find(m => m.isRequest && txt(m.method) === 'CANCEL');
      if (!cancel) continue;
      const has487 = msgs.some(m => !m.isRequest && m.status === 487);
      const twoxxAfter = msgs.find(m => !m.isRequest && num(m.status) !== null && m.status >= 200 && m.status < 300 &&
        txt(obj(m.cseq).method) === 'INVITE' && num(m.ts) !== null && num(cancel.ts) !== null && m.ts >= cancel.ts);
      if (twoxxAfter) {
        out.push({ kind: 'race', legId: leg.id, msgIds: [cancel.id, twoxxAfter.id],
          gapMs: (twoxxAfter.ts - cancel.ts) * 1000 });
      } else if (!has487) {
        out.push({ kind: 'no487', legId: leg.id, msgIds: [cancel.id] });
      }
      if (out.length >= MAX_MATCHES_PER_RULE) break;
    }
    return out;
  },
  build: (m, analysis, ctx) => {
    const race = m.kind === 'race';
    const callIds = ctx.calls.filter(c => arr(c.legIds).indexOf(m.legId) !== -1).map(c => c.id);
    return {
      severity: race ? 'crit' : 'warn',
      title: race
        ? 'CANCEL/200 OK race: the call was answered ' + fmtMs(m.gapMs) + ' after the caller cancelled'
        : 'CANCEL sent but no 487 Request Terminated came back',
      whatsWrong: race
        ? 'On leg ' + m.legId + ' a CANCEL was sent and a 2xx for the INVITE arrived ' + fmtMs(m.gapMs) +
          ' later. The two crossed on the wire, so the two ends now disagree about whether the call exists.'
        : 'On leg ' + m.legId + ' a CANCEL was sent and hiccup found no 487 Request Terminated for the INVITE ' +
          'transaction. The INVITE transaction was never given a final response in this capture.',
      whyItMatters: race
        ? 'This is how you get stranded calls: the caller has hung up and moved on, while the callee\'s phone is ' +
          'off-hook in a call to nobody, often still billing. It is also a classic source of "ghost calls" and of ' +
          'licence/session leaks on an SBC when the dialog is never cleaned up.'
        : 'The caller\'s transaction has no final response, so its state machine waits and the ladder looks ' +
          'unfinished. Downstream the callee may still be ringing — the abandoned call keeps a session, a trunk ' +
          'channel and possibly a licence occupied.',
      mechanism: 'CANCEL only asks to stop a pending INVITE, and it is hop-by-hop: each hop answers the CANCEL ' +
        'itself with a 200 OK (that 200 acknowledges the CANCEL, NOT the call) and then terminates its own ' +
        'pending INVITE transaction with 487 Request Terminated. The caller must therefore see two responses — ' +
        '200 for the CANCEL and 487 for the INVITE — and the INVITE transaction is not finished until the 487 ' +
        'arrives. A CANCEL also has no effect once a final response is on its way, which is exactly the race ' +
        'here: if the 2xx wins, the correct behaviour for the caller is to ACK the 2xx and immediately send BYE, ' +
        'because a dialog now exists and must be torn down properly rather than ignored.',
      fixes: [
        {
          target: 'generic',
          summary: 'Make sure whoever loses the race cleans up the dialog.',
          steps: [
            'Verify the caller\'s equipment ACKs a 2xx that arrives after its CANCEL and then sends BYE — silently dropping it leaves the callee in a call.',
            'Confirm the B2BUA relays the 487 back on the ingress leg rather than absorbing it.',
            'Look at the timing: if the CANCEL is being sent very late (after the far end has already answered), investigate why the caller gave up — often the ringback never arrived (see any early-media advice here).',
          ],
          config: null,
          caution: null,
          confidence: 'likely',
        },
        {
          target: 'oracle-acme',
          summary: 'Confirm the SBC generates the 487 upstream and tears down the egress leg when the race is lost.',
          steps: [
            'Check `show sipd status` for pending INVITE transactions and stuck sessions after the event.',
            'Review any manipulation acting on 4xx responses that might be dropping the 487.',
            'Check that the SBC issues a BYE on the answered leg when the ingress side has cancelled.',
          ],
          config: null,
          caution: null,
          confidence: 'possible',
        },
        {
          target: 'audiocodes',
          summary: 'Check the SBC\'s handling of a late 200 OK after CANCEL and look for stuck sessions.',
          steps: [
            'Monitor > VoIP Status > Active Calls after reproducing: a call that persists after the caller cancelled is the leak.',
            'Review Message Manipulations on 4xx responses that could suppress the 487.',
          ],
          config: null,
          caution: null,
          confidence: 'possible',
        },
      ],
      findingIds: findingIdsBy(ctx, f => intersects(f.msgIds, m.msgIds) || /cancel|487/i.test(txt(f.title))),
      legIds: [m.legId], callIds, msgIds: m.msgIds,
    };
  },
});

// --- 20. Diameter Rx failure alongside the INVITE --------------------------
RULES.push({
  id: 'diameter-rx-failure',
  kb: ['Diameter Rx AAR failure', 'Result-Code', 'Experimental-Result-Code', 'PCRF', 'dedicated bearer'],
  when: (analysis, ctx) => {
    const out = [];
    const sessions = new Map();   // session id -> { aar, answered }
    for (const x of ctx.aux) {
      if (!x || x.protocol !== 'diameter') continue;
      const d = obj(x.detail);
      const rc = num(d.resultCode) !== null ? num(d.resultCode) : num(d.result);
      const erc = num(d.experimentalResultCode);
      const cmd = txt(d.commandName || d.command || '');
      if ((rc !== null && rc >= 3000) || (erc !== null && erc >= 3000)) {
        out.push({ kind: 'rx-error', aux: x, cmd, rc, erc, legIds: arr(x.legIds), callIds: arr(x.callIds) });
      } else if (/^AA[RA]$/.test(cmd) || /AA-?Request|AA-?Answer/i.test(cmd)) {
        const key = txt(d.sessionId || d.sessionID || x.id);
        const s = sessions.get(key) || { req: null, ans: null };
        if (/R$|Request/i.test(cmd)) s.req = x; else s.ans = x;
        sessions.set(key, s);
      }
      if (out.length >= MAX_MATCHES_PER_RULE) break;
    }
    if (out.length < MAX_MATCHES_PER_RULE) {
      for (const [, s] of sessions) {
        if (s.req && !s.ans) {
          out.push({ kind: 'rx-unanswered', aux: s.req, cmd: 'AAR', rc: null, erc: null,
            legIds: arr(s.req.legIds), callIds: arr(s.req.callIds) });
          if (out.length >= MAX_MATCHES_PER_RULE) break;
        }
      }
    }
    return out;
  },
  build: (m, analysis, ctx) => {
    const x = obj(m.aux);
    const unanswered = m.kind === 'rx-unanswered';
    const codeText = m.erc !== null && m.erc !== undefined ? 'Experimental-Result-Code ' + m.erc
      : (m.rc !== null && m.rc !== undefined ? 'Result-Code ' + m.rc : 'no answer');
    return {
      severity: arr(m.callIds).length ? 'crit' : 'warn',
      title: unanswered
        ? 'Diameter Rx AAR sent with no answer — media authorization never completed'
        : 'Diameter Rx ' + (m.cmd || 'transaction') + ' failed (' + codeText + ')',
      whatsWrong: txt(x.summary) + (unanswered
        ? ' No matching answer appears in the capture, so the policy decision never came back.'
        : ' The PCRF/policy function rejected the request (' + codeText + ').') +
        (arr(m.callIds).length ? ' Correlated with call(s) ' + arr(m.callIds).join(', ') +
          ' — hiccup matched the Rx session to the SIP side, so this is the same call.' : ''),
      whyItMatters: 'The SIP side usually shows a 488, a 503, or a call that sets up and has no media at all. ' +
        'Engineers stare at the SDP for hours because the real refusal happened on a different protocol — the ' +
        'network declined to authorize the bearer, so there is nowhere for the media to go.',
      mechanism: 'On the Rx interface the P-CSCF asks the policy function to authorize the session\'s media: the ' +
        'AA-Request carries the Media-Component-Description built from the SDP (codecs, bandwidth, flow ' +
        'descriptions) and an AF-Charging-Identifier that ties it back to the SIP session — which is why hiccup ' +
        'can correlate the two by matching it against the P-Charging-Vector icid-value. The answer either grants ' +
        'the policy and the network sets up a dedicated bearer, or refuses. A refusal in the 5xxx experimental ' +
        'range typically means the service information was rejected (bandwidth above policy, an unexpected ' +
        'codec, a malformed flow description), while a base Result-Code of 3002/3004/5012 usually means a ' +
        'transport, routing or capacity problem at the Diameter layer rather than a policy decision. No answer ' +
        'at all points at peer or realm routing.',
      fixes: [
        {
          target: 'generic',
          summary: 'Read the answer\'s AVPs, then decide whether it is a policy decision or a Diameter transport problem.',
          steps: [
            'Open the answer in hiccup and note Result-Code / Experimental-Result-Code, Origin-Host and Destination-Realm.',
            'A 5xxx experimental code is a policy refusal: compare the Media-Component-Description against the subscriber\'s policy (bandwidth, codec set, number of components).',
            'A 3xxx base code or no answer is a Diameter-layer problem: check peer state, realm routing tables and the watchdog (DWR/DWA) between the P-CSCF and the PCRF.',
            'Correlate the timestamps with the SIP side — the SIP failure response almost always lands within a few hundred milliseconds of the Rx failure.',
          ],
          config: null,
          caution: null,
          confidence: 'likely',
        },
        {
          target: 'oracle-acme',
          summary: 'Where the SBC is the P-CSCF, check the external policy server object and its transport.',
          steps: [
            'Review the `ext-policy-server` configuration: address, realm, product name and the operation type in use.',
            'Confirm the Diameter connection state and that the SBC is not falling back to a local policy silently.',
            'Check whether the SDP the SBC forwards matches what the policy allows (a transcoded or narrowed codec list changes the Media-Component-Description).',
          ],
          config: acme(
            'ext-policy-server\n' +
            '  name                PCRF-1\n' +
            '  state               enabled\n' +
            '  address             198.51.100.70\n' +
            '  port                3868\n' +
            '  realm               epc.example.net\n' +
            '  protocol            DIAMETER'),
          caution: 'Disabling the policy server to "make calls work" removes bearer authorization entirely — that is a commercial and QoS decision, not a fix.',
          confidence: 'depends-on-topology',
        },
        {
          target: 'network',
          summary: 'Verify the Diameter path itself.',
          steps: [
            'Confirm TCP/SCTP 3868 reachability between the P-CSCF and the PCRF, in both directions.',
            'Check the Diameter watchdog is completing — a peer in a half-open state accepts requests and answers nothing.',
            'Look for a firewall idle timeout tearing down long-lived Diameter connections.',
          ],
          config: null,
          caution: null,
          confidence: 'possible',
        },
      ],
      findingIds: findingIdsBy(ctx, f => /diameter|rx |aar|pcrf/i.test(txt(f.title))),
      legIds: arr(m.legIds), callIds: arr(m.callIds), msgIds: [],
    };
  },
});

// --- 21. REFER transfer failure -------------------------------------------
RULES.push({
  id: 'refer-transfer-failure',
  kb: ['REFER', 'attended transfer fails', 'Refer-To', 'Replaces', 'NOTIFY sipfrag'],
  when: (analysis, ctx) => {
    const out = [];
    for (const leg of ctx.legs) {
      if (!leg || leg.protocol !== 'sip') continue;
      const msgs = originals(legMsgs(ctx, leg));
      const refer = msgs.find(m => m.isRequest && txt(m.method) === 'REFER');
      if (!refer) continue;
      const finals = msgs.filter(m => !m.isRequest && txt(obj(m.cseq).method) === 'REFER' &&
        num(m.status) !== null && m.status >= 300);
      if (finals.length) {
        out.push({ kind: 'rejected', legId: leg.id, status: finals[0].status, reason: txt(finals[0].reason),
          referTo: txt(hdr(refer, 'Refer-To')), msgIds: [refer.id, finals[0].id] });
      } else {
        // accepted, but the implicit subscription reports a failure in the sipfrag
        const bad = msgs.find(m => m.isRequest && txt(m.method) === 'NOTIFY' &&
          /SIP\/2\.0\s+[4-6]\d\d/.test(txt(m.raw)));
        if (bad) {
          const frag = (/SIP\/2\.0\s+([4-6]\d\d[^\r\n]*)/.exec(txt(bad.raw)) || [, ''])[1];
          out.push({ kind: 'notify-failed', legId: leg.id, frag: txt(frag).trim(),
            referTo: txt(hdr(refer, 'Refer-To')), msgIds: [refer.id, bad.id] });
        }
      }
      if (out.length >= MAX_MATCHES_PER_RULE) break;
    }
    return out;
  },
  build: (m, analysis, ctx) => {
    const rejected = m.kind === 'rejected';
    return {
      severity: 'warn',
      title: rejected
        ? 'REFER rejected with ' + m.status + (m.reason ? ' ' + m.reason : '') + ' — the transfer never started'
        : 'REFER accepted but the transfer failed (' + m.frag + ')',
      whatsWrong: 'On leg ' + m.legId + ', ' + (rejected
        ? 'the REFER was answered ' + m.status + (m.reason ? ' ' + m.reason : '') + '.'
        : 'the REFER was accepted and the implicit subscription then reported "' + m.frag + '".') +
        (m.referTo ? ' Refer-To was: ' + m.referTo : ''),
      whyItMatters: 'Attended and blind transfers fail. The user presses transfer, the call either stays where ' +
        'it is or drops entirely, and the receptionist/agent has to explain it to the caller. It is one of the ' +
        'most visible faults in a contact-centre or reception-desk deployment.',
      mechanism: 'REFER asks the recipient to contact the URI in Refer-To. Accepting it (202) creates an implicit ' +
        'subscription, and the transferee reports progress back in NOTIFY bodies containing a SIP status fragment ' +
        '(message/sipfrag) — so a 202 means "I will try", not "it worked". Attended transfer additionally relies ' +
        'on the Replaces header to substitute the new call for the existing one. SBCs break this in predictable ' +
        'ways: the Refer-To URI points at an internal address the far side cannot route to (or was not rewritten ' +
        'by topology hiding), the box is configured to consume REFER locally and generate a new INVITE but ' +
        'cannot find the referenced dialog, the peer does not allow REFER on the trunk at all, or the Replaces ' +
        'dialog identifiers no longer match after the B2BUA rewrote the Call-ID and tags on each leg.',
      fixes: [
        {
          target: 'oracle-acme',
          summary: 'Decide whether the SBC should terminate REFER locally or pass it through, and set it explicitly.',
          steps: [
            'Enable `refer-call-transfer` on the session-agent or sip-interface if the SBC should convert REFER into a new INVITE towards the referred target.',
            'If REFER must pass through, verify Refer-To (and any Replaces parameters) are rewritten so the far end can route them.',
            'Check that the referred-to destination has a route/local-policy entry — a REFER to an unroutable target fails as a rejection.',
          ],
          config: acme(
            'session-agent\n' +
            '  hostname            peer.example.net\n' +
            '  refer-call-transfer enabled'),
          caution: 'Terminating REFER locally means the SBC issues the new call: check licensing/session counting and CDR impact.',
          confidence: 'likely',
        },
        {
          target: 'audiocodes',
          summary: 'Set the REFER behaviour on the IP Profile for the peer.',
          steps: [
            'Setup > Signaling & Media > Coders & Profiles > IP Profiles > this peer: set `SBCRemoteReferBehavior` (regular / handle locally / by IP Group) to match what the peer supports.',
            'Where the device handles REFER locally, confirm the routing rules can reach the Refer-To target.',
            'Check Message Manipulations acting on Refer-To or Replaces.',
          ],
          config: audiocodes(
            '[ IPProfile ]\n' +
            '; SBCRemoteReferBehavior: 0=Regular, 1=Database URL, 2=IP Group Name, 3=Handle Locally\n' +
            'IPProfile 1 = "ITSP", ..., SBCRemoteReferBehavior=3;'),
          caution: 'Handling REFER locally changes who is billed for the transferred leg.',
          confidence: 'likely',
        },
        {
          target: 'generic',
          summary: 'Check the transfer target is reachable and the dialog references still match.',
          steps: [
            'Read the Refer-To URI in the trace: if it contains an internal address or a tag set from the other leg, it cannot work through a B2BUA unchanged.',
            'For attended transfer, confirm Replaces identifies a dialog the recipient actually knows about (Call-ID and both tags as that side sees them).',
            'Ask the peer whether REFER is permitted on the trunk at all — many carriers reject it by policy and expect re-INVITE-based transfer instead.',
          ],
          config: null,
          caution: null,
          confidence: 'likely',
        },
      ],
      findingIds: findingIdsBy(ctx, f => /refer|transfer/i.test(txt(f.title)) || intersects(f.msgIds, m.msgIds)),
      legIds: [m.legId], callIds: ctx.calls.filter(c => arr(c.legIds).indexOf(m.legId) !== -1).map(c => c.id),
      msgIds: m.msgIds,
    };
  },
});

// --- 22. Box-wide retransmission storm ------------------------------------
RULES.push({
  id: 'box-wide-storm',
  kb: ['retransmission storm', 'licence exhaustion', 'CPU saturation', 'session agent out of service', 'SBC overload'],
  when: (analysis, ctx) => ctx.stormWindows.slice(0, 4).map(w => ({ kind: 'storm', window: w })),
  build: (m, analysis, ctx) => {
    const w = obj(m.window);
    const span = num(w.endTs) !== null && num(w.startTs) !== null ? w.endTs - w.startTs : null;
    return {
      severity: 'crit',
      title: 'Box-wide retransmission storm: ' + txt(w.legsAffected) + ' legs retransmitting at once',
      whatsWrong: txt(w.legsAffected) + ' independent legs retransmitted ' + txt(w.retransCount) +
        ' messages inside the same window' + (span !== null ? ' (' + fmtS(span) + ')' : '') +
        '. hiccup\'s verdict for this window is "' + txt(w.verdict) + '".',
      whyItMatters: 'This is the difference between "this call is broken" and "the box is melting", and it ' +
        'changes who you wake up. Individual call troubleshooting is wasted effort here: unrelated dialogs do not ' +
        'fail in the same two seconds by coincidence. Expect a wave of customer reports covering everything on ' +
        'the platform for the duration of the window.',
      mechanism: 'Retransmissions are per-transaction and timer-driven: Timer A fires at T1 and doubles. When ' +
        'many independent transactions all start retransmitting in the same window, the shared element is the ' +
        'common factor — the box itself or its next hop. The usual causes are session/licence capacity reached ' +
        '(new transactions are dropped rather than rejected), CPU or task saturation so the SIP process cannot ' +
        'service the socket, a session agent or next-hop marked out of service, or a routing/interface flap. ' +
        'Worse, the mechanism amplifies itself: each unanswered request produces more retransmissions, which ' +
        'add load to an already saturated box.',
      fixes: [
        {
          target: 'oracle-acme',
          summary: 'Check capacity, licences and session-agent state for the window, then constrain rather than let it recur.',
          steps: [
            '`show sipd status` and `show sipd errors` around the timestamp — look for dropped messages and transaction-expire counts.',
            '`show session-agent` / `show sa stats`: an out-of-service agent or one hitting its constraints explains a whole-box event.',
            'Check licensed session capacity and the high-water marks (`show features`, session capacity counters).',
            'Apply session-constraints per session-agent so an overloaded peer gets rejected cleanly instead of causing a storm.',
          ],
          config: acme(
            'session-constraints\n' +
            '  name                PEER-LIMITS\n' +
            '  max-sessions        500\n' +
            '  max-burst-rate      50\n' +
            '  max-sustain-rate    30\n' +
            '\n' +
            'session-agent\n' +
            '  hostname            peer.example.net\n' +
            '  constraints         enabled\n' +
            '  session-constraints PEER-LIMITS'),
          caution: 'Constraints start rejecting calls at the limit — that is the point, but it is a visible change in behaviour and needs to be agreed.',
          confidence: 'possible',
        },
        {
          target: 'audiocodes',
          summary: 'Check licence/session capacity and admission control, and confirm the CPU was not saturated.',
          steps: [
            'Monitor > Performance Monitoring and the device\'s CPU/session statistics for the window.',
            'Verify the SBC session licence limit is not being reached (`show system license` / the Web UI licence page).',
            'Configure Admission Control (SBC CAC) per IP Group so overload is rejected rather than dropped.',
          ],
          config: null,
          caution: null,
          confidence: 'possible',
        },
        {
          target: 'network',
          summary: 'Rule out the next hop and the path rather than the box.',
          steps: [
            'Check whether the next hop was reachable during the window (interface flap, routing convergence, upstream maintenance).',
            'Compare against interface counters and any link-state logs at the same timestamp.',
            'If the storm coincides with a scheduled job (backup, statistics export), suspect resource contention on the platform.',
          ],
          config: null,
          caution: null,
          confidence: 'possible',
        },
      ],
      findingIds: findingIdsBy(ctx, f => /storm/i.test(txt(f.title))),
      legIds: [], callIds: [], msgIds: [],
    };
  },
});

// --- 23. Slow far end (late first response) -------------------------------
RULES.push({
  id: 'slow-far-end',
  kb: ['late response', 'slow call setup', '100 Trying missing', 'T1 timer', 'post-dial delay'],
  when: (analysis, ctx) => collapseMatches(ctx, ['slow-far-end']),
  build: (m, analysis, ctx) => {
    const s = obj(m.sample);
    return {
      severity: 'warn',
      title: 'Far end answers late: ' + m.what + ' to ' + m.dst + ' retransmitted before the first response',
      whatsWrong: '"' + txt(s.label) + '". ' + txt(obj(s.classification).detail),
      whyItMatters: 'Every call to this destination has visible post-dial delay — the caller waits in silence ' +
        'and often hangs up before ringback starts, which shows up in reporting as abandoned calls rather than ' +
        'as a fault. The retransmissions also mean the far end receives the same INVITE several times and has to ' +
        'discard the copies.',
      mechanism: 'A client transaction retransmits its INVITE after T1 (500 ms) if nothing has come back. Any ' +
        'SIP element that has received and parsed the request should answer well inside that — a proxy or B2BUA ' +
        'emits 100 Trying immediately, precisely to stop retransmissions. A first response arriving seconds ' +
        'later therefore means the far end (or something in front of it) is doing blocking work before it ' +
        'answers: a synchronous database or ENUM lookup, DNS resolution in the signalling path, media/DSP ' +
        'allocation, or a downstream leg it waits for. hiccup upgrades this verdict to "blocking DNS" when the ' +
        'delay is consistent across several legs to the same destination, so a per-destination pattern is the ' +
        'thing to look for.',
      fixes: [
        {
          target: 'generic',
          summary: 'Establish whether the delay is per-destination or general, then push it to the party that owns the delay.',
          steps: [
            'Compare the first-response delay across destinations in this capture: one destination affected means the far end or its resolution path; all destinations means something local.',
            'Capture DNS (port 53) alongside SIP to confirm or eliminate resolution as the cause.',
            'Give the far-end operator the timestamps and CSeq of the retransmitted INVITEs — the delay is measurable from their side too.',
          ],
          config: null,
          caution: null,
          confidence: 'likely',
        },
        {
          target: 'oracle-acme',
          summary: 'Detect and de-prioritise a slow peer instead of absorbing the delay on every call.',
          steps: [
            'Configure OPTIONS pings on the session-agent so the box notices when the peer degrades.',
            'Set out-of-service response codes and a response timeout so a slow/failing agent is taken out of rotation.',
            'If several agents serve the destination, enable recursion so a slow one does not stall every call.',
          ],
          config: acme(
            'session-agent\n' +
            '  hostname            peer.example.net\n' +
            '  ping-method         OPTIONS;hops=0\n' +
            '  ping-interval       30\n' +
            '  out-service-response-codes  408,500,503\n' +
            '  response-timeout    5'),
          caution: 'Aggressive out-of-service thresholds can flap a peer in and out of service on transient delay.',
          confidence: 'possible',
        },
        {
          target: 'audiocodes',
          summary: 'Enable proxy keep-alive and hot-swap so a slow proxy is bypassed.',
          steps: [
            'Setup > Signaling & Media > Core Entities > Proxy Sets: enable keep-alive with a sensible interval.',
            'Enable proxy hot-swap so the device moves to the next proxy in the set when one stops answering.',
            'Confirm the DNS resolve method for the Proxy Set is not adding lookup time per call.',
          ],
          config: null,
          caution: null,
          confidence: 'possible',
        },
      ],
      findingIds: findingIdsBy(ctx, f => f.category === 'retrans' && intersects(f.msgIds, m.msgIds)),
      legIds: m.legIds, callIds: m.callIds, msgIds: m.msgIds.slice(0, 12),
    };
  },
});

// --- 24. Q.850 / ISUP / H.323 release causes -------------------------------
const Q850_NOTES = {
  1: ['warn', 'unallocated number: the far switch has no translation for the digits it received — check digit manipulation and the ranges provisioned on the trunk'],
  3: ['warn', 'no route to destination: the far switch has no route for these digits'],
  16: ['info', 'normal call clearing — this is how a healthy call ends'],
  17: ['info', 'user busy — a normal outcome, unless every call to this destination gets it'],
  18: ['notice', 'no user responding: the terminating side never alerted at all'],
  19: ['info', 'no answer from user after alerting — ring-no-answer'],
  21: ['notice', 'call rejected: screening, blocked CLI, or an authorization failure at the far end'],
  22: ['notice', 'number changed'],
  27: ['warn', 'destination out of order'],
  28: ['warn', 'invalid or incomplete number: the digits arrived shorter or longer than the far end expects — a digit map or overlap-dialling problem'],
  31: ['notice', 'normal, unspecified: the far end gave no real reason, which usually means an application or policy reject'],
  34: ['crit', 'no circuit/channel available: trunk capacity or licence exhaustion on the far side'],
  38: ['crit', 'network out of order: the far network is failing, not this call'],
  41: ['crit', 'temporary failure: a genuine fault on the terminating side, usually recurrent rather than one-off'],
  42: ['crit', 'switching equipment congestion: the far switch is overloaded'],
  44: ['warn', 'requested circuit/channel not available'],
  47: ['crit', 'resource unavailable, unspecified — the catch-all for bearer, media or DSP allocation failures'],
  50: ['warn', 'requested facility not subscribed'],
  57: ['warn', 'bearer capability not authorized'],
  58: ['warn', 'bearer capability not presently available'],
  63: ['warn', 'service or option not available'],
  65: ['warn', 'bearer capability not implemented — a codec or bearer mismatch across the gateway'],
  79: ['warn', 'service or option not implemented'],
  88: ['crit', 'incompatible destination — classically a codec or bearer mismatch through the interworking function'],
  95: ['warn', 'invalid message: a protocol error, so read the messages immediately before this one'],
  97: ['warn', 'message type not implemented'],
  99: ['warn', 'information element not implemented'],
  102: ['crit', 'recovery on timer expiry: a timer ran out mid-setup and the far end stopped waiting'],
  111: ['warn', 'protocol error, unspecified'],
  127: ['crit', 'interworking, unspecified: the gateway could not map the far end\'s real reason, so the true cause is upstream'],
};

RULES.push({
  id: 'release-cause',
  kb: ['Q.850 cause code', 'ISUP release cause', 'H.323 RELEASE COMPLETE', 'cause mapping', 'ISUP to SIP'],
  when: (analysis, ctx) => {
    const groups = new Map();
    const add = (code, text, kind, msgId, legId) => {
      const note = Q850_NOTES[code];
      if (!note || note[0] === 'info') return;    // 16/17/19 are normal outcomes
      const key = kind + ':' + code;
      const g = groups.get(key) || { kind: 'cause', source: kind, code, causeText: txt(text),
        sev: note[0], note: note[1], count: 0, msgIds: [], legIds: [] };
      g.count++;
      if (msgId && g.msgIds.length < 8 && g.msgIds.indexOf(msgId) === -1) g.msgIds.push(msgId);
      if (legId && g.legIds.indexOf(legId) === -1) g.legIds.push(legId);
      groups.set(key, g);
    };
    for (const m of ctx.h323) {
      const code = num(m && m.causeCode);
      if (code === null) continue;
      const leg = ctx.legs.find(l => l && arr(l.msgIds).indexOf(m.id) !== -1);
      add(code, m.causeText, 'h323', m.id, leg ? leg.id : null);
    }
    for (const m of ctx.sip) {
      const isup = obj(m && m.isup);
      const code = num(isup.causeCode);
      if (code === null) continue;
      const leg = ctx.legs.find(l => l && arr(l.msgIds).indexOf(m.id) !== -1);
      add(code, isup.causeText, 'sip-i', m.id, leg ? leg.id : null);
    }
    return Array.from(groups.values()).slice(0, MAX_MATCHES_PER_RULE);
  },
  build: (m, analysis, ctx) => {
    const isup = m.source === 'sip-i';
    const label = 'cause ' + m.code + (m.causeText ? ' (' + m.causeText + ')' : '');
    return {
      severity: m.sev === 'crit' ? 'crit' : (m.sev === 'warn' ? 'warn' : 'notice'),
      title: (isup ? 'ISUP release with ' : 'H.323 release with ') + label +
        (m.count > 1 ? ' on ' + m.count + ' calls' : ''),
      whatsWrong: (isup
        ? 'An ISUP body inside the SIP signalling carries Q.850 ' + label
        : 'A Q.931 message carries Q.850 ' + label) +
        (m.count > 1 ? ', seen ' + m.count + ' times in this capture' : '') + '. Reading of that cause: ' + m.note + '.',
      whyItMatters: m.sev === 'crit'
        ? 'Callers get a failure or congestion tone with no useful explanation, and because the cause is ' +
          'generated on the far side of the gateway the SIP status code alone does not tell you why. Repeated ' +
          'occurrences of this cause point at a capacity or platform problem rather than individual calls.'
        : 'The cause value is the far end telling you precisely what it objected to — far more specific than the ' +
          'SIP status it gets mapped to. Reading it correctly saves an escalation cycle with the other operator.',
      mechanism: 'Q.850 defines the cause values used in Q.931 (H.323 RELEASE COMPLETE) and ISUP REL messages, ' +
        'with a location field saying which network generated it. SIP interworking maps them to status codes — ' +
        'user busy (17) becomes 486, no circuit available (34) becomes 503 — and that mapping is deliberately ' +
        'lossy, so several very different faults arrive as the same SIP response. Reading the original cause ' +
        'value (and its location) tells you whether the problem is number translation, capacity, bearer ' +
        'incompatibility or a protocol error, which is why cause-code mapping tables exist on every gateway. ' +
        'Cause 127 is a special case: it means the gateway itself could not determine a reason, so the real ' +
        'cause is further upstream and you need the far end\'s trace.',
      fixes: [
        {
          target: 'generic',
          summary: 'Treat the cause value as the far end\'s diagnosis and act on that specific meaning.',
          steps: [
            'Note the cause location as well as the value — it says whose network raised it (local, transit, remote user).',
            m.code === 88 || m.code === 65 ? 'Compare the offered bearer/codec with what the far end supports; incompatibility causes are almost always a media negotiation problem.' :
              (m.code === 34 || m.code === 42 ? 'Correlate with the time of day and call volume: capacity causes cluster at the busy hour.' :
                'Check digit manipulation and the number ranges provisioned for this trunk against the digits actually sent.'),
            'Give the far-end operator the timestamp, the called/calling numbers and the cause value — that is enough for them to find the call.',
          ],
          config: null,
          caution: null,
          confidence: 'likely',
        },
        {
          target: 'audiocodes',
          summary: 'Review the cause mapping tables so the SIP side receives a meaningful status.',
          steps: [
            'Check the ISDN-to-SIP and SIP-to-ISDN cause mapping tables and make sure this cause maps to a status the SIP side can act on.',
            'Avoid mapping distinct causes onto one generic 503 — it destroys the diagnostic value downstream.',
          ],
          config: audiocodes(
            '[ CauseMapISDN2SIP ]\n' +
            'CauseMapISDN2SIP 0 = ' + m.code + ', 503;    ; Q.850 cause -> SIP status\n' +
            '[ CauseMapSIP2ISDN ]\n' +
            'CauseMapSIP2ISDN 0 = 503, ' + m.code + ';'),
          caution: 'Cause mapping changes alter what upstream routing logic sees — check any least-cost-routing or failover rules that key on status codes.',
          confidence: 'possible',
        },
        {
          target: 'oracle-acme',
          summary: 'Check the SIP↔Q.850 mapping used by the interworking function.',
          steps: [
            'Review the cause-mapping configuration bound to the H.323 stack / interworking side.',
            'Confirm the mapping is applied in the direction you expect, and that a fallback does not flatten every cause into one status.',
          ],
          config: null,
          caution: null,
          confidence: 'depends-on-topology',
        },
      ],
      findingIds: findingIdsBy(ctx, f => f.category === 'h323' || intersects(f.msgIds, m.msgIds)),
      legIds: m.legIds, callIds: [], msgIds: m.msgIds,
      extraCitations: isup
        ? [cite(REFS.sipt, 'The ISUP body is being carried inside SIP under the SIP-T/SIP-I encapsulation model described here.')]
        : [cite(REFS.q931, 'The RELEASE COMPLETE message and its Cause information element are defined here.')],
    };
  },
});

// --- 25. Correlation ambiguity ---------------------------------------------
RULES.push({
  id: 'correlation-ambiguous',
  kb: ['call correlation', 'Session-ID header', 'P-Charging-Vector icid', 'X-header correlation', 'B2BUA leg pairing'],
  when: (analysis, ctx) => ctx.calls
    .filter(c => c && txt(c.state) === 'ambiguous')
    .slice(0, MAX_MATCHES_PER_RULE)
    .map(c => ({ kind: 'ambiguous', call: c })),
  build: (m, analysis, ctx) => {
    const c = obj(m.call);
    const cands = arr(c.candidates).map(x => txt(obj(x).legId) + ' (' + txt(obj(x).confidence) + ')').join(', ');
    return {
      severity: 'notice',
      title: 'Call ' + txt(c.id) + ' could not be paired unambiguously — hiccup is refusing to guess',
      whatsWrong: 'Legs ' + arr(c.legIds).join(', ') + ' scored too close to competing candidates' +
        (cands ? ' (' + cands + ')' : '') + ', so this call is marked ambiguous rather than paired. ' +
        'Nothing in the signalling ties the ingress and egress legs together strongly enough to be certain.',
      whyItMatters: 'Everything downstream of correlation — the two-leg diff, the ladder that shows both sides, ' +
        'the "what did the SBC change" answer — depends on knowing which egress leg belongs to which ingress ' +
        'leg. A wrong guess produces a confident, plausible and completely false diff, which is worse than no ' +
        'diff at all. On a busy trunk with repeated numbers this is the normal state of affairs unless a ' +
        'correlation identifier is present.',
      mechanism: 'A B2BUA terminates the dialog and creates a fresh one: new Call-ID, new tags, new branch, often ' +
        'rewritten numbers and rewritten SDP. Nothing in base SIP survives the hop, so correlation has to be ' +
        'inferred from weaker signals — a vendor X-header or a P-Charging-Vector icid-value that the box copies ' +
        'across (strongest), matching SDP origin session id, an egress INVITE appearing a few milliseconds after ' +
        'the ingress one, or surviving user parts. When two candidate legs score within the margin, the only ' +
        'honest answer is "ambiguous". The durable fix is to carry an identifier designed for this: the ' +
        'P-Charging-Vector icid-value in 3GPP networks, or the Session-ID header, which is specified precisely ' +
        'so that a single value survives B2BUAs end to end.',
      fixes: [
        {
          target: 'generic',
          summary: 'Put a correlation identifier on the wire, then this stops being guesswork for every tool you use.',
          steps: [
            'Enable Session-ID (RFC 7989) support on the SBC and the surrounding equipment if the releases support it — it is designed to survive a B2BUA.',
            'Failing that, have the SBC stamp an X-header on egress carrying the ingress Call-ID.',
            'For this capture: narrow it manually using timestamps, the media addresses/ports in the SDP, and the RTP streams — media often pairs legs when signalling cannot.',
          ],
          config: null,
          caution: 'A header carrying the internal Call-ID exposes a little internal information to the peer; strip it on trunks where that matters.',
          confidence: 'likely',
        },
        {
          target: 'oracle-acme',
          summary: 'Stamp the ingress Call-ID into an egress header with a manipulation.',
          steps: [
            'Create a sip-manipulation that stores the ingress Call-ID and adds it as an X-header on the egress INVITE.',
            'Bind it as the out-manipulation on the egress session-agent or realm.',
            'Re-capture and confirm hiccup now pairs the legs at high confidence.',
          ],
          config: acme(
            'sip-manipulation\n' +
            '  name                  ADD-CORRELATION\n' +
            '  header-rule\n' +
            '    name                stampCallId\n' +
            '    header-name         X-Correlation-Id\n' +
            '    action              add\n' +
            '    comparison-type     case-sensitive\n' +
            '    msg-type            request\n' +
            '    methods             INVITE\n' +
            '    new-value           $ORIGINAL_CALL_ID'),
          caution: 'Check the variable/stored-value syntax for your release — the mechanism is standard but the reference name differs.',
          confidence: 'depends-on-topology',
        },
        {
          target: 'audiocodes',
          summary: 'Preserve the original Call-ID across the legs, or add a correlation header.',
          steps: [
            'Setup > Signaling & Media > Coders & Profiles > IP Profiles: consider `SBCKeepOriginalCallID` so the same Call-ID appears on both legs.',
            'Alternatively add a Message Manipulation stamping a correlation header on egress.',
            'Confirm with the peer that a shared Call-ID is acceptable on that trunk.',
          ],
          config: audiocodes(
            '[ IPProfile ]\n' +
            'IPProfile 1 = "ITSP", ..., SBCKeepOriginalCallID=1;'),
          caution: 'Reusing the Call-ID across legs makes both legs share an identifier — useful for tracing, but some peers dislike seeing an internal Call-ID.',
          confidence: 'possible',
        },
        {
          target: 'ribbon',
          summary: 'Add an SMM rule stamping a correlation header on the egress trunk group.',
          steps: [
            'Create a sipAdaptorProfile rule that copies the ingress Call-ID into an X-header on egress.',
            'Bind it as the output adapter profile on the egress trunk group.',
          ],
          config: null,
          caution: null,
          confidence: 'depends-on-topology',
        },
      ],
      findingIds: findingIdsBy(ctx, f => f.category === 'correlation' && arr(f.callIds).indexOf(c.id) !== -1),
      legIds: arr(c.legIds), callIds: [txt(c.id)], msgIds: [],
    };
  },
});

// --- 26. Indicator flagged as faulty with no more specific rule -------------
// Every indicator key that already has a DEDICATED rule elsewhere in this
// table. The indicator-issue catch-all below only fires for a faulty
// indicator that has no specific rule — omitting a key here produces a
// near-duplicate generic card alongside the specific one.
const INDICATOR_COVERED = [
  't38', 'precondition', 'early-media', 'dns', 'diameter', 'stun-ice', 'dtls-srtp',
  'dtmf-rfc4733', '100rel', 'session-timers', 'topology-hiding',
];
const INDICATOR_REFS = {
  sip: 'sip_base', h323: 'h323', iwf: 'isup_map', 'sip-i': 'sipt', ims: 'ts24229',
  rtp: 'rtp_base', rtcp: 'rtp_reports', srtp: 'srtp', 'dtmf-rfc4733': 'dtmf',
  '100rel': 'rel100', 'session-timers': 'session_timers', 'update-method': 'update',
  'tcp-transport': 'sip_sending', 'tls-transport': 'sip_base', ipv6: 'ipv6_sip',
  registration: 'sip_registrations', 'topology-hiding': 'sip_contact',
  transcoding: 'offans', 'refer-transfer': 'refer', 'history-info': 'history_info',
};

RULES.push({
  id: 'indicator-issue',
  kb: ['protocol feature detected but broken', 'capability negotiation failure'],
  when: (analysis, ctx) => ctx.indicators
    .filter(i => i && i.state === 'issue' && INDICATOR_COVERED.indexOf(i.key) === -1)
    .slice(0, MAX_MATCHES_PER_RULE)
    .map(i => ({ kind: 'indicator', indicator: i })),
  build: (m, analysis, ctx) => {
    const i = obj(m.indicator);
    const refKey = INDICATOR_REFS[txt(i.key)];
    return {
      severity: 'warn',
      title: txt(i.label || i.key) + ' is in use but something about it is provably wrong',
      whatsWrong: txt(i.detail) || 'The ' + txt(i.key) + ' indicator is flagged as faulty in this capture.',
      whyItMatters: 'A feature that is half-working is worse than one that is absent: both ends believe it is ' +
        'available and behave accordingly, so the failure appears somewhere else entirely — as a dropped call, ' +
        'missing audio, or a rejection whose stated reason has nothing to do with the real cause.',
      mechanism: 'hiccup marks an indicator as "issue" only when the feature is detected AND the evidence shows ' +
        'it failing (offered and rejected, requested and never confirmed, negotiated and then contradicted). ' +
        'Open the evidence messages listed with this advice and read the negotiation in order: the offer, the ' +
        'answer, and the message that contradicts it. The generic pattern is a capability asserted on one leg ' +
        'and not carried onto the other, which is exactly what a B2BUA is in a position to break.',
      fixes: [
        {
          target: 'generic',
          summary: 'Follow the feature\'s negotiation across both legs and find the hop that drops it.',
          steps: [
            'List the messages where the feature appears (Supported/Require headers, SDP attributes, method names) on each leg.',
            'Find the first hop where it stops appearing — that is where the configuration change belongs.',
            'Decide deliberately whether the border element should interwork the feature or refuse it up front; silently dropping it is what produces this state.',
          ],
          config: null,
          caution: null,
          confidence: 'depends-on-topology',
        },
      ],
      findingIds: findingIdsBy(ctx, f => intersects(f.msgIds, arr(i.evidenceMsgIds))),
      legIds: legIdsForMsgs(ctx, i.evidenceMsgIds), callIds: arr(i.evidenceCallIds), msgIds: arr(i.evidenceMsgIds).slice(0, 8),
      extraCitations: refKey && REFS[refKey]
        ? [cite(REFS[refKey], 'The specification for the feature this indicator tracks (' + txt(i.key) + ').')]
        : [],
    };
  },
});

// ---------------------------------------------------------------------------
// Base citations per rule — the ALWAYS-applicable references for that
// condition. A build() may add match-specific ones on top via
// `extraCitations` (e.g. release-cause picks SIP-I vs H.323 depending on the
// match). Only citations I am confident are correct appear here at all; see
// the discipline note by REFS above. Rules not listed get [] (indicator-issue
// supplies its citation entirely through extraCitations, keyed off which
// indicator actually faulted).
// ---------------------------------------------------------------------------

const CITATIONS = {
  'invite-timer-b-no-100': [
    cite(REFS.sip_invite_ct, 'Defines Timer A/Timer B and the retransmission backoff being observed.'),
    cite(REFS.sip_sending, 'A parsed request should be answered almost immediately — the absence of even a 100 Trying is the anomaly.'),
  ],
  'udp-oversize': [
    cite(REFS.sip_sending, 'The rule that a UDP request approaching the MTU should switch to a congestion-controlled transport (TCP).'),
  ],
  'two-hundred-no-ack': [
    cite(REFS.sip_2xx_uac, 'The UAC is required to generate an ACK for every 2xx it receives, including retransmitted copies.'),
    cite(REFS.sip_2xx_uas, 'The UAS retransmits the 2xx until the ACK is received or the transaction times out — the behaviour being observed.'),
    cite(REFS.sip_dialog_uas, 'The Contact/route-set rules that determine where the ACK is actually sent.'),
  ],
  'route-set-mismatch': [
    cite(REFS.sip_dialog_uas, 'How the route set is built from Record-Route and where subsequent requests within the dialog are sent.'),
    cite(REFS.rr_issues, 'Known Record-Route/topology-hiding interaction problems this pattern resembles.'),
    cite(REFS.sip_contact, 'The Contact header requirement that topology hiding has to honour without breaking.'),
  ],
  'prack-100rel-asymmetry': [
    cite(REFS.rel100, 'Defines the Supported/Require 100rel negotiation and the PRACK method being asymmetric here.'),
  ],
  'session-timer-conflict': [
    cite(REFS.session_timers, 'Defines Session-Expires, Min-SE and the 422 (Session Interval Too Small) negotiation.'),
  ],
  'dtmf-pt-mismatch': [
    cite(REFS.dtmf, 'Defines the telephone-event payload format and its dynamic payload-type negotiation via rtpmap.'),
    cite(REFS.offans, 'The offer/answer rule that a dynamic payload type must be negotiated per leg, which a B2BUA can break.'),
  ],
  'codec-ptime-renegotiation': [
    cite(REFS.offans, 'Governs how an answer is generated from an offer, including codec selection and ptime.'),
    cite(REFS.sdp, 'The SDP attribute definitions (rtpmap, ptime, fmtp) involved in the mismatch.'),
  ],
  'early-media-asymmetry': [
    cite(REFS.early_media, 'Defines the 180-vs-183(+SDP) early media patterns being compared across the legs.'),
    cite(REFS.pem, 'P-Early-Media authorization, when present, governs whether early media should be cut through at all.'),
  ],
  'private-ip-leak': [
    cite(REFS.private_addr, 'Defines the private address ranges that should not be visible outside the trust boundary.'),
    cite(REFS.sip_contact, 'The Contact/SDP address rewriting that topology hiding is supposed to perform.'),
  ],
  't38-asymmetry': [
    cite(REFS.t38, 'Defines the T.38 fax-relay re-INVITE switchover this asymmetry breaks.'),
    cite(REFS.sdp_caps, 'The SDP capability-negotiation mechanism T.38 switchover typically relies on.'),
  ],
  'one-way-audio': [
    cite(REFS.sdp, 'Defines the sendrecv/sendonly/recvonly/inactive direction attributes that should match reality.'),
    cite(REFS.offans, 'The offer/answer rule that both sides negotiate a bidirectional stream unless explicitly restricted.'),
  ],
  'rtp-quality': [
    cite(REFS.rtp_reports, 'Defines the loss and interarrival jitter fields these statistics are computed the same way as.'),
    cite(REFS.g107, 'The E-model this MOS estimate is a simplified reduction of.'),
  ],
  'dns-egress-stall': [
    cite(REFS.locating, 'Defines the NAPTR → SRV → A resolution sequence being stalled or timing out here.'),
    cite(REFS.sip_sending, 'The transaction-timer consequence of a slow resolution step in the request path.'),
  ],
  'missing-service-route': [
    cite(REFS.service_route, 'Defines the Service-Route header and the registrar\'s obligation to return it in the 200 OK.'),
    cite(REFS.ts24229, 'The IMS registration procedures that depend on Service-Route being present to route subsequent requests correctly.'),
  ],
  'precondition-unconfirmed': [
    cite(REFS.precond, 'Defines the current/desired/confirm precondition status lines (a=curr/a=des/a=conf) this checks.'),
    cite(REFS.precond_upd, 'Clarifies precondition handling with the UPDATE method, relevant when confirmation never arrives.'),
  ],
  'ice-dtls-failure': [
    cite(REFS.ice, 'Defines the connectivity-check procedure whose failure is being reported.'),
    cite(REFS.dtls_srtp, 'Defines the DTLS-SRTP handshake that is stalling.'),
  ],
  'digest-auth-loop': [
    cite(REFS.sip_digest, 'Defines the Digest challenge/response exchange this loop fails to complete.'),
    cite(REFS.digest_http, 'The current HTTP Digest specification SIP\'s Digest usage is aligned with, including nonce handling.'),
  ],
  'cancel-race': [
    cite(REFS.sip_cancel_uac, 'Defines correct CANCEL behaviour on the client side, including the race with a final response.'),
    cite(REFS.sip_cancel_uas, 'Defines the UAS obligation to respond 487 to the cancelled INVITE.'),
  ],
  'diameter-rx-failure': [
    cite(REFS.ts29214, 'Defines the Rx AAR/AAA exchange for dedicated bearer authorization this INVITE depends on.'),
    cite(REFS.diameter, 'Base Diameter error-handling semantics for the Result-Code being reported.'),
  ],
  'refer-transfer-failure': [
    cite(REFS.refer, 'Defines the REFER method and the NOTIFY-reported outcome of the transfer attempt.'),
    cite(REFS.refer_clarify, 'Clarifies REFER/NOTIFY subscription handling relevant to transfer-outcome reporting.'),
  ],
  'box-wide-storm': [
    cite(REFS.sip_invite_ct, 'The per-transaction timer behaviour that, multiplied across many concurrent dialogs, produces the storm shape being reported.'),
  ],
  'slow-far-end': [
    cite(REFS.sip_invite_ct, 'Defines the T1-driven retransmission the delayed first response is triggering.'),
    cite(REFS.locating, 'A common source of this exact delay pattern when it is specific to one destination.'),
  ],
  'release-cause': [
    cite(REFS.q850, 'Defines the cause and location values this finding decodes.'),
  ],
  'correlation-ambiguous': [
    cite(REFS.session_id, 'The purpose-built header that would remove this ambiguity by surviving the B2BUA end to end.'),
    cite(REFS.pheaders_3gpp, 'The P-Charging-Vector icid-value mechanism that serves the same purpose in 3GPP networks.'),
  ],
  'indicator-issue': [],
};

// ---------------------------------------------------------------------------
// buildAdvice — the only exported entry point. Runs every rule defensively:
// a rule that throws (in `when` or `build`) is skipped, never fatal to the
// capture. Deterministic and synchronous — see the file header.
// ---------------------------------------------------------------------------

/**
 * @param {object} analysis - the AnalysisJSON object being assembled (called
 *   after media/aux/retrans/diff/indicators/scenario are attached).
 * @param {{retrieve?: (query: string) => Array<object>}} [opts] - optional KB
 *   retriever. Must be synchronous: if `retrieve` returns anything other than
 *   a plain array (e.g. a Promise), its result is treated as "no hits" rather
 *   than awaited, so buildAdvice never becomes async. This is deliberate —
 *   see ARCHITECTURE.md §Advice.
 * @returns {{advice: Array<object>}}
 */
function buildAdvice(analysis, opts) {
  const o = obj(opts);
  let ctx;
  try {
    ctx = buildContext(analysis);
  } catch (e) {
    return { advice: [] };
  }

  const out = [];
  for (const rule of RULES) {
    let matches;
    try {
      matches = arr(rule.when(analysis, ctx)).slice(0, MAX_MATCHES_PER_RULE);
    } catch (e) {
      continue;
    }
    for (const m of matches) {
      let partial;
      try {
        partial = rule.build(m, analysis, ctx);
      } catch (e) {
        continue;
      }
      if (!partial || !txt(partial.title)) continue;

      const citations = arr(CITATIONS[rule.id]).concat(arr(partial.extraCitations));

      let kbCitations = [];
      if (typeof o.retrieve === 'function') {
        try {
          const query = (Array.isArray(rule.kb) && rule.kb.length ? rule.kb.join(' ') : rule.id);
          const hits = o.retrieve(query);
          // Synchronous contract: a Promise (or anything non-array) is treated
          // as no hits rather than awaited — buildAdvice must stay sync.
          if (Array.isArray(hits)) {
            kbCitations = hits.slice(0, MAX_KB_HITS).map(h => ({
              docTitle: txt(h && h.docTitle),
              page: h && h.page != null ? h.page : null,
              heading: txt(h && (h.heading || '')),
              excerpt: txt(h && (h.text || h.excerpt || '')),
            }));
          }
        } catch (e) {
          // KB retrieval must never break advice generation.
        }
      }

      out.push({
        id: null,
        ruleId: rule.id,
        findingIds: uniq(arr(partial.findingIds)),
        severity: ['crit', 'warn', 'notice', 'info'].indexOf(partial.severity) !== -1 ? partial.severity : 'info',
        title: txt(partial.title),
        whatsWrong: txt(partial.whatsWrong),
        whyItMatters: txt(partial.whyItMatters),
        mechanism: txt(partial.mechanism),
        fixes: orderFixes(ctx, partial.fixes),
        citations,
        kbCitations,
        legIds: uniq(arr(partial.legIds)),
        callIds: uniq(arr(partial.callIds)),
        msgIds: uniq(arr(partial.msgIds)).slice(0, 20),
      });
    }
  }

  out.sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));
  const capped = out.slice(0, MAX_ADVICE);
  capped.forEach((a, i) => { a.id = 'a' + (i + 1); });

  return { advice: capped };
}

module.exports = { buildAdvice };
