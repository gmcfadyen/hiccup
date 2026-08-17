'use strict';
// rtp.js — media-plane analysis (Wave 2).
//
// Builds the `media` block of AnalysisJSON: per-(src,sport,dst,dport,ssrc) RTP streams
// with RFC 3550 loss/jitter accounting, RFC 4733 DTMF, T.38/UDPTL streams, compound
// RTCP reports, and a simplified ITU-T G.107 MOS *estimate*.
//
// Design notes:
//  - SDP is the primary detector: `m=` port + `c=` address (or the message's own src)
//    per leg maps a 5-tuple onto legs and calls. Captures without SDP fall back to a
//    conservative shape heuristic and are reported as kind 'unknown' — we never guess
//    a codec from a dynamic payload type.
//  - SRTP is recognised from signalling only (RTP/SAVP, RTP/SAVPF, a=crypto,
//    UDP/TLS/RTP/SAVP). Headers are not encrypted, so loss/jitter still work.
//    Decryption is never attempted.
//  - Hot loop discipline: one pass over the packet array, no per-packet object
//    allocation, and a one-entry stream cache (media arrives in bursts) so most
//    packets never build a map key at all.
//  - Nothing here throws: malformed packets are skipped, failures land in ctx.warnings.

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

const MAX_MEDIA_PACKETS = 200000;  // hard sampling cap (contract)
const MAX_STREAMS = 20000;         // memory guard on pathological captures
const MAX_RTCP_REPORTS = 5000;
const MAX_GAPS_PER_STREAM = 200;
const MAX_DTMF_PER_STREAM = 500;
const GAP_THRESHOLD_MS = 100;
const RECENT_SEQ_WINDOW = 128;     // power of two; bounded duplicate-detection window
const MAX_DROPOUT = 3000;          // RFC 3550 A.1
const MAX_MISORDER = 100;          // RFC 3550 A.1
const LOSS_CRIT_PCT = 5;
const LOSS_WARN_PCT = 1;
const JITTER_WARN_MS = 50;
const MIN_PACKETS_FOR_QUALITY = 20;
const T38_STOP_GAP_SEC = 5;

/** Ports that are never RTP — signalling, DNS, Diameter and common infrastructure. */
const NON_MEDIA_PORTS = new Set([
  53, 67, 68, 123, 137, 138, 139, 161, 162, 445, 514, 1719, 1720, 1900,
  3868, 3869, 5060, 5061, 5062, 5063, 5070, 5080, 5353,
]);

/** RFC 4733 event code -> digit. */
const DTMF_DIGITS = '0123456789*#ABCD';

/** Static RTP payload types (RFC 3551) — used for clock rate only. */
const STATIC_PT_RATE = {
  0: 8000, 3: 8000, 4: 8000, 5: 8000, 6: 16000, 7: 8000, 8: 8000, 9: 8000,
  10: 44100, 11: 44100, 12: 8000, 13: 8000, 14: 90000, 15: 8000, 16: 11025,
  17: 22050, 18: 8000, 25: 90000, 26: 90000, 28: 90000, 31: 90000, 32: 90000,
  33: 90000, 34: 90000,
};

/**
 * Codec impairment factors for the simplified E-model.
 * `ie` = equipment impairment at zero loss, `bpl` = packet-loss robustness.
 * Values are the commonly published G.113/G.107 appendix figures; unknown codecs
 * get ie 0 so the estimate reflects only the loss and jitter we measured.
 */
const CODEC_IMPAIRMENT = {
  PCMU: { ie: 0, bpl: 4.3 },
  PCMA: { ie: 0, bpl: 4.3 },
  L16: { ie: 0, bpl: 4.3 },
  G711: { ie: 0, bpl: 4.3 },
  G722: { ie: 13, bpl: 20 },
  G726: { ie: 7, bpl: 23 },
  G72632: { ie: 7, bpl: 23 },
  G728: { ie: 7, bpl: 19 },
  G729: { ie: 11, bpl: 19 },
  G729A: { ie: 11, bpl: 19 },
  G729AB: { ie: 11, bpl: 19 },
  G729B: { ie: 11, bpl: 19 },
  G723: { ie: 15, bpl: 16.1 },
  G7231: { ie: 15, bpl: 16.1 },
  GSM: { ie: 20, bpl: 10 },
  GSMEFR: { ie: 5, bpl: 10 },
  ILBC: { ie: 11, bpl: 10 },
  AMR: { ie: 8, bpl: 10 },
  AMRWB: { ie: 7, bpl: 10 },
  EVS: { ie: 5, bpl: 10 },
  OPUS: { ie: 5, bpl: 10 },
  SPEEX: { ie: 15, bpl: 10 },
};

const HEX = [];
for (let i = 0; i < 256; i++) HEX.push(i.toString(16).padStart(2, '0'));

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/** Space-separated hex dump, capped so a stored analysis stays small. */
function hexDump(buf, from, to, maxBytes) {
  const end = Math.min(to, from + maxBytes);
  const parts = [];
  for (let i = from; i < end; i++) parts.push(HEX[buf[i]]);
  let s = parts.join(' ');
  if (end < to) s += ' …';
  return s;
}

function round(n, dp) {
  if (!Number.isFinite(n)) return 0;
  const f = Math.pow(10, dp);
  return Math.round(n * f) / f;
}

function codecKey(codec) {
  if (typeof codec !== 'string') return '';
  return codec.toUpperCase().replace(/[^A-Z0-9]/g, '');
}

/**
 * Simplified ITU-T G.107 E-model MOS estimate from measured loss and jitter.
 * One-way delay is not observable from a single capture point, so a nominal
 * network delay plus a jitter-buffer allowance is assumed. Always an ESTIMATE.
 * @param {number} lossPct measured packet loss, percent
 * @param {number} meanJitterMs mean interarrival jitter, ms
 * @param {string|null} codec codec name (PCMU, G729, …) or null/unknown
 * @returns {number} MOS in 1.0 … 4.5
 */
function estimateMos(lossPct, meanJitterMs, codec) {
  const imp = CODEC_IMPAIRMENT[codecKey(codec)] || { ie: 0, bpl: 10 };
  const loss = Math.max(0, Math.min(100, Number(lossPct) || 0));
  const jit = Math.max(0, Number(meanJitterMs) || 0);
  // Assumed mouth-to-ear delay: nominal network + a jitter buffer of ~2x jitter.
  const d = 30 + 2 * jit;
  let id = 0.024 * d;
  if (d > 177.3) id += 0.11 * (d - 177.3);
  const ieEff = imp.ie + (95 - imp.ie) * (loss / (loss + imp.bpl));
  const r = 93.2 - id - ieEff;
  let mos;
  if (r < 0) mos = 1;
  else if (r > 100) mos = 4.5;
  else mos = 1 + 0.035 * r + r * (r - 60) * (100 - r) * 7e-6;
  if (!Number.isFinite(mos)) return 1;
  return round(Math.max(1, Math.min(4.5, mos)), 2);
}

// ---------------------------------------------------------------------------
// SDP index — the primary stream/leg matcher
// ---------------------------------------------------------------------------

/**
 * Index every SDP m-block (offers AND answers) by the address:port media will
 * arrive on, so a media 5-tuple can be attributed to legs and calls.
 * `strong` = c=/o= address (what the endpoint actually advertised);
 * `weak` = the signalling source of the message (used only when nothing else matches).
 */
function buildSdpIndex(messages, legs, calls) {
  const strong = new Map();
  const weak = new Map();
  const rtcpStrong = new Map();
  const t38Keys = new Set();
  const msgLeg = new Map();
  const legCalls = new Map();
  const legById = new Map();
  const legDeclaresAudio = new Map();

  for (const leg of legs) {
    if (!leg || !leg.id) continue;
    legById.set(leg.id, leg);
    for (const mid of leg.msgIds || []) msgLeg.set(mid, leg.id);
  }
  for (const call of calls) {
    if (!call || !call.id) continue;
    for (const legId of call.legIds || []) {
      let arr = legCalls.get(legId);
      if (!arr) { arr = []; legCalls.set(legId, arr); }
      if (!arr.includes(call.id)) arr.push(call.id);
    }
  }

  const put = (map, key, entry) => {
    const prev = map.get(key);
    if (!prev) { map.set(key, entry); return; }
    for (const l of entry.legIds) if (!prev.legIds.includes(l)) prev.legIds.push(l);
    for (const cid of entry.callIds) if (!prev.callIds.includes(cid)) prev.callIds.push(cid);
    for (const pt of entry.tePts) prev.tePts.add(pt);
    for (const [pt, v] of entry.ptInfo) if (!prev.ptInfo.has(pt)) prev.ptInfo.set(pt, v);
    prev.isSrtp = prev.isSrtp || entry.isSrtp;
    prev.isT38 = prev.isT38 || entry.isT38;
  };

  for (const msg of messages) {
    if (!msg || msg.protocol === 'h323') continue;
    const sdp = msg.sdp;
    if (!sdp || !Array.isArray(sdp.media) || sdp.media.length === 0) continue;
    const legId = msgLeg.get(msg.id) || null;
    const callIds = legId ? (legCalls.get(legId) || []) : [];
    const sessAttrs = Array.isArray(sdp.sessionAttrs) ? sdp.sessionAttrs.join('\n') : '';
    const sessCrypto = /^a=crypto[:\s]/im.test(sessAttrs);

    for (const mb of sdp.media) {
      if (!mb || typeof mb.port !== 'number' || mb.port <= 0 || mb.port > 65535) continue;
      const attrs = Array.isArray(mb.attrs) ? mb.attrs.join('\n') : '';
      const proto = String(mb.proto || '');
      const isSrtp = /SAVP/i.test(proto) || sessCrypto || /^a=crypto[:\s]/im.test(attrs);
      const isT38 = String(mb.type) === 'image'
        ? (/udptl/i.test(proto) || /t38/i.test(attrs) || /t38/i.test(proto))
        : false;
      const tePts = new Set();
      const ptInfo = new Map();
      for (const p of mb.payloads || []) {
        if (!p || typeof p.pt !== 'number') continue;
        ptInfo.set(p.pt, { codec: p.codec || null, rate: p.rate || null });
        if (p.codec && /^telephone-event$/i.test(p.codec)) tePts.add(p.pt);
      }
      const entry = {
        type: String(mb.type || ''),
        proto,
        direction: mb.direction || null,
        legIds: legId ? [legId] : [],
        callIds: callIds.slice(),
        tePts,
        ptInfo,
        isSrtp,
        isT38,
      };

      if (legId && mb.type === 'audio') legDeclaresAudio.set(legId, true);

      const addrs = [];
      if (sdp.connection) addrs.push(sdp.connection);
      if (sdp.origin && sdp.origin.addr && !addrs.includes(sdp.origin.addr)) addrs.push(sdp.origin.addr);
      // an explicit a=rtcp:PORT overrides the port+1 convention
      let rtcpPort = mb.port + 1;
      const mRtcp = /^a=rtcp:\s*(\d{1,5})/im.exec(attrs);
      if (mRtcp) {
        const rp = parseInt(mRtcp[1], 10);
        if (rp > 0 && rp <= 65535) rtcpPort = rp;
      }
      for (const a of addrs) {
        if (!a || a === '0.0.0.0' || a === '::') continue;
        put(strong, a + '|' + mb.port, entry);
        put(rtcpStrong, a + '|' + rtcpPort, entry);
        if (isT38) t38Keys.add(a + '|' + mb.port);
      }
      if (msg.src && !addrs.includes(msg.src)) {
        put(weak, msg.src + '|' + mb.port, entry);
        put(weak, msg.src + '|' + rtcpPort, entry);
        if (isT38) t38Keys.add(msg.src + '|' + mb.port);
      }
    }
  }

  return { strong, weak, rtcpStrong, t38Keys, msgLeg, legCalls, legById, legDeclaresAudio };
}

/**
 * Resolve a media 5-tuple to an SDP entry plus the union of legs/calls it touches.
 * The destination side is preferred (that is the endpoint that advertised the port).
 */
function resolveEndpoints(idx, src, sport, dst, dport, rtcp) {
  const dKey = dst + '|' + dport;
  const sKey = src + '|' + sport;
  const primary = rtcp ? idx.rtcpStrong : idx.strong;
  let dEntry = primary.get(dKey) || null;
  let sEntry = primary.get(sKey) || null;
  if (rtcp) {
    // rtcp-mux puts RTCP on the RTP port
    if (!dEntry) dEntry = idx.strong.get(dKey) || null;
    if (!sEntry) sEntry = idx.strong.get(sKey) || null;
  }
  let weakUsed = false;
  if (!dEntry && !sEntry) {
    dEntry = idx.weak.get(dKey) || null;
    sEntry = idx.weak.get(sKey) || null;
    weakUsed = Boolean(dEntry || sEntry);
  }
  const entry = dEntry || sEntry;
  if (!entry) return null;
  const legIds = [];
  const callIds = [];
  for (const e of [dEntry, sEntry]) {
    if (!e) continue;
    for (const l of e.legIds) if (!legIds.includes(l)) legIds.push(l);
    for (const cid of e.callIds) if (!callIds.includes(cid)) callIds.push(cid);
  }
  return { entry, legIds, callIds, weak: weakUsed };
}

// ---------------------------------------------------------------------------
// Stream state
// ---------------------------------------------------------------------------

function newStream(src, sport, dst, dport, ssrc, ts, match, isUdptl) {
  const entry = match ? match.entry : null;
  let clockRate = 8000;
  if (entry) {
    for (const [pt, info] of entry.ptInfo) {
      if (entry.tePts.has(pt)) continue;
      if (info.rate) { clockRate = info.rate; break; }
    }
  }
  return {
    src, sport, dst, dport, ssrc,
    isUdptl,
    entry,
    legIds: match ? match.legIds.slice() : [],
    callIds: match ? match.callIds.slice() : [],
    weakMatch: match ? Boolean(match.weak) : false,
    clockRate,
    firstTs: ts, lastTs: ts,
    packets: 0, bytes: 0,
    baseSeq: -1, maxSeq: 0, cycles: 0,
    duplicates: 0, outOfOrder: 0, seqResets: 0,
    badSeq: -1,
    recent: new Set(), ring: new Int32Array(RECENT_SEQ_WINDOW).fill(-1), ringIdx: 0,
    transitInit: false, lastTransit: 0, lastRtpTsRaw: 0, rtpTsUnwrapped: 0,
    jitter: 0, jitterSum: 0, jitterCount: 0, maxJitter: 0,
    ptCounts: new Map(),
    markerResets: 0,
    gaps: [], maxGapMs: 0,
    dtmf: [], curDtmf: null,
  };
}

/** Remember a sequence number in the bounded recent-window (for duplicate detection). */
function noteSeq(s, seq) {
  if (s.recent.has(seq)) return;
  const slot = s.ringIdx & (RECENT_SEQ_WINDOW - 1);
  const old = s.ring[slot];
  if (old >= 0) s.recent.delete(old);
  s.ring[slot] = seq;
  s.ringIdx++;
  s.recent.add(seq);
}

/**
 * RFC 3550 A.1-style sequence accounting with 16-bit wrap handling.
 * @returns {boolean} true when this packet is a duplicate
 */
function accountSeq(s, seq) {
  if (s.baseSeq < 0) {
    s.baseSeq = seq;
    s.maxSeq = seq;
    noteSeq(s, seq);
    return false;
  }
  const udelta = (seq - s.maxSeq) & 0xffff;
  if (udelta === 0) { s.duplicates++; return true; }
  if (udelta < MAX_DROPOUT) {
    if (seq < s.maxSeq) s.cycles += 65536; // sequence wrapped
    s.maxSeq = seq;
    noteSeq(s, seq);
    return false;
  }
  if (udelta > 65535 - MAX_MISORDER) {
    // arrived behind the highest seq: duplicate or genuine reordering
    if (s.recent.has(seq)) { s.duplicates++; return true; }
    s.outOfOrder++;
    noteSeq(s, seq);
    return false;
  }
  // Large jump — a restarted sender or a very lossy path.
  if (s.badSeq === seq) {
    s.seqResets++;
    s.cycles = 0;
    s.baseSeq = seq;
    s.maxSeq = seq;
    s.recent.clear();
    s.ring.fill(-1);
    s.ringIdx = 0;
    s.badSeq = -1;
    noteSeq(s, seq);
    return false;
  }
  s.badSeq = (seq + 1) & 0xffff;
  s.outOfOrder++;
  return false;
}

/** RFC 3550 6.4.1 interarrival jitter, accumulated in RTP clock units. */
function accountJitter(s, ts, rtpTs) {
  let d = rtpTs - s.lastRtpTsRaw;
  if (d > 2147483647) d -= 4294967296;
  else if (d < -2147483648) d += 4294967296;
  s.lastRtpTsRaw = rtpTs;
  s.rtpTsUnwrapped += s.transitInit ? d : 0;
  const arrival = (ts - s.firstTs) * s.clockRate;
  const transit = arrival - s.rtpTsUnwrapped;
  if (!s.transitInit) {
    s.transitInit = true;
    s.lastTransit = transit;
    return;
  }
  let diff = transit - s.lastTransit;
  s.lastTransit = transit;
  if (diff < 0) diff = -diff;
  if (diff > s.clockRate * 10) return; // clock reset / SSRC restart, not jitter
  s.jitter += (diff - s.jitter) / 16;
  const ms = (s.jitter / s.clockRate) * 1000;
  s.jitterSum += ms;
  s.jitterCount++;
  if (ms > s.maxJitter) s.maxJitter = ms;
}

function flushDtmf(s) {
  const cur = s.curDtmf;
  if (!cur) return;
  s.curDtmf = null;
  if (s.dtmf.length >= MAX_DTMF_PER_STREAM) return;
  const rate = s.clockRate > 0 ? s.clockRate : 8000;
  s.dtmf.push({
    ts: cur.ts,
    digit: cur.digit,
    durationMs: round((cur.durationUnits / rate) * 1000, 1),
  });
}

function dtmfDigit(event) {
  if (event >= 0 && event < 16) return DTMF_DIGITS[event];
  if (event === 16) return 'FLASH';
  return 'event-' + event;
}

// ---------------------------------------------------------------------------
// RTCP
// ---------------------------------------------------------------------------

function parseReportBlocks(b, start, count, end, ts, srIndex) {
  const blocks = [];
  for (let i = 0; i < count; i++) {
    const o = start + i * 24;
    if (o + 24 > end) break;
    const ssrc = b.readUInt32BE(o);
    const fraction = b[o + 4];
    let cum = (b[o + 5] << 16) | (b[o + 6] << 8) | b[o + 7];
    if (cum & 0x800000) cum -= 0x1000000; // signed 24-bit
    const jitter = b.readUInt32BE(o + 12);
    const lsr = b.readUInt32BE(o + 16);
    const dlsr = b.readUInt32BE(o + 20);
    const dlsrMs = round((dlsr / 65536) * 1000, 3);
    let rttMs = null;
    if (lsr !== 0) {
      const sentAt = srIndex.get(ssrc + '|' + lsr);
      if (sentAt !== undefined) {
        const r = (ts - sentAt) * 1000 - dlsrMs;
        if (r >= 0 && r < 10000) rttMs = round(r, 3);
      }
    }
    blocks.push({
      ssrc,
      fractionLostPct: round((fraction / 256) * 100, 2),
      cumulativeLost: cum,
      jitter,
      lsr,
      dlsrMs,
      rttMs,
    });
  }
  return blocks;
}

const RTCP_TYPES = { 200: 'SR', 201: 'RR', 202: 'SDES', 203: 'BYE', 204: 'APP', 207: 'XR' };

/**
 * Parse one compound RTCP datagram into RtcpReport entries (one per sub-packet).
 * A CNAME found in the datagram's SDES is copied onto its sibling reports.
 */
function parseRtcpDatagram(b, pkt, reports, srIndex) {
  const created = [];
  let cname = null;
  let off = 0;
  let guard = 0;
  while (off + 4 <= b.length && guard++ < 64) {
    if ((b[off] >> 6) !== 2) break;
    const pt = b[off + 1];
    const words = b.readUInt16BE(off + 2);
    const total = (words + 1) * 4;
    const end = Math.min(off + total, b.length);
    const type = RTCP_TYPES[pt] || null;
    if (!type) { if (total <= 0) break; off += total; continue; }
    const count = b[off] & 0x1f;
    let ssrc = null;
    let blocks = [];

    if (pt === 200 && off + 28 <= end) {
      ssrc = b.readUInt32BE(off + 4);
      const ntpSec = b.readUInt32BE(off + 8);
      const ntpFrac = b.readUInt32BE(off + 12);
      const ntpMid = (((ntpSec & 0xffff) * 65536) + (ntpFrac >>> 16)) >>> 0;
      srIndex.set(ssrc + '|' + ntpMid, pkt.ts);
      blocks = parseReportBlocks(b, off + 28, count, end, pkt.ts, srIndex);
    } else if (pt === 201 && off + 8 <= end) {
      ssrc = b.readUInt32BE(off + 4);
      blocks = parseReportBlocks(b, off + 8, count, end, pkt.ts, srIndex);
    } else if (pt === 202) {
      let o = off + 4;
      for (let i = 0; i < count && o + 4 <= end; i++) {
        const chunkSsrc = b.readUInt32BE(o);
        if (ssrc === null) ssrc = chunkSsrc;
        o += 4;
        while (o < end) {
          const t = b[o];
          if (t === 0) { o++; while (o < end && (o % 4) !== 0) o++; break; }
          if (o + 2 > end) { o = end; break; }
          const len = b[o + 1];
          if (o + 2 + len > end) { o = end; break; }
          if (t === 1 && cname === null) {
            cname = b.toString('utf8', o + 2, o + 2 + len).replace(/[^\x20-\x7e]/g, '');
          }
          o += 2 + len;
        }
      }
    } else if (off + 8 <= end) {
      ssrc = b.readUInt32BE(off + 4);
    }

    const report = {
      id: null,
      ts: pkt.ts,
      src: pkt.src,
      dst: pkt.dst,
      type,
      ssrc,
      blocks,
      cname: null,
      raw: hexDump(b, off, end, 128),
    };
    reports.push(report);
    created.push(report);
    if (reports.length >= MAX_RTCP_REPORTS) break;
    if (total <= 0) break;
    off += total;
  }
  if (cname !== null) for (const r of created) r.cname = cname;
  return created.length;
}

// ---------------------------------------------------------------------------
// Shape heuristics
// ---------------------------------------------------------------------------

function plausiblePayloadType(pt) {
  return (pt >= 0 && pt <= 34) || (pt >= 96 && pt <= 127);
}

/**
 * Conservative UDPTL (T.38) shape test. A UDPTL packet is PER-encoded as
 * seq-number (2 bytes) + primary-ifp-packet (1-byte length determinant + bytes)
 * + error-recovery, so byte 2 must be a plausible short length with room left over.
 * Streams accepted on shape alone are additionally required to be long and
 * sequence-monotonic in finaliseStream().
 */
function looksLikeUdptl(b) {
  if (b.length < 5) return false;
  if ((b[0] >> 6) === 2) return false; // leave RTP alone
  const len = b[2];
  return len >= 1 && len <= 127 && (3 + len) < b.length;
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/**
 * Analyse the media plane of a capture.
 *
 * @param {Array<object>} packets Packet[] from pcap.js / textlog.js
 * @param {{messages?: Array<object>, legs?: Array<object>, calls?: Array<object>,
 *          warnings?: string[]}} ctx read-only context from analyze.js
 * @returns {{streams: Array<object>, rtcp: Array<object>, findings: Array<object>}}
 *   MediaStream[] / RtcpReport[] / Finding[] per ARCHITECTURE.md §MediaStream.
 *   Never throws — problems are appended to ctx.warnings.
 */
function analyzeMedia(packets, ctx) {
  const out = { streams: [], rtcp: [], findings: [] };
  const c = (ctx && typeof ctx === 'object') ? ctx : {};
  const warnings = Array.isArray(c.warnings) ? c.warnings : [];
  const messages = Array.isArray(c.messages) ? c.messages : [];
  const legs = Array.isArray(c.legs) ? c.legs : [];
  const calls = Array.isArray(c.calls) ? c.calls : [];
  if (!Array.isArray(packets) || packets.length === 0) return out;

  let idx;
  try {
    idx = buildSdpIndex(messages, legs, calls);
  } catch (e) {
    warnings.push('media: SDP index failed: ' + ((e && e.message) || e));
    idx = {
      strong: new Map(), weak: new Map(), rtcpStrong: new Map(),
      t38Keys: new Set(), msgLeg: new Map(), legCalls: new Map(),
      legById: new Map(), legDeclaresAudio: new Map(),
    };
  }

  const streams = new Map();
  const rtcpReports = [];
  const srIndex = new Map();
  const flowSsrcs = new Map();   // 'src|sport|dst|dport' -> Set(ssrc)
  let sampled = 0;
  let truncated = false;
  let streamCapHit = false;
  let lastStream = null;
  let packetErrors = 0;

  for (let i = 0; i < packets.length; i++) {
    // Per-packet isolation: one malformed frame must never abort a whole capture.
    try {
      const p = packets[i];
      if (!p || p.transport !== 'udp') continue;
      const b = p.payload;
      if (!Buffer.isBuffer(b) || b.length < 4) continue;
      if (!Number.isFinite(p.ts)) continue;   // a NaN timestamp would poison every stat
      const sport = p.sport | 0;
      const dport = p.dport | 0;
      if (NON_MEDIA_PORTS.has(sport) || NON_MEDIA_PORTS.has(dport)) continue;

      const version = b[0] >> 6;
      const second = b[1];

      // ---- RTCP -------------------------------------------------------
      if (version === 2 && second >= 200 && second <= 207 && b.length >= 8) {
        if (sampled >= MAX_MEDIA_PACKETS) { truncated = true; break; }
        sampled++;
        if (rtcpReports.length < MAX_RTCP_REPORTS) {
          try { parseRtcpDatagram(b, p, rtcpReports, srIndex); } catch (e) { /* skip */ }
        }
        continue;
      }

      // ---- T.38 / UDPTL ------------------------------------------------
      if (version !== 2) {
        const shape = looksLikeUdptl(b);
        if (!shape && idx.t38Keys.size === 0) continue;   // cheap reject for UDP noise
        const m = resolveEndpoints(idx, p.src, sport, p.dst, dport, false);
        const sdpSaysT38 = Boolean(m && m.entry && m.entry.isT38);
        // Accept when SDP says T.38, or when nothing in SDP claims this port and the
        // payload is UDPTL-shaped. A port SDP claims for something else is left alone.
        if (!sdpSaysT38 && (m || !shape)) continue;
        if (sampled >= MAX_MEDIA_PACKETS) { truncated = true; break; }
        sampled++;
        const key = p.src + '|' + sport + '|' + p.dst + '|' + dport + '|udptl';
        let s = streams.get(key);
        if (!s) {
          if (streams.size >= MAX_STREAMS) { streamCapHit = true; continue; }
          s = newStream(p.src, sport, p.dst, dport, null, p.ts, m, true);
          streams.set(key, s);
        }
        s.packets++;
        s.bytes += b.length;
        if (p.ts > s.lastTs) {
          const gapMs = (p.ts - s.lastTs) * 1000;
          if (gapMs > GAP_THRESHOLD_MS) {
            if (s.gaps.length < MAX_GAPS_PER_STREAM) s.gaps.push({ ts: p.ts, ms: round(gapMs, 1) });
            if (gapMs > s.maxGapMs) s.maxGapMs = gapMs;
          }
          s.lastTs = p.ts;
        }
        accountSeq(s, (b[0] << 8) | b[1]);
        continue;
      }

      // ---- RTP ---------------------------------------------------------
      if (b.length < 12) continue;
      const cc = b[0] & 0x0f;
      const hasExt = (b[0] >> 4) & 1;
      const hasPad = (b[0] >> 5) & 1;
      const marker = (second & 0x80) !== 0;
      const pt = second & 0x7f;
      if (!plausiblePayloadType(pt)) continue;
      let hdr = 12 + cc * 4;
      if (hasExt) {
        if (hdr + 4 > b.length) continue;
        hdr += 4 + b.readUInt16BE(hdr + 2) * 4;
      }
      if (hdr > b.length) continue;
      let payEnd = b.length;
      if (hasPad) {
        const pad = b[payEnd - 1];
        if (pad > 0 && payEnd - pad >= hdr) payEnd -= pad;
      }

      if (sampled >= MAX_MEDIA_PACKETS) { truncated = true; break; }
      sampled++;

      const seq = b.readUInt16BE(2);
      const rtpTs = b.readUInt32BE(4);
      const ssrc = b.readUInt32BE(8);

      let s = lastStream;
      if (!s || s.ssrc !== ssrc || s.sport !== sport || s.dport !== dport
          || s.src !== p.src || s.dst !== p.dst) {
        const key = p.src + '|' + sport + '|' + p.dst + '|' + dport + '|' + ssrc;
        s = streams.get(key);
        if (!s) {
          if (streams.size >= MAX_STREAMS) { streamCapHit = true; continue; }
          const m = resolveEndpoints(idx, p.src, sport, p.dst, dport, false);
          s = newStream(p.src, sport, p.dst, dport, ssrc, p.ts, m, false);
          streams.set(key, s);
          const flowKey = p.src + '|' + sport + '|' + p.dst + '|' + dport;
          let set = flowSsrcs.get(flowKey);
          if (!set) { set = new Set(); flowSsrcs.set(flowKey, set); }
          set.add(ssrc);
          s.flowKey = flowKey;
        }
        lastStream = s;
      }

      s.packets++;
      s.bytes += b.length;
      if (p.ts > s.lastTs) {
        const gapMs = (p.ts - s.lastTs) * 1000;
        if (gapMs > GAP_THRESHOLD_MS) {
          if (s.gaps.length < MAX_GAPS_PER_STREAM) s.gaps.push({ ts: p.ts, ms: round(gapMs, 1) });
          if (gapMs > s.maxGapMs) s.maxGapMs = gapMs;
        }
        s.lastTs = p.ts;
      } else if (p.ts < s.firstTs) {
        s.firstTs = p.ts;
      }
      s.ptCounts.set(pt, (s.ptCounts.get(pt) || 0) + 1);

      const dup = accountSeq(s, seq);

      // telephone-event (RFC 4733)
      const payLen = payEnd - hdr;
      const isTe = s.entry
        ? s.entry.tePts.has(pt)
        : (pt >= 96 && payLen === 4 && b[hdr] <= 16 && (b[hdr + 1] & 0x40) === 0);

      if (isTe && payLen >= 4) {
        const event = b[hdr];
        const endBit = (b[hdr + 1] & 0x80) !== 0;
        const duration = b.readUInt16BE(hdr + 2);
        const cur = s.curDtmf;
        if (cur && cur.event === event && cur.startRtpTs === rtpTs && !cur.closed) {
          if (duration > cur.durationUnits) cur.durationUnits = duration;
          if (endBit) cur.closed = true;
        } else {
          flushDtmf(s);
          s.curDtmf = {
            event, digit: dtmfDigit(event), ts: p.ts,
            startRtpTs: rtpTs, durationUnits: duration, closed: endBit,
          };
        }
      } else {
        if (marker && s.packets > 1) s.markerResets++;
        if (!dup) accountJitter(s, p.ts, rtpTs);
      }
    } catch (e) {
      if (packetErrors++ === 0) {
        warnings.push('media: skipped a malformed media packet: ' + ((e && e.message) || e));
      }
    }
  }
  if (packetErrors > 1) {
    warnings.push(`media: ${packetErrors} media packets were unparseable and skipped.`);
  }

  if (truncated) {
    warnings.push(`media analysis truncated: sampled the first ${MAX_MEDIA_PACKETS} media packets only — stream statistics are partial.`);
  }
  if (streamCapHit) {
    warnings.push(`media analysis truncated: more than ${MAX_STREAMS} media streams; later streams were ignored.`);
  }

  // ---- finalise streams -------------------------------------------------
  const finals = [];
  for (const s of streams.values()) {
    try {
      flushDtmf(s);
      const finalised = finaliseStream(s, flowSsrcs);
      if (finalised) finals.push(finalised);
    } catch (e) {
      warnings.push('media: stream finalise failed: ' + ((e && e.message) || e));
    }
  }
  finals.sort((a, b) => (a.firstTs - b.firstTs)
    || String(a.src).localeCompare(String(b.src))
    || (a.sport - b.sport));
  finals.forEach((st, i) => { st.id = 'rs' + (i + 1); });

  rtcpReports.forEach((r, i) => { r.id = 'rc' + (i + 1); });

  out.streams = finals;
  out.rtcp = rtcpReports;
  try {
    out.findings = buildFindings(finals, idx, sampled);
  } catch (e) {
    warnings.push('media: findings failed: ' + ((e && e.message) || e));
  }
  return out;
}

/**
 * Turn accumulated stream state into the frozen MediaStream shape, or null when a
 * no-SDP candidate fails the conservative heuristic.
 */
function finaliseStream(s, flowSsrcs) {
  const entry = s.entry;

  // dominant payload type, ignoring telephone-event when real media exists
  let domPt = null;
  let domCount = -1;
  let tePt = null;
  for (const [pt, n] of s.ptCounts) {
    const isTe = entry ? entry.tePts.has(pt) : false;
    if (isTe) { if (tePt === null) tePt = pt; continue; }
    if (n > domCount) { domCount = n; domPt = pt; }
  }
  if (domPt === null && tePt !== null) domPt = tePt;

  const isT38 = s.isUdptl || Boolean(entry && entry.isT38);
  const isSrtp = Boolean(entry && entry.isSrtp) && !isT38;

  if (!entry && !s.isUdptl) {
    // No SDP anywhere: only keep streams that really look like RTP.
    const evenPort = (s.sport % 2 === 0) || (s.dport % 2 === 0);
    const clean = s.packets - s.outOfOrder - s.duplicates;
    const monotonic = s.packets > 0 ? clean / s.packets : 0;
    if (s.packets < 4) return null;
    if (!(evenPort || s.packets >= 50)) return null;
    if (domPt === null || !plausiblePayloadType(domPt)) return null;
    if (monotonic < 0.8) return null;
  }
  if (!entry && s.isUdptl) {
    // UDPTL by shape only — demand a substantial, mostly ordered flow.
    const evenPort = (s.sport % 2 === 0) || (s.dport % 2 === 0);
    if (s.packets < 8 || !evenPort) return null;
    const clean = s.packets - s.outOfOrder - s.duplicates;
    if (s.packets > 0 && clean / s.packets < 0.8) return null;
  }

  let kind;
  if (isT38) kind = 't38-udptl';
  else if (isSrtp) kind = 'srtp';
  else if (entry) kind = 'rtp';
  else kind = 'unknown';

  let codec = 'unknown';
  let clockRate = s.clockRate;
  if (isT38) {
    codec = 'T.38';
  } else if (entry && domPt !== null) {
    const info = entry.ptInfo.get(domPt);
    if (info && info.codec) codec = info.codec;
    if (info && info.rate) clockRate = info.rate;
    else if (STATIC_PT_RATE[domPt]) clockRate = STATIC_PT_RATE[domPt];
  }
  // kind 'unknown' deliberately keeps codec 'unknown' — never guess from a dynamic PT.

  const received = Math.max(0, s.packets - s.duplicates);
  let expected = 0;
  if (s.baseSeq >= 0) expected = (s.cycles + s.maxSeq) - s.baseSeq + 1;
  if (expected < received) expected = received;
  const lost = Math.max(0, expected - received);
  const lossPct = expected > 0 ? round((lost / expected) * 100, 2) : 0;

  const meanJitterMs = s.jitterCount > 0 ? round(s.jitterSum / s.jitterCount, 2) : 0;
  const maxJitterMs = round(s.maxJitter, 2);
  const durationSec = round(Math.max(0, s.lastTs - s.firstTs), 6);

  const flowSsrcCount = s.flowKey && flowSsrcs.has(s.flowKey) ? flowSsrcs.get(s.flowKey).size : 1;

  return {
    id: null,
    kind,
    src: s.src, sport: s.sport, dst: s.dst, dport: s.dport,
    ssrc: s.ssrc,
    payloadType: isT38 ? null : domPt,
    codec,
    clockRate,
    firstTs: s.firstTs,
    lastTs: s.lastTs,
    durationSec,
    packets: s.packets,
    bytes: s.bytes,
    expected,
    lost,
    lossPct,
    outOfOrder: s.outOfOrder,
    duplicates: s.duplicates,
    meanJitterMs: isT38 ? 0 : meanJitterMs,
    maxJitterMs: isT38 ? 0 : maxJitterMs,
    maxGapMs: round(s.maxGapMs, 1),
    gaps: s.gaps,
    mos: isT38 ? null : estimateMos(lossPct, meanJitterMs, kind === 'unknown' ? null : codec),
    mosMethod: 'e-model-simplified',
    dtmfEvents: s.dtmf,
    legIds: s.legIds,
    callIds: s.callIds,
    oneWay: false,
    markerResets: s.markerResets,
    ssrcChanges: Math.max(0, flowSsrcCount - 1),
    encrypted: isSrtp,
    matchedBy: entry ? (s.weakMatch ? 'sdp-src' : 'sdp') : 'heuristic',
  };
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/**
 * Findings use category 'media'. analyze.js names 'media' as this module's fallback
 * category (as it does 'dns'/'diameter'/'ice'/'sip-i' for the other Wave-2 modules),
 * so setting it explicitly matches the merged output either way.
 */
function finding(severity, title, detail, legIds, callIds) {
  return {
    id: null,
    severity,
    category: 'media',
    title,
    detail,
    msgIds: [],
    legIds: Array.isArray(legIds) ? legIds.slice(0, 8) : [],
    callIds: Array.isArray(callIds) ? callIds.slice(0, 8) : [],
  };
}

function legAnswered(leg) {
  if (!leg) return false;
  return Boolean(leg.answered) || leg.state === 'answered' || leg.state === 'completed';
}

function describe(st) {
  return `${st.src}:${st.sport} → ${st.dst}:${st.dport}`
    + (st.ssrc === null ? '' : ` ssrc=0x${st.ssrc.toString(16)}`);
}

/** Media findings per the Wave-2 spec. Severity/category are contract values. */
function buildFindings(streams, idx, sampledPackets) {
  const findings = [];

  // one-way detection: a leg with traffic in a single direction
  const byLeg = new Map();
  for (const st of streams) {
    for (const legId of st.legIds) {
      let arr = byLeg.get(legId);
      if (!arr) { arr = []; byLeg.set(legId, arr); }
      arr.push(st);
    }
  }
  for (const st of streams) {
    if (st.kind === 't38-udptl' || st.legIds.length === 0) continue;
    let reverse = false;
    for (const legId of st.legIds) {
      for (const other of byLeg.get(legId) || []) {
        if (other === st) continue;
        if (other.src === st.dst && other.dst === st.src) { reverse = true; break; }
      }
      if (reverse) break;
    }
    if (!reverse) st.oneWay = true;
  }

  const reported = new Set();
  for (const st of streams) {
    if (!st.oneWay) continue;
    const answeredLegs = st.legIds.filter(id => legAnswered(idx.legById.get(id)));
    if (answeredLegs.length === 0) continue;
    const key = answeredLegs.join(',') + '|' + st.src + '|' + st.dst;
    if (reported.has(key)) continue;
    reported.add(key);
    findings.push(finding('crit',
      'One-way media on an answered call',
      `Media flows ${describe(st)} (${st.packets} packets, ${st.codec}) but no stream was seen in the reverse direction on `
      + `leg${answeredLegs.length > 1 ? 's' : ''} ${answeredLegs.join(', ')}, which answered. `
      + 'One-way audio usually means NAT/pinhole or a media-address rewrite problem, not a codec problem.',
      answeredLegs, st.callIds));
  }

  // loss / jitter
  for (const st of streams) {
    if (st.packets < MIN_PACKETS_FOR_QUALITY || st.expected <= 0) continue;
    if (st.lossPct > LOSS_CRIT_PCT) {
      findings.push(finding('crit',
        `Severe RTP packet loss (${st.lossPct}%)`,
        `${describe(st)}: ${st.lost} of ${st.expected} expected packets missing (${st.lossPct}%), `
        + `mean jitter ${st.meanJitterMs} ms, MOS estimate ${st.mos === null ? 'n/a' : st.mos} `
        + '(simplified E-model — an estimate, not a measurement). '
        + 'Loss above 5% is audible as clipped or robotic speech.',
        st.legIds, st.callIds));
    } else if (st.lossPct >= LOSS_WARN_PCT) {
      findings.push(finding('warn',
        `RTP packet loss ${st.lossPct}%`,
        `${describe(st)}: ${st.lost} of ${st.expected} expected packets missing. `
        + 'Loss between 1% and 5% degrades speech quality on G.711 and is much worse on compressed codecs.',
        st.legIds, st.callIds));
    }
    if (st.maxJitterMs > JITTER_WARN_MS) {
      findings.push(finding('warn',
        `High RTP jitter (peak ${st.maxJitterMs} ms)`,
        `${describe(st)}: RFC 3550 interarrival jitter peaked at ${st.maxJitterMs} ms `
        + `(mean ${st.meanJitterMs} ms). Beyond about 50 ms a typical jitter buffer starts discarding packets, `
        + 'which sounds like loss even though nothing was dropped in transit.',
        st.legIds, st.callIds));
    }
    if (st.maxGapMs > 1000 && st.kind !== 't38-udptl') {
      findings.push(finding('warn',
        `Media gap of ${Math.round(st.maxGapMs)} ms`,
        `${describe(st)}: the longest interval with no packets at all was ${Math.round(st.maxGapMs)} ms `
        + `(${st.gaps.length} gap${st.gaps.length === 1 ? '' : 's'} over ${GAP_THRESHOLD_MS} ms). `
        + 'A gap of this length is a black hole (route flap, firewall timeout or a paused sender), not jitter.',
        st.legIds, st.callIds));
    }
  }

  // media never started after answer
  if (sampledPackets > 0 && streams.length > 0) {
    for (const [legId, declaresAudio] of idx.legDeclaresAudio) {
      if (!declaresAudio) continue;
      const leg = idx.legById.get(legId);
      if (!legAnswered(leg)) continue;
      const legStreams = byLeg.get(legId) || [];
      const answerTs = leg && Number.isFinite(leg.answerTs) ? leg.answerTs : null;
      const afterAnswer = answerTs === null
        ? legStreams
        : legStreams.filter(st => st.lastTs >= answerTs);
      if (afterAnswer.length > 0) continue;
      findings.push(finding('warn',
        'Media never started after answer',
        `Leg ${legId} answered${answerTs === null ? '' : ' at ' + answerTs.toFixed(3)} and negotiated an audio stream in SDP, `
        + `but ${legStreams.length === 0 ? 'no RTP was captured for it at all' : 'all of its RTP stopped before the answer'}. `
        + 'Either the media never left the far end, or it is going somewhere this capture point cannot see.',
        [legId], (idx.legCalls.get(legId) || [])));
    }
  }

  // transcoding visible in the media
  const callCodecs = new Map();
  for (const st of streams) {
    if (st.kind === 't38-udptl') continue;
    if (!st.codec || st.codec === 'unknown') continue;
    for (const callId of st.callIds) {
      let m = callCodecs.get(callId);
      if (!m) { m = new Map(); callCodecs.set(callId, m); }
      for (const legId of st.legIds) {
        let set = m.get(legId);
        if (!set) { set = new Set(); m.set(legId, set); }
        set.add(st.codec);
      }
    }
  }
  for (const [callId, perLeg] of callCodecs) {
    if (perLeg.size < 2) continue;
    const sigs = [];
    const legIds = [];
    for (const [legId, set] of perLeg) {
      legIds.push(legId);
      sigs.push(legId + '=' + Array.from(set).sort().join('/'));
    }
    const distinct = new Set(sigs.map(s => s.split('=')[1]));
    if (distinct.size < 2) continue;
    findings.push(finding('info',
      'Transcoding visible in the media',
      `Call ${callId} carries different codecs on different legs (${sigs.join(', ')}). `
      + 'The SBC is transcoding rather than passing media through, which costs DSP resource and adds delay — '
      + 'usually deliberate, occasionally a codec-policy accident.',
      legIds, [callId]));
  }

  // T.38 that starts then stops
  for (const st of streams) {
    if (st.kind !== 't38-udptl') continue;
    let legEnd = null;
    for (const legId of st.legIds) {
      const leg = idx.legById.get(legId);
      if (leg && Number.isFinite(leg.endTs)) legEnd = legEnd === null ? leg.endTs : Math.max(legEnd, leg.endTs);
    }
    const stoppedEarly = legEnd !== null && (legEnd - st.lastTs) > T38_STOP_GAP_SEC;
    const gapMidway = st.maxGapMs > T38_STOP_GAP_SEC * 1000;
    if (!stoppedEarly && !gapMidway) continue;
    findings.push(finding('warn',
      'T.38 fax stream started then stopped',
      `${describe(st)}: UDPTL/T.38 ran for ${st.durationSec.toFixed(2)}s (${st.packets} packets)`
      + (stoppedEarly ? `, then stopped ${round(legEnd - st.lastTs, 2)}s before the call cleared` : '')
      + (gapMidway ? `, with a ${Math.round(st.maxGapMs)} ms hole in the middle` : '')
      + '. A fax that halts part-way usually means the T.38 re-INVITE succeeded but one side stopped '
      + 'relaying UDPTL — check for an intervening firewall or a missing image media route.',
      st.legIds, st.callIds));
  }

  return findings;
}

module.exports = { analyzeMedia };
