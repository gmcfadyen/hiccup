'use strict';

/**
 * lib/h323.js — TPKT/Q.931 (H.225.0 call signalling) decode + H.323 leg grouping.
 *
 * Owns exactly two exports (see ARCHITECTURE.md, frozen contract):
 *   extractH323Messages(packets) -> [H323Message]   (ids h1… in timestamp order)
 *   groupH323Legs(messages)      -> [Leg]           (ids g1…, protocol 'h323', kind 'call')
 *
 * Scope: TCP flows on port 1720 plus any TCP flow whose assembled byte stream
 * starts with a TPKT header (03 00 LL LL). Per-flow/per-direction seq-ordered
 * segment assembly with simple duplicate-seq drop (same discipline as sip.js,
 * implemented independently — no cross-imports). Q.931 layer only; the H.225
 * User-User ASN.1 blob is NOT decoded — callIdentifier GUID and fastStart are
 * best-effort byte-pattern heuristics (LOW confidence, honest nulls/false).
 *
 * Zero runtime dependencies. CommonJS. Windows-safe (no filesystem access).
 */

/** Q.931 message type octet (low 7 bits) -> display name. */
const Q931_TYPE_NAMES = {
  0x01: 'ALERTING',
  0x02: 'CALL PROCEEDING',
  0x03: 'PROGRESS',
  0x05: 'SETUP',
  0x07: 'CONNECT',
  0x5a: 'RELEASE COMPLETE',
  0x62: 'FACILITY',
  0x6e: 'NOTIFY',
  0x7b: 'INFORMATION',
  0x7d: 'STATUS',
};

/** Q.850 cause value -> text, common values only (others get a generic string). */
const Q850_CAUSE_TEXT = {
  1: 'Unallocated (unassigned) number',
  16: 'Normal call clearing',
  17: 'User busy',
  18: 'No user responding',
  19: 'No answer from user (user alerted)',
  21: 'Call rejected',
  28: 'Invalid number format (address incomplete)',
  31: 'Normal, unspecified',
  34: 'No circuit/channel available',
  38: 'Network out of order',
  41: 'Temporary failure',
  42: 'Switching equipment congestion',
  44: 'Requested circuit/channel not available',
  47: 'Resource unavailable, unspecified',
  63: 'Service or option not available, unspecified',
  65: 'Bearer capability not implemented',
  79: 'Service or option not implemented, unspecified',
  88: 'Incompatible destination',
  102: 'Recovery on timer expiry',
  127: 'Interworking, unspecified',
};

/**
 * Q.850 cause text for a cause value (generic fallback for uncommon codes).
 * @param {number|null} code
 * @returns {string|null}
 */
function q850Text(code) {
  if (code === null || code === undefined) return null;
  return Q850_CAUSE_TEXT[code] || ('Q.850 cause ' + code);
}

/**
 * Space-separated lowercase hex dump of a buffer ('03 00 00 2a …').
 * @param {Buffer} buf
 * @returns {string}
 */
function toSpacedHex(buf) {
  const parts = new Array(buf.length);
  for (let i = 0; i < buf.length; i++) parts[i] = buf[i].toString(16).padStart(2, '0');
  return parts.join(' ');
}

/**
 * Printable-ASCII string from IA5 bytes (non-printables dropped), null if empty.
 * @param {Buffer} bytes
 * @returns {string|null}
 */
function printableString(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b >= 0x20 && b <= 0x7e) out += String.fromCharCode(b);
  }
  return out.length ? out : null;
}

/**
 * Decode a Called (0x70) / Calling (0x6C) Party Number IE value.
 * Walks the octet-3 group by ext bit: octets with MSB clear are followed by
 * more group octets (e.g. calling-party presentation/screening octet 3a); the
 * octet with MSB set ends the group; the rest is IA5 digits.
 * @param {Buffer} value IE value bytes (after id + length)
 * @returns {string|null} digit string, or null
 */
function decodeNumberIe(value) {
  let i = 0;
  while (i < value.length && (value[i] & 0x80) === 0) i++; // non-final group octets
  i++; // the ext-terminated (final) group octet
  if (i >= value.length) return null;
  return printableString(value.subarray(i));
}

/**
 * Decode a Cause (0x08) IE value -> Q.850 cause code (low 7 bits), null if truncated.
 * Skips the location/coding octet group (ext-bit walk, covers optional octet 3a
 * recommendation), then reads the cause value octet.
 * @param {Buffer} value
 * @returns {number|null}
 */
function decodeCauseIe(value) {
  let i = 0;
  while (i < value.length && (value[i] & 0x80) === 0) i++; // non-final location/coding octets
  i++; // final octet of the location group
  if (i >= value.length) return null;
  return value[i] & 0x7f;
}

/**
 * Best-effort scan of a User-User (0x7E) IE value.
 * value[0] is the user-user protocol discriminator; the rest is an H.225 UUIE
 * ASN.1 blob which we deliberately do NOT decode. Heuristics (LOW confidence):
 *  - guid: first 16 bytes following a 0x10 length-marker byte, rejected if the
 *    16 bytes are all one value; null when not confidently found.
 *  - fastStart: >=3 bytes in the 0x40–0x4f range in the blob (OpenLogicalChannel
 *    marker density) — crude presence signal only.
 * @param {Buffer} value
 * @returns {{guid: string|null, fastStart: boolean}}
 */
function decodeUserUserIe(value) {
  const out = { guid: null, fastStart: false };
  if (value.length < 2) return out;
  const blob = value.subarray(1); // skip user-user protocol discriminator
  for (let i = 0; i + 17 <= blob.length; i++) {
    if (blob[i] !== 0x10) continue;
    const cand = blob.subarray(i + 1, i + 17);
    let allSame = true;
    for (let k = 1; k < 16; k++) { if (cand[k] !== cand[0]) { allSame = false; break; } }
    if (allSame) continue; // 16 identical bytes: padding, not a GUID
    out.guid = cand.toString('hex');
    break;
  }
  let olcMarkers = 0;
  for (let i = 0; i < blob.length; i++) {
    if (blob[i] >= 0x40 && blob[i] <= 0x4f) olcMarkers++;
  }
  out.fastStart = olcMarkers >= 3;
  return out;
}

/**
 * Parse one Q.931 message (the bytes after the 4-byte TPKT header).
 * Returns null when this is not Q.931 (protocol discriminator !== 0x08, e.g.
 * an H.245 TPKT on the same wire) or is truncated beyond use.
 * @param {Buffer} q
 * @returns {null|{q931Type: string, callRef: number, callRefFlag: 0|1,
 *   calling: string|null, called: string|null, causeCode: number|null,
 *   display: string|null, guid: string|null, hasFastStart: boolean,
 *   hasBearerCap: boolean}}
 */
function parseQ931(q) {
  if (q.length < 3) return null;
  if (q[0] !== 0x08) return null; // Q.931 protocol discriminator
  const crLen = q[1] & 0x0f;
  if (q.length < 2 + crLen + 1) return null;
  let callRef = 0;
  let callRefFlag = 0;
  if (crLen > 0) {
    callRefFlag = (q[2] & 0x80) ? 1 : 0; // MSB of first call-reference octet
    callRef = q[2] & 0x7f;
    for (let k = 1; k < crLen; k++) callRef = (callRef << 8) | q[2 + k];
  }
  const typeOctet = q[2 + crLen] & 0x7f;
  const q931Type = Q931_TYPE_NAMES[typeOctet]
    || ('unknown(0x' + typeOctet.toString(16).padStart(2, '0') + ')');

  const out = {
    q931Type, callRef, callRefFlag,
    calling: null, called: null, causeCode: null,
    display: null, guid: null, hasFastStart: false, hasBearerCap: false,
  };

  // IE walk. Single-octet IEs have the MSB set (shift 0x9X, more-data 0xA0,
  // sending-complete 0xA1, …) — skip them. Variable IEs are id, len, value.
  let pos = 3 + crLen;
  while (pos < q.length) {
    const id = q[pos];
    if (id & 0x80) { pos += 1; continue; }
    if (pos + 2 > q.length) break;
    const len = q[pos + 1];
    const value = q.subarray(pos + 2, Math.min(pos + 2 + len, q.length));
    pos += 2 + len;
    switch (id) {
      case 0x70: out.called = decodeNumberIe(value); break;
      case 0x6c: out.calling = decodeNumberIe(value); break;
      case 0x08: out.causeCode = decodeCauseIe(value); break;
      case 0x28: out.display = printableString(value); break;
      case 0x04: out.hasBearerCap = true; break; // presence only
      case 0x7e: {
        const uu = decodeUserUserIe(value);
        out.guid = uu.guid;
        out.hasFastStart = uu.fastStart;
        break;
      }
      default: break; // unhandled variable IE — skipped
    }
  }
  return out;
}

/**
 * True when a byte stream plausibly begins with a TPKT header.
 * @param {Buffer} stream
 * @returns {boolean}
 */
function looksLikeTpkt(stream) {
  if (stream.length < 4) return false;
  if (stream[0] !== 0x03 || stream[1] !== 0x00) return false;
  const len = (stream[2] << 8) | stream[3];
  return len >= 7; // 4-byte header + minimal Q.931 (PD + CR-len + type)
}

/**
 * Find the next plausible TPKT header at/after `from` (resync after garbage).
 * @param {Buffer} stream
 * @param {number} from
 * @returns {number} offset, or -1
 */
function findNextTpkt(stream, from) {
  for (let i = from; i + 4 <= stream.length; i++) {
    if (stream[i] === 0x03 && stream[i + 1] === 0x00) {
      const len = (stream[i + 2] << 8) | stream[i + 3];
      if (len >= 7) return i;
    }
  }
  return -1;
}

/**
 * Extract H.323 (Q.931/H.225 call signalling) messages from packets.
 *
 * Scans TCP flows on port 1720 plus any TCP flow whose per-direction assembled
 * stream starts with a TPKT header. Each flow direction is assembled from its
 * segments ordered by TCP seq (duplicate seqs dropped, gaps concatenated
 * best-effort), then walked TPKT frame by TPKT frame; non-Q.931 frames (e.g.
 * H.245) are skipped silently. Incomplete trailing frames are dropped.
 *
 * @param {Array<object>} packets Packet[] per ARCHITECTURE.md (parsePcap/parseTextLog output)
 * @returns {Array<object>} H323Message[] per ARCHITECTURE.md, ids 'h1…' in ts order.
 *   Note: `display` (Display IE 0x28 text) is included as an additive extra field.
 */
function extractH323Messages(packets) {
  // Bucket TCP segments per flow direction.
  const dirs = new Map();
  for (const p of (packets || [])) {
    if (!p || p.transport !== 'tcp') continue;
    if (!p.payload || p.payload.length === 0) continue;
    const key = p.src + ':' + p.sport + '>' + p.dst + ':' + p.dport;
    let d = dirs.get(key);
    if (!d) {
      d = { segments: [], src: p.src, dst: p.dst, sport: p.sport, dport: p.dport };
      dirs.set(key, d);
    }
    d.segments.push(p);
  }

  const found = []; // { parsed, frame, pktRefs, ts, src, dst, sport, dport }
  for (const d of dirs.values()) {
    // Seq-ordered assembly with duplicate-seq drop; fall back to capture order
    // when seq is unavailable (e.g. text-log-sourced packets).
    const haveSeq = d.segments.every((s) => s.tcp && Number.isFinite(s.tcp.seq));
    let segs;
    if (haveSeq) {
      const seen = new Set();
      segs = d.segments.filter((s) => {
        if (seen.has(s.tcp.seq)) return false;
        seen.add(s.tcp.seq);
        return true;
      });
      segs.sort((a, b) => (a.tcp.seq - b.tcp.seq) || (a.n - b.n));
    } else {
      segs = d.segments.slice().sort((a, b) => a.n - b.n);
    }

    const stream = Buffer.concat(segs.map((s) => s.payload));
    const ranges = [];
    let off = 0;
    for (const s of segs) {
      ranges.push({ start: off, end: off + s.payload.length, n: s.n, ts: s.ts });
      off += s.payload.length;
    }

    const on1720 = d.sport === 1720 || d.dport === 1720;
    if (!on1720 && !looksLikeTpkt(stream)) continue;

    let pos = 0;
    while (pos + 4 <= stream.length) {
      if (stream[pos] !== 0x03 || stream[pos + 1] !== 0x00) {
        pos = findNextTpkt(stream, pos + 1);
        if (pos < 0) break;
        continue;
      }
      const flen = (stream[pos + 2] << 8) | stream[pos + 3];
      if (flen < 4) {
        pos = findNextTpkt(stream, pos + 1);
        if (pos < 0) break;
        continue;
      }
      if (pos + flen > stream.length) break; // incomplete trailing frame
      const frame = stream.subarray(pos, pos + flen);
      const parsed = parseQ931(frame.subarray(4));
      if (parsed) {
        const refs = ranges.filter((r) => r.start < pos + flen && r.end > pos);
        found.push({
          parsed,
          frame,
          pktRefs: refs.map((r) => r.n),
          ts: refs.length ? refs[0].ts : 0,
          src: d.src, dst: d.dst, sport: d.sport, dport: d.dport,
        });
      }
      pos += flen;
    }
  }

  found.sort((a, b) => (a.ts - b.ts)
    || ((a.pktRefs[0] || 0) - (b.pktRefs[0] || 0)));

  return found.map((m, i) => {
    const p = m.parsed;
    const causeText = q850Text(p.causeCode);
    let summary = p.q931Type + ' callRef=' + p.callRef;
    if (p.calling) summary += ' calling=' + p.calling;
    if (p.called) summary += ' called=' + p.called;
    if (p.causeCode !== null) summary += ' cause=' + p.causeCode + ' (' + causeText + ')';
    if (p.hasFastStart) summary += ' fastStart';
    return {
      id: 'h' + (i + 1),
      protocol: 'h323',
      pktRefs: m.pktRefs,
      ts: m.ts,
      src: m.src, dst: m.dst, sport: m.sport, dport: m.dport,
      transport: 'tcp',
      q931Type: p.q931Type,
      callRef: p.callRef,
      callRefFlag: p.callRefFlag,
      calling: p.calling,
      called: p.called,
      causeCode: p.causeCode,
      causeText,
      guid: p.guid,
      hasFastStart: p.hasFastStart,
      display: p.display, // additive extra: Display IE (0x28) text
      raw: toSpacedHex(m.frame),
      summary,
      size: m.frame.length,
    };
  });
}

/**
 * E.164-ish digit string from a number ('+33612345678' -> '33612345678'), null if none.
 * @param {string|null} num
 * @returns {string|null}
 */
function digitsOf(num) {
  if (!num) return null;
  const d = String(num).replace(/[^0-9]/g, '');
  return d.length ? d : null;
}

/**
 * Group H.323 messages into legs keyed on (tcp flow, callRef). The flow key is
 * direction-agnostic (both directions of the TCP connection are one call
 * segment). State rules per ARCHITECTURE.md:
 *   CONNECT -> answered; RELEASE COMPLETE after CONNECT -> completed;
 *   RELEASE COMPLETE with cause before CONNECT -> failed, except (cause table
 *   judgment) cause 16 after ALERTING -> canceled, cause 18/19 -> no-answer;
 *   never RELEASEd -> answered / in-progress.
 * Every message lands in exactly one leg.
 *
 * @param {Array<object>} messages H323Message[] from extractH323Messages (ts order)
 * @returns {Array<object>} Leg[] per ARCHITECTURE.md, ids 'g1…', kind always 'call'
 */
function groupH323Legs(messages) {
  const legs = [];
  const byKey = new Map();
  const msgs = (messages || []).filter((m) => m && m.protocol === 'h323');

  for (const m of msgs) {
    const a = m.src + ':' + m.sport;
    const b = m.dst + ':' + m.dport;
    const flow = a < b ? (a + '|' + b) : (b + '|' + a);
    const key = flow + '#' + m.callRef;
    let leg = byKey.get(key);
    if (!leg) {
      leg = {
        id: 'g' + (legs.length + 1),
        protocol: 'h323',
        kind: 'call', // h323: always 'call'
        from: null, to: null,
        fromUser: null, toUser: null,
        src: m.src, dst: m.dst, sport: m.sport, dport: m.dport,
        transport: 'tcp',
        startTs: m.ts, endTs: m.ts,
        state: 'in-progress',
        failCode: null,
        answered: false, answerTs: null,
        msgIds: [],
        callRef: m.callRef,
        guid: null,
        _sawSetup: false, _sawAlerting: false, _release: null,
      };
      byKey.set(key, leg);
      legs.push(leg);
    }
    leg.msgIds.push(m.id);
    if (m.ts < leg.startTs) leg.startTs = m.ts;
    if (m.ts > leg.endTs) leg.endTs = m.ts;
    if (m.guid && !leg.guid) leg.guid = m.guid;

    if (m.q931Type === 'SETUP' && !leg._sawSetup) {
      leg._sawSetup = true;
      leg.from = m.calling || null;
      leg.to = m.called || null;
      leg.fromUser = digitsOf(m.calling);
      leg.toUser = digitsOf(m.called);
      leg.src = m.src; leg.dst = m.dst;
      leg.sport = m.sport; leg.dport = m.dport;
    } else if (m.q931Type === 'ALERTING') {
      leg._sawAlerting = true;
    } else if (m.q931Type === 'CONNECT') {
      if (!leg.answered) { leg.answered = true; leg.answerTs = m.ts; }
    } else if (m.q931Type === 'RELEASE COMPLETE') {
      if (!leg._release) leg._release = m;
    }
  }

  for (const leg of legs) {
    const rel = leg._release;
    if (rel) {
      if (leg.answered) {
        leg.state = 'completed';
      } else if (rel.causeCode === 18 || rel.causeCode === 19) {
        // 'No user responding' / 'No answer from user (user alerted)'
        leg.state = 'no-answer';
      } else if (rel.causeCode === 16 && leg._sawAlerting) {
        // Normal clearing while ringing: the caller gave up
        leg.state = 'canceled';
      } else {
        leg.state = 'failed';
        leg.failCode = (rel.causeCode === null || rel.causeCode === undefined)
          ? null : rel.causeCode;
      }
    } else {
      leg.state = leg.answered ? 'answered' : 'in-progress';
    }
    delete leg._sawSetup;
    delete leg._sawAlerting;
    delete leg._release;
  }

  return legs;
}

module.exports = { extractH323Messages, groupH323Legs };
