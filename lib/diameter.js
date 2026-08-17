'use strict';

/**
 * lib/diameter.js — Diameter (RFC 6733) decode for the aux track, with Rx-to-SIP
 * correlation.
 *
 * Export (frozen, ARCHITECTURE.md §"Wave 2 module exports"):
 *   extractDiameter(packets, ctx) -> { aux: [AuxMessage], findings: [Finding] }
 *
 * Scope: TCP ports 3868 / 3869, per-direction seq-ordered stream assembly framed by
 * the Diameter header length (with resync after garbage). Header (version, length,
 * flags R/P/E/T, command code, application id, hop-by-hop, end-to-end) plus a generic
 * AVP walk: code, flags (V/M/P), length, vendor id when the V bit is set, 4-byte
 * padding, grouped AVPs recursed to a sane depth. Command and AVP name tables cover
 * the Rx / Gx / Cx / Sh set named in the contract; Result-Code and
 * Experimental-Result-Code are decoded to name + number.
 *
 * Cross-protocol correlation (DESIGN_1 "stretch": *almost nobody does this well*):
 * AF-Charging-Identifier — or an icid-looking token of Session-Id — is matched against
 * the SIP `P-Charging-Vector` icid-value in ctx.messages, filling legIds/callIds and
 * emitting an info finding naming both sides. When a request is answered with a failure
 * Result-Code and the SIP call it belongs to also failed, that becomes a warn.
 *
 * Defensive by contract: never throws; oddities land on ctx.warnings.
 *
 * Zero runtime dependencies. CommonJS.
 */

/** Hard caps so one pathological capture cannot stall an upload. */
const MAX_MESSAGES = 3000;
const MAX_RAW_BYTES = 512;
const MAX_AVP_DEPTH = 6;
const MAX_AVPS_PER_MESSAGE = 400;

/**
 * Command code -> [request name, answer name].
 * The VoIP set is exactly the contract's table (ARCHITECTURE.md §AuxMessage):
 * AAR/AAA 265, RAR/RAA 258, STR/STA 275, ASR/ASA 274, CCR/CCA 272, UAR/UAA 300,
 * MAR/MAA 303, SAR/SAA 306, LIR/LIA 307 — plus the base-protocol commands, which show
 * up in every real Diameter capture (peer setup and watchdogs).
 */
const COMMAND_NAMES = {
  257: ['CER', 'CEA'],
  258: ['RAR', 'RAA'],
  265: ['AAR', 'AAA'],
  271: ['ACR', 'ACA'],
  272: ['CCR', 'CCA'],
  274: ['ASR', 'ASA'],
  275: ['STR', 'STA'],
  280: ['DWR', 'DWA'],
  282: ['DPR', 'DPA'],
  300: ['UAR', 'UAA'],
  303: ['MAR', 'MAA'],
  306: ['SAR', 'SAA'],
  307: ['LIR', 'LIA'],
};

/** Application id -> short label. */
const APP_LABELS = {
  0: 'Base',
  3: 'Base Accounting',
  4: 'Credit-Control (Ro/Gy)',
  16777216: 'Cx/Dx',
  16777217: 'Sh',
  16777236: 'Rx',
  16777238: 'Gx',
  16777251: 'S6a/S6d',
};

/** AVP code -> name (the Rx/Gx/Cx/Sh set that matters, per the contract). */
const AVP_NAMES = {
  1: 'User-Name',
  8: 'Framed-IP-Address',
  30: 'Called-Station-Id',
  97: 'Framed-IPv6-Prefix',
  258: 'Auth-Application-Id',
  260: 'Vendor-Specific-Application-Id',
  263: 'Session-Id',
  264: 'Origin-Host',
  266: 'Vendor-Id',
  268: 'Result-Code',
  269: 'Product-Name',
  277: 'Auth-Session-State',
  278: 'Origin-State-Id',
  279: 'Failed-AVP',
  281: 'Error-Message',
  282: 'Route-Record',
  283: 'Destination-Realm',
  293: 'Destination-Host',
  296: 'Origin-Realm',
  297: 'Experimental-Result',
  298: 'Experimental-Result-Code',
  415: 'CC-Request-Number',
  416: 'CC-Request-Type',
  443: 'Subscription-Id',
  444: 'Subscription-Id-Data',
  450: 'Subscription-Id-Type',
  461: 'Service-Context-Id',
  500: 'Abort-Cause',
  504: 'AF-Application-Identifier',
  505: 'AF-Charging-Identifier',
  507: 'Flow-Description',
  511: 'Flow-Status',
  513: 'Specific-Action',
  517: 'Media-Component-Description',
  518: 'Media-Component-Number',
  519: 'Media-Sub-Component',
  601: 'Public-Identity',
  602: 'Server-Name',
};

/** AVPs decoded as Unsigned32 / Enumerated. */
const AVP_UINT32 = new Set([258, 266, 268, 277, 278, 298, 415, 416, 450, 500, 511, 513, 518]);
/** AVPs decoded as UTF8String / DiameterIdentity / DiameterURI / IPFilterRule. */
const AVP_UTF8 = new Set([1, 30, 263, 264, 269, 281, 282, 283, 293, 296, 444, 461, 504, 505, 507, 601, 602]);
/** AVPs known to be Grouped (recursed). */
const AVP_GROUPED = new Set([260, 279, 297, 443, 517, 519]);

/** Base-protocol Result-Code values (RFC 6733 §7.1). */
const RESULT_CODES = {
  1001: 'DIAMETER_MULTI_ROUND_AUTH',
  2001: 'DIAMETER_SUCCESS',
  2002: 'DIAMETER_LIMITED_SUCCESS',
  3001: 'DIAMETER_COMMAND_UNSUPPORTED',
  3002: 'DIAMETER_UNABLE_TO_DELIVER',
  3003: 'DIAMETER_REALM_NOT_SERVED',
  3004: 'DIAMETER_TOO_BUSY',
  3005: 'DIAMETER_LOOP_DETECTED',
  3006: 'DIAMETER_REDIRECT_INDICATION',
  3007: 'DIAMETER_APPLICATION_UNSUPPORTED',
  3008: 'DIAMETER_INVALID_HDR_BITS',
  3009: 'DIAMETER_INVALID_AVP_BITS',
  3010: 'DIAMETER_UNKNOWN_PEER',
  4001: 'DIAMETER_AUTHENTICATION_REJECTED',
  4002: 'DIAMETER_OUT_OF_SPACE',
  4003: 'ELECTION_LOST',
  5001: 'DIAMETER_AVP_UNSUPPORTED',
  5002: 'DIAMETER_UNKNOWN_SESSION_ID',
  5003: 'DIAMETER_AUTHORIZATION_REJECTED',
  5004: 'DIAMETER_INVALID_AVP_VALUE',
  5005: 'DIAMETER_MISSING_AVP',
  5006: 'DIAMETER_RESOURCES_EXCEEDED',
  5007: 'DIAMETER_CONTRADICTING_AVPS',
  5008: 'DIAMETER_AVP_NOT_ALLOWED',
  5009: 'DIAMETER_AVP_OCCURS_TOO_MANY_TIMES',
  5010: 'DIAMETER_NO_COMMON_APPLICATION',
  5011: 'DIAMETER_UNSUPPORTED_VERSION',
  5012: 'DIAMETER_UNABLE_TO_COMPLY',
  5014: 'DIAMETER_INVALID_AVP_LENGTH',
  5015: 'DIAMETER_INVALID_MESSAGE_LENGTH',
  5017: 'DIAMETER_NO_COMMON_SECURITY',
};

/** 3GPP Rx Experimental-Result-Code values (TS 29.214). */
const RX_EXPERIMENTAL = {
  5061: 'INVALID_SERVICE_INFORMATION',
  5062: 'FILTER_RESTRICTIONS',
  5063: 'REQUESTED_SERVICE_NOT_AUTHORIZED',
  5064: 'DUPLICATED_AF_SESSION',
  5065: 'IP-CAN_SESSION_NOT_AVAILABLE',
  5066: 'UNAUTHORIZED_NON_EMERGENCY_SESSION',
};

/** 3GPP Cx/Dx Experimental-Result-Code values (TS 29.229). */
const CX_EXPERIMENTAL = {
  2001: 'DIAMETER_FIRST_REGISTRATION',
  2002: 'DIAMETER_SUBSEQUENT_REGISTRATION',
  2003: 'DIAMETER_UNREGISTERED_SERVICE',
  2004: 'DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED',
  5001: 'DIAMETER_ERROR_USER_UNKNOWN',
  5002: 'DIAMETER_ERROR_IDENTITIES_DONT_MATCH',
  5003: 'DIAMETER_ERROR_IDENTITY_NOT_REGISTERED',
  5004: 'DIAMETER_ERROR_ROAMING_NOT_ALLOWED',
  5005: 'DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED',
  5006: 'DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED',
  5007: 'DIAMETER_ERROR_IN_ASSIGNMENT_TYPE',
  5008: 'DIAMETER_ERROR_TOO_MUCH_DATA',
  5009: 'DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA',
};

/**
 * Command name for a code, request or answer.
 * @param {number} code
 * @param {boolean} isRequest
 * @returns {string} e.g. 'AAR', or 'CMD999-Request' for unknown codes
 */
function commandName(code, isRequest) {
  const pair = COMMAND_NAMES[code];
  if (pair) return isRequest ? pair[0] : pair[1];
  return 'CMD' + code + (isRequest ? '-Request' : '-Answer');
}

/**
 * Application label ('Rx', 'Gx', 'Cx/Dx', 'Sh', …).
 * @param {number} appId
 * @returns {string}
 */
function appLabel(appId) {
  return APP_LABELS[appId] || ('app ' + appId);
}

/**
 * Result-Code name, or null when unknown.
 * @param {number} code
 * @returns {string|null}
 */
function resultCodeName(code) {
  return RESULT_CODES[code] || null;
}

/**
 * Experimental-Result-Code name for an application, or null when unknown.
 * @param {number} code
 * @param {number} appId
 * @returns {string|null}
 */
function experimentalName(code, appId) {
  if (appId === 16777236 || appId === 16777238) return RX_EXPERIMENTAL[code] || null;
  if (appId === 16777216 || appId === 16777217) return CX_EXPERIMENTAL[code] || null;
  return RX_EXPERIMENTAL[code] || CX_EXPERIMENTAL[code] || null;
}

/**
 * Space-separated lowercase hex, capped.
 * @param {Buffer} buf
 * @param {number} [cap]
 * @returns {string}
 */
function toSpacedHex(buf, cap) {
  const limit = Math.min(buf.length, cap || MAX_RAW_BYTES);
  const parts = new Array(limit);
  for (let i = 0; i < limit; i++) parts[i] = buf[i].toString(16).padStart(2, '0');
  let s = parts.join(' ');
  if (buf.length > limit) s += ' … (+' + (buf.length - limit) + ' bytes)';
  return s;
}

/**
 * True when the bytes are mostly printable ASCII (safe to show as a string).
 * @param {Buffer} buf
 * @returns {boolean}
 */
function isPrintable(buf) {
  if (!buf.length) return false;
  let printable = 0;
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b === 0x09 || b === 0x0a || b === 0x0d || (b >= 0x20 && b <= 0x7e)) printable++;
  }
  return printable / buf.length >= 0.9;
}

/**
 * Drop control characters from a decoded string.
 * @param {string} s
 * @returns {string}
 */
function cleanText(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0x20 && c !== 0x7f) out += s[i];
  }
  return out;
}

/**
 * Does this AVP payload look like a run of nested AVPs? Used only for AVP codes that
 * are not in the type tables, so an unknown Grouped AVP still renders as a tree.
 * @param {Buffer} data
 * @returns {boolean}
 */
function looksGrouped(data) {
  if (data.length < 8) return false;
  let pos = 0;
  let seen = 0;
  while (pos + 8 <= data.length) {
    const len = (data[pos + 5] << 16) | (data[pos + 6] << 8) | data[pos + 7];
    if (len < 8 || pos + len > data.length) return false;
    pos += len + ((4 - (len % 4)) % 4);
    seen += 1;
    if (seen > 32) return false;
  }
  return pos === data.length && seen > 0;
}

/**
 * Walk a run of AVPs (code, flags, length, optional vendor id, 4-byte padding).
 * @param {Buffer} buf
 * @param {number} start
 * @param {number} end
 * @param {number} appId application id (selects the Experimental-Result-Code table)
 * @param {number} depth current recursion depth
 * @param {{count: number}} budget shared AVP budget for this message
 * @returns {Array<object>} `[{ code, name, flags:{v,m,p}, vendorId, length, type, value,
 *   valueName?, avps? }]`
 */
function parseAvps(buf, start, end, appId, depth, budget) {
  const out = [];
  let pos = start;
  while (pos + 8 <= end) {
    if (budget.count >= MAX_AVPS_PER_MESSAGE) break;
    const code = buf.readUInt32BE(pos);
    const flagByte = buf[pos + 4];
    const len = (buf[pos + 5] << 16) | (buf[pos + 6] << 8) | buf[pos + 7];
    if (len < 8 || pos + len > end) break; // malformed: stop this run, keep what we have
    const vBit = (flagByte & 0x80) !== 0;
    let dataStart = pos + 8;
    let vendorId = 0;
    if (vBit) {
      if (len < 12) break;
      vendorId = buf.readUInt32BE(pos + 8);
      dataStart = pos + 12;
    }
    const data = buf.subarray(dataStart, pos + len);
    budget.count += 1;

    const avp = {
      code,
      name: AVP_NAMES[code] || ('AVP-' + code),
      flags: { v: vBit, m: (flagByte & 0x40) !== 0, p: (flagByte & 0x20) !== 0 },
      vendorId: vBit ? vendorId : 0,
      length: len,
      type: 'octets',
      value: null,
    };

    if (AVP_GROUPED.has(code) || (!AVP_UINT32.has(code) && !AVP_UTF8.has(code) && looksGrouped(data))) {
      avp.type = 'grouped';
      avp.avps = depth < MAX_AVP_DEPTH ? parseAvps(data, 0, data.length, appId, depth + 1, budget) : [];
      avp.value = avp.avps.map((c) => c.name).join(', ') || null;
    } else if (code === 8 && data.length === 4) {
      avp.type = 'ipaddress';
      avp.value = data[0] + '.' + data[1] + '.' + data[2] + '.' + data[3];
    } else if (AVP_UINT32.has(code) && data.length === 4) {
      avp.type = 'uint32';
      avp.value = data.readUInt32BE(0);
      if (code === 268) avp.valueName = resultCodeName(avp.value);
      else if (code === 298) avp.valueName = experimentalName(avp.value, appId);
      else if (code === 258) avp.valueName = appLabel(avp.value);
    } else if (AVP_UTF8.has(code) || isPrintable(data)) {
      avp.type = 'utf8';
      avp.value = cleanText(data.toString('utf8'));
    } else if (data.length === 4) {
      avp.type = 'uint32';
      avp.value = data.readUInt32BE(0);
    } else {
      avp.type = 'octets';
      avp.value = toSpacedHex(data, 32);
    }

    out.push(avp);
    pos += len + ((4 - (len % 4)) % 4); // AVPs are padded to a 4-byte boundary
  }
  return out;
}

/**
 * Parse a Diameter header at `off`, or null when it is not a plausible one.
 * @param {Buffer} buf
 * @param {number} off
 * @returns {object|null} `{ length, flags:{request,proxiable,error,retransmit}, code,
 *   appId, hopByHop, endToEnd }`
 */
function parseHeader(buf, off) {
  if (off + 20 > buf.length) return null;
  if (buf[off] !== 1) return null; // version
  const length = (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3];
  if (length < 20 || length % 4 !== 0 || length > (1 << 20)) return null;
  const f = buf[off + 4];
  if (f & 0x0f) return null; // reserved flag bits must be zero
  const code = (buf[off + 5] << 16) | (buf[off + 6] << 8) | buf[off + 7];
  if (code === 0) return null;
  return {
    length,
    flags: {
      request: (f & 0x80) !== 0,
      proxiable: (f & 0x40) !== 0,
      error: (f & 0x20) !== 0,
      retransmit: (f & 0x10) !== 0,
    },
    code,
    appId: buf.readUInt32BE(off + 8),
    hopByHop: buf.readUInt32BE(off + 12),
    endToEnd: buf.readUInt32BE(off + 16),
  };
}

/**
 * Next plausible Diameter header at/after `from` (resync after garbage).
 * @param {Buffer} buf
 * @param {number} from
 * @returns {number} offset, or -1
 */
function findNextHeader(buf, from) {
  for (let i = from; i + 20 <= buf.length; i++) {
    if (buf[i] !== 1) continue;
    const h = parseHeader(buf, i);
    if (h && i + h.length <= buf.length) return i;
  }
  return -1;
}

/**
 * Bucket TCP payloads per flow direction and assemble a seq-ordered byte stream.
 * (Local copy — Wave-2 modules never import one another.)
 * @param {Array<object>} packets
 * @param {function(object):boolean} keep predicate on the packet
 * @returns {Array<{src:string,dst:string,sport:number,dport:number,stream:Buffer,
 *   ranges:Array<{start:number,end:number,n:number,ts:number}>}>}
 */
function assembleTcpStreams(packets, keep) {
  const dirs = new Map();
  for (const p of packets) {
    if (!p || p.transport !== 'tcp' || !p.payload || p.payload.length === 0) continue;
    if (!keep(p)) continue;
    const key = p.src + ':' + p.sport + '>' + p.dst + ':' + p.dport;
    let d = dirs.get(key);
    if (!d) { d = { src: p.src, dst: p.dst, sport: p.sport, dport: p.dport, segments: [] }; dirs.set(key, d); }
    d.segments.push(p);
  }
  const out = [];
  for (const d of dirs.values()) {
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
    out.push({ src: d.src, dst: d.dst, sport: d.sport, dport: d.dport, stream, ranges });
  }
  return out;
}

/**
 * Flatten an AVP tree into `{ name: firstValue }` (children included).
 * @param {Array<object>} avps
 * @param {object} into
 * @param {number} depth
 * @returns {object}
 */
function flattenAvps(avps, into, depth) {
  for (const a of avps || []) {
    if (!(a.name in into) && a.value !== null && a.type !== 'grouped') into[a.name] = a.value;
    if (a.avps && depth < MAX_AVP_DEPTH) flattenAvps(a.avps, into, depth + 1);
  }
  return into;
}

/**
 * Every AVP with a given code in a tree (depth-first).
 * @param {Array<object>} avps
 * @param {number} code
 * @param {Array<object>} out
 * @param {number} depth
 * @returns {Array<object>}
 */
function findAvps(avps, code, out, depth) {
  for (const a of avps || []) {
    if (a.code === code) out.push(a);
    if (a.avps && depth < MAX_AVP_DEPTH) findAvps(a.avps, code, out, depth + 1);
  }
  return out;
}

/**
 * Human ms/s.
 * @param {number} ms
 * @returns {string}
 */
function fmtMs(ms) {
  if (!Number.isFinite(ms)) return '?';
  return ms >= 1000 ? (Math.round(ms / 100) / 10) + 's' : Math.round(ms) + 'ms';
}

/**
 * icid-value out of a SIP message's P-Charging-Vector, or null. (Implemented locally:
 * correlate.js does the same for leg pairing, but Wave-2 modules stay self-contained.)
 * @param {object} msg SipMessage
 * @returns {string|null}
 */
function sipIcid(msg) {
  const headers = (msg && msg.headers) || [];
  for (const h of headers) {
    if (!h || !h.name || !/^p-charging-vector$/i.test(String(h.name).trim())) continue;
    const m = /icid-value\s*=\s*(?:"([^"]*)"|([^;,\s]+))/i.exec(String(h.value || ''));
    if (m) {
      const v = (m[1] != null ? m[1] : m[2]).trim();
      if (v) return v;
    }
  }
  return null;
}

/**
 * Candidate icid strings carried by a Diameter message: AF-Charging-Identifier first,
 * then icid-looking tokens of Session-Id (';'/','-separated, >= 6 chars).
 * @param {object} detail aux detail
 * @returns {Array<string>}
 */
function diameterIcidCandidates(detail) {
  const out = [];
  const push = (v) => {
    if (typeof v !== 'string') return;
    const s = v.trim();
    if (s.length >= 6 && out.indexOf(s) < 0) out.push(s);
  };
  push(detail.afChargingIdentifier);
  if (typeof detail.sessionId === 'string') {
    for (const tok of detail.sessionId.split(/[;,]/)) push(tok);
  }
  return out;
}

/**
 * Extract Diameter observations from a capture and correlate Rx sessions to SIP.
 *
 * @param {Array<object>} packets Packet[] (parsePcap / parseTextLog output)
 * @param {{messages?: Array<object>, legs?: Array<object>, calls?: Array<object>,
 *   warnings?: Array<string>, auxIdStart?: number}} [ctx] analyze.js context; optional.
 *   `ctx.messages/legs/calls` drive the Rx-to-SIP correlation and `ctx.warnings` receives
 *   decoder oddities. `ctx.auxIdStart` (additive, optional) makes this module number its
 *   own rows from that offset — by default aux `id` is left null because analyze.js
 *   numbers the concatenated aux list of all three aux modules.
 * @returns {{aux: Array<object>, findings: Array<object>}} AuxMessage[] (protocol
 *   'diameter', ts order, `id: null`) plus Finding[] with `id: null`.
 */
function extractDiameter(packets, ctx) {
  const aux = [];
  const findings = [];
  const warn = (s) => {
    try { if (ctx && Array.isArray(ctx.warnings)) ctx.warnings.push(s); } catch (e) { /* ignore */ }
  };

  try {
    const flows = assembleTcpStreams(packets || [], (p) => p.sport === 3868 || p.dport === 3868
      || p.sport === 3869 || p.dport === 3869);
    const recs = [];
    let truncated = false;

    for (const f of flows) {
      let pos = 0;
      while (pos + 20 <= f.stream.length) {
        if (recs.length >= MAX_MESSAGES) { truncated = true; break; }
        const h = parseHeader(f.stream, pos);
        if (!h) {
          const next = findNextHeader(f.stream, pos + 1);
          if (next < 0) break;
          warn('diameter: resynchronised after ' + (next - pos) + ' unparsable bytes on '
            + f.src + ':' + f.sport + '>' + f.dst + ':' + f.dport);
          pos = next;
          continue;
        }
        if (pos + h.length > f.stream.length) break; // incomplete trailing message
        const body = f.stream.subarray(pos, pos + h.length);
        const budget = { count: 0 };
        const avps = parseAvps(body, 20, body.length, h.appId, 0, budget);
        const refs = f.ranges.filter((r) => r.start < pos + h.length && r.end > pos);
        recs.push({
          ts: refs.length ? refs[0].ts : 0,
          src: f.src, sport: f.sport, dst: f.dst, dport: f.dport,
          pktRefs: refs.map((r) => r.n),
          header: h, avps, body,
          avpsTruncated: budget.count >= MAX_AVPS_PER_MESSAGE,
        });
        pos += h.length;
      }
    }

    if (truncated) {
      warn('diameter: stopped after ' + MAX_MESSAGES + ' messages (capture truncated for analysis)');
    }
    if (!recs.length) return { aux, findings };
    recs.sort((a, b) => (a.ts - b.ts) || ((a.pktRefs[0] || 0) - (b.pktRefs[0] || 0)));

    // Pair answers to requests by (hop-by-hop id, command code, app id, reversed tuple).
    const pending = new Map();
    const reqKey = (r) => r.header.hopByHop + '|' + r.header.code + '|' + r.header.appId
      + '|' + r.src + ':' + r.sport + '>' + r.dst + ':' + r.dport;
    const ansKey = (r) => r.header.hopByHop + '|' + r.header.code + '|' + r.header.appId
      + '|' + r.dst + ':' + r.dport + '>' + r.src + ':' + r.sport;
    for (const r of recs) {
      r.answer = null;
      r.request = null;
      if (r.header.flags.request) {
        const k = reqKey(r);
        if (!pending.has(k)) pending.set(k, []);
        pending.get(k).push(r);
      } else {
        const list = pending.get(ansKey(r));
        if (list && list.length) {
          const q = list.shift();
          q.answer = r;
          r.request = q;
        }
      }
    }

    // `id` is left null: analyze.js concatenates the aux lists of all three aux modules
    // and numbers them 'x1…' itself, so self-assigned ids would collide. Pass
    // ctx.auxIdStart when calling this module standalone.
    const idStart = (ctx && Number.isFinite(ctx.auxIdStart)) ? ctx.auxIdStart : null;
    recs.forEach((r, i) => {
      const h = r.header;
      const isRequest = h.flags.request;
      const flat = flattenAvps(r.avps, {}, 0);
      const rcAvp = findAvps(r.avps, 268, [], 0)[0];
      const erAvp = findAvps(r.avps, 298, [], 0)[0];
      const resultCode = rcAvp && typeof rcAvp.value === 'number'
        ? { code: rcAvp.value, name: resultCodeName(rcAvp.value) || ('Result-Code ' + rcAvp.value) }
        : null;
      const experimental = erAvp && typeof erAvp.value === 'number'
        ? {
          code: erAvp.value,
          name: experimentalName(erAvp.value, h.appId) || ('Experimental-Result-Code ' + erAvp.value),
        }
        : null;

      // Failure verdict: base Result-Code >= 3000, or a 3GPP experimental 3xxx/4xxx/5xxx.
      const failure = !!((resultCode && resultCode.code >= 3000)
        || (experimental && experimental.code >= 3000));

      let latencyMs = null;
      if (isRequest && r.answer) latencyMs = Math.max(0, Math.round((r.answer.ts - r.ts) * 10000) / 10);
      else if (!isRequest && r.request) latencyMs = Math.max(0, Math.round((r.ts - r.request.ts) * 10000) / 10);

      const cmd = commandName(h.code, isRequest);
      const label = appLabel(h.appId);
      const afId = typeof flat['AF-Charging-Identifier'] === 'string' ? flat['AF-Charging-Identifier'] : null;
      const sessionId = typeof flat['Session-Id'] === 'string' ? flat['Session-Id'] : null;
      const mediaComponents = findAvps(r.avps, 517, [], 0).length;

      const detail = {
        role: isRequest ? 'request' : 'answer',
        commandCode: h.code,
        commandName: cmd,
        appId: h.appId,
        appLabel: label,
        flags: h.flags,
        hopByHop: h.hopByHop,
        endToEnd: h.endToEnd,
        sessionId,
        originHost: typeof flat['Origin-Host'] === 'string' ? flat['Origin-Host'] : null,
        originRealm: typeof flat['Origin-Realm'] === 'string' ? flat['Origin-Realm'] : null,
        destinationRealm: typeof flat['Destination-Realm'] === 'string' ? flat['Destination-Realm'] : null,
        destinationHost: typeof flat['Destination-Host'] === 'string' ? flat['Destination-Host'] : null,
        userName: typeof flat['User-Name'] === 'string' ? flat['User-Name'] : null,
        publicIdentity: typeof flat['Public-Identity'] === 'string' ? flat['Public-Identity'] : null,
        serverName: typeof flat['Server-Name'] === 'string' ? flat['Server-Name'] : null,
        framedIpAddress: typeof flat['Framed-IP-Address'] === 'string' ? flat['Framed-IP-Address'] : null,
        afChargingIdentifier: afId,
        mediaComponents,
        authApplicationId: typeof flat['Auth-Application-Id'] === 'number' ? flat['Auth-Application-Id'] : null,
        resultCode,
        experimentalResultCode: experimental,
        failure,
        errorMessage: typeof flat['Error-Message'] === 'string' ? flat['Error-Message'] : null,
        latencyMs,
        answered: isRequest ? !!r.answer : true,
        avps: r.avps,
        avpsTruncated: r.avpsTruncated,
        pktRefs: r.pktRefs.slice(),
        sipMsgIds: [],
        icid: null,
      };

      // Summary, in the contract's "what happened -> what came back" shape.
      const tag = afId ? ' icid=' + afId : (sessionId ? ' session=' + sessionId.split(';')[0] : '');
      let summary;
      if (isRequest) {
        if (r.answer) {
          const ansRc = findAvps(r.answer.avps, 268, [], 0)[0];
          const ansEr = findAvps(r.answer.avps, 298, [], 0)[0];
          let verdict = 'answered';
          if (ansRc && typeof ansRc.value === 'number') {
            verdict = (resultCodeName(ansRc.value) || 'Result-Code') + ' (' + ansRc.value + ')';
          } else if (ansEr && typeof ansEr.value === 'number') {
            verdict = (experimentalName(ansEr.value, h.appId) || 'Experimental-Result-Code')
              + ' (' + ansEr.value + ')';
          }
          summary = cmd + ' (' + label + ')' + tag + '  ->  ' + verdict + ' (' + fmtMs(latencyMs) + ')';
        } else {
          summary = cmd + ' (' + label + ')' + tag + '  ->  no answer';
        }
      } else {
        const verdict = resultCode ? resultCode.name + ' (' + resultCode.code + ')'
          : (experimental ? experimental.name + ' (' + experimental.code + ')' : 'no Result-Code');
        summary = cmd + ' (' + label + ')' + tag + '  ->  ' + verdict
          + (latencyMs !== null ? ' (' + fmtMs(latencyMs) + ')' : '');
      }

      aux.push({
        id: idStart === null ? null : 'x' + (idStart + i + 1),
        protocol: 'diameter',
        ts: r.ts,
        src: r.src, sport: r.sport, dst: r.dst, dport: r.dport,
        transport: 'tcp',
        summary,
        detail,
        raw: toSpacedHex(r.body),
        legIds: [],
        callIds: [],
      });
      r.aux = aux[aux.length - 1];
    });

    try {
      findings.push(...correlateRxToSip(recs, aux, ctx));
    } catch (e) {
      warn('diameter: Rx-to-SIP correlation failed: ' + (e && e.message ? e.message : e));
    }

    findings.push(...buildActivityFinding(aux));
  } catch (e) {
    warn('diameter: decode failed: ' + (e && e.message ? e.message : e));
  }

  return { aux, findings };
}

/**
 * Rx-to-SIP correlation (DESIGN_1's cross-protocol stretch goal).
 *
 * Matches AF-Charging-Identifier / Session-Id tokens against P-Charging-Vector
 * icid-value in ctx.messages, fills legIds/callIds on the aux rows (answers inherit
 * their request's association), and emits:
 *   info — the correlation fired, naming both sides;
 *   warn — a request answered with a failure Result-Code alongside a failing SIP call.
 *
 * @param {Array<object>} recs internal decoded records (carry `.aux`, `.answer`, `.request`)
 * @param {Array<object>} aux the emitted AuxMessage[]
 * @param {object} [ctx]
 * @returns {Array<object>} Finding[] with `id: null`
 */
function correlateRxToSip(recs, aux, ctx) {
  const findings = [];
  if (!ctx || !Array.isArray(ctx.messages) || !ctx.messages.length) return findings;

  const legOfMsg = new Map();
  for (const leg of (ctx.legs || [])) {
    for (const mid of (leg && leg.msgIds) || []) legOfMsg.set(mid, leg);
  }
  const callOfLeg = new Map();
  for (const c of (ctx.calls || [])) {
    for (const lid of (c && c.legIds) || []) callOfLeg.set(lid, c);
  }

  // icid (lower-cased) -> SIP evidence
  const byIcid = new Map();
  for (const m of ctx.messages) {
    if (!m || m.protocol === 'h323') continue;
    const icid = sipIcid(m);
    if (!icid) continue;
    const key = icid.toLowerCase();
    let e = byIcid.get(key);
    if (!e) { e = { icid, msgIds: [], legIds: new Set(), callIds: new Set(), legs: [] }; byIcid.set(key, e); }
    if (e.msgIds.length < 40) e.msgIds.push(m.id);
    const leg = legOfMsg.get(m.id);
    if (leg) {
      if (!e.legIds.has(leg.id)) { e.legIds.add(leg.id); e.legs.push(leg); }
      const call = callOfLeg.get(leg.id);
      if (call) e.callIds.add(call.id);
    }
  }
  if (!byIcid.size) return findings;

  /** Match candidate icid strings against the SIP icid index: exact first, then substring. */
  const matchIcid = (candidates) => {
    for (const cand of candidates) {
      const entry = byIcid.get(cand.toLowerCase());
      if (entry) return { entry, how: 'exact' };
    }
    for (const cand of candidates) {
      if (cand.length < 8) continue;
      const lc = cand.toLowerCase();
      for (const [key, entry] of byIcid) {
        if (key.length < 8) continue;
        if (lc.indexOf(key) >= 0 || key.indexOf(lc) >= 0) return { entry, how: 'substring' };
      }
    }
    return null;
  };

  const fired = new Map(); // icid -> aggregated evidence for the info finding
  for (const r of recs) {
    if (!r.aux) continue;
    const own = matchIcid(diameterIcidCandidates(r.aux.detail));
    const inherited = (!own && r.request && r.request.aux && r.request.aux._match)
      ? r.request.aux._match : null;
    const match = own || inherited;
    if (!match) continue;
    r.aux._match = match;
    r.aux.detail.icid = match.entry.icid;
    r.aux.detail.sipMsgIds = match.entry.msgIds.slice(0, 12);
    r.aux.legIds = Array.from(match.entry.legIds);
    r.aux.callIds = Array.from(match.entry.callIds);

    let f = fired.get(match.entry.icid);
    if (!f) {
      f = { entry: match.entry, cmds: new Set(), auxIds: [], appLabels: new Set(), how: match.how };
      fired.set(match.entry.icid, f);
    }
    f.cmds.add(r.aux.detail.commandName);
    f.appLabels.add(r.aux.detail.appLabel);
    if (f.auxIds.length < 20) f.auxIds.push(r.aux.id);
  }

  for (const f of fired.values()) {
    const cmds = Array.from(f.cmds).join('/');
    const apps = Array.from(f.appLabels).join('/');
    findings.push({
      id: null,
      severity: 'info',
      category: 'transport',
      title: 'Diameter ' + apps + ' session tied to the SIP call (icid ' + f.entry.icid + ')',
      detail: 'Diameter ' + cmds + ' on ' + apps + ' carries the same charging id as the SIP '
        + 'P-Charging-Vector icid-value ' + f.entry.icid
        + (f.how === 'substring' ? ' (matched as a Session-Id substring)' : '')
        + ', so ' + (f.entry.callIds.size ? 'call ' + Array.from(f.entry.callIds).join(', ') : 'this SIP dialog')
        + ' and the policy/charging exchange are one session. That is what lets you say whether the '
        + 'media bearer was authorised before the SIP answer, instead of guessing from timestamps.',
      msgIds: f.entry.msgIds.slice(0, 12),
      legIds: Array.from(f.entry.legIds),
      callIds: Array.from(f.entry.callIds),
    });
  }

  // A request answered with a failure Result-Code, alongside a failing SIP call.
  for (const r of recs) {
    if (!r.aux || r.aux.detail.role !== 'answer' || !r.aux.detail.failure) continue;
    const verdict = r.aux.detail.resultCode
      ? r.aux.detail.resultCode.name + ' (' + r.aux.detail.resultCode.code + ')'
      : (r.aux.detail.experimentalResultCode
        ? r.aux.detail.experimentalResultCode.name + ' (' + r.aux.detail.experimentalResultCode.code + ')'
        : 'a failure Result-Code');
    const cmd = r.request ? r.request.aux.detail.commandName : r.aux.detail.commandName;
    const match = r.aux._match || (r.request && r.request.aux && r.request.aux._match) || null;

    if (match) {
      const failedLegs = match.entry.legs.filter((l) => l
        && (l.state === 'failed' || l.state === 'canceled' || l.state === 'no-answer'));
      if (failedLegs.length) {
        findings.push({
          id: null,
          severity: 'warn',
          category: 'transport',
          title: cmd + ' rejected with ' + verdict + ' while the SIP call failed',
          detail: 'The ' + r.aux.detail.appLabel + ' ' + cmd + ' for icid ' + match.entry.icid
            + ' came back ' + verdict
            + (r.aux.detail.errorMessage ? ' ("' + r.aux.detail.errorMessage + '")' : '')
            + ', and SIP leg' + (failedLegs.length === 1 ? ' ' : 's ')
            + failedLegs.map((l) => l.id + ' (' + l.state
              + (l.failCode ? ' ' + l.failCode : '') + ')').join(', ')
            + ' failed. When policy control refuses the media authorisation the P-CSCF/SBC has no '
            + 'bearer to offer, so the SIP failure is downstream of this rejection — fix the '
            + 'service information / subscriber policy on the Rx side, not the SIP side.',
          msgIds: match.entry.msgIds.slice(0, 12),
          legIds: failedLegs.map((l) => l.id),
          callIds: Array.from(match.entry.callIds),
        });
        continue;
      }
    }

    // No icid link (or the linked legs are healthy): fall back to a temporal association.
    const near = [];
    for (const leg of (ctx.legs || [])) {
      if (!leg || leg.protocol !== 'sip') continue;
      if (leg.state !== 'failed' && leg.state !== 'canceled' && leg.state !== 'no-answer') continue;
      const s = Number.isFinite(leg.startTs) ? leg.startTs : null;
      if (s === null) continue;
      const e = Number.isFinite(leg.endTs) ? leg.endTs : s;
      if (r.ts >= s - 5 && r.ts <= e + 5) near.push(leg);
    }
    if (near.length) {
      findings.push({
        id: null,
        severity: 'warn',
        category: 'transport',
        title: cmd + ' rejected with ' + verdict + ' next to a failing SIP call',
        detail: 'The ' + r.aux.detail.appLabel + ' ' + cmd + ' was answered ' + verdict
          + (r.aux.detail.errorMessage ? ' ("' + r.aux.detail.errorMessage + '")' : '')
          + ' within 5s of SIP leg' + (near.length === 1 ? ' ' : 's ')
          + near.slice(0, 4).map((l) => l.id + ' (' + l.state + ')').join(', ')
          + ' failing. No charging id ties the two together, so this association is temporal only — '
          + 'but a policy rejection at that moment is the usual reason the SIP side gives up.',
        msgIds: [],
        legIds: near.slice(0, 4).map((l) => l.id),
        callIds: [],
      });
    }
  }

  for (const a of aux) delete a._match; // internal only: never serialised
  return findings;
}

/**
 * One info finding summarising Diameter activity (teaching surface, and the evidence
 * behind detect.js's `diameter` indicator).
 * @param {Array<object>} aux
 * @returns {Array<object>} Finding[] with `id: null`
 */
function buildActivityFinding(aux) {
  const rows = aux.filter((a) => a.protocol === 'diameter');
  if (!rows.length) return [];
  const apps = new Set();
  const cmds = new Map();
  let failures = 0;
  let unanswered = 0;
  for (const a of rows) {
    apps.add(a.detail.appLabel);
    if (a.detail.role === 'request') {
      cmds.set(a.detail.commandName, (cmds.get(a.detail.commandName) || 0) + 1);
      if (!a.detail.answered) unanswered += 1;
    }
    if (a.detail.failure) failures += 1;
  }
  const cmdText = Array.from(cmds.entries()).map(([k, v]) => k + ' ×' + v).join(', ') || 'no requests';
  return [{
    id: null,
    severity: 'info',
    category: 'transport',
    title: 'Diameter observed (' + Array.from(apps).join(', ') + ')',
    detail: rows.length + ' Diameter message' + (rows.length === 1 ? '' : 's') + ': ' + cmdText + '. '
      + failures + ' failure result code' + (failures === 1 ? '' : 's') + ', ' + unanswered
      + ' request' + (unanswered === 1 ? '' : 's') + ' unanswered. Rx (AAR/AAA) authorises the media '
      + 'bearer for an IMS session and Gx installs the policy rules on the gateway — a call can look '
      + 'clean on the SIP side and still fail because this exchange did.',
    msgIds: [],
    legIds: [],
    callIds: [],
  }];
}

module.exports = { extractDiameter };
