'use strict';

/**
 * lib/ice.js — STUN / ICE / DTLS-SRTP decode for the aux track.
 *
 * Export (frozen, ARCHITECTURE.md §"Wave 2 module exports"):
 *   extractIce(packets, ctx) -> { aux: [AuxMessage], findings: [Finding] }
 *
 * Scope:
 *  - **STUN** (RFC 5389): magic cookie 0x2112A442, method + class from the type bits,
 *    transaction id, attribute walk with XOR-MAPPED-ADDRESS (xor decode, v4 and v6),
 *    USERNAME, ERROR-CODE, ICE-CONTROLLED / ICE-CONTROLLING, USE-CANDIDATE, PRIORITY,
 *    SOFTWARE, REALM/NONCE, MESSAGE-INTEGRITY / FINGERPRINT presence, plus the TURN
 *    attributes that show up in the same flows. Requests and responses are paired by
 *    transaction id and grouped per candidate pair into `detail.checkList` with
 *    succeeded / failed / no-response.
 *  - **DTLS** record layer (content types 20 ChangeCipherSpec, 21 Alert, 22 Handshake,
 *    23 ApplicationData): handshake message types ClientHello 1, ServerHello 2,
 *    Certificate 11, ServerHelloDone 14, Finished 20 tracked as a progression;
 *    `detail.stalledAfter` when the handshake never finishes, `detail.srtpProfile` from
 *    the use_srtp extension when it is visible in the clear.
 *
 * One-way audio and WebRTC / Teams-side failures live here: when every ICE check fails
 * there is no media path at all, and a DTLS handshake that stalls means SRTP keys were
 * never agreed — the call signals perfectly and nobody hears anything.
 *
 * Never decrypts anything. Defensive by contract: never throws; oddities land on
 * ctx.warnings.
 *
 * Zero runtime dependencies. CommonJS.
 */

/** Hard caps so an ICE flood cannot bloat the analysis. */
const MAX_STUN_AUX = 600;       // per-message STUN rows emitted (all checks still counted)
const MAX_DTLS_AUX = 200;
const MAX_RAW_BYTES = 256;
const STUN_MAGIC = 0x2112a442;

/** STUN message class (2 bits) -> name. */
const STUN_CLASS_NAMES = ['request', 'indication', 'success response', 'error response'];

/** STUN method -> name (RFC 5389 + RFC 5766 TURN). */
const STUN_METHOD_NAMES = {
  1: 'Binding', 3: 'Allocate', 4: 'Refresh', 6: 'Send', 7: 'Data',
  8: 'CreatePermission', 9: 'ChannelBind',
};

/** STUN attribute type -> name. */
const STUN_ATTR_NAMES = {
  0x0001: 'MAPPED-ADDRESS',
  0x0003: 'CHANGE-REQUEST',
  0x0004: 'SOURCE-ADDRESS',
  0x0005: 'CHANGED-ADDRESS',
  0x0006: 'USERNAME',
  0x0008: 'MESSAGE-INTEGRITY',
  0x0009: 'ERROR-CODE',
  0x000a: 'UNKNOWN-ATTRIBUTES',
  0x000c: 'CHANNEL-NUMBER',
  0x000d: 'LIFETIME',
  0x0012: 'XOR-PEER-ADDRESS',
  0x0013: 'DATA',
  0x0014: 'REALM',
  0x0015: 'NONCE',
  0x0016: 'XOR-RELAYED-ADDRESS',
  0x0019: 'REQUESTED-TRANSPORT',
  0x001a: 'DONT-FRAGMENT',
  0x0020: 'XOR-MAPPED-ADDRESS',
  0x0022: 'RESERVATION-TOKEN',
  0x0024: 'PRIORITY',
  0x0025: 'USE-CANDIDATE',
  0x8020: 'XOR-MAPPED-ADDRESS (legacy)',
  0x8022: 'SOFTWARE',
  0x8023: 'ALTERNATE-SERVER',
  0x8028: 'FINGERPRINT',
  0x8029: 'ICE-CONTROLLED',
  0x802a: 'ICE-CONTROLLING',
  0x802b: 'RESPONSE-ORIGIN',
  0x802c: 'OTHER-ADDRESS',
};

/** DTLS/TLS content type -> name. */
const DTLS_CONTENT_NAMES = { 20: 'ChangeCipherSpec', 21: 'Alert', 22: 'Handshake', 23: 'ApplicationData' };

/** DTLS handshake message type -> name. */
const DTLS_HANDSHAKE_NAMES = {
  0: 'HelloRequest', 1: 'ClientHello', 2: 'ServerHello', 3: 'HelloVerifyRequest',
  4: 'NewSessionTicket', 11: 'Certificate', 12: 'ServerKeyExchange',
  13: 'CertificateRequest', 14: 'ServerHelloDone', 15: 'CertificateVerify',
  16: 'ClientKeyExchange', 20: 'Finished',
};

/** TLS alert description -> name (the ones worth naming in a trace). */
const TLS_ALERT_NAMES = {
  0: 'close_notify', 10: 'unexpected_message', 20: 'bad_record_mac', 21: 'decryption_failed',
  22: 'record_overflow', 30: 'decompression_failure', 40: 'handshake_failure',
  41: 'no_certificate', 42: 'bad_certificate', 43: 'unsupported_certificate',
  44: 'certificate_revoked', 45: 'certificate_expired', 46: 'certificate_unknown',
  47: 'illegal_parameter', 48: 'unknown_ca', 49: 'access_denied', 50: 'decode_error',
  51: 'decrypt_error', 70: 'protocol_version', 71: 'insufficient_security',
  80: 'internal_error', 86: 'inappropriate_fallback', 90: 'user_canceled',
  100: 'no_renegotiation', 110: 'unsupported_extension',
};

/** DTLS-SRTP protection profile (RFC 5764 §4.1.2, RFC 7714) -> name. */
const SRTP_PROFILES = {
  0x0001: 'SRTP_AES128_CM_HMAC_SHA1_80',
  0x0002: 'SRTP_AES128_CM_HMAC_SHA1_32',
  0x0005: 'SRTP_NULL_HMAC_SHA1_80',
  0x0006: 'SRTP_NULL_HMAC_SHA1_32',
  0x0007: 'SRTP_AEAD_AES_128_GCM',
  0x0008: 'SRTP_AEAD_AES_256_GCM',
};

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
 * Human ms/s.
 * @param {number} ms
 * @returns {string}
 */
function fmtMs(ms) {
  if (!Number.isFinite(ms)) return '?';
  return ms >= 1000 ? (Math.round(ms / 100) / 10) + 's' : Math.round(ms) + 'ms';
}

/** Printable-ASCII-only copy of a string. */
function cleanText(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0x20 && c !== 0x7f) out += s[i];
  }
  return out;
}

/**
 * Decode a STUN (XOR-)MAPPED-ADDRESS attribute value.
 * @param {Buffer} value attribute value bytes
 * @param {Buffer} msg whole STUN message (for the transaction id, needed for IPv6 xor)
 * @param {boolean} xor true for the XOR- variants
 * @returns {{family: 'ipv4'|'ipv6', address: string, port: number}|null}
 */
function decodeAddress(value, msg, xor) {
  if (!value || value.length < 4) return null;
  const family = value[1];
  let port = value.readUInt16BE(2);
  if (xor) port ^= 0x2112;
  if (family === 0x01) {
    if (value.length < 8) return null;
    const b = [value[4], value[5], value[6], value[7]];
    if (xor) {
      b[0] ^= 0x21; b[1] ^= 0x12; b[2] ^= 0xa4; b[3] ^= 0x42;
    }
    return { family: 'ipv4', address: b.join('.'), port };
  }
  if (family === 0x02) {
    if (value.length < 20) return null;
    const out = Buffer.from(value.subarray(4, 20));
    if (xor) {
      const cookieAndTx = msg.subarray(4, 20); // magic cookie + transaction id
      for (let i = 0; i < 16; i++) out[i] ^= cookieAndTx[i];
    }
    const groups = [];
    for (let i = 0; i < 8; i++) groups.push(((out[i * 2] << 8) | out[i * 2 + 1]).toString(16));
    return { family: 'ipv6', address: groups.join(':'), port };
  }
  return null;
}

/**
 * Parse a STUN message (RFC 5389). Returns null when the buffer is not plausibly STUN.
 * @param {Buffer} b payload bytes (may carry trailing data when multiplexed)
 * @returns {object|null} `{ type, method, methodName, cls, className, txid, length,
 *   attrs, username, errorCode, priority, useCandidate, iceRole, mappedAddress,
 *   software, hasMessageIntegrity, hasFingerprint, bytes }`
 */
function parseStun(b) {
  if (!b || b.length < 20) return null;
  if ((b[0] & 0xc0) !== 0) return null;              // first two bits must be zero
  if (b.readUInt32BE(4) !== STUN_MAGIC) return null;  // magic cookie
  const type = b.readUInt16BE(0);
  const length = b.readUInt16BE(2);
  if (length % 4 !== 0 || 20 + length > b.length) return null;
  const method = ((type & 0x3e00) >> 2) | ((type & 0x00e0) >> 1) | (type & 0x000f);
  const cls = ((type & 0x0100) >> 7) | ((type & 0x0010) >> 4);
  const msg = b.subarray(0, 20 + length);

  const out = {
    type, method,
    methodName: STUN_METHOD_NAMES[method] || ('method 0x' + method.toString(16)),
    cls, className: STUN_CLASS_NAMES[cls] || ('class ' + cls),
    txid: b.subarray(8, 20).toString('hex'),
    length,
    attrs: [],
    username: null,
    errorCode: null,
    priority: null,
    useCandidate: false,
    iceRole: null,
    mappedAddress: null,
    software: null,
    hasMessageIntegrity: false,
    hasFingerprint: false,
    bytes: msg,
  };

  let pos = 20;
  const end = 20 + length;
  while (pos + 4 <= end) {
    const atype = msg.readUInt16BE(pos);
    const alen = msg.readUInt16BE(pos + 2);
    if (pos + 4 + alen > end) break;
    const value = msg.subarray(pos + 4, pos + 4 + alen);
    const attr = { type: atype, name: STUN_ATTR_NAMES[atype] || ('0x' + atype.toString(16).padStart(4, '0')), length: alen, value: null };

    switch (atype) {
      case 0x0001: case 0x0004: case 0x0005: case 0x8023: case 0x802b: case 0x802c: {
        const a = decodeAddress(value, msg, false);
        attr.value = a ? a.address + ':' + a.port : null;
        if (atype === 0x0001 && a && !out.mappedAddress) out.mappedAddress = a;
        break;
      }
      case 0x0020: case 0x8020: case 0x0012: case 0x0016: {
        const a = decodeAddress(value, msg, true);
        attr.value = a ? a.address + ':' + a.port : null;
        if ((atype === 0x0020 || atype === 0x8020) && a) out.mappedAddress = a;
        break;
      }
      case 0x0006:
        attr.value = cleanText(value.toString('utf8'));
        out.username = attr.value;
        break;
      case 0x0014: case 0x0015: case 0x8022:
        attr.value = cleanText(value.toString('utf8'));
        if (atype === 0x8022) out.software = attr.value;
        break;
      case 0x0009: {
        if (value.length >= 4) {
          const code = (value[2] & 0x07) * 100 + value[3];
          const reason = cleanText(value.subarray(4).toString('utf8'));
          out.errorCode = { code, reason };
          attr.value = code + (reason ? ' ' + reason : '');
        }
        break;
      }
      case 0x0024:
        if (value.length >= 4) { out.priority = value.readUInt32BE(0); attr.value = out.priority; }
        break;
      case 0x0025:
        out.useCandidate = true;
        attr.value = true;
        break;
      case 0x8029: case 0x802a:
        out.iceRole = atype === 0x8029 ? 'controlled' : 'controlling';
        attr.value = value.length >= 8 ? value.subarray(0, 8).toString('hex') : null;
        break;
      case 0x0008:
        out.hasMessageIntegrity = true;
        break;
      case 0x8028:
        out.hasFingerprint = true;
        break;
      case 0x000d: case 0x000c:
        if (value.length >= 4) attr.value = value.readUInt32BE(0);
        break;
      case 0x000a: {
        const list = [];
        for (let i = 0; i + 2 <= value.length; i += 2) list.push('0x' + value.readUInt16BE(i).toString(16));
        attr.value = list.join(', ');
        break;
      }
      default:
        attr.value = alen ? toSpacedHex(value, 16) : null;
        break;
    }
    out.attrs.push(attr);
    pos += 4 + alen + ((4 - (alen % 4)) % 4); // attributes are padded to 4 bytes
  }
  return out;
}

/**
 * Pull the SRTP protection profiles out of a use_srtp (14) extension in a
 * ClientHello / ServerHello body.
 * @param {Buffer} body handshake message body
 * @param {boolean} isClientHello ClientHello bodies carry a DTLS cookie field
 * @returns {Array<string>} profile names (empty when not visible)
 */
function srtpProfilesFromHello(body, isClientHello) {
  try {
    let pos = 2 + 32; // client/server version + random
    if (pos >= body.length) return [];
    const sidLen = body[pos];
    pos += 1 + sidLen;
    if (isClientHello) {
      if (pos >= body.length) return [];
      const cookieLen = body[pos];
      pos += 1 + cookieLen;
      if (pos + 2 > body.length) return [];
      const csLen = body.readUInt16BE(pos);
      pos += 2 + csLen;
      if (pos >= body.length) return [];
      const compLen = body[pos];
      pos += 1 + compLen;
    } else {
      pos += 2; // cipher suite
      pos += 1; // compression method
    }
    if (pos + 2 > body.length) return [];
    const extTotal = body.readUInt16BE(pos);
    pos += 2;
    const extEnd = Math.min(body.length, pos + extTotal);
    while (pos + 4 <= extEnd) {
      const etype = body.readUInt16BE(pos);
      const elen = body.readUInt16BE(pos + 2);
      const edata = body.subarray(pos + 4, Math.min(extEnd, pos + 4 + elen));
      if (etype === 14 && edata.length >= 2) { // use_srtp
        const listLen = edata.readUInt16BE(0);
        const names = [];
        for (let i = 2; i + 2 <= Math.min(edata.length, 2 + listLen); i += 2) {
          const p = edata.readUInt16BE(i);
          names.push(SRTP_PROFILES[p] || ('profile 0x' + p.toString(16).padStart(4, '0')));
        }
        return names;
      }
      pos += 4 + elen;
    }
  } catch (e) {
    return [];
  }
  return [];
}

/**
 * Parse the DTLS record layer of one datagram.
 * @param {Buffer} b payload bytes
 * @returns {Array<object>} `[{ contentType, contentName, epoch, seq, length, handshake }]`
 *   where `handshake` is `{ msgType, name, msgSeq, srtpProfiles, encrypted }` or null.
 */
function parseDtlsRecords(b) {
  const out = [];
  let pos = 0;
  while (pos + 13 <= b.length) {
    const contentType = b[pos];
    if (!(contentType in DTLS_CONTENT_NAMES)) break;
    if (b[pos + 1] !== 0xfe) break;                     // DTLS 1.0 (feff) / 1.2 (fefd)
    const epoch = b.readUInt16BE(pos + 3);
    const seq = b.readUIntBE(pos + 5, 6);
    const length = b.readUInt16BE(pos + 11);
    if (pos + 13 + length > b.length) break;
    const frag = b.subarray(pos + 13, pos + 13 + length);
    const rec = {
      contentType,
      contentName: DTLS_CONTENT_NAMES[contentType],
      epoch, seq, length,
      handshake: null,
      alert: null,
    };
    if (contentType === 22) {
      if (epoch > 0) {
        // Encrypted handshake record: after ChangeCipherSpec this is Finished.
        rec.handshake = { msgType: 20, name: 'Finished', msgSeq: null, srtpProfiles: [], encrypted: true };
      } else if (frag.length >= 12) {
        const msgType = frag[0];
        const msgSeq = frag.readUInt16BE(4);
        const bodyLen = (frag[9] << 16) | (frag[10] << 8) | frag[11];
        const body = frag.subarray(12, Math.min(frag.length, 12 + bodyLen));
        const name = DTLS_HANDSHAKE_NAMES[msgType] || ('handshake type ' + msgType);
        let profiles = [];
        if (msgType === 1) profiles = srtpProfilesFromHello(body, true);
        else if (msgType === 2) profiles = srtpProfilesFromHello(body, false);
        rec.handshake = { msgType, name, msgSeq, srtpProfiles: profiles, encrypted: false };
      }
    } else if (contentType === 21 && epoch === 0 && frag.length >= 2) {
      rec.alert = {
        level: frag[0] === 2 ? 'fatal' : (frag[0] === 1 ? 'warning' : 'level ' + frag[0]),
        description: TLS_ALERT_NAMES[frag[1]] || ('alert ' + frag[1]),
      };
    }
    out.push(rec);
    pos += 13 + length;
  }
  return out;
}

/** Unordered endpoint-pair key so both directions land in one candidate pair. */
function pairKey(a, b) {
  return a < b ? a + ' <-> ' + b : b + ' <-> ' + a;
}

/**
 * Build the SDP-side index used to associate STUN/DTLS flows with SIP legs and calls:
 * media addresses (c= / m=), ICE candidate addresses and ice-ufrag values.
 * @param {object} [ctx] analyze.js context
 * @returns {{byEndpoint: Map<string,Set<string>>, byUfrag: Map<string,Set<string>>,
 *   callOfLeg: Map<string,string>, mediaLegs: number}}
 */
function buildSdpIndex(ctx) {
  const byEndpoint = new Map();
  const byUfrag = new Map();
  const callOfLeg = new Map();
  let mediaLegs = 0;
  if (!ctx || !Array.isArray(ctx.legs) || !Array.isArray(ctx.messages)) {
    return { byEndpoint, byUfrag, callOfLeg, mediaLegs };
  }
  for (const c of (ctx.calls || [])) {
    for (const lid of (c && c.legIds) || []) callOfLeg.set(lid, c.id);
  }
  const msgById = new Map();
  for (const m of ctx.messages) if (m && m.id) msgById.set(m.id, m);

  const addEndpoint = (key, legId) => {
    if (!key) return;
    let s = byEndpoint.get(key);
    if (!s) { s = new Set(); byEndpoint.set(key, s); }
    s.add(legId);
  };
  const addUfrag = (u, legId) => {
    if (!u) return;
    let s = byUfrag.get(u);
    if (!s) { s = new Set(); byUfrag.set(u, s); }
    s.add(legId);
  };

  for (const leg of ctx.legs) {
    if (!leg || leg.protocol !== 'sip') continue;
    let sawMedia = false;
    for (const mid of (leg.msgIds || [])) {
      const m = msgById.get(mid);
      if (!m || !m.sdp) continue;
      const sdp = m.sdp;
      const sessionAddr = sdp.connection || (sdp.origin && sdp.origin.addr) || null;
      for (const med of (sdp.media || [])) {
        sawMedia = true;
        if (sessionAddr && Number.isFinite(med.port)) addEndpoint(sessionAddr + ':' + med.port, leg.id);
        for (const a of (med.attrs || [])) {
          const cand = /^candidate:\S+\s+\d+\s+\S+\s+\d+\s+(\S+)\s+(\d+)/i.exec(String(a).replace(/^a=/, ''));
          if (cand) addEndpoint(cand[1] + ':' + cand[2], leg.id);
          const uf = /^ice-ufrag:(\S+)/i.exec(String(a).replace(/^a=/, ''));
          if (uf) addUfrag(uf[1], leg.id);
        }
      }
      for (const a of (sdp.sessionAttrs || [])) {
        const cand = /^candidate:\S+\s+\d+\s+\S+\s+\d+\s+(\S+)\s+(\d+)/i.exec(String(a).replace(/^a=/, ''));
        if (cand) addEndpoint(cand[1] + ':' + cand[2], leg.id);
        const uf = /^ice-ufrag:(\S+)/i.exec(String(a).replace(/^a=/, ''));
        if (uf) addUfrag(uf[1], leg.id);
      }
    }
    if (sawMedia) mediaLegs += 1;
  }
  return { byEndpoint, byUfrag, callOfLeg, mediaLegs };
}

/**
 * Legs/calls for one observation, from endpoint addresses and STUN usernames.
 * ICE USERNAME is `remote-ufrag:local-ufrag`, so either half can name a leg.
 * @param {object} idx buildSdpIndex output
 * @param {Array<string>} endpoints 'ip:port' strings
 * @param {Array<string>} usernames STUN USERNAME values
 * @returns {{legIds: Array<string>, callIds: Array<string>}}
 */
function associate(idx, endpoints, usernames) {
  const legIds = new Set();
  for (const ep of endpoints) {
    const s = idx.byEndpoint.get(ep);
    if (s) for (const l of s) legIds.add(l);
  }
  for (const u of usernames) {
    if (!u) continue;
    for (const part of String(u).split(':')) {
      const s = idx.byUfrag.get(part);
      if (s) for (const l of s) legIds.add(l);
    }
  }
  const callIds = new Set();
  for (const l of legIds) {
    const c = idx.callOfLeg.get(l);
    if (c) callIds.add(c);
  }
  return { legIds: Array.from(legIds), callIds: Array.from(callIds) };
}

/**
 * Extract STUN / ICE / DTLS observations from a capture.
 *
 * @param {Array<object>} packets Packet[] (parsePcap / parseTextLog output)
 * @param {{messages?: Array<object>, legs?: Array<object>, calls?: Array<object>,
 *   warnings?: Array<string>, auxIdStart?: number}} [ctx] analyze.js context; optional.
 *   Used for leg/call association (SDP media addresses, a=candidate, a=ice-ufrag) and for
 *   ctx.warnings. `ctx.auxIdStart` (additive, optional) makes this module number its own
 *   rows from that offset — by default aux `id` is left null because analyze.js numbers
 *   the concatenated aux list of all three aux modules.
 * @returns {{aux: Array<object>, findings: Array<object>}} AuxMessage[] (protocols
 *   'stun' | 'ice' | 'dtls', ts order, `id: null`) plus Finding[] with `id: null`.
 */
function extractIce(packets, ctx) {
  const aux = [];
  const findings = [];
  const warn = (s) => {
    try { if (ctx && Array.isArray(ctx.warnings)) ctx.warnings.push(s); } catch (e) { /* ignore */ }
  };

  try {
    const idx = buildSdpIndex(ctx);
    const stun = [];   // { p, msg }
    const dtls = [];   // { p, records }
    let stunSkipped = 0;
    let dtlsSkipped = 0;

    for (const p of (packets || [])) {
      if (!p || !p.payload || p.payload.length < 13) continue;   // cheap shape check first
      const b = p.payload;
      const b0 = b[0];
      if ((b0 & 0xc0) === 0 && b.length >= 20 && b.readUInt32BE(4) === STUN_MAGIC) {
        const msg = parseStun(b);
        if (msg) {
          if (stun.length < MAX_STUN_AUX * 8) stun.push({ p, msg });
          else stunSkipped += 1;
        }
        continue;
      }
      if (b[1] === 0xfe && (b0 === 20 || b0 === 21 || b0 === 22 || b0 === 23)) {
        const records = parseDtlsRecords(b);
        if (records.length) {
          if (dtls.length < MAX_DTLS_AUX * 4) dtls.push({ p, records });
          else dtlsSkipped += 1;
        }
      }
    }
    if (stunSkipped) warn('ice: skipped ' + stunSkipped + ' STUN packets beyond the analysis cap');
    if (dtlsSkipped) warn('ice: skipped ' + dtlsSkipped + ' DTLS packets beyond the analysis cap');
    if (!stun.length && !dtls.length) return { aux, findings };

    // ---- STUN: pair by transaction id, group per candidate pair ----------------
    const byTxid = new Map();
    for (const s of stun) {
      const key = s.msg.txid;
      let e = byTxid.get(key);
      if (!e) { e = { request: null, responses: [] }; byTxid.set(key, e); }
      if (s.msg.cls === 0 && !e.request) e.request = s;
      else if (s.msg.cls === 2 || s.msg.cls === 3) e.responses.push(s);
    }

    const pairs = new Map();
    const pairOf = (s) => {
      const a = s.p.src + ':' + s.p.sport;
      const b = s.p.dst + ':' + s.p.dport;
      const key = pairKey(a, b);
      let e = pairs.get(key);
      if (!e) {
        e = {
          pair: key, from: a, to: b,
          requests: 0, successes: 0, errors: 0, noResponse: 0,
          firstTs: s.p.ts, lastTs: s.p.ts,
          useCandidate: false, nominated: false,
          priority: null, username: null, iceRoles: [],
          errorCodes: [], mappedAddress: null,
          state: 'no-response',
          rttMs: null,
        };
        pairs.set(key, e);
      }
      if (s.p.ts < e.firstTs) e.firstTs = s.p.ts;
      if (s.p.ts > e.lastTs) e.lastTs = s.p.ts;
      return e;
    };

    for (const s of stun) {
      const e = pairOf(s);
      if (s.msg.username && !e.username) e.username = s.msg.username;
      if (s.msg.priority !== null && e.priority === null) e.priority = s.msg.priority;
      if (s.msg.iceRole && e.iceRoles.indexOf(s.msg.iceRole) < 0) e.iceRoles.push(s.msg.iceRole);
      if (s.msg.useCandidate) { e.useCandidate = true; e.nominated = true; }
      if (s.msg.mappedAddress && !e.mappedAddress) {
        e.mappedAddress = s.msg.mappedAddress.address + ':' + s.msg.mappedAddress.port;
      }
      if (s.msg.cls === 0) {
        e.requests += 1;
        const tx = byTxid.get(s.msg.txid);
        const answered = tx && tx.responses.length > 0;
        if (!answered) e.noResponse += 1;
        else {
          const first = tx.responses[0];
          const rtt = Math.max(0, Math.round((first.p.ts - s.p.ts) * 10000) / 10);
          if (e.rttMs === null || rtt < e.rttMs) e.rttMs = rtt;
        }
      } else if (s.msg.cls === 2) {
        e.successes += 1;
      } else if (s.msg.cls === 3) {
        e.errors += 1;
        if (s.msg.errorCode) {
          const t = s.msg.errorCode.code + (s.msg.errorCode.reason ? ' ' + s.msg.errorCode.reason : '');
          if (e.errorCodes.indexOf(t) < 0) e.errorCodes.push(t);
        }
      }
    }
    for (const e of pairs.values()) {
      if (e.successes > 0) e.state = 'succeeded';
      else if (e.errors > 0) e.state = 'failed';
      else e.state = 'no-response';
    }

    // ---- DTLS: progression per flow pair --------------------------------------
    const flows = new Map();
    for (const d of dtls) {
      const a = d.p.src + ':' + d.p.sport;
      const b = d.p.dst + ':' + d.p.dport;
      const key = pairKey(a, b);
      let f = flows.get(key);
      if (!f) {
        f = {
          pair: key, from: a, to: b,
          firstTs: d.p.ts, lastTs: d.p.ts,
          progression: [], seen: new Set(),
          ccsDirs: new Set(), finishedDirs: new Set(),
          srtpProfile: null, offeredProfiles: [],
          alerts: [], appData: 0,
          complete: false, stalledAfter: null,
          endpoints: new Set([a, b]),
        };
        flows.set(key, f);
      }
      if (d.p.ts < f.firstTs) f.firstTs = d.p.ts;
      if (d.p.ts > f.lastTs) f.lastTs = d.p.ts;
      const dir = d.p.src + ':' + d.p.sport;
      for (const rec of d.records) {
        if (rec.contentType === 22 && rec.handshake) {
          const name = rec.handshake.name;
          if (!f.seen.has(dir + '/' + name)) {
            f.seen.add(dir + '/' + name);
            f.progression.push({ ts: d.p.ts, from: dir, step: name });
          }
          if (rec.handshake.encrypted || rec.handshake.msgType === 20) f.finishedDirs.add(dir);
          if (rec.handshake.srtpProfiles && rec.handshake.srtpProfiles.length) {
            if (rec.handshake.msgType === 1) f.offeredProfiles = rec.handshake.srtpProfiles.slice();
            // ServerHello names the single selected profile.
            if (rec.handshake.msgType === 2) f.srtpProfile = rec.handshake.srtpProfiles[0];
            else if (!f.srtpProfile && rec.handshake.srtpProfiles.length === 1) {
              f.srtpProfile = rec.handshake.srtpProfiles[0];
            }
          }
        } else if (rec.contentType === 20) {
          f.ccsDirs.add(dir);
          if (!f.seen.has(dir + '/ChangeCipherSpec')) {
            f.seen.add(dir + '/ChangeCipherSpec');
            f.progression.push({ ts: d.p.ts, from: dir, step: 'ChangeCipherSpec' });
          }
        } else if (rec.contentType === 21 && rec.alert) {
          f.alerts.push({ ts: d.p.ts, from: dir, level: rec.alert.level, description: rec.alert.description });
          f.progression.push({ ts: d.p.ts, from: dir, step: 'Alert ' + rec.alert.level + ' ' + rec.alert.description });
        } else if (rec.contentType === 23) {
          f.appData += 1;
        }
      }
    }
    for (const f of flows.values()) {
      // Practical completion rule: both sides changed cipher spec (a Finished each way
      // is encrypted, so its content is presumed, not read).
      f.complete = f.ccsDirs.size >= 2 && f.finishedDirs.size >= 2;
      if (!f.complete) {
        const handshakeSteps = f.progression.filter((s) => s.step.indexOf('Alert') !== 0);
        f.stalledAfter = handshakeSteps.length ? handshakeSteps[handshakeSteps.length - 1].step : null;
        const fatal = f.alerts.find((a) => a.level === 'fatal');
        if (fatal) f.fatalAlert = fatal.description;
      }
      if (!f.srtpProfile && f.offeredProfiles.length === 1) f.srtpProfile = f.offeredProfiles[0];
    }

    // Association is computed per candidate pair (union of both endpoints and every
    // USERNAME seen on it) so a response with no USERNAME still names the same leg as
    // its request.
    const pairAssoc = new Map();
    for (const e of pairs.values()) {
      const usernames = [];
      for (const s of stun) {
        if (s.msg.username && pairKey(s.p.src + ':' + s.p.sport, s.p.dst + ':' + s.p.dport) === e.pair) {
          usernames.push(s.msg.username);
        }
      }
      pairAssoc.set(e.pair, associate(idx, [e.from, e.to], usernames));
    }

    // ---- Emit aux rows --------------------------------------------------------
    const rows = [];
    let stunEmitted = 0;
    for (const s of stun) {
      if (stunEmitted >= MAX_STUN_AUX) break;
      stunEmitted += 1;
      const m = s.msg;
      const a = s.p.src + ':' + s.p.sport;
      const b = s.p.dst + ':' + s.p.dport;
      const key = pairKey(a, b);
      const tx = byTxid.get(m.txid);
      let latencyMs = null;
      if (m.cls === 0 && tx && tx.responses.length) {
        latencyMs = Math.max(0, Math.round((tx.responses[0].p.ts - s.p.ts) * 10000) / 10);
      } else if ((m.cls === 2 || m.cls === 3) && tx && tx.request) {
        latencyMs = Math.max(0, Math.round((s.p.ts - tx.request.p.ts) * 10000) / 10);
      }

      const bits = [];
      if (m.useCandidate) bits.push('USE-CANDIDATE');
      if (m.iceRole) bits.push('ICE-' + m.iceRole.toUpperCase());
      if (m.priority !== null) bits.push('prio ' + m.priority);
      const tags = bits.length ? ' (' + bits.join(', ') + ')' : '';

      let summary;
      if (m.cls === 0) {
        if (tx && tx.responses.length) {
          const resp = tx.responses[0].msg;
          if (resp.cls === 3 && resp.errorCode) {
            summary = m.methodName + ' request' + tags + '  ->  ' + resp.errorCode.code + ' '
              + (resp.errorCode.reason || 'error') + ' (' + fmtMs(latencyMs) + ')';
          } else {
            const mapped = resp.mappedAddress
              ? resp.mappedAddress.address + ':' + resp.mappedAddress.port : 'success';
            summary = m.methodName + ' request' + tags + '  ->  ' + mapped + ' (' + fmtMs(latencyMs) + ')';
          }
        } else {
          summary = m.methodName + ' request' + tags + '  ->  no response';
        }
      } else if (m.cls === 3) {
        summary = m.methodName + ' error response  ->  '
          + (m.errorCode ? m.errorCode.code + ' ' + (m.errorCode.reason || '') : 'unknown error')
          + (latencyMs !== null ? ' (' + fmtMs(latencyMs) + ')' : '');
      } else if (m.cls === 2) {
        summary = m.methodName + ' success response  ->  '
          + (m.mappedAddress ? m.mappedAddress.address + ':' + m.mappedAddress.port : 'no mapped address')
          + (latencyMs !== null ? ' (' + fmtMs(latencyMs) + ')' : '');
      } else {
        summary = m.methodName + ' indication';
      }

      const assoc = pairAssoc.get(key) || associate(idx, [a, b], [m.username]);
      rows.push({
        protocol: 'stun',
        ts: s.p.ts,
        src: s.p.src, sport: s.p.sport, dst: s.p.dst, dport: s.p.dport,
        transport: s.p.transport,
        summary,
        detail: {
          role: STUN_CLASS_NAMES[m.cls] || 'unknown',
          method: m.methodName,
          messageClass: m.className,
          txid: m.txid,
          pair: key,
          username: m.username,
          priority: m.priority,
          useCandidate: m.useCandidate,
          iceRole: m.iceRole,
          mappedAddress: m.mappedAddress
            ? m.mappedAddress.address + ':' + m.mappedAddress.port : null,
          errorCode: m.errorCode,
          software: m.software,
          hasMessageIntegrity: m.hasMessageIntegrity,
          hasFingerprint: m.hasFingerprint,
          attributes: m.attrs.map((x) => ({ name: x.name, value: x.value })),
          latencyMs,
          answered: m.cls === 0 ? !!(tx && tx.responses.length) : true,
          pktRefs: [s.p.n],
        },
        raw: toSpacedHex(m.bytes),
        legIds: assoc.legIds,
        callIds: assoc.callIds,
      });
    }
    if (stun.length > stunEmitted) {
      warn('ice: ' + (stun.length - stunEmitted) + ' STUN messages summarised only (per-message cap '
        + MAX_STUN_AUX + '); the ICE check list still counts them all');
    }

    // The ICE check-list summary row: one per capture, carrying detail.checkList.
    if (pairs.size) {
      const list = Array.from(pairs.values()).sort((a, b) => a.firstTs - b.firstTs);
      const succeeded = list.filter((e) => e.state === 'succeeded');
      const failed = list.filter((e) => e.state === 'failed');
      const noResp = list.filter((e) => e.state === 'no-response');
      const nominated = list.find((e) => e.nominated && e.state === 'succeeded')
        || succeeded[0] || null;
      const endpoints = [];
      const usernames = [];
      for (const e of list) {
        endpoints.push(e.from, e.to);
        if (e.username) usernames.push(e.username);
      }
      const assoc = associate(idx, endpoints, usernames);
      const first = list[0];
      const summary = 'ICE connectivity checks: ' + list.length + ' candidate pair'
        + (list.length === 1 ? '' : 's') + '  ->  ' + succeeded.length + ' succeeded, '
        + failed.length + ' failed, ' + noResp.length + ' no response'
        + (nominated ? ' (nominated ' + nominated.pair + ')' : '');
      rows.push({
        protocol: 'ice',
        ts: first.firstTs,
        src: (first.from.split(':')[0] || null), sport: Number(first.from.split(':').pop()) || null,
        dst: (first.to.split(':')[0] || null), dport: Number(first.to.split(':').pop()) || null,
        transport: 'udp',
        summary,
        detail: {
          role: 'summary',
          checkList: list.map((e) => ({
            pair: e.pair, from: e.from, to: e.to,
            state: e.state,
            requests: e.requests,
            succeeded: e.successes,
            failed: e.errors,
            noResponse: e.noResponse,
            nominated: e.nominated,
            useCandidate: e.useCandidate,
            priority: e.priority,
            username: e.username,
            iceRoles: e.iceRoles,
            errorCodes: e.errorCodes,
            mappedAddress: e.mappedAddress,
            rttMs: e.rttMs,
            firstTs: e.firstTs, lastTs: e.lastTs,
          })),
          pairs: list.length,
          succeededPairs: succeeded.length,
          failedPairs: failed.length,
          noResponsePairs: noResp.length,
          nominatedPair: nominated ? nominated.pair : null,
          anySucceeded: succeeded.length > 0,
        },
        raw: null,
        legIds: assoc.legIds,
        callIds: assoc.callIds,
      });
    }

    // Per-record DTLS rows, then one summary row per flow.
    let dtlsEmitted = 0;
    for (const d of dtls) {
      if (dtlsEmitted >= MAX_DTLS_AUX) break;
      const a = d.p.src + ':' + d.p.sport;
      const b = d.p.dst + ':' + d.p.dport;
      const key = pairKey(a, b);
      const assoc = associate(idx, [a, b], []);
      for (const rec of d.records) {
        if (dtlsEmitted >= MAX_DTLS_AUX) break;
        dtlsEmitted += 1;
        let summary;
        if (rec.contentType === 22 && rec.handshake) {
          summary = 'DTLS ' + rec.handshake.name
            + (rec.handshake.encrypted ? ' (encrypted record — presumed)' : '')
            + (rec.handshake.srtpProfiles && rec.handshake.srtpProfiles.length
              ? '  ->  use_srtp ' + rec.handshake.srtpProfiles.join(', ') : '');
        } else if (rec.contentType === 21 && rec.alert) {
          summary = 'DTLS Alert  ->  ' + rec.alert.level + ' ' + rec.alert.description;
        } else {
          summary = 'DTLS ' + rec.contentName + (rec.epoch ? ' (epoch ' + rec.epoch + ')' : '');
        }
        rows.push({
          protocol: 'dtls',
          ts: d.p.ts,
          src: d.p.src, sport: d.p.sport, dst: d.p.dst, dport: d.p.dport,
          transport: d.p.transport,
          summary,
          detail: {
            role: 'record',
            pair: key,
            contentType: rec.contentType,
            contentName: rec.contentName,
            epoch: rec.epoch,
            seq: rec.seq,
            handshakeType: rec.handshake ? rec.handshake.name : null,
            encrypted: rec.handshake ? !!rec.handshake.encrypted : rec.epoch > 0,
            srtpProfiles: rec.handshake ? (rec.handshake.srtpProfiles || []) : [],
            alert: rec.alert,
            pktRefs: [d.p.n],
          },
          raw: toSpacedHex(d.p.payload),
          legIds: assoc.legIds,
          callIds: assoc.callIds,
        });
      }
    }

    for (const f of flows.values()) {
      const assoc = associate(idx, Array.from(f.endpoints), []);
      const steps = f.progression.map((s) => s.step);
      let summary;
      if (f.complete) {
        summary = 'DTLS-SRTP handshake completed  ->  '
          + (f.srtpProfile || 'profile not visible in the clear');
      } else {
        summary = 'DTLS-SRTP handshake did not complete  ->  stalled after '
          + (f.stalledAfter || 'the first record')
          + (f.fatalAlert ? ' (fatal alert: ' + f.fatalAlert + ')' : '');
      }
      rows.push({
        protocol: 'dtls',
        ts: f.firstTs,
        src: (f.from.split(':')[0] || null), sport: Number(f.from.split(':').pop()) || null,
        dst: (f.to.split(':')[0] || null), dport: Number(f.to.split(':').pop()) || null,
        transport: 'udp',
        summary,
        detail: {
          role: 'summary',
          pair: f.pair,
          progression: f.progression,
          steps,
          complete: f.complete,
          stalledAfter: f.complete ? null : (f.stalledAfter || null),
          srtpProfile: f.srtpProfile,
          offeredSrtpProfiles: f.offeredProfiles,
          alerts: f.alerts,
          appDataRecords: f.appData,
          firstTs: f.firstTs, lastTs: f.lastTs,
        },
        raw: null,
        legIds: assoc.legIds,
        callIds: assoc.callIds,
      });
    }

    rows.sort((a, b) => (a.ts - b.ts)
      || ((a.detail && a.detail.role === 'summary' ? 1 : 0) - (b.detail && b.detail.role === 'summary' ? 1 : 0)));
    // `id` is left null: analyze.js concatenates the aux lists of all three aux modules
    // and numbers them 'x1…' itself, so self-assigned ids would collide. Pass
    // ctx.auxIdStart when calling this module standalone.
    const idStart = (ctx && Number.isFinite(ctx.auxIdStart)) ? ctx.auxIdStart : null;
    rows.forEach((r, i) => {
      r.id = idStart === null ? null : 'x' + (idStart + i + 1);
      aux.push({
        id: r.id, protocol: r.protocol, ts: r.ts,
        src: r.src, sport: r.sport, dst: r.dst, dport: r.dport,
        transport: r.transport,
        summary: r.summary, detail: r.detail, raw: r.raw,
        legIds: r.legIds, callIds: r.callIds,
      });
    });

    findings.push(...buildIceFindings(pairs, flows, idx, aux));
  } catch (e) {
    warn('ice: decode failed: ' + (e && e.message ? e.message : e));
  }

  return { aux, findings };
}

/**
 * Findings: crit when every ICE check fails on a call that wanted media, warn on a
 * stalled DTLS handshake, info summarising a successful ICE / DTLS-SRTP negotiation.
 * @param {Map<string,object>} pairs candidate-pair records
 * @param {Map<string,object>} flows DTLS flow records
 * @param {object} idx buildSdpIndex output
 * @param {Array<object>} aux emitted aux rows (for legIds/callIds reuse)
 * @returns {Array<object>} Finding[] with `id: null`
 */
function buildIceFindings(pairs, flows, idx, aux) {
  const findings = [];
  const list = Array.from(pairs.values());
  const iceSummary = aux.find((a) => a.protocol === 'ice' && a.detail && a.detail.role === 'summary');
  const iceLegIds = iceSummary ? iceSummary.legIds : [];
  const iceCallIds = iceSummary ? iceSummary.callIds : [];

  if (list.length) {
    const succeeded = list.filter((e) => e.state === 'succeeded');
    const failed = list.filter((e) => e.state === 'failed');
    const noResp = list.filter((e) => e.state === 'no-response');
    const checks = list.reduce((n, e) => n + e.requests, 0);
    if (!succeeded.length && checks > 0) {
      const reasons = [];
      for (const e of failed) for (const c of e.errorCodes) if (reasons.indexOf(c) < 0) reasons.push(c);
      // crit needs real evidence that a call wanted media: several checks, an
      // associated SIP leg, or a leg that negotiated media. A single stray STUN packet
      // in an otherwise SIP-only capture is a warn, not a dead call.
      const strong = checks >= 2 || iceLegIds.length > 0 || (idx && idx.mediaLegs > 0);
      findings.push({
        id: null,
        severity: strong ? 'crit' : 'warn',
        category: 'transport',
        title: strong
          ? 'Every ICE connectivity check failed — no media path'
          : 'ICE connectivity check went unanswered',
        detail: checks + ' STUN binding check' + (checks === 1 ? '' : 's') + ' across ' + list.length
          + ' candidate pair' + (list.length === 1 ? '' : 's') + ' produced no success response ('
          + failed.length + ' failed, ' + noResp.length + ' unanswered'
          + (reasons.length ? '; errors: ' + reasons.join(', ') : '') + ')'
          + (idx && idx.mediaLegs
            ? ', while ' + idx.mediaLegs + ' SIP leg' + (idx.mediaLegs === 1 ? '' : 's')
              + ' negotiated media' : '')
          + '. ICE never nominated a pair, so however clean the signalling looks there is no path '
          + 'for RTP: expect silence in both directions. Usual causes are a symmetric NAT with no '
          + 'relay candidate, UDP blocked towards the candidate ports, or an ice-ufrag/pwd mismatch '
          + 'after the SBC rewrote the SDP.',
        msgIds: [],
        legIds: iceLegIds,
        callIds: iceCallIds,
      });
    }
  }

  const flowList = Array.from(flows.values());
  for (const f of flowList) {
    if (f.complete) continue;
    const row = aux.find((a) => a.protocol === 'dtls' && a.detail
      && a.detail.role === 'summary' && a.detail.pair === f.pair);
    findings.push({
      id: null,
      severity: 'warn',
      category: 'transport',
      title: 'DTLS-SRTP handshake never completed on ' + f.pair,
      detail: 'The DTLS handshake progressed as far as ' + (f.stalledAfter || 'its first record')
        + ' and then stopped'
        + (f.fatalAlert ? ' with a fatal alert (' + f.fatalAlert + ')' : ' with nothing further seen')
        + '. Without a completed handshake there are no SRTP keys, so media is either absent or '
        + 'undecryptable at the far end — the call answers and no one hears anything. Check that '
        + 'the DTLS packets are reaching the same address/port ICE nominated, that the certificate '
        + 'fingerprint in the SDP matches the one offered, and that no middlebox is dropping '
        + 'non-RTP UDP on the media port.',
      msgIds: [],
      legIds: row ? row.legIds : [],
      callIds: row ? row.callIds : [],
    });
  }

  const okPairs = list.filter((e) => e.state === 'succeeded');
  const okFlows = flowList.filter((f) => f.complete);
  if (okPairs.length || okFlows.length) {
    const nominated = list.find((e) => e.nominated && e.state === 'succeeded') || okPairs[0] || null;
    const profile = okFlows.map((f) => f.srtpProfile).filter(Boolean)[0] || null;
    findings.push({
      id: null,
      severity: 'info',
      category: 'transport',
      title: okFlows.length
        ? 'ICE and DTLS-SRTP negotiated successfully'
        : 'ICE negotiated successfully',
      detail: (okPairs.length ? okPairs.length + ' candidate pair'
        + (okPairs.length === 1 ? '' : 's') + ' answered'
        + (nominated ? ', nominated ' + nominated.pair
          + (nominated.rttMs !== null ? ' (check RTT ' + fmtMs(nominated.rttMs) + ')' : '') : '')
        : 'No candidate pair needed re-checking')
        + (okFlows.length ? '. DTLS-SRTP completed on ' + okFlows.length + ' flow'
          + (okFlows.length === 1 ? '' : 's')
          + (profile ? ' with ' + profile : ' (profile not visible in the clear)') : '')
        + '. ICE proves a bidirectional UDP path exists before media starts, and the DTLS handshake '
        + 'is what derives the SRTP keys — both succeeding means a media problem after this point is '
        + 'about codecs or the far end, not connectivity.',
      msgIds: [],
      legIds: iceLegIds,
      callIds: iceCallIds,
    });
  }

  return findings;
}

module.exports = { extractIce };
