'use strict';

/**
 * lib/dns.js — DNS query/response decode (RFC 1035) for the aux track.
 *
 * Exports (frozen, ARCHITECTURE.md §"Wave 2 module exports"):
 *   extractDns(packets, ctx) -> { aux: [AuxMessage], findings: [Finding] }
 *   dnsEvidence(aux)         -> { byDest: { '<queried name>': { slowQueries, timeouts, maxLatencyMs } },
 *                                 byAlias: { ... same shape, additive } }
 *
 * Scope: UDP port 53 and TCP port 53 (2-byte length prefix, per-direction seq
 * assembly). Full name decoding with compression pointers (loop-guarded), QTYPE /
 * QCLASS / RCODE names, RDATA decode for A, AAAA, SRV, NAPTR, CNAME, PTR, NS, MX,
 * TXT and SOA. Responses are paired to queries by (txid, reversed 4-tuple);
 * `detail.latencyMs` is filled on both sides, unanswered queries get
 * `detail.timedOut: true`, anything over 1s gets `detail.slow: true`.
 *
 * Why it matters: this is the evidence that upgrades retrans.js's `dns-blocking`
 * verdict from inference to proof (DESIGN_1 §3 — "far end slower than T1, often
 * blocking DNS (SRV/NAPTR) on egress, not congestion").
 *
 * Defensive by contract: never throws. Malformed packets are skipped; oddities are
 * pushed onto ctx.warnings when a ctx is supplied.
 *
 * Zero runtime dependencies. CommonJS.
 */

/** Hard caps so one pathological capture cannot stall an upload. */
const MAX_MESSAGES = 4000;      // DNS messages decoded
const MAX_RAW_BYTES = 512;      // bytes of hex kept per aux `raw`
const SLOW_MS = 1000;           // contract: "detail.slow:true over 1s"

/** QTYPE / TYPE numbers -> names. */
const TYPE_NAMES = {
  1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT',
  28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 41: 'OPT', 43: 'DS', 46: 'RRSIG',
  47: 'NSEC', 48: 'DNSKEY', 64: 'SVCB', 65: 'HTTPS', 252: 'AXFR', 255: 'ANY',
};

/** QCLASS / CLASS numbers -> names. */
const CLASS_NAMES = { 1: 'IN', 3: 'CH', 4: 'HS', 254: 'NONE', 255: 'ANY' };

/** RCODE -> name (RFC 1035 + RFC 2136/6891 additions). */
const RCODE_NAMES = {
  0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP',
  5: 'REFUSED', 6: 'YXDOMAIN', 7: 'YXRRSET', 8: 'NXRRSET', 9: 'NOTAUTH',
  10: 'NOTZONE', 16: 'BADVERS',
};

/** OPCODE -> name. */
const OPCODE_NAMES = { 0: 'QUERY', 1: 'IQUERY', 2: 'STATUS', 4: 'NOTIFY', 5: 'UPDATE' };

/**
 * Name for a DNS type number ('SRV', or 'TYPE99' for unknowns).
 * @param {number} t
 * @returns {string}
 */
function typeName(t) {
  return TYPE_NAMES[t] || ('TYPE' + t);
}

/**
 * Name for a DNS class number ('IN', or 'CLASS99').
 * @param {number} c
 * @returns {string}
 */
function className(c) {
  return CLASS_NAMES[c] || ('CLASS' + c);
}

/**
 * Name for an RCODE ('NXDOMAIN', or 'RCODE11').
 * @param {number} r
 * @returns {string}
 */
function rcodeName(r) {
  return RCODE_NAMES[r] || ('RCODE' + r);
}

/**
 * Space-separated lowercase hex, capped (same presentation as h323.js `raw`).
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
 * Make a decoded label safe to display (control bytes escaped, dots escaped).
 * @param {string} s
 * @returns {string}
 */
function safeLabel(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x2e) out += '\\.';
    else if (c < 0x20 || c > 0x7e) out += '\\x' + c.toString(16).padStart(2, '0');
    else out += s[i];
  }
  return out;
}

/**
 * Decode a (possibly compressed) DNS name at `off`.
 *
 * Compression pointers are followed with three independent guards: a visited-offset
 * set (catches self- and mutual loops), a jump cap, and the RFC 1035 255-octet total
 * length limit. Returns null when the name is malformed — callers then abandon the
 * message rather than throwing.
 *
 * @param {Buffer} buf whole DNS message (pointers are message-relative)
 * @param {number} off offset of the first length octet
 * @returns {{name: string, next: number}|null} decoded name and the offset just past
 *   the name *as encoded at `off`* (i.e. past the pointer, not past its target)
 */
function decodeName(buf, off) {
  const labels = [];
  const seen = new Set();
  let pos = off;
  let end = -1;
  let jumps = 0;
  let total = 0;
  while (pos >= 0 && pos < buf.length) {
    const len = buf[pos];
    if (len === 0) {
      pos += 1;
      if (end < 0) end = pos;
      return { name: labels.length ? labels.join('.') : '.', next: end };
    }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) return null;
      const ptr = ((len & 0x3f) << 8) | buf[pos + 1];
      if (end < 0) end = pos + 2;
      jumps += 1;
      if (jumps > 64 || ptr >= buf.length || seen.has(ptr)) return null; // pointer loop
      seen.add(ptr);
      pos = ptr;
      continue;
    }
    if ((len & 0xc0) !== 0) return null; // reserved label type
    if (pos + 1 + len > buf.length) return null;
    total += len + 1;
    if (total > 255) return null;
    labels.push(safeLabel(buf.toString('latin1', pos + 1, pos + 1 + len)));
    pos += 1 + len;
  }
  return null;
}

/**
 * Read a length-prefixed character-string (RFC 1035 §3.3) at `off`.
 * @param {Buffer} buf
 * @param {number} off
 * @returns {{text: string, next: number}|null}
 */
function readCharString(buf, off) {
  if (off >= buf.length) return null;
  const len = buf[off];
  if (off + 1 + len > buf.length) return null;
  return { text: safeLabel(buf.toString('latin1', off + 1, off + 1 + len)), next: off + 1 + len };
}

/**
 * Dotted-quad from 4 bytes.
 * @param {Buffer} b
 * @param {number} off
 * @returns {string}
 */
function ipv4(b, off) {
  return b[off] + '.' + b[off + 1] + '.' + b[off + 2] + '.' + b[off + 3];
}

/**
 * RFC 5952-ish IPv6 text from 16 bytes (longest zero run compressed).
 * @param {Buffer} b
 * @param {number} off
 * @returns {string}
 */
function ipv6(b, off) {
  const groups = [];
  for (let i = 0; i < 8; i++) groups.push(((b[off + i * 2] << 8) | b[off + i * 2 + 1]).toString(16));
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === '0') {
      if (curStart < 0) { curStart = i; curLen = 0; }
      curLen += 1;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else {
      curStart = -1; curLen = 0;
    }
  }
  if (bestLen < 2) return groups.join(':');
  return groups.slice(0, bestStart).join(':') + '::' + groups.slice(bestStart + bestLen).join(':');
}

/**
 * Decode one resource record's RDATA into `{ data, value }`.
 * `value` is the one-line text form used in summaries; `data` is the structured form.
 * Unknown types get a hex `value` and `data.hex`.
 *
 * @param {Buffer} buf whole message (for compression pointers inside RDATA)
 * @param {number} type RR type
 * @param {number} rdStart start of RDATA
 * @param {number} rdLen RDATA length
 * @returns {{data: object, value: string}}
 */
function decodeRdata(buf, type, rdStart, rdLen) {
  const end = rdStart + rdLen;
  const hex = () => ({ data: { hex: toSpacedHex(buf.subarray(rdStart, end), 64) }, value: toSpacedHex(buf.subarray(rdStart, end), 32) });
  try {
    switch (type) {
      case 1: { // A
        if (rdLen !== 4) return hex();
        const addr = ipv4(buf, rdStart);
        return { data: { address: addr }, value: addr };
      }
      case 28: { // AAAA
        if (rdLen !== 16) return hex();
        const addr = ipv6(buf, rdStart);
        return { data: { address: addr }, value: addr };
      }
      case 2: case 5: case 12: { // NS, CNAME, PTR
        const n = decodeName(buf, rdStart);
        if (!n) return hex();
        return { data: { target: n.name }, value: n.name };
      }
      case 15: { // MX
        if (rdLen < 3) return hex();
        const pref = buf.readUInt16BE(rdStart);
        const n = decodeName(buf, rdStart + 2);
        if (!n) return hex();
        return { data: { preference: pref, exchange: n.name }, value: pref + ' ' + n.name };
      }
      case 33: { // SRV
        if (rdLen < 7) return hex();
        const priority = buf.readUInt16BE(rdStart);
        const weight = buf.readUInt16BE(rdStart + 2);
        const port = buf.readUInt16BE(rdStart + 4);
        const n = decodeName(buf, rdStart + 6);
        if (!n) return hex();
        return {
          data: { priority, weight, port, target: n.name },
          value: priority + ' ' + weight + ' ' + n.name + ':' + port,
        };
      }
      case 35: { // NAPTR
        if (rdLen < 7) return hex();
        const order = buf.readUInt16BE(rdStart);
        const preference = buf.readUInt16BE(rdStart + 2);
        const f = readCharString(buf, rdStart + 4);
        if (!f) return hex();
        const s = readCharString(buf, f.next);
        if (!s) return hex();
        const r = readCharString(buf, s.next);
        if (!r) return hex();
        const repl = decodeName(buf, r.next);
        const replacement = repl ? repl.name : '.';
        return {
          data: { order, preference, flags: f.text, service: s.text, regexp: r.text, replacement },
          value: order + ' ' + preference + ' "' + f.text + '" "' + s.text + '" "' + r.text + '" ' + replacement,
        };
      }
      case 16: { // TXT
        const strings = [];
        let p = rdStart;
        while (p < end) {
          const cs = readCharString(buf, p);
          if (!cs || cs.next <= p) break;
          strings.push(cs.text);
          p = cs.next;
        }
        return { data: { strings }, value: strings.map((s) => '"' + s + '"').join(' ') };
      }
      case 6: { // SOA
        const m = decodeName(buf, rdStart);
        if (!m) return hex();
        const r = decodeName(buf, m.next);
        if (!r || r.next + 20 > end) return hex();
        const serial = buf.readUInt32BE(r.next);
        const refresh = buf.readUInt32BE(r.next + 4);
        const retry = buf.readUInt32BE(r.next + 8);
        const expire = buf.readUInt32BE(r.next + 12);
        const minimum = buf.readUInt32BE(r.next + 16);
        return {
          data: { mname: m.name, rname: r.name, serial, refresh, retry, expire, minimum },
          value: m.name + ' ' + r.name + ' ' + serial,
        };
      }
      default:
        return hex();
    }
  } catch (e) {
    return hex();
  }
}

/**
 * Parse a whole DNS message.
 *
 * Includes cheap plausibility checks (opcode, section counts, Z bits) so that
 * non-DNS traffic that happens to use port 53 is skipped rather than mis-decoded.
 *
 * @param {Buffer} buf
 * @returns {object|null} `{ txid, qr, opcode, opcodeName, aa, tc, rd, ra, rcode,
 *   rcodeName, counts, questions, answers, authority, additional }` or null.
 */
function parseDnsMessage(buf) {
  if (!buf || buf.length < 12) return null;
  const txid = buf.readUInt16BE(0);
  const flags = buf.readUInt16BE(2);
  const opcode = (flags >> 11) & 0x0f;
  if (!(opcode in OPCODE_NAMES)) return null;
  const qr = (flags & 0x8000) !== 0;
  const rcode = flags & 0x0f;
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
  const ns = buf.readUInt16BE(8);
  const ar = buf.readUInt16BE(10);
  if (qd > 32 || an > 512 || ns > 512 || ar > 512) return null;
  if (!qr && an > 0 && opcode === 0) return null; // a query with answers: not DNS as we know it

  const out = {
    txid, qr, opcode, opcodeName: OPCODE_NAMES[opcode] || ('OPCODE' + opcode),
    aa: (flags & 0x0400) !== 0,
    tc: (flags & 0x0200) !== 0,
    rd: (flags & 0x0100) !== 0,
    ra: (flags & 0x0080) !== 0,
    rcode, rcodeName: rcodeName(rcode),
    counts: { questions: qd, answers: an, authority: ns, additional: ar },
    questions: [], answers: [], authority: [], additional: [],
  };

  let pos = 12;
  for (let i = 0; i < qd; i++) {
    const n = decodeName(buf, pos);
    if (!n || n.next + 4 > buf.length) return out.questions.length ? out : null;
    const t = buf.readUInt16BE(n.next);
    const c = buf.readUInt16BE(n.next + 2);
    out.questions.push({ name: n.name, type: t, typeName: typeName(t), klass: c, klassName: className(c) });
    pos = n.next + 4;
  }

  const readSection = (count, into, decodeIt) => {
    for (let i = 0; i < count; i++) {
      const n = decodeName(buf, pos);
      if (!n || n.next + 10 > buf.length) { pos = buf.length; return; }
      const t = buf.readUInt16BE(n.next);
      const c = buf.readUInt16BE(n.next + 2);
      const ttl = buf.readUInt32BE(n.next + 4);
      const rdLen = buf.readUInt16BE(n.next + 8);
      const rdStart = n.next + 10;
      if (rdStart + rdLen > buf.length) { pos = buf.length; return; }
      const rr = {
        name: n.name, type: t, typeName: typeName(t), klass: c, klassName: className(c),
        ttl, rdLength: rdLen,
      };
      if (decodeIt) {
        const d = decodeRdata(buf, t, rdStart, rdLen);
        rr.data = d.data;
        rr.value = d.value;
      }
      into.push(rr);
      pos = rdStart + rdLen;
    }
  };
  readSection(an, out.answers, true);
  readSection(ns, out.authority, false);
  readSection(ar, out.additional, false);
  return out;
}

/**
 * Bucket TCP payloads per flow direction and assemble a seq-ordered byte stream.
 * (Same discipline as h323.js / sip.js, implemented locally — Wave-2 modules never
 * import one another.)
 * @param {Array<object>} packets
 * @param {function(object):boolean} keep predicate on the packet
 * @returns {Array<{src,dst,sport,dport,stream:Buffer,ranges:Array<{start,end,n,ts}>}>}
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
      segs = d.segments.filter((s) => (seen.has(s.tcp.seq) ? false : (seen.add(s.tcp.seq), true)));
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
 * Collect decoded DNS messages from a Packet[] (UDP 53 + TCP 53).
 * @param {Array<object>} packets
 * @param {function(string):void} warn
 * @returns {Array<object>} records `{ ts, src, sport, dst, dport, transport, pktRefs, buf, msg }`
 */
function collectDnsMessages(packets, warn) {
  const recs = [];
  let truncated = false;

  for (const p of (packets || [])) {
    if (recs.length >= MAX_MESSAGES) { truncated = true; break; }
    if (!p || p.transport !== 'udp') continue;            // port + shape checks first
    if (p.sport !== 53 && p.dport !== 53) continue;
    const buf = p.payload;
    if (!buf || buf.length < 12) continue;
    const msg = parseDnsMessage(buf);
    if (!msg) continue;
    recs.push({
      ts: p.ts, src: p.src, sport: p.sport, dst: p.dst, dport: p.dport,
      transport: 'udp', pktRefs: [p.n], buf, msg,
    });
  }

  const tcpFlows = assembleTcpStreams(packets || [], (p) => p.sport === 53 || p.dport === 53);
  for (const f of tcpFlows) {
    let pos = 0;
    while (pos + 2 <= f.stream.length) {
      if (recs.length >= MAX_MESSAGES) { truncated = true; break; }
      const len = f.stream.readUInt16BE(pos);
      if (len < 12 || pos + 2 + len > f.stream.length) break; // truncated / not DNS-over-TCP
      const buf = f.stream.subarray(pos + 2, pos + 2 + len);
      const msg = parseDnsMessage(buf);
      if (msg) {
        const refs = f.ranges.filter((r) => r.start < pos + 2 + len && r.end > pos);
        recs.push({
          ts: refs.length ? refs[0].ts : 0,
          src: f.src, sport: f.sport, dst: f.dst, dport: f.dport,
          transport: 'tcp', pktRefs: refs.map((r) => r.n), buf, msg,
        });
      }
      pos += 2 + len;
    }
  }

  if (truncated) warn('dns: stopped after ' + MAX_MESSAGES + ' DNS messages (capture truncated for analysis)');
  recs.sort((a, b) => (a.ts - b.ts) || ((a.pktRefs[0] || 0) - (b.pktRefs[0] || 0)));
  return recs;
}

/** Normalised lookup key for a queried name: lowercase, no trailing dot. */
function normName(name) {
  if (!name) return null;
  let s = String(name).toLowerCase();
  if (s.length > 1 && s.endsWith('.')) s = s.slice(0, -1);
  return s || null;
}

/** '_sip._udp.example.com' -> 'example.com' (service labels stripped), else null. */
function baseName(name) {
  const n = normName(name);
  if (!n) return null;
  const parts = n.split('.');
  let i = 0;
  while (i < parts.length && parts[i].charAt(0) === '_') i++;
  if (i === 0 || i >= parts.length) return null;
  const b = parts.slice(i).join('.');
  return b && b !== n ? b : null;
}

/** Human seconds/ms, e.g. '2.4s' / '23ms'. */
function fmtMs(ms) {
  if (!Number.isFinite(ms)) return '?';
  return ms >= 1000 ? (Math.round(ms / 100) / 10) + 's' : Math.round(ms) + 'ms';
}

/**
 * Extract DNS observations from a capture.
 *
 * @param {Array<object>} packets Packet[] (parsePcap / parseTextLog output)
 * @param {{messages?: Array<object>, legs?: Array<object>, calls?: Array<object>,
 *   warnings?: Array<string>, auxIdStart?: number}} [ctx] analyze.js context; optional.
 *   `ctx.warnings` receives decoder oddities. `ctx.auxIdStart` (additive, optional) makes
 *   this module number its own rows from that offset — by default aux `id` is left null
 *   because analyze.js numbers the concatenated aux list of all three aux modules.
 * @returns {{aux: Array<object>, findings: Array<object>}} AuxMessage[] (protocol 'dns',
 *   ts order, `id: null`) plus Finding[] with `id: null` (analyze.js assigns both).
 */
function extractDns(packets, ctx) {
  const aux = [];
  const findings = [];
  const warn = (s) => {
    try { if (ctx && Array.isArray(ctx.warnings)) ctx.warnings.push(s); } catch (e) { /* ignore */ }
  };

  try {
    const recs = collectDnsMessages(packets, warn);
    if (!recs.length) return { aux, findings };

    let captureEnd = 0;
    for (const p of (packets || [])) {
      if (p && Number.isFinite(p.ts) && p.ts > captureEnd) captureEnd = p.ts;
    }

    // Pair responses to queries by (txid, reversed 4-tuple), first unmatched wins.
    const pending = new Map(); // key -> [rec]
    const keyOf = (r) => r.msg.txid + '|' + r.src + ':' + r.sport + '>' + r.dst + ':' + r.dport;
    const revKeyOf = (r) => r.msg.txid + '|' + r.dst + ':' + r.dport + '>' + r.src + ':' + r.sport;

    for (const r of recs) {
      r.answeredBy = null;
      r.query = null;
      if (!r.msg.qr) {
        const k = keyOf(r);
        if (!pending.has(k)) pending.set(k, []);
        pending.get(k).push(r);
      } else {
        const list = pending.get(revKeyOf(r));
        if (list && list.length) {
          const qName = r.msg.questions.length ? normName(r.msg.questions[0].name) : null;
          let idx = list.findIndex((q) => {
            if (q.ts > r.ts + 0.000001) return false;
            const n = q.msg.questions.length ? normName(q.msg.questions[0].name) : null;
            return !qName || !n || qName === n;
          });
          if (idx < 0) idx = list.findIndex((q) => q.ts <= r.ts + 0.000001);
          if (idx >= 0) {
            const q = list[idx];
            list.splice(idx, 1);
            q.answeredBy = r;
            r.query = q;
          }
        }
      }
    }

    // Build the aux rows. `id` is left null: analyze.js concatenates the aux lists of
    // all three aux modules and numbers them 'x1…' itself, so self-assigned ids would
    // collide. Pass ctx.auxIdStart when calling this module standalone.
    const idStart = (ctx && Number.isFinite(ctx.auxIdStart)) ? ctx.auxIdStart : null;
    recs.forEach((r, i) => {
      const m = r.msg;
      const q0 = m.questions.length ? m.questions[0] : null;
      const qname = q0 ? q0.name : null;
      const qtype = q0 ? q0.typeName : null;
      const answers = (m.qr ? m.answers : (r.answeredBy ? r.answeredBy.msg.answers : []))
        .map((a) => ({ name: a.name, type: a.typeName, ttl: a.ttl, value: a.value }));

      let latencyMs = null;
      let timedOut = false;
      let waitedMs = null;
      if (!m.qr) {
        if (r.answeredBy) {
          latencyMs = Math.round((r.answeredBy.ts - r.ts) * 10000) / 10;
          if (latencyMs < 0) latencyMs = 0;
        } else {
          timedOut = true;
          waitedMs = Number.isFinite(captureEnd) && captureEnd > r.ts
            ? Math.round((captureEnd - r.ts) * 10000) / 10 : null;
        }
      } else if (r.query) {
        latencyMs = Math.round((r.ts - r.query.ts) * 10000) / 10;
        if (latencyMs < 0) latencyMs = 0;
      }
      const slow = Number.isFinite(latencyMs) && latencyMs > SLOW_MS;

      const rcodeStr = m.qr ? m.rcodeName : (r.answeredBy ? r.answeredBy.msg.rcodeName : null);
      let summary;
      if (!m.qr) {
        const head = (qtype || m.opcodeName) + '? ' + (qname || '(no question)');
        if (timedOut) {
          summary = head + '  ->  no answer' + (waitedMs !== null ? ' (' + fmtMs(waitedMs) + ')' : '');
        } else if (rcodeStr && rcodeStr !== 'NOERROR') {
          summary = head + '  ->  ' + rcodeStr + ' (' + fmtMs(latencyMs) + ')';
        } else if (answers.length) {
          const shown = answers.slice(0, 2).map((a) => a.value).join(', ');
          summary = head + '  ->  ' + shown
            + (answers.length > 2 ? ' +' + (answers.length - 2) + ' more' : '')
            + ' (' + fmtMs(latencyMs) + ')';
        } else {
          summary = head + '  ->  no answer records (' + fmtMs(latencyMs) + ')';
        }
      } else {
        const head = m.rcodeName + ' for ' + (qtype ? qtype + ' ' : '') + (qname || '(no question)');
        summary = head + '  ->  ' + answers.length + ' answer' + (answers.length === 1 ? '' : 's')
          + (latencyMs !== null ? ' (' + fmtMs(latencyMs) + ')' : '');
      }

      aux.push({
        id: idStart === null ? null : 'x' + (idStart + i + 1),
        protocol: 'dns',
        ts: r.ts,
        src: r.src, sport: r.sport, dst: r.dst, dport: r.dport,
        transport: r.transport,
        summary,
        detail: {
          role: m.qr ? 'response' : 'query',
          txid: m.txid,
          opcode: m.opcodeName,
          qname, qtype, qclass: q0 ? q0.klassName : null,
          questions: m.questions.map((q) => ({ name: q.name, type: q.typeName, klass: q.klassName })),
          answers,
          counts: m.counts,
          flags: { aa: m.aa, tc: m.tc, rd: m.rd, ra: m.ra },
          rcode: m.qr ? m.rcode : (r.answeredBy ? r.answeredBy.msg.rcode : null),
          rcodeName: rcodeStr,
          resolver: m.qr ? r.src : r.dst,
          latencyMs,
          timedOut,
          slow,
          waitedMs,
          answered: m.qr ? !!r.query : !!r.answeredBy,
          pktRefs: r.pktRefs.slice(),
        },
        raw: toSpacedHex(r.buf),
        legIds: [],
        callIds: [],
      });
    });

    // Best-effort leg/call association: the queried name (or its base domain)
    // appearing in a leg's Request-URI / To / Route host.
    try {
      associateLegs(aux, ctx);
    } catch (e) {
      warn('dns: leg association failed: ' + (e && e.message ? e.message : e));
    }

    findings.push(...buildDnsFindings(aux));
  } catch (e) {
    warn('dns: decode failed: ' + (e && e.message ? e.message : e));
  }

  return { aux, findings };
}

/**
 * Attach legIds/callIds to DNS aux rows whose queried name appears in a leg's
 * signalling (Request-URI host, To host, Route/Contact host). Best-effort only.
 * @param {Array<object>} aux
 * @param {object} [ctx]
 * @returns {void}
 */
function associateLegs(aux, ctx) {
  if (!ctx || !Array.isArray(ctx.legs) || !Array.isArray(ctx.messages)) return;
  const msgById = new Map();
  for (const m of ctx.messages) if (m && m.id) msgById.set(m.id, m);

  const callByLeg = new Map();
  for (const c of (ctx.calls || [])) {
    for (const lid of (c && c.legIds) || []) callByLeg.set(lid, c.id);
  }

  // leg -> lowercased haystack of its hostnames
  const legHosts = [];
  for (const leg of ctx.legs) {
    if (!leg || leg.protocol !== 'sip') continue;
    let hay = '';
    for (const mid of (leg.msgIds || []).slice(0, 12)) {
      const m = msgById.get(mid);
      if (!m) continue;
      if (m.requestUri) hay += ' ' + m.requestUri;
      if (m.toUri) hay += ' ' + m.toUri;
      if (m.contact) hay += ' ' + m.contact;
      for (const r of (m.routes || [])) hay += ' ' + r;
    }
    legHosts.push({ id: leg.id, hay: hay.toLowerCase() });
  }
  if (!legHosts.length) return;

  for (const a of aux) {
    const qn = normName(a.detail && a.detail.qname);
    if (!qn) continue;
    const bn = baseName(qn);
    const legIds = [];
    for (const lh of legHosts) {
      if (lh.hay.indexOf(qn) >= 0 || (bn && lh.hay.indexOf(bn) >= 0)) legIds.push(lh.id);
    }
    if (!legIds.length) continue;
    a.legIds = legIds;
    const callIds = [];
    for (const lid of legIds) {
      const cid = callByLeg.get(lid);
      if (cid && callIds.indexOf(cid) < 0) callIds.push(cid);
    }
    a.callIds = callIds;
  }
}

/**
 * Findings from the DNS aux rows: timeouts (warn), slow resolution (warn),
 * hard lookup failures (notice) and an activity summary (info).
 * @param {Array<object>} aux
 * @returns {Array<object>} Finding[] with `id: null`
 */
function buildDnsFindings(aux) {
  const findings = [];
  const queries = aux.filter((a) => a.detail && a.detail.role === 'query');
  if (!queries.length) return findings;

  const byName = new Map();
  for (const q of queries) {
    const key = normName(q.detail.qname) || '(no question)';
    let e = byName.get(key);
    if (!e) {
      e = { name: key, total: 0, timeouts: 0, slow: 0, maxLatencyMs: 0, failures: new Map(), types: new Set(), legIds: new Set(), callIds: new Set(), resolver: q.detail.resolver };
      byName.set(key, e);
    }
    e.total += 1;
    if (q.detail.qtype) e.types.add(q.detail.qtype);
    if (q.detail.timedOut) e.timeouts += 1;
    if (q.detail.slow) e.slow += 1;
    if (Number.isFinite(q.detail.latencyMs) && q.detail.latencyMs > e.maxLatencyMs) e.maxLatencyMs = q.detail.latencyMs;
    const rc = q.detail.rcodeName;
    if (rc && rc !== 'NOERROR') e.failures.set(rc, (e.failures.get(rc) || 0) + 1);
    for (const l of q.legIds || []) e.legIds.add(l);
    for (const c of q.callIds || []) e.callIds.add(c);
  }

  for (const e of byName.values()) {
    const types = Array.from(e.types).join('/') || 'DNS';
    if (e.timeouts > 0) {
      findings.push({
        id: null,
        severity: 'warn',
        category: 'transport',
        title: 'DNS lookup for ' + e.name + ' never answered',
        detail: e.timeouts + ' of ' + e.total + ' ' + types + ' quer' + (e.total === 1 ? 'y' : 'ies')
          + ' for ' + e.name + ' got no response from ' + (e.resolver || 'the resolver')
          + '. Egress routing stalls behind resolution (RFC 3263), so an INVITE can retransmit '
          + 'to Timer B without the far end ever being contacted — the capture shows the resolver, not the far end, is the problem.',
        msgIds: [],
        legIds: Array.from(e.legIds),
        callIds: Array.from(e.callIds),
      });
    }
    if (e.slow > 0) {
      findings.push({
        id: null,
        severity: 'warn',
        category: 'transport',
        title: 'Slow DNS resolution for ' + e.name + ' (' + fmtMs(e.maxLatencyMs) + ')',
        detail: e.slow + ' ' + types + ' quer' + (e.slow === 1 ? 'y' : 'ies') + ' for ' + e.name
          + ' took over 1s (worst ' + fmtMs(e.maxLatencyMs) + '). SIP timer T1 is 500ms, so a resolver '
          + 'this slow makes the first INVITE retransmit before the target is even known — that is '
          + 'blocking DNS on egress, not a slow far end.',
        msgIds: [],
        legIds: Array.from(e.legIds),
        callIds: Array.from(e.callIds),
      });
    }
    if (e.failures.size) {
      const parts = Array.from(e.failures.entries()).map(([k, v]) => k + ' ×' + v);
      findings.push({
        id: null,
        severity: 'notice',
        category: 'transport',
        title: 'DNS lookup for ' + e.name + ' failed (' + parts.join(', ') + ')',
        detail: 'The resolver answered ' + parts.join(', ') + ' for ' + types + ' ' + e.name
          + '. A NXDOMAIN/SERVFAIL/REFUSED on an egress target means the SBC has no destination to '
          + 'try — check the session agent / next-hop hostname and the resolver\'s view of that zone.',
        msgIds: [],
        legIds: Array.from(e.legIds),
        callIds: Array.from(e.callIds),
      });
    }
  }

  const timeouts = queries.filter((q) => q.detail.timedOut).length;
  const slow = queries.filter((q) => q.detail.slow).length;
  findings.push({
    id: null,
    severity: 'info',
    category: 'transport',
    title: 'DNS observed in this capture (' + queries.length + ' quer' + (queries.length === 1 ? 'y' : 'ies') + ')',
    detail: queries.length + ' DNS quer' + (queries.length === 1 ? 'y' : 'ies') + ' across '
      + byName.size + ' name' + (byName.size === 1 ? '' : 's') + ': ' + slow + ' slow (>1s), '
      + timeouts + ' unanswered. SIP uses NAPTR/SRV/A lookups (RFC 3263) to pick transport, port '
      + 'and host for the next hop, so DNS latency shows up as SIP latency.',
    msgIds: [],
    legIds: [],
    callIds: [],
  });

  return findings;
}

/**
 * Aggregate DNS evidence for advisor.js, keyed by the **queried name** — the
 * destination the SBC was trying to resolve. This is what proves the retransmission
 * classifier's `dns-blocking` verdict.
 *
 * `byDest` is exactly the contract shape (one entry per queried name). `byAlias` is
 * additive: the same stats re-keyed by the service-stripped base domain
 * ('_sip._udp.example.com' -> 'example.com') and by each resolved A/AAAA address /
 * SRV target, so a caller holding only an IP or a bare domain can still join.
 *
 * @param {Array<object>} aux AuxMessage[] (any mix of protocols; non-DNS ignored)
 * @returns {{byDest: Object<string,{slowQueries:number,timeouts:number,maxLatencyMs:number}>,
 *   byAlias: Object<string,{slowQueries:number,timeouts:number,maxLatencyMs:number}>}}
 */
function dnsEvidence(aux) {
  const byDest = {};
  const byAlias = {};
  try {
    const bump = (bag, key, d) => {
      if (!key) return;
      let e = bag[key];
      if (!e) { e = { slowQueries: 0, timeouts: 0, maxLatencyMs: 0 }; bag[key] = e; }
      if (d.slow) e.slowQueries += 1;
      if (d.timedOut) e.timeouts += 1;
      if (Number.isFinite(d.latencyMs) && d.latencyMs > e.maxLatencyMs) e.maxLatencyMs = d.latencyMs;
    };
    for (const a of (aux || [])) {
      if (!a || a.protocol !== 'dns' || !a.detail) continue;
      if (a.detail.role !== 'query') continue; // one row per query: never double-count
      const d = a.detail;
      const name = normName(d.qname);
      if (!name) continue;
      bump(byDest, name, d);
      bump(byAlias, baseName(name), d);
      for (const ans of (d.answers || [])) {
        if (ans.type === 'A' || ans.type === 'AAAA') bump(byAlias, normName(ans.value), d);
        else if (ans.type === 'SRV' && typeof ans.value === 'string') {
          const host = ans.value.split(' ').pop();
          bump(byAlias, normName(host ? host.replace(/:\d+$/, '') : null), d);
        }
      }
    }
  } catch (e) {
    return { byDest, byAlias };
  }
  return { byDest, byAlias };
}

module.exports = { extractDns, dnsEvidence };
