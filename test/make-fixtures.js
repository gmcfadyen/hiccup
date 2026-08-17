#!/usr/bin/env node
'use strict';
/**
 * test/make-fixtures.js -- hiccup's synthetic capture corpus generator.
 *
 * Writes test/fixtures/*.{pcap,pcapng,txt,cfg,ini} plus
 * test/fixtures/expected.json (the assertion table selftest.js consumes).
 *
 * Everything here is generated from scratch: a byte-accurate pure-JS pcap /
 * pcapng writer (Ethernet II + IPv4 with correct header checksums, UDP and TCP
 * with real pseudo-header checksums and sane seq progression, plus a genuinely
 * IPv4-fragmented variant), and hand-built SIP / SDP / Q.931 / ISUP / RTP /
 * RTCP / DNS / Diameter / STUN / DTLS / UDPTL payloads.
 *
 * Rules the corpus follows so the analysers get a fair test:
 *   - Content-Length is computed over the actual CRLF body (latin1 bytes).
 *   - z9hG4bK branches are byte-identical across retransmissions of one
 *     transaction and unique per transaction; ACK for a 2xx is its own
 *     transaction with its own branch.
 *   - Retransmission spacing follows RFC 3261: T1 = 500ms then doubling,
 *     capped at T2 = 4s for the (0.5, 1, 2, 4, 4, 4) ladder; timer-b.pcap uses
 *     the uncapped INVITE ladder so its run reaches Timer B at 32s.
 *   - Hosts: A = 198.51.100.10 (RFC 5737), SBC outside = 203.0.113.5,
 *     SBC inside = 10.20.0.5, core = 10.20.0.30 (RFC 1918) so the topology
 *     and lab-addressing detectors have something to bite on.
 *   - Every generated capture is re-parsed through ../lib/pcap.js before the
 *     script exits; a packet-count or field mismatch fails the run.
 *
 * Deterministic: all ids/tags/branches are md5-derived from stable labels and
 * all timestamps are offsets from a fixed epoch, so re-running produces
 * byte-identical files. ASCII only (Windows/PowerShell friendly).
 *
 * Usage: node test/make-fixtures.js  [--out <dir>]
 *
 * Zero runtime dependencies (node builtins only). CommonJS.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { parsePcap } = require('../lib/pcap');

const CRLF = '\r\n';
const OUT_DIR = (function () {
  const i = process.argv.indexOf('--out');
  if (i !== -1 && process.argv[i + 1]) return path.resolve(process.argv[i + 1]);
  return path.join(__dirname, 'fixtures');
})();

/** Fixed capture epoch: 2026-08-17T10:03:31Z, so output never drifts. */
const BASE_TS = Math.floor(Date.UTC(2026, 7, 17, 10, 3, 31) / 1000);

/* ------------------------------------------------------------------ */
/* hosts                                                               */
/* ------------------------------------------------------------------ */

const A_IP = '198.51.100.10';        // customer PBX / access side
const SBC_OUT = '203.0.113.5';       // SBC outside (public) interface
const SBC_IN = '10.20.0.5';          // SBC inside interface
const B_IP = '10.20.0.30';           // core softswitch / carrier side
const GW_IP = '203.0.113.20';        // H.323 gateway
const DNS_IP = '10.20.0.53';         // recursive resolver
const PCRF_IP = '10.20.0.9';         // Diameter Rx peer
const WEBRTC_IP = '198.51.100.77';   // browser / OTT client
const UE_IP = '10.30.0.77';          // VoLTE UE
const PCSCF_IP = '10.30.0.1';        // P-CSCF

/* ------------------------------------------------------------------ */
/* deterministic identifier helpers                                    */
/* ------------------------------------------------------------------ */

/**
 * Stable hex digest for a label (deterministic across runs).
 * @param {string} label
 * @returns {string} 32 hex chars
 */
function hex32(label) {
  return crypto.createHash('md5').update('hiccup:' + String(label)).digest('hex');
}

/**
 * RFC 3261 magic-cookie Via branch, unique per label, stable per label.
 * @param {string} label transaction label
 * @returns {string}
 */
function branch(label) {
  return 'z9hG4bK' + hex32('branch:' + label).slice(0, 16);
}

/**
 * From/To tag value, unique per label.
 * @param {string} label
 * @returns {string}
 */
function tagOf(label) {
  return hex32('tag:' + label).slice(0, 12);
}

/**
 * Call-ID value, unique per label.
 * @param {string} label
 * @param {string} host host part of the Call-ID
 * @returns {string}
 */
function callIdOf(label, host) {
  return hex32('cid:' + label).slice(0, 26) + '@' + host;
}

/**
 * Deterministic per-host MAC address (locally administered, 02:...).
 * @param {string} ip
 * @returns {Buffer} 6 bytes
 */
function macFor(ip) {
  return Buffer.from('02' + hex32('mac:' + ip).slice(0, 10), 'hex');
}

/**
 * Deterministic pseudo-random byte stream (for media payloads etc).
 * @param {string} label seed label
 * @param {number} len byte count
 * @returns {Buffer}
 */
function noise(label, len) {
  const out = Buffer.alloc(len);
  let block = crypto.createHash('md5').update('noise:' + label).digest();
  let o = 0;
  let round = 0;
  while (o < len) {
    const n = Math.min(block.length, len - o);
    block.copy(out, o, 0, n);
    o += n;
    round++;
    block = crypto.createHash('md5').update(block).update(String(round)).digest();
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* checksums                                                           */
/* ------------------------------------------------------------------ */

/**
 * Internet checksum (RFC 1071) over a buffer.
 * @param {Buffer} buf
 * @returns {number} 16-bit checksum
 */
function checksum16(buf) {
  let sum = 0;
  let i = 0;
  for (; i + 1 < buf.length; i += 2) sum += buf.readUInt16BE(i);
  if (i < buf.length) sum += buf[i] << 8;
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}

/**
 * TCP/UDP checksum over the IPv4 pseudo-header plus the L4 segment.
 * @param {string} src source IPv4 dotted quad
 * @param {string} dst destination IPv4 dotted quad
 * @param {number} proto IP protocol number (6 or 17)
 * @param {Buffer} seg the L4 segment with its checksum field zeroed
 * @returns {number} 16-bit checksum (caller substitutes 0xffff for 0 on UDP)
 */
function l4Checksum(src, dst, proto, seg) {
  const pseudo = Buffer.alloc(12);
  writeIp(pseudo, 0, src);
  writeIp(pseudo, 4, dst);
  pseudo[8] = 0;
  pseudo[9] = proto;
  pseudo.writeUInt16BE(seg.length, 10);
  return checksum16(Buffer.concat([pseudo, seg]));
}

const CRC32_TABLE = (function () {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c;
  }
  return t;
})();

/**
 * CRC-32 (IEEE 802.3) of a buffer -- used by the STUN FINGERPRINT attribute.
 * @param {Buffer} buf
 * @returns {number} unsigned 32-bit CRC
 */
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC32_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/* ------------------------------------------------------------------ */
/* L2 / L3 / L4 frame construction                                     */
/* ------------------------------------------------------------------ */

/**
 * Write a dotted-quad IPv4 address into a buffer.
 * @param {Buffer} buf
 * @param {number} off
 * @param {string} ip
 */
function writeIp(buf, off, ip) {
  const p = String(ip).split('.');
  for (let i = 0; i < 4; i++) buf[off + i] = parseInt(p[i], 10) & 0xff;
}

let ipIdCounter = 0x4000;

/**
 * Build an IPv4 packet (IHL 5, no options).
 * @param {string} src source address
 * @param {string} dst destination address
 * @param {number} proto IP protocol number
 * @param {Buffer} payload L4 bytes (or fragment slice)
 * @param {{id?: number, fragOff?: number, mf?: boolean, ttl?: number}} [opts]
 *   fragOff is a byte offset (must be a multiple of 8)
 * @returns {Buffer} the full IPv4 packet
 */
function ipv4(src, dst, proto, payload, opts) {
  const o = opts || {};
  const id = o.id === undefined ? (ipIdCounter = (ipIdCounter + 1) & 0xffff) : o.id;
  const fragOff = o.fragOff || 0;
  const h = Buffer.alloc(20);
  h[0] = 0x45;
  h[1] = 0x00;
  h.writeUInt16BE(20 + payload.length, 2);
  h.writeUInt16BE(id & 0xffff, 4);
  h.writeUInt16BE((o.mf ? 0x2000 : 0) | ((fragOff >>> 3) & 0x1fff), 6);
  h[8] = o.ttl === undefined ? 64 : o.ttl;
  h[9] = proto;
  h.writeUInt16BE(0, 10);
  writeIp(h, 12, src);
  writeIp(h, 16, dst);
  h.writeUInt16BE(checksum16(h), 10);
  return Buffer.concat([h, payload]);
}

/**
 * Build a UDP datagram with a correct IPv4 pseudo-header checksum.
 * @param {string} src source address
 * @param {string} dst destination address
 * @param {number} sport
 * @param {number} dport
 * @param {Buffer} payload
 * @returns {Buffer}
 */
function udp(src, dst, sport, dport, payload) {
  const dg = Buffer.alloc(8 + payload.length);
  dg.writeUInt16BE(sport, 0);
  dg.writeUInt16BE(dport, 2);
  dg.writeUInt16BE(8 + payload.length, 4);
  dg.writeUInt16BE(0, 6);
  payload.copy(dg, 8);
  const ck = l4Checksum(src, dst, 17, dg);
  dg.writeUInt16BE(ck === 0 ? 0xffff : ck, 6);
  return dg;
}

const TCP_FIN = 0x01;
const TCP_SYN = 0x02;
const TCP_PSH = 0x08;
const TCP_ACK = 0x10;

/**
 * Build a TCP segment (20-byte header, no options) with a real checksum.
 * @param {string} src source address
 * @param {string} dst destination address
 * @param {number} sport
 * @param {number} dport
 * @param {number} seq sequence number
 * @param {number} ack acknowledgement number
 * @param {number} flags TCP flag bits
 * @param {Buffer} payload segment payload (may be empty)
 * @param {number} [win] window size
 * @returns {Buffer}
 */
function tcp(src, dst, sport, dport, seq, ack, flags, payload, win) {
  const seg = Buffer.alloc(20 + payload.length);
  seg.writeUInt16BE(sport, 0);
  seg.writeUInt16BE(dport, 2);
  seg.writeUInt32BE(seq >>> 0, 4);
  seg.writeUInt32BE(ack >>> 0, 8);
  seg[12] = 5 << 4; // data offset 5 words, no options
  seg[13] = flags;
  seg.writeUInt16BE(win === undefined ? 64240 : win, 14);
  seg.writeUInt16BE(0, 16);
  seg.writeUInt16BE(0, 18);
  payload.copy(seg, 20);
  seg.writeUInt16BE(l4Checksum(src, dst, 6, seg), 16);
  return seg;
}

/**
 * Wrap an IP packet in an Ethernet II frame, padded to the 60-byte minimum.
 * @param {string} src source IP (selects the source MAC)
 * @param {string} dst destination IP (selects the destination MAC)
 * @param {Buffer} ipPacket
 * @returns {Buffer} the on-wire frame (no FCS, as pcap stores it)
 */
function ethFrame(src, dst, ipPacket) {
  const eth = Buffer.alloc(14);
  macFor(dst).copy(eth, 0);
  macFor(src).copy(eth, 6);
  eth.writeUInt16BE(0x0800, 12);
  let frame = Buffer.concat([eth, ipPacket]);
  if (frame.length < 60) frame = Buffer.concat([frame, Buffer.alloc(60 - frame.length)]);
  return frame;
}

/* ------------------------------------------------------------------ */
/* capture builder                                                     */
/* ------------------------------------------------------------------ */

/**
 * Create a capture accumulator.
 *
 * `frames` collects { ts, data } in insertion order (sorted by ts on write).
 * `logical` counts the L7-carrying datagrams lib/pcap.js should emit, so the
 * self-verification pass can assert an exact packet count.
 * @returns {object} capture builder
 */
function newCap() {
  const cap = {
    frames: [],
    logical: 0,

    /** Append a raw pre-built frame. */
    push(ts, src, dst, ipPacket, countsAsPacket) {
      cap.frames.push({ ts: BASE_TS + ts, data: ethFrame(src, dst, ipPacket) });
      if (countsAsPacket) cap.logical++;
      return cap;
    },

    /** One UDP datagram in one frame. */
    udp(ts, src, sport, dst, dport, payload) {
      return cap.push(ts, src, dst, ipv4(src, dst, 17, udp(src, dst, sport, dport, payload)), true);
    },

    /**
     * One UDP datagram, genuinely IPv4-fragmented into `chunk`-byte pieces
     * (chunk must be a multiple of 8). Reassembles to exactly one packet.
     */
    udpFragmented(ts, src, sport, dst, dport, payload, chunk) {
      const dg = udp(src, dst, sport, dport, payload);
      const id = (ipIdCounter = (ipIdCounter + 1) & 0xffff);
      let off = 0;
      let n = 0;
      while (off < dg.length) {
        const slice = dg.slice(off, Math.min(off + chunk, dg.length));
        const mf = off + slice.length < dg.length;
        cap.push(ts + n * 0.00002, src, dst,
          ipv4(src, dst, 17, slice, { id: id, fragOff: off, mf: mf }), false);
        off += slice.length;
        n++;
      }
      cap.logical++;
      return cap;
    },

    /** One TCP segment (payload may be empty; empty ones are not L7 packets). */
    tcp(ts, src, sport, dst, dport, seq, ack, flags, payload) {
      const pay = payload || Buffer.alloc(0);
      cap.push(ts, src, dst,
        ipv4(src, dst, 6, tcp(src, dst, sport, dport, seq, ack, flags, pay)),
        pay.length > 0);
      return cap;
    },
  };
  return cap;
}

/**
 * A TCP connection with correct per-direction sequence progression.
 * @param {object} cap capture builder
 * @param {string} aIp client address
 * @param {number} aPort client port
 * @param {string} bIp server address
 * @param {number} bPort server port
 * @param {number} isnA client initial sequence number
 * @param {number} isnB server initial sequence number
 * @returns {{handshake: function, send: function, teardown: function}}
 */
function newTcpConn(cap, aIp, aPort, bIp, bPort, isnA, isnB) {
  const ends = {
    a: { ip: aIp, port: aPort, next: isnA >>> 0 },
    b: { ip: bIp, port: bPort, next: isnB >>> 0 },
  };
  function other(which) { return which === 'a' ? ends.b : ends.a; }
  return {
    /** SYN / SYN-ACK / ACK. */
    handshake(ts) {
      const a = ends.a;
      const b = ends.b;
      cap.tcp(ts, a.ip, a.port, b.ip, b.port, a.next, 0, TCP_SYN, null);
      a.next = (a.next + 1) >>> 0;
      cap.tcp(ts + 0.0005, b.ip, b.port, a.ip, a.port, b.next, a.next, TCP_SYN | TCP_ACK, null);
      b.next = (b.next + 1) >>> 0;
      cap.tcp(ts + 0.001, a.ip, a.port, b.ip, b.port, a.next, b.next, TCP_ACK, null);
      return this;
    },
    /** One data segment from 'a' or 'b'. */
    send(ts, which, payload) {
      const from = ends[which];
      const to = other(which);
      cap.tcp(ts, from.ip, from.port, to.ip, to.port, from.next, to.next,
        TCP_PSH | TCP_ACK, payload);
      from.next = (from.next + payload.length) >>> 0;
      return this;
    },
    /** FIN / ACK / FIN / ACK, initiated by `which`. */
    teardown(ts, which) {
      const from = ends[which === 'b' ? 'b' : 'a'];
      const to = other(which === 'b' ? 'b' : 'a');
      cap.tcp(ts, from.ip, from.port, to.ip, to.port, from.next, to.next, TCP_FIN | TCP_ACK, null);
      from.next = (from.next + 1) >>> 0;
      cap.tcp(ts + 0.0005, to.ip, to.port, from.ip, from.port, to.next, from.next, TCP_ACK, null);
      cap.tcp(ts + 0.001, to.ip, to.port, from.ip, from.port, to.next, from.next, TCP_FIN | TCP_ACK, null);
      to.next = (to.next + 1) >>> 0;
      cap.tcp(ts + 0.0015, from.ip, from.port, to.ip, to.port, from.next, to.next, TCP_ACK, null);
      return this;
    },
  };
}

/* ------------------------------------------------------------------ */
/* pcap / pcapng writers                                               */
/* ------------------------------------------------------------------ */

/**
 * Encode frames as a classic little-endian pcap file (magic d4c3b2a1 on disk,
 * i.e. the standard host-endian magic 0xa1b2c3d4 written LE).
 * @param {Array<{ts: number, data: Buffer}>} frames
 * @param {{linkType?: number, snaplen?: number}} [opts]
 * @returns {Buffer}
 */
function encodePcap(frames, opts) {
  const o = opts || {};
  const linkType = o.linkType === undefined ? 1 : o.linkType;
  const gh = Buffer.alloc(24);
  gh.writeUInt32LE(0xa1b2c3d4, 0);
  gh.writeUInt16LE(2, 4);
  gh.writeUInt16LE(4, 6);
  gh.writeInt32LE(0, 8);
  gh.writeUInt32LE(0, 12);
  gh.writeUInt32LE(o.snaplen === undefined ? 262144 : o.snaplen, 16);
  gh.writeUInt32LE(linkType, 20);

  const parts = [gh];
  const sorted = frames.slice().sort((x, y) => x.ts - y.ts);
  for (const f of sorted) {
    let sec = Math.floor(f.ts);
    let usec = Math.round((f.ts - sec) * 1e6);
    if (usec >= 1e6) { sec += 1; usec -= 1e6; }
    const rh = Buffer.alloc(16);
    rh.writeUInt32LE(sec, 0);
    rh.writeUInt32LE(usec, 4);
    rh.writeUInt32LE(f.data.length, 8);
    rh.writeUInt32LE(f.data.length, 12);
    parts.push(rh, f.data);
  }
  return Buffer.concat(parts);
}

/**
 * Encode frames as a little-endian pcapng file: SHB + IDB (if_tsresol 6) + EPBs.
 * @param {Array<{ts: number, data: Buffer}>} frames
 * @param {{linkType?: number}} [opts]
 * @returns {Buffer}
 */
function encodePcapng(frames, opts) {
  const o = opts || {};
  const linkType = o.linkType === undefined ? 1 : o.linkType;
  const parts = [];

  // Section Header Block (28 bytes, no options).
  const shb = Buffer.alloc(28);
  shb.writeUInt32LE(0x0a0d0d0a, 0);
  shb.writeUInt32LE(28, 4);
  shb.writeUInt32LE(0x1a2b3c4d, 8);
  shb.writeUInt16LE(1, 12);
  shb.writeUInt16LE(0, 14);
  shb.writeUInt32LE(0xffffffff, 16); // section length -1 (unknown)
  shb.writeUInt32LE(0xffffffff, 20);
  shb.writeUInt32LE(28, 24);
  parts.push(shb);

  // Interface Description Block with if_tsresol = 6 (microseconds).
  const idb = Buffer.alloc(32);
  idb.writeUInt32LE(0x00000001, 0);
  idb.writeUInt32LE(32, 4);
  idb.writeUInt16LE(linkType, 8);
  idb.writeUInt16LE(0, 10);
  idb.writeUInt32LE(262144, 12);
  idb.writeUInt16LE(9, 16);  // opt code: if_tsresol
  idb.writeUInt16LE(1, 18);  // opt length
  idb[20] = 6;               // 10^-6 seconds
  idb.writeUInt16LE(0, 24);  // opt_endofopt
  idb.writeUInt16LE(0, 26);
  idb.writeUInt32LE(32, 28);
  parts.push(idb);

  const sorted = frames.slice().sort((x, y) => x.ts - y.ts);
  for (const f of sorted) {
    const pad = (4 - (f.data.length % 4)) % 4;
    const total = 32 + f.data.length + pad;
    const b = Buffer.alloc(total);
    b.writeUInt32LE(0x00000006, 0);
    b.writeUInt32LE(total, 4);
    b.writeUInt32LE(0, 8); // interface id
    const us = Math.round(f.ts * 1e6);
    b.writeUInt32LE(Math.floor(us / 4294967296), 12);
    b.writeUInt32LE(us % 4294967296, 16);
    b.writeUInt32LE(f.data.length, 20);
    b.writeUInt32LE(f.data.length, 24);
    f.data.copy(b, 28);
    b.writeUInt32LE(total, total - 4);
    parts.push(b);
  }
  return Buffer.concat(parts);
}

/* ------------------------------------------------------------------ */
/* SIP / SDP builders                                                  */
/* ------------------------------------------------------------------ */

/**
 * Assemble a SIP message with a correct Content-Length (bytes of the CRLF body).
 * @param {string} startLine request-line or status-line
 * @param {Array<Array<string>>} headers [name, value] pairs, in wire order
 * @param {string} [body] body text (already CRLF-terminated)
 * @param {string} [contentType] Content-Type value (added before Content-Length)
 * @returns {string} the full message text
 */
function sipMsg(startLine, headers, body, contentType) {
  const b = body || '';
  const hdrs = headers.slice();
  if (contentType) hdrs.push(['Content-Type', contentType]);
  hdrs.push(['Content-Length', String(Buffer.byteLength(b, 'latin1'))]);
  const head = hdrs.map((h) => h[0] + ': ' + h[1]).join(CRLF);
  return startLine + CRLF + head + CRLF + CRLF + b;
}

/**
 * Join SDP lines with CRLF and terminate the last line.
 * @param {string[]} arr
 * @returns {string}
 */
function sdpBody(arr) {
  return arr.join(CRLF) + CRLF;
}

/**
 * Convert SIP text to its on-wire bytes (latin1 keeps binary bodies intact).
 * @param {string} text
 * @returns {Buffer}
 */
function wire(text) {
  return Buffer.from(text, 'latin1');
}

/**
 * RFC 3261 retransmission offsets.
 * @param {number} n number of transmissions (the first is at offset 0)
 * @param {{cap?: number}} [opts] cap the interval at T2 (default 4s); pass
 *   {cap: Infinity} for the pure doubling INVITE ladder that reaches Timer B.
 * @returns {number[]} cumulative offsets in seconds
 */
function backoff(n, opts) {
  const capAt = opts && opts.cap !== undefined ? opts.cap : 4;
  const out = [0];
  let interval = 0.5;
  let t = 0;
  for (let i = 1; i < n; i++) {
    t += interval;
    out.push(Math.round(t * 1000) / 1000);
    interval = Math.min(interval * 2, capAt);
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* fixture registry                                                    */
/* ------------------------------------------------------------------ */

const FIXTURES = [];   // { name, file, expect, cap?, format }
const TEXT_FILES = []; // { file, text } (non-capture: HMR configs, KB guide)

/**
 * Register a pcap/pcapng capture fixture.
 * @param {object} spec { name, file, cap, expect, pcapng? }
 */
function addCapture(spec) {
  FIXTURES.push({
    name: spec.name,
    file: spec.file,
    cap: spec.cap,
    pcapng: !!spec.pcapng,
    expect: spec.expect,
  });
}

/**
 * Register a text-log capture fixture (already-rendered text).
 * @param {object} spec { name, file, text, expect }
 */
function addTextCapture(spec) {
  FIXTURES.push({
    name: spec.name,
    file: spec.file,
    text: spec.text,
    expect: spec.expect,
  });
}

/**
 * Render a name-addr with an optional tag: '"Bob" <sip:b@x>;tag=abc'.
 * @param {string|null} name display name (omitted when falsy)
 * @param {string} uri SIP URI
 * @param {string|null} [tag] tag parameter value
 * @returns {string}
 */
function nameAddr(name, uri, tag) {
  return (name ? '"' + name + '" ' : '') + '<' + uri + '>' + (tag ? ';tag=' + tag : '');
}

/**
 * A Via header value for one hop.
 * @param {string} ip sent-by host
 * @param {number} port sent-by port
 * @param {string} br branch parameter
 * @param {string} [transport] UDP (default) / TCP
 * @returns {string}
 */
function via(ip, port, br, transport) {
  return 'SIP/2.0/' + (transport || 'UDP') + ' ' + ip + ':' + port + ';branch=' + br;
}

/**
 * Create a one-leg SIP dialog renderer.
 *
 * The "caller" side is `src`; requests flow src -> dst and responses back.
 * Both directions render with the caller's Via, as the wire requires.
 *
 * @param {object} o leg description
 * @param {string} o.callId Call-ID value
 * @param {string} o.fromUri From URI
 * @param {string} o.fromTag From tag
 * @param {string} o.toUri To URI
 * @param {string} o.toTag To tag (used once the dialog is established)
 * @param {string} [o.fromName] From display name
 * @param {string} [o.toName] To display name
 * @param {string} o.srcIp caller address
 * @param {number} o.srcPort caller port
 * @param {string} o.dstIp callee address
 * @param {number} o.dstPort callee port
 * @param {string} o.contact caller Contact URI
 * @param {string} [o.transport] 'UDP' (default) or 'TCP' for Via/Contact
 * @returns {object} renderer with req()/res() helpers
 */
function newLeg(o) {
  const transport = o.transport || 'UDP';
  return {
    o: o,
    /**
     * Render a request from the caller side.
     * @param {string} method
     * @param {string} ruri Request-URI
     * @param {number} cseq CSeq number
     * @param {string} br top Via branch
     * @param {object} [opts] { toTag, extra, body, ctype, maxf, contact,
     *                          viaExtra, fromTagOverride }
     * @returns {string}
     */
    req(method, ruri, cseq, br, opts) {
      const p = opts || {};
      const hdrs = [
        ['Via', via(o.srcIp, o.srcPort, br, transport) + (p.viaExtra || '')],
      ];
      for (const v of (p.moreVias || [])) hdrs.push(['Via', v]);
      hdrs.push(
        ['Max-Forwards', String(p.maxf === undefined ? 70 : p.maxf)],
        ['From', nameAddr(o.fromName, o.fromUri, p.fromTagOverride || o.fromTag)],
        ['To', nameAddr(o.toName, o.toUri, p.toTag ? o.toTag : null)],
        ['Call-ID', o.callId],
        ['CSeq', cseq + ' ' + method]
      );
      if (p.contact !== false) hdrs.push(['Contact', '<' + o.contact + '>']);
      for (const h of (p.extra || [])) hdrs.push(h);
      return sipMsg(method + ' ' + ruri + ' SIP/2.0', hdrs, p.body, p.ctype);
    },
    /**
     * Render a response travelling back towards the caller.
     * @param {number} status
     * @param {string} reason
     * @param {number} cseq CSeq number
     * @param {string} cseqMethod CSeq method
     * @param {string} br the transaction's Via branch
     * @param {object} [opts] { toTag, extra, body, ctype, contact }
     * @returns {string}
     */
    res(status, reason, cseq, cseqMethod, br, opts) {
      const p = opts || {};
      const hdrs = [
        ['Via', via(o.srcIp, o.srcPort, br, transport)],
        ['From', nameAddr(o.fromName, o.fromUri, o.fromTag)],
        ['To', nameAddr(o.toName, o.toUri, p.toTag === false ? null : o.toTag)],
        ['Call-ID', o.callId],
        ['CSeq', cseq + ' ' + cseqMethod],
      ];
      if (p.contact) hdrs.push(['Contact', '<' + p.contact + '>']);
      for (const h of (p.extra || [])) hdrs.push(h);
      return sipMsg('SIP/2.0 ' + status + ' ' + reason, hdrs, p.body, p.ctype);
    },
  };
}

/**
 * Turn SIP events into a UDP capture.
 * @param {Array<{ts: number, src: string, sport: number, dst: string,
 *   dport: number, text: string}>} events
 * @returns {object} capture builder
 */
function sipEventsToCap(events) {
  const cap = newCap();
  for (const e of events) cap.udp(e.ts, e.src, e.sport, e.dst, e.dport, wire(e.text));
  return cap;
}

/* ================================================================== */
/* 1. basic-call -- clean A -> SBC -> B call, both legs                */
/* ================================================================== */

const BASIC_ICID = 'icid-value=hiccup7f3a91c2;orig-ioi=pbx.example.com';

/**
 * The canonical two-leg SBC call used by basic-call.pcap, pcapng-call.pcapng
 * and sbc-log.txt. Carries every diff category the contract asks for:
 * X-Internal-Cause stripped, P-Asserted-Identity added, From user rewritten,
 * codec list narrowed (PCMU/PCMA/G729 -> PCMU/G729), transcoding forced
 * (PCMU answered in, G729 answered out), DTMF 101 -> 96, ptime 20 -> 30,
 * 100rel required in / absent out, Session-Expires 1800;uac vs 900;uas with
 * Min-SE 1200 > 900 (a real 422 hazard), 183+SDP out vs 180 in, and a
 * private 192.168.10.20 in the SDP o= line surviving into egress.
 * @returns {Array<object>} SIP events in timestamp order
 */
function buildBasicCallEvents() {
  const inLeg = newLeg({
    callId: callIdOf('basic-in', 'pbx.example.com'),
    fromName: 'Alice', fromUri: 'sip:+33123456789@pbx.example.com',
    fromTag: tagOf('basic-in-f'),
    toUri: 'sip:+33987654321@sbc.example.net', toTag: tagOf('basic-in-t'),
    srcIp: A_IP, srcPort: 5060, dstIp: SBC_OUT, dstPort: 5060,
    contact: 'sip:+33123456789@' + A_IP + ':5060',
  });
  const egLeg = newLeg({
    callId: callIdOf('basic-eg', 'sbc.example.net'),
    fromUri: 'sip:+33900000123@sbc.example.net',
    fromTag: tagOf('basic-eg-f'),
    toUri: 'sip:+33987654321@core.example.net', toTag: tagOf('basic-eg-t'),
    srcIp: SBC_IN, srcPort: 5060, dstIp: B_IP, dstPort: 5060,
    contact: 'sip:+33900000123@' + SBC_IN + ':5060',
  });

  const inInviteBr = branch('basic-in-inv');
  const inAckBr = branch('basic-in-ack');
  const inByeBr = branch('basic-in-bye');
  const egInviteBr = branch('basic-eg-inv');
  const egAckBr = branch('basic-eg-ack');
  const egByeBr = branch('basic-eg-bye');

  const inOffer = sdpBody([
    'v=0',
    'o=- 8000001 1 IN IP4 192.168.10.20',
    's=-',
    'c=IN IP4 ' + A_IP,
    't=0 0',
    'm=audio 40000 RTP/AVP 0 8 18 101',
    'a=rtpmap:0 PCMU/8000',
    'a=rtpmap:8 PCMA/8000',
    'a=rtpmap:18 G729/8000',
    'a=fmtp:18 annexb=no',
    'a=rtpmap:101 telephone-event/8000',
    'a=fmtp:101 0-16',
    'a=ptime:20',
    'a=sendrecv',
  ]);
  const egOffer = sdpBody([
    'v=0',
    'o=- 8000001 1 IN IP4 192.168.10.20',
    's=-',
    'c=IN IP4 ' + SBC_IN,
    't=0 0',
    'm=audio 20000 RTP/AVP 0 18 96',
    'a=rtpmap:0 PCMU/8000',
    'a=rtpmap:18 G729/8000',
    'a=fmtp:18 annexb=no',
    'a=rtpmap:96 telephone-event/8000',
    'a=fmtp:96 0-16',
    'a=ptime:30',
    'a=sendrecv',
  ]);
  const egAnswer = sdpBody([
    'v=0',
    'o=core 5551212 1 IN IP4 ' + B_IP,
    's=-',
    'c=IN IP4 ' + B_IP,
    't=0 0',
    'm=audio 30000 RTP/AVP 18 96',
    'a=rtpmap:18 G729/8000',
    'a=fmtp:18 annexb=no',
    'a=rtpmap:96 telephone-event/8000',
    'a=ptime:30',
    'a=sendrecv',
  ]);
  const inAnswer = sdpBody([
    'v=0',
    'o=sbc 7770001 1 IN IP4 ' + SBC_OUT,
    's=-',
    'c=IN IP4 ' + SBC_OUT,
    't=0 0',
    'm=audio 21000 RTP/AVP 0 101',
    'a=rtpmap:0 PCMU/8000',
    'a=rtpmap:101 telephone-event/8000',
    'a=ptime:20',
    'a=sendrecv',
  ]);

  const A = { ip: A_IP, port: 5060 };
  const SO = { ip: SBC_OUT, port: 5060 };
  const SI = { ip: SBC_IN, port: 5060 };
  const B = { ip: B_IP, port: 5060 };
  const ev = [];
  function push(ts, from, to, text) {
    ev.push({ ts: ts, src: from.ip, sport: from.port, dst: to.ip, dport: to.port, text: text });
  }

  push(0.000, A, SO, inLeg.req('INVITE', 'sip:+33987654321@' + SBC_OUT, 1, inInviteBr, {
    body: inOffer, ctype: 'application/sdp',
    extra: [
      ['Allow', 'INVITE, ACK, CANCEL, BYE, OPTIONS, PRACK, UPDATE, REFER, INFO'],
      ['Supported', '100rel, timer'],
      ['Require', '100rel'],
      ['Session-Expires', '1800;refresher=uac'],
      ['Min-SE', '1200'],
      ['P-Charging-Vector', BASIC_ICID],
      ['X-Internal-Cause', 'route-select=trunk-a; attempt=1'],
      ['User-Agent', 'Asterisk PBX 18.9.0'],
    ],
  }));
  push(0.010, SO, A, inLeg.res(100, 'Trying', 1, 'INVITE', inInviteBr, { toTag: false }));
  push(0.030, SI, B, egLeg.req('INVITE', 'sip:+33987654321@' + B_IP, 1, egInviteBr, {
    maxf: 69,
    body: egOffer, ctype: 'application/sdp',
    extra: [
      ['Allow', 'INVITE, ACK, CANCEL, BYE, OPTIONS, PRACK, UPDATE, REFER, INFO'],
      ['Supported', 'timer'],
      ['Session-Expires', '900;refresher=uas'],
      ['Min-SE', '900'],
      ['P-Asserted-Identity', '<sip:+33123456789@sbc.example.net>'],
      ['P-Charging-Vector', BASIC_ICID + ';term-ioi=core.example.net'],
      ['User-Agent', 'OracleSBC/8.4.0'],
    ],
  }));
  push(0.045, B, SI, egLeg.res(100, 'Trying', 1, 'INVITE', egInviteBr, { toTag: false }));
  push(0.400, B, SI, egLeg.res(183, 'Session Progress', 1, 'INVITE', egInviteBr, {
    body: egAnswer, ctype: 'application/sdp',
    contact: 'sip:+33987654321@' + B_IP + ':5060',
    extra: [['Server', 'CoreSwitch/6.2']],
  }));
  push(0.500, SO, A, inLeg.res(180, 'Ringing', 1, 'INVITE', inInviteBr, {
    contact: 'sip:+33987654321@' + SBC_OUT + ':5060',
  }));
  push(1.200, B, SI, egLeg.res(200, 'OK', 1, 'INVITE', egInviteBr, {
    body: egAnswer, ctype: 'application/sdp',
    contact: 'sip:+33987654321@' + B_IP + ':5060',
    extra: [['Server', 'CoreSwitch/6.2'], ['Session-Expires', '900;refresher=uas']],
  }));
  push(1.220, SO, A, inLeg.res(200, 'OK', 1, 'INVITE', inInviteBr, {
    body: inAnswer, ctype: 'application/sdp',
    contact: 'sip:+33987654321@' + SBC_OUT + ':5060',
    extra: [['Session-Expires', '1800;refresher=uac'], ['Require', 'timer']],
  }));
  push(1.230, A, SO, inLeg.req('ACK', 'sip:+33987654321@' + SBC_OUT + ':5060', 1, inAckBr, {
    toTag: true, maxf: 70,
  }));
  push(1.240, SI, B, egLeg.req('ACK', 'sip:+33987654321@' + B_IP + ':5060', 1, egAckBr, {
    toTag: true, maxf: 69,
  }));
  push(11.000, A, SO, inLeg.req('BYE', 'sip:+33987654321@' + SBC_OUT + ':5060', 2, inByeBr, {
    toTag: true, contact: false,
    extra: [['Reason', 'Q.850;cause=16;text="Normal call clearing"']],
  }));
  push(11.010, SI, B, egLeg.req('BYE', 'sip:+33987654321@' + B_IP + ':5060', 2, egByeBr, {
    toTag: true, maxf: 69, contact: false,
    extra: [['Reason', 'Q.850;cause=16;text="Normal call clearing"']],
  }));
  push(11.030, B, SI, egLeg.res(200, 'OK', 2, 'BYE', egByeBr, { toTag: true }));
  push(11.040, SO, A, inLeg.res(200, 'OK', 2, 'BYE', inByeBr, { toTag: true }));

  ev.sort((x, y) => x.ts - y.ts);
  return ev;
}

const BASIC_DIFF_TAGS = [
  'header-stripped', 'header-added', 'header-rewritten', 'from-rewritten',
  'codec-narrowed', 'codec-transcoding', 'ptime-mismatch', 'dtmf-pt-mismatch',
  '100rel-asymmetry', 'session-timer-changed', 'session-timer-conflict',
  'early-media-183', 'private-ip-leak',
];

const BASIC_EXPECT = {
  sipMessages: 14,
  h323Messages: 0,
  legs: 2,
  calls: 1,
  callStates: { paired: 1 },
  callTypes: { 'sip-sip': 1 },
  diffTags: BASIC_DIFF_TAGS,
  findingsInclude: [{ severity: 'crit', category: 'diff' }],
  indicatorsOn: ['sip', 'dtmf-rfc4733', 'session-timers', 'topology-hiding'],
  adviceTitlesInclude: ['topology'],
};

let BASIC_EVENTS = null; // the shared two-leg call, reused by the text fixtures

(function registerBasicCall() {
  const events = buildBasicCallEvents();
  addCapture({
    name: 'basic-call',
    file: 'basic-call.pcap',
    cap: sipEventsToCap(events),
    expect: Object.assign({ format: 'pcap' }, BASIC_EXPECT),
  });
  addCapture({
    name: 'pcapng-call',
    file: 'pcapng-call.pcapng',
    cap: sipEventsToCap(events),
    pcapng: true,
    expect: Object.assign({ format: 'pcapng' }, BASIC_EXPECT),
  });
  BASIC_EVENTS = events;
})();

/* ================================================================== */
/* 2. timer-b -- INVITE x7, zero responses, runs into Timer B          */
/* ================================================================== */

(function registerTimerB() {
  const leg = newLeg({
    callId: callIdOf('timerb', 'pbx.example.com'),
    fromName: 'Alice', fromUri: 'sip:+33123456789@pbx.example.com',
    fromTag: tagOf('timerb-f'),
    toUri: 'sip:+33987654321@sbc.example.net', toTag: tagOf('timerb-t'),
    srcIp: A_IP, srcPort: 5060, dstIp: SBC_OUT, dstPort: 5060,
    contact: 'sip:+33123456789@' + A_IP + ':5060',
  });
  const br = branch('timerb-inv');
  const text = leg.req('INVITE', 'sip:+33987654321@' + SBC_OUT, 1, br, {
    body: sdpBody([
      'v=0', 'o=- 9100001 1 IN IP4 ' + A_IP, 's=-', 'c=IN IP4 ' + A_IP, 't=0 0',
      'm=audio 40100 RTP/AVP 0 101', 'a=rtpmap:0 PCMU/8000',
      'a=rtpmap:101 telephone-event/8000', 'a=ptime:20', 'a=sendrecv',
    ]),
    ctype: 'application/sdp',
    extra: [['Supported', 'timer'], ['User-Agent', 'Asterisk PBX 18.9.0']],
  });
  // Uncapped INVITE ladder (Timer A doubles): 0, .5, 1.5, 3.5, 7.5, 15.5, 31.5
  // so the run spans 31.5s and the classifier can call Timer B.
  const offsets = backoff(7, { cap: Infinity });
  const cap = newCap();
  for (const t of offsets) cap.udp(t, A_IP, 5060, SBC_OUT, 5060, wire(text));
  addCapture({
    name: 'timer-b',
    file: 'timer-b.pcap',
    cap: cap,
    expect: {
      format: 'pcap',
      sipMessages: 7, h323Messages: 0, legs: 1, calls: 1,
      callStates: { unpaired: 1 }, callTypes: { single: 1 },
      retransCodes: ['never-arrived'],
      findingsInclude: [{ severity: 'crit', category: 'retrans' }],
      mediaStreams: 0,
      indicatorsOn: ['sip'],
      adviceTitlesInclude: ['Timer B'],
    },
  });
})();

/* ================================================================== */
/* 3. late-response -- INVITE x3 then 100/180/200 at ~2.4s             */
/* ================================================================== */

(function registerLateResponse() {
  const leg = newLeg({
    callId: callIdOf('late', 'pbx.example.com'),
    fromName: 'Alice', fromUri: 'sip:+33123456789@pbx.example.com',
    fromTag: tagOf('late-f'),
    toUri: 'sip:+33987654321@sbc.example.net', toTag: tagOf('late-t'),
    srcIp: A_IP, srcPort: 5060, dstIp: SBC_OUT, dstPort: 5060,
    contact: 'sip:+33123456789@' + A_IP + ':5060',
  });
  const invBr = branch('late-inv');
  const ackBr = branch('late-ack');
  const byeBr = branch('late-bye');
  const offer = sdpBody([
    'v=0', 'o=- 9200001 1 IN IP4 ' + A_IP, 's=-', 'c=IN IP4 ' + A_IP, 't=0 0',
    'm=audio 40200 RTP/AVP 0 101', 'a=rtpmap:0 PCMU/8000',
    'a=rtpmap:101 telephone-event/8000', 'a=ptime:20', 'a=sendrecv',
  ]);
  const answer = sdpBody([
    'v=0', 'o=sbc 7772001 1 IN IP4 ' + SBC_OUT, 's=-', 'c=IN IP4 ' + SBC_OUT, 't=0 0',
    'm=audio 21200 RTP/AVP 0 101', 'a=rtpmap:0 PCMU/8000',
    'a=rtpmap:101 telephone-event/8000', 'a=ptime:20', 'a=sendrecv',
  ]);
  const invite = leg.req('INVITE', 'sip:+33987654321@' + SBC_OUT, 1, invBr, {
    body: offer, ctype: 'application/sdp',
    extra: [['Supported', 'timer'], ['User-Agent', 'Asterisk PBX 18.9.0']],
  });
  const cap = newCap();
  for (const t of backoff(3)) cap.udp(t, A_IP, 5060, SBC_OUT, 5060, wire(invite));
  const A = [A_IP, 5060];
  const S = [SBC_OUT, 5060];
  cap.udp(2.400, S[0], S[1], A[0], A[1], wire(leg.res(100, 'Trying', 1, 'INVITE', invBr, { toTag: false })));
  cap.udp(2.600, S[0], S[1], A[0], A[1], wire(leg.res(180, 'Ringing', 1, 'INVITE', invBr, {
    contact: 'sip:+33987654321@' + SBC_OUT + ':5060',
  })));
  cap.udp(3.500, S[0], S[1], A[0], A[1], wire(leg.res(200, 'OK', 1, 'INVITE', invBr, {
    body: answer, ctype: 'application/sdp',
    contact: 'sip:+33987654321@' + SBC_OUT + ':5060',
  })));
  cap.udp(3.520, A[0], A[1], S[0], S[1], wire(leg.req('ACK', 'sip:+33987654321@' + SBC_OUT + ':5060', 1, ackBr, { toTag: true })));
  cap.udp(20.000, A[0], A[1], S[0], S[1], wire(leg.req('BYE', 'sip:+33987654321@' + SBC_OUT + ':5060', 2, byeBr, { toTag: true, contact: false })));
  cap.udp(20.020, S[0], S[1], A[0], A[1], wire(leg.res(200, 'OK', 2, 'BYE', byeBr, { toTag: true })));
  addCapture({
    name: 'late-response',
    file: 'late-response.pcap',
    cap: cap,
    expect: {
      format: 'pcap',
      sipMessages: 9, h323Messages: 0, legs: 1, calls: 1,
      callStates: { unpaired: 1 },
      retransCodes: ['slow-far-end'],
      findingsInclude: [{ severity: 'warn', category: 'retrans' }],
      indicatorsOn: ['sip'],
    },
  });
})();

/* ================================================================== */
/* 4. big-invite -- 1450-byte UDP INVITE, no response (+ fragmented)   */
/* ================================================================== */

(function registerBigInvite() {
  const leg = newLeg({
    callId: callIdOf('big', 'pbx.example.com'),
    fromName: 'Alice', fromUri: 'sip:+33123456789@pbx.example.com',
    fromTag: tagOf('big-f'),
    toUri: 'sip:+33987654321@sbc.example.net', toTag: tagOf('big-t'),
    srcIp: A_IP, srcPort: 5060, dstIp: SBC_OUT, dstPort: 5060,
    contact: 'sip:+33123456789@' + A_IP + ':5060',
  });
  const br = branch('big-inv');
  const offer = sdpBody([
    'v=0', 'o=- 9300001 1 IN IP4 ' + A_IP, 's=-', 'c=IN IP4 ' + A_IP, 't=0 0',
    'm=audio 40300 RTP/AVP 0 8 9 18 4 3 101',
    'a=rtpmap:0 PCMU/8000', 'a=rtpmap:8 PCMA/8000', 'a=rtpmap:9 G722/8000',
    'a=rtpmap:18 G729/8000', 'a=fmtp:18 annexb=no', 'a=rtpmap:4 G723/8000',
    'a=rtpmap:3 GSM/8000', 'a=rtpmap:101 telephone-event/8000',
    'a=fmtp:101 0-16', 'a=ptime:20', 'a=maxptime:150', 'a=sendrecv',
  ]);

  // Real-world bloat: a long History-Info chain (a queue/hunt-group trail).
  function build(pad) {
    const hi = [];
    for (let i = 1; i <= 5; i++) {
      hi.push(['History-Info',
        '<sip:+3380012345' + i + '@queue.example.com?Reason=SIP%3Bcause%3D302>;index=1.' + i +
        ';rc=' + i]);
    }
    hi.push(['History-Info',
      '<sip:+33987654321@queue.example.com?Reason=SIP%3Bcause%3D302%3Btext%3D%22' +
      'overflow' + pad + '%22>;index=1.6']);
    return leg.req('INVITE', 'sip:+33987654321@' + SBC_OUT, 1, br, {
      body: offer, ctype: 'application/sdp',
      extra: [
        ['Allow', 'INVITE, ACK, CANCEL, BYE, OPTIONS, PRACK, UPDATE, REFER, INFO, NOTIFY, MESSAGE'],
        ['Supported', '100rel, timer, replaces, from-change, histinfo'],
        ['Session-Expires', '1800;refresher=uac'],
        ['Min-SE', '90'],
        ['P-Asserted-Identity', '"Alice Example" <sip:+33123456789@pbx.example.com>'],
        ['Diversion', '<sip:+33800123450@queue.example.com>;reason=no-answer;counter=1'],
      ].concat(hi).concat([['User-Agent', 'Asterisk PBX 18.9.0 (bloated-histinfo build)']]),
    });
  }
  let text = build('');
  const grow = 1450 - Buffer.byteLength(text, 'latin1');
  if (grow < 0) throw new Error('big-invite base is already ' + (-grow) + ' bytes over 1450');
  text = build('x'.repeat(grow));
  const size = Buffer.byteLength(text, 'latin1');
  if (size !== 1450) throw new Error('big-invite came out ' + size + ' bytes, wanted 1450');

  const offsets = backoff(4);
  const plain = newCap();
  for (const t of offsets) plain.udp(t, A_IP, 5060, SBC_OUT, 5060, wire(text));
  const fragged = newCap();
  // 1458-byte datagram split at 1000/458 -- offset 1000 is a multiple of 8.
  for (const t of offsets) fragged.udpFragmented(t, A_IP, 5060, SBC_OUT, 5060, wire(text), 1000);

  const expect = {
    format: 'pcap',
    sipMessages: 4, h323Messages: 0, legs: 1, calls: 1,
    callStates: { unpaired: 1 },
    retransCodes: ['udp-fragmentation'],
    findingsInclude: [{ severity: 'crit', category: 'retrans' }],
    indicatorsOn: ['sip'],
    adviceTitlesInclude: ['fragment'],
  };
  addCapture({ name: 'big-invite', file: 'big-invite.pcap', cap: plain, expect: expect });
  addCapture({
    name: 'big-invite-frags', file: 'big-invite-frags.pcap', cap: fragged,
    expect: Object.assign({}, expect),
  });
})();

/* ================================================================== */
/* 5. ack-lost -- call answers, 200 OK x6, no ACK ever seen            */
/* ================================================================== */

(function registerAckLost() {
  const leg = newLeg({
    callId: callIdOf('acklost', 'pbx.example.com'),
    fromName: 'Alice', fromUri: 'sip:+33123456789@pbx.example.com',
    fromTag: tagOf('acklost-f'),
    toUri: 'sip:+33987654321@sbc.example.net', toTag: tagOf('acklost-t'),
    srcIp: A_IP, srcPort: 5060, dstIp: SBC_OUT, dstPort: 5060,
    contact: 'sip:+33123456789@' + A_IP + ':5060',
  });
  const invBr = branch('acklost-inv');
  const cap = newCap();
  cap.udp(0.000, A_IP, 5060, SBC_OUT, 5060, wire(leg.req('INVITE', 'sip:+33987654321@' + SBC_OUT, 1, invBr, {
    body: sdpBody([
      'v=0', 'o=- 9400001 1 IN IP4 ' + A_IP, 's=-', 'c=IN IP4 ' + A_IP, 't=0 0',
      'm=audio 40400 RTP/AVP 0 101', 'a=rtpmap:0 PCMU/8000',
      'a=rtpmap:101 telephone-event/8000', 'a=ptime:20', 'a=sendrecv',
    ]),
    ctype: 'application/sdp',
    extra: [['Supported', 'timer'], ['User-Agent', 'Asterisk PBX 18.9.0']],
  })));
  cap.udp(0.010, SBC_OUT, 5060, A_IP, 5060, wire(leg.res(100, 'Trying', 1, 'INVITE', invBr, { toTag: false })));
  cap.udp(0.300, SBC_OUT, 5060, A_IP, 5060, wire(leg.res(180, 'Ringing', 1, 'INVITE', invBr, {
    contact: 'sip:+33987654321@' + SBC_OUT + ':5060',
  })));
  // The far end's 200 OK is Contact'd at an address our ACK cannot reach, so it
  // keeps retransmitting on the RFC 3261 ladder and no ACK ever appears.
  const ok = leg.res(200, 'OK', 1, 'INVITE', invBr, {
    body: sdpBody([
      'v=0', 'o=sbc 7774001 1 IN IP4 ' + SBC_OUT, 's=-', 'c=IN IP4 ' + SBC_OUT, 't=0 0',
      'm=audio 21400 RTP/AVP 0 101', 'a=rtpmap:0 PCMU/8000',
      'a=rtpmap:101 telephone-event/8000', 'a=ptime:20', 'a=sendrecv',
    ]),
    ctype: 'application/sdp',
    contact: 'sip:+33987654321@10.99.99.99:5060',
  });
  for (const t of backoff(6)) cap.udp(1.000 + t, SBC_OUT, 5060, A_IP, 5060, wire(ok));
  addCapture({
    name: 'ack-lost',
    file: 'ack-lost.pcap',
    cap: cap,
    expect: {
      format: 'pcap',
      sipMessages: 9, h323Messages: 0, legs: 1, calls: 1,
      callStates: { unpaired: 1 },
      retransCodes: ['ack-not-landing'],
      findingsInclude: [{ severity: 'crit', category: 'retrans' }],
      indicatorsOn: ['sip'],
      adviceTitlesInclude: ['ACK'],
    },
  });
})();

/* ================================================================== */
/* 6. storm -- 8 concurrent legs all retransmitting in the same 2s     */
/* ================================================================== */

(function registerStorm() {
  const cap = newCap();
  for (let i = 0; i < 8; i++) {
    const from = '+3361000000' + i;
    const to = '+3390000000' + i;
    const leg = newLeg({
      callId: callIdOf('storm-' + i, 'pbx.example.com'),
      fromUri: 'sip:' + from + '@pbx.example.com', fromTag: tagOf('storm-f-' + i),
      toUri: 'sip:' + to + '@sbc.example.net', toTag: tagOf('storm-t-' + i),
      srcIp: A_IP, srcPort: 5060, dstIp: SBC_OUT, dstPort: 5060,
      contact: 'sip:' + from + '@' + A_IP + ':5060',
    });
    const br = branch('storm-inv-' + i);
    const text = leg.req('INVITE', 'sip:' + to + '@' + SBC_OUT, 1, br, {
      body: sdpBody([
        'v=0', 'o=- 950000' + i + ' 1 IN IP4 ' + A_IP, 's=-', 'c=IN IP4 ' + A_IP, 't=0 0',
        'm=audio ' + (41000 + i * 2) + ' RTP/AVP 0 101', 'a=rtpmap:0 PCMU/8000',
        'a=rtpmap:101 telephone-event/8000', 'a=ptime:20', 'a=sendrecv',
      ]),
      ctype: 'application/sdp',
      extra: [['Supported', 'timer'], ['User-Agent', 'Asterisk PBX 18.9.0']],
    });
    for (const t of backoff(3)) cap.udp(i * 0.05 + t, A_IP, 5060, SBC_OUT, 5060, wire(text));
  }
  addCapture({
    name: 'storm',
    file: 'storm.pcap',
    cap: cap,
    expect: {
      format: 'pcap',
      sipMessages: 24, h323Messages: 0, legs: 8, calls: 8,
      callStates: { unpaired: 8 },
      retransCodes: ['box-wide-storm'],
      findingsInclude: [{ severity: 'crit', category: 'retrans' }],
      indicatorsOn: ['sip'],
    },
  });
})();

/* ================================================================== */
/* 7. ambiguous -- two identical ingress calls, one visible egress leg */
/* ================================================================== */

(function registerAmbiguous() {
  // Two simultaneous ingress INVITEs carrying the SAME From/To users and the
  // same SDP o= session id, and one egress INVITE that could belong to either.
  // Timing is deliberate: each ingress leg scores >= 0.5 against the egress leg
  // and the two scores sit inside correlate.js's 0.15 ambiguity margin, while
  // ingress-vs-ingress stays under the 0.5 pairing threshold. The contract says
  // refuse to guess -- so the egress leg must come out `ambiguous`.
  const cap = newCap();
  const offer = (port) => sdpBody([
    'v=0', 'o=- 5550001 1 IN IP4 ' + A_IP, 's=-', 'c=IN IP4 ' + A_IP, 't=0 0',
    'm=audio ' + port + ' RTP/AVP 0 101', 'a=rtpmap:0 PCMU/8000',
    'a=rtpmap:101 telephone-event/8000', 'a=ptime:20', 'a=sendrecv',
  ]);

  function ingress(idx, ts, port) {
    const leg = newLeg({
      callId: callIdOf('amb-in-' + idx, 'pbx.example.com'),
      fromUri: 'sip:+33123456789@pbx.example.com', fromTag: tagOf('amb-in-f-' + idx),
      toUri: 'sip:+33987654321@sbc.example.net', toTag: tagOf('amb-in-t-' + idx),
      srcIp: A_IP, srcPort: 5060, dstIp: SBC_OUT, dstPort: 5060,
      contact: 'sip:+33123456789@' + A_IP + ':5060',
    });
    const br = branch('amb-in-inv-' + idx);
    cap.udp(ts, A_IP, 5060, SBC_OUT, 5060, wire(leg.req('INVITE', 'sip:+33987654321@' + SBC_OUT, 1, br, {
      body: offer(port), ctype: 'application/sdp',
      extra: [['Supported', 'timer'], ['User-Agent', 'Asterisk PBX 18.9.0']],
    })));
    cap.udp(ts + 0.005, SBC_OUT, 5060, A_IP, 5060, wire(leg.res(100, 'Trying', 1, 'INVITE', br, { toTag: false })));
    cap.udp(ts + 0.180, SBC_OUT, 5060, A_IP, 5060, wire(leg.res(180, 'Ringing', 1, 'INVITE', br, {
      contact: 'sip:+33987654321@' + SBC_OUT + ':5060',
    })));
  }
  ingress(1, 0.000, 42000);
  ingress(2, 0.100, 42002);

  const egLeg = newLeg({
    callId: callIdOf('amb-eg', 'sbc.example.net'),
    fromUri: 'sip:+33123456789@sbc.example.net', fromTag: tagOf('amb-eg-f'),
    toUri: 'sip:+33987654321@core.example.net', toTag: tagOf('amb-eg-t'),
    srcIp: SBC_IN, srcPort: 5060, dstIp: B_IP, dstPort: 5060,
    contact: 'sip:+33123456789@' + SBC_IN + ':5060',
  });
  const egBr = branch('amb-eg-inv');
  cap.udp(0.140, SBC_IN, 5060, B_IP, 5060, wire(egLeg.req('INVITE', 'sip:+33987654321@' + B_IP, 1, egBr, {
    maxf: 69,
    body: sdpBody([
      'v=0', 'o=- 5550001 1 IN IP4 ' + SBC_IN, 's=-', 'c=IN IP4 ' + SBC_IN, 't=0 0',
      'm=audio 22000 RTP/AVP 0 101', 'a=rtpmap:0 PCMU/8000',
      'a=rtpmap:101 telephone-event/8000', 'a=ptime:20', 'a=sendrecv',
    ]),
    ctype: 'application/sdp',
    extra: [['Supported', 'timer'], ['User-Agent', 'OracleSBC/8.4.0']],
  })));
  cap.udp(0.150, B_IP, 5060, SBC_IN, 5060, wire(egLeg.res(100, 'Trying', 1, 'INVITE', egBr, { toTag: false })));

  addCapture({
    name: 'ambiguous',
    file: 'ambiguous.pcap',
    cap: cap,
    expect: {
      format: 'pcap',
      sipMessages: 8, h323Messages: 0, legs: 3, calls: 3,
      callStates: { ambiguous: 1, unpaired: 2, paired: 0 },
      callTypes: { 'sip-sip': 1, single: 2 },
      findingsInclude: [{ severity: 'notice', category: 'correlation' }],
      indicatorsOn: ['sip'],
    },
  });
})();

/* ================================================================== */
/* 8. tcp-call -- SIP over TCP, split and coalesced segments           */
/* ================================================================== */

(function registerTcpCall() {
  const leg = newLeg({
    callId: callIdOf('tcpcall', 'pbx.example.com'),
    fromName: 'Alice', fromUri: 'sip:+33123456789@pbx.example.com',
    fromTag: tagOf('tcpcall-f'),
    toUri: 'sip:+33987654321@sbc.example.net', toTag: tagOf('tcpcall-t'),
    srcIp: A_IP, srcPort: 51234, dstIp: SBC_OUT, dstPort: 5060,
    contact: 'sip:+33123456789@' + A_IP + ':51234;transport=tcp',
    transport: 'TCP',
  });
  const invBr = branch('tcpcall-inv');
  const ackBr = branch('tcpcall-ack');
  const byeBr = branch('tcpcall-bye');
  const invite = leg.req('INVITE', 'sip:+33987654321@' + SBC_OUT + ';transport=tcp', 1, invBr, {
    body: sdpBody([
      'v=0', 'o=- 9600001 1 IN IP4 ' + A_IP, 's=-', 'c=IN IP4 ' + A_IP, 't=0 0',
      'm=audio 40600 RTP/AVP 0 8 101', 'a=rtpmap:0 PCMU/8000', 'a=rtpmap:8 PCMA/8000',
      'a=rtpmap:101 telephone-event/8000', 'a=fmtp:101 0-16', 'a=ptime:20', 'a=sendrecv',
    ]),
    ctype: 'application/sdp',
    extra: [['Supported', 'timer'], ['User-Agent', 'Asterisk PBX 18.9.0']],
  });
  const trying = leg.res(100, 'Trying', 1, 'INVITE', invBr, { toTag: false });
  const ringing = leg.res(180, 'Ringing', 1, 'INVITE', invBr, {
    contact: 'sip:+33987654321@' + SBC_OUT + ':5060;transport=tcp',
  });
  const ok = leg.res(200, 'OK', 1, 'INVITE', invBr, {
    body: sdpBody([
      'v=0', 'o=sbc 7776001 1 IN IP4 ' + SBC_OUT, 's=-', 'c=IN IP4 ' + SBC_OUT, 't=0 0',
      'm=audio 21600 RTP/AVP 0 101', 'a=rtpmap:0 PCMU/8000',
      'a=rtpmap:101 telephone-event/8000', 'a=ptime:20', 'a=sendrecv',
    ]),
    ctype: 'application/sdp',
    contact: 'sip:+33987654321@' + SBC_OUT + ':5060;transport=tcp',
  });
  const ack = leg.req('ACK', 'sip:+33987654321@' + SBC_OUT + ':5060;transport=tcp', 1, ackBr, { toTag: true });
  const bye = leg.req('BYE', 'sip:+33987654321@' + SBC_OUT + ':5060;transport=tcp', 2, byeBr, {
    toTag: true, contact: false,
  });
  const byeOk = leg.res(200, 'OK', 2, 'BYE', byeBr, { toTag: true });

  const cap = newCap();
  const conn = newTcpConn(cap, A_IP, 51234, SBC_OUT, 5060, 1000, 5000);
  conn.handshake(0.000);
  const invBuf = wire(invite);
  const splitAt = 400;
  conn.send(0.010, 'a', invBuf.slice(0, splitAt));            // message split ...
  conn.send(0.030, 'a', invBuf.slice(splitAt));               // ... across two segments
  conn.send(0.050, 'b', wire(trying + ringing));              // two messages coalesced
  conn.send(1.000, 'b', wire(ok));
  conn.send(1.020, 'a', wire(ack));
  conn.send(9.000, 'a', wire(bye));
  conn.send(9.020, 'b', wire(byeOk));
  conn.teardown(9.100, 'a');

  addCapture({
    name: 'tcp-call',
    file: 'tcp-call.pcap',
    cap: cap,
    expect: {
      format: 'pcap',
      sipMessages: 7, h323Messages: 0, legs: 1, calls: 1,
      callStates: { unpaired: 1 },
      indicatorsOn: ['sip', 'tcp-transport'],
    },
  });
})();

/* ================================================================== */
/* 9. register-auth -- 401 Digest challenge then authorized REGISTER   */
/* ================================================================== */

const DIGEST_RESPONSE = 'd41d8cd98f00b204e9800998ecf8427e';
const DIGEST_CNONCE = '0a4f113b9d5c7e21';

(function registerRegisterAuth() {
  const leg = newLeg({
    callId: callIdOf('reg', 'pbx.example.com'),
    fromUri: 'sip:+33123456789@example.net', fromTag: tagOf('reg-f'),
    toUri: 'sip:+33123456789@example.net', toTag: tagOf('reg-t'),
    srcIp: A_IP, srcPort: 5060, dstIp: SBC_OUT, dstPort: 5060,
    contact: 'sip:+33123456789@' + A_IP + ':5060',
  });
  const br1 = branch('reg-1');
  const br2 = branch('reg-2');
  const nonce = '4f3a2b1c9d8e7f6055aa3311';
  const cap = newCap();

  cap.udp(0.000, A_IP, 5060, SBC_OUT, 5060, wire(leg.req('REGISTER', 'sip:example.net', 1, br1, {
    contact: false,
    extra: [
      ['Contact', '<sip:+33123456789@' + A_IP + ':5060>;+sip.instance="<urn:uuid:8f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f>"'],
      ['Expires', '3600'],
      ['Supported', 'path, outbound'],
      ['User-Agent', 'PolycomVVX-VVX_450-UA/6.4.0'],
    ],
  })));
  cap.udp(0.008, SBC_OUT, 5060, A_IP, 5060, wire(leg.res(401, 'Unauthorized', 1, 'REGISTER', br1, {
    toTag: true,
    extra: [
      ['WWW-Authenticate', 'Digest realm="example.net", nonce="' + nonce +
        '", opaque="6b1f0c99", qop="auth", algorithm=MD5'],
      ['Server', 'OracleSBC/8.4.0'],
    ],
  })));
  cap.udp(0.030, A_IP, 5060, SBC_OUT, 5060, wire(leg.req('REGISTER', 'sip:example.net', 2, br2, {
    contact: false,
    extra: [
      ['Contact', '<sip:+33123456789@' + A_IP + ':5060>;+sip.instance="<urn:uuid:8f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f>"'],
      ['Expires', '3600'],
      ['Supported', 'path, outbound'],
      ['Authorization', 'Digest username="+33123456789", realm="example.net", nonce="' + nonce +
        '", uri="sip:example.net", response="' + DIGEST_RESPONSE + '", cnonce="' + DIGEST_CNONCE +
        '", nc=00000001, qop=auth, algorithm=MD5'],
      ['User-Agent', 'PolycomVVX-VVX_450-UA/6.4.0'],
    ],
  })));
  cap.udp(0.042, SBC_OUT, 5060, A_IP, 5060, wire(leg.res(200, 'OK', 2, 'REGISTER', br2, {
    toTag: true,
    extra: [
      ['Contact', '<sip:+33123456789@' + A_IP + ':5060>;expires=3600'],
      ['Path', '<sip:term@' + SBC_OUT + ';lr>'],
      ['Service-Route', '<sip:orig@scscf.example.net;lr>'],
      ['P-Associated-URI', '<sip:+33123456789@example.net>, <tel:+33123456789>'],
      ['Expires', '3600'],
      ['Server', 'OracleSBC/8.4.0'],
    ],
  })));

  addCapture({
    name: 'register-auth',
    file: 'register-auth.pcap',
    cap: cap,
    expect: {
      format: 'pcap',
      sipMessages: 4, h323Messages: 0, legs: 1, calls: 0,
      absentStrings: [DIGEST_RESPONSE, DIGEST_CNONCE],
      indicatorsOn: ['sip', 'registration', 'ims'],
    },
  });
})();

/* ------------------------------------------------------------------ */
/* H.225 / Q.931 over TPKT                                             */
/* ------------------------------------------------------------------ */

const Q931_SETUP = 0x05;
const Q931_CALL_PROCEEDING = 0x02;
const Q931_ALERTING = 0x01;
const Q931_CONNECT = 0x07;
const Q931_RELEASE_COMPLETE = 0x5a;

/**
 * Encode one variable-length Q.931 information element.
 * @param {number} id IE identifier
 * @param {Buffer} value IE value bytes
 * @returns {Buffer}
 */
function q931Ie(id, value) {
  return Buffer.concat([Buffer.from([id, value.length]), value]);
}

/**
 * Called Party Number IE (0x70): octet 3 = ext|type|plan, then IA5 digits.
 * @param {string} digits
 * @returns {Buffer}
 */
function calledPartyIe(digits) {
  return q931Ie(0x70, Buffer.concat([Buffer.from([0x81]), Buffer.from(digits, 'ascii')]));
}

/**
 * Calling Party Number IE (0x6C): octet 3 (ext=0) + octet 3a (ext=1), digits.
 * Exercises the ext-bit walk in lib/h323.js's number decoder.
 * @param {string} digits
 * @returns {Buffer}
 */
function callingPartyIe(digits) {
  return q931Ie(0x6c, Buffer.concat([Buffer.from([0x21, 0x80]), Buffer.from(digits, 'ascii')]));
}

/**
 * Cause IE (0x08): coding/location octet then the cause value.
 * @param {number} cause Q.850 cause value
 * @returns {Buffer}
 */
function causeIe(cause) {
  return q931Ie(0x08, Buffer.from([0x84, 0x80 | (cause & 0x7f)]));
}

/**
 * User-User IE (0x7E) carrying a synthetic H.225 UUIE blob.
 * The ASN.1 body is NOT decoded by hiccup (by contract), so this is a
 * plausible byte pattern: the H.225.0 protocolIdentifier OID encoding, a
 * 0x10-prefixed 16-byte callIdentifier, and optionally OpenLogicalChannel
 * markers so the fastStart heuristic can fire.
 * @param {string} guidHex 32 hex chars
 * @param {boolean} fastStart include OLC-looking markers
 * @returns {Buffer}
 */
function userUserIe(guidHex, fastStart) {
  const head = Buffer.from([0x20, 0xa0, 0x06, 0x00, 0x08, 0x91, 0x4a, 0x00, 0x04]);
  const guid = Buffer.concat([Buffer.from([0x10]), Buffer.from(guidHex, 'hex')]);
  const olc = fastStart
    ? Buffer.from([0x41, 0x42, 0x43, 0x44, 0x01, 0x00, 0x0e, 0x60, 0x13, 0x80, 0x0b, 0x80])
    : Buffer.from([0x01, 0x00, 0x05, 0x61]);
  const tail = Buffer.from([0x11, 0x00]);
  return q931Ie(0x7e, Buffer.concat([Buffer.from([0x05]), head, guid, olc, tail]));
}

/**
 * Frame a Q.931 message inside a TPKT header (03 00 len).
 * @param {number} msgType Q.931 message type octet
 * @param {number} callRef call reference value (15 bits)
 * @param {number} flag call reference flag (0 = from the allocating side)
 * @param {Array<Buffer>} ies information elements, in order
 * @returns {Buffer} TPKT + Q.931 bytes
 */
function tpktQ931(msgType, callRef, flag, ies) {
  const cr = Buffer.alloc(2);
  cr.writeUInt16BE(callRef & 0x7fff, 0);
  if (flag) cr[0] |= 0x80;
  const q = Buffer.concat([Buffer.from([0x08, 0x02]), cr, Buffer.from([msgType])].concat(ies));
  const tpkt = Buffer.alloc(4);
  tpkt[0] = 0x03;
  tpkt[1] = 0x00;
  tpkt.writeUInt16BE(4 + q.length, 2);
  return Buffer.concat([tpkt, q]);
}

/**
 * Emit a complete five-message H.323 call segment on TCP 1720.
 * @param {object} cap capture builder
 * @param {number} t0 start offset in seconds
 * @param {string} callerIp originating endpoint
 * @param {number} callerPort originating TCP port
 * @param {string} gwIp gateway address (port 1720)
 * @param {number} callRef call reference
 * @param {string} calling calling party digits
 * @param {string} called called party digits
 * @param {string} guidHex 32 hex chars for the callIdentifier
 */
function h323CallSegment(cap, t0, callerIp, callerPort, gwIp, callRef, calling, called, guidHex) {
  const conn = newTcpConn(cap, callerIp, callerPort, gwIp, 1720, 0x20000, 0x30000);
  conn.handshake(t0);
  conn.send(t0 + 0.010, 'a', tpktQ931(Q931_SETUP, callRef, 0, [
    q931Ie(0x04, Buffer.from([0x88, 0x18, 0x01])),      // Bearer capability
    callingPartyIe(calling),
    calledPartyIe(called),
    q931Ie(0x28, Buffer.from('Alice Example', 'ascii')), // Display
    userUserIe(guidHex, true),
  ]));
  conn.send(t0 + 0.060, 'b', tpktQ931(Q931_CALL_PROCEEDING, callRef, 1, [
    userUserIe(guidHex, false),
  ]));
  conn.send(t0 + 0.400, 'b', tpktQ931(Q931_ALERTING, callRef, 1, [
    userUserIe(guidHex, false),
  ]));
  conn.send(t0 + 3.200, 'b', tpktQ931(Q931_CONNECT, callRef, 1, [
    userUserIe(guidHex, true),
  ]));
  conn.send(t0 + 18.000, 'a', tpktQ931(Q931_RELEASE_COMPLETE, callRef, 0, [
    causeIe(16),
    userUserIe(guidHex, false),
  ]));
  conn.teardown(t0 + 18.100, 'a');
}

/* ================================================================== */
/* 10. h323-call -- TPKT/Q.931 SETUP .. RELEASE COMPLETE (cause 16)    */
/* ================================================================== */

(function registerH323Call() {
  const cap = newCap();
  h323CallSegment(cap, 0.000, A_IP, 53211, GW_IP, 0x1234,
    '+33612345678', '+33987654321', hex32('h323-guid').slice(0, 32));
  addCapture({
    name: 'h323-call',
    file: 'h323-call.pcap',
    cap: cap,
    expect: {
      format: 'pcap',
      sipMessages: 0, h323Messages: 5, legs: 1, calls: 1,
      callStates: { unpaired: 1 }, callTypes: { single: 1 },
      indicatorsOn: ['h323'],
    },
  });
})();

/* ================================================================== */
/* 11. iwf-call -- H.323 ingress + SIP egress, one sip-h323 call        */
/* ================================================================== */

(function registerIwfCall() {
  const cap = newCap();
  const guid = hex32('iwf-guid').slice(0, 32);
  h323CallSegment(cap, 0.000, A_IP, 53400, GW_IP, 0x2a01,
    '+33612345678', '+33987654321', guid);

  // The IWF turns the SETUP into an INVITE 200ms later, same numbers.
  const leg = newLeg({
    callId: callIdOf('iwf-eg', 'iwf.example.net'),
    fromUri: 'sip:+33612345678@iwf.example.net', fromTag: tagOf('iwf-eg-f'),
    toUri: 'sip:+33987654321@core.example.net', toTag: tagOf('iwf-eg-t'),
    srcIp: SBC_IN, srcPort: 5060, dstIp: B_IP, dstPort: 5060,
    contact: 'sip:+33612345678@' + SBC_IN + ':5060',
  });
  const invBr = branch('iwf-inv');
  const ackBr = branch('iwf-ack');
  const byeBr = branch('iwf-bye');
  const offer = sdpBody([
    'v=0', 'o=iwf 9700001 1 IN IP4 ' + SBC_IN, 's=-', 'c=IN IP4 ' + SBC_IN, 't=0 0',
    'm=audio 23000 RTP/AVP 0 101', 'a=rtpmap:0 PCMU/8000',
    'a=rtpmap:101 telephone-event/8000', 'a=ptime:20', 'a=sendrecv',
  ]);
  const answer = sdpBody([
    'v=0', 'o=core 5551313 1 IN IP4 ' + B_IP, 's=-', 'c=IN IP4 ' + B_IP, 't=0 0',
    'm=audio 33000 RTP/AVP 0 101', 'a=rtpmap:0 PCMU/8000',
    'a=rtpmap:101 telephone-event/8000', 'a=ptime:20', 'a=sendrecv',
  ]);
  cap.udp(0.210, SBC_IN, 5060, B_IP, 5060, wire(leg.req('INVITE', 'sip:+33987654321@' + B_IP, 1, invBr, {
    body: offer, ctype: 'application/sdp',
    extra: [
      ['Supported', 'timer'],
      ['User-Agent', 'OracleSBC-IWF/8.4.0'],
      ['X-H323-Call-Id', guid],
    ],
  })));
  cap.udp(0.225, B_IP, 5060, SBC_IN, 5060, wire(leg.res(100, 'Trying', 1, 'INVITE', invBr, { toTag: false })));
  cap.udp(0.500, B_IP, 5060, SBC_IN, 5060, wire(leg.res(180, 'Ringing', 1, 'INVITE', invBr, {
    contact: 'sip:+33987654321@' + B_IP + ':5060',
  })));
  cap.udp(3.180, B_IP, 5060, SBC_IN, 5060, wire(leg.res(200, 'OK', 1, 'INVITE', invBr, {
    body: answer, ctype: 'application/sdp', contact: 'sip:+33987654321@' + B_IP + ':5060',
  })));
  cap.udp(3.200, SBC_IN, 5060, B_IP, 5060, wire(leg.req('ACK', 'sip:+33987654321@' + B_IP + ':5060', 1, ackBr, { toTag: true })));
  cap.udp(18.010, SBC_IN, 5060, B_IP, 5060, wire(leg.req('BYE', 'sip:+33987654321@' + B_IP + ':5060', 2, byeBr, {
    toTag: true, contact: false,
    extra: [['Reason', 'Q.850;cause=16;text="Normal call clearing"']],
  })));
  cap.udp(18.030, B_IP, 5060, SBC_IN, 5060, wire(leg.res(200, 'OK', 2, 'BYE', byeBr, { toTag: true })));

  addCapture({
    name: 'iwf-call',
    file: 'iwf-call.pcap',
    cap: cap,
    expect: {
      format: 'pcap',
      sipMessages: 7, h323Messages: 5, legs: 2, calls: 1,
      callStates: { paired: 1 }, callTypes: { 'sip-h323': 1 },
      findingsInclude: [{ severity: 'info', category: 'correlation' }],
      indicatorsOn: ['sip', 'h323', 'iwf'],
    },
  });
})();

/* ------------------------------------------------------------------ */
/* small binary helpers                                                */
/* ------------------------------------------------------------------ */

/** @param {number} n @returns {Buffer} 2 big-endian bytes */
function u16be(n) { const b = Buffer.alloc(2); b.writeUInt16BE(n & 0xffff, 0); return b; }
/** @param {number} n @returns {Buffer} 4 big-endian bytes */
function u32be(n) { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0, 0); return b; }

/* ------------------------------------------------------------------ */
/* RTP / RTCP                                                          */
/* ------------------------------------------------------------------ */

/**
 * Build an RTP packet (version 2, no padding/extension/CSRCs).
 * @param {number} pt payload type
 * @param {number} seq sequence number
 * @param {number} ts RTP timestamp
 * @param {number} ssrc synchronization source
 * @param {boolean} marker marker bit
 * @param {Buffer} payload
 * @returns {Buffer}
 */
function rtpPacket(pt, seq, ts, ssrc, marker, payload) {
  const h = Buffer.alloc(12);
  h[0] = 0x80;
  h[1] = (marker ? 0x80 : 0) | (pt & 0x7f);
  h.writeUInt16BE(seq & 0xffff, 2);
  h.writeUInt32BE(ts >>> 0, 4);
  h.writeUInt32BE(ssrc >>> 0, 8);
  return Buffer.concat([h, payload]);
}

/**
 * Wrap an RTCP body in a packet header.
 * @param {number} pt RTCP payload type (200 SR, 201 RR, 202 SDES)
 * @param {number} rc report/source count
 * @param {Buffer} body
 * @returns {Buffer}
 */
function rtcpPack(pt, rc, body) {
  const h = Buffer.alloc(4);
  h[0] = 0x80 | (rc & 0x1f);
  h[1] = pt & 0xff;
  h.writeUInt16BE(((4 + body.length) / 4) - 1, 2);
  return Buffer.concat([h, body]);
}

/**
 * NTP-format timestamp parts for an epoch-seconds value.
 * @param {number} ts epoch seconds
 * @returns {{sec: number, frac: number}}
 */
function ntpParts(ts) {
  const sec = Math.floor(ts) + 2208988800;
  const frac = Math.floor((ts - Math.floor(ts)) * 4294967296);
  return { sec: sec >>> 0, frac: frac >>> 0 };
}

/**
 * An RTCP receiver report block.
 * @param {object} o { ssrc, fractionLost, cumLost, extHighSeq, jitter, lsr, dlsr }
 * @returns {Buffer} 24 bytes
 */
function rtcpReportBlock(o) {
  const b = Buffer.alloc(24);
  b.writeUInt32BE(o.ssrc >>> 0, 0);
  b[4] = o.fractionLost & 0xff;
  b.writeUIntBE(o.cumLost & 0xffffff, 5, 3);
  b.writeUInt32BE(o.extHighSeq >>> 0, 8);
  b.writeUInt32BE(o.jitter >>> 0, 12);
  b.writeUInt32BE(o.lsr >>> 0, 16);
  b.writeUInt32BE(o.dlsr >>> 0, 20);
  return b;
}

/**
 * RTCP Sender Report.
 * @param {number} ssrc sender SSRC
 * @param {number} wallTs epoch seconds for the NTP field
 * @param {number} rtpTs matching RTP timestamp
 * @param {number} pkts packets sent
 * @param {number} octets octets sent
 * @param {Array<Buffer>} blocks report blocks
 * @returns {Buffer}
 */
function rtcpSr(ssrc, wallTs, rtpTs, pkts, octets, blocks) {
  const ntp = ntpParts(wallTs);
  const body = Buffer.alloc(24);
  body.writeUInt32BE(ssrc >>> 0, 0);
  body.writeUInt32BE(ntp.sec, 4);
  body.writeUInt32BE(ntp.frac, 8);
  body.writeUInt32BE(rtpTs >>> 0, 12);
  body.writeUInt32BE(pkts >>> 0, 16);
  body.writeUInt32BE(octets >>> 0, 20);
  return rtcpPack(200, blocks.length, Buffer.concat([body].concat(blocks)));
}

/**
 * RTCP Receiver Report.
 * @param {number} ssrc reporter SSRC
 * @param {Array<Buffer>} blocks report blocks
 * @returns {Buffer}
 */
function rtcpRr(ssrc, blocks) {
  return rtcpPack(201, blocks.length, Buffer.concat([u32be(ssrc)].concat(blocks)));
}

/**
 * RTCP SDES with a single CNAME item.
 * @param {number} ssrc
 * @param {string} cname
 * @returns {Buffer}
 */
function rtcpSdes(ssrc, cname) {
  const item = Buffer.concat([Buffer.from([0x01, cname.length]), Buffer.from(cname, 'ascii')]);
  let chunk = Buffer.concat([u32be(ssrc), item, Buffer.from([0x00])]);
  const pad = (4 - (chunk.length % 4)) % 4;
  if (pad) chunk = Buffer.concat([chunk, Buffer.alloc(pad)]);
  return rtcpPack(202, 1, chunk);
}

/* ================================================================== */
/* 12. rtp-loss -- real RTP streams with loss, a 300ms gap, and RTCP    */
/* ================================================================== */

(function registerRtpLoss() {
  const cap = newCap();
  const A_RTP = 40000;
  const S_RTP = 41000;
  const SSRC_A = 0x1a2b3c4d;
  const SSRC_S = 0x5f6e7d8c;

  const leg = newLeg({
    callId: callIdOf('rtploss', 'pbx.example.com'),
    fromName: 'Alice', fromUri: 'sip:+33123456789@pbx.example.com',
    fromTag: tagOf('rtploss-f'),
    toUri: 'sip:+33987654321@sbc.example.net', toTag: tagOf('rtploss-t'),
    srcIp: A_IP, srcPort: 5060, dstIp: SBC_OUT, dstPort: 5060,
    contact: 'sip:+33123456789@' + A_IP + ':5060',
  });
  const invBr = branch('rtploss-inv');
  const ackBr = branch('rtploss-ack');
  const byeBr = branch('rtploss-bye');
  cap.udp(0.000, A_IP, 5060, SBC_OUT, 5060, wire(leg.req('INVITE', 'sip:+33987654321@' + SBC_OUT, 1, invBr, {
    body: sdpBody([
      'v=0', 'o=- 9800001 1 IN IP4 ' + A_IP, 's=-', 'c=IN IP4 ' + A_IP, 't=0 0',
      'm=audio ' + A_RTP + ' RTP/AVP 0 101', 'a=rtpmap:0 PCMU/8000',
      'a=rtpmap:101 telephone-event/8000', 'a=fmtp:101 0-16', 'a=ptime:20', 'a=sendrecv',
    ]),
    ctype: 'application/sdp',
    extra: [['Supported', 'timer'], ['User-Agent', 'Asterisk PBX 18.9.0']],
  })));
  cap.udp(0.010, SBC_OUT, 5060, A_IP, 5060, wire(leg.res(100, 'Trying', 1, 'INVITE', invBr, { toTag: false })));
  cap.udp(0.300, SBC_OUT, 5060, A_IP, 5060, wire(leg.res(180, 'Ringing', 1, 'INVITE', invBr, {
    contact: 'sip:+33987654321@' + SBC_OUT + ':5060',
  })));
  cap.udp(1.200, SBC_OUT, 5060, A_IP, 5060, wire(leg.res(200, 'OK', 1, 'INVITE', invBr, {
    body: sdpBody([
      'v=0', 'o=sbc 7778001 1 IN IP4 ' + SBC_OUT, 's=-', 'c=IN IP4 ' + SBC_OUT, 't=0 0',
      'm=audio ' + S_RTP + ' RTP/AVP 0 101', 'a=rtpmap:0 PCMU/8000',
      'a=rtpmap:101 telephone-event/8000', 'a=ptime:20', 'a=sendrecv',
    ]),
    ctype: 'application/sdp',
    contact: 'sip:+33987654321@' + SBC_OUT + ':5060',
  })));
  cap.udp(1.220, A_IP, 5060, SBC_OUT, 5060, wire(leg.req('ACK', 'sip:+33987654321@' + SBC_OUT + ':5060', 1, ackBr, { toTag: true })));

  // 8s of G.711 at 20ms: 400 packets each way.
  // A -> SBC loses 8 scattered packets (2%).
  // SBC -> A loses 15 consecutive packets around t=5s (a 300ms black hole).
  const START = 1.300;
  const N = 400;
  const SCATTERED = [37, 88, 131, 190, 233, 291, 344, 388];
  const GAP_START = 185;   // packet index; 185 * 20ms = 3.7s into the stream
  const GAP_LEN = 15;
  for (let i = 0; i < N; i++) {
    const ts = START + i * 0.020;
    const rtpTs = 160000 + i * 160;
    if (SCATTERED.indexOf(i) === -1) {
      cap.udp(ts, A_IP, A_RTP, SBC_OUT, S_RTP,
        rtpPacket(0, 1000 + i, rtpTs, SSRC_A, i === 0, noise('rtp-a-' + i, 160)));
    }
    if (i < GAP_START || i >= GAP_START + GAP_LEN) {
      cap.udp(ts + 0.004, SBC_OUT, S_RTP, A_IP, A_RTP,
        rtpPacket(0, 2000 + i, 320000 + i * 160, SSRC_S, i === 0, noise('rtp-s-' + i, 160)));
    }
  }

  // RTCP at +2s and +6s from each side (SR + SDES compound).
  function rtcpPair(t, fromIp, fromPort, toIp, toPort, ssrc, peerSsrc, rtpTs, pkts, frac, cum, highSeq, cname) {
    const compound = Buffer.concat([
      rtcpSr(ssrc, BASE_TS + t, rtpTs, pkts, pkts * 160, [rtcpReportBlock({
        ssrc: peerSsrc, fractionLost: frac, cumLost: cum, extHighSeq: highSeq,
        jitter: 42, lsr: 0xb1c2d3e4, dlsr: 3200,
      })]),
      rtcpSdes(ssrc, cname),
    ]);
    cap.udp(t, fromIp, fromPort, toIp, toPort, compound);
  }
  rtcpPair(3.300, A_IP, A_RTP + 1, SBC_OUT, S_RTP + 1, SSRC_A, SSRC_S, 176000, 100, 0, 0, 2100, 'alice@pbx.example.com');
  rtcpPair(3.320, SBC_OUT, S_RTP + 1, A_IP, A_RTP + 1, SSRC_S, SSRC_A, 336000, 100, 5, 2, 1100, 'sbc@sbc.example.net');
  rtcpPair(7.300, A_IP, A_RTP + 1, SBC_OUT, S_RTP + 1, SSRC_A, SSRC_S, 208000, 300, 38, 15, 2300, 'alice@pbx.example.com');
  rtcpPair(7.320, SBC_OUT, S_RTP + 1, A_IP, A_RTP + 1, SSRC_S, SSRC_A, 368000, 300, 13, 8, 1300, 'sbc@sbc.example.net');

  cap.udp(9.400, A_IP, 5060, SBC_OUT, 5060, wire(leg.req('BYE', 'sip:+33987654321@' + SBC_OUT + ':5060', 2, byeBr, {
    toTag: true, contact: false,
  })));
  cap.udp(9.420, SBC_OUT, 5060, A_IP, 5060, wire(leg.res(200, 'OK', 2, 'BYE', byeBr, { toTag: true })));

  addCapture({
    name: 'rtp-loss',
    file: 'rtp-loss.pcap',
    cap: cap,
    expect: {
      format: 'pcap',
      sipMessages: 7, h323Messages: 0, legs: 1, calls: 1,
      callStates: { unpaired: 1 },
      mediaStreams: 2,
      indicatorsOn: ['sip', 'rtp', 'rtcp'],
    },
  });
})();

/* ------------------------------------------------------------------ */
/* ISUP (ITU-T Q.763) for SIP-I                                        */
/* ------------------------------------------------------------------ */

/**
 * BCD-encode a digit string, two digits per octet, low nibble first.
 * @param {string} digits
 * @returns {Buffer}
 */
function isupBcd(digits) {
  const d = String(digits).replace(/[^0-9]/g, '');
  const out = Buffer.alloc(Math.ceil(d.length / 2));
  for (let i = 0; i < d.length; i++) {
    const v = d.charCodeAt(i) - 48;
    if (i % 2 === 0) out[i >> 1] = v;
    else out[i >> 1] |= v << 4;
  }
  return out;
}

/**
 * ISUP number parameter value: NAI octet (odd/even flag in bit 8), NPI octet,
 * then BCD digits.
 * @param {string} digits E.164 digits
 * @param {number} nai nature of address indicator (4 = international)
 * @param {number} npiOctet second octet (numbering plan / presentation bits)
 * @returns {Buffer}
 */
function isupNumber(digits, nai, npiOctet) {
  const d = String(digits).replace(/[^0-9]/g, '');
  const odd = (d.length % 2) === 1 ? 0x80 : 0x00;
  return Buffer.concat([Buffer.from([odd | (nai & 0x7f), npiOctet]), isupBcd(d)]);
}

/**
 * Encode an ISUP Initial Address Message (IAM) as carried in a SIP-I body.
 * Mandatory fixed part, one mandatory variable parameter (Called Party Number)
 * and one optional parameter (Calling Party Number).
 * @param {string} called called party digits
 * @param {string} calling calling party digits
 * @returns {Buffer}
 */
function isupIam(called, calling) {
  const cpn = isupNumber(called, 4, 0x10);          // international, ISDN plan
  const cgn = isupNumber(calling, 4, 0x11);         // + presentation allowed / user provided
  const fixed = Buffer.from([
    0x01,        // message type: IAM
    0x00,        // nature of connection indicators
    0x60, 0x01,  // forward call indicators
    0x0a,        // calling party's category: ordinary subscriber
    0x00,        // transmission medium requirement: speech
  ]);
  const ptrCpn = 2;
  const ptrOpt = 2 + 1 + cpn.length;
  return Buffer.concat([
    fixed,
    Buffer.from([ptrCpn, ptrOpt]),
    Buffer.from([cpn.length]), cpn,
    Buffer.from([0x0a, cgn.length]), cgn,   // optional: Calling Party Number
    Buffer.from([0x00]),                    // end of optional parameters
  ]);
}

/**
 * Encode an ISUP Release (REL) message with a Cause Indicators parameter.
 * @param {number} cause Q.850 cause value
 * @returns {Buffer}
 */
function isupRel(cause) {
  const causeVal = Buffer.from([0x84, 0x80 | (cause & 0x7f)]);
  const ptrOpt = 2 + causeVal.length;
  return Buffer.concat([
    Buffer.from([0x0c]),                 // message type: REL
    Buffer.from([2, ptrOpt]),
    Buffer.from([causeVal.length]), causeVal,
    Buffer.from([0x00]),
  ]);
}

/**
 * Encode an ISUP Answer Message (ANM), no optional parameters.
 * @returns {Buffer}
 */
function isupAnm() {
  return Buffer.from([0x09, 0x02, 0x00]);
}

/**
 * Assemble a multipart/mixed body from parts.
 * @param {string} boundary boundary token
 * @param {Array<{headers: Array<Array<string>>, body: string}>} parts
 * @returns {string} latin1 text of the body
 */
function multipart(boundary, parts) {
  let out = '';
  for (const p of parts) {
    out += '--' + boundary + CRLF;
    for (const h of p.headers) out += h[0] + ': ' + h[1] + CRLF;
    out += CRLF + p.body + CRLF;
  }
  out += '--' + boundary + '--' + CRLF;
  return out;
}

/* ================================================================== */
/* 13. sipi-call -- multipart SDP + ISUP IAM, and a REL with cause 16   */
/* ================================================================== */

(function registerSipiCall() {
  const BOUNDARY = 'uniqueBoundary';
  const leg = newLeg({
    callId: callIdOf('sipi', 'tandem.carrier.example'),
    fromUri: 'sip:+33612345678@tandem.carrier.example', fromTag: tagOf('sipi-f'),
    toUri: 'sip:+33987654321@transit.example.net', toTag: tagOf('sipi-t'),
    srcIp: A_IP, srcPort: 5060, dstIp: SBC_OUT, dstPort: 5060,
    contact: 'sip:+33612345678@' + A_IP + ':5060',
  });
  const invBr = branch('sipi-inv');
  const ackBr = branch('sipi-ack');
  const byeBr = branch('sipi-bye');
  const sdp = sdpBody([
    'v=0', 'o=- 9900001 1 IN IP4 ' + A_IP, 's=-', 'c=IN IP4 ' + A_IP, 't=0 0',
    'm=audio 40900 RTP/AVP 8 18', 'a=rtpmap:8 PCMA/8000', 'a=rtpmap:18 G729/8000',
    'a=ptime:20', 'a=sendrecv',
  ]);
  const answerSdp = sdpBody([
    'v=0', 'o=- 5551515 1 IN IP4 ' + SBC_OUT, 's=-', 'c=IN IP4 ' + SBC_OUT, 't=0 0',
    'm=audio 21900 RTP/AVP 8', 'a=rtpmap:8 PCMA/8000', 'a=ptime:20', 'a=sendrecv',
  ]);
  const iamBytes = isupIam('33987654321', '33612345678');
  const relBytes = isupRel(16);
  for (const b of [iamBytes, relBytes]) {
    const s = b.toString('latin1');
    if (s.indexOf('\r\n\r\n') !== -1 || s.indexOf(BOUNDARY) !== -1) {
      throw new Error('ISUP blob collides with MIME framing');
    }
  }
  const inviteBody = multipart(BOUNDARY, [
    {
      headers: [['Content-Type', 'application/sdp'], ['Content-Disposition', 'session;handling=required']],
      body: sdp,
    },
    {
      headers: [['Content-Type', 'application/isup;version=itu-t92+'],
        ['Content-Disposition', 'signal;handling=optional'],
        ['Content-Transfer-Encoding', 'binary']],
      body: iamBytes.toString('latin1'),
    },
  ]);
  const okBody = multipart(BOUNDARY, [
    {
      headers: [['Content-Type', 'application/sdp'], ['Content-Disposition', 'session;handling=required']],
      body: answerSdp,
    },
    {
      headers: [['Content-Type', 'application/isup;version=itu-t92+'],
        ['Content-Disposition', 'signal;handling=optional'],
        ['Content-Transfer-Encoding', 'binary']],
      body: isupAnm().toString('latin1'),
    },
  ]);

  const cap = newCap();
  cap.udp(0.000, A_IP, 5060, SBC_OUT, 5060, wire(leg.req('INVITE', 'sip:+33987654321@' + SBC_OUT, 1, invBr, {
    body: inviteBody,
    ctype: 'multipart/mixed;boundary=' + BOUNDARY,
    moreVias: [
      via('203.0.113.60', 5060, branch('sipi-transit-1')),
      via('203.0.113.61', 5060, branch('sipi-transit-2')),
    ],
    extra: [
      ['Supported', 'timer'],
      ['Max-Breadth', '10'],
      ['User-Agent', 'Nokia-TAS/22.5 (SIP-I)'],
    ],
  })));
  cap.udp(0.020, SBC_OUT, 5060, A_IP, 5060, wire(leg.res(100, 'Trying', 1, 'INVITE', invBr, { toTag: false })));
  cap.udp(1.100, SBC_OUT, 5060, A_IP, 5060, wire(leg.res(200, 'OK', 1, 'INVITE', invBr, {
    body: okBody, ctype: 'multipart/mixed;boundary=' + BOUNDARY,
    contact: 'sip:+33987654321@' + SBC_OUT + ':5060',
  })));
  cap.udp(1.120, A_IP, 5060, SBC_OUT, 5060, wire(leg.req('ACK', 'sip:+33987654321@' + SBC_OUT + ':5060', 1, ackBr, { toTag: true })));
  cap.udp(25.000, A_IP, 5060, SBC_OUT, 5060, wire(leg.req('BYE', 'sip:+33987654321@' + SBC_OUT + ':5060', 2, byeBr, {
    toTag: true, contact: false,
    body: relBytes.toString('latin1'),
    ctype: 'application/isup;version=itu-t92+',
    extra: [['Reason', 'Q.850;cause=16;text="Normal call clearing"']],
  })));
  cap.udp(25.020, SBC_OUT, 5060, A_IP, 5060, wire(leg.res(200, 'OK', 2, 'BYE', byeBr, { toTag: true })));

  addCapture({
    name: 'sipi-call',
    file: 'sipi-call.pcap',
    cap: cap,
    expect: {
      format: 'pcap',
      sipMessages: 6, h323Messages: 0, legs: 1, calls: 1,
      callStates: { unpaired: 1 },
      indicatorsOn: ['sip', 'sip-i'],
      scenario: 'carrier-interconnect',
    },
  });
})();

/* ------------------------------------------------------------------ */
/* DNS                                                                 */
/* ------------------------------------------------------------------ */

/**
 * Encode a domain name as uncompressed DNS labels.
 * @param {string} name
 * @returns {Buffer}
 */
function dnsName(name) {
  const parts = String(name).split('.').filter(Boolean);
  const bufs = [];
  for (const p of parts) bufs.push(Buffer.concat([Buffer.from([p.length]), Buffer.from(p, 'ascii')]));
  bufs.push(Buffer.from([0]));
  return Buffer.concat(bufs);
}

/**
 * Encode a DNS character-string (length-prefixed).
 * @param {string} s
 * @returns {Buffer}
 */
function dnsCharStr(s) {
  return Buffer.concat([Buffer.from([s.length]), Buffer.from(s, 'ascii')]);
}

/**
 * Build a DNS query message.
 * @param {number} id transaction id
 * @param {string} qname question name
 * @param {number} qtype question type (1 A, 33 SRV, 35 NAPTR)
 * @returns {Buffer}
 */
function dnsQuery(id, qname, qtype) {
  const h = Buffer.alloc(12);
  h.writeUInt16BE(id, 0);
  h.writeUInt16BE(0x0100, 2); // standard query, recursion desired
  h.writeUInt16BE(1, 4);
  return Buffer.concat([h, dnsName(qname), u16be(qtype), u16be(1)]);
}

/**
 * Build a DNS response message echoing the question.
 * @param {number} id transaction id
 * @param {string} qname question name
 * @param {number} qtype question type
 * @param {Array<{type: number, ttl: number, rdata: Buffer}>} answers
 * @param {number} [rcode] response code (0 NOERROR)
 * @returns {Buffer}
 */
function dnsResponse(id, qname, qtype, answers, rcode) {
  const h = Buffer.alloc(12);
  h.writeUInt16BE(id, 0);
  h.writeUInt16BE(0x8180 | ((rcode || 0) & 0x0f), 2); // response + RD + RA
  h.writeUInt16BE(1, 4);
  h.writeUInt16BE(answers.length, 6);
  const parts = [h, dnsName(qname), u16be(qtype), u16be(1)];
  for (const a of answers) {
    parts.push(dnsName(qname), u16be(a.type), u16be(1), u32be(a.ttl), u16be(a.rdata.length), a.rdata);
  }
  return Buffer.concat(parts);
}

/* ================================================================== */
/* 14. dns-slow -- NAPTR/SRV stalls that explain INVITE retransmissions */
/* ================================================================== */

(function registerDnsSlow() {
  const cap = newCap();
  const CARRIER = 'carrier.example.net';
  const SRV_NAME = '_sip._udp.' + CARRIER;
  const HOST = 'sbc1.' + CARRIER;

  // NAPTR resolves quickly.
  cap.udp(0.000, SBC_IN, 35120, DNS_IP, 53, dnsQuery(0x1a2b, CARRIER, 35));
  cap.udp(0.004, DNS_IP, 53, SBC_IN, 35120, dnsResponse(0x1a2b, CARRIER, 35, [{
    type: 35, ttl: 300,
    rdata: Buffer.concat([
      u16be(50), u16be(50), dnsCharStr('s'), dnsCharStr('SIP+D2U'),
      dnsCharStr(''), dnsName(SRV_NAME),
    ]),
  }]));
  // The SRV lookup takes 2.4 seconds -- this is what stalls every INVITE.
  cap.udp(0.005, SBC_IN, 35121, DNS_IP, 53, dnsQuery(0x1a2c, SRV_NAME, 33));
  cap.udp(2.405, DNS_IP, 53, SBC_IN, 35121, dnsResponse(0x1a2c, SRV_NAME, 33, [{
    type: 33, ttl: 300,
    rdata: Buffer.concat([u16be(10), u16be(0), u16be(5060), dnsName(HOST)]),
  }]));
  // ... and the A lookup that follows is never answered at all.
  cap.udp(2.410, SBC_IN, 35122, DNS_IP, 53, dnsQuery(0x1a2d, HOST, 1));

  // Two egress legs to the same destination, both stalled by the same lookup.
  function stalledLeg(idx, t0, respAt) {
    const from = '+3361000012' + idx;
    const to = '+3398765432' + idx;
    const leg = newLeg({
      callId: callIdOf('dnsslow-' + idx, 'sbc.example.net'),
      fromUri: 'sip:' + from + '@sbc.example.net', fromTag: tagOf('dnsslow-f-' + idx),
      toUri: 'sip:' + to + '@' + CARRIER, toTag: tagOf('dnsslow-t-' + idx),
      srcIp: SBC_IN, srcPort: 5060, dstIp: B_IP, dstPort: 5060,
      contact: 'sip:' + from + '@' + SBC_IN + ':5060',
    });
    const invBr = branch('dnsslow-inv-' + idx);
    const ackBr = branch('dnsslow-ack-' + idx);
    const invite = leg.req('INVITE', 'sip:' + to + '@' + CARRIER, 1, invBr, {
      maxf: 69,
      body: sdpBody([
        'v=0', 'o=- 830000' + idx + ' 1 IN IP4 ' + SBC_IN, 's=-', 'c=IN IP4 ' + SBC_IN, 't=0 0',
        'm=audio ' + (24000 + idx * 2) + ' RTP/AVP 0 101', 'a=rtpmap:0 PCMU/8000',
        'a=rtpmap:101 telephone-event/8000', 'a=ptime:20', 'a=sendrecv',
      ]),
      ctype: 'application/sdp',
      extra: [['Supported', 'timer'], ['User-Agent', 'OracleSBC/8.4.0']],
    });
    for (const t of backoff(3)) cap.udp(t0 + t, SBC_IN, 5060, B_IP, 5060, wire(invite));
    cap.udp(respAt, B_IP, 5060, SBC_IN, 5060, wire(leg.res(100, 'Trying', 1, 'INVITE', invBr, { toTag: false })));
    cap.udp(respAt + 0.15, B_IP, 5060, SBC_IN, 5060, wire(leg.res(180, 'Ringing', 1, 'INVITE', invBr, {
      contact: 'sip:' + to + '@' + B_IP + ':5060',
    })));
    cap.udp(respAt + 0.60, B_IP, 5060, SBC_IN, 5060, wire(leg.res(200, 'OK', 1, 'INVITE', invBr, {
      body: sdpBody([
        'v=0', 'o=core 555171' + idx + ' 1 IN IP4 ' + B_IP, 's=-', 'c=IN IP4 ' + B_IP, 't=0 0',
        'm=audio ' + (34000 + idx * 2) + ' RTP/AVP 0 101', 'a=rtpmap:0 PCMU/8000',
        'a=rtpmap:101 telephone-event/8000', 'a=ptime:20', 'a=sendrecv',
      ]),
      ctype: 'application/sdp', contact: 'sip:' + to + '@' + B_IP + ':5060',
    })));
    cap.udp(respAt + 0.62, SBC_IN, 5060, B_IP, 5060, wire(leg.req('ACK', 'sip:' + to + '@' + B_IP + ':5060', 1, ackBr, {
      toTag: true, maxf: 69,
    })));
  }
  stalledLeg(1, 0.010, 2.450);
  stalledLeg(2, 0.020, 2.465);

  addCapture({
    name: 'dns-slow',
    file: 'dns-slow.pcap',
    cap: cap,
    expect: {
      format: 'pcap',
      sipMessages: 14, h323Messages: 0, legs: 2, calls: 2,
      callStates: { unpaired: 2 },
      retransCodes: ['dns-blocking'],
      findingsInclude: [{ severity: 'warn', category: 'retrans' }],
      auxProtocols: ['dns'],
      indicatorsOn: ['sip', 'dns'],
      adviceTitlesInclude: ['DNS'],
    },
  });
})();

/* ------------------------------------------------------------------ */
/* Diameter                                                            */
/* ------------------------------------------------------------------ */

const VENDOR_3GPP = 10415;

/**
 * Encode one Diameter AVP (padded to a 4-byte boundary).
 * @param {number} code AVP code
 * @param {number} flags AVP flag bits (0x40 = mandatory)
 * @param {Buffer} data AVP data
 * @param {number} [vendorId] vendor id (sets the V bit and the vendor field)
 * @returns {Buffer}
 */
function diameterAvp(code, flags, data, vendorId) {
  const hdrLen = vendorId ? 12 : 8;
  const len = hdrLen + data.length;
  const pad = (4 - (len % 4)) % 4;
  const b = Buffer.alloc(len + pad);
  b.writeUInt32BE(code >>> 0, 0);
  b[4] = (flags | (vendorId ? 0x80 : 0)) & 0xff;
  b.writeUIntBE(len, 5, 3);
  if (vendorId) {
    b.writeUInt32BE(vendorId >>> 0, 8);
    data.copy(b, 12);
  } else {
    data.copy(b, 8);
  }
  return b;
}

/**
 * Encode a Diameter message.
 * @param {number} flags command flags (0x80 request, 0x40 proxiable)
 * @param {number} cmd command code
 * @param {number} appId application id
 * @param {number} hbh hop-by-hop id
 * @param {number} e2e end-to-end id
 * @param {Array<Buffer>} avps encoded AVPs
 * @returns {Buffer}
 */
function diameterMsg(flags, cmd, appId, hbh, e2e, avps) {
  const body = Buffer.concat(avps);
  const b = Buffer.alloc(20 + body.length);
  b[0] = 1;
  b.writeUIntBE(20 + body.length, 1, 3);
  b[4] = flags & 0xff;
  b.writeUIntBE(cmd & 0xffffff, 5, 3);
  b.writeUInt32BE(appId >>> 0, 8);
  b.writeUInt32BE(hbh >>> 0, 12);
  b.writeUInt32BE(e2e >>> 0, 16);
  body.copy(b, 20);
  return b;
}

/* ================================================================== */
/* 15. diameter-rx -- Rx AAR/AAA whose charging id matches the SIP icid */
/* ================================================================== */

const RX_ICID = 'hiccupRX8811';

(function registerDiameterRx() {
  const cap = newCap();
  const RX_APP = 16777236; // 3GPP Rx
  const sessionId = 'pcscf.example.net;1470764900;1;' + RX_ICID;

  const leg = newLeg({
    callId: callIdOf('rx-call', 'ims.example.net'),
    fromUri: 'sip:+33612345678@ims.example.net', fromTag: tagOf('rx-f'),
    toUri: 'sip:+33987654321@ims.example.net', toTag: tagOf('rx-t'),
    srcIp: SBC_IN, srcPort: 5060, dstIp: B_IP, dstPort: 5060,
    contact: 'sip:+33612345678@' + SBC_IN + ':5060',
  });
  const invBr = branch('rx-inv');
  const ackBr = branch('rx-ack');
  const byeBr = branch('rx-bye');
  cap.udp(0.000, SBC_IN, 5060, B_IP, 5060, wire(leg.req('INVITE', 'sip:+33987654321@ims.example.net', 1, invBr, {
    body: sdpBody([
      'v=0', 'o=- 8400001 1 IN IP4 ' + SBC_IN, 's=-', 'c=IN IP4 ' + SBC_IN, 't=0 0',
      'm=audio 25000 RTP/AVP 104 96', 'a=rtpmap:104 AMR-WB/16000/1',
      'a=rtpmap:96 telephone-event/8000', 'a=ptime:20', 'a=sendrecv',
    ]),
    ctype: 'application/sdp',
    extra: [
      ['P-Charging-Vector', 'icid-value=' + RX_ICID + ';orig-ioi=pcscf.example.net'],
      ['P-Asserted-Identity', '<sip:+33612345678@ims.example.net>'],
      ['Supported', '100rel, timer'],
      ['User-Agent', 'P-CSCF/3.1'],
    ],
  })));
  cap.udp(0.012, B_IP, 5060, SBC_IN, 5060, wire(leg.res(100, 'Trying', 1, 'INVITE', invBr, { toTag: false })));

  // Rx AAR/AAA over TCP 3868, carrying the same charging identifier.
  const conn = newTcpConn(cap, SBC_IN, 41007, PCRF_IP, 3868, 0x50000, 0x60000);
  conn.handshake(0.020);
  const mediaComponent = Buffer.concat([
    diameterAvp(518, 0x40, u32be(1), VENDOR_3GPP),                          // Media-Component-Number
    diameterAvp(511, 0x40, u32be(2), VENDOR_3GPP),                          // Flow-Status: ENABLED
    diameterAvp(520, 0x40, Buffer.from('audio', 'ascii'), VENDOR_3GPP),     // Media-Type
  ]);
  const aar = diameterMsg(0xc0, 265, RX_APP, 0x7f1a2b3c, 0x11223344, [
    diameterAvp(263, 0x40, Buffer.from(sessionId, 'ascii')),                // Session-Id
    diameterAvp(258, 0x40, u32be(RX_APP)),                                  // Auth-Application-Id
    diameterAvp(264, 0x40, Buffer.from('pcscf.example.net', 'ascii')),      // Origin-Host
    diameterAvp(296, 0x40, Buffer.from('example.net', 'ascii')),            // Origin-Realm
    diameterAvp(283, 0x40, Buffer.from('example.net', 'ascii')),            // Destination-Realm
    diameterAvp(505, 0x40, Buffer.from(RX_ICID, 'ascii'), VENDOR_3GPP),     // AF-Charging-Identifier
    diameterAvp(517, 0x40, mediaComponent, VENDOR_3GPP),                    // Media-Component-Description
    diameterAvp(8, 0x40, Buffer.from([10, 30, 0, 77])),                     // Framed-IP-Address
  ]);
  const aaa = diameterMsg(0x40, 265, RX_APP, 0x7f1a2b3c, 0x11223344, [
    diameterAvp(263, 0x40, Buffer.from(sessionId, 'ascii')),
    diameterAvp(268, 0x40, u32be(2001)),                                    // Result-Code: DIAMETER_SUCCESS
    diameterAvp(264, 0x40, Buffer.from('pcrf.example.net', 'ascii')),
    diameterAvp(296, 0x40, Buffer.from('example.net', 'ascii')),
    diameterAvp(258, 0x40, u32be(RX_APP)),
  ]);
  conn.send(0.030, 'a', aar);
  conn.send(0.088, 'b', aaa);

  cap.udp(0.400, B_IP, 5060, SBC_IN, 5060, wire(leg.res(180, 'Ringing', 1, 'INVITE', invBr, {
    contact: 'sip:+33987654321@' + B_IP + ':5060',
  })));
  cap.udp(2.100, B_IP, 5060, SBC_IN, 5060, wire(leg.res(200, 'OK', 1, 'INVITE', invBr, {
    body: sdpBody([
      'v=0', 'o=- 5551919 1 IN IP4 ' + B_IP, 's=-', 'c=IN IP4 ' + B_IP, 't=0 0',
      'm=audio 35000 RTP/AVP 104 96', 'a=rtpmap:104 AMR-WB/16000/1',
      'a=rtpmap:96 telephone-event/8000', 'a=ptime:20', 'a=sendrecv',
    ]),
    ctype: 'application/sdp', contact: 'sip:+33987654321@' + B_IP + ':5060',
  })));
  cap.udp(2.120, SBC_IN, 5060, B_IP, 5060, wire(leg.req('ACK', 'sip:+33987654321@' + B_IP + ':5060', 1, ackBr, { toTag: true })));
  cap.udp(30.000, SBC_IN, 5060, B_IP, 5060, wire(leg.req('BYE', 'sip:+33987654321@' + B_IP + ':5060', 2, byeBr, {
    toTag: true, contact: false,
  })));
  cap.udp(30.020, B_IP, 5060, SBC_IN, 5060, wire(leg.res(200, 'OK', 2, 'BYE', byeBr, { toTag: true })));
  conn.teardown(30.100, 'a');

  addCapture({
    name: 'diameter-rx',
    file: 'diameter-rx.pcap',
    cap: cap,
    expect: {
      format: 'pcap',
      sipMessages: 7, h323Messages: 0, legs: 1, calls: 1,
      callStates: { unpaired: 1 },
      auxProtocols: ['diameter'],
      indicatorsOn: ['sip', 'diameter', 'ims'],
    },
  });
})();

// __PART6__
