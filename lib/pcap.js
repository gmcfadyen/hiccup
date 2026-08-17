'use strict';

/**
 * lib/pcap.js — pcap / pcapng decoder for hiccup.
 *
 * Decodes classic pcap (both endiannesses, microsecond + nanosecond variants)
 * and pcapng (SHB/IDB/EPB with per-interface if_tsresol). Link layers:
 * Ethernet(1) incl. 802.1Q / QinQ VLAN tags, Linux SLL(113), SLL2(276),
 * Raw IP(101/228/229), Null/Loopback(0). IPv4 (with best-effort fragment
 * reassembly) and IPv6 (extension headers skipped). Emits only UDP/TCP packets
 * that carry L7 payload bytes — zero-payload segments (pure ACKs, bare
 * SYN/FIN) are skipped; sip.js/h323.js do their own stream framing from data
 * segments.
 *
 * Never throws on malformed input: every anomaly becomes a string in
 * `warnings` and the offending frame is skipped.
 *
 * Zero runtime dependencies. CommonJS. See ARCHITECTURE.md §Data shapes.
 */

var MAX_WARNINGS = 200;

// Ethertypes treated as VLAN tags (802.1Q, 802.1ad QinQ, legacy QinQ).
var VLAN_TPIDS = { 0x8100: true, 0x88a8: true, 0x9100: true };

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

function u16(buf, off, be) {
  return be ? buf.readUInt16BE(off) : buf.readUInt16LE(off);
}

function u32(buf, off, be) {
  return be ? buf.readUInt32BE(off) : buf.readUInt32LE(off);
}

function ip4str(buf, off) {
  return buf[off] + '.' + buf[off + 1] + '.' + buf[off + 2] + '.' + buf[off + 3];
}

function ip6str(buf, off) {
  var groups = [];
  for (var i = 0; i < 8; i++) groups.push(buf.readUInt16BE(off + i * 2));
  // find the longest run of zero groups (length >= 2) for :: compression
  var bestStart = -1, bestLen = 0, runStart = -1, runLen = 0;
  for (var g = 0; g <= 8; g++) {
    if (g < 8 && groups[g] === 0) {
      if (runStart === -1) { runStart = g; runLen = 0; }
      runLen++;
    } else {
      if (runLen > bestLen) { bestStart = runStart; bestLen = runLen; }
      runStart = -1; runLen = 0;
    }
  }
  if (bestLen < 2) {
    return groups.map(function (v) { return v.toString(16); }).join(':');
  }
  var head = groups.slice(0, bestStart).map(function (v) { return v.toString(16); }).join(':');
  var tail = groups.slice(bestStart + bestLen).map(function (v) { return v.toString(16); }).join(':');
  return head + '::' + tail;
}

function warn(ctx, msg) {
  if (ctx.warnings.length < MAX_WARNINGS) {
    ctx.warnings.push(msg);
  } else if (!ctx.suppressed) {
    ctx.suppressed = true;
    ctx.warnings.push('additional warnings suppressed');
  }
}

/* ------------------------------------------------------------------ */
/* L4 decode + packet emission                                         */
/* ------------------------------------------------------------------ */

/**
 * Decode UDP/TCP from an IP payload and emit a Packet if it carries L7 bytes.
 * dg = { src, dst, proto, data (Buffer), ts, wire, fragmented, frame }
 */
function emitL4(ctx, dg) {
  var data = dg.data;
  if (dg.proto === 17) { // UDP
    if (data.length < 8) {
      warn(ctx, 'frame ' + dg.frame + ': truncated UDP header — skipped');
      return;
    }
    var sport = data.readUInt16BE(0);
    var dport = data.readUInt16BE(2);
    var udpLen = data.readUInt16BE(4);
    var end = udpLen >= 8 ? udpLen : data.length;
    if (end > data.length) {
      warn(ctx, 'frame ' + dg.frame + ': UDP datagram truncated (' +
        (end - 8) + ' bytes declared, ' + (data.length - 8) + ' captured)');
      end = data.length;
    }
    var payload = data.slice(8, end);
    if (payload.length === 0) return;
    ctx.packets.push({
      n: ctx.packets.length + 1,
      ts: dg.ts,
      src: dg.src, dst: dg.dst,
      sport: sport, dport: dport,
      transport: 'udp',
      payload: payload,
      fragmented: dg.fragmented,
      wireBytes: dg.wire,
    });
  } else if (dg.proto === 6) { // TCP
    if (data.length < 20) {
      warn(ctx, 'frame ' + dg.frame + ': truncated TCP header — skipped');
      return;
    }
    var doff = (data[12] >> 4) * 4;
    if (doff < 20 || doff > data.length) {
      warn(ctx, 'frame ' + dg.frame + ': bad/truncated TCP data offset — skipped');
      return;
    }
    var flags = data[13];
    var tcpPayload = data.slice(doff);
    if (tcpPayload.length === 0) return; // pure ACK / bare SYN / bare FIN — no L7 bytes
    ctx.packets.push({
      n: ctx.packets.length + 1,
      ts: dg.ts,
      src: dg.src, dst: dg.dst,
      sport: data.readUInt16BE(0), dport: data.readUInt16BE(2),
      transport: 'tcp',
      payload: tcpPayload,
      tcp: {
        seq: data.readUInt32BE(4),
        syn: !!(flags & 0x02),
        fin: !!(flags & 0x01),
      },
      fragmented: dg.fragmented,
      wireBytes: dg.wire,
    });
  }
  // other IP protocols: skipped silently (contract: non-UDP/TCP skipped)
}

/* ------------------------------------------------------------------ */
/* IPv4 (with fragment reassembly) and IPv6                            */
/* ------------------------------------------------------------------ */

function handleIPv4(ctx, buf, ts, wire, frame) {
  if (buf.length < 20) {
    warn(ctx, 'frame ' + frame + ': truncated IPv4 header — skipped');
    return;
  }
  if ((buf[0] >> 4) !== 4) {
    warn(ctx, 'frame ' + frame + ': IPv4 expected but version nibble is ' + (buf[0] >> 4) + ' — skipped');
    return;
  }
  var ihl = (buf[0] & 0x0f) * 4;
  if (ihl < 20 || ihl > buf.length) {
    warn(ctx, 'frame ' + frame + ': bad IPv4 IHL — skipped');
    return;
  }
  var totalLen = buf.readUInt16BE(2);
  var end = totalLen;
  if (totalLen < ihl) end = buf.length; // bogus total length — use what we have
  if (end > buf.length) {
    warn(ctx, 'frame ' + frame + ': IPv4 packet truncated (' + totalLen +
      ' bytes declared, ' + buf.length + ' captured)');
    end = buf.length;
  }
  var id = buf.readUInt16BE(4);
  var flagsFrag = buf.readUInt16BE(6);
  var mf = !!(flagsFrag & 0x2000);
  var fragOff = (flagsFrag & 0x1fff) * 8;
  var proto = buf[9];
  var src = ip4str(buf, 12);
  var dst = ip4str(buf, 16);
  var payload = buf.slice(ihl, end);

  if (fragOff === 0 && !mf) {
    emitL4(ctx, { src: src, dst: dst, proto: proto, data: payload, ts: ts, wire: wire, fragmented: false, frame: frame });
    return;
  }

  // fragment — reassembly keyed on (src, dst, id, proto)
  var key = src + '|' + dst + '|' + id + '|' + proto;
  var g = ctx.frags.get(key);
  if (!g) {
    g = { parts: [], end: null, wire: 0, ts: ts, frame: frame, key: key };
    ctx.frags.set(key, g);
  }
  if (g.parts.length >= 2048) {
    warn(ctx, 'frame ' + frame + ': IPv4 fragment group ' + key + ' too large — fragment dropped');
    return;
  }
  g.parts.push({ off: fragOff, data: payload });
  g.wire += wire;
  if (ts < g.ts) g.ts = ts;
  if (!mf) g.end = fragOff + payload.length;
  if (g.end !== null) tryAssemble(ctx, g);
}

/** Emit the reassembled datagram if the fragment group is contiguous 0..end. */
function tryAssemble(ctx, g) {
  var parts = g.parts.slice().sort(function (a, b) { return a.off - b.off; });
  var cursor = 0;
  for (var i = 0; i < parts.length; i++) {
    if (parts[i].off > cursor) return; // gap — keep waiting
    var pEnd = parts[i].off + parts[i].data.length;
    if (pEnd > cursor) cursor = pEnd;
    if (cursor >= g.end) break;
  }
  if (cursor < g.end) return;
  var out = Buffer.alloc(g.end);
  for (var j = 0; j < parts.length; j++) {
    var p = parts[j];
    var copyLen = Math.min(p.data.length, g.end - p.off);
    if (copyLen > 0) p.data.copy(out, p.off, 0, copyLen);
  }
  ctx.frags.delete(g.key);
  var kp = g.key.split('|');
  emitL4(ctx, {
    src: kp[0], dst: kp[1], proto: Number(kp[3]),
    data: out, ts: g.ts, wire: g.wire, fragmented: true, frame: g.frame,
  });
}

function handleIPv6(ctx, buf, ts, wire, frame) {
  if (buf.length < 40) {
    warn(ctx, 'frame ' + frame + ': truncated IPv6 header — skipped');
    return;
  }
  if ((buf[0] >> 4) !== 6) {
    warn(ctx, 'frame ' + frame + ': IPv6 expected but version nibble is ' + (buf[0] >> 4) + ' — skipped');
    return;
  }
  var payloadLen = buf.readUInt16BE(4);
  var next = buf[6];
  var src = ip6str(buf, 8);
  var dst = ip6str(buf, 24);
  var off = 40;
  var end = 40 + payloadLen;
  if (end > buf.length) {
    warn(ctx, 'frame ' + frame + ': IPv6 packet truncated (' + payloadLen +
      ' payload bytes declared, ' + (buf.length - 40) + ' captured)');
    end = buf.length;
  }

  // skip extension headers: hop-by-hop(0), routing(43), fragment(44), dest-opts(60)
  var guard = 0;
  while (guard++ < 16) {
    if (next === 0 || next === 43 || next === 60) {
      if (off + 2 > end) {
        warn(ctx, 'frame ' + frame + ': truncated IPv6 extension header — skipped');
        return;
      }
      var extLen = (buf[off + 1] + 1) * 8;
      if (off + extLen > end) {
        warn(ctx, 'frame ' + frame + ': truncated IPv6 extension header — skipped');
        return;
      }
      next = buf[off];
      off += extLen;
    } else if (next === 44) { // fragment header (fixed 8 bytes)
      if (off + 8 > end) {
        warn(ctx, 'frame ' + frame + ': truncated IPv6 fragment header — skipped');
        return;
      }
      var fo = buf.readUInt16BE(off + 2);
      var fragOff = fo & 0xfff8;
      var more = fo & 0x0001;
      if (fragOff !== 0 || more !== 0) {
        warn(ctx, 'frame ' + frame + ': IPv6 fragment — reassembly not supported, dropped');
        return;
      }
      next = buf[off]; // atomic fragment — carry on
      off += 8;
    } else {
      break;
    }
  }

  if (next !== 6 && next !== 17) return; // non-UDP/TCP — skipped
  emitL4(ctx, {
    src: src, dst: dst, proto: next,
    data: buf.slice(off, end), ts: ts, wire: wire, fragmented: false, frame: frame,
  });
}

/* ------------------------------------------------------------------ */
/* link-layer decode                                                   */
/* ------------------------------------------------------------------ */

/**
 * Given an ethertype and the offset just past where it was read, strip any
 * stacked VLAN tags (802.1Q / QinQ). Returns { et, off } or null on truncation.
 */
function stripVlans(buf, et, off) {
  var guard = 0;
  while (VLAN_TPIDS[et] && guard++ < 8) {
    if (off + 4 > buf.length) return null;
    et = buf.readUInt16BE(off + 2); // TCI(2) then inner ethertype
    off += 4;
  }
  return { et: et, off: off };
}

/** Decode one captured frame according to linkType. Never throws. */
function handleFrame(ctx, data, ts, wire, linkType, frame) {
  var et, r;
  switch (linkType) {
    case 1: { // Ethernet
      if (data.length < 14) {
        warn(ctx, 'frame ' + frame + ': truncated Ethernet header — skipped');
        return;
      }
      et = data.readUInt16BE(12);
      r = stripVlans(data, et, 14);
      if (!r) {
        warn(ctx, 'frame ' + frame + ': truncated VLAN tag — skipped');
        return;
      }
      dispatchEthertype(ctx, r.et, data.slice(r.off), ts, wire, frame);
      return;
    }
    case 113: { // Linux SLL
      if (data.length < 16) {
        warn(ctx, 'frame ' + frame + ': truncated SLL header — skipped');
        return;
      }
      et = data.readUInt16BE(14);
      r = stripVlans(data, et, 16);
      if (!r) {
        warn(ctx, 'frame ' + frame + ': truncated VLAN tag — skipped');
        return;
      }
      dispatchEthertype(ctx, r.et, data.slice(r.off), ts, wire, frame);
      return;
    }
    case 276: { // Linux SLL2
      if (data.length < 20) {
        warn(ctx, 'frame ' + frame + ': truncated SLL2 header — skipped');
        return;
      }
      et = data.readUInt16BE(0);
      r = stripVlans(data, et, 20);
      if (!r) {
        warn(ctx, 'frame ' + frame + ': truncated VLAN tag — skipped');
        return;
      }
      dispatchEthertype(ctx, r.et, data.slice(r.off), ts, wire, frame);
      return;
    }
    case 0: { // Null/Loopback — 4-byte host-endian address family word
      if (data.length < 4) {
        warn(ctx, 'frame ' + frame + ': truncated Null/Loopback header — skipped');
        return;
      }
      var fam = data.readUInt32LE(0);
      if (fam > 0xffff) fam = data.readUInt32BE(0); // writer was the other endianness
      var ip = data.slice(4);
      if (fam === 2) handleIPv4(ctx, ip, ts, wire, frame);
      else if (fam === 24 || fam === 28 || fam === 30) handleIPv6(ctx, ip, ts, wire, frame);
      // other families: skipped silently
      return;
    }
    case 101: case 228: case 229: { // Raw IP — decide by version nibble
      if (data.length < 1) {
        warn(ctx, 'frame ' + frame + ': empty raw-IP frame — skipped');
        return;
      }
      var v = data[0] >> 4;
      if (v === 4) handleIPv4(ctx, data, ts, wire, frame);
      else if (v === 6) handleIPv6(ctx, data, ts, wire, frame);
      else warn(ctx, 'frame ' + frame + ': raw-IP frame with version nibble ' + v + ' — skipped');
      return;
    }
    default:
      // unsupported link type: one warning for the whole capture
      if (!ctx.badLinkWarned) {
        ctx.badLinkWarned = true;
        warn(ctx, 'unsupported link type ' + linkType + ' — those frames skipped');
      }
  }
}

function dispatchEthertype(ctx, et, buf, ts, wire, frame) {
  if (et === 0x0800) handleIPv4(ctx, buf, ts, wire, frame);
  else if (et === 0x86dd) handleIPv6(ctx, buf, ts, wire, frame);
  // ARP, LLDP, etc: skipped silently
}

/* ------------------------------------------------------------------ */
/* classic pcap                                                        */
/* ------------------------------------------------------------------ */

function parseClassic(ctx, buffer, be, nanos) {
  if (buffer.length < 24) {
    warn(ctx, 'pcap file truncated inside the global header');
    return { linkType: null };
  }
  var linkType = u32(buffer, 20, be);
  var off = 24;
  var frame = 0;
  var divisor = nanos ? 1e9 : 1e6;
  while (off + 16 <= buffer.length) {
    frame++;
    var sec = u32(buffer, off, be);
    var frac = u32(buffer, off + 4, be);
    var incl = u32(buffer, off + 8, be);
    var orig = u32(buffer, off + 12, be);
    if (incl > 0x0fffffff) {
      warn(ctx, 'frame ' + frame + ': implausible record length ' + incl + ' — stopping');
      return { linkType: linkType };
    }
    if (off + 16 + incl > buffer.length) {
      warn(ctx, 'capture truncated mid-record at frame ' + frame + ' — remaining bytes ignored');
      return { linkType: linkType };
    }
    var ts = sec + frac / divisor;
    try {
      handleFrame(ctx, buffer.slice(off + 16, off + 16 + incl), ts, orig || incl, linkType, frame);
    } catch (e) {
      warn(ctx, 'frame ' + frame + ': decode error (' + e.message + ') — skipped');
    }
    off += 16 + incl;
  }
  if (off < buffer.length) {
    warn(ctx, 'capture truncated inside a record header — trailing ' + (buffer.length - off) + ' bytes ignored');
  }
  return { linkType: linkType };
}

/* ------------------------------------------------------------------ */
/* pcapng                                                              */
/* ------------------------------------------------------------------ */

/** Parse IDB options for if_tsresol (code 9). Returns seconds-per-tick. */
function idbResol(ctx, buffer, optStart, optEnd, be) {
  var off = optStart;
  while (off + 4 <= optEnd) {
    var code = u16(buffer, off, be);
    var olen = u16(buffer, off + 2, be);
    if (code === 0) break; // opt_endofopt
    if (off + 4 + olen > optEnd) break; // malformed options — stop quietly
    if (code === 9 && olen >= 1) {
      var v = buffer[off + 4];
      if (v & 0x80) return Math.pow(2, -(v & 0x7f)); // power-of-2 flag bit
      return Math.pow(10, -v);
    }
    off += 4 + olen + ((4 - (olen % 4)) % 4); // values padded to 4 bytes
  }
  return 1e-6; // default microseconds
}

function parsePcapng(ctx, buffer) {
  var off = 0;
  var be = null;           // per-section endianness, from the SHB byte-order magic
  var interfaces = [];     // reset at every SHB
  var firstLink = null;
  var frame = 0;

  while (off + 12 <= buffer.length) {
    var isShb = buffer.readUInt32BE(off) === 0x0a0d0d0a; // same bytes either endianness
    if (isShb) {
      if (off + 12 > buffer.length) break;
      var bom = buffer.readUInt32BE(off + 8);
      if (bom === 0x1a2b3c4d) be = true;
      else if (bom === 0x4d3c2b1a) be = false;
      else {
        warn(ctx, 'pcapng: bad byte-order magic in section header — stopping');
        return { linkType: firstLink };
      }
      interfaces = []; // new section: interface ids restart at 0
    }
    if (be === null) {
      warn(ctx, 'pcapng: data before the first section header — stopping');
      return { linkType: firstLink };
    }
    var blockType = u32(buffer, off, be);
    var totalLen = u32(buffer, off + 4, be);
    if (totalLen < 12 || totalLen % 4 !== 0) {
      warn(ctx, 'pcapng: bad block length ' + totalLen + ' — stopping');
      return { linkType: firstLink };
    }
    if (off + totalLen > buffer.length) {
      warn(ctx, 'pcapng: capture truncated mid-block — remaining bytes ignored');
      return { linkType: firstLink };
    }
    var body = off + 8;
    var bodyEnd = off + totalLen - 4;

    if (blockType === 0x00000001) { // IDB
      if (body + 8 <= bodyEnd) {
        var lt = u16(buffer, body, be);
        interfaces.push({ linkType: lt, resol: idbResol(ctx, buffer, body + 8, bodyEnd, be) });
        if (firstLink === null) firstLink = lt;
      } else {
        warn(ctx, 'pcapng: truncated interface description block — skipped');
      }
    } else if (blockType === 0x00000006) { // EPB
      frame++;
      if (body + 20 > bodyEnd) {
        warn(ctx, 'pcapng: truncated enhanced packet block (frame ' + frame + ') — skipped');
      } else {
        var ifId = u32(buffer, body, be);
        var tsHigh = u32(buffer, body + 4, be);
        var tsLow = u32(buffer, body + 8, be);
        var capLen = u32(buffer, body + 12, be);
        var origLen = u32(buffer, body + 16, be);
        var iface = interfaces[ifId];
        if (!iface) {
          warn(ctx, 'pcapng: frame ' + frame + ' references unknown interface ' + ifId + ' — skipped');
        } else {
          var dataStart = body + 20;
          if (capLen > bodyEnd - dataStart) {
            warn(ctx, 'pcapng: frame ' + frame + ' captured length overruns its block — clamped');
            capLen = Math.max(0, bodyEnd - dataStart);
          }
          var ts = (tsHigh * 4294967296 + tsLow) * iface.resol;
          try {
            handleFrame(ctx, buffer.slice(dataStart, dataStart + capLen), ts,
              origLen || capLen, iface.linkType, frame);
          } catch (e) {
            warn(ctx, 'pcapng: frame ' + frame + ': decode error (' + e.message + ') — skipped');
          }
        }
      }
    } else if (blockType === 0x00000003) { // Simple Packet Block — no ts/interface
      if (!ctx.spbWarned) {
        ctx.spbWarned = true;
        warn(ctx, 'pcapng: simple packet blocks present — not supported, skipped');
      }
    }
    // all other block types (NRB, ISB, custom, ...): skipped silently

    off += totalLen;
  }
  if (off < buffer.length && buffer.length - off >= 4) {
    warn(ctx, 'pcapng: capture truncated inside a block header — trailing bytes ignored');
  }
  return { linkType: firstLink };
}

/* ------------------------------------------------------------------ */
/* entry point                                                         */
/* ------------------------------------------------------------------ */

/**
 * Parse a pcap or pcapng capture into hiccup Packet objects.
 *
 * Supported: classic pcap (magics a1b2c3d4 / d4c3b2a1 microseconds,
 * a1b23c4d / 4d3cb2a1 nanoseconds) and pcapng (0a0d0d0a). Only UDP/TCP
 * packets carrying L7 payload bytes are emitted; IPv4 fragments are
 * reassembled (incomplete groups dropped with a warning). Malformed or
 * truncated input never throws — problems are reported in `warnings`.
 *
 * @param {Buffer} buffer  raw capture file bytes
 * @returns {{ format: ('pcap'|'pcapng'), linkType: (number|null),
 *            warnings: string[], packets: Array<object> }}
 *          packets follow the Packet shape in ARCHITECTURE.md:
 *          { n, ts, src, dst, sport, dport, transport, payload,
 *            tcp?, fragmented, wireBytes }
 */
function parsePcap(buffer) {
  var ctx = {
    packets: [],
    warnings: [],
    suppressed: false,
    badLinkWarned: false,
    spbWarned: false,
    frags: new Map(), // key (src|dst|id|proto) -> pending fragment group
  };

  if (!Buffer.isBuffer(buffer)) buffer = Buffer.from(buffer || []);

  var format = 'pcap';
  var linkType = null;

  if (buffer.length < 4) {
    warn(ctx, 'file too short to be a capture');
  } else {
    var magic = buffer.readUInt32BE(0);
    if (magic === 0x0a0d0d0a) {
      format = 'pcapng';
      linkType = parsePcapng(ctx, buffer).linkType;
    } else if (magic === 0xa1b2c3d4) {
      linkType = parseClassic(ctx, buffer, true, false).linkType;
    } else if (magic === 0xd4c3b2a1) {
      linkType = parseClassic(ctx, buffer, false, false).linkType;
    } else if (magic === 0xa1b23c4d) {
      linkType = parseClassic(ctx, buffer, true, true).linkType;
    } else if (magic === 0x4d3cb2a1) {
      linkType = parseClassic(ctx, buffer, false, true).linkType;
    } else {
      warn(ctx, 'not a pcap or pcapng file (magic 0x' + magic.toString(16) + ')');
    }
  }

  // anything still sitting in the fragment table is an incomplete group
  ctx.frags.forEach(function (g, key) {
    warn(ctx, 'dropped incomplete IPv4 fragment group (' + key.split('|').slice(0, 2).join(' -> ') +
      ' id=' + key.split('|')[2] + ' proto=' + key.split('|')[3] + ', ' +
      g.parts.length + ' fragment' + (g.parts.length === 1 ? '' : 's') + ' seen)');
  });
  ctx.frags.clear();

  return {
    format: format,
    linkType: linkType,
    warnings: ctx.warnings,
    packets: ctx.packets,
  };
}

module.exports = { parsePcap: parsePcap };
