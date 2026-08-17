'use strict';
/**
 * lib/textlog.js — SBC log / SIP text ingest for hiccup.
 *
 * Turns pasted or exported SIP text into the shared Packet[] shape (see
 * ARCHITECTURE.md). Three formats, sniffed from content (never the filename):
 *
 *  - 'acme-log' : Oracle/Acme sipmsg.log exports. Blocks like
 *                 `Aug 17 10:03:31.123 On [1:0]203.0.113.5:5060 received from 198.51.100.10:5060`
 *                 followed by a raw SIP message, separated by dashed lines.
 *                 Several legs of one call interleaved in one file is the normal case.
 *  - 'sngrep'   : sngrep/sipgrep envelopes:
 *                 `U 2026/08/17 10:03:31.123456 198.51.100.10:5060 -> 203.0.113.5:5060`
 *  - 'raw-sip'  : bare concatenated SIP messages.
 *
 * Liberal in what it accepts: CRLF/LF/CR endings, leading log noise between
 * blocks, dashed separators of any length >= 10, envelope lines with or without
 * the [slot:port] bracket, optional year in Acme timestamps, TCP/TLS markers
 * anywhere on the envelope line, IPv6 addresses in brackets, indented messages.
 *
 * Payloads are emitted as Buffers of the exact SIP text, CRLF-normalized; a
 * Content-Length header that no longer matches the normalized body is patched
 * so downstream TCP stream framing (lib/sip.js) stays consistent.
 *
 * Zero runtime dependencies. CommonJS.
 */

const DEFAULT_PORT = 5060;

const MONTHS = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

// SIP start lines (evaluated against a single, already-split line).
const REQ_LINE = /^[A-Z][A-Z0-9_-]{0,15}\s+\S+\s+SIP\/2\.0\s*$/;
const STATUS_LINE = /^SIP\/2\.0\s+\d{3}(?:\s.*)?$/;

// Dashed block separator, any length >= 10.
const SEPARATOR = /^\s*-{10,}\s*$/;

// Acme/Oracle sipmsg.log envelope. Groups:
// 1 month, 2 day, 3 year (optional), 4 h, 5 m, 6 s, 7 frac (optional),
// 8 On-address, 9 direction phrase, 10 peer address.
// The [slot:port] bracket is digits-only, so a bracketed IPv6 address
// ([2001:db8::5]) never matches it and falls through to the address capture.
const ACME_ENV = /([A-Za-z]{3})\s+(\d{1,2})(?:\s+(\d{4}))?\s+(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?\s+On\s+(?:\[\d{1,3}:\d{1,5}\])?\s*(?:(?:TCP|TLS|UDP|SCTP)\s+)?(\S+)\s+(received\s+from|sent\s+to)\s+(?:(?:TCP|TLS|UDP|SCTP)\s+)?(?:\[\d{1,3}:\d{1,5}\])?\s*(\S+)/i;

// sngrep/sipgrep envelope. Groups:
// 1 transport letter, 2 year, 3 month, 4 day, 5 h, 6 m, 7 s, 8 frac, 9 src, 10 dst.
const SNGREP_ENV = /^\s*([UTRutr])\s+(\d{4})[/-](\d{1,2})[/-](\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?\s+(\S+)\s+-+>\s+(\S+)/;

/**
 * Is this line a SIP request-line or status-line (ignoring leading indent)?
 * @param {string} line
 * @returns {boolean}
 */
function isStartLine(line) {
  const t = line.replace(/^\s+/, '');
  return REQ_LINE.test(t) || STATUS_LINE.test(t);
}

/**
 * Parse an `addr`, `addr:port`, `[v6]` or `[v6]:port` token. Port defaults 5060.
 * @param {string} token
 * @returns {{ip: string, port: number}}
 */
function parseAddr(token) {
  let t = String(token == null ? '' : token).replace(/[),.;]+$/, '');
  const bm = /^\[([^\]]+)\](?::(\d+))?$/.exec(t);
  if (bm) return { ip: bm[1], port: bm[2] ? parseInt(bm[2], 10) : DEFAULT_PORT };
  const firstC = t.indexOf(':');
  const lastC = t.lastIndexOf(':');
  if (lastC !== -1 && firstC === lastC && /^\d+$/.test(t.slice(lastC + 1))) {
    return { ip: t.slice(0, lastC), port: parseInt(t.slice(lastC + 1), 10) };
  }
  // Bare IPv6 (multiple colons, no brackets) or plain host/IPv4 with no port.
  return { ip: t, port: DEFAULT_PORT };
}

/**
 * Local-time epoch seconds (float) from timestamp parts.
 * @param {number} year @param {number} mon 0-based @param {number} day
 * @param {number} h @param {number} mi @param {number} s
 * @param {string|undefined} frac fractional-second digits
 * @returns {number}
 */
function makeTs(year, mon, day, h, mi, s, frac) {
  const base = new Date(year, mon, day, h, mi, s, 0).getTime() / 1000;
  return frac ? base + parseFloat('0.' + frac) : base;
}

/**
 * Consume one SIP message from lines[], starting at a start line.
 * Content-Length-aware: a body may contain blank lines without ending the
 * message (multi-part / unusual SDP), and trailing junk is not absorbed.
 * If the start line is indented, that exact indent is stripped from the block.
 * @param {string[]} lines
 * @param {number} i index of the start line
 * @param {number} end exclusive scan limit
 * @returns {{headerLines: string[], bodyLines: string[], next: number}}
 */
function consumeMessage(lines, i, end) {
  const indent = /^\s*/.exec(lines[i])[0];
  const ded = indent
    ? (l) => (l.startsWith(indent) ? l.slice(indent.length) : l)
    : (l) => l;

  const headerLines = [ded(lines[i])];
  i++;
  while (i < end && lines[i].trim() !== '' && !isStartLine(lines[i]) && !SEPARATOR.test(lines[i])) {
    headerLines.push(ded(lines[i]));
    i++;
  }

  let cl = null;
  for (let k = 1; k < headerLines.length; k++) {
    const m = /^(?:content-length|l)\s*:\s*(\d+)\s*$/i.exec(headerLines[k]);
    if (m) { cl = parseInt(m[1], 10); break; }
  }

  const bodyLines = [];
  if (i < end && lines[i].trim() === '') {
    i++; // blank line ending the headers
    if (cl === null) {
      // No Content-Length: take body lines up to the next blank line,
      // start line, or separator.
      while (i < end && lines[i].trim() !== '' && !isStartLine(lines[i]) && !SEPARATOR.test(lines[i])) {
        bodyLines.push(ded(lines[i]));
        i++;
      }
    } else if (cl > 0) {
      // Content-Length known: blank lines inside the body do not end the
      // message until the declared length is satisfied (counted as CRLF).
      let bytes = 0;
      while (i < end) {
        const line = ded(lines[i]);
        if (bytes >= cl && (line.trim() === '' || isStartLine(line) || SEPARATOR.test(line))) break;
        bodyLines.push(line);
        bytes += Buffer.byteLength(line, 'utf8') + 2;
        i++;
      }
    }
  }
  return { headerLines, bodyLines, next: i };
}

/**
 * CRLF-join a consumed message into a Buffer, patching Content-Length if the
 * normalized body length no longer matches the declared value.
 * @param {string[]} headerLines
 * @param {string[]} bodyLines
 * @returns {Buffer}
 */
function buildPayload(headerLines, bodyLines) {
  const body = bodyLines.length ? bodyLines.join('\r\n') + '\r\n' : '';
  const actual = Buffer.byteLength(body, 'utf8');
  const hl = headerLines.slice();
  for (let k = 1; k < hl.length; k++) {
    const m = /^((?:content-length|l)\s*:\s*)(\d+)\s*$/i.exec(hl[k]);
    if (m) {
      if (parseInt(m[2], 10) !== actual) hl[k] = m[1] + actual;
      break;
    }
  }
  return Buffer.from(hl.join('\r\n') + '\r\n\r\n' + body, 'utf8');
}

/**
 * Find and consume the first SIP message inside a block (skips leading noise).
 * @param {string[]} lines @param {number} start @param {number} end
 * @returns {Buffer|null}
 */
function extractFromBlock(lines, start, end) {
  let s = start;
  while (s < end && !isStartLine(lines[s])) s++;
  if (s >= end) return null;
  const cm = consumeMessage(lines, s, end);
  return buildPayload(cm.headerLines, cm.bodyLines);
}

/**
 * First header value matching one of the (lowercase) names, or null.
 * @param {string[]} headerLines @param {string[]} names
 * @returns {string|null}
 */
function getHeaderValue(headerLines, names) {
  for (let k = 1; k < headerLines.length; k++) {
    const m = /^([A-Za-z][\w.-]*)\s*:\s*(.*)$/.exec(headerLines[k]);
    if (m && names.indexOf(m[1].toLowerCase()) !== -1) return m[2].trim();
  }
  return null;
}

/**
 * Parse the top Via: transport + sent-by address. Null when absent/unparsable.
 * @param {string[]} headerLines
 * @returns {{transport: ('udp'|'tcp'), addr: {ip: string, port: number}}|null}
 */
function topVia(headerLines) {
  for (let k = 1; k < headerLines.length; k++) {
    const m = /^(?:via|v)\s*:\s*(.+)$/i.exec(headerLines[k]);
    if (!m) continue;
    const firstVal = m[1].split(',')[0];
    const vm = /SIP\s*\/\s*2\.0\s*\/\s*([A-Za-z]+)\s+([^\s;,]+)/.exec(firstVal);
    if (!vm) return null;
    const transport = /^(?:tcp|tls|sctp|ws|wss)$/i.test(vm[1]) ? 'tcp' : 'udp';
    return { transport, addr: parseAddr(vm[2]) };
  }
  return null;
}

/**
 * Host:port from a SIP URI (request-URI), or null.
 * @param {string} uri
 * @returns {{ip: string, port: number}|null}
 */
function uriHostAddr(uri) {
  let s = String(uri || '').trim().replace(/^</, '').replace(/>$/, '');
  s = s.replace(/^(?:sips?|tel):/i, '');
  const at = s.lastIndexOf('@');
  if (at !== -1) s = s.slice(at + 1);
  s = s.split(/[;?]/)[0].trim();
  if (!s) return null;
  return parseAddr(s);
}

/**
 * Decide which of the three formats this text is. Acme wins over sngrep when
 * both kinds of envelope appear (an sngrep line inside an Acme export is noise
 * and vice versa — pick the majority, Acme on ties).
 * @param {string[]} lines
 * @returns {'acme-log'|'sngrep'|'raw-sip'}
 */
function detectFormat(lines) {
  let acme = 0;
  let sngrep = 0;
  for (let i = 0; i < lines.length; i++) {
    if (ACME_ENV.test(lines[i])) acme++;
    else if (SNGREP_ENV.test(lines[i])) sngrep++;
  }
  if (acme > 0 && acme >= sngrep) return 'acme-log';
  if (sngrep > 0) return 'sngrep';
  return 'raw-sip';
}

/**
 * Parse Acme/Oracle sipmsg.log-style text.
 * @param {string[]} lines @param {string[]} warnings @param {number} refYear
 * @returns {Array<Object>} partial packets ({ts,src,dst,sport,dport,transport,payload})
 */
function parseAcme(lines, warnings, refYear) {
  const packets = [];
  let lastTs = 0;
  let i = 0;
  while (i < lines.length) {
    const m = ACME_ENV.exec(lines[i]);
    if (!m) { i++; continue; }
    const envLineNo = i + 1;
    const envLine = lines[i];

    // Block: everything up to the next separator or envelope line.
    let end = i + 1;
    while (end < lines.length && !SEPARATOR.test(lines[end]) && !ACME_ENV.test(lines[end])) end++;

    const monKey = m[1].charAt(0).toUpperCase() + m[1].slice(1).toLowerCase();
    const mon = MONTHS[monKey];
    let ts;
    if (mon === undefined) {
      warnings.push('line ' + envLineNo + ': unrecognised month "' + m[1] + '" — reusing previous timestamp');
      ts = lastTs + 0.001;
    } else {
      const year = m[3] ? parseInt(m[3], 10) : refYear;
      ts = makeTs(year, mon, parseInt(m[2], 10), parseInt(m[4], 10), parseInt(m[5], 10), parseInt(m[6], 10), m[7]);
    }
    lastTs = ts;

    const onAddr = parseAddr(m[8]);
    const peer = parseAddr(m[10]);
    const received = /received/i.test(m[9]);
    const transport = /\b(?:tcp|tls)\b/i.test(envLine) ? 'tcp' : 'udp';

    const payload = extractFromBlock(lines, i + 1, end);
    if (!payload) {
      warnings.push('line ' + envLineNo + ': envelope without a SIP message — skipped');
    } else {
      packets.push({
        ts,
        src: received ? peer.ip : onAddr.ip,
        sport: received ? peer.port : onAddr.port,
        dst: received ? onAddr.ip : peer.ip,
        dport: received ? onAddr.port : peer.port,
        transport,
        payload,
      });
    }
    i = end;
  }
  return packets;
}

/**
 * Parse sngrep/sipgrep-style text. 'U' → udp; 'T'/'R' → tcp.
 * @param {string[]} lines @param {string[]} warnings
 * @returns {Array<Object>} partial packets
 */
function parseSngrep(lines, warnings) {
  const packets = [];
  let i = 0;
  while (i < lines.length) {
    const m = SNGREP_ENV.exec(lines[i]);
    if (!m) { i++; continue; }
    const envLineNo = i + 1;

    let end = i + 1;
    while (end < lines.length && !SNGREP_ENV.test(lines[end]) && !SEPARATOR.test(lines[end])) end++;

    const transport = m[1].toUpperCase() === 'U' ? 'udp' : 'tcp';
    const ts = makeTs(
      parseInt(m[2], 10), parseInt(m[3], 10) - 1, parseInt(m[4], 10),
      parseInt(m[5], 10), parseInt(m[6], 10), parseInt(m[7], 10), m[8]
    );
    const src = parseAddr(m[9]);
    const dst = parseAddr(m[10]);

    const payload = extractFromBlock(lines, i + 1, end);
    if (!payload) {
      warnings.push('line ' + envLineNo + ': sngrep envelope without a SIP message — skipped');
    } else {
      packets.push({
        ts,
        src: src.ip, sport: src.port,
        dst: dst.ip, dport: dst.port,
        transport,
        payload,
      });
    }
    i = end;
  }
  return packets;
}

/**
 * Parse bare concatenated SIP messages. No addresses in the file, so src/dst
 * are synthesized: requests flow top-Via → request-URI host; responses flow
 * back to the top Via, with the far side recovered from the request already
 * seen on the same Call-ID; 'unknown-a'/'unknown-b' otherwise.
 * ts is synthetic: file order, 10ms apart, from 0.
 * @param {string[]} lines @param {string[]} warnings
 * @returns {Array<Object>} partial packets
 */
function parseRaw(lines, warnings) {
  const packets = [];
  const callMap = new Map(); // Call-ID -> {src, dst} of the first request seen
  const UNKNOWN_A = { ip: 'unknown-a', port: DEFAULT_PORT };
  const UNKNOWN_B = { ip: 'unknown-b', port: DEFAULT_PORT };
  let i = 0;
  while (i < lines.length) {
    if (!isStartLine(lines[i])) { i++; continue; }
    const cm = consumeMessage(lines, i, lines.length);
    i = cm.next;

    const payload = buildPayload(cm.headerLines, cm.bodyLines);
    const startLine = cm.headerLines[0];
    const isReq = !/^SIP\/2\.0/.test(startLine);
    const via = topVia(cm.headerLines);
    const callId = getHeaderValue(cm.headerLines, ['call-id', 'i']);

    let src;
    let dst;
    if (isReq) {
      src = via ? via.addr : UNKNOWN_A;
      dst = uriHostAddr(startLine.split(/\s+/)[1]) || UNKNOWN_B;
      if (callId && !callMap.has(callId)) callMap.set(callId, { src, dst });
    } else {
      dst = via ? via.addr : UNKNOWN_A;
      const rec = callId ? callMap.get(callId) : null;
      if (rec) {
        src = rec.src.ip === dst.ip ? rec.dst : (rec.dst.ip === dst.ip ? rec.src : rec.dst);
      } else {
        src = UNKNOWN_B;
      }
    }

    packets.push({
      ts: packets.length * 0.01,
      src: src.ip, sport: src.port,
      dst: dst.ip, dport: dst.port,
      transport: via ? via.transport : 'udp',
      payload,
    });
  }
  if (packets.length === 0 && warnings) {
    // caller adds the generic empty warning
  }
  return packets;
}

/**
 * Parse a SIP text log (Acme/Oracle sipmsg.log export, sngrep/sipgrep output,
 * or bare concatenated SIP messages) into the shared Packet[] shape.
 *
 * @param {string|Buffer} text log text (Buffer decoded as UTF-8; BOM stripped)
 * @param {number} [refYear] year assumed for timestamps that carry none
 *   (Acme logs usually omit it); defaults to the current year, captured once.
 * @returns {{format: ('acme-log'|'sngrep'|'raw-sip'), warnings: string[], packets: Array<{
 *   n: number, ts: number, src: string, dst: string, sport: number, dport: number,
 *   transport: ('udp'|'tcp'), payload: Buffer,
 *   tcp: ({seq: number, syn: boolean, fin: boolean}|undefined),
 *   fragmented: boolean, wireBytes: number}>}}
 */
function parseTextLog(text, refYear) {
  let str = Buffer.isBuffer(text) ? text.toString('utf8') : String(text == null ? '' : text);
  if (str.charCodeAt(0) === 0xFEFF) str = str.slice(1);
  const year = (refYear != null && Number.isFinite(+refYear)) ? +refYear : new Date().getFullYear();

  const lines = str.split(/\r\n|\n|\r/);
  const warnings = [];
  const format = detectFormat(lines);

  let partials;
  if (format === 'acme-log') partials = parseAcme(lines, warnings, year);
  else if (format === 'sngrep') partials = parseSngrep(lines, warnings);
  else partials = parseRaw(lines, warnings);

  if (partials.length === 0) warnings.push('no SIP messages found in text input');

  // Finalize into the frozen Packet shape; give TCP packets a coherent
  // per-flow synthetic seq so downstream stream framing/ordering works.
  const flows = new Map();
  const packets = partials.map((p, idx) => {
    const pk = {
      n: idx + 1,
      ts: p.ts,
      src: p.src,
      dst: p.dst,
      sport: p.sport,
      dport: p.dport,
      transport: p.transport,
      payload: p.payload,
      tcp: undefined,
      fragmented: false,
      wireBytes: p.payload.length,
    };
    if (p.transport === 'tcp') {
      const key = p.src + '|' + p.sport + '|' + p.dst + '|' + p.dport;
      const cur = flows.get(key) || 0;
      pk.tcp = { seq: cur, syn: false, fin: false };
      flows.set(key, cur + p.payload.length);
    }
    return pk;
  });

  if (warnings.length > 200) {
    const extra = warnings.length - 200;
    warnings.length = 200;
    warnings.push('…and ' + extra + ' more warnings');
  }

  return { format, warnings, packets };
}

/**
 * Cheap content sniff: is this buffer plausibly a SIP text log parseTextLog
 * can handle? Printable-ratio check (no NUL bytes, >= 90% printable/UTF-8)
 * plus at least one SIP request/status line or a recognised envelope line.
 * Used by analyze.js after the pcap magic checks fail.
 *
 * @param {Buffer|string} buffer
 * @returns {boolean}
 */
function sniffText(buffer) {
  const buf = Buffer.isBuffer(buffer)
    ? buffer
    : Buffer.from(String(buffer == null ? '' : buffer), 'utf8');
  if (buf.length === 0) return false;

  const sample = buf.length > 65536 ? buf.subarray(0, 65536) : buf;
  let printable = 0;
  for (let i = 0; i < sample.length; i++) {
    const b = sample[i];
    if (b === 0) return false;
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126) || b >= 128) printable++;
  }
  if (printable / sample.length < 0.9) return false;

  const text = sample.toString('utf8');
  if (/^[ \t]*[A-Z][A-Z0-9_-]{0,15}[ \t]+\S+[ \t]+SIP\/2\.0[ \t]*$/m.test(text)) return true;
  if (/^[ \t]*SIP\/2\.0[ \t]+\d{3}\b/m.test(text)) return true;
  if (/\bOn\s+(?:\[\d{1,3}:\d{1,5}\])?\s*\S+\s+(?:received\s+from|sent\s+to)\s+\S+/i.test(text)) return true;
  if (/^[ \t]*[UTRutr][ \t]+\d{4}[/-]\d{1,2}[/-]\d{1,2}[ \t]+\d{1,2}:\d{2}:\d{2}/m.test(text)) return true;
  return false;
}

module.exports = { parseTextLog, sniffText };
