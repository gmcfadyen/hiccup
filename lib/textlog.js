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
 * A body is bounded by the declared Content-Length AND by the next message
 * boundary, whichever comes first: a Content-Length larger than the body the
 * capture actually holds (routine in truncated exports and elided SDP) cannot
 * swallow the messages that follow it, and the shortfall is reported as a
 * warning rather than passing silently.
 *
 * Zero runtime dependencies. CommonJS.
 */

const DEFAULT_PORT = 5060;

const MONTHS = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

// SIP start lines (evaluated against a single, already-split line).
//
// Built from two shared sources so the parser and sniffText() can never
// disagree about what a start line is.
//
// What was relaxed (both were recorded as known RFC 4475 gaps):
//  - the method is RFC 3261's `token` charset (alphanum plus "-.!%*_+`'~"),
//    not just [A-Z0-9_-], so a %-escaped method name (`RE%47IST%45R`,
//    RFC 4475 esc02) is recognised instead of silently vanishing;
//  - the version is any SIP/<digits>.<digits>, not a hardcoded SIP/2.0, and
//    the status code is 1-10 digits, not exactly 3 — so a version-check
//    request (`SIP/7.0`, RFC 4475 badvers) and an out-of-range status code
//    (RFC 4475 bigcode) are at least SEEN.
//
// What was deliberately NOT relaxed, because a false positive here splits one
// message into two — and, since a start line now also bounds a body (see
// consumeMessage), truncates the previous message as well:
//  - the method must start with an uppercase letter and contains no lowercase
//    letters and no ":", so neither prose ("Discarding this INVITE...") nor a
//    header line ("User-Agent: FooBox SIP/2.0") can pose as a request line;
//  - the request-URI must contain a ":". RFC 3261's Request-URI is a SIP,
//    SIPS or absoluteURI and every one of those carries a scheme, so this
//    costs nothing on well-formed input while ruling out the realistic log
//    chatter shape `WORD WORD SIP/2.0` (e.g. "RETRANSMIT INVITE SIP/2.0");
//  - both stay anchored ^...$ against ONE already-split line, so a SIP/2.0
//    mention anywhere inside a line never matches;
//  - the digit runs are bounded ({1,3}, {1,10}) rather than open-ended.
const METHOD_TOKEN = "[A-Z][A-Z0-9\\-.!%*_+`'~]{0,31}";
const SIP_VERSION = 'SIP\\/\\d{1,3}\\.\\d{1,3}';
const REQ_URI = '[^\\s:]+:\\S*';
const REQ_LINE = new RegExp('^' + METHOD_TOKEN + '\\s+' + REQ_URI + '\\s+' + SIP_VERSION + '\\s*$');
const STATUS_LINE = new RegExp('^' + SIP_VERSION + '\\s+\\d{1,10}(?:\\s.*)?$');

// Multiline variants for sniffText(), which scans a whole buffer rather than
// one line: same sources, plus the leading indent isStartLine() strips, and
// [ \t] instead of \s so a field separator can never eat a line break.
const REQ_LINE_ANYWHERE = new RegExp(
  '^[ \\t]*' + METHOD_TOKEN + '[ \\t]+' + REQ_URI + '[ \\t]+' + SIP_VERSION + '[ \\t]*$', 'm');
const STATUS_LINE_ANYWHERE = new RegExp(
  '^[ \\t]*' + SIP_VERSION + '[ \\t]+\\d{1,10}(?:[ \\t].*)?$', 'm');

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
 *
 * The body is bounded by the EARLIEST of: the declared Content-Length being
 * satisfied, the next SIP start line, a dashed separator, or the end of the
 * scan range. A capture that declares more body than it actually contains
 * (routine in truncated sipmsg.log exports and elided SDP) therefore stops at
 * the next message instead of swallowing the rest of the file, and pushes a
 * warning naming the shortfall.
 *
 * @param {string[]} lines
 * @param {number} i index of the start line
 * @param {number} end exclusive scan limit
 * @param {string[]} [warnings] collector for a short-body warning
 * @returns {{headerLines: string[], bodyLines: string[], next: number}}
 */
function consumeMessage(lines, i, end, warnings) {
  const startLineNo = i + 1;
  // What "we ran out of lines" means depends on the caller: the whole file
  // for raw-sip, one envelope's block for acme-log/sngrep.
  const RAN_OUT = end >= lines.length ? 'end of input' : 'the end of the log block';
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

  // Body types that may legitimately contain a line that IS a SIP start line:
  // message/sipfrag (RFC 3420 — a REFER's NOTIFY carries "SIP/2.0 200 OK" as
  // its entire body) and any multipart container that could wrap one. For
  // those, and only those, a start line is not treated as a body boundary —
  // otherwise the commonest transfer trace in the product's own problem
  // domain would be split into a body-less NOTIFY plus a phantom message.
  const ctype = getHeaderValue(headerLines, ['content-type', 'c']) || '';
  const nestedSip = /^\s*(?:message\/|multipart\/)/i.test(ctype);

  const bodyLines = [];
  let short = null; // {got: number, stopped: string} when the body ran out early
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
      // Anything that starts the NEXT message still ends it, satisfied or not.
      let bytes = 0;
      let stopped = RAN_OUT;
      while (i < end) {
        const line = ded(lines[i]);
        const isSep = SEPARATOR.test(line);
        const isStart = isStartLine(line);
        if (bytes >= cl) {
          if (line.trim() === '' || isStart || isSep) break;
        } else if (isSep || (isStart && !nestedSip)) {
          stopped = isSep ? 'the log separator' : 'the next message boundary';
          break;
        }
        bodyLines.push(line);
        bytes += Buffer.byteLength(line, 'utf8') + 2;
        i++;
      }
      if (bytes < cl) short = { got: bytes, stopped };
    }
  } else if (cl !== null && cl > 0) {
    // Headers ended without the blank line that introduces a body: the
    // message was cut off at the header block, so nothing of the declared
    // body was captured.
    short = {
      got: 0,
      stopped: i >= end ? RAN_OUT
        : (SEPARATOR.test(lines[i]) ? 'the log separator' : 'the next message boundary'),
    };
  }
  if (short && warnings) {
    warnings.push('line ' + startLineNo + ': declared Content-Length ' + cl +
      ' exceeds captured body (' + short.got + ' bytes) — body truncated at ' + short.stopped);
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
 * @param {string[]} [warnings] collector passed through to consumeMessage
 * @returns {Buffer|null}
 */
function extractFromBlock(lines, start, end, warnings) {
  let s = start;
  while (s < end && !isStartLine(lines[s])) s++;
  if (s >= end) return null;
  const cm = consumeMessage(lines, s, end, warnings);
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

    const payload = extractFromBlock(lines, i + 1, end, warnings);
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

    const payload = extractFromBlock(lines, i + 1, end, warnings);
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
    const cm = consumeMessage(lines, i, lines.length, warnings);
    i = cm.next;

    const payload = buildPayload(cm.headerLines, cm.bodyLines);
    const startLine = cm.headerLines[0];
    // Version-agnostic, or a SIP/7.0 status line would be mistaken for a
    // request now that STATUS_LINE no longer hardcodes SIP/2.0.
    const isReq = !STATUS_LINE.test(startLine);
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
  // Same start-line definition as the parser (see REQ_LINE/STATUS_LINE): a
  // file the parser would happily read must never be told it is not SIP text.
  if (REQ_LINE_ANYWHERE.test(text)) return true;
  if (STATUS_LINE_ANYWHERE.test(text)) return true;
  if (/\bOn\s+(?:\[\d{1,3}:\d{1,5}\])?\s*\S+\s+(?:received\s+from|sent\s+to)\s+\S+/i.test(text)) return true;
  if (/^[ \t]*[UTRutr][ \t]+\d{4}[/-]\d{1,2}[/-]\d{1,2}[ \t]+\d{1,2}:\d{2}:\d{2}/m.test(text)) return true;
  return false;
}

module.exports = { parseTextLog, sniffText };
