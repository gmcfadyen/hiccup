'use strict';
/**
 * lib/sip.js — SIP + SDP parsing and leg (dialog) grouping for hiccup.
 *
 * Exports (per ARCHITECTURE.md, frozen contract):
 *   extractSipMessages(packets) -> [SipMessage]
 *   parseSipMessage(text)       -> parsed message fields | null
 *   parseSdp(text)              -> Sdp
 *   getHeader(msg, name)        -> first value | null
 *   getHeaders(msg, name)       -> [values]
 *   groupSipLegs(messages)      -> [Leg]
 *
 * Zero runtime dependencies. Never throws on garbage input — unparseable
 * units are skipped.
 */

// ---------------------------------------------------------------------------
// Header name canonicalization (compact forms per contract)
// ---------------------------------------------------------------------------

const COMPACT = {
  f: 'from',
  t: 'to',
  i: 'call-id',
  m: 'contact',
  v: 'via',
  c: 'content-type',
  l: 'content-length',
  k: 'supported',
};

/**
 * Canonicalize a header name: lowercase + compact-form expansion.
 * @param {string} name
 * @returns {string}
 */
function canonName(name) {
  const n = String(name || '').trim().toLowerCase();
  return COMPACT[n] || n;
}

/**
 * Get the first value of a header on a parsed SIP message, case-insensitive
 * and compact-form aware (f=From, t=To, i=Call-ID, m=Contact, v=Via,
 * c=Content-Type, l=Content-Length, k=Supported).
 * @param {object} msg - parsed SIP message (must have headers[])
 * @param {string} name - header name (full or compact, any case)
 * @returns {string|null} first value or null
 */
function getHeader(msg, name) {
  const all = getHeaders(msg, name);
  return all.length ? all[0] : null;
}

/**
 * Get all values of a header on a parsed SIP message, case-insensitive and
 * compact-form aware. Values are returned exactly as stored in headers[]
 * (comma-combined values are NOT split here).
 * @param {object} msg - parsed SIP message (must have headers[])
 * @param {string} name - header name (full or compact, any case)
 * @returns {string[]} values in original order (empty array when absent)
 */
function getHeaders(msg, name) {
  const out = [];
  if (!msg || !Array.isArray(msg.headers)) return out;
  const want = canonName(name);
  for (const h of msg.headers) {
    if (h && canonName(h.name) === want) out.push(h.value);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

/**
 * Split a comma-combined header value into individual entries, respecting
 * double-quoted strings and angle brackets (so commas inside <sip:...> or
 * "display, name" do not split).
 * @param {string} value
 * @returns {string[]}
 */
function splitCombined(value) {
  const out = [];
  if (typeof value !== 'string') return out;
  let cur = '';
  let quote = false;
  let angle = 0;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (quote) {
      cur += ch;
      if (ch === '\\' && i + 1 < value.length) { cur += value[++i]; continue; }
      if (ch === '"') quote = false;
      continue;
    }
    if (ch === '"') { quote = true; cur += ch; continue; }
    if (ch === '<') { angle++; cur += ch; continue; }
    if (ch === '>') { if (angle > 0) angle--; cur += ch; continue; }
    if (ch === ',' && angle === 0) {
      const t = cur.trim();
      if (t) out.push(t);
      cur = '';
      continue;
    }
    cur += ch;
  }
  const t = cur.trim();
  if (t) out.push(t);
  return out;
}

/**
 * Parse a From/To/Contact style address header value.
 * @param {string} value
 * @returns {{uri: string|null, tag: string|null}}
 */
function parseAddress(value) {
  const res = { uri: null, tag: null };
  if (typeof value !== 'string' || !value.trim()) return res;
  const v = value.trim();
  let params = '';
  const lt = v.indexOf('<');
  if (lt >= 0) {
    const gt = v.indexOf('>', lt + 1);
    if (gt > lt) {
      res.uri = v.slice(lt + 1, gt).trim() || null;
      params = v.slice(gt + 1);
    } else {
      res.uri = v.slice(lt + 1).trim() || null;
    }
  } else {
    // no angle brackets: addr-spec up to first ';', rest are header params
    const sc = v.indexOf(';');
    if (sc >= 0) {
      res.uri = v.slice(0, sc).trim() || null;
      params = v.slice(sc);
    } else {
      res.uri = v.trim() || null;
    }
  }
  const m = /(?:^|;)\s*tag\s*=\s*([^;\s]+)/i.exec(params);
  if (m) res.tag = m[1];
  return res;
}

/**
 * Extract the user part of a SIP/SIPS/TEL URI ('alice' from sip:alice@a.com,
 * '+33612345678' from tel:+33612345678). Null when there is no user part.
 * @param {string|null} uri
 * @returns {string|null}
 */
function uriUser(uri) {
  if (typeof uri !== 'string') return null;
  let m = /^\s*sips?:([^@;?>\s]+)@/i.exec(uri);
  if (m) return m[1];
  m = /^\s*tel:([^;?>\s]+)/i.exec(uri);
  if (m) return m[1];
  return null;
}

/** Static payload-type fallback table (pt -> {codec, rate}). */
const STATIC_PT = {
  0: { codec: 'PCMU', rate: 8000 },
  3: { codec: 'GSM', rate: 8000 },
  4: { codec: 'G723', rate: 8000 },
  8: { codec: 'PCMA', rate: 8000 },
  9: { codec: 'G722', rate: 8000 },
  18: { codec: 'G729', rate: 8000 },
};

// ---------------------------------------------------------------------------
// SDP
// ---------------------------------------------------------------------------

/**
 * Parse an SDP body per the contract shape. Never throws — unparseable
 * lines are skipped, missing sections come back null/empty.
 * @param {string} text - raw SDP text
 * @returns {{origin: {user: string|null, sessId: string|null, sessVersion: string|null, addr: string|null},
 *            connection: string|null,
 *            media: Array<{type: string, port: number, proto: string,
 *              payloads: Array<{pt: number, codec: string|null, rate: number|null, fmtp: string|null}>,
 *              ptime: number|null, direction: string|null, attrs: string[]}>,
 *            sessionAttrs: string[], raw: string}}
 */
function parseSdp(text) {
  const sdp = {
    origin: { user: null, sessId: null, sessVersion: null, addr: null },
    connection: null,
    media: [],
    sessionAttrs: [],
    raw: typeof text === 'string' ? text : '',
  };
  if (typeof text !== 'string' || !text) return sdp;
  try {
    const lines = text.split(/\r\n|\n|\r/);
    let cur = null; // current media block, or null while in session section
    let curPayloadsByPt = null;
    let sessionDirection = null;
    let firstMediaConn = null;
    const DIRECTIONS = { sendrecv: 1, sendonly: 1, recvonly: 1, inactive: 1 };

    for (const rawLine of lines) {
      const line = rawLine.replace(/\s+$/, '');
      if (line.length < 2 || line[1] !== '=') continue;
      const kind = line[0];
      const val = line.slice(2);

      if (kind === 'o') {
        const parts = val.trim().split(/\s+/);
        if (parts.length >= 6) {
          sdp.origin = {
            user: parts[0],
            sessId: parts[1],
            sessVersion: parts[2],
            addr: parts[5],
          };
        }
        continue;
      }
      if (kind === 'c') {
        const parts = val.trim().split(/\s+/);
        const addr = parts.length >= 3 ? parts[2].split('/')[0] : null;
        if (!addr) continue;
        if (cur === null) {
          if (sdp.connection === null) sdp.connection = addr;
        } else if (firstMediaConn === null) {
          firstMediaConn = addr;
        }
        continue;
      }
      if (kind === 'm') {
        const parts = val.trim().split(/\s+/);
        if (parts.length < 3) { cur = null; curPayloadsByPt = null; continue; }
        cur = {
          type: parts[0],
          port: parseInt(parts[1], 10) || 0,
          proto: parts[2],
          payloads: [],
          ptime: null,
          direction: null,
          attrs: [],
        };
        curPayloadsByPt = {};
        for (let i = 3; i < parts.length; i++) {
          if (!/^\d+$/.test(parts[i])) continue; // non-RTP fmts (e.g. udptl t38)
          const pt = parseInt(parts[i], 10);
          const stat = STATIC_PT[pt] || null;
          const p = {
            pt,
            codec: stat ? stat.codec : null,
            rate: stat ? stat.rate : null,
            fmtp: null,
          };
          cur.payloads.push(p);
          if (!(pt in curPayloadsByPt)) curPayloadsByPt[pt] = p;
        }
        sdp.media.push(cur);
        continue;
      }
      if (kind === 'a') {
        const attrLine = 'a=' + val;
        if (cur === null) {
          sdp.sessionAttrs.push(attrLine);
          const d = val.trim().toLowerCase();
          if (DIRECTIONS[d]) sessionDirection = d;
          continue;
        }
        cur.attrs.push(attrLine);
        let m = /^rtpmap:(\d+)\s+([^\s/]+)\/(\d+)/i.exec(val.trim());
        if (m) {
          const p = curPayloadsByPt[parseInt(m[1], 10)];
          if (p) { p.codec = m[2]; p.rate = parseInt(m[3], 10); }
          continue;
        }
        m = /^fmtp:(\d+)\s+(.*)$/i.exec(val.trim());
        if (m) {
          const p = curPayloadsByPt[parseInt(m[1], 10)];
          if (p) p.fmtp = m[2];
          continue;
        }
        m = /^ptime:\s*(\d+)/i.exec(val.trim());
        if (m) { cur.ptime = parseInt(m[1], 10); continue; }
        const d = val.trim().toLowerCase();
        if (DIRECTIONS[d]) cur.direction = d;
        continue;
      }
      // other line kinds (v=, s=, t=, b=, ...) are ignored
    }

    // direction inheritance: media-level wins, else session-level, else null
    if (sessionDirection) {
      for (const mb of sdp.media) {
        if (mb.direction === null) mb.direction = sessionDirection;
      }
    }
    if (sdp.connection === null && firstMediaConn !== null) {
      sdp.connection = firstMediaConn;
    }
  } catch (e) {
    // never throw on garbage — return whatever was accumulated
  }
  return sdp;
}

// ---------------------------------------------------------------------------
// SIP message parsing
// ---------------------------------------------------------------------------

const REQUEST_LINE_RE = /^([A-Z]+)\s+(\S+)\s+SIP\/2\.0\s*$/;
const STATUS_LINE_RE = /^SIP\/2\.0\s+(\d{3})\s*(.*)$/;

/**
 * Find the header/body separator in a SIP message text.
 * @param {string} text
 * @returns {{idx: number, len: number}} idx=-1 when not found
 */
function findHeaderEnd(text) {
  const a = text.indexOf('\r\n\r\n');
  const b = text.indexOf('\n\n');
  if (a >= 0 && (b < 0 || a <= b)) return { idx: a, len: 4 };
  if (b >= 0) return { idx: b, len: 2 };
  return { idx: -1, len: 0 };
}

/**
 * Parse one complete SIP message from text. Returns the parsed message
 * fields (protocol/raw/size/isRequest/method/... per the SipMessage contract,
 * minus the transport envelope which extractSipMessages fills in), or null
 * when the text is not a parseable SIP message. Never throws.
 * @param {string} text - full SIP message, CRLF or LF line endings
 * @returns {object|null}
 */
function parseSipMessage(text) {
  try {
    if (typeof text !== 'string' || !text) return null;

    const sep = findHeaderEnd(text);
    const headerPart = sep.idx >= 0 ? text.slice(0, sep.idx) : text;
    let body = sep.idx >= 0 ? text.slice(sep.idx + sep.len) : '';

    const lines = headerPart.split(/\r\n|\n|\r/);
    if (!lines.length) return null;
    const startLine = lines[0];

    let isRequest = false;
    let method = null;
    let requestUri = null;
    let status = null;
    let reason = null;

    let m = REQUEST_LINE_RE.exec(startLine);
    if (m && m[1] !== 'SIP') {
      isRequest = true;
      method = m[1];
      requestUri = m[2];
    } else {
      m = STATUS_LINE_RE.exec(startLine);
      if (!m) return null;
      status = parseInt(m[1], 10);
      reason = m[2].trim() || null;
    }

    // headers: preserve order + case, fold continuation lines (leading WS)
    const headers = [];
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (line === '') continue;
      if (/^[ \t]/.test(line)) {
        if (headers.length) {
          headers[headers.length - 1].value =
            (headers[headers.length - 1].value + ' ' + line.trim()).trim();
        }
        continue;
      }
      const colon = line.indexOf(':');
      if (colon <= 0) continue; // not a header line — skip garbage
      const name = line.slice(0, colon).trim();
      const value = line.slice(colon + 1).trim();
      if (!name) continue;
      headers.push({ name, value });
    }

    const msg = {
      protocol: 'sip',
      raw: text,
      size: Buffer.byteLength(text, 'latin1'),
      isRequest,
      method,
      requestUri,
      status,
      reason,
      callId: null,
      fromUri: null,
      fromTag: null,
      toUri: null,
      toTag: null,
      cseq: null,
      branch: null,
      vias: [],
      routes: [],
      recordRoutes: [],
      contact: null,
      headers,
      bodyType: null,
      sdp: null,
      retransOf: null,
    };

    msg.callId = getHeader(msg, 'call-id');

    const from = parseAddress(getHeader(msg, 'from') || '');
    msg.fromUri = from.uri;
    msg.fromTag = from.tag;
    const to = parseAddress(getHeader(msg, 'to') || '');
    msg.toUri = to.uri;
    msg.toTag = to.tag;

    const cseqVal = getHeader(msg, 'cseq');
    if (cseqVal) {
      const cm = /^\s*(\d+)\s+(\S+)/.exec(cseqVal);
      if (cm) msg.cseq = { num: parseInt(cm[1], 10), method: cm[2] };
    }
    // responses: method comes from CSeq
    if (!isRequest && msg.cseq) msg.method = msg.cseq.method;

    // Via / Route / Record-Route: split comma-combined values into entries
    for (const v of getHeaders(msg, 'via')) {
      for (const one of splitCombined(v)) msg.vias.push(one);
    }
    for (const v of getHeaders(msg, 'route')) {
      for (const one of splitCombined(v)) msg.routes.push(one);
    }
    for (const v of getHeaders(msg, 'record-route')) {
      for (const one of splitCombined(v)) msg.recordRoutes.push(one);
    }
    if (msg.vias.length) {
      const bm = /;\s*branch\s*=\s*([^;,\s]+)/i.exec(msg.vias[0]);
      if (bm) msg.branch = bm[1];
    }

    const contactVal = getHeader(msg, 'contact');
    if (contactVal) {
      const cv = contactVal.trim();
      if (cv === '*') {
        msg.contact = '*';
      } else {
        const first = splitCombined(cv)[0] || cv;
        msg.contact = parseAddress(first).uri;
      }
    }

    // body handling
    const ctVal = getHeader(msg, 'content-type');
    if (ctVal) {
      msg.bodyType = ctVal.split(';')[0].trim().toLowerCase() || null;
    }
    // trim body by Content-Length when present and plausible (UDP datagrams
    // may carry trailing bytes; TCP framing already cut exactly)
    const clVal = getHeader(msg, 'content-length');
    if (clVal !== null && /^\d+$/.test(clVal.trim())) {
      const cl = parseInt(clVal.trim(), 10);
      if (cl >= 0 && cl <= Buffer.byteLength(body, 'latin1')) {
        body = Buffer.from(body, 'latin1').slice(0, cl).toString('latin1');
      }
    }

    if (msg.bodyType === 'application/sdp' && body) {
      msg.sdp = parseSdp(body);
    } else if (msg.bodyType && msg.bodyType.startsWith('multipart/') && body) {
      const sdpPart = extractSdpFromMultipart(ctVal, body);
      if (sdpPart) msg.sdp = parseSdp(sdpPart);
    }

    return msg;
  } catch (e) {
    return null;
  }
}

/**
 * Locate the application/sdp part inside a multipart body.
 * @param {string} contentType - full Content-Type value (with boundary param)
 * @param {string} body - raw multipart body
 * @returns {string|null} the SDP part's body, or null
 */
function extractSdpFromMultipart(contentType, body) {
  try {
    const bm = /boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))/i.exec(contentType || '');
    if (!bm) return null;
    const boundary = bm[1] || bm[2];
    const parts = body.split('--' + boundary);
    for (const part of parts) {
      const p = part.replace(/^\r?\n/, '');
      if (!p || p.trim() === '--' || p.trim() === '') continue;
      const sep = findHeaderEnd(p);
      if (sep.idx < 0) continue;
      const partHeaders = p.slice(0, sep.idx);
      if (/content-type\s*:\s*application\/sdp/i.test(partHeaders)) {
        let partBody = p.slice(sep.idx + sep.len);
        // strip the trailing CRLF that precedes the next boundary marker
        partBody = partBody.replace(/\r?\n$/, '');
        return partBody;
      }
    }
    return null;
  } catch (e) {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Extraction from packets
// ---------------------------------------------------------------------------

const UDP_SNIFF_RE = /^(?:[A-Z]+\s+\S+\s+SIP\/2\.0(?:\r\n|\n|\r)|SIP\/2\.0\s+\d{3})/;
const STREAM_START_RE = /(?:^|\r\n|\n)(?=[A-Z]+ \S+ SIP\/2\.0(?:\r\n|\n)|SIP\/2\.0 \d{3})/g;

/**
 * Extract SIP messages from decoded packets.
 * UDP: sniff every payload on any port for a request/status start line.
 * TCP: per-flow (4-tuple, per direction) byte-stream assembly ordered by raw
 * seq with duplicate-seq drop, skipping flows touching port 1720 (H.323);
 * messages framed by header end + Content-Length (a segment may hold a
 * partial message or several messages).
 * Ids s1… assigned in timestamp order.
 * @param {Array<object>} packets - Packet[] from parsePcap/parseTextLog
 * @returns {Array<object>} SipMessage[] per the contract
 */
function extractSipMessages(packets) {
  const found = []; // { parsed, ts, pktRefs, first }
  if (!Array.isArray(packets)) return [];

  const tcpFlows = new Map(); // key -> { segs: [{seq,buf,pkt}], seen:Set, pseudo:number }

  for (const pkt of packets) {
    try {
      if (!pkt || !pkt.payload || !pkt.payload.length) continue;
      if (pkt.transport === 'udp') {
        const text = pkt.payload.toString('latin1');
        if (!UDP_SNIFF_RE.test(text)) continue;
        const parsed = parseSipMessage(text);
        if (!parsed) continue;
        parsed.size = pkt.payload.length;
        found.push({ parsed, ts: pkt.ts, pktRefs: [pkt.n], first: pkt });
      } else if (pkt.transport === 'tcp') {
        if (pkt.sport === 1720 || pkt.dport === 1720) continue; // H.323 flows
        const key = pkt.src + '|' + pkt.sport + '|' + pkt.dst + '|' + pkt.dport;
        let flow = tcpFlows.get(key);
        if (!flow) {
          flow = { segs: [], seen: new Set(), pseudo: 0 };
          tcpFlows.set(key, flow);
        }
        let seq;
        if (pkt.tcp && typeof pkt.tcp.seq === 'number') {
          seq = pkt.tcp.seq >>> 0;
          if (flow.seen.has(seq)) continue; // duplicate-seq drop
          flow.seen.add(seq);
        } else {
          seq = flow.pseudo; // text-log TCP packets: preserve capture order
          flow.pseudo += pkt.payload.length;
        }
        flow.segs.push({ seq, buf: pkt.payload, pkt });
      }
    } catch (e) {
      // skip broken packet, never throw
    }
  }

  // assemble each TCP flow
  for (const flow of tcpFlows.values()) {
    try {
      flow.segs.sort((a, b) => (a.seq === b.seq ? 0 : a.seq < b.seq ? -1 : 1));
      const ranges = []; // {start,end,pkt} in the concatenated stream
      let total = 0;
      for (const s of flow.segs) {
        ranges.push({ start: total, end: total + s.buf.length, pkt: s.pkt });
        total += s.buf.length;
      }
      const stream = Buffer.concat(flow.segs.map((s) => s.buf), total);
      const text = stream.toString('latin1');

      let offset = 0;
      while (offset < text.length) {
        // skip CRLF keepalives / stray whitespace
        while (offset < text.length && (text[offset] === '\r' || text[offset] === '\n')) offset++;
        if (offset >= text.length) break;

        // resync to the next plausible start line if needed
        if (!UDP_SNIFF_RE.test(text.slice(offset, offset + 1000))) {
          STREAM_START_RE.lastIndex = offset + 1;
          const sm = STREAM_START_RE.exec(text);
          if (!sm) break;
          offset = sm.index + sm[0].length;
          continue;
        }

        const rest = text.slice(offset);
        const sep = findHeaderEnd(rest);
        if (sep.idx < 0) break; // partial headers — wait (end of capture)

        const headerText = rest.slice(0, sep.idx);
        let cl = 0;
        const clm = /(?:^|\r\n|\n)(?:content-length|l)\s*:\s*(\d+)/i.exec(headerText);
        if (clm) cl = parseInt(clm[1], 10);
        const msgLen = sep.idx + sep.len + cl;
        if (msgLen > rest.length) break; // partial body — end of capture

        const rawMsg = rest.slice(0, msgLen);
        const parsed = parseSipMessage(rawMsg);
        if (parsed) {
          const start = offset;
          const end = offset + msgLen;
          const refs = [];
          let first = null;
          for (const r of ranges) {
            if (r.start < end && r.end > start) {
              refs.push(r.pkt.n);
              if (!first) first = r.pkt;
            }
          }
          parsed.size = msgLen;
          found.push({ parsed, ts: first ? first.ts : 0, pktRefs: refs, first });
        }
        offset += msgLen;
      }
    } catch (e) {
      // skip broken flow, never throw
    }
  }

  // ids in timestamp order (tie-break: first packet number)
  found.sort((a, b) =>
    a.ts !== b.ts ? a.ts - b.ts : (a.pktRefs[0] || 0) - (b.pktRefs[0] || 0)
  );

  const messages = [];
  for (let i = 0; i < found.length; i++) {
    const f = found[i];
    const p = f.first || {};
    messages.push(Object.assign(
      {
        id: 's' + (i + 1),
        protocol: 'sip',
        pktRefs: f.pktRefs,
        ts: p.ts !== undefined ? p.ts : f.ts,
        src: p.src !== undefined ? p.src : null,
        dst: p.dst !== undefined ? p.dst : null,
        sport: p.sport !== undefined ? p.sport : null,
        dport: p.dport !== undefined ? p.dport : null,
        transport: p.transport !== undefined ? p.transport : null,
      },
      f.parsed
    ));
  }
  return messages;
}

// ---------------------------------------------------------------------------
// Leg (dialog) grouping
// ---------------------------------------------------------------------------

const KIND_BY_METHOD = {
  INVITE: 'call',
  REGISTER: 'register',
  OPTIONS: 'options',
  SUBSCRIBE: 'subscribe',
  NOTIFY: 'notify',
  MESSAGE: 'message',
};

/**
 * Group SIP messages into legs (dialogs) per the contract: Call-ID +
 * from-tag (+ to-tag once established); forked to-tags stay one leg. Every
 * message lands in exactly one leg — strays become kind 'other'. Leg ids
 * d1… in order of first appearance (ts order).
 * @param {Array<object>} messages - SipMessage[] (ts-ordered from extractSipMessages)
 * @returns {Array<object>} Leg[]
 */
function groupSipLegs(messages) {
  const legs = [];
  if (!Array.isArray(messages)) return legs;

  const byCallId = new Map(); // callId -> [leg]
  const sorted = messages.slice().sort((a, b) => {
    const ta = a && typeof a.ts === 'number' ? a.ts : 0;
    const tb = b && typeof b.ts === 'number' ? b.ts : 0;
    return ta - tb;
  });

  for (const msg of sorted) {
    try {
      if (!msg || msg.protocol !== 'sip') continue;
      const callId = msg.callId || '';
      let bucket = byCallId.get(callId);
      if (!bucket) { bucket = []; byCallId.set(callId, bucket); }

      // find a matching leg: same Call-ID, and the leg's from-tag matches
      // either tag on the message (covers reverse-direction in-dialog
      // requests, e.g. BYE from the callee). Forked to-tags stay one leg.
      let leg = null;
      for (const l of bucket) {
        if (l.fromTag) {
          if (l.fromTag === msg.fromTag || (msg.toTag && l.fromTag === msg.toTag)) {
            leg = l; break;
          }
        } else if (!msg.fromTag) {
          leg = l; break;
        }
      }

      if (!leg) {
        const initialReq = !!(msg.isRequest && !msg.toTag);
        const kind = initialReq
          ? (KIND_BY_METHOD[msg.method] || 'other')
          : 'other'; // in-dialog only / response-only strays
        leg = {
          id: 'd' + (legs.length + 1),
          protocol: 'sip',
          kind,
          from: msg.fromUri || null,
          to: msg.toUri || null,
          fromUser: uriUser(msg.fromUri),
          toUser: uriUser(msg.toUri),
          src: msg.src, dst: msg.dst, sport: msg.sport, dport: msg.dport,
          transport: msg.transport,
          startTs: msg.ts, endTs: msg.ts,
          state: 'in-progress',
          failCode: null,
          answered: false, answerTs: null,
          msgIds: [],
          callId: msg.callId || null,
          fromTag: msg.fromTag || null,
          toTag: null,
          invite: null,
          // internal state-machine scratch (removed before return)
          _sm: { cancelSeen: false, byeSeen: false, finalNon2xx: null, canceled: false, final2xx: false },
        };
        legs.push(leg);
        bucket.push(leg);
      }

      leg.msgIds.push(msg.id);
      leg.endTs = msg.ts;

      // learn the to-tag once established (first non-null remote tag)
      if (!leg.toTag) {
        if (leg.fromTag && msg.toTag && leg.fromTag === msg.fromTag) {
          leg.toTag = msg.toTag;
        } else if (leg.fromTag && msg.fromTag && leg.fromTag === msg.toTag) {
          leg.toTag = msg.fromTag;
        } else if (!leg.fromTag && msg.toTag) {
          leg.toTag = msg.toTag;
        }
      }

      if (msg.isRequest && msg.method === 'INVITE' && !leg.invite) {
        leg.invite = msg.id;
      }

      // state machine
      const sm = leg._sm;
      if (msg.isRequest) {
        if (msg.method === 'CANCEL') sm.cancelSeen = true;
        else if (msg.method === 'BYE') sm.byeSeen = true;
      } else if (typeof msg.status === 'number' && msg.status >= 200) {
        const forInvite = msg.cseq && msg.cseq.method === 'INVITE';
        if (leg.kind === 'call') {
          if (forInvite) {
            if (msg.status < 300) {
              if (!leg.answered) { leg.answered = true; leg.answerTs = msg.ts; }
              sm.final2xx = true;
            } else {
              if (msg.status === 487 && sm.cancelSeen) sm.canceled = true;
              if (sm.finalNon2xx === null) sm.finalNon2xx = msg.status;
            }
          }
        } else {
          // non-call kinds: any final response settles the leg
          if (msg.status < 300) sm.final2xx = true;
          else if (sm.finalNon2xx === null) sm.finalNon2xx = msg.status;
        }
      }
    } catch (e) {
      // never throw on a garbage message — skip it
    }
  }

  // finalize states
  for (const leg of legs) {
    const sm = leg._sm;
    delete leg._sm;
    if (leg.kind === 'call') {
      if (leg.answered && sm.byeSeen) leg.state = 'completed';
      else if (sm.canceled) leg.state = 'canceled';
      else if (!leg.answered && sm.finalNon2xx !== null) {
        leg.state = 'failed';
        leg.failCode = sm.finalNon2xx;
      } else if (leg.answered) leg.state = 'answered';
      else if (leg.invite) leg.state = 'no-answer';
      else leg.state = 'in-progress';
    } else {
      if (sm.final2xx) leg.state = 'completed';
      else if (sm.finalNon2xx !== null) {
        leg.state = 'failed';
        leg.failCode = sm.finalNon2xx;
      } else leg.state = 'in-progress';
    }
  }

  return legs;
}

module.exports = {
  extractSipMessages,
  parseSipMessage,
  parseSdp,
  getHeader,
  getHeaders,
  groupSipLegs,
};
