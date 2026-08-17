'use strict';
/**
 * lib/isup.js — SIP-I / SIP-T support for hiccup.
 *
 * Two jobs, both driven from `extractIsup(messages)`:
 *
 *  1. MIME: every SIP message whose Content-Type is `multipart/*` is split on
 *     its boundary into `msg.bodyParts = [{contentType, disposition, body}]`.
 *     When a part is `application/sdp` and `msg.sdp` is still null, the part is
 *     parsed with lib/sip.js's parseSdp so SIP-I calls get their SDP into the
 *     correlation and diff engines. `msg.raw` is never modified.
 *
 *  2. ISUP: parts whose type is `application/isup` (any case, with or without
 *     `version=` parameters, `application/ISUP`, `application/x-isup`, or a bare
 *     `ISUP` token) are decoded per ITU-T Q.763 into `msg.isup`.
 *
 * Real-world SIP-I bodies are messy: truncated mid-parameter, hex-dumped as
 * text by a logging SBC, or base64'd by a mail-style MIME encoder. All three
 * are detected. Nothing in this module throws — an undecodable body produces an
 * info finding instead.
 *
 * Export (frozen contract): extractIsup(messages) -> { findings }
 * Mutations (documented in ARCHITECTURE.md): msg.isup, msg.bodyParts, msg.sdp
 * (only when it was null).
 *
 * Zero runtime dependencies. Findings carry no citations — advisor.js owns those.
 */

const { getHeader, parseSdp } = require('./sip');

/** Never decode more than this many body bytes as one ISUP message. */
const MAX_ISUP_BYTES = 4096;
/** Cap the per-message info findings so a carrier trunk capture stays readable. */
const MAX_INFO_FINDINGS = 40;
/** Cap the "this body would not decode" notes for the same reason. */
const MAX_PROBLEM_FINDINGS = 10;
/** Findings category — matches analyze.js's fallback for this module. */
const CATEGORY = 'sip-i';

// ---------------------------------------------------------------------------
// Q.763 tables
// ---------------------------------------------------------------------------

/** ISUP message type octet -> { short, name } (ITU-T Q.763 Table 4). */
const MESSAGE_TYPES = {
  0x01: { short: 'IAM', name: 'Initial address' },
  0x02: { short: 'SAM', name: 'Subsequent address' },
  0x03: { short: 'INR', name: 'Information request' },
  0x04: { short: 'INF', name: 'Information' },
  0x05: { short: 'COT', name: 'Continuity' },
  0x06: { short: 'ACM', name: 'Address complete' },
  0x07: { short: 'CON', name: 'Connect' },
  0x08: { short: 'FOT', name: 'Forward transfer' },
  0x09: { short: 'ANM', name: 'Answer' },
  0x0c: { short: 'REL', name: 'Release' },
  0x0d: { short: 'SUS', name: 'Suspend' },
  0x0e: { short: 'RES', name: 'Resume' },
  0x10: { short: 'RLC', name: 'Release complete' },
  0x11: { short: 'CCR', name: 'Continuity check request' },
  0x12: { short: 'RSC', name: 'Reset circuit' },
  0x13: { short: 'BLO', name: 'Blocking' },
  0x14: { short: 'UBL', name: 'Unblocking' },
  0x15: { short: 'BLA', name: 'Blocking acknowledgement' },
  0x16: { short: 'UBA', name: 'Unblocking acknowledgement' },
  0x17: { short: 'GRS', name: 'Circuit group reset' },
  0x18: { short: 'CGB', name: 'Circuit group blocking' },
  0x19: { short: 'CGU', name: 'Circuit group unblocking' },
  0x1a: { short: 'CGBA', name: 'Circuit group blocking acknowledgement' },
  0x1b: { short: 'CGUA', name: 'Circuit group unblocking acknowledgement' },
  0x24: { short: 'LPA', name: 'Loopback acknowledgement' },
  0x27: { short: 'DRS', name: 'Delayed release' },
  0x28: { short: 'PAM', name: 'Pass-along' },
  0x29: { short: 'GRA', name: 'Circuit group reset acknowledgement' },
  0x2a: { short: 'CQM', name: 'Circuit group query' },
  0x2b: { short: 'CQR', name: 'Circuit group query response' },
  0x2c: { short: 'CPG', name: 'Call progress' },
  0x2d: { short: 'USR', name: 'User-to-user information' },
  0x2e: { short: 'UCIC', name: 'Unequipped circuit identification code' },
  0x2f: { short: 'CFN', name: 'Confusion' },
  0x30: { short: 'OLM', name: 'Overload' },
  0x31: { short: 'CRG', name: 'Charge information' },
  0x33: { short: 'FAC', name: 'Facility' },
  0x38: { short: 'SGM', name: 'Segmentation' },
};

/** ISUP parameter code -> Q.763 parameter name (display only). */
const PARAM_NAMES = {
  0x01: 'Call reference',
  0x02: 'Transmission medium requirement',
  0x03: 'Access transport',
  0x04: 'Called party number',
  0x05: 'Subsequent number',
  0x06: 'Nature of connection indicators',
  0x07: 'Forward call indicators',
  0x08: 'Optional forward call indicators',
  0x09: "Calling party's category",
  0x0a: 'Calling party number',
  0x0b: 'Redirecting number',
  0x0c: 'Redirection number',
  0x0d: 'Connection request',
  0x0e: 'Information request indicators',
  0x0f: 'Information indicators',
  0x10: 'Continuity indicators',
  0x11: 'Backward call indicators',
  0x12: 'Cause indicators',
  0x13: 'Redirection information',
  0x15: 'Circuit group supervision message type',
  0x16: 'Range and status',
  0x18: 'Facility indicator',
  0x1a: 'Closed user group interlock code',
  0x1d: 'User service information',
  0x1e: 'Signalling point code',
  0x20: 'User-to-user information',
  0x21: 'Connected number',
  0x22: 'Suspend/resume indicators',
  0x23: 'Transit network selection',
  0x24: 'Event information',
  0x26: 'Circuit state indicator',
  0x27: 'Automatic congestion level',
  0x28: 'Original called number',
  0x29: 'Optional backward call indicators',
  0x2a: 'User-to-user indicators',
  0x2b: 'Origination ISC point code',
  0x2c: 'Generic notification indicator',
  0x2d: 'Call history information',
  0x2e: 'Access delivery information',
  0x2f: 'Network specific facility',
  0x30: 'User service information prime',
  0x31: 'Propagation delay counter',
  0x32: 'Remote operations',
  0x33: 'Service activation',
  0x34: 'User teleservice information',
  0x35: 'Transmission medium used',
  0x36: 'Call diversion information',
  0x37: 'Echo control information',
  0x38: 'Message compatibility information',
  0x39: 'Parameter compatibility information',
  0x3a: 'MLPP precedence',
  0x3b: 'MCID request indicators',
  0x3c: 'MCID response indicators',
  0x3d: 'Hop counter',
  0x3e: 'Transmission medium requirement prime',
  0x3f: 'Location number',
  0x40: 'Redirection number restriction',
  0x43: 'Call transfer reference',
  0x44: 'Loop prevention indicators',
  0x45: 'Call transfer number',
  0x4b: 'CCSS',
  0x4c: 'Forward GVNS',
  0x4d: 'Backward GVNS',
  0x4e: 'Redirect capability',
  0x5b: 'Network management controls',
  0x65: 'Correlation id',
  0x66: 'SCF id',
  0x6e: 'Call diversion treatment indicators',
  0x6f: 'Called IN number',
  0x70: 'Call offering treatment indicators',
  0x71: 'Charged party identification',
  0x72: 'Conference treatment indicators',
  0x73: 'Display information',
  0x77: 'Redirect counter',
  0x78: 'Application transport',
  0x79: 'Collect call request',
  0xc0: 'Generic number',
  0xc1: 'Generic digits',
};

/**
 * Message structure per Q.763: mandatory fixed parameters (code + octet
 * length, in order), mandatory variable parameters (codes, in pointer order),
 * and whether an optional part pointer follows.
 */
const STRUCT = {
  0x01: { fixed: [[0x06, 1], [0x07, 2], [0x09, 1], [0x02, 1]], variable: [0x04], optional: true }, // IAM
  0x02: { fixed: [], variable: [0x05], optional: false },  // SAM
  0x03: { fixed: [[0x0e, 2]], variable: [], optional: true }, // INR
  0x04: { fixed: [[0x0f, 2]], variable: [], optional: true }, // INF
  0x05: { fixed: [[0x10, 1]], variable: [], optional: false }, // COT
  0x06: { fixed: [[0x11, 2]], variable: [], optional: true }, // ACM
  0x07: { fixed: [[0x11, 2]], variable: [], optional: true }, // CON
  0x08: { fixed: [], variable: [], optional: true },          // FOT
  0x09: { fixed: [], variable: [], optional: true },          // ANM
  0x0c: { fixed: [], variable: [0x12], optional: true },      // REL
  0x0d: { fixed: [[0x22, 1]], variable: [], optional: true }, // SUS
  0x0e: { fixed: [[0x22, 1]], variable: [], optional: true }, // RES
  0x10: { fixed: [], variable: [], optional: true },          // RLC
  0x11: { fixed: [], variable: [], optional: false },         // CCR
  0x12: { fixed: [], variable: [], optional: false },         // RSC
  0x13: { fixed: [], variable: [], optional: false },         // BLO
  0x14: { fixed: [], variable: [], optional: false },         // UBL
  0x15: { fixed: [], variable: [], optional: false },         // BLA
  0x16: { fixed: [], variable: [], optional: false },         // UBA
  0x24: { fixed: [], variable: [], optional: false },         // LPA
  0x27: { fixed: [], variable: [], optional: true },          // DRS
  0x2c: { fixed: [[0x24, 1]], variable: [], optional: true }, // CPG
  0x2e: { fixed: [], variable: [], optional: false },         // UCIC
  0x2f: { fixed: [], variable: [0x12], optional: true },      // CFN
  0x30: { fixed: [], variable: [], optional: false },         // OLM
  0x31: { fixed: [], variable: [], optional: true },          // CRG
  0x33: { fixed: [[0x18, 1]], variable: [], optional: true }, // FAC
};

/** Q.850 cause value -> text. */
const Q850 = {
  1: 'Unallocated (unassigned) number',
  2: 'No route to specified transit network',
  3: 'No route to destination',
  4: 'Send special information tone',
  5: 'Misdialled trunk prefix',
  6: 'Channel unacceptable',
  7: 'Call awarded and being delivered in an established channel',
  8: 'Preemption',
  9: 'Preemption - circuit reserved for reuse',
  14: 'QoR: ported number',
  16: 'Normal call clearing',
  17: 'User busy',
  18: 'No user responding',
  19: 'No answer from user (user alerted)',
  20: 'Subscriber absent',
  21: 'Call rejected',
  22: 'Number changed',
  23: 'Redirection to new destination',
  25: 'Exchange routing error',
  26: 'Non-selected user clearing',
  27: 'Destination out of order',
  28: 'Invalid number format (address incomplete)',
  29: 'Facility rejected',
  30: 'Response to STATUS ENQUIRY',
  31: 'Normal, unspecified',
  34: 'No circuit/channel available',
  38: 'Network out of order',
  39: 'Permanent frame mode connection out of service',
  40: 'Permanent frame mode connection operational',
  41: 'Temporary failure',
  42: 'Switching equipment congestion',
  43: 'Access information discarded',
  44: 'Requested circuit/channel not available',
  46: 'Precedence call blocked',
  47: 'Resource unavailable, unspecified',
  49: 'Quality of service not available',
  50: 'Requested facility not subscribed',
  53: 'Outgoing calls barred within CUG',
  55: 'Incoming calls barred within CUG',
  57: 'Bearer capability not authorized',
  58: 'Bearer capability not presently available',
  62: 'Inconsistency in designated outgoing access information',
  63: 'Service or option not available, unspecified',
  65: 'Bearer capability not implemented',
  66: 'Channel type not implemented',
  69: 'Requested facility not implemented',
  70: 'Only restricted digital information bearer capability is available',
  79: 'Service or option not implemented, unspecified',
  81: 'Invalid call reference value',
  82: 'Identified channel does not exist',
  83: 'A suspended call exists, but this call identity does not',
  84: 'Call identity in use',
  85: 'No call suspended',
  86: 'Call having the requested call identity has been cleared',
  87: 'User not member of CUG',
  88: 'Incompatible destination',
  90: 'Non-existent CUG',
  91: 'Invalid transit network selection',
  95: 'Invalid message, unspecified',
  96: 'Mandatory information element is missing',
  97: 'Message type non-existent or not implemented',
  98: 'Message not compatible with call state',
  99: 'Information element/parameter non-existent or not implemented',
  100: 'Invalid information element contents',
  101: 'Message not compatible with call state',
  102: 'Recovery on timer expiry',
  103: 'Parameter non-existent or not implemented, passed on',
  110: 'Message with unrecognized parameter, discarded',
  111: 'Protocol error, unspecified',
  127: 'Interworking, unspecified',
};

/** Nature of address indicator values. */
const NAI = {
  0: 'spare',
  1: 'subscriber number',
  2: 'unknown (national use)',
  3: 'national (significant) number',
  4: 'international number',
  5: 'network-specific number',
  6: 'network routing number, national format',
  7: 'network routing number, network-specific format',
  8: 'network routing number concatenated with called directory number',
};

/** Numbering plan indicator values. */
const NPI = {
  0: 'unknown',
  1: 'ISDN/telephony E.164',
  3: 'data numbering plan X.121',
  4: 'telex numbering plan F.69',
  5: 'private numbering plan',
  6: 'reserved (national)',
  7: 'reserved',
};

const PRESENTATION = {
  0: 'presentation allowed',
  1: 'presentation restricted',
  2: 'address not available',
  3: 'spare',
};

const SCREENING = {
  0: 'user provided, not verified',
  1: 'user provided, verified and passed',
  2: 'user provided, verified and failed',
  3: 'network provided',
};

const CAUSE_CODING = {
  0: 'ITU-T',
  1: 'ISO/IEC',
  2: 'national',
  3: 'location-specific',
};

const CAUSE_LOCATION = {
  0: 'user',
  1: 'private network serving the local user',
  2: 'public network serving the local user',
  3: 'transit network',
  4: 'public network serving the remote user',
  5: 'private network serving the remote user',
  7: 'international network',
  10: 'network beyond the interworking point',
};

const CALLING_CATEGORY = {
  0x00: "calling party's category unknown at this time",
  0x01: 'operator, language French',
  0x02: 'operator, language English',
  0x03: 'operator, language German',
  0x04: 'operator, language Russian',
  0x05: 'operator, language Spanish',
  0x0a: 'ordinary calling subscriber',
  0x0b: 'calling subscriber with priority',
  0x0c: 'data call (voice band data)',
  0x0d: 'test call',
  0x0f: 'payphone',
};

const TMR = {
  0: 'speech',
  2: '64 kbit/s unrestricted',
  3: '3.1 kHz audio',
  6: '64 kbit/s preferred',
  7: '2x64 kbit/s unrestricted',
  8: '384 kbit/s unrestricted',
  9: '1536 kbit/s unrestricted',
  10: '1920 kbit/s unrestricted',
};

const SATELLITE = {
  0: 'no satellite circuit',
  1: 'one satellite circuit',
  2: 'two satellite circuits',
  3: 'spare',
};

const CONTINUITY_CHECK = {
  0: 'continuity check not required',
  1: 'continuity check required on this circuit',
  2: 'continuity check performed on a previous circuit',
  3: 'spare',
};

const E2E_METHOD = {
  0: 'no end-to-end method available',
  1: 'pass-along method available',
  2: 'SCCP method available',
  3: 'pass-along and SCCP methods available',
};

const ISUP_PREFERENCE = {
  0: 'ISUP preferred all the way',
  1: 'ISUP not required all the way',
  2: 'ISUP required all the way',
  3: 'spare',
};

const SCCP_METHOD = {
  0: 'no indication',
  1: 'connectionless method available',
  2: 'connection oriented method available',
  3: 'connectionless and connection oriented available',
};

const CHARGE_IND = {
  0: 'no indication',
  1: 'no charge',
  2: 'charge',
  3: 'spare',
};

const CALLED_STATUS = {
  0: 'no indication',
  1: 'subscriber free',
  2: 'connect when free',
  3: 'spare',
};

const CALLED_CATEGORY = {
  0: 'no indication',
  1: 'ordinary subscriber',
  2: 'payphone',
  3: 'spare',
};

const EVENT_INFO = {
  1: 'ALERTING',
  2: 'PROGRESS',
  3: 'in-band information or an appropriate pattern is now available',
  4: 'call forwarded on busy',
  5: 'call forwarded on no reply',
  6: 'call forwarded unconditional',
};

/** User service information / Q.931 bearer capability tables. */
const ITC = {
  0x00: 'speech',
  0x08: 'unrestricted digital information',
  0x09: 'restricted digital information',
  0x10: '3.1 kHz audio',
  0x11: 'unrestricted digital information with tones/announcements',
  0x18: 'video',
};

const TRANSFER_MODE = { 0: 'circuit mode', 2: 'packet mode' };

const TRANSFER_RATE = {
  0x00: 'packet mode',
  0x10: '64 kbit/s',
  0x11: '2 x 64 kbit/s',
  0x13: '384 kbit/s',
  0x15: '1536 kbit/s',
  0x17: '1920 kbit/s',
};

const LAYER1 = {
  0x01: 'ITU-T V.110 / I.460',
  0x02: 'G.711 mu-law',
  0x03: 'G.711 A-law',
  0x04: 'G.721 32 kbit/s ADPCM',
  0x05: 'H.221 / H.242',
  0x07: 'non-ITU-T rate adaption',
  0x08: 'V.120',
  0x09: 'X.31 HDLC flag stuffing',
};

const GENERIC_NUMBER_QUALIFIER = {
  0x00: 'dialled digits',
  0x01: 'additional called number',
  0x05: 'additional connected number',
  0x06: 'additional calling party number',
  0x07: 'additional original called number',
  0x08: 'additional redirecting number',
  0x09: 'additional redirection number',
  0x0a: 'reserved',
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/** Two-digit lowercase hex for one byte. */
function hex2(b) {
  return (b & 0xff).toString(16).padStart(2, '0');
}

/**
 * Space-separated lowercase hex dump ('01 20 0a …'), matching h323.js's
 * `raw` convention so the inspector renders both the same way.
 * @param {Buffer} buf
 * @returns {string}
 */
function spacedHex(buf) {
  if (!buf || !buf.length) return '';
  const out = new Array(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = hex2(buf[i]);
  return out.join(' ');
}

/** Table lookup with a hex fallback so unknown values are never dropped. */
function look(table, key, prefix) {
  if (table && Object.prototype.hasOwnProperty.call(table, key)) return table[key];
  return (prefix || 'value') + ' 0x' + hex2(key);
}

/** Find the header/body separator of a SIP message or MIME part. */
function findHeaderEnd(text) {
  const a = text.indexOf('\r\n\r\n');
  const b = text.indexOf('\n\n');
  if (a >= 0 && (b < 0 || a <= b)) return { idx: a, len: 4 };
  if (b >= 0) return { idx: b, len: 2 };
  return { idx: -1, len: 0 };
}

/**
 * The body of a SIP message, taken from `msg.raw` (never modified) and cut to
 * Content-Length when that is present and plausible.
 * @param {object} msg SipMessage
 * @returns {string} body text (latin1 characters, one per byte)
 */
function messageBody(msg) {
  const text = typeof msg.raw === 'string' ? msg.raw : '';
  if (!text) return '';
  const sep = findHeaderEnd(text);
  if (sep.idx < 0) return '';
  let body = text.slice(sep.idx + sep.len);
  const cl = getHeader(msg, 'content-length');
  if (cl !== null && /^\d+$/.test(String(cl).trim())) {
    const n = parseInt(String(cl).trim(), 10);
    const have = Buffer.byteLength(body, 'latin1');
    if (n >= 0 && n <= have) body = Buffer.from(body, 'latin1').slice(0, n).toString('latin1');
  }
  return body;
}

/** Base media type of a Content-Type value, lowercased ('application/isup'). */
function baseType(contentType) {
  if (typeof contentType !== 'string') return '';
  return contentType.split(';')[0].trim().toLowerCase();
}

/**
 * True when a part's Content-Type denotes encapsulated ISUP: `application/isup`
 * (with or without `version=`/`base=` parameters), `application/ISUP`,
 * `application/x-isup`, `application/vnd.3gpp.isup` or a bare `ISUP` token.
 * @param {string|null} contentType
 * @returns {boolean}
 */
function isIsupType(contentType) {
  const t = baseType(contentType);
  if (!t) return false;
  return /(?:^|[/._+-])(?:x-)?isup$/.test(t);
}

// ---------------------------------------------------------------------------
// MIME multipart split
// ---------------------------------------------------------------------------

/**
 * Parse a MIME part's own headers.
 * @param {string} text header block of the part
 * @returns {Array<{name: string, value: string}>}
 */
function parsePartHeaders(text) {
  const headers = [];
  const lines = String(text || '').split(/\r\n|\n|\r/);
  for (const line of lines) {
    if (!line) continue;
    if (/^[ \t]/.test(line)) {
      if (headers.length) {
        headers[headers.length - 1].value =
          (headers[headers.length - 1].value + ' ' + line.trim()).trim();
      }
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const name = line.slice(0, colon).trim();
    if (!name) continue;
    headers.push({ name, value: line.slice(colon + 1).trim() });
  }
  return headers;
}

/** First value of a header name in a part-header list. */
function partHeader(headers, name) {
  const want = String(name).toLowerCase();
  for (const h of headers) {
    if (h.name.toLowerCase() === want) return h.value;
  }
  return null;
}

/**
 * Split a multipart body on its boundary.
 * @param {string} contentType full Content-Type value (carries `boundary=`)
 * @param {string} body raw multipart body
 * @returns {{parts: Array<{contentType: string|null, disposition: string|null,
 *            body: string, transferEncoding: string|null}>, warnings: string[]}}
 */
function splitMultipart(contentType, body) {
  const out = { parts: [], warnings: [] };
  const bm = /boundary\s*=\s*(?:"([^"]*)"|([^;\s]+))/i.exec(contentType || '');
  const boundary = bm ? (bm[1] || bm[2] || '') : '';
  if (!boundary) {
    out.warnings.push('multipart Content-Type has no usable boundary parameter');
    return out;
  }
  const chunks = String(body || '').split('--' + boundary);
  for (let i = 1; i < chunks.length; i++) {
    let chunk = chunks[i];
    if (chunk.startsWith('--')) break;           // closing delimiter
    chunk = chunk.replace(/^[ \t]*\r?\n/, '');   // transport padding + CRLF
    if (!chunk.trim()) continue;
    const sep = findHeaderEnd(chunk);
    let headers = [];
    let partBody = chunk;
    if (sep.idx >= 0) {
      headers = parsePartHeaders(chunk.slice(0, sep.idx));
      partBody = chunk.slice(sep.idx + sep.len);
    } else {
      out.warnings.push('multipart part ' + i + ' has no header/body separator');
    }
    partBody = partBody.replace(/\r?\n$/, '');   // CRLF that belongs to the next boundary
    out.parts.push({
      contentType: partHeader(headers, 'content-type'),
      disposition: partHeader(headers, 'content-disposition'),
      body: partBody,
      transferEncoding: partHeader(headers, 'content-transfer-encoding'),
    });
  }
  if (!out.parts.length) out.warnings.push('multipart body contained no parts');
  return out;
}

// ---------------------------------------------------------------------------
// Body -> bytes (binary, hex text or base64)
// ---------------------------------------------------------------------------

/**
 * Candidate byte interpretations of a part body, most plausible first.
 * SBC exports frequently hex-dump or base64 the ISUP blob instead of carrying
 * it as 8-bit binary.
 * @param {string} body part body text
 * @param {string|null} transferEncoding Content-Transfer-Encoding value
 * @returns {Array<{encoding: 'binary'|'hex-text'|'base64', bytes: Buffer}>}
 */
function candidateBytes(body, transferEncoding) {
  const cands = [];
  const text = typeof body === 'string' ? body : '';
  if (!text.length) return cands;
  const cte = String(transferEncoding || '').trim().toLowerCase();

  const binary = { encoding: 'binary', bytes: Buffer.from(text, 'latin1') };

  const compact = text.replace(/[\s:,]/g, '');
  const hexish = /^(?:0x)?[0-9a-fA-F]+$/.test(compact)
    ? compact.replace(/^0x/i, '')
    : null;
  const hexCand = hexish && hexish.length >= 4 && hexish.length % 2 === 0
    ? { encoding: 'hex-text', bytes: Buffer.from(hexish, 'hex') }
    : null;

  const b64ish = text.replace(/\s/g, '');
  const b64Cand = /^[A-Za-z0-9+/]+={0,2}$/.test(b64ish) && b64ish.length >= 8 &&
    b64ish.length % 4 === 0
    ? { encoding: 'base64', bytes: Buffer.from(b64ish, 'base64') }
    : null;

  if (cte === 'base64' && b64Cand) cands.push(b64Cand);
  if (cte === 'hex' && hexCand) cands.push(hexCand);
  cands.push(binary);
  if (hexCand) cands.push(hexCand);
  if (b64Cand) cands.push(b64Cand);

  // de-duplicate by encoding, keeping the first (hint-driven) occurrence
  const seen = Object.create(null);
  const unique = [];
  for (const c of cands) {
    if (!c || !c.bytes || !c.bytes.length) continue;
    if (seen[c.encoding]) continue;
    seen[c.encoding] = true;
    unique.push(c.bytes.length > MAX_ISUP_BYTES
      ? { encoding: c.encoding, bytes: c.bytes.slice(0, MAX_ISUP_BYTES), clipped: true }
      : c);
  }
  return unique;
}

// ---------------------------------------------------------------------------
// Parameter decoders
// ---------------------------------------------------------------------------

/**
 * Decode ISUP address signals: 2 BCD digits per octet, low nibble first.
 * The odd/even flag says the high nibble of the final octet is filler.
 * @param {Buffer} buf address signal octets
 * @param {boolean} odd true when the number has an odd digit count
 * @returns {string} digit string ('A'..'F' for the non-decimal signal codes)
 */
function bcdDigits(buf, odd) {
  let out = '';
  for (let i = 0; i < buf.length; i++) {
    const lo = buf[i] & 0x0f;
    const hi = (buf[i] >> 4) & 0x0f;
    out += lo < 10 ? String(lo) : 'ABCDEF'[lo - 10];
    if (odd && i === buf.length - 1) break;
    out += hi < 10 ? String(hi) : 'ABCDEF'[hi - 10];
  }
  return out;
}

/**
 * Decode a called-party / calling-party / generic number parameter value.
 * @param {Buffer} buf parameter value octets
 * @param {'called'|'calling'} kind which octet-2 layout applies
 * @param {number} skip leading octets to skip (generic number qualifier)
 * @returns {object|null} { digits, odd, nai, naiText, npi, npiText, ... }
 */
function decodeNumber(buf, kind, skip) {
  const off = skip || 0;
  if (!buf || buf.length < off + 2) return null;
  const oct1 = buf[off];
  const oct2 = buf[off + 1];
  const odd = (oct1 & 0x80) !== 0;
  const nai = oct1 & 0x7f;
  const npi = (oct2 >> 4) & 0x07;
  const res = {
    digits: bcdDigits(buf.slice(off + 2), odd),
    odd,
    nai,
    naiText: look(NAI, nai, 'nature'),
    npi,
    npiText: look(NPI, npi, 'plan'),
  };
  if (kind === 'called') {
    res.internalNetworkNumber = (oct2 & 0x80) !== 0;
  } else {
    res.numberIncomplete = (oct2 & 0x80) !== 0;
    res.presentation = look(PRESENTATION, (oct2 >> 2) & 0x03, 'presentation');
    res.screening = look(SCREENING, oct2 & 0x03, 'screening');
  }
  return res;
}

/**
 * Decode a Cause Indicators parameter value (Q.850).
 * @param {Buffer} buf parameter value octets
 * @returns {object|null} { causeCode, causeText, coding, location, diagnostic }
 */
function decodeCause(buf) {
  if (!buf || !buf.length) return null;
  const res = {
    coding: look(CAUSE_CODING, (buf[0] >> 5) & 0x03, 'coding'),
    location: look(CAUSE_LOCATION, buf[0] & 0x0f, 'location'),
    causeCode: null,
    causeText: null,
    diagnostic: buf.length > 2 ? spacedHex(buf.slice(2)) : null,
  };
  if (buf.length >= 2) {
    res.causeCode = buf[1] & 0x7f;
    res.causeText = Object.prototype.hasOwnProperty.call(Q850, res.causeCode)
      ? Q850[res.causeCode]
      : 'Q.850 cause ' + res.causeCode;
  }
  return res;
}

/**
 * Decode Forward Call Indicators (2 octets).
 * @param {Buffer} buf
 * @returns {object|null}
 */
function decodeForwardCallIndicators(buf) {
  if (!buf || !buf.length) return null;
  const a = buf[0];
  const res = {
    international: (a & 0x01) !== 0,
    endToEndMethod: look(E2E_METHOD, (a >> 1) & 0x03, 'method'),
    interworking: (a & 0x08) !== 0,
    endToEndInformation: (a & 0x10) !== 0,
    isupAllTheWay: (a & 0x20) !== 0,
    isupPreference: look(ISUP_PREFERENCE, (a >> 6) & 0x03, 'preference'),
    isdnAccess: null,
    sccpMethod: null,
  };
  if (buf.length >= 2) {
    const b = buf[1];
    res.isdnAccess = (b & 0x01) !== 0;
    res.sccpMethod = look(SCCP_METHOD, (b >> 1) & 0x03, 'method');
  }
  return res;
}

/** Readable one-liner for a Forward Call Indicators decode. */
function fciText(f) {
  if (!f) return null;
  const bits = [
    f.international ? 'international call' : 'national call',
    f.interworking ? 'interworking encountered' : 'no interworking encountered',
    f.isupAllTheWay ? 'ISUP used all the way' : 'ISUP not used all the way',
    f.isupPreference,
  ];
  if (f.isdnAccess !== null) bits.push(f.isdnAccess ? 'ISDN access' : 'non-ISDN access');
  return bits.join('; ');
}

/**
 * Decode a User Service Information / Q.931 bearer capability value.
 * @param {Buffer} buf
 * @returns {string|null} readable summary
 */
function decodeUserServiceInfo(buf) {
  if (!buf || !buf.length) return null;
  const bits = [look(ITC, buf[0] & 0x1f, 'transfer capability')];
  if (buf.length >= 2) {
    bits.push(look(TRANSFER_MODE, (buf[1] >> 5) & 0x03, 'transfer mode'));
    bits.push(look(TRANSFER_RATE, buf[1] & 0x1f, 'transfer rate'));
  }
  if (buf.length >= 3 && ((buf[2] >> 5) & 0x03) === 1) {
    bits.push(look(LAYER1, buf[2] & 0x1f, 'layer 1 protocol'));
  }
  return bits.join(', ');
}

/**
 * Decode one ISUP parameter into a display name, a readable value and, where
 * relevant, structured fields the caller lifts onto msg.isup.
 * @param {number} code parameter code
 * @param {Buffer} buf parameter value octets
 * @returns {object} { name, value, ...structured }
 */
function decodeParam(code, buf) {
  const name = Object.prototype.hasOwnProperty.call(PARAM_NAMES, code)
    ? PARAM_NAMES[code]
    : 'parameter 0x' + hex2(code);
  const hex = spacedHex(buf);
  const res = { name, value: hex, hex };

  try {
    switch (code) {
      case 0x04:   // Called party number
      case 0x05: { // Subsequent number (same layout)
        const n = decodeNumber(buf, 'called', 0);
        if (!n) break;
        res.digits = n.digits;
        res.number = n;
        res.value = (n.digits || '(no digits)') +
          ' [nature=' + n.naiText + ', plan=' + n.npiText +
          ', ' + (n.odd ? 'odd' : 'even') + ' digit count]';
        break;
      }
      case 0x0a:   // Calling party number
      case 0x0b:   // Redirecting number
      case 0x0c:   // Redirection number
      case 0x21:   // Connected number
      case 0x28:   // Original called number
      case 0x3f: { // Location number
        const n = decodeNumber(buf, 'calling', 0);
        if (!n) break;
        res.digits = n.digits;
        res.number = n;
        res.value = (n.digits || '(no digits)') +
          ' [nature=' + n.naiText + ', plan=' + n.npiText +
          ', ' + n.presentation + ', ' + n.screening + ']';
        break;
      }
      case 0x06: { // Nature of connection indicators
        if (!buf.length) break;
        const parts = [
          look(SATELLITE, buf[0] & 0x03, 'satellite'),
          look(CONTINUITY_CHECK, (buf[0] >> 2) & 0x03, 'continuity check'),
          (buf[0] & 0x10) ? 'echo control device included' : 'no echo control device',
        ];
        res.value = parts.join('; ');
        res.natureOfConnection = res.value;
        break;
      }
      case 0x07: { // Forward call indicators
        const f = decodeForwardCallIndicators(buf);
        if (!f) break;
        res.fci = f;
        res.value = fciText(f);
        break;
      }
      case 0x09: { // Calling party's category
        if (!buf.length) break;
        res.value = look(CALLING_CATEGORY, buf[0], 'category') + ' (0x' + hex2(buf[0]) + ')';
        res.callingPartyCategory = res.value;
        break;
      }
      case 0x02:   // Transmission medium requirement
      case 0x3e: { // Transmission medium requirement prime
        if (!buf.length) break;
        res.value = look(TMR, buf[0], 'requirement');
        break;
      }
      case 0x12: { // Cause indicators
        const c = decodeCause(buf);
        if (!c) break;
        res.causeCode = c.causeCode;
        res.causeText = c.causeText;
        res.cause = c;
        res.value = (c.causeCode === null ? '(no cause value)' : c.causeCode + ' ' + c.causeText) +
          ' [coding=' + c.coding + ', location=' + c.location + ']' +
          (c.diagnostic ? ' diagnostic=' + c.diagnostic : '');
        break;
      }
      case 0x11: { // Backward call indicators
        if (!buf.length) break;
        const parts = [
          look(CHARGE_IND, buf[0] & 0x03, 'charge'),
          look(CALLED_STATUS, (buf[0] >> 2) & 0x03, 'called party status'),
          look(CALLED_CATEGORY, (buf[0] >> 4) & 0x03, 'called party category'),
        ];
        if (buf.length >= 2) parts.push((buf[1] & 0x04) ? 'ISDN access' : 'non-ISDN access');
        res.value = parts.join('; ');
        break;
      }
      case 0x24: { // Event information
        if (!buf.length) break;
        res.value = look(EVENT_INFO, buf[0] & 0x7f, 'event') +
          ((buf[0] & 0x80) ? '; event presentation restricted' : '');
        res.eventInformation = res.value;
        break;
      }
      case 0x22: { // Suspend/resume indicators
        if (!buf.length) break;
        res.value = (buf[0] & 0x01) ? 'network initiated' : 'ISDN subscriber initiated';
        break;
      }
      case 0x1d:   // User service information
      case 0x30:   // User service information prime
      case 0x34: { // User teleservice information
        const t = decodeUserServiceInfo(buf);
        if (!t) break;
        res.value = t;
        res.userServiceInformation = t;
        break;
      }
      case 0x3d: { // Hop counter
        if (!buf.length) break;
        res.value = String(buf[0] & 0x1f);
        break;
      }
      case 0x23: { // Transit network selection
        const n = decodeNumber(buf, 'called', 0);
        if (n) res.value = (n.digits || '(no digits)') + ' [nature=' + n.naiText + ']';
        break;
      }
      case 0x73: { // Display information (IA5 text)
        let s = '';
        for (let i = 0; i < buf.length; i++) {
          if (buf[i] >= 0x20 && buf[i] <= 0x7e) s += String.fromCharCode(buf[i]);
        }
        if (s) res.value = s;
        break;
      }
      case 0xc0: { // Generic number: qualifier octet then a calling-number layout
        if (!buf.length) break;
        const qualifier = buf[0];
        const n = decodeNumber(buf, 'calling', 1);
        res.qualifier = qualifier;
        res.qualifierText = look(GENERIC_NUMBER_QUALIFIER, qualifier, 'qualifier');
        if (n) {
          res.digits = n.digits;
          res.number = n;
          res.value = res.qualifierText + ': ' + (n.digits || '(no digits)') +
            ' [nature=' + n.naiText + ', plan=' + n.npiText +
            ', ' + n.presentation + ', ' + n.screening + ']';
        } else {
          res.value = res.qualifierText + ': ' + hex;
        }
        break;
      }
      case 0xc1: { // Generic digits: encoding/type octet then digits
        if (buf.length < 2) break;
        res.digits = bcdDigits(buf.slice(1), false);
        res.value = 'type 0x' + hex2(buf[0] & 0x1f) + ': ' + res.digits;
        break;
      }
      default:
        break;
    }
  } catch (e) {
    res.value = hex; // a bad parameter never costs us the message
  }
  return res;
}

// ---------------------------------------------------------------------------
// Q.763 message decode
// ---------------------------------------------------------------------------

/**
 * Pick the message name + structure for a type octet. 0x05 is COT in Q.763
 * but is also seen carrying a Subsequent Address Message; a COT body is
 * exactly one octet, so length disambiguates.
 * @param {number} typeCode
 * @param {Buffer} bytes
 * @param {number} typeOffset
 * @returns {{short: string, name: string, known: boolean, struct: object|null}}
 */
function classify(typeCode, bytes, typeOffset) {
  if (typeCode === 0x05 && bytes.length - (typeOffset + 1) >= 3) {
    return { short: 'SAM', name: 'Subsequent address', known: true, struct: STRUCT[0x02] };
  }
  const info = MESSAGE_TYPES[typeCode];
  if (info) {
    return { short: info.short, name: info.name, known: true, struct: STRUCT[typeCode] || null };
  }
  return {
    short: 'unknown(0x' + hex2(typeCode) + ')',
    name: 'unknown ISUP message type',
    known: false,
    struct: null,
  };
}

/**
 * Walk a candidate byte buffer as a Q.763 message, with the message type octet
 * at `typeOffset` (0 = plain ISUP body, 2 = a 2-octet little-endian CIC first).
 *
 * `score` ranks competing readings of the same body (binary vs hex text vs
 * base64, CIC vs no CIC); `acceptable` says whether the reading is good enough
 * to publish as msg.isup at all.
 * @param {Buffer} bytes
 * @param {number} typeOffset
 * @returns {object} decode attempt
 */
function decodeAt(bytes, typeOffset) {
  const res = {
    typeOffset,
    cic: typeOffset >= 2 && bytes.length >= 2 ? ((bytes[1] << 8) | bytes[0]) : null,
    typeCode: null,
    short: null,
    name: null,
    known: false,
    hasStruct: false,
    fields: [],       // [{code, bytes, part}] in wire order
    consumed: 0,      // highest byte offset the decode explained
    truncated: false,
    warnings: [],
    score: 0,
    acceptable: false,
  };
  if (!bytes || bytes.length <= typeOffset) {
    res.warnings.push('ISUP body too short to hold a message type octet');
    return res;
  }
  res.typeCode = bytes[typeOffset];
  res.consumed = typeOffset + 1;
  const cls = classify(res.typeCode, bytes, typeOffset);
  res.short = cls.short;
  res.name = cls.name;
  res.known = cls.known;
  if (cls.known) res.score += 3;
  if (!cls.struct) {
    if (cls.known) res.warnings.push('no structural decode implemented for ' + cls.short);
    return res;
  }
  res.hasStruct = true;

  let i = typeOffset + 1;
  let structOk = true;

  for (const pair of cls.struct.fixed) {
    const code = pair[0];
    const len = pair[1];
    if (i + len > bytes.length) {
      res.truncated = true;
      structOk = false;
      res.warnings.push('body ends inside the mandatory fixed part');
      break;
    }
    res.fields.push({ code, bytes: bytes.slice(i, i + len), part: 'fixed' });
    i += len;
    res.consumed = Math.max(res.consumed, i);
  }

  if (structOk) {
    const nVar = cls.struct.variable.length;
    const nPtr = nVar + (cls.struct.optional ? 1 : 0);
    const ptrBase = i;
    if (ptrBase + nPtr > bytes.length) {
      if (nPtr > 0) {
        res.truncated = true;
        structOk = false;
        res.warnings.push('body ends inside the parameter pointer area');
      }
    } else {
      res.consumed = Math.max(res.consumed, ptrBase + nPtr);
      for (let k = 0; k < nVar; k++) {
        const ptr = bytes[ptrBase + k];
        if (ptr === 0) {
          res.warnings.push('mandatory variable parameter pointer is zero');
          continue;
        }
        const at = ptrBase + k + ptr;
        if (at >= bytes.length) {
          res.truncated = true;
          res.warnings.push('mandatory variable parameter pointer runs past the body');
          continue;
        }
        const len = bytes[at];
        if (at + 1 + len > bytes.length) res.truncated = true;
        const end = Math.min(at + 1 + len, bytes.length);
        res.fields.push({ code: cls.struct.variable[k], bytes: bytes.slice(at + 1, end), part: 'variable' });
        res.consumed = Math.max(res.consumed, end);
      }
      if (cls.struct.optional) {
        const ptr = bytes[ptrBase + nVar];
        if (ptr !== 0) {
          let at = ptrBase + nVar + ptr;
          if (at >= bytes.length) {
            res.truncated = true;
            res.warnings.push('optional part pointer runs past the body');
          }
          let guard = 0;
          while (at < bytes.length && guard++ < 128) {
            const code = bytes[at];
            if (code === 0x00) {      // end of optional parameters
              res.consumed = Math.max(res.consumed, at + 1);
              break;
            }
            if (at + 1 >= bytes.length) {
              res.truncated = true;
              res.warnings.push('body ends inside an optional parameter header');
              break;
            }
            const len = bytes[at + 1];
            const end = at + 2 + len;
            if (end > bytes.length) {
              res.truncated = true;
              res.warnings.push('optional parameter 0x' + hex2(code) + ' is truncated');
              res.fields.push({ code, bytes: bytes.slice(at + 2), part: 'optional' });
              res.consumed = bytes.length;
              break;
            }
            res.fields.push({ code, bytes: bytes.slice(at + 2, end), part: 'optional' });
            res.consumed = Math.max(res.consumed, end);
            at = end;
          }
        }
      }
    }
  }

  if (structOk && !res.truncated) res.score += 2;
  if (res.fields.length) res.score += 1;
  if (res.truncated) res.score -= 2;

  // Coverage: a correct reading explains (nearly) the whole body. This is what
  // separates a genuine binary ISUP blob from an ASCII hex dump whose first
  // character happens to be a valid message type octet.
  const covered = res.consumed >= bytes.length
    ? 2
    : res.consumed >= bytes.length - 4 ? 1 : 0;
  res.score += covered;
  if (res.consumed * 10 < bytes.length * 6) res.score -= 1;

  // Publishable when the type is known and the reading either explains most of
  // the body or is honestly truncated (a partial decode still teaches the user
  // what the message was).
  res.acceptable = res.known && res.hasStruct &&
    (res.truncated || covered > 0 || res.consumed * 10 >= bytes.length * 7);
  return res;
}

/**
 * Decode a byte buffer as one ISUP message, trying both the plain layout and a
 * leading 2-octet CIC (some gateways include it in the MIME body).
 * @param {Buffer} bytes
 * @returns {object} the better of the two decode attempts
 */
function decodeBytes(bytes) {
  const a = decodeAt(bytes, 0);
  if (!bytes || bytes.length < 3) return a;
  const b = decodeAt(bytes, 2);
  return better(b, a) ? b : a;
}

/**
 * Is decode attempt `x` a better reading than `y`? Acceptable beats
 * unacceptable, then the higher score wins (ties keep the incumbent).
 * @param {object} x
 * @param {object} y
 * @returns {boolean}
 */
function better(x, y) {
  if (!x) return false;
  if (!y) return true;
  if (x.acceptable !== y.acceptable) return !!x.acceptable;
  return x.score > y.score;
}

/**
 * Turn a decode attempt into the `msg.isup` object.
 * @param {object} dec output of decodeBytes
 * @param {Buffer} bytes the bytes it decoded
 * @param {string} encoding how the body was carried
 * @returns {object} msg.isup
 */
function buildIsup(dec, bytes, encoding) {
  const isup = {
    messageType: dec.short || 'unknown',
    messageName: dec.name || null,
    calledParty: null,
    callingParty: null,
    causeCode: null,
    causeText: null,
    natureOfConnection: null,
    params: [],
    raw: spacedHex(bytes),
    // additive detail (see ARCHITECTURE.md §Wave 2 SipMessage additions)
    cic: dec.cic === undefined ? null : dec.cic,
    encoding,
    truncated: !!dec.truncated,
    callingPartyCategory: null,
    forwardCallIndicators: null,
    userServiceInformation: null,
    eventInformation: null,
    genericNumbers: [],
    warnings: (dec.warnings || []).slice(),
  };

  for (const f of dec.fields || []) {
    let d;
    try {
      d = decodeParam(f.code, f.bytes);
    } catch (e) {
      d = { name: 'parameter 0x' + hex2(f.code), value: spacedHex(f.bytes) };
    }
    isup.params.push({ name: d.name, value: d.value });

    if (d.digits && (f.code === 0x04 || f.code === 0x05) && isup.calledParty === null) {
      isup.calledParty = d.digits;
    }
    if (d.digits && f.code === 0x0a && isup.callingParty === null) {
      isup.callingParty = d.digits;
    }
    if (d.causeCode !== undefined && d.causeCode !== null && isup.causeCode === null) {
      isup.causeCode = d.causeCode;
      isup.causeText = d.causeText || null;
    }
    if (d.natureOfConnection && !isup.natureOfConnection) {
      isup.natureOfConnection = d.natureOfConnection;
    }
    if (d.callingPartyCategory && !isup.callingPartyCategory) {
      isup.callingPartyCategory = d.callingPartyCategory;
    }
    if (d.fci && !isup.forwardCallIndicators) isup.forwardCallIndicators = d.fci;
    if (d.userServiceInformation && !isup.userServiceInformation) {
      isup.userServiceInformation = d.userServiceInformation;
    }
    if (d.eventInformation && !isup.eventInformation) isup.eventInformation = d.eventInformation;
    if (f.code === 0xc0) {
      isup.genericNumbers.push({
        qualifier: d.qualifierText || null,
        number: d.digits || null,
      });
    }
  }
  return isup;
}

// ---------------------------------------------------------------------------
// ISUP cause vs SIP status: meaning comparison
// ---------------------------------------------------------------------------

/**
 * Meaning class of a Q.850 cause value. 'unspecified' never raises a mismatch.
 * @param {number|null} cause
 * @returns {string|null}
 */
function causeClass(cause) {
  if (typeof cause !== 'number') return null;
  if (cause === 16) return 'normal';
  if (cause === 17) return 'busy';
  if (cause === 18 || cause === 19 || cause === 20) return 'no-answer';
  if (cause === 1 || cause === 2 || cause === 3 || cause === 22 || cause === 23 ||
      cause === 26 || cause === 28) return 'invalid-number';
  if (cause === 34 || cause === 41 || cause === 42 || cause === 44 || cause === 47 ||
      cause === 49 || cause === 58) return 'congestion';
  if (cause === 27 || cause === 38 || cause === 39) return 'network-failure';
  if (cause === 21 || cause === 53 || cause === 55 || cause === 57 || cause === 87) return 'rejected';
  if (cause === 65 || cause === 66 || cause === 69 || cause === 70 || cause === 79 ||
      cause === 88) return 'unimplemented';
  if (cause === 102) return 'timer';
  if (cause === 95 || cause === 96 || cause === 97 || cause === 98 || cause === 99 ||
      cause === 100 || cause === 101 || cause === 103 || cause === 110 ||
      cause === 111 || cause === 127) return 'protocol-error';
  return 'unspecified';
}

/**
 * Meaning class of a SIP final status code.
 * @param {number|null} status
 * @returns {string|null}
 */
function statusClass(status) {
  if (typeof status !== 'number') return null;
  if (status === 486 || status === 600) return 'busy';
  if (status === 404 || status === 410 || status === 484 || status === 485 ||
      status === 604) return 'invalid-number';
  if (status === 480) return 'no-answer';
  if (status === 408 || status === 504) return 'timer';
  if (status === 503) return 'congestion';
  if (status === 502) return 'network-failure';
  if (status === 403 || status === 401 || status === 407 || status === 603) return 'rejected';
  if (status === 415 || status === 488 || status === 501 || status === 606) return 'unimplemented';
  if (status === 400 || status === 500) return 'protocol-error';
  if (status === 487) return 'normal';   // CANCEL maps to a normal-clearing release
  return 'unspecified';
}

/** Classes that mean close enough to the same thing to stay quiet about. */
const CLASS_COMPATIBLE = {
  normal: ['normal'],
  busy: ['busy'],
  'no-answer': ['no-answer', 'timer'],
  'invalid-number': ['invalid-number'],
  congestion: ['congestion', 'network-failure', 'timer'],
  'network-failure': ['network-failure', 'congestion'],
  rejected: ['rejected'],
  unimplemented: ['unimplemented'],
  timer: ['timer', 'no-answer', 'congestion'],
  'protocol-error': ['protocol-error', 'congestion', 'network-failure'],
};

/** Plain-language gloss of a meaning class, for the finding text. */
const CLASS_MEANING = {
  normal: 'a normal, deliberate hang-up',
  busy: 'the called party is busy',
  'no-answer': 'the called party did not answer',
  'invalid-number': 'the number does not exist or is malformed',
  congestion: 'no circuit or resource was available (a capacity or trunk problem)',
  'network-failure': 'a network element is out of order',
  rejected: 'the call was deliberately rejected or barred',
  unimplemented: 'a requested bearer or service is not supported',
  timer: 'a timer expired waiting for the far end',
  'protocol-error': 'a signalling/protocol error',
  unspecified: 'no specific meaning',
};

/**
 * True when an ISUP cause and a SIP status disagree about what happened.
 * @param {string|null} cc cause class
 * @param {string|null} sc status class
 * @returns {boolean}
 */
function classesDisagree(cc, sc) {
  if (!cc || !sc) return false;
  if (cc === 'unspecified' || sc === 'unspecified') return false;
  if (cc === sc) return false;
  const ok = CLASS_COMPATIBLE[cc] || [cc];
  return ok.indexOf(sc) === -1;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Decode SIP-I / SIP-T bodies across a set of SIP messages.
 *
 * Mutates each message in place:
 *   - `msg.bodyParts` for multipart bodies (and for a single-part ISUP body),
 *     as `[{contentType, disposition, body}]`;
 *   - `msg.sdp` when a multipart part carries SDP and no SDP was parsed yet;
 *   - `msg.isup` with the decoded Q.763 message when an ISUP part is present.
 * `msg.raw` is never touched.
 *
 * Never throws: a malformed or truncated body yields an info finding.
 *
 * @param {Array<object>} messages SipMessage[] (H.323 messages are ignored)
 * @returns {{findings: Array<{id: null, severity: string, category: string,
 *   title: string, detail: string, msgIds: string[], legIds: string[],
 *   callIds: string[]}>}}
 */
function extractIsup(messages) {
  const findings = [];
  const list = Array.isArray(messages) ? messages : [];
  const decoded = [];      // messages that ended up with .isup
  let infoEmitted = 0;
  let infoSuppressed = 0;
  let problemEmitted = 0;
  let problemSuppressed = 0;

  const pushFinding = (severity, title, detail, msgIds) => {
    findings.push({
      id: null,
      severity,
      category: CATEGORY,
      title,
      detail,
      msgIds: (msgIds || []).filter(Boolean),
      legIds: [],
      callIds: [],
    });
  };

  // A capture full of the same broken body must not bury the real findings.
  const pushProblem = (title, detail, msgIds) => {
    if (problemEmitted >= MAX_PROBLEM_FINDINGS) { problemSuppressed++; return; }
    problemEmitted++;
    pushFinding('info', title, detail, msgIds);
  };

  for (const msg of list) {
    try {
      if (!msg || typeof msg !== 'object' || msg.protocol !== 'sip') continue;
      const ctVal = getHeader(msg, 'content-type');
      if (!ctVal) continue;
      const base = baseType(ctVal);
      const isMultipart = base.indexOf('multipart/') === 0;
      const isSingleIsup = !isMultipart && isIsupType(ctVal);
      if (!isMultipart && !isSingleIsup) continue;

      const body = messageBody(msg);
      if (!body) {
        pushProblem('Empty ' + base + ' body in ' + label(msg),
          'The message declares a ' + base + ' body but nothing followed the headers, ' +
          'so no SDP or ISUP could be recovered. Captures truncated by a snaplen do this.',
          [msg.id]);
        continue;
      }

      let parts;
      if (isMultipart) {
        const split = splitMultipart(ctVal, body);
        parts = split.parts;
        for (const w of split.warnings) {
          pushProblem('Unreadable multipart body in ' + label(msg),
            w + ' — the body was left as-is, so any encapsulated ISUP is not decoded.',
            [msg.id]);
        }
        if (!parts.length) continue;
      } else {
        parts = [{
          contentType: String(ctVal).trim(),
          disposition: getHeader(msg, 'content-disposition'),
          body,
          transferEncoding: getHeader(msg, 'content-transfer-encoding'),
        }];
      }

      msg.bodyParts = parts.map((p) => ({
        contentType: p.contentType === undefined ? null : p.contentType,
        disposition: p.disposition === undefined ? null : p.disposition,
        body: p.body,
      }));

      // SDP: fill it in when sip.js could not (SIP-I calls must still diff).
      if (msg.sdp === null || msg.sdp === undefined) {
        for (const p of parts) {
          if (baseType(p.contentType) !== 'application/sdp') continue;
          let text = p.body;
          if (String(p.transferEncoding || '').trim().toLowerCase() === 'base64') {
            try {
              text = Buffer.from(String(text).replace(/\s/g, ''), 'base64').toString('latin1');
            } catch (e) { /* keep the original text */ }
          }
          if (text && String(text).indexOf('=') > 0) {
            msg.sdp = parseSdp(text);
            break;
          }
        }
      }

      // ISUP parts
      const isupParts = parts.filter((p) => isIsupType(p.contentType));
      if (!isupParts.length) continue;
      if (isupParts.length > 1) {
        pushProblem('Multiple ISUP parts in ' + label(msg),
          isupParts.length + ' ISUP parts were present; the first one was decoded into ' +
          'the message\'s ISUP view and the rest are available in bodyParts.', [msg.id]);
      }

      const part = isupParts[0];
      const cands = candidateBytes(part.body, part.transferEncoding);
      if (!cands.length) {
        pushProblem('Undecodable ISUP body in ' + label(msg),
          'The ' + (baseType(part.contentType) || 'ISUP') + ' part was empty or held no ' +
          'usable bytes (binary, hex text and base64 readings all came out empty).',
          [msg.id]);
        continue;
      }

      let best = null;
      let bestCand = null;
      for (const cand of cands) {
        const dec = decodeBytes(cand.bytes);
        if (better(dec, best)) { best = dec; bestCand = cand; }
      }
      if (!best || !best.acceptable) {
        // No reading produced a known Q.763 message type — say so, do not guess.
        const shown = bestCand ? spacedHex(bestCand.bytes.slice(0, 16)) : '';
        pushProblem('Could not decode the ISUP body in ' + label(msg),
          'The ' + (baseType(part.contentType) || 'ISUP') + ' part did not decode as a ' +
          'Q.763 message under any reading (binary, hex text or base64). ' +
          'First bytes: ' + (shown || 'none') + '. Left undecoded rather than guessed.',
          [msg.id]);
        continue;
      }

      const isup = buildIsup(best, bestCand.bytes, bestCand.encoding);
      if (bestCand.clipped) {
        isup.warnings.push('body longer than ' + MAX_ISUP_BYTES + ' bytes — decoded the first part only');
      }
      msg.isup = isup;
      decoded.push(msg);

      if (infoEmitted < MAX_INFO_FINDINGS) {
        infoEmitted++;
        pushFinding('info',
          'ISUP ' + isup.messageType + ' in ' + label(msg),
          isupInfoDetail(msg, isup, part),
          [msg.id]);
      } else {
        infoSuppressed++;
      }
    } catch (e) {
      // A single odd message must never cost the capture its analysis.
      try {
        pushProblem('SIP-I body decode skipped',
          'Decoding the body of ' + label(msg) + ' failed (' +
          (e && e.message ? e.message : String(e)) + '); the message is otherwise intact.',
          msg && msg.id ? [msg.id] : []);
      } catch (e2) { /* give up quietly */ }
    }
  }

  if (infoSuppressed > 0) {
    pushFinding('info', infoSuppressed + ' further ISUP messages decoded',
      'Only the first ' + MAX_INFO_FINDINGS + ' encapsulated ISUP messages are listed ' +
      'individually; every decoded message still carries its own ISUP view in the inspector.',
      []);
  }
  if (problemSuppressed > 0) {
    pushFinding('info', problemSuppressed + ' further undecodable SIP-I bodies',
      'The same body problem recurred on ' + problemSuppressed + ' more messages; only the ' +
      'first ' + MAX_PROBLEM_FINDINGS + ' are listed individually.', []);
  }

  // ISUP release cause vs SIP status — the interworking check.
  try {
    for (const f of causeVsStatusFindings(list, decoded)) findings.push(f);
  } catch (e) {
    // never let the cross-check break the module
  }

  return { findings };
}

/** Short human label for a message ('INVITE s3' / '503 s7'). */
function label(msg) {
  if (!msg) return 'a SIP message';
  const id = msg.id ? String(msg.id) : '?';
  if (msg.isRequest && msg.method) return msg.method + ' ' + id;
  if (typeof msg.status === 'number') return msg.status + ' ' + id;
  return id;
}

/**
 * Detail sentence for the per-message info finding.
 * @param {object} msg
 * @param {object} isup
 * @param {object} part the ISUP body part
 * @returns {string}
 */
function isupInfoDetail(msg, isup, part) {
  const bits = [];
  bits.push('SIP-I: ' + label(msg) + ' encapsulates an ISUP ' + isup.messageType +
    (isup.messageName ? ' (' + isup.messageName + ')' : '') + '.');
  const who = [];
  who.push('called ' + (isup.calledParty || 'not present'));
  who.push('calling ' + (isup.callingParty || 'not present'));
  bits.push(who.join(', ') + '.');
  if (isup.causeCode !== null) {
    bits.push('Release cause ' + isup.causeCode +
      (isup.causeText ? ' (' + isup.causeText + ')' : '') + '.');
  }
  if (isup.natureOfConnection) bits.push('Nature of connection: ' + isup.natureOfConnection + '.');
  if (isup.callingPartyCategory) bits.push('Calling party category: ' + isup.callingPartyCategory + '.');
  if (isup.userServiceInformation) bits.push('Bearer: ' + isup.userServiceInformation + '.');
  if (isup.eventInformation) bits.push('Event: ' + isup.eventInformation + '.');
  if (isup.genericNumbers.length) {
    bits.push('Generic number: ' + isup.genericNumbers
      .map((g) => (g.qualifier || 'number') + ' ' + (g.number || '(none)')).join(', ') + '.');
  }
  if (isup.cic !== null && isup.cic !== undefined) bits.push('CIC ' + isup.cic + '.');
  const carriage = isup.encoding === 'binary' ? 'binary' :
    isup.encoding === 'hex-text' ? 'hex text' : 'base64';
  bits.push('Carried as ' + carriage + ' in the ' +
    (baseType(part && part.contentType) || 'application/isup') + ' part.');
  if (isup.truncated) {
    bits.push('The body is truncated — parameters after the cut are missing, which is ' +
      'normal in a snaplen-limited capture.');
  }
  if (isup.params.length) {
    bits.push('Parameters: ' + isup.params.map((p) => p.name).join(', ') + '.');
  }
  return bits.join(' ');
}

/**
 * Compare each encapsulated ISUP release cause with the SIP status that
 * released the same dialog and warn when the two mean different things.
 * @param {Array<object>} all every SIP message
 * @param {Array<object>} decoded messages carrying a decoded .isup
 * @returns {Array<object>} Finding[]
 */
function causeVsStatusFindings(all, decoded) {
  const out = [];
  if (!decoded.length) return out;

  // Per Call-ID: was the INVITE answered, and what was the first final non-2xx?
  const byCallId = new Map();
  for (const m of all) {
    if (!m || m.protocol !== 'sip' || m.isRequest) continue;
    const status = typeof m.status === 'number' ? m.status : null;
    if (status === null || status < 200) continue;
    const forInvite = m.cseq && m.cseq.method === 'INVITE';
    if (!forInvite) continue;
    const key = m.callId || '';
    let g = byCallId.get(key);
    if (!g) { g = { answered: false, final: null }; byCallId.set(key, g); }
    if (status < 300) g.answered = true;
    else if (!g.final) g.final = { status, reason: m.reason || null, msgId: m.id };
  }

  const seen = Object.create(null);
  for (const m of decoded) {
    const isup = m.isup;
    if (!isup || isup.messageType !== 'REL' || typeof isup.causeCode !== 'number') continue;

    let status = null;
    let reason = null;
    let statusMsgId = null;
    if (!m.isRequest && typeof m.status === 'number' && m.status >= 300) {
      status = m.status;
      reason = m.reason || null;
      statusMsgId = m.id;
    } else if (m.isRequest) {
      const g = byCallId.get(m.callId || '');
      if (g && !g.answered && g.final) {
        status = g.final.status;
        reason = g.final.reason;
        statusMsgId = g.final.msgId;
      }
    }
    if (status === null) continue;

    const cc = causeClass(isup.causeCode);
    const sc = statusClass(status);
    if (!classesDisagree(cc, sc)) continue;

    const key = m.id + '>' + statusMsgId;
    if (seen[key]) continue;
    seen[key] = true;

    const msgIds = statusMsgId && statusMsgId !== m.id ? [m.id, statusMsgId] : [m.id];
    const statusText = status + (reason ? ' ' + reason : '');
    out.push({
      id: null,
      severity: 'warn',
      category: CATEGORY,
      title: 'ISUP release cause ' + isup.causeCode + ' disagrees with SIP ' + status +
        ' (' + label(m) + ')',
      detail:
        'The encapsulated ISUP REL gives cause ' + isup.causeCode +
        (isup.causeText ? ' (' + isup.causeText + ')' : '') + ' — ' +
        (CLASS_MEANING[cc] || 'one meaning') + ' — while the SIP side released the call with ' +
        statusText + ', which means ' + (CLASS_MEANING[sc] || 'something else') + '. ' +
        'The two halves of the interworking point are telling different stories about why ' +
        'the call ended: whichever side a downstream system believes, one of them is wrong. ' +
        'That breaks retry logic, call-failure reporting and billing reason codes, and it ' +
        'hides genuine trunk faults behind a benign-looking SIP status (or the reverse). ' +
        'Check the gateway\'s ISUP-to-SIP cause mapping table' +
        (statusMsgId && statusMsgId !== m.id
          ? ' — the SIP status came from ' + statusMsgId + '.'
          : '.'),
      msgIds,
      legIds: [],
      callIds: [],
    });
  }
  return out;
}

module.exports = { extractIsup };
