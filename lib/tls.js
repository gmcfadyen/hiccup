'use strict';

/**
 * lib/tls.js — read the CLEAR part of TLS handshakes in a pcap.
 *
 * hiccup does not decrypt anything (docs/DECRYPTION.md). But the start of a
 * TLS session is in the clear: ClientHello (version, SNI, ALPN), ServerHello,
 * and — for TLS 1.2 and earlier — the server (and client) Certificate, plus any
 * unencrypted Alert. That is enough to answer the first question on a SIP-over-
 * TLS trunk such as Teams Direct Routing: "did the handshake even work, and is
 * the certificate the right one?". For a capture with no readable SIP it is the
 * only evidence there is.
 *
 * Output follows the same shape as lib/ice.js and lib/dns.js:
 *   extractTls(packets, ctx) -> { aux: [...], findings: [...] }
 * One 'tls' aux summary per TCP flow that carries TLS, and findings for fatal
 * alerts, incomplete handshakes, expired / not-yet-valid / self-signed
 * certificates, SNI that the certificate does not cover, and TLS < 1.2.
 *
 * Zero dependencies, defensive: any parse problem ends that flow's decoding and
 * is reported as "not readable", never thrown.
 */

const MAX_FLOWS = 50;
const MAX_STREAM_BYTES = 256 * 1024;

const VERSIONS = { 0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' };
const ALERTS = {
  0: 'close_notify', 10: 'unexpected_message', 20: 'bad_record_mac', 40: 'handshake_failure', 42: 'bad_certificate',
  43: 'unsupported_certificate', 44: 'certificate_revoked', 45: 'certificate_expired', 46: 'certificate_unknown',
  47: 'illegal_parameter', 48: 'unknown_ca', 49: 'access_denied', 50: 'decode_error', 51: 'decrypt_error',
  70: 'protocol_version', 71: 'insufficient_security', 80: 'internal_error', 86: 'inappropriate_fallback',
  90: 'user_canceled', 109: 'missing_extension', 112: 'unrecognized_name', 113: 'bad_certificate_status_response',
  116: 'certificate_required', 120: 'no_application_protocol',
};

// ---------------------------------------------------------------- DER (X.509)

function tlv(buf, off) {
  if (off + 2 > buf.length) throw new Error('der: truncated');
  const tag = buf[off];
  let len = buf[off + 1];
  let p = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 3 || p + n > buf.length) throw new Error('der: bad length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p++];
  }
  if (p + len > buf.length) throw new Error('der: overrun');
  return { tag, start: p, end: p + len };
}

function derTime(buf, t) {
  const s = buf.slice(t.start, t.end).toString('latin1');
  const m = t.tag === 0x17 ? /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z$/.exec(s) : /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z$/.exec(s);
  if (!m) return null;
  let y = parseInt(m[1], 10);
  if (t.tag === 0x17) y += y >= 50 ? 1900 : 2000;
  return Date.UTC(y, parseInt(m[2], 10) - 1, parseInt(m[3], 10), parseInt(m[4], 10), parseInt(m[5], 10), parseInt(m[6] || '0', 10));
}

/** Common Name and Organisation of a DER Name. */
function derName(buf, name) {
  const out = { cn: null, o: null, text: '' };
  let p = name.start;
  while (p < name.end) {
    const rdn = tlv(buf, p); p = rdn.end;
    let q = rdn.start;
    while (q < rdn.end) {
      const atv = tlv(buf, q); q = atv.end;
      const oid = tlv(buf, atv.start);
      const val = tlv(buf, oid.end);
      const oidHex = buf.slice(oid.start, oid.end).toString('hex');
      const v = buf.slice(val.start, val.end).toString('utf8');
      if (oidHex === '550403') out.cn = v;
      else if (oidHex === '55040a') out.o = v;
    }
  }
  out.text = [out.cn ? 'CN=' + out.cn : null, out.o ? 'O=' + out.o : null].filter(Boolean).join(', ');
  return out;
}

/** Minimal X.509 reader: subject/issuer, validity and dNSName SANs. Null if unreadable. */
function parseCertificate(der) {
  try {
    const cert = tlv(der, 0);
    const tbs = tlv(der, cert.start);
    let t = tlv(der, tbs.start);
    if (t.tag === 0xa0) t = tlv(der, t.end);          // explicit version
    t = tlv(der, t.end);                               // (serial consumed above) -> signature alg
    const issuer = tlv(der, t.end);
    const validity = tlv(der, issuer.end);
    const subject = tlv(der, validity.end);
    const spki = tlv(der, subject.end);
    const nb = tlv(der, validity.start);
    const na = tlv(der, nb.end);
    const out = {
      subject: derName(der, subject),
      issuer: derName(der, issuer),
      notBefore: derTime(der, nb),
      notAfter: derTime(der, na),
      san: [],
    };
    out.selfSigned = !!out.subject.text && out.subject.text === out.issuer.text;
    let p = spki.end;
    while (p < tbs.end) {
      const e = tlv(der, p); p = e.end;
      if (e.tag !== 0xa3) continue;
      const seq = tlv(der, e.start);
      let q = seq.start;
      while (q < seq.end) {
        const ext = tlv(der, q); q = ext.end;
        const oid = tlv(der, ext.start);
        if (der.slice(oid.start, oid.end).toString('hex') !== '551d11') continue;
        let v = tlv(der, oid.end);
        if (v.tag === 0x01) v = tlv(der, v.end);       // skip critical flag
        const names = tlv(der, v.start);
        let r = names.start;
        while (r < names.end) {
          const gn = tlv(der, r); r = gn.end;
          if (gn.tag === 0x82) out.san.push(der.slice(gn.start, gn.end).toString('latin1').toLowerCase());
        }
      }
    }
    return out;
  } catch (e) {
    return null;
  }
}

/** Does the certificate cover `host` (exact SAN, one-label wildcard, or CN when no SAN)? */
function certCovers(cert, host) {
  const h = String(host || '').toLowerCase();
  if (!h || !cert) return true;
  const names = cert.san.length ? cert.san : (cert.subject.cn ? [cert.subject.cn.toLowerCase()] : []);
  if (!names.length) return true;
  return names.some((n) => n === h || (n.startsWith('*.') && h.split('.').slice(1).join('.') === n.slice(2) && h.split('.').length === n.split('.').length));
}

// ---------------------------------------------------------------- TLS records

function u16(b, o) { return (b[o] << 8) | b[o + 1]; }
function u24(b, o) { return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]; }

function parseClientHello(b) {
  const out = { version: u16(b, 0), sni: null, alpn: [], supported: [] };
  let p = 2 + 32;
  p += 1 + b[p];                       // session id
  const cs = u16(b, p); p += 2 + cs;   // cipher suites
  p += 1 + b[p];                       // compression
  if (p + 2 > b.length) return out;
  const extEnd = Math.min(b.length, p + 2 + u16(b, p)); p += 2;
  while (p + 4 <= extEnd) {
    const type = u16(b, p); const len = u16(b, p + 2); const d = b.slice(p + 4, p + 4 + len); p += 4 + len;
    if (type === 0 && d.length >= 5) out.sni = d.slice(5, 5 + u16(d, 3)).toString('latin1');
    else if (type === 16 && d.length >= 2) {
      let q = 2;
      while (q < d.length) { const l = d[q]; out.alpn.push(d.slice(q + 1, q + 1 + l).toString('latin1')); q += 1 + l; }
    } else if (type === 43 && d.length >= 1) {
      for (let q = 1; q + 1 < d.length; q += 2) out.supported.push(u16(d, q));
    }
  }
  return out;
}

function parseServerHello(b) {
  const out = { version: u16(b, 0), cipher: null, tls13: false };
  let p = 2 + 32;
  p += 1 + b[p];
  out.cipher = u16(b, p); p += 3;      // cipher + compression
  if (p + 2 > b.length) return out;
  const extEnd = Math.min(b.length, p + 2 + u16(b, p)); p += 2;
  while (p + 4 <= extEnd) {
    const type = u16(b, p); const len = u16(b, p + 2);
    if (type === 43 && len >= 2 && u16(b, p + 4) === 0x0304) { out.tls13 = true; out.version = 0x0304; }
    p += 4 + len;
  }
  return out;
}

function parseCertificates(b) {
  const certs = [];
  let p = 3;
  const end = Math.min(b.length, 3 + u24(b, 0));
  while (p + 3 <= end) {
    const l = u24(b, p); p += 3;
    if (p + l > b.length) break;
    certs.push(b.slice(p, p + l)); p += l;
  }
  return certs;
}

/** Decode one direction's byte stream into what is visible in the clear. */
function decodeStream(buf) {
  const r = { handshakes: [], alerts: [], ccs: false, appData: 0, encryptedAfterHello: false, certs: [], clientHello: null, serverHello: null, certRequest: false, unreadable: false };
  let off = 0;
  let hs = Buffer.alloc(0);
  let clear = true;
  while (off + 5 <= buf.length) {
    const type = buf[off]; const ver = u16(buf, off + 1); const len = u16(buf, off + 3);
    if ((ver >> 8) !== 3 || len > 18432) { r.unreadable = true; break; }
    if (off + 5 + len > buf.length) break;
    const body = buf.slice(off + 5, off + 5 + len);
    off += 5 + len;
    if (type === 20) { r.ccs = true; clear = false; continue; }
    if (type === 21) {
      if (clear && len === 2) r.alerts.push({ level: body[0] === 2 ? 'fatal' : 'warning', code: body[1], description: ALERTS[body[1]] || ('alert ' + body[1]) });
      continue;
    }
    if (type === 23) { r.appData++; continue; }
    if (type !== 22 || !clear) { if (type === 22) r.encryptedAfterHello = true; continue; }
    hs = Buffer.concat([hs, body]);
    while (hs.length >= 4 && hs.length >= 4 + u24(hs, 1)) {
      const mtype = hs[0]; const mlen = u24(hs, 1);
      const m = hs.slice(4, 4 + mlen); hs = hs.slice(4 + mlen);
      try {
        if (mtype === 1) { r.handshakes.push('ClientHello'); r.clientHello = parseClientHello(m); }
        else if (mtype === 2) {
          r.handshakes.push('ServerHello'); r.serverHello = parseServerHello(m);
          if (r.serverHello.tls13) clear = false; // everything after ServerHello is encrypted in 1.3
        } else if (mtype === 11) { r.handshakes.push('Certificate'); r.certs = parseCertificates(m); }
        else if (mtype === 13) { r.handshakes.push('CertificateRequest'); r.certRequest = true; }
        else if (mtype === 14) r.handshakes.push('ServerHelloDone');
        else if (mtype === 16) r.handshakes.push('ClientKeyExchange');
        else if (mtype === 12) r.handshakes.push('ServerKeyExchange');
        else r.handshakes.push('handshake ' + mtype);
      } catch (e) { r.unreadable = true; }
    }
  }
  return r;
}

/** Reassemble one direction of a TCP flow from its packets (by sequence number). */
function streamOf(pkts) {
  const list = pkts.slice().sort((a, b) => (a.tcp && b.tcp ? ((a.tcp.seq - b.tcp.seq) | 0) : a.n - b.n));
  if (!list.length) return Buffer.alloc(0);
  const base = list[0].tcp ? list[0].tcp.seq : 0;
  const parts = [];
  let have = 0;
  for (const p of list) {
    const at = p.tcp ? ((p.tcp.seq - base) >>> 0) : have;
    if (at > have) { parts.push(Buffer.alloc(0)); break; }   // a gap: stop at the hole
    const skip = have - at;
    if (skip < p.payload.length) { parts.push(p.payload.slice(skip)); have += p.payload.length - skip; }
    if (have > MAX_STREAM_BYTES) break;
  }
  return Buffer.concat(parts);
}

function looksLikeTls(b) {
  return b.length >= 5 && (b[0] === 0x16 || b[0] === 0x15) && b[1] === 0x03 && b[2] <= 0x04;
}

function versionName(v) { return VERSIONS[v] || ('0x' + (v || 0).toString(16)); }

/**
 * @param {Array<object>} packets Packet[] from pcap.js
 * @returns {{aux: Array<object>, findings: Array<object>}}
 */
function extractTls(packets) {
  const aux = [];
  const findings = [];
  const flows = new Map();
  for (const p of packets || []) {
    if (!p || p.transport !== 'tcp' || !p.payload || !p.payload.length) continue;
    const a = p.src + ':' + p.sport; const b = p.dst + ':' + p.dport;
    const key = a < b ? a + '|' + b : b + '|' + a;
    let f = flows.get(key);
    if (!f) { f = { key, dirs: new Map(), firstTs: p.ts, lastTs: p.ts, pkts: [] }; flows.set(key, f); }
    if (!f.dirs.has(a)) f.dirs.set(a, []);
    f.dirs.get(a).push(p);
    f.pkts.push(p.n);
    f.lastTs = p.ts;
  }

  let count = 0;
  for (const f of flows.values()) {
    if (count >= MAX_FLOWS) break;
    const dirs = Array.from(f.dirs.entries()).map(([from, pk]) => ({ from, buf: streamOf(pk) }));
    if (!dirs.some((d) => looksLikeTls(d.buf))) continue;
    count++;
    const decoded = dirs.filter((d) => looksLikeTls(d.buf)).map((d) => ({ from: d.from, r: decodeStream(d.buf), bytes: d.buf.length }));
    const client = decoded.find((d) => d.r.clientHello) || null;
    const server = decoded.find((d) => d.r.serverHello) || null;
    const certSide = decoded.find((d) => d.r.certs.length && d !== client) || decoded.find((d) => d.r.certs.length) || null;
    const clientCertSide = client && client.r.certs.length ? client : null;

    const sh = server && server.r.serverHello;
    const versionNum = sh ? sh.version : (client ? (client.r.clientHello.supported.indexOf(0x0304) !== -1 ? 0x0304 : client.r.clientHello.version) : 0);
    const version = versionName(versionNum);
    const alerts = [];
    for (const d of decoded) for (const al of d.r.alerts) alerts.push({ from: d === client ? 'client' : 'server', level: al.level, description: al.description });
    const fatal = alerts.find((x) => x.level === 'fatal') || null;
    const bothCcs = decoded.length >= 2 && decoded.every((d) => d.r.ccs);
    const tls13Data = !!(sh && sh.tls13 && decoded.some((d) => d.r.appData > 0));
    const complete = !fatal && !!(sh && (bothCcs || tls13Data));
    const serverCert = certSide && certSide.r.certs.length ? parseCertificate(certSide.r.certs[0]) : null;
    const clientCert = clientCertSide ? parseCertificate(clientCertSide.r.certs[0]) : null;
    const sni = client ? client.r.clientHello.sni : null;
    const tsMs = (f.firstTs > 1e12 ? f.firstTs : f.firstTs * 1000);
    const hostAddr = (client || decoded[0]).from;
    const peerAddr = (dirs.find((d) => d.from !== hostAddr) || { from: null }).from;
    const certsHidden = !!(sh && sh.tls13);

    const steps = [];
    for (const d of decoded) for (const h of d.r.handshakes) steps.push((d === client ? 'client' : 'server') + ': ' + h);
    for (const al of alerts) steps.push(al.from + ': Alert ' + al.level + ' ' + al.description);

    let summary;
    if (fatal) summary = 'TLS handshake FAILED — ' + fatal.from + ' sent fatal alert ' + fatal.description;
    else if (complete) summary = version + ' handshake completed' + (sni ? ' (SNI ' + sni + ')' : '') + (serverCert && serverCert.subject.cn ? ', server certificate ' + serverCert.subject.cn : '') + (certsHidden ? ' (certificate encrypted in TLS 1.3)' : '');
    else if (client && !sh) summary = 'TLS ClientHello sent' + (sni ? ' (SNI ' + sni + ')' : '') + ' but no ServerHello was seen — the server never answered the handshake';
    else summary = 'TLS handshake incomplete after ' + (steps.length ? steps[steps.length - 1] : 'the first record');

    const src = hostAddr.slice(0, hostAddr.lastIndexOf(':'));
    const sport = Number(hostAddr.slice(hostAddr.lastIndexOf(':') + 1)) || null;
    const dst = peerAddr ? peerAddr.slice(0, peerAddr.lastIndexOf(':')) : null;
    const dport = peerAddr ? Number(peerAddr.slice(peerAddr.lastIndexOf(':') + 1)) || null : null;

    const expired = serverCert && serverCert.notAfter !== null && tsMs > serverCert.notAfter;
    const notYet = serverCert && serverCert.notBefore !== null && tsMs < serverCert.notBefore;
    const coversSni = !serverCert || !sni || certCovers(serverCert, sni);

    const row = {
      id: null, protocol: 'tls', ts: f.firstTs, src, sport, dst, dport, transport: 'tcp',
      summary,
      detail: {
        role: 'summary', version, sni, alpn: client ? client.r.clientHello.alpn : [],
        complete, steps, alerts, certsHidden, mutualTls: !!(clientCert || (server && server.r.certRequest)),
        serverCert: serverCert && summarizeCert(serverCert, expired, notYet, coversSni),
        clientCert: clientCert && summarizeCert(clientCert, false, false, true),
        firstTs: f.firstTs, lastTs: f.lastTs, pktRefs: f.pkts.slice(0, 20),
      },
      raw: null, legIds: [], callIds: [],
    };
    aux.push(row);

    const ref = { legIds: [], callIds: [], msgIds: [] };
    const where = ' (' + src + ':' + sport + ' -> ' + dst + ':' + dport + ')';
    if (fatal) findings.push({ severity: 'crit', category: 'tls', title: 'TLS handshake failed: ' + fatal.description, detail: fatal.from + ' sent a fatal TLS alert ' + fatal.description + where + '. No SIP can flow over this connection.', ...ref });
    else if (!complete && client && !sh) findings.push({ severity: 'crit', category: 'tls', title: 'TLS ClientHello got no ServerHello', detail: 'The client started a TLS handshake' + (sni ? ' for ' + sni : '') + where + ' and the server never replied with a ServerHello — a firewall, closed port or a non-TLS listener on that port.', ...ref });
    if (expired) findings.push({ severity: 'crit', category: 'tls', title: 'TLS server certificate had expired', detail: 'The certificate ' + serverCert.subject.text + ' expired ' + new Date(serverCert.notAfter).toISOString().slice(0, 10) + ' and this handshake was captured later' + where + '.', ...ref });
    if (notYet) findings.push({ severity: 'crit', category: 'tls', title: 'TLS server certificate was not yet valid', detail: 'The certificate ' + serverCert.subject.text + ' only becomes valid ' + new Date(serverCert.notBefore).toISOString().slice(0, 10) + ' — check the clock on both ends' + where + '.', ...ref });
    if (!coversSni) findings.push({ severity: 'crit', category: 'tls', title: 'TLS certificate does not cover the requested name', detail: 'The client asked for ' + sni + ' but the certificate names are ' + (serverCert.san.length ? serverCert.san.join(', ') : 'CN=' + (serverCert.subject.cn || '?')) + where + '. A strict client such as Microsoft Teams rejects this.', ...ref });
    if (serverCert && serverCert.selfSigned) findings.push({ severity: 'warn', category: 'tls', title: 'TLS server certificate is self-signed', detail: 'The certificate ' + serverCert.subject.text + ' is its own issuer' + where + '. Public services such as Teams Direct Routing require a certificate from a trusted CA.', ...ref });
    if (versionNum && versionNum < 0x0303) findings.push({ severity: 'warn', category: 'tls', title: 'TLS older than 1.2 negotiated', detail: version + ' was used' + where + '. Microsoft Teams Direct Routing needs TLS 1.2 or later.', ...ref });
  }
  return { aux, findings };
}

function summarizeCert(c, expired, notYet, coversSni) {
  return {
    subject: c.subject.text, issuer: c.issuer.text, san: c.san.slice(0, 20),
    notBefore: c.notBefore === null ? null : new Date(c.notBefore).toISOString(),
    notAfter: c.notAfter === null ? null : new Date(c.notAfter).toISOString(),
    selfSigned: c.selfSigned, expired: !!expired, notYetValid: !!notYet, coversSni: !!coversSni,
  };
}

module.exports = { extractTls, parseCertificate, certCovers, decodeStream };
