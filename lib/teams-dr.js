'use strict';

/**
 * lib/teams-dr.js — Microsoft Teams Direct Routing recognition and checks.
 *
 * Pure, deterministic evidence-reading over parsed SipMessages (see
 * ARCHITECTURE.md "SipMessage"): no LLM, no network, no filesystem, no
 * dependencies. Shared by detect.js (scenario scoring) and advisor.js (the
 * Teams findings), so the "is this Direct Routing?" test lives in one place.
 *
 * Everything here reads what is on the wire in the (decrypted) SIP. It never
 * claims a tenant, certificate or PowerShell setting is wrong — it reports what
 * the capture shows and the advisor frames the fix.
 */

// Microsoft's Direct Routing signalling proxies. The commercial cloud uses
// sip/sip2/sip3.pstnhub.microsoft.com; the sovereign clouds use their own
// pstnhub hostnames. Matching "pstnhub" under a microsoft domain keeps this
// from tripping on an unrelated vendor.
const PSTNHUB_RE = /(?:^|[^a-z0-9-])((?:sip\d?\.)?pstnhub\.[a-z0-9.-]*microsoft\.(?:com|us))\b/i;
const MS_UA_RE = /microsoft\.pstnhub|pstnhub\.sipproxy|microsoft-sip|skypeforbusiness|microsoft teams/i;

function arr(x) { return Array.isArray(x) ? x : []; }
function txt(x) { return x === null || x === undefined ? '' : String(x); }

function headerAll(m, name) {
  const want = name.toLowerCase();
  const out = [];
  for (const h of arr(m && m.headers)) {
    if (h && txt(h.name).toLowerCase() === want) out.push(txt(h.value));
  }
  return out;
}
function header(m, name) { const v = headerAll(m, name); return v.length ? v[0] : ''; }

/** User part of a SIP/tel URI ('sip:+4412@h' -> '+4412'). */
function uriUser(uri) {
  const m = /^(?:sips?|tel):([^@;>\s]+)/i.exec(txt(uri).replace(/^[^<]*<|>.*$/g, '').trim());
  return m ? decodeURIComponent(m[1]) : '';
}
/** Host part of a SIP URI, without port/params. */
function uriHost(uri) {
  const m = /^(?:sips?:)(?:[^@]*@)?\[?([^\]\s;>:]+)/i.exec(txt(uri).replace(/^[^<]*<|>.*$/g, '').trim());
  return m ? m[1] : '';
}
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/** All text of a message the FQDN could appear in. */
function addressText(m) {
  return [m.requestUri, m.toUri, m.fromUri, m.contact].concat(arr(m.vias), arr(m.routes), arr(m.recordRoutes)).map(txt).join(' ');
}

/**
 * Parse every `a=crypto` line in a message's SDP.
 * @returns {{media: Array<{proto: string, port: number, suites: string[]}>}}
 */
function sdpCrypto(m) {
  const out = { media: [] };
  const sdp = m && m.sdp;
  if (!sdp || typeof sdp.raw !== 'string') return out;
  let cur = null;
  for (const line of sdp.raw.split(/\r\n|\n|\r/)) {
    const mm = /^m=(\w+)\s+(\d+)\s+(\S+)/.exec(line);
    if (mm) { cur = { type: mm[1], port: parseInt(mm[2], 10), proto: mm[3], suites: [] }; out.media.push(cur); continue; }
    const cm = /^a=crypto:\d+\s+(\S+)/.exec(line);
    if (cm && cur) cur.suites.push(cm[1].toUpperCase());
  }
  out.media = out.media.filter(x => x.type === 'audio');
  return out;
}

/**
 * Recognise Direct Routing and gather the facts the findings need.
 * @param {Array<object>} sipMessages parsed SIP messages (originals and retransmits)
 * @param {Array<object>} [tlsAux] 'tls' aux rows from lib/tls.js — lets a capture with
 *   no readable SIP (an encrypted 5061 trace) still be recognised from SNI / certificate names
 * @returns {object}
 */
function analyzeTeamsDr(sipMessages, tlsAux) {
  const msgs = arr(sipMessages).filter(m => m && m.protocol === 'sip');
  const signals = [];
  const msIps = new Set();
  const evidence = { fqdn: [], ua: [], xms: [], conv: [] };
  let pstnhubName = '';
  let sbcId = '';

  for (const m of msgs) {
    const at = addressText(m);
    const pm = PSTNHUB_RE.exec(at);
    if (pm) { evidence.fqdn.push(m.id); if (!pstnhubName) pstnhubName = pm[1].toLowerCase(); }
    const ua = header(m, 'user-agent') + ' ' + header(m, 'server');
    if (MS_UA_RE.test(ua)) { evidence.ua.push(m.id); if (m.src) msIps.add(m.src); }
    // A message *from* Microsoft names its own proxy in Contact/From, or is a
    // response from the host we sent a pstnhub request-URI to.
    if (pm && m.isRequest && m.src && /pstnhub/i.test(txt(m.contact) + txt(m.fromUri))) msIps.add(m.src);
    if (pm && m.isRequest && m.dst && /pstnhub/i.test(txt(m.requestUri) + arr(m.routes).join(' '))) msIps.add(m.dst);
    const xms = header(m, 'x-ms-sbc');
    if (xms) { evidence.xms.push(m.id); if (!sbcId) sbcId = xms; }
    if (header(m, 'ms-conversation-id')) evidence.conv.push(m.id);
  }

  const tlsHit = [];
  for (const x of arr(tlsAux)) {
    const d = (x && x.detail) || {};
    const names = [d.sni].concat(d.serverCert ? arr(d.serverCert.san).concat([d.serverCert.subject]) : [], d.clientCert ? arr(d.clientCert.san).concat([d.clientCert.subject]) : []);
    const hit = names.map(txt).find(n => /pstnhub/i.test(n));
    if (hit) { tlsHit.push(x); if (!pstnhubName) { const m = PSTNHUB_RE.exec(' ' + hit.replace(/^\*\./, '')); pstnhubName = (m ? m[1] : hit).toLowerCase(); } }
  }

  if (!evidence.fqdn.length && tlsHit.length) signals.push({ name: 'pstnhub-fqdn', detail: 'the TLS handshake names the Direct Routing proxy ' + pstnhubName + ' (SNI or certificate)', ids: [] });
  if (evidence.fqdn.length) signals.push({ name: 'pstnhub-fqdn', detail: 'the Direct Routing proxy ' + pstnhubName + ' appears in the signalling', ids: evidence.fqdn.slice(0, 6) });
  if (evidence.ua.length) signals.push({ name: 'pstnhub-user-agent', detail: 'a Microsoft PSTNHub SIP proxy User-Agent/Server is present', ids: evidence.ua.slice(0, 6) });
  if (evidence.xms.length) signals.push({ name: 'x-ms-sbc', detail: 'an X-MS-SBC header identifies the SBC to Microsoft (' + sbcId + ')', ids: evidence.xms.slice(0, 6) });
  if (evidence.conv.length) signals.push({ name: 'ms-conversation-id', detail: 'Ms-Conversation-ID headers are present, which Teams adds to every leg', ids: evidence.conv.slice(0, 6) });

  const toMs = m => (m.dst && msIps.has(m.dst)) || PSTNHUB_RE.test(txt(m.requestUri) + arr(m.routes).join(' '));
  const detected = signals.length > 0;

  // --- OPTIONS keep-alive health -------------------------------------------
  const options = { total: 0, ok: 0, failed: [], unanswered: [] };
  if (detected) {
    const answered = new Map();
    for (const m of msgs) {
      if (m.isRequest || !m.cseq || m.cseq.method !== 'OPTIONS' || m.status < 200) continue;
      answered.set(m.callId + '|' + m.cseq.num, m);
    }
    for (const m of msgs) {
      if (!m.isRequest || m.method !== 'OPTIONS' || m.retransOf || !m.cseq) continue;
      options.total++;
      const r = answered.get(m.callId + '|' + m.cseq.num);
      if (!r) options.unanswered.push(m.id);
      else if (r.status >= 200 && r.status < 300) options.ok++;
      else options.failed.push({ id: r.id, status: r.status, reason: txt(r.reason) });
    }
  }

  // --- media security towards Microsoft ------------------------------------
  const media = [];
  for (const m of msgs) {
    if (!detected || m.retransOf || !m.sdp || !toMs(m)) continue;
    const c = sdpCrypto(m);
    for (const a of c.media) {
      if (a.port === 0) continue;
      const srtp = /SAVP/i.test(a.proto);
      let problem = null;
      if (!srtp || !a.suites.length) problem = 'no-srtp';
      else if (a.suites.indexOf('AES_CM_128_HMAC_SHA1_80') === -1) problem = 'no-sha1-80';
      if (problem) media.push({ id: m.id, problem, proto: a.proto, suites: a.suites, callId: m.callId });
    }
  }

  // --- identity / addressing towards Microsoft -----------------------------
  const identity = [];
  const contactIp = [];
  for (const m of msgs) {
    if (!detected || m.retransOf || !m.isRequest || !toMs(m)) continue;
    if (m.method === 'INVITE') {
      for (const [field, uri] of [['Request-URI', m.requestUri], ['From', m.fromUri], ['To', m.toUri]]) {
        const u = uriUser(uri);
        if (u && /^\+?\d+$/.test(u) && u[0] !== '+') identity.push({ id: m.id, field, user: u });
      }
    }
    if (m.method === 'INVITE' || m.method === 'OPTIONS') {
      const host = uriHost(m.contact);
      if (host && IPV4_RE.test(host)) contactIp.push({ id: m.id, host });
    }
  }

  // --- rejections from Microsoft -------------------------------------------
  const rejects = [];
  for (const m of msgs) {
    if (!detected || m.retransOf || m.isRequest || m.status < 400) continue;
    if (!(m.src && msIps.has(m.src)) && !MS_UA_RE.test(header(m, 'server') + header(m, 'user-agent'))) continue;
    if (m.cseq && m.cseq.method === 'OPTIONS') continue; // reported under options
    rejects.push({ id: m.id, status: m.status, reason: txt(m.reason), method: m.cseq ? m.cseq.method : '', callId: m.callId });
  }

  const tls = tlsHit.length > 0 || msgs.some(m => /tls/i.test(arr(m.vias).join(' ')) || m.sport === 5061 || m.dport === 5061 || /^sips:/i.test(txt(m.requestUri)));

  return { detected, signals, pstnhub: pstnhubName, sbc: sbcId, msIps: Array.from(msIps), options, media, identity, contactIp, rejects, tls };
}

module.exports = { analyzeTeamsDr, sdpCrypto, uriUser, uriHost, PSTNHUB_RE, MS_UA_RE };
