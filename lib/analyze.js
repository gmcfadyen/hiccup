'use strict';
// analyze.js — orchestration: sniff → parse → extract → group → correlate → diff
// → retrans → redact → merge. Owns the AnalysisJSON contract in ARCHITECTURE.md.

const { parsePcap } = require('./pcap');
const { parseTextLog, sniffText } = require('./textlog');
const { extractSipMessages, groupSipLegs, getHeader } = require('./sip');
const { extractH323Messages, groupH323Legs } = require('./h323');
const { correlateLegs } = require('./correlate');
const { diffLegs } = require('./diff');
const { analyzeRetransmissions } = require('./retrans');

const PCAP_MAGICS = [0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1];
const PCAPNG_MAGIC = 0x0a0d0d0a;

function userError(message) {
  const e = new Error(message);
  e.userMessage = message;
  return e;
}

/** Sniff the buffer and parse it into Packet[] with a format label. */
function parseInput(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 4) {
    throw userError('This file is empty or too small to be a capture.');
  }
  const magic = buffer.readUInt32BE(0);
  if (PCAP_MAGICS.includes(magic) || PCAP_MAGICS.includes(buffer.readUInt32LE(0))) {
    return parsePcap(buffer);
  }
  if (magic === PCAPNG_MAGIC || buffer.readUInt32LE(0) === PCAPNG_MAGIC) {
    return parsePcap(buffer);
  }
  if (sniffText(buffer)) {
    return parseTextLog(buffer.toString('utf8'));
  }
  throw userError('Not a recognized capture: expected pcap, pcapng, or a SIP text/SBC log export.');
}

/** Digest credentials must never survive into stored analysis or LLM prompts. */
function redactSipMessage(msg) {
  const CRED_HEADER = /^(authorization|proxy-authorization)$/i;
  const redactParams = (v) => v
    .replace(/(response\s*=\s*")[^"]*(")/gi, '$1REDACTED$2')
    .replace(/(cnonce\s*=\s*")[^"]*(")/gi, '$1REDACTED$2');
  for (const h of msg.headers || []) {
    if (CRED_HEADER.test(h.name) || /response\s*=|cnonce\s*=/i.test(h.value)) {
      const before = h.value;
      const after = redactParams(before);
      if (after !== before) {
        h.value = after;
        if (typeof msg.raw === 'string') msg.raw = msg.raw.split(before).join(after);
      }
    }
  }
  // Belt and braces on the raw text in case a credential lived outside headers[].
  if (typeof msg.raw === 'string' && /response\s*=\s*"/i.test(msg.raw)) {
    msg.raw = redactParams(msg.raw);
  }
}

function maskDigits(s) {
  return s.replace(/(\+?\d{4})\d{2,}(\d{2})/g, (_, a, b) => a + '…' + b);
}

/** Optional caller/callee masking for shared environments. Best-effort. */
function redactNumbersInMessage(msg) {
  for (const h of msg.headers || []) {
    if (/^(from|to|p-asserted-identity|remote-party-id|contact|history-info|diversion|f|t|m)$/i.test(h.name)) {
      h.value = maskDigits(h.value);
    }
  }
  if (typeof msg.raw === 'string') {
    msg.raw = msg.raw.replace(/sip:(\+?\d{7,})@/g, (_, num) => 'sip:' + maskDigits(num) + '@');
  }
  if (msg.fromUser && /^\+?\d{7,}$/.test(msg.fromUser)) msg.fromUser = maskDigits(msg.fromUser);
  if (msg.toUser && /^\+?\d{7,}$/.test(msg.toUser)) msg.toUser = maskDigits(msg.toUser);
}

/**
 * Analyze one uploaded capture (pcap/pcapng buffer or SBC/SIP text file).
 * @param {Buffer} buffer raw uploaded bytes
 * @param {{redactNumbers?: boolean}} [opts]
 * @returns {object} AnalysisJSON per ARCHITECTURE.md
 */
function analyzeCapture(buffer, opts = {}) {
  const parsed = parseInput(buffer);
  const packets = parsed.packets || [];
  const warnings = (parsed.warnings || []).slice();

  const sipMessages = extractSipMessages(packets);
  const h323Messages = extractH323Messages(packets);
  if (sipMessages.length === 0 && h323Messages.length === 0) {
    throw userError('Parsed the file, but found no SIP or H.323 signalling in it.');
  }

  // Redact before any module can quote a credential into derived text.
  for (const m of sipMessages) redactSipMessage(m);
  if (opts.redactNumbers) {
    for (const m of sipMessages) redactNumbersInMessage(m);
  }

  const sipLegs = groupSipLegs(sipMessages);
  const h323Legs = groupH323Legs(h323Messages);
  const legs = sipLegs.concat(h323Legs);

  const messages = sipMessages.concat(h323Messages)
    .sort((a, b) => (a.ts - b.ts) || String(a.id).localeCompare(String(b.id)));
  const msgById = new Map(messages.map(m => [m.id, m]));
  const legById = new Map(legs.map(l => [l.id, l]));

  const correlation = correlateLegs(legs, messages);
  const calls = correlation.calls || [];

  for (const call of calls) {
    call.diffs = [];
    const ids = call.legIds || [];
    for (let i = 0; i + 1 < ids.length; i++) {
      const a = legById.get(ids[i]);
      const b = legById.get(ids[i + 1]);
      if (a && b && a.protocol === 'sip' && b.protocol === 'sip') {
        try {
          call.diffs.push({ a: a.id, b: b.id, diff: diffLegs(a, b, messages) });
        } catch (e) {
          warnings.push(`diff failed for ${a.id}/${b.id}: ${e.message}`);
        }
      }
    }
  }

  const retrans = analyzeRetransmissions(messages, legs);

  // Merge findings: modules first, then cross-references cleaned up.
  const findings = [];
  const collect = (list, fallbackCategory) => {
    for (const f of list || []) {
      findings.push({
        id: null,
        severity: f.severity || 'info',
        category: f.category || fallbackCategory,
        title: f.title || '(untitled finding)',
        detail: f.detail || '',
        msgIds: (f.msgIds || []).filter(id => msgById.has(id)),
        legIds: (f.legIds || []).filter(id => legById.has(id)),
        callIds: f.callIds || [],
      });
    }
  };
  collect(correlation.findings, 'correlation');
  for (const call of calls) for (const d of call.diffs || []) collect(d.diff && d.diff.findings, 'diff');
  collect(retrans.findings, 'retrans');
  if (warnings.length) {
    collect([{
      severity: 'info', category: 'parse',
      title: `${warnings.length} parser warning${warnings.length === 1 ? '' : 's'}`,
      detail: warnings.slice(0, 20).join('; '),
    }], 'parse');
  }
  const sevRank = { crit: 0, warn: 1, notice: 2, info: 3 };
  findings.sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9));
  findings.forEach((f, i) => { f.id = 'f' + (i + 1); });

  const tsList = messages.map(m => m.ts).filter(t => Number.isFinite(t));
  const transports = { udp: 0, tcp: 0 };
  for (const m of messages) {
    if (m.transport === 'udp') transports.udp++;
    else if (m.transport === 'tcp') transports.tcp++;
  }

  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    stats: {
      format: parsed.format,
      packets: packets.length,
      sipMessages: sipMessages.length,
      h323Messages: h323Messages.length,
      legs: legs.length,
      calls: calls.length,
      pairedCalls: calls.filter(c => c.state === 'paired').length,
      timespan: tsList.length
        ? { start: tsList.reduce((a, b) => Math.min(a, b)), end: tsList.reduce((a, b) => Math.max(a, b)) }
        : { start: null, end: null },
      transports,
      warnings,
    },
    messages,
    legs,
    calls,
    retrans,
    findings,
  };
}

module.exports = { analyzeCapture, parseInput };
