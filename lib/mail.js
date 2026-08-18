'use strict';
// mail.js — outbound SMTP, zero dependencies (node:tls only).
//
// Ported from RFPlex.ai's proven sendSmtp(): same Resend account, same
// AUTH LOGIN + multipart/alternative shape. Kept as a straight port rather
// than a rewrite because that implementation has been sending real mail in
// production for months; this is not the place to be original.
//
// Credentials live in data/email-config.json:
//   { user, password, from, smtpHost, smtpPort }
//
// DEGRADES TO A NO-OP when that file is missing or incomplete. hiccup's job is
// analysing SIP traces; an unconfigured mailer must never take the analyser
// down, so isConfigured() is a first-class part of the API and every caller is
// expected to tolerate `{ sent: false }`.

const fs = require('fs');
const path = require('path');
const tls = require('tls');
const crypto = require('crypto');

const DEFAULT_HOST = 'smtp.resend.com';
const DEFAULT_PORT = 465;
const SMTP_TIMEOUT_MS = 30000;

/** Read data/email-config.json, or null when absent/unreadable/malformed. */
function loadConfig(dataDir) {
  const file = path.join(dataDir, 'email-config.json');
  try {
    const raw = fs.readFileSync(file, 'utf8');
    const cfg = JSON.parse(raw.replace(/^﻿/, ''));
    if (!cfg || typeof cfg !== 'object') return null;
    if (!cfg.user || !cfg.password) return null;   // unusable without both
    return {
      host: String(cfg.smtpHost || DEFAULT_HOST),
      port: Number(cfg.smtpPort) || DEFAULT_PORT,
      user: String(cfg.user),
      // Resend shows the key with spaces in the dashboard; strip them the way
      // RFPlex's sender does, otherwise AUTH silently fails.
      pass: String(cfg.password).replace(/\s+/g, ''),
      from: String(cfg.from || cfg.user),
    };
  } catch {
    return null;
  }
}

/** True when a usable SMTP config is present. */
function isConfigured(dataDir) {
  return loadConfig(dataDir) !== null;
}

/**
 * Send one multipart/alternative message.
 * @returns {Promise<void>} rejects on any unexpected SMTP reply code
 */
function sendSmtp({ host, port, user, pass, from, to, subject, text, html }) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({ host, port, servername: host }, () => {});
    sock.setEncoding('utf8');
    let buf = '';
    let step = 0;

    const boundary = 'b_' + crypto.randomBytes(12).toString('hex');
    const messageId = '<' + crypto.randomBytes(8).toString('hex') + '@' +
      (host.replace(/^smtp\./, '') || 'hiccup.monster') + '>';
    const fromHeader = from.includes('<') ? from : ('hiccup <' + from + '>');
    const envelopeFrom = (from.match(/<([^>]+)>/) ? RegExp.$1 : from) || user;

    const data = [
      'From: ' + fromHeader,
      'To: ' + to,
      'Subject: ' + subject,
      'Message-ID: ' + messageId,
      'Date: ' + new Date().toUTCString(),
      'MIME-Version: 1.0',
      'Content-Type: multipart/alternative; boundary="' + boundary + '"',
      '',
      '--' + boundary, 'Content-Type: text/plain; charset=utf-8', '', text, '',
      '--' + boundary, 'Content-Type: text/html; charset=utf-8', '', html, '',
      '--' + boundary + '--',
      '.',
    ].join('\r\n');

    const steps = [
      { send: 'EHLO hiccup.monster\r\n', expect: 250 },
      { send: 'AUTH LOGIN\r\n', expect: 334 },
      { send: Buffer.from(user).toString('base64') + '\r\n', expect: 334 },
      { send: Buffer.from(pass).toString('base64') + '\r\n', expect: 235 },
      { send: 'MAIL FROM:<' + envelopeFrom + '>\r\n', expect: 250 },
      { send: 'RCPT TO:<' + to + '>\r\n', expect: 250 },
      { send: 'DATA\r\n', expect: 354 },
      { send: data + '\r\n', expect: 250 },
      { send: 'QUIT\r\n', expect: 221 },
    ];

    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error('SMTP timeout'));
    }, SMTP_TIMEOUT_MS);

    sock.on('data', (chunk) => {
      buf += chunk;
      for (;;) {
        const i = buf.indexOf('\r\n');
        if (i === -1) return;
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        const code = parseInt(line.slice(0, 3), 10);
        if (line[3] === '-') continue;            // multi-line reply, keep reading
        if (step === 0 && code === 220) { sock.write(steps[0].send); step = 1; continue; }
        const expected = steps[step - 1] && steps[step - 1].expect;
        if (code !== expected) {
          clearTimeout(timer);
          sock.destroy();
          return reject(new Error('SMTP step ' + step + ' failed: ' + line));
        }
        if (step >= steps.length) { clearTimeout(timer); sock.end(); return resolve(); }
        sock.write(steps[step].send);
        step++;
      }
    });

    sock.on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

/**
 * Send mail if configured; otherwise report that it was skipped.
 * Never throws for "not configured" — that is an expected state, not an error.
 *
 * @param {string} dataDir
 * @param {{to:string, subject:string, text:string, html:string}} msg
 * @returns {Promise<{sent:boolean, reason?:string}>}
 */
async function send(dataDir, msg) {
  const cfg = loadConfig(dataDir);
  if (!cfg) return { sent: false, reason: 'no email-config.json' };
  const to = String((msg && msg.to) || '').trim();
  if (!to) return { sent: false, reason: 'no recipient' };
  await sendSmtp({
    host: cfg.host, port: cfg.port, user: cfg.user, pass: cfg.pass, from: cfg.from,
    to,
    subject: String((msg && msg.subject) || '(no subject)'),
    text: String((msg && msg.text) || ''),
    html: String((msg && msg.html) || ''),
  });
  return { sent: true };
}

module.exports = { send, isConfigured, loadConfig };
