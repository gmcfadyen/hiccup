#!/usr/bin/env node
'use strict';
// test/mcp.js — MCP-over-HTTP trace reading (lib/mcptrace.js), end to end through
// analyzeCapture(): plaintext-HTTP pcaps, a HAR export, and client-log transcripts.
// Builds its captures in memory (a minimal raw-IP pcap writer), so it needs no fixtures.
// Zero dependencies. Exit code 1 on any failure.

const assert = require('assert');
const eq = (a, b, m) => assert.strictEqual(a, b, m);
const { analyzeCapture } = require('../lib/analyze');

let pass = 0; let fail = 0;
function t(name, fn) {
  try { fn(); pass++; console.log('PASS ' + name); } catch (e) {
    fail++; console.log('FAIL ' + name + '\n     ' + String(e && e.message).split('\n')[0]);
  }
}

// ---------------------------------------------------------------- pcap builder
function ip4(b, o, s) { s.split('.').forEach((x, i) => { b[o + i] = parseInt(x, 10); }); }
function tcpFrame(src, dst, sport, dport, seq, payload) {
  const ipLen = 20 + 20 + payload.length;
  const b = Buffer.alloc(ipLen);
  b[0] = 0x45; b.writeUInt16BE(ipLen, 2); b[8] = 64; b[9] = 6;
  ip4(b, 12, src); ip4(b, 16, dst);
  b.writeUInt16BE(sport, 20); b.writeUInt16BE(dport, 22);
  b.writeUInt32BE(seq >>> 0, 24); b[32] = 0x50; b[33] = 0x18; b.writeUInt16BE(65535, 34);
  payload.copy(b, 40);
  return b;
}
function pcap(frames) {
  const hdr = Buffer.alloc(24);
  hdr.writeUInt32LE(0xa1b2c3d4, 0); hdr.writeUInt16LE(2, 4); hdr.writeUInt16LE(4, 6);
  hdr.writeUInt32LE(65535, 16); hdr.writeUInt32LE(101, 20);          // LINKTYPE_RAW
  const parts = [hdr];
  frames.forEach((f, i) => {
    const ph = Buffer.alloc(16);
    ph.writeUInt32LE(1750000000 + Math.floor(f.ts), 0); ph.writeUInt32LE(Math.round((f.ts % 1) * 1e6), 4);
    ph.writeUInt32LE(f.data.length, 8); ph.writeUInt32LE(f.data.length, 12);
    parts.push(ph, f.data);
  });
  return Buffer.concat(parts);
}

/** Build a TCP conversation. msgs: [{dir:'c'|'s', ts, text}], segmenting at `seg` bytes. */
function conversation(msgs, seg) {
  const C = '10.0.0.5'; const S = '10.0.0.9'; const cp = 51234; const sp = 8080;
  let cs = 1000; let ss = 5000;
  const frames = [];
  for (const m of msgs) {
    const data = Buffer.from(m.text, 'utf8');
    const n = seg || data.length || 1;
    for (let o = 0; o < data.length; o += n) {
      const chunk = data.slice(o, o + n);
      if (m.dir === 'c') { frames.push({ ts: m.ts + o * 1e-6, data: tcpFrame(C, S, cp, sp, cs, chunk) }); cs += chunk.length; }
      else { frames.push({ ts: m.ts + o * 1e-6, data: tcpFrame(S, C, sp, cp, ss, chunk) }); ss += chunk.length; }
    }
  }
  return pcap(frames);
}

const req = (body, extra) => 'POST /mcp HTTP/1.1\r\nHost: mcp.local\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\n'
  + (extra || '') + 'Content-Length: ' + Buffer.byteLength(body) + '\r\n\r\n' + body;
const res = (status, body, extra, ct) => 'HTTP/1.1 ' + status + ' X\r\nContent-Type: ' + (ct || 'application/json') + '\r\n' + (extra || '')
  + 'Content-Length: ' + Buffer.byteLength(body) + '\r\n\r\n' + body;
const J = (o) => JSON.stringify(Object.assign({ jsonrpc: '2.0' }, o));

const INIT = J({ id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test-client', version: '1' } } });
const INIT_OK = J({ id: 1, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'weather', version: '2.0' } } });
const SID = 'Mcp-Session-Id: abcdef123456\r\n';
const SESS = SID + 'MCP-Protocol-Version: 2025-06-18\r\n';

const codes = (a) => [].concat(...a.aux.filter((x) => x.protocol === "mcp").map((x) => x.detail.issues.map((i) => i.code)));
const finding = (a, re) => a.findings.find((f) => f.category === 'mcp' && re.test(f.title));

// ------------------------------------------------------------------ scenarios
t('healthy session: no problems, activity summarised', () => {
  const sse = 'event: message\ndata: ' + J({ id: 3, result: { content: [{ type: 'text', text: '18C' }] } }) + '\n\n';
  const a = analyzeCapture(conversation([
    { dir: 'c', ts: 1, text: req(INIT) },
    { dir: 's', ts: 1.05, text: res(200, INIT_OK, SID) },
    { dir: 'c', ts: 1.1, text: req(J({ method: 'notifications/initialized' }), SESS) },
    { dir: 's', ts: 1.11, text: 'HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n' },
    { dir: 'c', ts: 1.2, text: req(J({ id: 2, method: 'tools/list' }), SESS) },
    { dir: 's', ts: 1.25, text: res(200, J({ id: 2, result: { tools: [{ name: 'get_weather' }] } })) },
    { dir: 'c', ts: 1.3, text: req(J({ id: 3, method: 'tools/call', params: { name: 'get_weather', arguments: { city: 'Oslo' } } }), SESS) },
    { dir: 's', ts: 1.4, text: res(200, sse, '', 'text/event-stream') },
  ]));
  assert.strictEqual(a.stats.mcpExchanges, 4);
  assert.deepStrictEqual(codes(a), []);
  assert.ok(finding(a, /MCP traffic observed \(weather\)/), 'activity finding');
  assert.ok(!a.findings.some((f) => f.category === 'mcp' && f.severity !== 'info'));
  assert.ok(a.aux.some((x) => /tools\/call get_weather/.test(x.summary)));
});

t('401 with a bearer challenge is critical and carries the OAuth fix', () => {
  const a = analyzeCapture(conversation([
    { dir: 'c', ts: 1, text: req(INIT) },
    { dir: 's', ts: 1.02, text: res(401, '{"error":"unauthorized"}', 'WWW-Authenticate: Bearer realm="mcp", resource_metadata="https://x/.well-known/oauth-protected-resource"\r\n') },
  ]));
  assert.deepStrictEqual(codes(a), ['http-401']);
  const f = finding(a, /authentication required/);
  assert.strictEqual(f.severity, 'crit');
  assert.ok(/resource_metadata/.test(f.detail));
});

t('session expiry (404 + Mcp-Session-Id) and a missing session header are told apart', () => {
  const a = analyzeCapture(conversation([
    { dir: 'c', ts: 1, text: req(INIT) },
    { dir: 's', ts: 1.02, text: res(200, INIT_OK, SID) },
    { dir: 'c', ts: 1.1, text: req(J({ method: 'notifications/initialized' })) },
    { dir: 's', ts: 1.11, text: 'HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n' },
    { dir: 'c', ts: 2, text: req(J({ id: 2, method: 'tools/list' }), SESS) },
    { dir: 's', ts: 2.01, text: res(404, '{"error":"unknown session"}') },
  ]));
  const c = codes(a);
  assert.ok(c.includes('http-404-session'), c.join());
  assert.ok(c.includes('missing-session-id'), c.join());
});

t('JSON-RPC errors, tool isError, slow and unanswered requests', () => {
  const a = analyzeCapture(conversation([
    { dir: 'c', ts: 1, text: req(INIT) },
    { dir: 's', ts: 1.02, text: res(200, INIT_OK, SID) },
    { dir: 'c', ts: 1.1, text: req(J({ method: 'notifications/initialized' }), SESS) },
    { dir: 's', ts: 1.11, text: 'HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n' },
    { dir: 'c', ts: 2, text: req(J({ id: 2, method: 'tools/call', params: { name: 'get_weather', arguments: {} } }), SESS) },
    { dir: 's', ts: 2.01, text: res(200, J({ id: 2, error: { code: -32602, message: 'city is required' } })) },
    { dir: 'c', ts: 3, text: req(J({ id: 3, method: 'tools/call', params: { name: 'get_weather', arguments: { city: 'x' } } }), SESS) },
    { dir: 's', ts: 9.5, text: res(200, J({ id: 3, result: { isError: true, content: [{ type: 'text', text: 'upstream 503' }] } })) },
    { dir: 'c', ts: 10, text: req(J({ id: 4, method: 'resources/list' }), SESS) },
    { dir: 's', ts: 10.01, text: res(200, J({ id: 4, error: { code: -32601, message: 'Method not found' } })) },
    { dir: 'c', ts: 11, text: req(J({ id: 5, method: 'tools/call', params: { name: 'slow_tool' } }), SESS) },
  ]));
  const c = codes(a);
  for (const want of ['rpc-invalid-params', 'tool-error', 'slow-response', 'rpc-method-not-found', 'capability-missing', 'no-response']) {
    assert.ok(c.includes(want), 'missing ' + want + ' in ' + c.join());
  }
  const adv = finding(a, /Server rejected the parameters/);
  assert.ok(adv && /city is required/.test(adv.detail), 'error message carried into the finding');
});

t('SSE reply split across TCP segments and chunked is reassembled', () => {
  const ev = 'data: ' + J({ id: 2, result: { tools: [] } }) + '\n\n';
  const chunked = 'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n'
    + Buffer.byteLength(ev).toString(16) + '\r\n' + ev + '\r\n0\r\n\r\n';
  const a = analyzeCapture(conversation([
    { dir: 'c', ts: 1, text: req(INIT) },
    { dir: 's', ts: 1.02, text: res(200, INIT_OK, SID) },
    { dir: 'c', ts: 1.1, text: req(J({ method: 'notifications/initialized' }), SESS) },
    { dir: 's', ts: 1.11, text: 'HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n' },
    { dir: 'c', ts: 2, text: req(J({ id: 2, method: 'tools/list' }), SESS) },
    { dir: 's', ts: 2.2, text: chunked },
  ], 40));
  assert.deepStrictEqual(codes(a), []);
  assert.ok(a.aux.some((x) => x.detail.rpc.some((r) => r.kind === 'response' && r.id === 2)));
});

t('an HTML page in place of the MCP server is called out', () => {
  const a = analyzeCapture(conversation([
    { dir: 'c', ts: 1, text: req(INIT) },
    { dir: 's', ts: 1.02, text: res(200, '<html>Sign in</html>', '', 'text/html') },
  ]));
  assert.ok(codes(a).includes('non-mcp-response'), codes(a).join());
});

t('credentials never reach the analysis', () => {
  const a = analyzeCapture(conversation([
    { dir: 'c', ts: 1, text: req(J({ id: 1, method: 'tools/call', params: { name: 'x', arguments: { api_key: 'sk-SECRET-123', city: 'Oslo' } } }), 'Authorization: Bearer hk_SUPERSECRET\r\n') },
    { dir: 's', ts: 1.02, text: res(401, '{}', 'WWW-Authenticate: Bearer\r\n') },
  ]));
  const dump = JSON.stringify(a);
  assert.ok(!/SUPERSECRET/.test(dump) && !/sk-SECRET-123/.test(dump), 'secret leaked');
  assert.ok(/Bearer REDACTED/.test(dump));
});

t('HTTP that is not MCP is ignored (and an HTTP-only pcap is not mistaken for MCP)', () => {
  assert.throws(() => analyzeCapture(conversation([
    { dir: 'c', ts: 1, text: 'GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n' },
    { dir: 's', ts: 1.1, text: res(200, '<html></html>', '', 'text/html') },
  ])), /no SIP, H\.323 or MCP/);
});

t('HAR export is read, with HTTP status and timing', () => {
  const har = { log: { version: '1.2', entries: [
    { startedDateTime: '2026-01-01T10:00:00.000Z', time: 120, request: { method: 'POST', url: 'https://mcp.example.com/mcp',
      headers: [{ name: 'Authorization', value: 'Bearer abc' }, { name: 'Content-Type', value: 'application/json' }],
      postData: { text: INIT } }, response: { status: 200, statusText: 'OK', headers: [{ name: 'Mcp-Session-Id', value: 'sess-1234567' }, { name: 'Content-Type', value: 'application/json' }], content: { mimeType: 'application/json', text: INIT_OK } } },
    { startedDateTime: '2026-01-01T10:00:01.000Z', time: 40, request: { method: 'POST', url: 'https://mcp.example.com/mcp',
      headers: [{ name: 'Mcp-Session-Id', value: 'sess-1234567' }], postData: { text: J({ id: 2, method: 'tools/list' }) } },
      response: { status: 502, statusText: 'Bad Gateway', headers: [{ name: 'Content-Type', value: 'text/html' }], content: { mimeType: 'text/html', text: '<h1>502</h1>' } } },
  ] } };
  const a = analyzeCapture(Buffer.from(JSON.stringify(har)));
  assert.strictEqual(a.stats.format, 'mcp-har');
  assert.ok(codes(a).includes('http-5xx'), codes(a).join());
  assert.ok(!/Bearer abc/.test(JSON.stringify(a)));
  assert.strictEqual(a.aux[0].detail.latencyMs, 120);
});

t('Claude Desktop style client log is read (direction from the log line)', () => {
  const log = [
    '2026-01-01T10:00:00.100Z [info] [weather] Message from client: ' + INIT,
    '2026-01-01T10:00:00.250Z [info] [weather] Message from server: ' + INIT_OK,
    '2026-01-01T10:00:00.300Z [info] [weather] Message from client: ' + J({ method: 'notifications/initialized' }),
    '2026-01-01T10:00:01.000Z [info] [weather] Message from client: ' + J({ id: 2, method: 'tools/call', params: { name: 'get_weather', arguments: {} } }),
    '2026-01-01T10:00:01.050Z [info] [weather] Message from server: ' + J({ id: 2, error: { code: -32602, message: 'Invalid arguments: city' } }),
    '2026-01-01T10:00:02.000Z [info] [weather] Message from client: ' + J({ id: 3, method: 'tools/call', params: { name: 'get_weather' } }),
  ].join('\n');
  const a = analyzeCapture(Buffer.from(log));
  assert.strictEqual(a.stats.format, 'mcp-log');
  const c = codes(a);
  assert.ok(c.includes('rpc-invalid-params') && c.includes('no-response'), c.join());
  assert.ok(finding(a, /protocol 2025-06-18/) || a.findings.some((f) => /protocol 2025-06-18/.test(f.detail)));
});

t('JSON lines without direction are inferred (requests client→server, results server→client)', () => {
  const log = [INIT, INIT_OK, J({ method: 'notifications/initialized' }), J({ id: 2, method: 'tools/list' })].join('\n');
  const a = analyzeCapture(Buffer.from(log));
  assert.ok(codes(a).includes('no-response'), codes(a).join());
  assert.ok(!codes(a).includes('orphan-response'));
});

t('a capture that starts mid-session skips the handshake checks', () => {
  const a = analyzeCapture(Buffer.from([
    '2026-01-01T10:00:00Z client: ' + J({ id: 7, method: 'tools/list' }),
    '2026-01-01T10:00:00.1Z server: ' + J({ id: 7, result: { tools: [] } }),
  ].join('\n')));
  assert.ok(!codes(a).includes('no-initialize') && !codes(a).includes('orphan-response'), codes(a).join());
});

t('the advisor turns MCP findings into cited advice', () => {
  const a = analyzeCapture(conversation([
    { dir: 'c', ts: 1, text: req(INIT) },
    { dir: 's', ts: 1.02, text: res(401, '{}', 'WWW-Authenticate: Bearer\r\n') },
  ]));
  const adv = a.advice.find((x) => /authentication required/.test(x.title));
  assert.ok(adv, 'advice present: ' + a.advice.map((x) => x.title).join(' | '));
  assert.ok(adv.fixes.length && adv.citations.some((c) => /modelcontextprotocol/.test(c.url || '')));
});

// ------------------------------------------- plain-English explain + chat
function flightTrace() {
  const OK = (id, payload, extra) => res(200, J({ id, result: Object.assign({ content: [{ type: 'text', text: JSON.stringify(payload) }] }, extra || {}) }));
  return analyzeCapture(conversation([
    { dir: 'c', ts: 1, text: req(INIT) },
    { dir: 's', ts: 1.02, text: res(200, INIT_OK, SID) },
    { dir: 'c', ts: 1.1, text: req(J({ method: 'notifications/initialized' }), SESS) },
    { dir: 's', ts: 1.11, text: 'HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n' },
    { dir: 'c', ts: 2, text: req(J({ id: 2, method: 'tools/call', params: { name: 'search_flights', arguments: { origin: 'NCE', destination: 'LHR', departure_date: '2026-12-09', adults: 2 } } }), SESS) },
    { dir: 's', ts: 2.05, text: OK(2, { offers: [{ id: 'A', price_eur: '101.00' }, { id: 'B', price_eur: '163.20' }], note: 'Indicative prices. Call confirm_price before booking.' }) },
    { dir: 'c', ts: 3, text: req(J({ id: 3, method: 'tools/call', params: { name: 'confirm_price', arguments: { offer_id: 'OFR-NOPE' } } }), SESS) },
    { dir: 's', ts: 3.01, text: OK(3, { error: 'OFFER_NOT_FOUND', message: 'Offer not found.', next_step: 'Search again.' }, { isError: true }) },
    { dir: 'c', ts: 4, text: req(J({ id: 4, method: 'tools/call', params: { name: 'book_flight', arguments: { travelers: [{ first_name: 'Ada', last_name: 'Lovelace' }], user_confirmed: true, confirmed_total_eur: '101.00' } } }), SESS) },
    { dir: 's', ts: 4.01, text: OK(4, { order_id: 'ORD-1', pnr: 'ABC123', status: 'HELD', total_eur: '101.00' }) },
    { dir: 'c', ts: 5, text: req(J({ id: 5, method: 'tools/call', params: { name: 'get_booking', arguments: { order_id: 'ORD-1' } } }), SESS) },
    { dir: 's', ts: 5.01, text: res(404, J({ id: 'server-error', error: { code: -32600, message: 'Session not found' } })) },
  ]));
}
const explainOf = (a, re) => {
  const x = a.aux.find((r) => r.protocol === 'mcp' && re.test(r.summary));
  assert.ok(x, 'exchange ' + re + ' present');
  return x.detail.explain.join(' | ');
};

t('each exchange carries a plain-English explanation of request and response', () => {
  const a = flightTrace();
  assert.ok(/test-client opens an MCP session, asking for protocol 2025-06-18/.test(explainOf(a, /initialize/)), explainOf(a, /initialize/));
  assert.ok(/weather 2\.0 accepts.*issues a session id/.test(explainOf(a, /initialize/)), explainOf(a, /initialize/));
  const search = explainOf(a, /search_flights/);
  assert.ok(/run Search flights: NCE → LHR, departing 2026-12-09, 2 adults\./.test(search), search);
  assert.ok(/returned 2 offers \(€101\.00 – €163\.20\)/.test(search), search);
  assert.ok(!/Indicative/.test(search), 'prose notes are left out: ' + search);
  const fail = explainOf(a, /confirm_price/);
  assert.ok(/tool ran but reported failure: OFFER_NOT_FOUND: Offer not found\. Suggested next step: Search again\./.test(fail), fail);
  const book = explainOf(a, /book_flight/);
  assert.ok(/for Ada Lovelace/.test(book) && /confirmed total €101\.00/.test(book) && /pnr ABC123, status HELD, total €101\.00/.test(book), book);
  assert.ok(/HTTP 404 — the server no longer knows this session \(JSON-RPC -32600/.test(explainOf(a, /get_booking/)));
  assert.ok(!JSON.stringify(a).includes('_json'), 'the parsed message helper never reaches the stored analysis');
});

t('chat: an MCP-only capture gets the MCP persona and MCP tools, not SIP ones', () => {
  const agent = require('../lib/agent');
  const a = flightTrace();
  assert.strictEqual(agent.captureKind(a), 'mcp');
  const sys = agent._buildAgentSystem(a);
  assert.ok(/Model Context Protocol/.test(sys) && /NO SIP/.test(sys), 'MCP persona');
  assert.ok(!/SIP\/SBC\/H\.323 engineer/.test(sys) && !/simulate_hmr/.test(sys), 'no SIP persona or HMR rules');
  const names = agent._buildTools(a, null).map((x) => x.def.function.name);
  for (const want of ['list_findings', 'get_advice', 'list_mcp_exchanges', 'get_mcp_exchange']) assert.ok(names.includes(want), 'has ' + want);
  for (const not of ['list_calls', 'get_call', 'search_messages', 'get_message', 'get_media_quality', 'generate_hmr_rule', 'simulate_hmr']) {
    assert.ok(!names.includes(not), 'must not offer ' + not + ' on an MCP trace');
  }
  // the full catalogue (hiccup's own MCP server) still lists everything
  const cat = agent._buildTools({}, null, { catalogue: true }).map((x) => x.def.function.name);
  assert.ok(cat.includes('simulate_hmr') && cat.includes('get_mcp_exchange'), 'catalogue: ' + cat.join());
});

t('chat: MCP tools find the failures and return the evidence', () => {
  const agent = require('../lib/agent');
  const a = flightTrace();
  const by = new Map(agent._buildTools(a, null).map((x) => [x.def.function.name, x]));
  const all = by.get('list_mcp_exchanges').run({});
  assert.strictEqual(all.total, 6);
  const bad = by.get('list_mcp_exchanges').run({ problems_only: true });
  const outcomes = bad.exchanges.map((x) => x.outcome).join(' | ');
  assert.ok(/isError/.test(outcomes) && /HTTP 404/.test(outcomes), outcomes);
  assert.ok(!bad.exchanges.some((x) => /search_flights/.test(x.call)), 'a clean exchange is not a problem');
  eq(by.get('list_mcp_exchanges').run({ tool: 'book_flight' }).matched, 1);
  eq(by.get('list_mcp_exchanges').run({ status: '4xx' }).matched, 1);
  const id = bad.exchanges.find((x) => /isError/.test(x.outcome)).id;
  const one = by.get('get_mcp_exchange').run({ id });
  assert.ok(one.explain && /OFFER_NOT_FOUND/.test(one.explain.join(' ')), 'explanation included');
  assert.ok(one.issues.some((i) => i.code === 'tool-error' && i.citations && i.citations.length), 'issues carry their citations');
  assert.ok(one.messages.some((m) => /OFR-NOPE/.test(m.raw || '')), 'raw JSON-RPC included');
  assert.ok(by.get('get_mcp_exchange').run({ id: 'x99' }).error, 'unknown id names itself');
  const text = agent.mcpExchangesText(a, 30);
  assert.ok(/Search flights: NCE → LHR/.test(text), 'one-shot prompt text carries the explanation');
});

t('an MCP-only trace is classified as MCP (scenario + lamp), not as an unknown SIP capture', () => {
  const a = flightTrace();
  assert.strictEqual(a.scenario.primary, 'mcp');
  assert.ok(/Model Context Protocol/.test(a.scenario.detail) && !/SIP trace/.test(a.scenario.detail), a.scenario.detail);
  const lamp = a.indicators.find((i) => i.key === 'mcp');
  assert.ok(lamp && lamp.state === 'issue', 'MCP lamp lit as issue (there is a crit finding): ' + JSON.stringify(lamp));
});

t('chat: a SIP capture is unchanged (SIP persona, SIP tools, no MCP tools)', () => {
  const agent = require('../lib/agent');
  const sip = { stats: { sipMessages: 2 }, messages: [{ id: 's1', protocol: 'sip', raw: 'INVITE sip:a SIP/2.0' }], aux: [] };
  assert.strictEqual(agent.captureKind(sip), 'voice');
  assert.ok(/SIP\/SBC\/H\.323 engineer/.test(agent._buildAgentSystem(sip)));
  const names = agent._buildTools(sip, null).map((x) => x.def.function.name);
  assert.ok(names.includes('simulate_hmr') && !names.includes('list_mcp_exchanges'), names.join());
});

console.log('\nMCP: ' + pass + '/' + (pass + fail) + ' passed');
process.exit(fail ? 1 : 0);
