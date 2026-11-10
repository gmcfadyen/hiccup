'use strict';

/**
 * lib/mcptrace.js — read and diagnose MCP (Model Context Protocol) traffic.
 *
 * MCP's "streamable HTTP" transport is JSON-RPC 2.0 carried in HTTP POST bodies,
 * answered with either application/json or a text/event-stream (SSE). hiccup treats
 * it like any other protocol it reads: decode it, pair requests with responses,
 * apply deterministic rules, and say what is wrong and what to change. No LLM.
 *
 * Three ways in (all end in the same Exchange[] model):
 *   1. A pcap/pcapng holding PLAINTEXT HTTP/1.1 (a loopback or internal hop, a
 *      TLS-terminating proxy's backend side). Reassembled per TCP flow, any port.
 *   2. A HAR export (browser devtools, MCP Inspector behind a proxy, Charles, ...).
 *   3. A JSON-RPC transcript: JSON lines, or client log lines such as Claude
 *      Desktop's `Message from client: {...}` / `Message from server: {...}`.
 *
 * hiccup does not decrypt TLS (docs/DECRYPTION.md). An MCP capture taken on the wire
 * over HTTPS is ciphertext: lib/tls.js still reports the handshake, and the advice
 * points at the HAR / client-log routes above.
 *
 * Exports:
 *   extractMcp(packets, ctx) -> { aux: [AuxMessage], findings: [Finding] }
 *       ctx.mcpExchanges (from parseMcpText) is used when the input was text/HAR.
 *   sniffMcpText(buffer) -> boolean
 *   parseMcpText(text)   -> { format, warnings, packets: [], mcpExchanges: [Exchange] }
 *
 * Defensive by contract: never throws; every cap is explicit.
 * Zero runtime dependencies. CommonJS.
 */

const MAX_EXCHANGES = 3000;
const MAX_RAW = 600;
const MAX_STREAM_BYTES = 8 * 1024 * 1024;
const SLOW_MS = 5000;
const VERY_SLOW_MS = 30000;
const KNOWN_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];

const SPEC = 'https://modelcontextprotocol.io/specification/2025-06-18';
const cite = (section, title, path) => ({ source: 'MCP spec', section, title, url: SPEC + path });
const CITES = {
  transport: cite('Transports', 'Streamable HTTP', '/basic/transports#streamable-http'),
  lifecycle: cite('Lifecycle', 'Initialization and version negotiation', '/basic/lifecycle'),
  auth: cite('Authorization', 'OAuth 2.1 for HTTP transports', '/basic/authorization'),
  session: cite('Transports', 'Session management', '/basic/transports#session-management'),
  tools: cite('Tools', 'Tool calls and error reporting', '/server/tools#error-handling'),
  cancel: cite('Cancellation', 'notifications/cancelled', '/basic/utilities/cancellation'),
  jsonrpc: { source: 'JSON-RPC 2.0', section: 'Error object', title: 'Error codes',
    url: 'https://www.jsonrpc.org/specification#error_object' },
  http: { source: 'RFC 9110', section: null, title: 'HTTP Semantics', url: 'https://www.rfc-editor.org/rfc/rfc9110' },
  prm: { source: 'RFC 9728', section: null, title: 'OAuth 2.0 Protected Resource Metadata',
    url: 'https://www.rfc-editor.org/rfc/rfc9728' },
};

// ----------------------------------------------------------------- issue table
// All MCP diagnostic knowledge lives here. Each code carries the plain-language
// "why it matters" and ordered fixes; evidence is added per occurrence. The advisor
// renders these generically (rule 'mcp-problem'), so adding a code adds advice.
const ISSUES = {
  'http-401': {
    severity: 'crit', title: 'MCP server rejected the request: authentication required (401)',
    why: 'The server wants a valid credential and did not get one, so no MCP method can run. Clients usually surface this as "connection failed" or an endless re-auth loop.',
    fixes: [
      { summary: 'Send a valid bearer token on every request.', steps: [
        'Add `Authorization: Bearer <token>` to every POST/GET to the MCP endpoint, including the first `initialize`.',
        'If the WWW-Authenticate header names a `resource_metadata` URL, fetch it (RFC 9728) to find the authorization server, run the OAuth flow, and retry with the issued token.',
        'If it says `error="invalid_token"`, the token is expired, revoked or issued for another audience/resource — get a fresh one for this server\'s URL.' ] },
      { summary: 'Check a proxy is not stripping the Authorization header.', steps: [
        'Compare the request as the client sent it with what the server logged; CDNs and gateways that cache or rewrite headers are the usual culprit.' ] },
    ], cites: [CITES.auth, CITES.prm],
  },
  'http-403': {
    severity: 'crit', title: 'MCP server refused the request (403 Forbidden)',
    why: 'The credential was understood but not permitted — wrong scope/audience, an IP or Origin allow-list, or a WAF rule.',
    fixes: [
      { summary: 'Check scopes, audience and Origin policy.', steps: [
        'If the body mentions Origin/Host, the server is doing DNS-rebinding protection: connect with the Host/Origin it expects, or add yours to its allow-list.',
        'Request the scopes the tool needs and make sure the token\'s audience matches this MCP server URL.',
        'If a WAF is in front, look for a block event matching the request path and User-Agent.' ] },
    ], cites: [CITES.auth, CITES.transport],
  },
  'http-404-session': {
    severity: 'crit', title: 'MCP session no longer exists on the server (404 with Mcp-Session-Id)',
    why: 'The server forgot the session (restart, scale-out to a different instance, idle expiry). The spec says a client getting 404 for a session id must start a new session; a client that keeps reusing the id fails forever.',
    fixes: [
      { summary: 'Start a fresh session: send a new `initialize` without Mcp-Session-Id.', steps: [
        'Client: on 404 for a request that carried Mcp-Session-Id, discard the id and re-run initialize.',
        'Server behind a load balancer: pin each session to one backend (sticky on Mcp-Session-Id) or move session state to a shared store.',
        'Raise the server\'s session idle timeout if clients are quiet for long periods.' ] },
    ], cites: [CITES.session],
  },
  'http-404': {
    severity: 'crit', title: 'MCP endpoint not found (404)',
    why: 'The URL the client posts to is not the MCP endpoint, so nothing can be negotiated.',
    fixes: [
      { summary: 'Use the exact endpoint URL the server documents.', steps: [
        'Common mistakes: `/` instead of `/mcp`, `/sse` (legacy transport) instead of the streamable endpoint, or a missing/extra trailing slash.',
        'Check any reverse-proxy path rewrite: the backend must still see the path it routes on.' ] },
    ], cites: [CITES.transport],
  },
  'http-405-post': {
    severity: 'crit', title: 'MCP endpoint does not accept POST (405)',
    why: 'Streamable HTTP requires the endpoint to accept POST. A 405 on POST usually means the client is pointed at a legacy SSE endpoint or a static route.',
    fixes: [
      { summary: 'Point the client at the streamable-HTTP endpoint.', steps: [
        'If the server only offers the older HTTP+SSE transport (a GET /sse then POST /messages), use a client configured for SSE or upgrade the server.' ] },
    ], cites: [CITES.transport],
  },
  'http-406': {
    severity: 'crit', title: 'Server rejected the Accept header (406 Not Acceptable)',
    why: 'A client POSTing to the MCP endpoint must accept BOTH application/json and text/event-stream; many servers return 406 if either is missing.',
    fixes: [
      { summary: 'Send `Accept: application/json, text/event-stream` on every POST.', steps: [
        'Hand-rolled clients and curl tests often send only `application/json`.' ] },
    ], cites: [CITES.transport],
  },
  'http-415': {
    severity: 'crit', title: 'Server rejected the Content-Type (415)',
    why: 'The request body must be JSON.',
    fixes: [{ summary: 'Send `Content-Type: application/json`.', steps: [
      'Check the HTTP library is not defaulting to form encoding or `text/plain`.' ] }],
    cites: [CITES.transport],
  },
  'http-400': {
    severity: 'warn', title: 'Server rejected a request as malformed (400)',
    why: 'The server could not accept the message — bad JSON, a missing/invalid Mcp-Session-Id or MCP-Protocol-Version header, or an unsupported batch.',
    fixes: [{ summary: 'Read the 400 body; it normally names the problem.', steps: [
      'After `initialize`, every request must carry the Mcp-Session-Id the server issued (if it issued one) and an MCP-Protocol-Version header.',
      'Do not send JSON-RPC batches to servers speaking 2025-06-18 or later.' ] }],
    cites: [CITES.session, CITES.transport],
  },
  'http-redirect': {
    severity: 'crit', title: 'POST to the MCP endpoint was redirected',
    why: 'Many HTTP clients turn a redirected POST into a GET (301/302) or drop the body, so the JSON-RPC request never arrives and the follow-up returns 405/404. The usual trigger is http→https or a trailing-slash redirect.',
    fixes: [{ summary: 'Configure the client with the final URL.', steps: [
      'Use the https URL and the exact path (with or without the trailing slash) the redirect points to.',
      'Or make the proxy serve the MCP path directly instead of redirecting.' ] }],
    cites: [CITES.http],
  },
  'http-429': {
    severity: 'warn', title: 'MCP server is rate limiting the client (429)',
    why: 'Requests above the server or gateway\'s limit are rejected; agent loops can hit this quickly.',
    fixes: [{ summary: 'Back off and honour Retry-After.', steps: [
      'Cache `tools/list` rather than calling it per turn, and cap parallel `tools/call`.',
      'Ask the operator to raise the limit for this token.' ] }],
    cites: [CITES.http],
  },
  'http-5xx': {
    severity: 'crit', title: 'MCP server or its gateway failed (HTTP 5xx)',
    why: 'The request reached something that could not serve it. A 502/504 from a gateway means the MCP backend was down or too slow; 500 is a server bug.',
    fixes: [{ summary: 'Look at the server and gateway logs for that timestamp.', steps: [
      '502/503: backend not running, crashing, or health-check failing behind the proxy.',
      '504: backend slower than the gateway\'s timeout — raise it, and for SSE disable response buffering and set a read timeout longer than your longest tool call.',
      '500: the tool handler threw; reproduce that exact `tools/call` directly.' ] }],
    cites: [CITES.http],
  },
  'non-mcp-response': {
    severity: 'crit', title: 'Reply to an MCP request is not JSON or SSE',
    why: 'A client expects application/json or text/event-stream. Anything else (HTML login page, WAF block page, captive portal) means something other than the MCP server answered.',
    fixes: [{ summary: 'Find what is answering instead of the MCP server.', steps: [
      'Open the response body: an HTML sign-in or "request blocked" page identifies a proxy, SSO gateway or WAF in the path.',
      'Allow the MCP path and `text/event-stream` through it, or bypass it for this endpoint.' ] }],
    cites: [CITES.transport],
  },
  'no-response': {
    severity: 'warn', title: 'MCP request never got a response',
    why: 'The client is left waiting until its own timeout. Typical causes: a hung tool handler, a proxy that buffers or kills long SSE streams, or the connection being cut mid-call.',
    fixes: [{ summary: 'Find where the response was lost.', steps: [
      'Check the server log for the request id: if it never arrived, the problem is in the network/proxy; if it arrived, the handler hung.',
      'Behind nginx/ALB/Cloudflare: turn off response buffering for the MCP path, and raise idle/read timeouts above the longest tool run.',
      'Have long tools emit `notifications/progress` so intermediaries see traffic, and honour `notifications/cancelled`.' ] }],
    cites: [CITES.transport, CITES.cancel],
  },
  'slow-response': {
    severity: 'notice', title: 'MCP request was slow to answer',
    why: 'Long waits make agents look hung and trip client or gateway timeouts.',
    fixes: [{ summary: 'Speed up or stream progress for the slow method.', steps: [
      'Profile the named tool; add progress notifications for anything over a few seconds.',
      'Confirm the gateway timeout is longer than this call.' ] }],
    cites: [CITES.transport],
  },
  'rpc-parse-error': {
    severity: 'warn', title: 'Server could not parse the JSON the client sent (-32700)',
    why: 'The body reached the server damaged or not JSON, so nothing in it was executed.',
    fixes: [{ summary: 'Check the bytes on the wire match what the client meant to send.', steps: [
      'A proxy that truncates or re-encodes bodies, a wrong Content-Length, or a non-UTF-8 charset can all do this.',
      'Log the raw request body on the server for one failing call.' ] }],
    cites: [CITES.jsonrpc],
  },
  'rpc-invalid-request': {
    severity: 'warn', title: 'Server says the message is not a valid JSON-RPC request (-32600)',
    why: 'The envelope is wrong — missing `jsonrpc: "2.0"`, bad `id` type, or a batch the server does not accept.',
    fixes: [{ summary: 'Fix the envelope.', steps: [
      'Every message needs `"jsonrpc":"2.0"`; requests need a string or integer `id` (never null) and a `method`.',
      'Send one message per POST rather than an array.' ] }],
    cites: [CITES.jsonrpc],
  },
  'rpc-method-not-found': {
    severity: 'warn', title: 'Server does not implement the method called (-32601)',
    why: 'The client called a method the server does not support — often a capability the server never advertised during initialize.',
    fixes: [{ summary: 'Only call methods the server advertised.', steps: [
      'Compare the method with `capabilities` in the initialize result (tools, resources, prompts, logging, completions).',
      'Check method spelling: `tools/list`, `tools/call`, `resources/read`, `prompts/get`.',
      'If you recently upgraded the client, the server may be on an older protocolVersion.' ] }],
    cites: [CITES.lifecycle, CITES.jsonrpc],
  },
  'rpc-invalid-params': {
    severity: 'warn', title: 'Server rejected the parameters (-32602)',
    why: 'The method exists but the arguments did not match its schema, so the tool or resource did not run.',
    fixes: [{ summary: 'Make the arguments match the tool\'s inputSchema.', steps: [
      'Fetch `tools/list` and validate against the tool\'s `inputSchema` (required fields, types, enums).',
      'The error message below usually names the offending field.' ] }],
    cites: [CITES.tools, CITES.jsonrpc],
  },
  'rpc-internal-error': {
    severity: 'crit', title: 'Server hit an internal error handling the request (-32603)',
    why: 'The request was valid but the server code failed.',
    fixes: [{ summary: 'Reproduce and fix on the server.', steps: [
      'Find the stack trace in the server log at this timestamp; replay the exact request.',
      'Servers should return tool failures as a result with `isError: true`, reserving -32603 for protocol faults.' ] }],
    cites: [CITES.jsonrpc, CITES.tools],
  },
  'rpc-server-not-initialized': {
    severity: 'warn', title: 'Server says the session is not initialized',
    why: 'A request arrived before the initialize handshake completed on this session, or the server restarted and lost it.',
    fixes: [{ summary: 'Re-run the handshake.', steps: [
      'Send `initialize`, then `notifications/initialized`, then your requests — on the same session.' ] }],
    cites: [CITES.lifecycle],
  },
  'rpc-error': {
    severity: 'warn', title: 'Server returned a JSON-RPC error',
    why: 'The call failed at the protocol level.',
    fixes: [{ summary: 'Read the error code and message.', steps: [
      'Codes -32700…-32600 are protocol faults; -32000…-32099 are server-defined and the message explains them.' ] }],
    cites: [CITES.jsonrpc],
  },
  'tool-error': {
    severity: 'notice', title: 'A tool call ran but reported failure (isError)',
    why: 'This is the normal way an MCP tool says "I tried and it did not work" — the protocol is healthy, the tool is not. The model sees the text and may retry.',
    fixes: [{ summary: 'Fix the tool\'s own failure.', steps: [
      'Read the error text below: bad input, a downstream API error, missing permission or an expired upstream credential are the usual causes.',
      'Make errors actionable so the model can correct its next call.' ] }],
    cites: [CITES.tools],
  },
  'no-initialize': {
    severity: 'warn', title: 'Request sent before initialize completed',
    why: 'The lifecycle requires `initialize` and its response before any other request. Strict servers refuse; lenient ones work until a capability is needed.',
    fixes: [{ summary: 'Always initialize first.', steps: [
      'Order: initialize (request) → result → notifications/initialized → everything else.' ] }],
    cites: [CITES.lifecycle],
  },
  'no-initialized-notification': {
    severity: 'notice', title: 'Client never sent notifications/initialized',
    why: 'The handshake is incomplete; spec-following servers may ignore or reject requests until they see it.',
    fixes: [{ summary: 'Send `notifications/initialized` after the initialize result.', steps: [
      'It is a notification (no `id`); expect HTTP 202 Accepted.' ] }],
    cites: [CITES.lifecycle],
  },
  'version-mismatch': {
    severity: 'notice', title: 'Server negotiated a different protocol version than the client asked for',
    why: 'The server answered with another version. A client that does not support it must disconnect; one that does will run with the older/newer feature set.',
    fixes: [{ summary: 'Align versions or upgrade the older side.', steps: [
      'Check that the client supports the version in the initialize result; features from the newer spec (structured output, elicitation, resource links) will not exist on an older negotiation.' ] }],
    cites: [CITES.lifecycle],
  },
  'unknown-version': {
    severity: 'warn', title: 'Server replied with a protocol version hiccup does not recognise',
    why: 'The negotiated `protocolVersion` is not one of the published MCP revisions, so client and server may disagree about message shapes.',
    fixes: [{ summary: 'Set a published version.', steps: [
      'Known revisions: ' + KNOWN_VERSIONS.join(', ') + '.' ] }],
    cites: [CITES.lifecycle],
  },
  'missing-session-id': {
    severity: 'warn', title: 'Client stopped sending Mcp-Session-Id after the server issued one',
    why: 'The server assigned a session at initialize; later requests without the header are treated as a different (or invalid) session and are answered 400/404.',
    fixes: [{ summary: 'Echo Mcp-Session-Id on every later request.', steps: [
      'Capture it from the initialize response header and send it on all subsequent POST/GET/DELETE.',
      'Check a proxy is not dropping custom headers (some strip names it does not know).' ] }],
    cites: [CITES.session],
  },
  'missing-protocol-version-header': {
    severity: 'notice', title: 'MCP-Protocol-Version header missing on later requests',
    why: 'From 2025-06-18 the client must send the negotiated version on every HTTP request after initialize; servers may reject without it.',
    fixes: [{ summary: 'Send `MCP-Protocol-Version: <negotiated version>` on every request after initialize.', steps: [] }],
    cites: [CITES.transport],
  },
  'capability-missing': {
    severity: 'warn', title: 'Client used a feature the server did not advertise',
    why: 'The initialize result does not list this capability, so the server is allowed to refuse it (typically -32601).',
    fixes: [{ summary: 'Gate calls on advertised capabilities.', steps: [
      'Check `capabilities.tools / resources / prompts` in the initialize result before calling their methods.' ] }],
    cites: [CITES.lifecycle],
  },
  'bad-jsonrpc': {
    severity: 'warn', title: 'Message is not valid JSON-RPC 2.0',
    why: 'Missing `jsonrpc: "2.0"`, a response carrying both result and error, or no method/result/error at all. Strict peers ignore or reject these.',
    fixes: [{ summary: 'Emit well-formed JSON-RPC 2.0.', steps: [
      'A response has exactly one of `result` or `error`; a request has `method` and a non-null `id`.' ] }],
    cites: [CITES.jsonrpc],
  },
  'duplicate-id': {
    severity: 'warn', title: 'Request id reused while the first is still unanswered',
    why: 'Ids must be unique per session; a reused id makes responses ambiguous.',
    fixes: [{ summary: 'Use a monotonic id per session.', steps: [] }],
    cites: [CITES.jsonrpc],
  },
  'orphan-response': {
    severity: 'notice', title: 'Response for a request not seen in this capture',
    why: 'Either the capture started mid-session or the server answered with an id the client never sent.',
    fixes: [{ summary: 'If the capture is partial, ignore; otherwise check the server echoes the request id exactly.', steps: [] }],
    cites: [CITES.jsonrpc],
  },
  'batch-unsupported': {
    severity: 'notice', title: 'JSON-RPC batch used on a protocol version that dropped batching',
    why: 'Batching was removed in 2025-06-18; servers on that revision may reject arrays.',
    fixes: [{ summary: 'Send each message as its own POST.', steps: [] }],
    cites: [CITES.transport],
  },
  'legacy-sse': {
    severity: 'notice', title: 'Legacy HTTP+SSE transport (2024-11-05) in use',
    why: 'The server announced an `endpoint` event on a GET stream. That transport is deprecated; newer clients default to streamable HTTP and fail against SSE-only servers.',
    fixes: [{ summary: 'Use the matching transport on both sides.', steps: [
      'Configure the client for SSE, or move the server to streamable HTTP (single POST endpoint).' ] }],
    cites: [CITES.transport],
  },
  'cancelled': {
    severity: 'notice', title: 'Client cancelled a request',
    why: 'The client gave up waiting — usually a timeout or the user stopping the run. Look at what that request was doing.',
    fixes: [{ summary: 'Investigate why the request took long enough to be cancelled.', steps: [] }],
    cites: [CITES.cancel],
  },
  'non-json-body': {
    severity: 'warn', title: 'Body on an MCP request/response is not valid JSON',
    why: 'The peer cannot parse it. Seen with truncated bodies, double-encoding, or an HTML error page.',
    fixes: [{ summary: 'Inspect the raw body below.', steps: [] }],
    cites: [CITES.jsonrpc],
  },
};

const RPC_ERROR_CODES = {
  '-32700': 'rpc-parse-error', '-32600': 'rpc-invalid-request', '-32601': 'rpc-method-not-found',
  '-32602': 'rpc-invalid-params', '-32603': 'rpc-internal-error', '-32002': 'rpc-server-not-initialized',
};

// ------------------------------------------------------------------ redaction
const SECRET_KEY = /token|secret|password|passwd|api[-_]?key|authorization|credential|cookie|client[-_]?secret/i;

function redactValue(v, depth) {
  if (depth > 8 || v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.map((x) => redactValue(x, depth + 1));
  const out = {};
  for (const k of Object.keys(v)) {
    out[k] = SECRET_KEY.test(k) && typeof v[k] === 'string' ? 'REDACTED' : redactValue(v[k], depth + 1);
  }
  return out;
}

function redactHeaders(h) {
  const out = {};
  for (const k of Object.keys(h || {})) {
    const lk = k.toLowerCase();
    let v = String(h[k]);
    if (lk === 'authorization' || lk === 'proxy-authorization') v = v.replace(/^(\S+)\s+.*/, '$1 REDACTED');
    else if (lk === 'cookie' || lk === 'set-cookie') v = 'REDACTED';
    else if (/^x-.*(key|token|secret)/.test(lk)) v = 'REDACTED';
    else if (lk === 'mcp-session-id') v = v.length > 8 ? v.slice(0, 6) + '…' : v;
    out[lk] = v;
  }
  return out;
}

// ----------------------------------------------------------------- HTTP / SSE
const REQ_LINE = /^(POST|GET|DELETE|PUT|PATCH|OPTIONS|HEAD) (\S+) HTTP\/1\.[01]$/;
const RES_LINE = /^HTTP\/1\.[01] (\d{3})(?: (.*))?$/;
const START_RE = /(?:^|\r\n)(?:(?:POST|GET|DELETE|PUT|PATCH|OPTIONS|HEAD) \S+ HTTP\/1\.[01]|HTTP\/1\.[01] \d{3})/g;

function parseHeaderBlock(lines) {
  const h = {};
  for (let i = 1; i < lines.length; i++) {
    const c = lines[i].indexOf(':');
    if (c <= 0) continue;
    const k = lines[i].slice(0, c).trim().toLowerCase();
    const v = lines[i].slice(c + 1).trim();
    h[k] = k in h ? h[k] + ', ' + v : v;
  }
  return h;
}

/** Decode a chunked body starting at `off`. Returns what is complete so far. */
function decodeChunked(buf, off) {
  const parts = [];
  let p = off;
  for (;;) {
    const e = buf.indexOf('\r\n', p, 'latin1');
    if (e < 0) return { body: Buffer.concat(parts), end: p, complete: false };
    const size = parseInt(buf.toString('latin1', p, e).split(';')[0].trim(), 16);
    if (!Number.isFinite(size)) return { body: Buffer.concat(parts), end: p, complete: false };
    if (size === 0) {
      const t = buf.indexOf('\r\n\r\n', e, 'latin1');
      return { body: Buffer.concat(parts), end: t < 0 ? buf.length : t + 4, complete: true };
    }
    if (e + 2 + size > buf.length) {
      parts.push(buf.slice(e + 2));
      return { body: Buffer.concat(parts), end: buf.length, complete: false };
    }
    parts.push(buf.slice(e + 2, e + 2 + size));
    p = e + 2 + size + 2;
  }
}

function parseHttpStream(buf) {
  const out = [];
  let off = 0;
  while (off < buf.length) {
    const he = buf.indexOf('\r\n\r\n', off, 'latin1');
    if (he < 0) break;
    const lines = buf.toString('latin1', off, he).split('\r\n');
    const rq = REQ_LINE.exec(lines[0]);
    const rs = rq ? null : RES_LINE.exec(lines[0]);
    if (!rq && !rs) {
      START_RE.lastIndex = off + 1;
      const m = START_RE.exec(buf.toString('latin1', off + 1));
      if (!m) break;
      off = off + 1 + m.index + (m[0].startsWith('\r\n') ? 2 : 0);
      continue;
    }
    const headers = parseHeaderBlock(lines);
    const bodyStart = he + 4;
    const status = rs ? parseInt(rs[1], 10) : 0;
    const noBody = status < 200 || status === 204 || status === 304 || (rq && rq[1] === 'HEAD');
    let body = Buffer.alloc(0);
    let end = bodyStart;
    let complete = true;
    if (noBody && rs) {
      end = bodyStart;
    } else if (/chunked/i.test(headers['transfer-encoding'] || '')) {
      const d = decodeChunked(buf, bodyStart);
      body = d.body; end = d.end; complete = d.complete;
    } else if (headers['content-length'] !== undefined) {
      const n = parseInt(headers['content-length'], 10) || 0;
      end = Math.min(buf.length, bodyStart + n);
      body = buf.slice(bodyStart, end);
      complete = bodyStart + n <= buf.length;
    } else if (rs) {
      body = buf.slice(bodyStart); end = buf.length; complete = false;     // close-delimited / open SSE
    }
    out.push({
      kind: rq ? 'req' : 'res', start: off, method: rq ? rq[1] : null, path: rq ? rq[2] : null,
      status, reason: rs ? (rs[2] || '') : '', headers, body, complete,
    });
    off = Math.max(end, off + 1);
  }
  return out;
}

function parseSse(text) {
  const events = [];
  const blocks = text.replace(/\r\n/g, '\n').split('\n\n');
  for (const b of blocks) {
    if (!b.trim()) continue;
    let ev = 'message'; const data = [];
    let id = null;
    for (const line of b.split('\n')) {
      if (line.startsWith(':')) continue;
      const c = line.indexOf(':');
      const field = c < 0 ? line : line.slice(0, c);
      const val = c < 0 ? '' : line.slice(c + 1).replace(/^ /, '');
      if (field === 'event') ev = val; else if (field === 'data') data.push(val); else if (field === 'id') id = val;
    }
    events.push({ event: ev, data: data.join('\n'), id });
  }
  return events;
}

/** Turn an HTTP body into JSON-RPC message candidates: [{json?, parseError?, raw, event?}] */
function bodyToMessages(headers, body, isResponse) {
  const ct = String(headers['content-type'] || '').toLowerCase();
  const text = body.toString('utf8');
  if (!text.trim()) return [];
  if (ct.includes('text/event-stream') || (isResponse && /^(event|data|id|retry|:)/.test(text))) {
    const out = [];
    for (const e of parseSse(text)) {
      if (e.event === 'endpoint') { out.push({ legacyEndpoint: e.data, raw: e.data }); continue; }
      if (!e.data.trim()) continue;
      try { out.push({ json: JSON.parse(e.data), raw: e.data, sse: true }); } catch (err) {
        out.push({ parseError: true, raw: e.data, sse: true });
      }
    }
    return out;
  }
  try {
    const j = JSON.parse(text);
    return Array.isArray(j) ? j.map((x) => ({ json: x, raw: null, batch: true })) : [{ json: j, raw: text }];
  } catch (e) {
    return [{ parseError: true, raw: text }];
  }
}

// ----------------------------------------------------------- pcap → exchanges
function assembleDirs(packets) {
  const dirs = new Map();
  for (const p of packets) {
    if (!p || p.transport !== 'tcp' || !p.payload || !p.payload.length) continue;
    const key = p.src + ':' + p.sport + '>' + p.dst + ':' + p.dport;
    let d = dirs.get(key);
    if (!d) { d = { src: p.src, dst: p.dst, sport: p.sport, dport: p.dport, segs: [] }; dirs.set(key, d); }
    d.segs.push(p);
  }
  const out = [];
  for (const d of dirs.values()) {
    const seen = new Set();
    const haveSeq = d.segs.every((s) => s.tcp && Number.isFinite(s.tcp.seq));
    let segs = d.segs;
    if (haveSeq) {
      segs = segs.filter((s) => (seen.has(s.tcp.seq) ? false : (seen.add(s.tcp.seq), true)));
      segs.sort((a, b) => (a.tcp.seq - b.tcp.seq) || (a.n - b.n));
    } else segs = segs.slice().sort((a, b) => a.n - b.n);
    if (!segs.length) continue;
    const first = segs[0].payload.toString('latin1', 0, 16);
    if (!/^(POST|GET|DELETE|PUT|PATCH|OPTIONS|HEAD) |^HTTP\/1\./.test(first)) continue;
    const ranges = [];
    let off = 0;
    for (const s of segs) { ranges.push({ start: off, ts: s.ts }); off += s.payload.length; }
    if (off > MAX_STREAM_BYTES) continue;
    out.push({ src: d.src, dst: d.dst, sport: d.sport, dport: d.dport, buf: Buffer.concat(segs.map((s) => s.payload)), ranges });
  }
  return out;
}

function tsAt(ranges, off) {
  let ts = ranges[0] ? ranges[0].ts : 0;
  for (const r of ranges) { if (r.start <= off) ts = r.ts; else break; }
  return ts;
}

function exchangesFromPackets(packets) {
  const warnings = [];
  const dirs = assembleDirs(packets);
  const msgsByDir = new Map();
  for (const d of dirs) {
    const msgs = parseHttpStream(d.buf).map((m) => Object.assign(m, { ts: tsAt(d.ranges, m.start) }));
    msgsByDir.set(d.src + ':' + d.sport + '>' + d.dst + ':' + d.dport, { d, msgs });
  }
  const exchanges = [];
  for (const [key, { d, msgs }] of msgsByDir) {
    const reqs = msgs.filter((m) => m.kind === 'req');
    if (!reqs.length) continue;
    const back = msgsByDir.get(d.dst + ':' + d.dport + '>' + d.src + ':' + d.sport);
    const ress = back ? back.msgs.filter((m) => m.kind === 'res' && m.status >= 200) : [];
    reqs.forEach((rq, i) => {
      const rs = ress[i] || null;
      exchanges.push({
        ts: rq.ts, endTs: rs ? rs.ts : null,
        flow: key,
        client: d.src, server: d.dst + ':' + d.dport,
        http: {
          method: rq.method, path: rq.path, status: rs ? rs.status : null, reason: rs ? rs.reason : '',
          reqHeaders: rq.headers, resHeaders: rs ? rs.headers : {}, sseOpen: !!(rs && !rs.complete),
        },
        reqBody: rq.body, resBody: rs ? rs.body : null,
      });
    });
  }
  exchanges.sort((a, b) => a.ts - b.ts);
  return { exchanges, warnings };
}

// ------------------------------------------------------------ text/HAR → model
function looksMcp(j) {
  return j && typeof j === 'object' && j.jsonrpc === '2.0';
}

const LOG_LINE = /(?:^|\s)(?:Message from (client|server)|(client|server)\s*(?:->|→|=>|to)\s*(client|server)|(?:\[(?:client|server)\]))\b\s*:?\s*(\{.*\})\s*$/i;

function sniffMcpText(buffer) {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(String(buffer == null ? '' : buffer), 'utf8');
  if (!buf.length) return false;
  const head = buf.toString('utf8', 0, Math.min(buf.length, 64 * 1024));
  if (/^\s*\{[\s\S]*"log"\s*:\s*\{[\s\S]*"entries"\s*:/.test(head) && /"jsonrpc"\s*:\s*"2\.0|\\"jsonrpc\\"\s*:\s*\\"2\.0/.test(buf.toString('utf8'))) return true;
  return /"jsonrpc"\s*:\s*"2\.0"/.test(head) && /"(method|result|error)"\s*:/.test(head);
}

function parseMcpText(text) {
  const warnings = [];
  const t = String(text || '');
  // HAR
  if (/^\s*\{/.test(t) && /"entries"\s*:/.test(t.slice(0, 200000))) {
    let har = null;
    try { har = JSON.parse(t); } catch (e) { warnings.push('HAR: not valid JSON (' + e.message + ')'); }
    if (har && har.log && Array.isArray(har.log.entries)) {
      const ex = [];
      for (const e of har.log.entries) {
        const rq = e.request || {}; const rs = e.response || {};
        const reqText = rq.postData && rq.postData.text;
        const resText = rs.content && rs.content.text;
        const hdr = (list) => { const o = {}; for (const h of list || []) o[String(h.name).toLowerCase()] = h.value; return o; };
        const reqH = hdr(rq.headers); const resH = hdr(rs.headers);
        if (!resH['content-type'] && rs.content && rs.content.mimeType) resH['content-type'] = rs.content.mimeType;
        const resBody = rs.content && rs.content.encoding === 'base64' && resText ? Buffer.from(resText, 'base64') : Buffer.from(resText || '', 'utf8');
        const isMcp = looksMcp(safeJson(reqText)) || (Array.isArray(safeJson(reqText)) && looksMcp((safeJson(reqText) || [])[0]))
          || /event-stream/.test(resH['content-type'] || '') && rq.method === 'GET' || !!reqH['mcp-session-id'] || !!resH['mcp-session-id']
          || /jsonrpc/.test(resText || '');
        if (!isMcp) continue;
        const ts = Date.parse(e.startedDateTime) / 1000;
        let urlPath = rq.url || '';
        let server = '';
        try { const u = new URL(rq.url); urlPath = u.pathname + (u.search || ''); server = u.host; } catch (err) { /* keep raw */ }
        ex.push({
          ts: Number.isFinite(ts) ? ts : ex.length, endTs: Number.isFinite(ts) && Number.isFinite(e.time) ? ts + e.time / 1000 : null,
          flow: 'har', client: reqH['x-forwarded-for'] || 'har-client', server,
          http: { method: rq.method, path: urlPath, status: rs.status || null, reason: rs.statusText || '',
            reqHeaders: reqH, resHeaders: resH, sseOpen: false },
          reqBody: Buffer.from(reqText || '', 'utf8'), resBody,
        });
      }
      if (!ex.length) warnings.push('HAR: no MCP (JSON-RPC) requests found among its entries');
      return { format: 'mcp-har', warnings, packets: [], mcpExchanges: ex };
    }
  }
  // JSON array transcript
  const arr = /^\s*\[/.test(t) ? safeJson(t) : null;
  const lineMsgs = [];
  if (Array.isArray(arr)) {
    arr.forEach((j) => { if (looksMcp(j)) lineMsgs.push({ json: j, dir: null }); });
  } else {
    let n = 0;
    for (const line of t.split(/\r?\n/)) {
      const lm = LOG_LINE.exec(line);
      let dir = null; let jtxt = null;
      if (lm) {
        if (lm[1]) dir = lm[1].toLowerCase() === 'client' ? 'c2s' : 's2c';
        else if (lm[2]) dir = lm[2].toLowerCase() === 'client' ? 'c2s' : 's2c';
        else dir = /\[client\]/i.test(line) ? 'c2s' : 's2c';
        jtxt = lm[4];
      } else {
        const i = line.indexOf('{"jsonrpc"');
        if (i >= 0) jtxt = line.slice(i);
        else if (/^\s*\{/.test(line) && line.includes('"jsonrpc"')) jtxt = line.trim();
      }
      if (!jtxt) continue;
      const j = safeJson(jtxt);
      if (!looksMcp(j)) continue;
      const tm = /(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:[.,](\d{1,6}))?(Z|[+-]\d{2}:?\d{2})?/.exec(line);
      const ts = tm ? Date.parse(tm[1] + 'T' + tm[2] + '.' + ((tm[3] || '0') + '000').slice(0, 3) + (tm[4] || 'Z')) / 1000 : null;
      lineMsgs.push({ json: j, dir, ts: Number.isFinite(ts) ? ts : null, n: n++ });
    }
  }
  if (!lineMsgs.length) return { format: 'mcp-log', warnings: ['no JSON-RPC 2.0 messages found'], packets: [], mcpExchanges: [] };
  // Fill unknown directions: requests/notifications from a client, results from a server, except
  // the well-known server-originated methods.
  const SERVER_METHODS = /^(notifications\/(message|progress|tools\/list_changed|resources\/(list_changed|updated)|prompts\/list_changed)|sampling\/|roots\/list|elicitation\/|ping$)/;
  const SERVER_REQ = /^(sampling\/|roots\/list|elicitation\/)/;
  const ex = [];
  let tsFallback = 0;
  for (const m of lineMsgs) {
    let dir = m.dir;
    const j = m.json;
    if (!dir) {
      if (typeof j.method === 'string') dir = SERVER_METHODS.test(j.method) && !/^ping$/.test(j.method) ? 's2c' : 'c2s';
      else dir = 's2c';
    }
    const ts = m.ts !== null && m.ts !== undefined ? m.ts : (tsFallback += 0.01);
    ex.push({ ts, endTs: null, flow: 'log', client: 'client', server: 'server', http: null,
      reqBody: null, resBody: null, logMsg: { json: j, dir }, _serverReq: typeof j.method === 'string' && SERVER_REQ.test(j.method) });
  }
  return { format: 'mcp-log', warnings, packets: [], mcpExchanges: ex };
}

function safeJson(s) { try { return JSON.parse(s); } catch (e) { return null; } }

// --------------------------------------------------------------- the analysis
function kindOf(j) {
  if (!j || typeof j !== 'object' || Array.isArray(j)) return 'invalid';
  const hasId = j.id !== undefined && j.id !== null;
  if (typeof j.method === 'string') return hasId ? 'request' : 'notification';
  if ('error' in j) return 'error';
  if ('result' in j && j.id !== undefined) return 'response';
  return 'invalid';
}

const clip = (s, n) => { s = String(s == null ? '' : s); return s.length > n ? s.slice(0, n) + '…' : s; };

function firstText(result) {
  const c = result && Array.isArray(result.content) ? result.content : [];
  const t = c.find((x) => x && typeof x.text === 'string');
  return t ? t.text : '';
}

/**
 * Turn exchanges into aux rows + findings.
 * @param {Array<object>} exchanges
 * @param {Array<object>} warnings
 */
function analyzeExchanges(exchanges, warnings) {
  const aux = [];
  const occurrences = new Map();     // issue code -> [{evidence, aux}]
  const note = (row, code, evidence, extra) => {
    const def = ISSUES[code];
    if (!def) return;
    const iss = { code, severity: def.severity, title: def.title, evidence: clip(evidence, 400), why: def.why,
      fixes: def.fixes, cites: def.cites };
    if (extra && extra.severity) iss.severity = extra.severity;
    if (row) row.detail.issues.push(iss);
    if (!occurrences.has(code)) occurrences.set(code, []);
    occurrences.get(code).push({ evidence: iss.evidence, severity: iss.severity });
  };

  const sessions = new Map();        // 'sid:<id>' | 'cl:<client>' -> state (several keys may alias one state)
  const freshState = () => ({
    pending: new Map(), initDone: false, initSent: false, initializedNotified: false, sawAny: false,
    protocolVersion: null, requestedVersion: null, sessionId: null, caps: null, serverInfo: null,
    clientInfo: null, midSession: false, tools: 0, firstTs: null, batchFlagged: false,
  });
  const allStates = new Set();
  const stateFor = (sid, client, startsSession) => {
    const ck = 'cl:' + (client || 'default');
    let st = (sid && sessions.get('sid:' + sid)) || sessions.get(ck);
    if (!st || (startsSession && st.initDone)) { st = freshState(); allStates.add(st); }
    sessions.set(ck, st);
    if (sid) sessions.set('sid:' + sid, st);
    return st;
  };

  const list = exchanges.slice(0, MAX_EXCHANGES);
  if (exchanges.length > MAX_EXCHANGES) warnings.push('mcp: only the first ' + MAX_EXCHANGES + ' exchanges were analysed');
  let totalMsgs = 0; let toolCalls = 0; let errors = 0;
  let lastTs = 0;

  for (const ex of list) {
    const http = ex.http;
    const reqH = http ? http.reqHeaders || {} : {};
    const resH = http ? http.resHeaders || {} : {};
    const sid = reqH['mcp-session-id'] || resH['mcp-session-id'] || null;
    const startsSession = !!(ex.reqBody && /"method"\s*:\s*"initialize"/.test(ex.reqBody.toString('utf8')))
      || !!(ex.logMsg && ex.logMsg.dir === 'c2s' && ex.logMsg.json.method === 'initialize');
    const st = stateFor(sid, ex.client, startsSession);
    if (st.firstTs === null) st.firstTs = ex.ts;
    if (Number.isFinite(ex.ts)) lastTs = Math.max(lastTs, ex.endTs || ex.ts);

    const row = {
      id: null, protocol: 'mcp', ts: ex.ts, src: ex.client || 'client', sport: 0, dst: ex.server || 'server', dport: 0,
      transport: http ? 'http' : 'jsonrpc', summary: '', raw: null, legIds: [], callIds: [],
      detail: { kind: 'exchange', http: null, rpc: [], issues: [], sessionId: sid ? redactHeaders({ 'mcp-session-id': sid })['mcp-session-id'] : null,
        latencyMs: ex.endTs && ex.ts ? Math.round((ex.endTs - ex.ts) * 1000) : null },
    };

    // ---- messages carried by this exchange
    const reqMsgs = ex.logMsg ? [{ json: ex.logMsg.json, raw: null, dir: ex.logMsg.dir }]
      : (ex.reqBody && ex.reqBody.length ? bodyToMessages(reqH, ex.reqBody, false).map((m) => Object.assign(m, { dir: 'c2s' })) : []);
    const resMsgs = ex.logMsg ? [] : (ex.resBody && ex.resBody.length ? bodyToMessages(resH, ex.resBody, true).map((m) => Object.assign(m, { dir: 's2c' })) : []);
    const httpFailed = !!(http && http.status && http.status >= 300);
    const all = reqMsgs.concat(httpFailed ? resMsgs.filter((m) => m.json && looksMcp(m.json)) : resMsgs);

    if (http) {
      const rH = redactHeaders(reqH); const sH = redactHeaders(resH);
      row.detail.http = { method: http.method, path: http.path, status: http.status, reason: http.reason,
        contentType: resH['content-type'] || null, requestHeaders: rH, responseHeaders: sH, sse: /event-stream/.test(resH['content-type'] || '') };
      row.dport = parseInt(String(ex.server || '').split(':').pop(), 10) || 0;
    }

    let batchSeen = false;
    for (const m of all) {
      totalMsgs++;
      if (m.legacyEndpoint !== undefined) {
        note(row, 'legacy-sse', 'endpoint event: ' + m.legacyEndpoint);
        row.detail.rpc.push({ dir: m.dir, kind: 'endpoint', summary: 'endpoint ' + clip(m.legacyEndpoint, 120) });
        continue;
      }
      if (m.parseError) {
        note(row, 'non-json-body', (m.dir === 'c2s' ? 'request' : 'response') + ' body: ' + clip(m.raw, 160));
        row.detail.rpc.push({ dir: m.dir, kind: 'invalid', summary: 'not JSON: ' + clip(m.raw, 80) });
        continue;
      }
      if (m.batch) batchSeen = true;
      const j = redactValue(m.json, 0);
      const k = kindOf(m.json);
      const entry = { dir: m.dir, kind: k, method: j && j.method || null, id: j && j.id !== undefined ? j.id : null, summary: '' };

      if (!looksMcp(m.json) && k !== 'invalid') note(row, 'bad-jsonrpc', 'jsonrpc field is ' + JSON.stringify(m.json.jsonrpc));
      if (k === 'invalid' || (m.json && 'result' in m.json && 'error' in m.json)) {
        note(row, 'bad-jsonrpc', clip(JSON.stringify(j), 200));
      }

      // direction guard: the capture's own direction wins, else the body's side
      if (k === 'request' || k === 'notification') {
        const fromClient = m.dir === 'c2s' && !ex._serverReq;
        entry.summary = j.method + (k === 'request' ? '' : ' (notification)');
        if (j.method === 'tools/call') {
          toolCalls++; st.tools++;
          entry.summary = 'tools/call ' + clip(j.params && j.params.name, 60);
        }
        if (fromClient || (ex.http && m.dir === 'c2s')) {
          if (j.method === 'initialize') {
            st.initSent = true;
            st.requestedVersion = j.params && j.params.protocolVersion || null;
            st.clientInfo = j.params && j.params.clientInfo || null;
          } else if (j.method === 'notifications/initialized') {
            st.initializedNotified = true;
          } else if (j.method === 'notifications/cancelled') {
            note(row, 'cancelled', 'request ' + JSON.stringify(j.params && j.params.requestId) + (j.params && j.params.reason ? ' — ' + j.params.reason : ''));
          } else if (j.method !== 'ping') {
            if (!st.initSent && !st.sawAny) st.midSession = true;
            if (st.initSent && !st.initDone && k === 'request') note(row, 'no-initialize', j.method + ' sent before initialize returned');
            if (st.initDone && !st.initializedNotified && !st.warnedInit && k === 'request') {
              st.warnedInit = true;
              note(row, 'no-initialized-notification', 'first post-handshake request was ' + j.method);
            }
            const need = /^tools\//.test(j.method) ? 'tools' : /^resources\//.test(j.method) ? 'resources'
              : /^prompts\//.test(j.method) ? 'prompts' : null;
            if (need && st.caps && !(need in st.caps) && !st['warned_' + need]) {
              st['warned_' + need] = true;
              note(row, 'capability-missing', j.method + ' called but initialize result advertised: ' + (Object.keys(st.caps).join(', ') || 'no capabilities'));
            }
          }
          if (k === 'request') {
            const pk = JSON.stringify(j.id);
            if (st.pending.has(pk)) note(row, 'duplicate-id', 'id ' + pk + ' (' + j.method + ')');
            st.pending.set(pk, { ts: ex.ts, method: j.method, name: j.params && j.params.name, row, entry });
          }
          st.sawAny = true;
          // header hygiene, HTTP only
          if (http && j.method !== 'initialize') {
            if (st.sessionId && !reqH['mcp-session-id'] && !st.warnedSid) {
              st.warnedSid = true; note(row, 'missing-session-id', j.method + ' sent without Mcp-Session-Id (server issued ' + redactHeaders({ 'mcp-session-id': st.sessionId })['mcp-session-id'] + ')');
            }
            if (st.protocolVersion >= '2025-06-18' && !reqH['mcp-protocol-version'] && !st.warnedPv) {
              st.warnedPv = true; note(row, 'missing-protocol-version-header', j.method + ' sent without MCP-Protocol-Version');
            }
          }
        }
      } else if (k === 'response' || k === 'error') {
        const pk = JSON.stringify(m.json.id);
        const pend = st.pending.get(pk);
        const lat = pend && ex.ts ? Math.round(((ex.endTs || ex.ts) - pend.ts) * 1000) : row.detail.latencyMs;
        entry.summary = (pend ? pend.method + (pend.name ? ' ' + clip(pend.name, 40) : '') + ' → ' : 'response → ') + (k === 'error' ? 'error ' + (m.json.error && m.json.error.code) : 'result');
        if (pend) {
          st.pending.delete(pk);
          pend.entry.answered = true; pend.row.detail.answeredBy = k;
          pend.row.detail.latencyMs = Number.isFinite(lat) ? lat : pend.row.detail.latencyMs;
          if (Number.isFinite(lat) && lat >= SLOW_MS) {
            note(pend.row, 'slow-response', pend.method + (pend.name ? ' ' + pend.name : '') + ' took ' + lat + ' ms', { severity: lat >= VERY_SLOW_MS ? 'warn' : 'notice' });
          }
          if (pend.method === 'initialize' && k === 'response') {
            st.initDone = true;
            const res = m.json.result || {};
            st.protocolVersion = res.protocolVersion || null;
            st.caps = res.capabilities && typeof res.capabilities === 'object' ? res.capabilities : {};
            st.serverInfo = res.serverInfo || null;
            const issued = resH['mcp-session-id'];
            if (issued) st.sessionId = issued;
            if (st.protocolVersion && st.requestedVersion && st.protocolVersion !== st.requestedVersion) {
              note(row, 'version-mismatch', 'client asked ' + st.requestedVersion + ', server answered ' + st.protocolVersion);
            }
            if (st.protocolVersion && !KNOWN_VERSIONS.includes(st.protocolVersion) && !/^\d{4}-\d{2}-\d{2}$/.test(st.protocolVersion)) {
              note(row, 'unknown-version', 'protocolVersion ' + JSON.stringify(st.protocolVersion));
            }
          }
        } else {
          if (!st.midSession && !(ex.logMsg && !pend)) note(row, 'orphan-response', 'id ' + pk);
          else if (ex.http || st.initSent) note(row, 'orphan-response', 'id ' + pk);
        }
        if (k === 'error') {
          errors++;
          const code = m.json.error && m.json.error.code;
          const msg = m.json.error && m.json.error.message;
          note(row, RPC_ERROR_CODES[String(code)] || 'rpc-error', 'code ' + code + (msg ? ': ' + msg : '') + (pend ? ' (answering ' + pend.method + ')' : ''));
          entry.error = { code, message: clip(msg, 200) };
        } else if (m.json.result && m.json.result.isError === true) {
          errors++;
          note(row, 'tool-error', (pend && pend.name ? pend.name + ': ' : '') + clip(firstText(m.json.result), 200));
        }
      }
      entry.raw = clip(JSON.stringify(j), MAX_RAW);
      row.detail.rpc.push(entry);
    }
    if (batchSeen && !st.batchFlagged && st.protocolVersion && st.protocolVersion >= '2025-06-18') {
      st.batchFlagged = true; note(row, 'batch-unsupported', 'array body on negotiated ' + st.protocolVersion);
    }

    // ---- HTTP-level checks
    if (http) {
      const s = http.status;
      const m = http.method;
      const wa = resH['www-authenticate'];
      if (s === 401) note(row, 'http-401', m + ' ' + http.path + ' → 401' + (wa ? ' · WWW-Authenticate: ' + clip(wa, 160) : ' · no WWW-Authenticate challenge'));
      else if (s === 403) note(row, 'http-403', m + ' ' + http.path + ' → 403' + (ex.resBody && ex.resBody.length ? ' · ' + clip(ex.resBody.toString('utf8'), 120) : ''));
      else if (s === 404) note(row, reqH['mcp-session-id'] ? 'http-404-session' : 'http-404', m + ' ' + http.path + ' → 404');
      else if (s === 405 && m === 'POST') note(row, 'http-405-post', 'POST ' + http.path + ' → 405 · Allow: ' + (resH.allow || 'n/a'));
      else if (s === 406) note(row, 'http-406', 'Accept sent: ' + (reqH.accept || '(none)'));
      else if (s === 415) note(row, 'http-415', 'Content-Type sent: ' + (reqH['content-type'] || '(none)'));
      else if (s === 400) note(row, 'http-400', m + ' ' + http.path + ' → 400' + (ex.resBody && ex.resBody.length ? ' · ' + clip(ex.resBody.toString('utf8'), 160) : ''));
      else if (s === 429) note(row, 'http-429', 'Retry-After: ' + (resH['retry-after'] || 'not given'));
      else if (s >= 500) note(row, 'http-5xx', m + ' ' + http.path + ' → ' + s + ' ' + http.reason);
      else if ([301, 302, 303, 307, 308].includes(s) && m === 'POST') note(row, 'http-redirect', 'POST ' + http.path + ' → ' + s + ' Location: ' + (resH.location || '?'));
      if (m === 'POST' && s && s >= 200 && s < 300 && s !== 202 && ex.resBody && ex.resBody.length) {
        const ct = String(resH['content-type'] || '').toLowerCase();
        if (ct && !/json|event-stream/.test(ct)) note(row, 'non-mcp-response', 'Content-Type ' + ct + ' · ' + clip(ex.resBody.toString('utf8'), 100));
      }
      if (/^(POST)$/.test(m) && s && s >= 200 && s < 300 && !/json|event-stream/.test(String(resH['content-type'] || '')) && ex.resBody && ex.resBody.length === 0 && s === 200 && reqMsgs.some((r) => r.json && kindOf(r.json) === 'request')) {
        note(row, 'non-mcp-response', '200 with empty body to a request that needs a JSON-RPC response');
      }
    }

    if (httpFailed && http.method === 'POST') {
      for (const [pk, pend] of st.pending) if (pend.row === row) st.pending.delete(pk);
    }

    // ---- summary
    const first = row.detail.rpc[0];
    const status = http ? (http.status ? ' → ' + http.status : ' → (no response)') : '';
    const what = first ? first.summary + (row.detail.rpc.length > 1 ? ' (+' + (row.detail.rpc.length - 1) + ')' : '') : (http ? (http.method === 'GET' ? 'GET stream' : 'no JSON-RPC body') : '');
    row.summary = (http ? http.method + ' ' + clip(http.path, 60) + '  ' : '') + what + status
      + (row.detail.latencyMs !== null && row.detail.latencyMs !== undefined ? ' (' + row.detail.latencyMs + ' ms)' : '');
    if (row.detail.issues.length) row.summary += '  ⚠ ' + row.detail.issues.map((i) => i.code).join(', ');
    row.raw = first && first.raw ? first.raw : null;
    aux.push(row);
  }

  // ---- end of trace: anything still pending never got an answer
  for (const st of allStates) {
    for (const [pk, pend] of st.pending) {
      if (pend.method === 'ping') continue;
      note(pend.row, 'no-response', pend.method + (pend.name ? ' ' + pend.name : '') + ' (id ' + pk + ') — no response in this capture, ' + Math.max(0, Math.round((lastTs - pend.ts) * 1000)) + ' ms after it was sent');
    }
  }
  // refresh summaries of rows that gained issues at the end
  for (const row of aux) {
    if (row.detail.issues.length && !/⚠/.test(row.summary)) row.summary += '  ⚠ ' + row.detail.issues.map((i) => i.code).join(', ');
  }

  // ---- findings: one per issue code, evidence listed
  const findings = [];
  const sevRank = { crit: 0, warn: 1, notice: 2, info: 3 };
  for (const [code, occ] of occurrences) {
    const def = ISSUES[code];
    const sev = occ.reduce((a, o) => (sevRank[o.severity] < sevRank[a] ? o.severity : a), occ[0].severity);
    const lead = def.fixes[0];
    findings.push({
      id: null, severity: sev, category: 'mcp', title: def.title + (occ.length > 1 ? ' (×' + occ.length + ')' : ''),
      detail: occ.slice(0, 3).map((o) => o.evidence).join(' | ') + ' — ' + def.why
        + (lead ? ' Fix: ' + lead.summary + (lead.steps[0] ? ' ' + lead.steps[0] : '') : ''),
      msgIds: [], legIds: [], callIds: [],
    });
  }
  findings.sort((a, b) => sevRank[a.severity] - sevRank[b.severity]);

  // ---- an activity summary, so a clean MCP trace still says what it saw
  if (list.length) {
    const infoSession = Array.from(allStates).find((s) => s.serverInfo || s.protocolVersion) || {};
    findings.push({
      id: null, severity: 'info', category: 'mcp',
      title: 'MCP traffic observed' + (infoSession.serverInfo && infoSession.serverInfo.name ? ' (' + infoSession.serverInfo.name + ')' : ''),
      detail: totalMsgs + ' JSON-RPC message' + (totalMsgs === 1 ? '' : 's') + ' in ' + list.length + ' HTTP/log exchange' + (list.length === 1 ? '' : 's')
        + (infoSession.protocolVersion ? ', protocol ' + infoSession.protocolVersion : '')
        + (infoSession.clientInfo && infoSession.clientInfo.name ? ', client ' + infoSession.clientInfo.name : '')
        + ', ' + toolCalls + ' tool call' + (toolCalls === 1 ? '' : 's') + ', ' + errors + ' error' + (errors === 1 ? '' : 's') + '.'
        + (Array.from(allStates).some((s) => s.midSession) ? ' The capture starts mid-session, so handshake checks were skipped.' : ''),
      msgIds: [], legIds: [], callIds: [],
    });
  }
  return { aux, findings };
}

/**
 * Entry point used by analyze.js.
 * @param {Array<object>} packets Packet[] (pcap / text-log)
 * @param {object} ctx may carry mcpExchanges (HAR / transcript input) and warnings
 */
function extractMcp(packets, ctx) {
  const warnings = (ctx && ctx.warnings) || [];
  try {
    let exchanges = (ctx && ctx.mcpExchanges) || null;
    if (!exchanges) {
      const r = exchangesFromPackets(packets || []);
      // Only treat a pcap as MCP if a body actually carries JSON-RPC (HTTP alone is not MCP).
      exchanges = r.exchanges.filter((e) => {
        const rq = e.reqBody && e.reqBody.length ? e.reqBody.toString('utf8') : '';
        const rs = e.resBody && e.resBody.length ? e.resBody.toString('utf8') : '';
        return /"jsonrpc"\s*:\s*"2\.0"/.test(rq) || /"jsonrpc"\s*:\s*"2\.0"/.test(rs)
          || !!(e.http.reqHeaders['mcp-session-id'] || e.http.resHeaders['mcp-session-id'])
          || /^event: endpoint/m.test(rs);
      });
    }
    if (!exchanges.length) return { aux: [], findings: [] };
    return analyzeExchanges(exchanges, warnings);
  } catch (e) {
    warnings.push('mcp failed: ' + (e && e.message ? e.message : e));
    return { aux: [], findings: [] };
  }
}

module.exports = { extractMcp, sniffMcpText, parseMcpText, ISSUES, _parseHttpStream: parseHttpStream, _parseSse: parseSse };
