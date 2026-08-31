'use strict';
// mcp.js — a minimal Model Context Protocol server: hiccup's capture tools,
// exposed to the customer's OWN AI assistant (Claude Code, Claude Desktop,
// Cursor — anything that speaks MCP).
//
// WHY THIS EXISTS
//
// The built-in chat is capped by the shared local model. Over MCP, the
// customer's frontier model does the reasoning and hiccup supplies what it is
// actually authoritative for: deterministic parsing, findings, and cited
// advice about their captures. Every MCP-driven analysis burns the CUSTOMER'S
// tokens, not this box's GPU.
//
// WHAT THIS IS, PROTOCOL-WISE
//
// JSON-RPC 2.0 over MCP's "streamable HTTP" transport, tools capability only.
// A tools-only server never initiates messages, so every POST gets a single
// application/json response and GET has nothing to stream — both explicitly
// allowed by the spec. Stateless on purpose: no Mcp-Session-Id is issued, and
// clients then simply operate without one. Methods:
//
//   initialize                  -> capabilities + serverInfo
//   notifications/initialized   -> accepted silently (as is any notification)
//   tools/list                  -> the tool catalogue
//   tools/call                  -> run one tool
//   ping                        -> {}
//
// Everything else is a clean JSON-RPC error, never a crash. Tool EXECUTION
// failures are result.isError (the model reads them and adapts); only an
// unknown tool or malformed request is a protocol-level error.
//
// The tool set is lib/agent.js's registry — the same ten read-only accessors
// the internal chat agent uses — with one adaptation: agent tools are built
// around ONE already-loaded analysis, while an MCP client works account-wide.
// So list_captures is added, every per-capture tool gains a required
// capture_id, and ownership is enforced by construction: the deps injected by
// server.js are closed over the authenticated account uid, so a capture id
// belonging to anyone else simply does not resolve.
//
// Zero dependencies. Nothing here does I/O; server.js injects it all.

const agent = require('./agent');

// Newest first. initialize echoes the client's version when we support it,
// otherwise offers our newest and lets the client decide.
const SUPPORTED_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];

const JSONRPC = '2.0';
const E_PARSE = -32700;
const E_INVALID_REQUEST = -32600;
const E_METHOD_NOT_FOUND = -32601;
const E_INVALID_PARAMS = -32602;
const E_INTERNAL = -32603;

/** A JSON-RPC error response. */
function rpcError(id, code, message) {
  return { jsonrpc: JSONRPC, id: id === undefined ? null : id, error: { code, message } };
}

function rpcResult(id, result) {
  return { jsonrpc: JSONRPC, id, result };
}

/**
 * Build the MCP tool catalogue for one authenticated account.
 *
 * @param {object} deps everything is scoped to the caller's account by the
 *   injector — none of these take a user id:
 * @param {Function} deps.listCaptures () -> [{id, filename, uploadedAt, stats, findingCounts}]
 * @param {Function} deps.loadAnalysis (captureId) -> AnalysisJSON | null
 * @param {Function} [deps.kbSearch]   (query, k) -> hits
 * @returns {Array<{def: object, run: Function}>}
 */
function buildCaptureTools(deps) {
  const tools = [];

  tools.push({
    def: {
      name: 'list_captures',
      description: 'Every capture in this hiccup account: id, filename, upload time, ' +
        'message/call counts and finding severities. Start here — every other tool ' +
        'needs a capture_id from this list.',
      inputSchema: { type: 'object', properties: {}, required: [] },
    },
    run: () => {
      const list = deps.listCaptures() || [];
      return {
        count: list.length,
        captures: list.map((c) => ({
          capture_id: c.id, filename: c.filename, uploadedAt: c.uploadedAt,
          stats: c.stats, findingCounts: c.findingCounts,
        })),
      };
    },
  });

  // The agent registry needs an analysis to close over; build it against an
  // empty one just to enumerate the catalogue. Definitions do not depend on
  // the data, only run() does — and run() below rebuilds against the real
  // analysis for the capture the client named.
  const catalogue = agent._buildTools({}, deps.kbSearch || null);
  for (const t of catalogue) {
    const fn = t.def.function;
    const schema = JSON.parse(JSON.stringify(fn.parameters || { type: 'object', properties: {} }));
    schema.properties = schema.properties || {};
    schema.properties.capture_id = {
      type: 'string',
      description: 'which capture to read — an id from list_captures',
    };
    schema.required = ['capture_id'].concat(schema.required || []);
    const name = fn.name;
    tools.push({
      def: { name, description: fn.description, inputSchema: schema },
      run: (args) => {
        const a = args || {};
        const captureId = String(a.capture_id || '');
        if (!captureId) return { error: 'capture_id is required — call list_captures first' };
        const analysis = deps.loadAnalysis(captureId);
        if (!analysis) {
          return { error: 'no capture with id ' + captureId + ' in this account — call list_captures' };
        }
        const registry = agent._buildTools(analysis, deps.kbSearch || null);
        const impl = registry.find((x) => x.def.function.name === name);
        if (!impl) return { error: 'tool not available for this capture' };
        const rest = Object.assign({}, a);
        delete rest.capture_id;
        return impl.run(rest);
      },
    });
  }

  return tools;
}

/**
 * Create a handler for one authenticated MCP connection-equivalent.
 *
 * @param {object} opts
 * @param {Array<{def:object, run:Function}>} opts.tools from buildCaptureTools
 * @param {string} opts.serverVersion hiccup's version string
 * @returns {{handle: Function}} handle(parsedBody) -> response object,
 *   or null when nothing should be sent (notifications)
 */
function createMcpHandler(opts) {
  const tools = opts.tools || [];
  const byName = new Map(tools.map((t) => [t.def.name, t]));

  async function handle(msg) {
    // Batches were removed from the protocol in 2025-06-18; a tools-only
    // server loses nothing by refusing them uniformly.
    if (Array.isArray(msg)) {
      return rpcError(null, E_INVALID_REQUEST, 'batch requests are not supported');
    }
    if (!msg || typeof msg !== 'object' || msg.jsonrpc !== JSONRPC) {
      return rpcError(msg && msg.id, E_INVALID_REQUEST, 'not a JSON-RPC 2.0 message');
    }

    const { id, method, params } = msg;

    // Notifications (no id): acknowledge by saying nothing, whatever they are.
    if (id === undefined || id === null) return null;

    if (typeof method !== 'string') {
      return rpcError(id, E_INVALID_REQUEST, 'method must be a string');
    }

    if (method === 'initialize') {
      const asked = params && typeof params.protocolVersion === 'string'
        ? params.protocolVersion : null;
      const version = SUPPORTED_VERSIONS.includes(asked) ? asked : SUPPORTED_VERSIONS[0];
      return rpcResult(id, {
        protocolVersion: version,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'hiccup', title: 'hiccup — SIP trace analyser', version: opts.serverVersion || '0.0.0' },
        instructions:
          'Read-only tools over the SIP/H.323 captures in this hiccup account. ' +
          'Call list_captures first; every other tool takes a capture_id from it. ' +
          'Findings, advice and citations are computed deterministically by hiccup — ' +
          'treat them as ground truth about the capture, and never invent protocol ' +
          'citations beyond what get_advice returns.',
      });
    }

    if (method === 'ping') return rpcResult(id, {});

    if (method === 'tools/list') {
      return rpcResult(id, { tools: tools.map((t) => t.def) });
    }

    if (method === 'tools/call') {
      const name = params && typeof params.name === 'string' ? params.name : '';
      const tool = byName.get(name);
      if (!tool) return rpcError(id, E_INVALID_PARAMS, 'unknown tool: ' + name);
      const args = (params && typeof params.arguments === 'object' && params.arguments) || {};
      let out;
      try {
        out = await tool.run(args);
      } catch (e) {
        // An exception inside a tool is an execution failure the model should
        // see and route around, not a protocol error.
        out = { error: 'tool failed: ' + ((e && e.message) || 'unknown error') };
      }
      const isError = !!(out && out.error);
      let text;
      try { text = JSON.stringify(out); }
      catch { text = JSON.stringify({ error: 'unserialisable tool result' }); }
      return rpcResult(id, { content: [{ type: 'text', text }], isError });
    }

    return rpcError(id, E_METHOD_NOT_FOUND, 'method not found: ' + method);
  }

  return { handle };
}

module.exports = {
  buildCaptureTools,
  createMcpHandler,
  SUPPORTED_VERSIONS,
  // exported for tests
  _codes: { E_PARSE, E_INVALID_REQUEST, E_METHOD_NOT_FOUND, E_INVALID_PARAMS, E_INTERNAL },
};
