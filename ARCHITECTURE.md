# hiccup — v1 architecture & module contracts

Read DESIGN_1.md first for the product brief. This file is the build contract: exact
module boundaries, data shapes, and API routes. If you are building one module, treat
every shape here as frozen — other modules are being built against it concurrently.

Scope additions on top of DESIGN_1: text-file ingest (SBC log exports and bare SIP
text), H.323 (Q.931/H.225 basic decode) and SIP↔H.323 IWF correlation, a chatbot that
can be interrogated about the capture and SIP/H.323 concepts, and a Wireshark-style
per-call list + flow view.

## Ground rules

- Node.js, **zero runtime dependencies** (plain `http`, `crypto`, `fs`). Same shape as RFPlex.
- Windows host; use `path.join`, never hardcode `/`.
- Port **8400** (env `PORT` overrides). Bind 127.0.0.1 by default; `HOST` env overrides
  (the Cloudflare tunnel fronts it later, same as RFPlex).
- All persistent state under `data/` (gitignored): `users.json`, `sessions.json`,
  `config.json`, `captures/<userId>/<captureId>/{original.bin,meta.json,analysis.json}`.
- Free during beta. Accounts required for everything except the landing page and /api/status.
- CommonJS (`require`/`module.exports`) throughout, matching RFPlex.
- Style: plain, readable, no classes unless natural; JSDoc on exported functions.

## ID spaces (no collisions, opaque to consumers)

SIP messages `s1…`, H.323 messages `h1…`, SIP legs `d1…`, H.323 legs `g1…`,
calls `c1…`, retrans collapses `r1…`, findings `f1…`.

## Module map and ownership

| File | Exports (exact) | Builds |
|---|---|---|
| `lib/pcap.js` | `parsePcap(buffer)` | pcap/pcapng/L2-L4 decode |
| `lib/textlog.js` | `parseTextLog(text)`, `sniffText(buffer)` | SBC log / SIP text ingest → Packet[] |
| `lib/sip.js` | `extractSipMessages(packets)`, `parseSipMessage(text)`, `parseSdp(text)`, `getHeader(msg,name)`, `getHeaders(msg,name)`, `groupSipLegs(messages)` | SIP + SDP parsing, leg (dialog) grouping |
| `lib/h323.js` | `extractH323Messages(packets)`, `groupH323Legs(messages)` | TPKT/Q.931 (H.225) decode + H.323 leg grouping |
| `lib/retrans.js` | `analyzeRetransmissions(messages, legs)` | collapse + classify + storm detection (SIP only) |
| `lib/correlate.js` | `correlateLegs(legs, messages)` | multi-leg pairing (SIP↔SIP, SIP↔H.323) + confidence |
| `lib/diff.js` | `diffLegs(ingressLeg, egressLeg, messages)` | the delta engine (SIP↔SIP pairs) |
| `lib/analyze.js` | `analyzeCapture(buffer, opts)` | orchestration + redaction + findings merge (built by integrator — do NOT build) |
| `lib/llm.js` | `initLlm(config)`, `getLlmStatus()`, `askLlm({system,messages})` | shared-Ollama client (RFPlex-deferential) |
| `lib/auth.js` | see §Auth | accounts, sessions, Google sign-in |
| `lib/store.js` | `loadJson(file,fallback)`, `saveJson(file,obj)`, capture-dir helpers | persistence |
| `server.js` | — | http server, routes, static |
| `public/*` | — | UI |
| `test/make-fixtures.js` | CLI + writes `test/fixtures/expected.json` | synthetic pcap/text corpus |
| `test/selftest.js` | CLI | end-to-end assertions |

## Ingest pipeline

`analyzeCapture` sniffs the buffer: pcap magic (`a1b2c3d4`/`d4c3b2a1`/`a1b23c4d`/
`4d3cb2a1`) or pcapng (`0a0d0d0a`) → `parsePcap`; otherwise, if it decodes as text
(UTF-8/latin-1, printable-heavy) → `parseTextLog`; otherwise 422. File extension is
never trusted.

Both producers emit the same **Packet** shape, then:
`extractSipMessages(packets)` + `extractH323Messages(packets)` →
`groupSipLegs` + `groupH323Legs` → `correlateLegs` → per-pair `diffLegs` →
`analyzeRetransmissions` → merged AnalysisJSON.

## Data shapes (frozen)

### Packet — output of `parsePcap` and `parseTextLog`

```js
// parsePcap(buffer)   -> { format: 'pcap'|'pcapng', linkType, warnings: [string], packets: [Packet] }
// parseTextLog(text)  -> { format: 'acme-log'|'sngrep'|'raw-sip', warnings: [string], packets: [Packet] }
Packet = {
  n: 1,                     // 1-based capture order
  ts: 1723891234.123456,    // epoch seconds, float
  src: '10.0.0.1',          // IP as string (v4 dotted / v6 colon)
  dst: '192.168.1.1',
  sport: 5060, dport: 5060,
  transport: 'udp'|'tcp',
  payload: Buffer,          // L7 bytes. UDP: full datagram payload (after IPv4 fragment reassembly).
                            // TCP: this segment's payload bytes (sip.js/h323.js do stream framing).
  tcp: { seq: 0, syn: false, fin: false } | undefined,
  fragmented: false,        // true if rebuilt from IPv4 fragments
  wireBytes: 1520,          // on-wire frame size (sum across fragments when reassembled)
}
```

pcap scope: classic pcap (both endians, us + ns variants) and pcapng (SHB/IDB/EPB,
per-interface tsresol). Link types: Ethernet(1) incl. 802.1Q VLAN (single + QinQ),
Linux SLL(113), SLL2(276), Raw IP(101/228/229), Null/Loopback(0). IPv4 + IPv6 (skip
extension headers). IPv4 fragment reassembly keyed on (src,dst,id,proto), best-effort,
drop incomplete with a warning. Non-UDP/TCP packets are skipped. Never throw on
malformed frames — skip with a warning string in `warnings`.

textlog scope (SBC engineers paste/export these; multiple legs of one call interleaved
in one file is the NORMAL case):
- **Acme/Oracle sipmsg.log style**: blocks like
  `Aug 17 10:03:31.123 On [1:0]203.0.113.5:5060 received from 198.51.100.10:5060` (or
  `sent to`), followed by a raw SIP message, blocks separated by a `----…` dashed line.
  Missing year → current year. `received from X` → src=X, dst=the `On` address;
  `sent to X` → reversed. Port defaults 5060. Transport `udp` unless the line says TCP/TLS.
- **sngrep/sipgrep style**: `U 2026/08/17 10:03:31.123456 198.51.100.10:5060 -> 203.0.113.5:5060`
  then the message ('T' → tcp).
- **raw-sip**: bare concatenated SIP messages (blank-line separated, or detected by
  request/status lines). No addresses → synthesize src/dst from top Via + request
  direction where possible, else `unknown-a`/`unknown-b`; ts = file order, 10ms apart.
`sniffText(buffer)` → true when the buffer is plausibly one of these (used by analyze.js).

### SipMessage — output of `extractSipMessages(packets)`

`extractSipMessages` finds SIP in UDP payloads (any port — sniff for request-line/status-line)
and in TCP flows (per-direction ordered byte stream, framed by Content-Length; simple
duplicate-seq drop; skip flows on port 1720). Ids `s1…` in timestamp order.

```js
SipMessage = {
  id: 's12', protocol: 'sip',
  pktRefs: [12],             // Packet.n values this message came from
  ts, src, dst, sport, dport, transport,   // copied from first packet
  raw: '...',                // full text, CRLF preserved
  size: 812,                 // byte length of the SIP payload
  isRequest: true,
  method: 'INVITE',          // for responses too (taken from CSeq)
  requestUri: 'sip:...' | null,
  status: null | 180, reason: null | 'Ringing',
  callId, fromUri, fromTag, toUri, toTag,
  cseq: { num: 1, method: 'INVITE' },
  branch: 'z9hG4bK...' | null,      // top Via branch
  vias: ['SIP/2.0/UDP ...'],        // full Via values, in order
  routes: [], recordRoutes: [], contact: 'sip:...' | null,
  headers: [{ name: 'From', value: '...' }],  // ALL headers, original order + case
  bodyType: 'application/sdp' | null,
  sdp: Sdp | null,
  retransOf: null,           // filled in later by retrans.js: original id
}
Sdp = {
  origin: { user, sessId: '1234', sessVersion: '2', addr: '10.0.0.1' },
  connection: '10.0.0.1' | null,
  media: [{
    type: 'audio', port: 4000, proto: 'RTP/AVP',
    payloads: [{ pt: 0, codec: 'PCMU', rate: 8000, fmtp: null }],  // codec/rate resolved
                                    // from rtpmap, with static-PT fallback table (0=PCMU,8=PCMA,18=G729…)
    ptime: 20 | null, direction: 'sendrecv'|'sendonly'|'recvonly'|'inactive'|null,
    attrs: ['...'],                 // raw a= lines for this m-block
  }],
  sessionAttrs: ['...'],            // session-level a= lines
  raw: '...',
}
```

`getHeader(msg, name)` → first value or null, case-insensitive, compact-form aware
(f=From, t=To, i=Call-ID, m=Contact, v=Via, c=Content-Type, l=Content-Length, k=Supported).
`getHeaders(msg, name)` → array.

### H323Message — output of `extractH323Messages(packets)`

Scan TCP flows on port 1720 + any TCP flow whose bytes start with TPKT (03 00 len).
TPKT-frame, then decode the Q.931 layer only: protocol discriminator 08, call reference
(value + flag), message type. Decode plain TLV IEs: Bearer Capability (0x04), Cause
(0x08 — value + text via a cause table), Called Party Number (0x70), Calling Party
Number (0x6C), Display (0x28), User-User (0x7E — do NOT ASN.1-decode; extract a best-
effort 16-byte H.323 callIdentifier GUID by scanning the blob for plausible GUID
patterns, else null; note fastStart presence heuristically). Ids `h1…`.

```js
H323Message = {
  id: 'h3', protocol: 'h323',
  pktRefs: [...], ts, src, dst, sport, dport, transport: 'tcp',
  q931Type: 'SETUP'|'CALL PROCEEDING'|'ALERTING'|'CONNECT'|'RELEASE COMPLETE'
            |'FACILITY'|'PROGRESS'|'STATUS'|'NOTIFY'|'INFORMATION'|'unknown(0xNN)',
  callRef: 1234, callRefFlag: 0|1,       // flag 1 = sent FROM the side that allocated the ref
  calling: '+33612345678' | null, called: '...' | null,
  causeCode: 16 | null, causeText: 'Normal call clearing' | null,
  guid: '1a2b…' (hex) | null,            // H.323 callIdentifier if found
  hasFastStart: false,
  raw: '03 00 00 2a 08 02 …',            // hex dump, space-separated, for the inspector
  summary: 'SETUP callRef=1234 called=+33612345678',
  size: 42,
}
```

### Leg — outputs of `groupSipLegs` / `groupH323Legs`

A **leg** is one signalling relationship seen at the capture point: a SIP dialog
(`d1…`) or an H.323 call segment (`g1…`). Both share the common fields; SIP legs add
the SIP-specific ones. Every message lands in exactly one leg (create 'other' legs for
strays).

```js
Leg = {
  id: 'd1' | 'g1', protocol: 'sip'|'h323',
  kind: 'call'|'register'|'options'|'subscribe'|'notify'|'message'|'other',  // h323: always 'call'
  from: 'sip:alice@a.com' | '+33612345678', to: '...',
  fromUser: 'alice'|null, toUser: 'bob'|null,   // user parts / E.164 digits
  src, dst, sport, dport, transport,            // of the initial request/SETUP
  startTs, endTs,
  state: 'in-progress'|'answered'|'completed'|'failed'|'canceled'|'no-answer',
  failCode: null | 486,        // SIP status or Q.931 cause code
  answered: false, answerTs: null,
  msgIds: ['s3','s4',...],     // every message incl. retransmissions, capture order
  // SIP only:
  callId, fromTag, toTag: null|'...', invite: 's3'|null,
  // H.323 only:
  callRef, guid: null|'…',
}
```

SIP grouping: Call-ID + from-tag (+ to-tag once established); forked to-tags stay one
leg in v1. State rules (calls): 2xx to INVITE → answered; then BYE → completed. CANCEL
then 487 → canceled. Final non-2xx → failed with failCode. INVITE never answered, no
final → no-answer. Anything still open → in-progress.
H.323 grouping: (tcp flow, callRef). CONNECT → answered; RELEASE COMPLETE after
CONNECT → completed; RELEASE COMPLETE with cause before CONNECT → failed (cause 16
after ALERTING only → canceled/no-answer judgment call: use cause table);
never RELEASEd → in-progress.

### Retransmissions — `analyzeRetransmissions(messages, legs)`

SIP legs only. Detection: same leg, same top Via branch + CSeq + (method or status
code) + byte-identical `raw` → retransmission of the first. Also mark `retransOf` on
the message objects (mutate in place).

```js
-> {
  collapses: [{
    id: 'r1', legId, kind: 'request'|'response',
    method: 'INVITE', status: null|200,
    count: 7, firstTs, lastTs,
    outcome: 'no-response'|'late-response'|'eventually-acked'|'abandoned'|'resolved',
    label: 'INVITE ×7, no response, abandoned at 32s (Timer B)',   // human row text
    classification: {
      code: 'never-arrived'|'slow-far-end'|'dns-blocking'|'udp-fragmentation'
            |'ack-not-landing'|'box-wide-storm'|'unknown',
      cause: 'one-line likely cause, per DESIGN_1 table',
      confidence: 0.0-1.0,
      detail: 'evidence sentence(s)',
    },
    msgIds: [...],
  }],
  aggregate: {
    buckets: [{ ts, retransCount, legsAffected }],   // 1s buckets, only non-zero
    stormWindows: [{ startTs, endTs, legsAffected, retransCount, verdict: 'box-wide' }],
      // storm = >=3 legs retransmitting inside the same 2s window
  },
  findings: [Finding],
}
```

Classification evidence (from DESIGN_1 §3): no 100 Trying at all → never-arrived;
retransmits then late response → slow-far-end (or dns-blocking when the delay repeats
across legs to the same destination); message >1300 bytes UDP + no response →
udp-fragmentation; 200 OK retransmitting → ack-not-landing; concurrent multi-leg
cluster → box-wide-storm (attach to stormWindows too). Timer references: T1=500ms,
Timer B/F = 64*T1 = 32s.

### Correlation — `correlateLegs(legs, messages)`

Only `kind === 'call'` legs. A call through a B2BUA appears as 2+ SIP legs; through an
IWF as a SIP leg + an H.323 leg. Legs chain: if A↔B and B↔C pair, they merge into one
call with `legIds` ordered by startTs.

```js
-> {
  calls: [{
    id: 'c1',
    type: 'sip-sip'|'sip-h323'|'single',
    legIds: ['d1','d2',...],           // startTs order; [0] is ingress
    state: 'paired'|'ambiguous'|'unpaired',
    confidence: 0.0-1.0,               // min over pairings; 0 for unpaired singles
    pairings: [{ a: 'd1', b: 'd2', confidence, signals: [
      { name: 'pcv-icid'|'x-header'|'sdp-origin'|'temporal'|'user-parts'|'via-rewrite'|'number-match',
        matched: true, weight: 0.4, detail: 'icid-value 1234abcd on both legs' }] }],
    candidates: [{ legId, confidence }],   // ambiguous: the competing pairings
  }],
  findings: [Finding],
}
```

SIP↔SIP signal weights (start here, tune against fixtures): pcv-icid / vendor X-header
match 0.45; sdp-origin sessId+version match 0.30; temporal (egress INVITE 0–250ms after
ingress) 0.15 scaled by proximity; surviving To/From user parts 0.10; consistent
Via/Contact rewrite 0.05. SIP↔H.323 signals: number-match (called/calling digits vs
To/From users, longest-suffix >=6 digits) 0.45; temporal (SETUP vs INVITE within 500ms)
0.30; guid appearing in a SIP header (rare) 0.25. Pair greedily
highest-confidence-first; a pairing needs >=0.5. If the best two candidates for one
ingress are within 0.15 → `ambiguous`, do NOT pick (DESIGN_1 rule). Direction: earlier
start = ingress. A leg joins at most one call. Unpaired call legs each get a `single`
call entry (confidence 0) — single-leg captures are normal.

### Diff — `diffLegs(ingressLeg, egressLeg, messages)`

SIP↔SIP pairs only (analyze.js calls it per adjacent SIP pair in each call's chain).
Compare initial INVITEs (+ their SDP answers where a category needs them).

```js
-> {
  categories: [{
    key: 'headers'|'sdp'|'dtmf'|'reliability'|'session-timers'|'early-media'
         |'transport'|'topology'|'t38',
    title: 'Headers',
    items: [{
      tag: 'dtmf-pt-mismatch',        // stable machine tag, from the list below
      severity: 'info'|'notice'|'warn'|'crit',
      label: 'telephone-event payload type differs',
      ingress: null | 'value on ingress leg',
      egress: null | 'value on egress leg',
      detail: 'one-line explanation an SBC-curious engineer learns from',
    }],
  }],
  findings: [Finding],   // only warn/crit items, promoted
}
```

Stable tags (selftest asserts on these — emit exactly these strings):
`header-added` `header-stripped` `header-rewritten` `codec-narrowed` `codec-transcoding`
`ptime-mismatch` `dtmf-pt-mismatch` `dtmf-missing-one-leg` `100rel-asymmetry`
`session-timer-conflict` `session-timer-changed` `early-media-183` `early-media-pem`
`udp-frag-risk` `private-ip-leak` `t38-asymmetry` `from-rewritten` `to-rewritten`.

Category content per DESIGN_1 §2: headers added/stripped/rewritten (ignore hop-by-hop
noise: Via, Max-Forwards, Content-Length, Record-Route — report Route/RR only under
topology); sdp: codec list in vs out, transcoding forced (answer codec differs per
leg), ptime mismatch; dtmf: telephone-event PT differs per leg (101 vs 96) or absent
one side; reliability: 100rel/PRACK offered vs required vs absent per leg;
session-timers: Session-Expires / Min-SE / refresher per leg, conflicts; early-media:
183+SDP vs 180, media direction pre-answer, P-Early-Media; transport: either leg's
INVITE >1300 bytes on UDP → fragmentation risk; topology: RFC1918 IPs surviving into
egress headers/SDP where ingress had them (topology-hiding leak); t38: T.38 re-INVITE
present on one leg, outcome differs.

### Finding (shared shape, used by retrans/correlate/diff/analyze)

```js
Finding = {
  id: 'f1',                 // assigned by analyze.js at merge time — modules may leave null
  severity: 'info'|'notice'|'warn'|'crit',
  category: 'retrans'|'correlation'|'diff'|'transport'|'auth'|'parse'|'h323',
  title: 'short title', detail: 'explanation with evidence',
  msgIds: [], legIds: [], callIds: [],
}
```

### AnalysisJSON — `analyzeCapture(buffer, {redactNumbers=false})`

```js
{
  version: 1, generatedAt: iso8601,
  stats: { format,             // 'pcap'|'pcapng'|'acme-log'|'sngrep'|'raw-sip'
           packets, sipMessages, h323Messages, legs, calls, pairedCalls,
           timespan: { start, end }, transports: { udp: n, tcp: n }, warnings: [] },
  messages: [SipMessage|H323Message],   // ONE array, ts order; raw INCLUDED but redacted; Buffers never serialized
  legs: [Leg],
  calls: [ CorrelatedCall & { diffs: [{a, b, diff: DiffResult}] } ],  // per adjacent SIP-SIP pair
  retrans: RetransResult,
  findings: [Finding],      // merged from all modules, ids assigned, crit→info order
}
```

Redaction (always, before storing): Digest `response`, `cnonce`, and any
`Authorization`/`Proxy-Authorization` credential params → `REDACTED` in `raw` and in
`headers[]`. With `redactNumbers`: digits in user parts of URIs and display names get
middle-masked (`+3366…12`). analyze.js owns this pass.

`analyzeCapture` throws Errors with a `userMessage` property on unusable input (not a
pcap/not SIP text, zero signalling messages) — server maps to 422 with that message.

## LLM module — `lib/llm.js` (the RFPlex-deference contract)

hiccup shares GAVINPC's Ollama (`http://127.0.0.1:11434`) with RFPlex (port 3001),
which is the **priority tenant**. Facts about RFPlex (verified against its source):
its models are `qwen3.5:9b` (smart) / `qwen3.5:2b` (fast) / `qwen3-embedding:0.6b`;
it pins generate+embed models with `keep_alive:-1`; its chat calls pass no keep_alive;
`GET http://127.0.0.1:3001/api/status/llm` (no auth, cached 30s server-side) returns
`{ generated_at, engine_reachable, accepting_jobs, paused_reason, state:
'operational'|'degraded'|'unknown', models: [{role:'smart'|'fast'|'embedding',
purpose, name, state: 'loaded'|'ready'|'unavailable'|'unknown'}], self_hosted, note }`.

Policy, in order:

1. **Model choice**: ask RFPlex — prefer its `smart` model when Ollama has it
   installed, else its `fast`. Cache the status 30s, 1.5s timeout. If RFPlex is
   unreachable: use whatever `GET /api/ps` says is currently loaded (skip embedding
   models). Else first of `config.preferredModels` present in `/api/tags`. **Never
   pull a model. Never trigger a load of a different model while `/api/ps` shows any
   generation model loaded** (that would evict RFPlex's) — in that situation use the
   loaded one.
2. **keep_alive**: if `/api/ps` shows the chosen model pinned (expires_at absent,
   "never", or year >2100), pass `keep_alive: -1` to preserve RFPlex's pin. Otherwise
   pass `keep_alive: '5m'` — hiccup never extends GPU residency beyond that itself.
3. **Yield to RFPlex**: before dispatching each queued request, if RFPlex status says
   `engine_reachable && accepting_jobs === false` (RFPlex's GPU gate is closed — it is
   mid-job or paused), wait 3s and re-check, up to 10 times, then proceed anyway.
   Use a 5s status cache for this check.
4. **Concurrency 1**, FIFO queue, max depth 8 (reject with err.code='busy' beyond),
   request timeout 120s, one retry on 5xx/ECONNREFUSED after 2s.
   `options.num_ctx` 8192, temperature 0.2, `num_predict` 700; `think:false` when
   the model name starts with `qwen3` (RFPlex does the same — 2-5× verbosity otherwise).
5. Use `/api/chat` (messages array), non-streaming (`stream:false`).
   `askLlm({system, messages})` → `Promise<{text, model}>`; messages =
   [{role:'user'|'assistant', content}].
6. LLM is garnish: every product feature works with Ollama down. `getLlmStatus()` →
   `{ available, model, source: 'rfplex'|'loaded'|'preferred'|null, rfplexModel,
   rfplexReachable, queue }`.
7. Prompts must never contain Digest credentials (already redacted in analysis).

## Auth — `lib/auth.js`

```js
initAuth(dataDir, config)          // loads users/sessions, starts session sweep timer
createUser({email, password, name, googleSub}) -> user   // throws {userMessage} on dup email
verifyPassword(email, password) -> user | null           // scrypt, timing-safe compare
createSession(userId) -> { token, expiresAt }            // 32B random hex, 30d sliding
getSession(token) -> { user } | null
destroySession(token)
verifyGoogleIdToken(credential) -> Promise<{ sub, email, name, picture }>
  // Google Identity Services ID token: verify RS256 against https://www.googleapis.com/oauth2/v3/certs
  // (cache JWKS 12h), check iss (accounts.google.com | https://accounts.google.com),
  // aud === config.googleClientId, exp. Reject with {userMessage} on any failure.
countUsers() -> n
```

Users in `data/users.json`: `{id, email (lowercased unique), name, passwordHash:
'scrypt:N:r:p:saltHex:hashHex' | null, googleSub: null|'...', role: 'user'|'admin',
createdAt, lastLoginAt}`. First user created becomes `role:'admin'`. Google sign-in
with unknown email creates the account (that's signup). Password min 8 chars. Sessions
persisted to `data/sessions.json` (write-behind ok), cookie `hiccup_session`, HttpOnly,
SameSite=Lax, Path=/, Secure auto-added when `config.baseUrl` starts with https.

`data/config.json` (created with defaults on first boot):
```js
{ "port": 8400, "host": "127.0.0.1", "baseUrl": "http://127.0.0.1:8400",
  "googleClientId": null,
  "ollamaUrl": "http://127.0.0.1:11434",
  "rfplexStatusUrl": "http://127.0.0.1:3001/api/status/llm",
  "preferredModels": ["qwen3.5:9b", "qwen3.5:2b", "qwen3:8b", "llama3.1:8b"],
  "maxUploadMb": 50 }
```

## HTTP API — `server.js`

Plain `http.createServer`. JSON bodies (1MB cap) except capture upload. Every handler
in a try/catch → 500 JSON `{error}`. Session from cookie; helper `requireAuth(req,res)`
returns user or writes 401 JSON and returns null. Routes:

```
POST /api/auth/signup   {email,password,name?}       -> {user}  + Set-Cookie
POST /api/auth/login    {email,password}             -> {user}  + Set-Cookie
POST /api/auth/google   {credential}                 -> {user}  + Set-Cookie (creates acct if new)
POST /api/auth/logout                                -> {ok} + cookie clear
GET  /api/me                                         -> {user} | 401
GET  /api/config/public                              -> {appName:'hiccup', googleClientId, freeBeta:true}
GET  /api/status                                     -> {app:'hiccup', version, uptime, llm:getLlmStatus()}   // no auth
POST /api/captures      raw body, X-Filename hdr     -> {id, meta}   (auth; cap maxUploadMb; 422 {error} on unusable; analysis runs synchronously)
GET  /api/captures                                   -> [{id, filename, uploadedAt, sizeBytes, stats, findingCounts:{crit,warn,notice,info}}]
GET  /api/captures/:id/analysis                      -> AnalysisJSON (owner only, 404 otherwise)
DELETE /api/captures/:id                             -> {ok}
POST /api/chat          {captureId, messages:[{role,content}], scope?} -> {reply, model} | 503 {error,llm} when unavailable
                        // scope: {type:'capture'|'call'|'leg'|'message'|'finding', id}
                        // server builds the system prompt: hiccup persona ("expert SIP/SBC/H.323
                        // engineer explaining a capture"), capture stats + findings summary,
                        // plus the scoped object serialized compactly (message raw capped 4KB,
                        // call: legs summary + diff items). History capped to last 12 messages.
GET  /                  public/index.html (landing + auth; its JS checks /api/me and offers "Open app")
GET  /app               public/app.html (its JS redirects to / when /api/me 401s)
static: public/* by extension whitelist (.html .css .js .svg .png .ico), no traversal.
```

Capture ids: 12 hex chars. Original upload stored as `original.bin` alongside
`meta.json` + `analysis.json`. meta.json = `{id, filename, uploadedAt, sizeBytes,
stats, findingCounts}`.

## UI — `public/`

Files: `index.html` (landing + auth), `app.html` (the tool), `hiccup.css` (shared design
system), `app.css` (app-view styles; app.html links both), `app.js`, `ladder.js` (pure
rendering helpers loaded by app.html), `brand/` (favicons, mascot and wordmark artwork).

`brand/` holds the raster brand set: `favicon.ico` (16/32/48/64) plus `icon-32/180/192/512`,
`apple-touch-icon.png` and `icon-maskable-512.png` (opaque, for tiles that get masked),
`mascot-hero*.png` and `mascot-wand-480.png`, `lockup-900.png`, `social-card.png`
(1200x630 og:image) and the two wordmark inkings. The wordmark ships as
`wordmark-on-light.png` / `wordmark-on-dark.png` and is placed with the
`.brand-wordmark` class rather than an `<img>`, because only CSS can see the theme
state on `<html>` — see the block at the foot of `hiccup.css`. The superseded
`logo.svg` / `monster.svg` are kept but no longer referenced.

`hiccup.css` owns the design system and MUST define: CSS vars `--bg --panel --panel2
--text --muted --accent --crit --warn --notice --info --mono`, and classes `.btn
.btn-primary .input .card .chip .sev-crit .sev-warn .sev-notice .sev-info .mono`.
`app.css` may only add view-specific styles on top of those primitives.

Brand: name always lowercase **hiccup**. Dark UI: bg `#0e1116`, panel `#161b22`, text
`#dce3ea`, accent amber `#f5a623`, severity colors crit `#f2545b` warn `#f5a623` notice
`#58a6ff` info `#8b949e`. Monospace (`ui-monospace, Consolas`) for anything SIP. System
sans for chrome. Logo: the word `hiccup` with the second `c` bumped a few px up — a
hiccup in the baseline (pure text/SVG, no image assets).

app.html — sidebar: capture list + drag-drop upload zone (fetch raw bytes, X-Filename
header; accept .pcap .pcapng .cap .txt .log or anything). Main area tabs:

- **Calls** (the default tab — Wireshark Telephony→VoIP-Calls style): table with
  columns Start, Stop, Initial Speaker (src), From, To, Protocol (SIP / H.323 /
  SIP↔SIP / SIP↔H.323), State, Confidence (bar, with an explicit AMBIGUOUS chip when
  applicable — never hide ambiguity), Msgs. Row click → **Flow**: a per-call ladder
  showing only that call's legs (all of them — the SBC's two legs side by side across
  3-4 host columns), plus the call's diff cards below (two-column ingress/egress
  values, severity chips, one card per category with items).
- **Ladder**: whole-capture SVG sequence diagram: column per host:port, arrows per
  message colored by class (request / 1xx / 2xx / 3-6xx / h323), retrans collapsed to
  one bold row with `×N` badge (toggle to expand), click → right-side inspector with
  full redacted raw (or hex for H.323) + parsed summary + an **"explain this"** button
  that opens the chat prefilled with scope {type:'message', id}.
- **Retrans**: collapse table (label, classification code + cause, confidence) + a
  storm strip: 1s buckets as bars, storm windows highlighted, with the box-wide verdict
  called out.
- **Findings**: severity-sorted list; clicking jumps to the relevant view; each row has
  an "explain" button (chat, scope finding).

**Chat** ("ask hiccup"): persistent right-side drawer, toggle button in the header.
Real conversation UI (history bubbles, textarea, Enter to send) hitting /api/chat with
the current capture + current scope (whatever is selected). Works as a general
interrogation surface: "what does Session-Expires do", "why is call 2 ambiguous",
"what stripped the PAI header". Show the model name + "shares its brain with RFPlex —
answers may queue behind RFPlex work" when status.llm.source==='rfplex'. When
status.llm.available is false, keep the drawer but show a "local model offline" note
instead of the input. Chat history is per-capture, client-side only (sessionStorage).

index.html: pitch ("see where the call went wrong"), three feature bullets (two-leg
diff + delta view, retransmission classifier, SIP↔H.323 correlation), email+password
signup/login forms, "Sign in with Google" (GIS script, only when /api/config/public
has a client id), beta note: free while in beta. On success → location = '/app'.

Support link (same as RFPlex): `<a href="https://buymeacoffee.com/mcfadyen"
target="_blank" rel="noopener">☕ Buy Me a Coffee</a>` — in the index.html footer and
in the app.html header bar (small, right side, next to the user menu). Plain text+emoji
link only, never the CDN image button.

No frameworks, no CDN fonts, no external requests except Google's GIS script (loaded
only when googleClientId configured).

## Fixtures — `test/make-fixtures.js`

Pure-JS pcap **writer** (classic pcap, Ethernet/IPv4/UDP + TCP; one pcapng variant; one
IPv4-fragmented variant) + realistic SIP/H.323 scenario builders + text-log emitters.
Writes to `test/fixtures/` and writes `test/fixtures/expected.json` that selftest
asserts against. Scenarios:

1. `basic-call.pcap` — clean A→SBC→B call, both legs. Correlation: P-Charging-Vector
   icid + temporal. Diff material: SBC strips `X-Internal-Cause`, adds
   P-Asserted-Identity, rewrites From user, codec list narrowed (PCMU,PCMA,G729 →
   PCMU), DTMF 101→96, ptime 20→30, ingress requires 100rel / egress doesn't offer it,
   Session-Expires 1800/refresher uac vs 900/uas, private IP leaked in egress `o=` line.
2. `timer-b.pcap` — INVITE ×7 (RFC3261 backoff spacing), zero responses → never-arrived.
3. `late-response.pcap` — INVITE ×3 then 100/180/200 at ~2.4s → slow-far-end.
4. `big-invite.pcap` — 1450-byte UDP INVITE, no response → udp-fragmentation. Plus
   `big-invite-frags.pcap`: same but actually IP-fragmented (reassembly test).
5. `ack-lost.pcap` — call answers, 200 OK ×6, no ACK → ack-not-landing.
6. `storm.pcap` — 8 concurrent legs all retransmitting in the same 2s → box-wide-storm.
7. `ambiguous.pcap` — two simultaneous ingress calls, same From/To users, no icid;
   egress pair must come out `ambiguous`, not silently paired.
8. `tcp-call.pcap` — basic call on TCP with one SIP message split across segments and
   two messages coalesced in one segment (framing test).
9. `pcapng-call.pcapng` — scenario 1 re-encoded as pcapng.
10. `register-auth.pcap` — REGISTER 401 Digest challenge + authorized REGISTER
    (redaction test: the Digest response value must NOT survive into analysis), Path +
    Service-Route in the 200.
11. `h323-call.pcap` — TCP 1720: TPKT/Q.931 SETUP (calling+called numbers),
    CALL PROCEEDING, ALERTING, CONNECT, RELEASE COMPLETE (cause 16).
12. `iwf-call.pcap` — H.323 leg (as 11) + SIP egress leg, same numbers, SETUP→INVITE
    within 200ms → one `sip-h323` call.
13. `sbc-log.txt` — Acme sipmsg.log-style text: BOTH legs of one call interleaved with
    `received from`/`sent to` framing and dashed separators (the SBC-export use case).
14. `raw-messages.txt` — bare concatenated SIP messages of a simple call.

SIP text must be RFC-plausible: Via branches z9hG4bK-prefixed, tags, CSeq discipline,
Content-Length correct (compute it), realistic SDP. Hosts: A=198.51.100.10, SBC
outside=203.0.113.5, SBC inside=10.20.0.5, B=10.20.0.30 (RFC5737/1918 so topology
findings trigger).

Wave-2 fixture additions (see §Wave 2 below): `rtp-loss.pcap`, `sipi-call.pcap`,
`dns-slow.pcap`, `diameter-rx.pcap`, `ice-stun.pcap`, `t38-fax.pcap`,
`callcentre.pcap`, `ims-volte.pcap`, `acme-hmr.cfg`, `audiocodes-hmr.ini`,
`ribbon-smm.txt`, `guide-sample.txt`.

`expected.json` shape (selftest consumes this generically):
```js
[{ name: 'timer-b', file: 'timer-b.pcap',
   expect: {
     format: 'pcap',
     sipMessages: 7,            // exact counts where deterministic
     h323Messages: 0,
     legs: 1, calls: 1,
     callStates: { paired: 0, ambiguous: 0, unpaired: 1 },   // optional, counts by state
     callTypes: { 'single': 1 },                              // optional
     retransCodes: ['never-arrived'],       // classification codes that MUST appear
     diffTags: ['dtmf-pt-mismatch', ...],   // diff item tags that MUST appear (optional)
     findingsInclude: [{severity:'crit', category:'retrans'}],  // optional
     absentStrings: ['THE-DIGEST-RESPONSE-VALUE'],  // must not appear anywhere in serialized analysis
   } }]
```

## Selftest — `test/selftest.js`

Node script, `npm run selftest`. Runs `make-fixtures.js` first (child_process), then
each fixture through `analyzeCapture`, asserting its `expected.json` entry generically
(only assert keys that are present). Also: auth unit pass (signup → login → session →
wrong password rejected → duplicate email rejected; verifyGoogleIdToken is NOT network-
tested — only that a garbage token rejects), store atomic-save pass, llm degradation
pass (init with ollamaUrl pointing at a dead 127.0.0.1 port: getLlmStatus().available
=== false and askLlm rejects cleanly). Uses a throwaway data dir under test/tmp-data/
(delete before/after). Output `PASS k/n` lines then a summary; non-zero exit on any
fail. No network beyond 127.0.0.1.

---

# Wave 2 — protocols, advice, search, workbench UI

Wave 1 (above) is built and loads clean. Wave 2 adds protocol breadth, an advisory
engine with citations, HMR analysis, config-guide ingestion, trace-wide search, and the
SIP-Workbench-style layout. **Everything in Wave 1 stays as specified** — Wave 2 only
adds new modules, new top-level keys in AnalysisJSON, and new routes.

## New AnalysisJSON top-level keys (additive)

```js
{
  ...wave1,
  media:  { streams: [MediaStream], rtcp: [RtcpReport] },
  aux:    [AuxMessage],        // DNS / Diameter / STUN / ICE / DTLS observations
  indicators: [Indicator],     // the "lamps"
  scenario: Scenario,
  advice: [Advice],            // articulated problems + cited fixes
}
```

SipMessage gains (optional, added by lib/isup.js when present):
`isup: { messageType:'IAM'|'ACM'|'ANM'|'REL'|'CPG'|'CON'|'SAM', calledParty, callingParty,
causeCode, causeText, natureOfConnection, params:[{name,value}], raw }` and
`bodyParts: [{ contentType, disposition, body }]` for multipart INVITEs.

### MediaStream — `lib/rtp.js`

```js
MediaStream = {
  id: 'rs1', kind: 'rtp'|'srtp'|'t38-udptl'|'unknown',
  src, sport, dst, dport, ssrc: 439041101 | null,
  payloadType: 0, codec: 'PCMU' | 'T.38' | 'unknown', clockRate: 8000,
  firstTs, lastTs, durationSec, packets: 1234, bytes: 210000,
  expected: 1250, lost: 16, lossPct: 1.28,        // RFC 3550 seq-based
  outOfOrder: 3, duplicates: 0,
  meanJitterMs: 4.2, maxJitterMs: 41.0,           // RFC 3550 interarrival jitter
  maxGapMs: 320, gaps: [{ ts, ms }],              // silence/black-hole gaps >100ms
  mos: 3.9, mosMethod: 'e-model-simplified',      // ITU-T G.107 simplified; label as ESTIMATE
  dtmfEvents: [{ ts, digit, durationMs }],        // RFC 4733 telephone-event
  legIds: [], callIds: [],                        // matched via SDP m=/c= of those legs
  oneWay: false,                                  // no reverse stream seen for a paired leg
  markerResets: 0, ssrcChanges: 0,
}
RtcpReport = { id:'rc1', ts, src, dst, type:'SR'|'RR'|'BYE'|'SDES'|'APP'|'XR',
  ssrc, blocks:[{ ssrc, fractionLostPct, cumulativeLost, jitter, lsr, dlsrMs, rttMs }],
  cname: null|'...', raw }
```

Detection: primary source is SDP (`m=` port + `c=` address per leg, plus the answer) —
match streams to legs. Secondary heuristic for captures without SDP: even UDP port,
RTP version 2, plausible PT, monotonic-ish seq. `t38-udptl`: SDP `m=image ... udptl t38`
or UDPTL structure. `srtp`: SDP `RTP/SAVP`/`SAVPF` or `a=crypto` — report stats from
headers only (never attempt decryption), set `kind:'srtp'` and note payload is encrypted.
Cap work: sample at most 200k media packets, note truncation in a warning.

### AuxMessage — `lib/dns.js`, `lib/diameter.js`, `lib/ice.js`

```js
AuxMessage = {
  id: 'x1', protocol: 'dns'|'diameter'|'stun'|'ice'|'dtls',
  ts, src, sport, dst, dport, transport,
  summary: 'NAPTR? example.com  ->  no answer (2.4s)',
  detail: {...},              // per-protocol, see below
  raw: '...' | null,          // hex or text
  legIds: [], callIds: [],    // best-effort association
}
```

- **DNS** (`lib/dns.js`): parse query/response (UDP 53 + TCP 53), types A/AAAA/SRV/
  NAPTR/CNAME/PTR/NS, rcode names, match responses to queries by (txid, 4-tuple),
  compute `detail.latencyMs`, flag `detail.timedOut:true` for unanswered queries and
  `detail.slow:true` over 1s. This is the evidence source that upgrades the
  retransmission classifier's `dns-blocking` verdict from inference to proof — export
  `dnsEvidence(auxList)` -> `{ byDest: { 'host': { slowQueries, timeouts, maxLatencyMs } } }`
  for advisor.js.
- **Diameter** (`lib/diameter.js`): Diameter header (version 1, length, flags, command
  code, app id, hop-by-hop, end-to-end) over TCP port 3868/3869; decode AVPs
  generically (code, flags, length, vendor id, value as int/UTF8/octets) with a name table
  for the Rx/Gx/Cx/Sh AVPs that matter (Session-Id 263, Result-Code 268,
  Experimental-Result-Code 298, Auth-Application-Id 258, Framed-IP-Address 8,
  AF-Charging-Identifier 505, Media-Component-Description 517, Origin-Host 264,
  Destination-Realm 283, Public-Identity 601, Server-Name 602, User-Name 1).
  Command names: AAR/AAA 265, RAR/RAA 258, STR/STA 275, ASR/ASA 274, CCR/CCA 272,
  UAR/UAA 300, MAR/MAA 303, SAR/SAA 306, LIR/LIA 307. **Rx-to-SIP correlation**: match
  `AF-Charging-Identifier` (or Session-Id substring) against the SIP
  `P-Charging-Vector` icid-value -> fill `legIds`/`callIds`. That is DESIGN_1's
  cross-protocol stretch goal; when it fires, emit an info finding naming both sides.
- **STUN/ICE/DTLS** (`lib/ice.js`): STUN (RFC 5389 magic cookie 0x2112A442) message
  class/method names, XOR-MAPPED-ADDRESS, USERNAME, ERROR-CODE, ICE-CONTROLLED/
  CONTROLLING, USE-CANDIDATE; group into `detail.checkList` per 5-tuple pair with
  `succeeded`/`failed`/`no-response`; DTLS record layer (content type 22 handshake)
  -> ClientHello/ServerHello/Certificate/Finished progression, `detail.stalledAfter`
  when a handshake never completes, plus `detail.srtpProfile` from use_srtp when
  visible. One-way-audio and WebRTC/Teams-side failures live here.

### Indicator — `lib/detect.js`

```js
Indicator = { key, label, state: 'on'|'off'|'partial'|'issue', detail, evidenceMsgIds: [], evidenceCallIds: [] }
```

Fixed key set, always all returned in this order (UI renders them as lamps, `off` shown
dim): `sip`, `h323`, `iwf`, `sip-i`, `ims`, `rtp`, `rtcp`, `srtp`, `dtls-srtp`, `t38`,
`dtmf-rfc4733`, `100rel`, `session-timers`, `update-method`, `precondition`, `dns`,
`diameter`, `stun-ice`, `tcp-transport`, `tls-transport`, `ipv6`, `registration`,
`topology-hiding`, `transcoding`, `early-media`, `refer-transfer`, `history-info`.
`state:'issue'` when detected AND something is provably wrong with it (e.g. `t38`
present but re-INVITE rejected; `precondition` requested but never confirmed).
Each indicator's `detail` is one plain sentence, written for someone who may not know
the feature — this is the teaching surface DESIGN_1 asks for.

IMS detection (per DESIGN_1 core feature 4): `Path`/`Service-Route` in REGISTER,
`P-Associated-URI`, third-party REGISTER, `sip:orig` in Route, `P-Charging-Vector`
icid, preconditions (`a=curr`/`a=des`/`a=conf`), `P-Early-Media`,
`P-Access-Network-Info`, `P-Visited-Network-ID`. Also fold in 5G markers when present
(`P-Access-Network-Info` containing `3GPP-NR` / `5G`, `Feature-Caps`, `sip.instance`
with a gr param).

### Scenario — `lib/detect.js`

```js
Scenario = {
  primary: 'call-centre'|'enterprise-trunk'|'residential-ims'|'volte-5g'|'carrier-interconnect'
           |'webrtc-ott'|'fax-service'|'lab-test'|'unknown',
  confidence: 0.0-1.0,
  signals: [{ name, detail, weight }],
  detail: 'two or three sentences: what this capture appears to be, and what that
            implies for how to read the rest of the analysis',
  alternatives: [{ primary, confidence }],
}
```

Signals (evidence-based, no LLM): call-centre -> high concurrent call volume, short
setups, predictive-dialer patterns, many calls to one DID, `Diversion`/`History-Info`
queue hops, REFER-heavy transfers. enterprise-trunk -> single trunk pair, a PBX
User-Agent (Avaya/Cisco/Mitel/3CX/Asterisk/FreePBX strings), E.164 DDI block, static
IPs, OPTIONS keepalives. residential-ims -> REGISTER with Path/Service-Route, one
subscriber, P-Access-Network-Info xDSL/fibre, single line. volte-5g -> IMS markers +
preconditions + `3GPP-E-UTRAN`/`3GPP-NR` access info + AMR/EVS codecs + Rx Diameter.
carrier-interconnect -> SIP-I/ISUP bodies, no REGISTER, big number ranges, transit
Via chains. webrtc-ott -> STUN/ICE + DTLS-SRTP + opus + `a=ice-ufrag`. fax-service ->
T.38/UDPTL or G.711 with `a=fax`. lab-test -> RFC5737/RFC1918-only addressing,
sipp/pjsua/sipsak User-Agents, synthetic number patterns.

### Advice — `lib/advisor.js`

The articulation layer the user asked for: *what is wrong, why, how to fix it, and the
citation*. **Deterministic — never LLM-generated.** The LLM may later paraphrase an
Advice object in chat, but the object itself, and above all its citations, come from a
hand-written knowledge base in this module.

```js
Advice = {
  id: 'a1',
  findingIds: ['f2'],                   // findings this explains (may be [])
  severity: 'crit'|'warn'|'notice'|'info',
  title: 'ACK never reaches the far end after topology hiding',
  whatsWrong: 'plain-language statement of the observed fault, quoting the evidence',
  whyItMatters: 'the user-visible symptom - "the call answers then drops at ~32s"',
  mechanism: 'the protocol-level explanation, teaching-oriented',
  fixes: [{
    target: 'oracle-acme'|'audiocodes'|'ribbon'|'cisco-cube'|'freeswitch'|'asterisk'
            |'endpoint'|'network'|'generic',
    summary: 'one line',
    steps: ['ordered, concrete steps'],
    config: 'vendor config snippet (draft, review before applying)' | null,
    caution: 'what this could break' | null,
    confidence: 'likely'|'possible'|'depends-on-topology',
  }],
  citations: [Citation],
  kbCitations: [],                      // filled via the injected retriever, see lib/kb.js
}
Citation = { source: 'RFC 3261', section: 'Section 13.2.2.4', title: 'The ACK Request',
             url: 'https://www.rfc-editor.org/rfc/rfc3261#section-13.2.2.4',
             note: 'why this reference applies' }
```

`buildAdvice(analysis, opts)` -> `{ advice: [Advice] }`. Rule coverage (minimum set —
one rule per condition, each with at least one **verified** citation):

| Condition | Anchor references |
|---|---|
| INVITE retransmit to Timer B, no 100 | RFC 3261 17.1.1.2 (Timer A/B), 18.1.1 |
| UDP request >1300 bytes, no response | RFC 3261 18.1.1 (MTU rule, switch to TCP) |
| 200 OK retransmitting, no ACK | RFC 3261 13.2.2.4, 12.1.1 (Contact/Record-Route) |
| Route/Record-Route mismatch after topology hiding | RFC 3261 12.1.1, RFC 5658 |
| 100rel / PRACK asymmetry | RFC 3262 sections 3 and 4 |
| Session timer conflict (Min-SE > Session-Expires) | RFC 4028 sections 3, 5, 6 (422 handling) |
| telephone-event PT mismatch across legs | RFC 4733 2.4.1, RFC 3264 6.1 |
| ptime / codec renegotiation | RFC 3264 6.1, RFC 4566 section 6 |
| Early media 183 vs 180 / no SDP | RFC 3960 section 3, RFC 5009 (P-Early-Media) |
| Private IP leak through topology hiding | RFC 1918 section 3, RFC 3261 8.1.1.8 (Contact) |
| T.38 re-INVITE rejected / asymmetric | ITU-T T.38, RFC 3407 |
| One-way audio (stream in one direction) | RFC 4566 section 6, RFC 3264 6.1 |
| RTP loss / jitter above threshold | RFC 3550 6.4.1, ITU-T G.107 |
| DNS SRV/NAPTR timeout on egress | RFC 3263 section 4, RFC 3261 18.1.1 |
| Missing Service-Route in REGISTER 200 | RFC 3608 6.1, 3GPP TS 24.229 |
| Preconditions requested, never confirmed | RFC 3312 sections 3 and 5, RFC 4032 |
| ICE checks all fail / DTLS stalls | RFC 8445 section 7, RFC 5764 section 4 |
| Digest auth loop (401 then 401) | RFC 3261 22.2, RFC 7616 |
| CANCEL race / 487 handling | RFC 3261 sections 9.1 and 9.2 |
| Diameter Rx AAR failure alongside INVITE | 3GPP TS 29.214, RFC 6733 section 7 |
| REFER transfer failure | RFC 3515 section 2, RFC 7647 |

Every citation must be one you are confident is correct — if unsure of a section
number, cite the RFC without a section rather than inventing one. Build `url` from the
rfc-editor anchor pattern (`https://www.rfc-editor.org/rfc/rfcNNNN#section-X.Y`), and
omit the anchor when you omit the section. Non-RFC standards (3GPP TS, ITU-T) get
`url: null` and a `source` string a reader can search for.

### HMR — `lib/hmr.js` (DESIGN_1 core feature 5, plus articulation)

```js
parseConfig(text) -> { vendor: 'oracle-acme'|'audiocodes'|'ribbon'|'unknown',
                       confidence, rules: [HmrRule], warnings: [] }
explainRule(rule) -> { intent, correctness: { ok, issues: [{severity, detail, citation}] },
                       improvements: [{ detail, rationale }] }
renderRule(rule, vendor) -> string        // reviewable draft config, never applied
matchAgainstAnalysis(rules, analysis) -> { matches: [{ ruleId, callIds, diffTags,
                       verdict: 'observed-as-configured'|'configured-not-observed'
                                |'observed-not-configured', detail }] }
HmrRule = {
  id: 'h1', name, vendor, raw,
  scope: { direction: 'in'|'out'|'both'|null, msgType: 'request'|'response'|'any', methods: [] },
  conditions: [{ element, comparison: 'equals'|'matches'|'exists'|'absent', value }],
  target: { header, element: 'uri.user'|'uri.host'|'param.tag'|'value'|null, index: null },
  operation: 'add'|'delete'|'modify'|'store'|'replace'|'none',
  value: null | { kind: 'literal'|'expression', text },
  bindings: [{ kind: 'session-agent'|'realm'|'sip-interface'|'ip-profile'|'ip-group'
                     |'signaling-group', name }],
}
```

The IR is the asset (DESIGN_1: "translation is then a rendering problem"). Parsers:
Acme/Oracle `sip-manipulation` -> `header-rule` -> `element-rule` blocks from a running
config; AudioCodes `.ini` MessageManipulations table rows; Ribbon SMM rule text.
`explainRule` is the feature the user asked for — plain-English intent ("rewrites the
From user to the trunk's main billing number on egress"), a correctness check (does the
condition ever match given the target? is a `store` referenced before it is set? is the
operation on a header the SBC will regenerate anyway? missing msg-type? a regex that
also matches the wrong direction?), and improvement suggestions (narrow the condition,
use `manipulate` instead of delete+add, precedence hazards). Cite RFCs when a rule
breaks protocol rules (e.g. rewriting a `Via` branch -> RFC 3261 8.1.1.7).
`matchAgainstAnalysis` closes the loop: which configured rules explain the diffs the
capture actually shows, and which observed manipulations no rule accounts for.

### Config-guide KB — `lib/kb.js`

Answer to "can it read vendor guides and determine the right config change": it can
ingest them, retrieve the relevant passages, and ground a **reviewable draft** in them —
it must never present the result as a verified change.

```js
initKb(dataDir)
addDoc({ userId, filename, buffer, vendor, product }) -> { id, chunks, pages, title }
listDocs(userId) -> [{ id, filename, title, vendor, product, chunks, addedAt, sizeBytes }]
deleteDoc(userId, id) -> boolean
searchKb(userId, query, k) -> [{ docId, docTitle, page, heading, text, score }]
```

Formats: `.txt .md .html .htm .ini .cfg .conf .cli .log` natively (HTML -> tag-stripped
text). PDF via a **lazy** `require('pdf-parse')` — if the module is absent, reject with
`userMessage: 'PDF support needs an optional dependency: npm install pdf-parse'`. Keep
`pdf-parse` in `optionalDependencies` only, so a core install stays dependency-free.
Retrieval is BM25-ish keyword scoring over ~1200-char chunks with heading capture —
**no embeddings** (an embedding model would compete with RFPlex for the GPU, which the
LLM contract forbids). Store under `data/kb/<userId>/<docId>/{meta.json,chunks.json}`.
advisor.js accepts an injected retriever: `buildAdvice(analysis, { retrieve })` where
`retrieve(queryString)` returns KB hits appended to `advice[].kbCitations` as
`{ docTitle, page, heading, excerpt }`.

## Search — client-side, spec'd here for the UI agents

No server module required. `app.js` builds an in-memory index over the loaded
AnalysisJSON and supports: bare substring (case-insensitive) across every message's raw
text, header values, URIs, user parts, Call-IDs, tags, branches, SDP, H.323 numbers, aux
summaries, finding titles and advice text; **digit-normalized phone search** (strip
`+ - ( ) space .`, match any 4+ digit substring against normalized user parts, so
`654321` finds `+33987654321`); and `field:value` filters — `call:`, `leg:`, `callid:`,
`from:`, `to:`, `method:`, `status:`, `ip:`, `port:`, `codec:`, `proto:` (sip/h323/rtp/
dns/diameter/stun), `sev:` (crit/warn/notice/info), `has:` (t38/ims/sipi/srtp/dtmf/
retrans/advice). Results group by **session** (call), each row showing the matched field
and a highlighted excerpt; selecting a result loads that call's ladder with the match
highlighted. Debounce 150ms; cap 500 hits with a "more" note.

## New routes

```
GET    /api/captures/:id/advice                   -> {advice:[Advice]}   (from stored analysis)
POST   /api/hmr/analyze   {text, captureId}       -> {vendor, confidence, rules:[{rule, explanation, rendered:{...}}], matches}
POST   /api/kb/docs       raw body, X-Filename    -> {doc}
GET    /api/kb/docs                               -> [doc]
DELETE /api/kb/docs/:id                           -> {ok}
POST   /api/kb/search     {q, k}                  -> {hits:[...]}
```

`/api/chat` gains the new material in its system prompt: indicators, scenario, advice
titles, media stream summaries, and (when the question looks config-shaped) the top KB
hits — with an explicit instruction that citations must come from the supplied Advice
objects and KB excerpts, and that it must not invent RFC section numbers.

## UI — the Workbench layout

Replace the Wave-1 tab layout in `app.html` with the five-pane arrangement from SIP
Workbench (the user's reference screenshot), keeping the existing topbar and chat
drawer. Two agents share these files — **the DOM id contract is frozen**:

```
#searchbar        text input #search-input + #search-clear + #search-count
#filter-pane      left-top: session/Call-ID tree (#filter-tree)
#selection-pane   left-bottom: numbered message list (#selection-list)
#ladder-pane      centre: #ladder-svg-host + #ladder-toolbar (collapse toggle, zoom, export)
#time-pane        centre-left gutter inside the ladder pane: #time-gutter
#info-pane        bottom-right: tabs #info-tabs (Contents|Packet Info|Media|Advice)
                  + panels #info-contents #info-packet #info-media #info-advice
#lamps            indicator strip: one .lamp[data-key] per Indicator
#scenario-chip    scenario summary chip (click -> info-pane Advice tab)
#rfplex-promo     sidebar promo card
```

- **#filter-pane**: tree grouped by call -> legs -> transactions (method + status), with
  a state dot per node and a `xN` retrans badge. Selecting a node scopes the ladder,
  selection and info panes. Sessions with a `crit` finding get a red edge.
- **#selection-pane**: the Workbench-style numbered table — `#`, Description
  (`INVITE`, `401 Unauthorized`, `RTP 200 pkts`), Delta (ms since the previous row, the
  column engineers actually read), with error rows tinted. Sortable by # or Delta.
- **#ladder-pane**: multicolour ladder for the selected session. Colours: request
  `--accent`, 1xx `--notice`, 2xx `#3fb950`, 3xx `#a371f7`, 4xx/5xx/6xx `--crit`,
  H.323 `#d2a8ff`, media `#39c5cf` dashed, aux (DNS/Diameter/STUN) `#8b949e` dotted.
  **Error highlighting**: any message carrying a warn/crit finding gets a thicker
  stroke, a severity dot, and a tooltip with the advice title; retrans collapse rows
  show `xN`. Hovering a row cross-highlights the same row in #selection-pane.
- **#time-pane**: absolute timestamp + delta gutter aligned to the ladder rows.
- **#info-pane**: *Contents* = full redacted raw (mono, wrapped, search term
  highlighted); *Packet Info* = parsed tree (headers, SDP fields, ISUP params, Q.931
  IEs); *Media* = the MediaStream/RtcpReport table for the selected session with
  loss/jitter/MOS and a small loss-over-time sparkline; *Advice* = the Advice cards for
  the selection — `whatsWrong` / `whyItMatters` / `mechanism`, then fix cards per vendor
  with copyable config drafts, then citation links (opening in a new tab), then KB
  citations when present. Every card gets an "explain in chat" button.
- **#lamps**: a lamp per Indicator, dim when `off`, accent when `on`, amber ring for
  `partial`, red ring for `issue`; tooltip/aria-label = `detail`; click filters the view
  to the evidence.
- **rfplex.ai promotion**: `#rfplex-promo` card in the sidebar — "Also from the same
  workshop: **RFPlex.ai** — AI that answers RFPs, RFIs and DDQs from your own document
  library. Self-hosted, EU-sovereign, free during beta." linking
  `https://rfplex.ai/?utm_source=hiccup&utm_medium=app&utm_campaign=crosslink`
  (`target="_blank" rel="noopener"`). The same card in the `index.html` footer, plus one
  line in the chat drawer: "hiccup and RFPlex.ai share the same local-LLM stack."
  Tasteful, never a modal, never an interstitial.
- Keep the Buy Me a Coffee link exactly as built.
- New page `public/hmr.html` + `public/hmr.js`: paste-or-upload SBC config ->
  vendor detection, per-rule cards (intent / correctness / improvements), a translate-to
  selector rendering the other two vendors' equivalents, and a "check against a capture"
  picker calling `matchAgainstAnalysis`.
- New page `public/kb.html` + `public/kb.js`: upload/list/delete config guides and a
  search box over them.

## Licensing / distribution (Wave 2 deliverables)

- `LICENSE` — BUSL-1.1 (Business Source License), Licensor "Gavin McFadyen", Licensed
  Work "hiccup", Additional Use Grant: internal, non-production evaluation and
  non-commercial use; Change Date: four years from first publication; Change License:
  Apache-2.0. Mirror the structure of `C:\Users\gavin\RFPlex.ai\LICENSE`.
- `LICENSE-COMMERCIAL.md` — commercial terms summary + contact, mirroring
  `C:\Users\gavin\RFPlex.ai\LICENSE-COMMERCIAL.md`.
- `NOTICE` — short copyright/trademark notice.
- `README.md` — add a Licence section stating plainly: source-available, **not** open
  source; production/commercial use needs a licence.
- `wireshark/hiccup.lua` + `wireshark/README.md` — a Wireshark **bridge** plugin: adds
  `Tools -> hiccup -> Analyse this capture in hiccup`, resolves the current capture
  filename, uploads it to `http://127.0.0.1:8400/api/captures` (shelling out to
  `curl`/PowerShell, since Lua has no HTTP), then opens the browser at the capture. Also
  `Tools -> hiccup -> Settings...` for host/port/session cookie. Document the limits
  honestly in its README: Wireshark plugins cannot embed hiccup's UI, and a Lua
  post-dissector cannot replicate the cross-leg analysis — the bridge is the useful
  integration.
- `docs/DECRYPTION.md` — the encrypted-traffic guidance (documentation only, no feature).

## Wave 2 module exports (exact — analyze.js calls these)

| File | Exports |
|---|---|
| `lib/rtp.js` | `analyzeMedia(packets, ctx)` -> `{ streams, rtcp, findings }` |
| `lib/isup.js` | `extractIsup(messages)` -> `{ findings }` (mutates SIP messages: adds `.isup`, `.bodyParts`) |
| `lib/dns.js` | `extractDns(packets)` -> `{ aux, findings }`; `dnsEvidence(aux)` -> `{ byDest }` |
| `lib/diameter.js` | `extractDiameter(packets, ctx)` -> `{ aux, findings }` |
| `lib/ice.js` | `extractIce(packets)` -> `{ aux, findings }` |
| `lib/detect.js` | `detectIndicators(analysis)` -> `[Indicator]`; `detectScenario(analysis)` -> `Scenario` |
| `lib/advisor.js` | `buildAdvice(analysis, opts)` -> `{ advice }` |
| `lib/hmr.js` | `parseConfig`, `explainRule`, `renderRule`, `matchAgainstAnalysis` |
| `lib/kb.js` | `initKb`, `addDoc`, `listDocs`, `deleteDoc`, `searchKb` |

`ctx` (passed by analyze.js) = `{ messages, legs, calls, warnings }` — read-only apart
from the documented mutations. Every one of these must be **defensive**: never throw on
odd input (push a string onto `ctx.warnings` or return empty arrays), because a single
malformed packet must never fail a whole capture. `detectIndicators` / `detectScenario` /
`buildAdvice` receive the analysis object **after** media/aux/retrans/diff are attached,
so they can read `analysis.media`, `analysis.aux`, `analysis.retrans`, `analysis.calls`,
`analysis.legs`, `analysis.messages`, `analysis.findings`.

---

# Wave 3 — Teams & Projects

Adapted from RFPlex.ai's actual "projects" system (researched from its source
directly, not from memory). RFPlex's model is **not** per-project ACLs — it is
account-wide sharing (a "team" shares 100% of its data, no per-resource
permission) plus named **projects** as folders within that shared space. That
is what "people can group together and keep files in one space" describes, and
it is what this section builds: faithfully the same shape, deliberately fixing
three things RFPlex's own history shows were mistakes.

**Fixed proactively, not retrofitted after an incident (RFPlex's history, in order):**
1. RFPlex initially left ~38 project-scoped routes keyed on raw `userId` while
   only *listing* showed team data — members got 404 everywhere else. Here,
   `accountUid()` resolution is the ONLY id every storage call may use, checked
   into every route from the start (see the rule below), not bolted on later.
2. RFPlex shipped a **critical path-traversal CVE**: a caller-supplied
   `projectId` reached `path.join()` with no ownership check, letting one
   tenant read another's data via `projectId: "../../<victim>"`. Here,
   `resolveOwnedProjectId()` (hex-shape validation + ownership check) is
   mandatory on every route accepting a project id, from the first commit.
3. RFPlex's `access: 'full'|'readonly'` member tier was stored on every
   invite/membership record but **never enforced anywhere** — pure dead
   weight. Not built here at all: every team member has full access, full
   stop. Simpler contract, nothing to get wrong.

## The core idea: `accountUid()`

A **team** is a group of users who share ALL captures and KB docs equally.
Storage is keyed by one canonical id per account — `accountUid(userId)` —
instead of by the individual user. `lib/store.js` and `lib/kb.js` are
**unchanged**: their existing `userId` parameter now conventionally receives
`accountUid(userId)`, not the raw session id. This is a zero-migration change
for every solo user: teamless, `accountUid(userId) === userId`, so single-user
behaviour is byte-for-byte identical to today.

```js
// lib/teams.js
accountUid(userId) -> string
  // team.dataRootId if userId is on a team, else userId itself. Called ONCE
  // per request (see server.js rule below) -- never derived from anything
  // the client sends, only from the authenticated session.
```

**Hard rule for every route touching stored data** (captures, KB docs,
projects): resolve `const uid = teams.accountUid(user.id)` exactly once at
the top of the handler, and use `uid` for every `store.js`/`kb.js`/
`projects.js` call in that handler. Never pass `user.id` directly to a
storage function once a handler has computed `uid` — that inconsistency is
the exact bug class RFPlex shipped (a delete route used raw `userId` while
every sibling route had migrated to `accountUid`, silently pointing a team
member's delete at the wrong, empty directory).

Platform-level `user.role` ('user'|'admin', set by [[project-hiccup]]'s
existing first-user-is-admin rule) is a **separate axis** from team-level
role (owner/admin/member, below) — do not conflate the two. Nothing here
touches `lib/auth.js`.

## Data model — `lib/teams.js`

```js
initTeams(dataDir)

createTeam(userId, name) -> Team
  // throws {userMessage} if userId is already on a team. No seat cap, no
  // tier gating -- hiccup has no billing; cap team size at 50 members as a
  // sanity bound only.
getTeamIdFor(userId) -> teamId | null
accountUid(userId) -> string
getAccountRole(userId) -> 'owner'|'admin'|'member'|null
canManageMembers(userId) -> boolean            // owner or admin
isSuspended(userId) -> boolean

getTeamView(userId) -> { team: Team|null, members: [Member], pendingInvites: [PendingInvite],
                          myRole, myCanManage }
  // team:null (rest empty) when userId is on no team -- this is the normal
  // solo-user response, not an error.

createInvite(inviterUserId, email) -> { token, expiresAt, inviteUrl }
  // throws {userMessage} if inviter cannot manage members, if inviter has no
  // team, or if email already belongs to a member of this team. Supersedes
  // any prior pending invite to the same email+team. No email is sent (see
  // §Email below) -- the caller (server.js) returns inviteUrl for the UI to
  // show as a copy-this-link affordance.
getInviteInfo(token) -> { email, teamName, emailExists, hasPassword } | null
  // hasPassword distinguishes "type your password to join" from "sign in
  // first" (Google-only accounts) on the accept page. Returns null (server
  // maps to 404) for an unknown or expired token.
acceptInvite(token, { sessionUserId, password, createAccount }) -> { userId }
  // Three branches, exactly mirroring RFPlex's (the identity-verification
  // step exists because an invite token travels by email -- forwardable,
  // loggable -- so it must never by itself be enough to join someone else's
  // account):
  //   1. sessionUserId's own email === the invited email -> join immediately,
  //      no password needed (already proven identity via an active session).
  //   2. Invited email belongs to an existing hiccup account, caller is NOT
  //      authenticated as it -> requires `password`, verified via
  //      auth.verifyPassword(email, password); a Google-only account with no
  //      password hash rejects with a clear userMessage ("sign in first").
  //   3. Invited email is new -> requires `createAccount: {password, name}`,
  //      calls auth.createUser({email, password, name}) then joins.
  // A user may belong to exactly one team: joining while already on a
  // different team throws {userMessage} (closes RFPlex's silent-hijack class
  // of bug where switching teams silently orphaned data).
  // Consumes the invite token on success.

setMemberRole(actingUserId, targetUserId, role)          // role: 'admin'|'member'; owner-only
setMemberSuspended(actingUserId, targetUserId, suspended) // owner/admin; not on the owner or (if
                                                           // acting is admin) another admin
removeMember(actingUserId, targetUserId)                  // owner/admin; not self, not the owner;
                                                           // admin cannot remove another admin
transferOwnership(actingUserId, targetUserId)             // owner-only; dataRootId NEVER changes
                                                           // on transfer (would orphan the team's
                                                           // storage under the old owner's id)
```

```js
Team = { teamId, ownerId, dataRootId, name, createdAt }
Member = { userId, name, email, role: 'owner'|'admin'|'member', suspended, joinedAt }
PendingInvite = { email, createdAt, expiresAt }   // never includes the token itself
```

Storage: `data/teams.json` (object, keyed by teamId), `data/team-members.json`
(object, keyed by userId -> `{teamId, role, joinedAt}`), `data/invitations.json`
(object, keyed by a 32-byte-hex token -> `{teamId, invitedBy, email, createdAt,
expiresAt}`, 7-day expiry, swept lazily on read). All via `store.js`'s
`loadJson`/`saveJson` (atomic write -- reuse it, do not reimplement).

**Suspension enforcement**: `lib/auth.js` is untouched. `server.js`'s
`requireAuth(req, res)` — after resolving the session via `auth.getSession` —
additionally calls `teams.isSuspended(user.id)`; if true, clears the session
cookie and returns 401 exactly as for no-session. This keeps session
mechanics and team mechanics decoupled.

**Path safety** (mandatory on every route that accepts a project id in the
URL, body, or a header — this is the fix for RFPlex's CVE, built in from the
start rather than added after an incident):
```js
// server.js helper, mirroring the shape validation already used for capture
// ids (12 hex chars) and rejecting anything else before it can reach a
// path.join anywhere downstream.
function resolveOwnedProjectId(accountUid, rawId) {
  if (typeof rawId !== 'string' || !/^[a-f0-9]{12}$/.test(rawId)) return null;
  return projects.getProject(accountUid, rawId) ? rawId : null;
}
```

## Email — deliberately not built in this wave

hiccup has no email-sending capability today (no Resend/SMTP integration
anywhere in the codebase — this is genuinely new infrastructure, not an
oversight). Wiring that up needs its own sender domain/account, which I
cannot provision. Rather than block the whole feature on it, `createInvite`
returns the invite URL directly and the UI presents "copy this link and send
it to your colleague" (a normal, common pattern for a v1). The token/accept
flow is identical either way — plugging in real email later is purely
additive (call a `sendInviteEmail` function where the UI copy button is
today), never a redesign. Flag this clearly in the UI copy so nobody expects
an email that isn't coming.

## Data model — `lib/projects.js`

```js
initProjects(dataDir)
listProjects(accountUid) -> [Project]              // includes captureCount per project
createProject(accountUid, { name, description }) -> Project
  // throws {userMessage} on empty/too-long name (80 chars) or >100 projects
getProject(accountUid, projectId) -> Project | null
renameProject(accountUid, projectId, { name, description }) -> Project
deleteProject(accountUid, projectId) -> boolean
  // Does NOT cascade-delete captures (deliberately diverges from RFPlex,
  // which does cascade-delete files+chunks). A capture-analysis tool's
  // uploads are not cheaply re-creatable the way a re-uploadable RFP
  // document is -- deleting a folder should not destroy your pcaps.
  // Un-assigns every capture in the project (sets its projectId back to
  // null / "Unfiled") instead.
```

```js
Project = { id, name, description, createdAt, updatedAt, captureCount }
```

Storage: `data/projects/<accountUid>.json` (array, one file per account —
matches RFPlex's actual shape). Project ids: 12 hex chars, same convention
and generator pattern as `store.js`'s `newCaptureId()`.

## Changes to existing capture storage (Wave 1/2 contracts, additive only)

- `meta.json` (per capture) gains `projectId: string | null` (null =
  "Unfiled", the default for every capture uploaded without a project
  chosen — uploading stays exactly as frictionless as it is today).
- `POST /api/captures` accepts an optional `X-Project-Id` header; when
  present, validated via `resolveOwnedProjectId` (404 `{error}` if it names
  a project the account doesn't own) before the upload proceeds.
- `GET /api/captures` accepts an optional `?project=` query
  (`<12-hex-id>` | `unfiled` | omitted-means-all); filters the existing
  listing in memory — no change to `store.js`'s `listCaptures`.
- Every existing capture route (`GET/DELETE /api/captures/:id`, `/analysis`,
  `/advice`, `/api/chat`, `/api/hmr/analyze`'s captureId param) now resolves
  storage via `accountUid(user.id)` instead of `user.id` directly — this is
  the one-line change, per route, that makes today's captures/KB docs
  team-shared with zero data migration.
- `lib/kb.js` calls (`addDoc`/`listDocs`/`deleteDoc`/`searchKb`) likewise
  receive `accountUid(user.id)` as their `userId` argument — KB guides stay
  **account-wide, not project-scoped** (a vendor guide is useful across every
  case a team works, matching how RFPlex kept its Q&A library account-wide
  rather than per-project).

## HTTP API — new routes

```
POST   /api/team                {name}                          -> {team}
GET    /api/team                                                -> {team, members, pendingInvites, myRole, myCanManage}
POST   /api/team/invite         {email}                          -> {token, inviteUrl, email}
GET    /api/team/invite-info/:token                              -> {email, teamName, emailExists, hasPassword}  | 404
POST   /api/team/accept         {token, password?, name?, email?} -> {user} + Set-Cookie   // public, no session required
PATCH  /api/team/members/:userId {role?, suspended?}              -> {ok}
DELETE /api/team/members/:userId                                 -> {ok}
POST   /api/team/transfer-ownership {userId}                      -> {ok}

GET    /api/projects                                             -> [Project]
POST   /api/projects            {name, description?}              -> {project}
PATCH  /api/projects/:id        {name?, description?}             -> {project}
DELETE /api/projects/:id                                          -> {ok}
```

All `/api/team/*` and `/api/projects/*` routes except `POST /api/team/accept`
and `GET /api/team/invite-info/:token` require `requireAuth`. Every handler
that touches storage resolves `accountUid` first per the hard rule above.

## UI

**`public/team.html` + `public/team.js`** (new page, same chrome as
hmr.html/kb.html — topbar with nav links, theme toggle, coffee link — add a
`team` nav link alongside `workbench`/`HMR`/`guides` in ALL FOUR pages'
`<nav class="topnav">`, keeping the existing `.topnav-link` markup pattern
exactly): "no team yet" state (a name field + "Create team" button) when
`GET /api/team` returns `team:null`; once on a team, an invite card (email
field + "Create invite link" button that reveals a copy-to-clipboard URL box
with the explicit "no email is sent — share this link yourself" note) visible
only when `myCanManage`, and a member list (name/email, role badge, "(you)"
tag, suspend/restore/remove/make-admin buttons gated on `myCanManage` and the
same self/owner/admin-vs-admin rules the API enforces — the UI hiding a
button is a convenience, the API is the actual enforcement).

**`public/accept-invite.html` + `public/accept-invite.js`** (new page, public
— no auth chrome, no redirect-to-`/`-on-401): reads `?token=`, calls
`GET /api/team/invite-info/:token`, then checks `GET /api/me` to see if
already authenticated as the invited email, and renders exactly one of the
three branches `acceptInvite` expects (silent-join button / password field /
name+password fields for a brand-new account), POSTs to
`/api/team/accept`, redirects to `/app` on success.

**Sidebar (`app.html`)**: the capture list gains a project filter/grouping
control above it (`#project-filter`: a `<select>` — "All captures" /
"Unfiled" / one entry per project — driving the existing `GET /api/captures`
call's `?project=` param) and the upload flow gains a project picker next to
the dropzone (defaults to "Unfiled", remembers the last choice in
sessionStorage) that sets `X-Project-Id` on upload. A small "+ manage
projects" link opens an inline create/rename/delete panel (reuse `.card`/
`.input`/`.btn` primitives — this does not need its own page).

## Fixtures / selftest additions

`test/make-fixtures.js` is NOT touched by this wave (it produces capture
files, which are orthogonal to teams/projects). `test/selftest.js` gains a
new pass, following its existing auth-pass pattern exactly (temp data dir,
lazy require): create user A, create user B, A creates a team, A invites
B's email, B accepts (join-while-authenticated branch), assert
`accountUid(A) === accountUid(B)`; assert a capture uploaded by A is visible
to B via `GET /api/captures` (list) and `GET /api/captures/:id/analysis`
(direct fetch); assert a THIRD user C (no team) gets 404 on that same
capture id (cross-tenant isolation — the exact case RFPlex's CVE broke);
assert B (plain member) gets 403 inviting a new member, then A promotes B to
admin and the same invite call now succeeds; assert suspending B makes B's
existing session 401 immediately; assert `resolveOwnedProjectId` rejects a
malformed id (`../../etc`, wrong length, non-hex) without ever reaching
`getProject`.

## Wave 3 module exports (exact)

| File | Exports |
|---|---|
| `lib/teams.js` | `initTeams`, `accountUid`, `getTeamIdFor`, `getAccountRole`, `canManageMembers`, `isSuspended`, `createTeam`, `getTeamView`, `createInvite`, `getInviteInfo`, `acceptInvite`, `setMemberRole`, `setMemberSuspended`, `removeMember`, `transferOwnership` |
| `lib/projects.js` | `initProjects`, `listProjects`, `createProject`, `getProject`, `renameProject`, `deleteProject` |

`lib/teams.js` requires `./auth` (for `verifyPassword`/`createUser` inside
`acceptInvite`) and `./store` (for `loadJson`/`saveJson`). `lib/projects.js`
requires only `./store`. Neither requires the other. `server.js` requires
both with the same graceful-optional-require pattern already used for
`lib/hmr.js`/`lib/kb.js`.

---

# Wave 4 — Advice into the persistent drawer, guided flow, colour discipline

User feedback after using the Workbench: the Advice tab is the single most
valuable thing in the app and was buried as one of four tabs in a
bottom-right pane; the "retrans ×N" toggle button in the ladder toolbar reads
as confusing chrome (retransmissions are handled silently now — DESIGN_1
core feature 3 plus the earlier "deal with them silently" pass — a manual
expand/collapse toggle exposes an implementation detail nobody asked to see
raw); and the overall flow should read as four plain steps: **upload → see
the calls/sessions → search or select one → see the advice, with errors
highlighted.** This wave supersedes the relevant parts of Wave 2's §UI
(quoted below) rather than editing that section in place, so the history
stays legible.

## Advice moves into the "ask hiccup" drawer, open by default

**Supersedes**: the `*Advice*` bullet under Wave 2's `#info-pane` description,
the `#info-tabs` bullet including `Advice` in its tab list, and
`#scenario-chip`'s "click -> info-pane Advice tab" behaviour.

- `#chat-drawer` is **open by default** on load (not `hidden`), and stays
  open across capture/call/message selection — it is no longer an
  optional overlay the user has to remember to summon. Closing it is still
  possible (keep `#chat-close`) for anyone who wants the extra ladder width;
  the *default* state on a fresh page load is open.
- The drawer's own header stays `#chat-model` / `#chat-close` as built. Below
  the header, the drawer now has an **Advice section first**, populated
  automatically with the Advice cards for whatever is currently in scope
  (capture-level when nothing is selected, call-scoped once a call is
  picked, message/finding-scoped when those are picked) — this is the exact
  content and card structure Wave 2 specified for `#info-advice`
  (`whatsWrong`/`whyItMatters`/`mechanism`, fix cards per vendor with
  copyable drafts, citation links, KB citations), just relocated. It updates
  reactively on every scope change, the same way the chat history already
  does (`state.chatOpen`-gated re-render; since the drawer is now always
  open this simply means it re-renders every time, not conditionally).
  Below the Advice section, the existing chat conversation UI
  (`#chat-scope` `#chat-hint` `#chat-messages` `#chat-error` `#chat-offline`
  `#chat-form`) continues to work exactly as built — "put the advice here to
  start with" means Advice is the first thing you see in the drawer, not
  that it replaces the ability to ask a follow-up question.
- `#info-pane`'s tab list drops to **three tabs**: Contents, Packet Info,
  Media. `#info-advice` and `#info-tab-advice` are removed from the DOM —
  Advice has exactly one home now (the drawer), not two competing
  surfaces that could drift out of sync.
- `#scenario-chip` now opens/focuses the drawer's Advice section (scoped to
  the capture as a whole) instead of switching an info-pane tab that no
  longer exists.
- `--chat-w` (currently 400px) may need widening — advice fix-cards with
  config drafts want more room than a chat bubble column. Judgement call for
  whoever implements; keep it a comfortable reading width, not full-viewport.

## Retransmission toggle button removed

**Supersedes**: `#ladder-toolbar (collapse toggle, zoom, export)` in Wave
2's frozen id block.

Remove the `<button data-action="ladder-collapse-retrans">retrans ×N</button>`
control from `#ladder-toolbar` entirely. Retransmissions are always
collapsed now — no user-facing toggle. Ladder rendering keeps
`collapsed: true` as a fixed constant, not a piece of UI state; simplify any
now-dead `aria-pressed`/toggle-state handling in `app.js`/`ladder.js` that
existed only to drive this button. Zoom and export controls in the toolbar
are unaffected.

## Guided flow: verify, don't rebuild

The four-step flow the user described (upload → calls → search/select →
advice+highlighting) is *mostly already the existing architecture* — this is
a verification and reinforcement pass, not a new information architecture:

1. **Upload** — the sidebar dropzone, unchanged.
2. **See calls/sessions** — `#filter-pane`'s call tree, already the default
   first thing populated after analysis. No change needed to the pane
   itself; confirm it's genuinely what a user's eye lands on once a capture
   finishes analysing (it already occupies the largest top-left area).
3. **Search or select** — `#searchbar` is already prominent and always
   visible; selecting a call in `#filter-pane` already scopes the ladder,
   selection pane and (now) the drawer's Advice section. Confirm this
   reactive chain still fires correctly for every selection path (tree
   click, search-result click, lamp click) now that the drawer is always
   open rather than conditionally rendered.
4. **Advice + highlighted errors** — solved by the drawer change above, plus
   the existing ladder error-highlighting (`has-warn`/`has-crit`, thicker
   stroke + severity dot, per Wave 2). Verify this path end-to-end: select a
   call with a warn/crit finding -> the ladder visibly flags the offending
   row -> the drawer's Advice section shows the card explaining it, with no
   extra click anywhere in that chain.

Do not tear down or restructure the five-pane grid beyond what the above
requires (the drawer's default-open state, and info-pane losing one tab).

## Colour discipline: warn = orange/amber, crit = red, never conflated

The base tokens are already correct (`--warn: #f5a623` amber, `--crit:
#f2545b` red, both light+dark) — this is a **usage audit**, not a retheme.
Check every place severity drives a colour (ladder row/sevdot, lamps, chips,
advice card accents, findings list, the retrans/storm strip, scenario chip)
and confirm: warn is always the amber/orange token, crit is always the red
token, and nothing else in the app (loading states, focus rings, generic
accents) borrows red or amber in a way that could read as an error/warning
when it isn't one. Fix anything found; note anything ambiguous rather than
guessing.

---

## FIXED 2026-08-19 — `lib/textlog.js` raw-sip/acme-log parsing

> **All three gaps below are now closed** (see "Wave 17" at the end of this
> document for the fix, the regexes and the reasoning). Kept as written because
> the diagnosis is still the clearest statement of what was wrong and why the
> *silence* mattered more than the parse miss. Measured result: the repo's own
> `test/fixtures/adversarial/rfc4475-torture.txt` went from **10 to 19** parsed
> messages, with one warning where there had been none.

### Original entry (found, not yet fixed)

Found 2026-08-18 running RFC 4475 ("SIP Torture Test Messages") content
through the parser as a robustness check. The specific fixture file used to
find these is no longer in the repo (see git history / conversation record
around this date for provenance — it was removed over an unrelated licensing
concern for other files in the same batch, and separately went missing by a
mechanism that wasn't determined), but the underlying bugs are real,
independently reproducible, and still present as of this writing:

1. **Method tokens containing `%`** (RFC 3261's `token` grammar explicitly
   allows it — RFC 4475's `esc02` message uses `RE%47IST%45R`) don't match
   `REQ_LINE` in `textlog.js` (~line 36; the method class is `[A-Z0-9_-]`,
   no `%`) → the message is silently invisible, not even counted as a
   candidate, no warning pushed.
2. **Non-`SIP/2.0` version strings** (`SIP/7.0`, RFC 4475's `badvers`) and
   **status codes outside 3 digits** (a 10-digit code, RFC 4475's `bigcode`)
   both fail `REQ_LINE`/`STATUS_LINE`'s hardcoded `SIP/2.0` / `\d{3}`
   (~lines 36-37) → same silent invisibility, no warning.
3. **Unbounded `Content-Length` body consumption**: a `Content-Length` value
   far larger than the actual body (RFC 4475's `clerr`, `Content-Length: 9999`
   against a ~150-byte real body) makes `consumeMessage`'s body-reading loop
   (~lines 132-143) consume every remaining line in the file as "body" —
   the loop has no bound besides running out of input — silently swallowing
   every subsequent message in the file with no warning pushed on that path.

None of this violates the "never throw on malformed input" contract (nothing
crashes), but the *silent* part is a real gap against this document's own
"skip with a warning string" promise for `raw-sip`/text-log parsing
specifically. Worth a dedicated fix pass: (1) widen the method-token class to
match RFC 3261's actual `token` grammar, (2) relax the version/status-line
match to warn-and-skip rather than silently ignore on a near-miss, (3) bound
the body-consumption loop by remaining-file-length and warn when
`Content-Length` doesn't fit what's left.

---

# Wave 5 — global keyboard layer, command palette, skeleton loading states

Follow-up from a UI review against current (2023+) industry guidelines. Two
independent additions, briefed together here since the first two share
keyboard-handling infrastructure:

## A. Global keyboard layer + command palette

**The gap**: `app.js` has several per-element `keydown` handlers (row
navigation inside specific lists, table headers, the chat input) but no
app-wide shortcut layer and no command palette — both close to universal in
this class of tool by 2024-2026 (GitHub, Linear, VS Code, Raycast, Gmail).
hiccup already has a rich field-filtered search bar (`#search-input`) for
*capture content* — the palette below is deliberately for *navigation and
actions*, not a replacement for that search, to avoid merging two different
search domains into one component.

**Hard rule, non-negotiable**: every global single-key binding (`/`, `j`,
`k`, `?`, `Escape`) MUST be suppressed whenever focus is inside an
`<input>`, `<textarea>`, `[contenteditable]`, or `<select>` — check
`document.activeElement` (or the event target) at the top of the global
handler and bail out immediately for those cases, letting the keystroke
reach the field normally. This is the single most common bug in shortcut
layers (typing "j" into the search box must type the letter "j", never
navigate). `Ctrl/Cmd+K` (the palette opener) is the one exception — it
should fire even from inside most inputs (matching every peer tool's
convention), EXCEPT while the user is actively composing chat input
(`#chat-input`) or the HMR paste textarea, where a stray Ctrl/Cmd+K would be
surprising mid-thought — use judgement, document the choice.

**Global bindings** (all inactive while typing in a field, per the rule
above, except where noted):
- `/` — focus `#search-input` (matches GitHub/Gmail convention for a
  dedicated, unmodified search-focus key).
- `j` / `k` — move the selection down/up one row in whichever list last had
  a selection change (the calls tree `#filter-tree` or the numbered
  `#selection-list`) — track "last active list" as a small piece of state,
  default to the calls tree when nothing has been selected yet this
  session.
- `Escape` — context-sensitive, in this priority order: if the command
  palette is open, close it; else if `#search-input` is focused with a
  query, clear and blur it; else if the chat drawer is open AND the
  viewport is the narrow/stacked layout (drawer isn't the always-open
  desktop default there), close it; else do nothing (never fight the
  browser's own Escape behaviour, e.g. exiting fullscreen).
- `?` (only when not typing in a field) — open a lightweight shortcuts-help
  overlay listing every binding here. Undiscoverable shortcuts have near-zero
  value; this is not optional polish, it's the point.
- `Ctrl/Cmd+K` — open the command palette (below).

**Command palette**: a centred overlay (own component, not reusing the chat
drawer or any existing modal), opened by `Ctrl/Cmd+K` or a small icon button
you may add to the topbar, closed by `Escape` or a click outside. Contains a
single text input (fuzzy-matches against action labels — simple substring +
subsequence scoring is sufficient, no need for a scoring library) and a
scrollable result list, arrow-key navigable, `Enter` executes the
highlighted action, mouse click executes directly. Seed action set (extend
sensibly if an obvious one is missing, don't feel bound to exactly this
list): switch to workbench/HMR/guides/team pages, toggle light/dark theme,
open/close the ask-hiccup drawer, jump to a specific info-pane tab
(Contents/Packet Info/Media) when a capture is loaded, open the
manage-projects panel, sign out. Do NOT fold capture-content search into
this component — that stays `#search-input`'s job.

Accessibility: the palette traps focus while open (Tab cycles within it,
doesn't leak to the page behind), returns focus to whatever had it before
opening when closed, uses `role="dialog"` `aria-modal="true"` with a visible
label, and its own result list uses `aria-activedescendant` or equivalent
roving-tabindex pattern rather than moving real DOM focus per keystroke.
The `?` help overlay follows the same dialog/focus-trap pattern.

New ids/classes: your choice, follow the existing kebab-case convention
(e.g. `#command-palette`, `#shortcuts-help`) — nothing here is a frozen
contract id since it's new UI, just be internally consistent and put a
short comment at first use documenting the id like every other pane already
does in `app.html`'s CONTRACT comment block (append to it, don't remove
anything from it).

## B. Skeleton loading states during upload + analysis

**The gap**: `#upload-msg` shows a text status line during
`POST /api/captures`, but the calls tree, ladder and info panes stay in
their plain empty state (or, for a second upload, their *previous* capture's
content) until the response lands, then populate all at once. Modern
pattern (GitHub, Linear, Slack) is a skeleton placeholder shaped like the
eventual content, replacing spinner-and-wait for anything likely to take
more than ~300ms — analysis of a large pcap is exactly that case.

Add skeleton placeholder rendering for the period between upload start and
the analysis response landing:
- `#filter-tree`: 3-4 pulsing placeholder rows shaped like tree rows (a
  short indented bar + a shorter sub-label bar), not real content.
- `#ladder-svg-host`: a placeholder host-column header band + a few faint
  horizontal row bars, echoing the real ladder's layout without claiming to
  show real data.
- `#selection-list`: 3-4 placeholder rows matching the numbered-table shape.
- Keep `#upload-msg`'s existing busy text — the skeletons are additive, not
  a replacement for that status line.
- Skeleton CSS: a subtle shimmer/pulse animation using existing tokens only
  (`--panel2`/`--border` for the placeholder bars, a soft opacity pulse) —
  respect `prefers-reduced-motion` exactly like the rest of the app already
  does (swap the shimmer for a static, slightly-dimmed placeholder when
  reduced motion is requested; grep app.css for the existing
  `@media (prefers-reduced-motion: reduce)` block and add to it, don't
  create a second one).
- Show skeletons only while `POST /api/captures` for a *fresh* upload is in
  flight (not while merely switching between already-loaded captures in the
  sidebar list, which should stay instant) — key it off the upload
  fetch's own pending state, not a generic "app busy" flag.
- Clear skeletons and render real content on both success and failure paths
  (a failed/422 upload must not leave skeletons stuck forever — fall back to
  the normal empty state with the error surfaced via `#upload-msg.err`).

## C. Target Size (WCAG 2.2 §2.5.8) + a Focus Not Obscured (§2.4.11) audit

**Target Size — the actual fix, not just a note.** Every icon-only
interactive control (no visible text label) must have a hit area of at
least 24×24 CSS px, checked against the WCAG exemptions (inline-in-text,
an equivalent larger target exists elsewhere, essential-small like a map
pin, user-agent-controlled) before assuming a given control needs
enlarging — some may already be exempt or already large enough; audit
first, don't blanket-resize everything. Known tight candidates from a
visual review: the theme-toggle button (`[data-theme-toggle]`), the
drawer's `#chat-close`, `#search-clear`, the ladder toolbar's icon buttons
(zoom in/out/reset, export, collapse-related controls if any remain), the
lamp chips in `#lamps` if their padded box comes in under 24px on either
axis, capture-row delete buttons, and `#project-manage-close`.

Pattern (Cisco/Material/Fluent-style — this is an explicit invitation to
use colour here, not just invisible padding): give each of these a padded,
roughly-square hit area (pad up to ~32-36px even where the glyph itself
stays visually small — the click/tap target is what must hit 24px
minimum, not the glyph), and make the enlarged area visible on
hover/focus with a tinted rounded background using `var(--accent-wash)`
(or `var(--tint-select)` for a slightly stronger version) rather than
leaving the extra padding invisible — this makes the larger target
*discoverable*, which matters as much as the numeric minimum. Reuse one
shared class (e.g. `.icon-btn`) for this treatment rather than
hand-tuning each control separately, so the pattern is consistent and
easy to apply to something missed in this pass.

**Focus Not Obscured — audit, then close what's actually open.** Section
A/B's drawer default-open (desktop) already shifts the main layout via
`margin-right` rather than floating on top of it, so it should not
literally cover focusable content on wide viewports — confirm this is
still true after any Wave-5-A/B layout changes, don't just assume. Beyond
the drawer specifically: grep app.css for every `position: sticky` and
`position: fixed` rule (info-pane tab bar, ladder toolbar, table-dense
sticky headers, the topbar itself) and, for each, verify that
`:focus-visible` on an element scrolling underneath it either scrolls
that element far enough into view to clear the sticky/fixed layer, or
never actually gets covered in the first place given the pane's own
internal scroll containment. Where you find a genuine case (not a
hypothetical one — verify by reasoning through the actual DOM/CSS, or by
booting the server and checking computed positions), fix it with
`scroll-margin-top`/`scroll-padding-top` on the scroll container sized to
the sticky element's height, which is the standard, low-risk fix for
exactly this failure mode. Report what you checked and what (if anything)
needed fixing — this is meant to be a real audit with a real, possibly
short, list of findings, not padding out a report with restated theory.


---

# Wave 6 — In-app feedback with structural context

**Why this exists.** Gavin needs to know what users think AND what they were
looking at when they thought it, because "the ladder is confusing" is
unactionable without knowing which capture shape produced it. The whole design
question is therefore: how much context can be attached before the feature
starts leaking the very data hiccup promises to keep still?

## The privacy boundary — the load-bearing decision

hiccup's own footer says **"self-hosted · your traces never leave this box."**
A feedback feature that shipped trace content off the box would make that a
lie. So the boundary is drawn explicitly and enforced **server-side**, not by
trusting whatever the browser posts.

**ALLOWED in `context` (structural — describes the *shape* of what was on
screen, never its content):**

| field | example | why it is safe |
|---|---|---|
| `page` | `"/app"` | route only |
| `appVersion` | `"0.1.0"` | build id |
| `captureFormat` | `"pcap"` \| `"pcapng"` \| `"text"` | format, not content |
| `captureBytes` | `40660` | size only |
| `counts` | `{sip:88, h323:0, calls:12, legs:13}` | cardinality only |
| `scenario` | `{key:"call-centre", confidence:0.85}` | hiccup's own classification |
| `scopeType` | `"capture"\|"call"\|"leg"\|"transaction"` | selection *kind* |
| `scopeIds` | `{callId:"c4", legId:"d4"}` | hiccup-generated ids, meaningless outside this capture |
| `selectedRow` | `{kind:"msg", method:"REFER", status:null}` | SIP method/status verbs only |
| `lamps` | `[{key:"refer-transfer", state:"issue"}]` | protocol feature names |
| `adviceRuleIds` | `["indicator-issue"]` | rule ids, never rendered advice text |
| `viewport` | `{w:2036, h:1040}` | layout debugging |
| `userAgent` | UA string | browser bugs |
| `theme` | `"dark"` | theme-specific bugs |

**FORBIDDEN — never collected, and stripped server-side if a client sends it
anyway:** raw message text (`raw`), header values, SDP bodies, phone numbers /
From / To / P-Asserted-Identity, IP addresses and ports, the capture bytes,
**the capture filename** (routinely carries customer names) and **the current
search term** (users search by phone number). The last two are genuinely useful
for reproduction and were still rejected — that is the deliberate trade.

`sanitizeContext()` in `lib/feedback.js` is an **allow-list**: it builds a fresh
object from known keys and known primitive types. Unknown keys are dropped
silently. This means a future UI change cannot widen the boundary by accident —
widening requires editing the allow-list, in this file's table, on purpose.

**The user sees it before it sends.** The modal renders the exact JSON that will
be posted, in a collapsible panel, plus a toggle to submit with no context at
all. Consent is informed or it is not consent.

## Data shapes

```
Feedback {
  id: string,              // "fb_" + 12 hex
  ts: number,              // epoch ms
  userId: string,          // who submitted (server-side, never client-supplied)
  email: string,           // denormalised for the digest
  kind: 'bug' | 'idea' | 'confusing' | 'praise' | 'other',
  rating: number|null,     // 1-5, optional
  comment: string,         // <= 4000 chars, trimmed
  context: object|null,    // sanitizeContext() output, or null if declined
  read: boolean            // admin viewer toggles this
}
```

Stored as one JSON array at `data/feedback/feedback.json` via `store.js`'s
atomic `saveJson`. A flat file is right here: this is low-volume human input,
and the alternative (a per-record directory like captures) buys nothing.

## HTTP

| method | path | who |
|---|---|---|
| POST | `/api/feedback` | any signed-in user |
| GET | `/api/admin/feedback` | site admin |
| POST | `/api/admin/feedback/:id/read` | site admin |
| POST | `/api/admin/feedback/digest/send?dry=1` | site admin |
| GET | `/admin/feedback` | site admin (page) |

**`requireSiteAdmin()` is new.** `lib/auth.js` already stamps
`role: 'admin'` on the first user (`_users.length === 0 ? 'admin' : 'user'`)
but **nothing has ever gated on it** — the only "admin" checks in server.js
today are team owner/admin, a different concept living in `lib/teams.js`. This
wave adds the site-wide gate. It is deliberately NOT the team role: a team
admin administers their own team, not the whole box.

Rate limit: 5 submissions per user per hour, in-memory. Abuse here is noise in
Gavin's inbox, not a security boundary, so an in-memory counter that resets on
restart is proportionate.

## Weekly digest

In-process timer, checked every 15 minutes, fires **Monday 09:00 local**,
matching RFPlex's existing growth-digest cadence. The last-sent ISO week is
persisted to `data/feedback/digest-state.json`, so:

- a service restart mid-week does **not** re-send that week's digest, and
- a box that was off on Monday still sends when it next comes up that week.

Both failure modes are real for a home-lab box that reboots for Windows
updates; a bare `setInterval(7 days)` gets both wrong.

`lib/mail.js` is a zero-dependency SMTP client over `node:tls`, ported from
RFPlex's proven `sendSmtp()` (same Resend account, same AUTH LOGIN +
multipart/alternative shape). It reads `data/email-config.json` and, when that
file is absent or incomplete, **degrades to a logged no-op**: an unconfigured
mailer must never take the analyser down, and hiccup's core job has nothing to
do with email.

## UI

`public/feedback.js` is a standalone widget, loaded by `app.html`, `hmr.html`,
`kb.html` and `team.html`. It reuses Wave-5A's `.overlay` shell and focus-trap
conventions rather than inventing a second modal idiom. On pages that are not
the workbench there is no capture, so `collectContext()` returns just the
page-level fields — the same allow-list, fewer populated keys.

The widget owns `#feedback-open` (topbar button), `#feedback-modal`,
`#feedback-form`, `#feedback-context-toggle` and `#feedback-context-pre`.

---

# Wave 7 — The crawlable surface

The analyser is behind a session, so before this wave the landing page was the
entire indexable site: one hero, one auth card, nothing for a search engine to
rank and nothing for an engineer to land on. Wave 7 adds a small public
reference section and the crawler plumbing around it.

## New routes

```
GET /robots.txt                 -> text/plain   crawl policy (no auth)
GET /sitemap.xml                -> application/xml   urlset built from PUBLIC_PAGES
GET /sip                        -> public/sip/index.html               (hub)
GET /sip/488-not-acceptable-here
GET /sip/408-request-timeout
GET /sip/486-busy-here
GET /sip/one-way-audio
GET /sip/retransmissions        -> public/sip/*.html
```

## `PUBLIC_PAGES` — one table, two consumers

`server.js` holds a `Map` of clean URL → file under `public/`, and both the
router and `/sitemap.xml` read it. Adding a reference page is therefore a single
edit: it cannot become routable-but-uncrawlable, or listed-but-404. It is a Map
rather than an object literal so `/__proto__` resolves to nothing.

`lastmod` comes from each file's `mtime`, never a literal date — a literal would
start lying the day after it was typed and no deploy step would ever catch it.
A page whose file is missing is dropped from the sitemap rather than advertised
as a 404, matching how the optional-module requires degrade elsewhere.

The origin in both documents comes from `config.baseUrl` (the same value
`lib/teams.js` builds invite links from), not from the request's `Host` header,
which a client controls.

## Crawl policy

`robots.txt` disallows `/api/`, `/admin/`, `/app`, `/hmr`, `/kb`, `/team` and
`/accept-invite`. This is a statement about *usefulness*, not secrecy — every one
of those is already behind `requireAuth`, and robots.txt is advisory. The bare
`Allow: /` is deliberately placed **after** the disallows: above them, a
first-match-wins crawler would treat it as overriding every line.

Every auth-gated page also carries `<meta name="robots" content="noindex">`
(`app.html`, `hmr.html`, `team.html`, `accept-invite.html`, and the two admin
pages, which already had it). `accept-invite.html` is public in the sense that it
needs no session, but its URL *is* a single-use token — an indexed invite link is
an indexed credential.

## The reference pages

`public/sip/*.html`: five short pages (488, 408, 486, one-way audio,
retransmissions) plus a hub at `public/sip/index.html`, each written for someone
who has the trace open already. They carry a canonical link, Open Graph and
Twitter tags, and a `TechArticle` (hub: `CollectionPage`) JSON-LD block.
`index.html` gained a canonical link, a `SoftwareApplication` block and an `h1`
— the wordmark above the tagline is CSS artwork, so the landing page had no
heading a crawler could read at all.

Structured data claims only what is checkable against `LICENSE`, `package.json`
and the page itself: **no `aggregateRating`, no `reviewCount`, no author
organisation**. There are no reviews and there is no company, and inventing
either is both untrue and a manual-action risk.

`public/sip.css` styles them. It restates app.css's topbar block rather than
linking `app.css`, because these pages are the one part of hiccup served to
people who have not signed in and ~60KB of workbench grid, ladder and chat-drawer
rules would be entirely unused. That duplication is the known cost: if the shared
topbar ever moves, it moves in two files.

---

# Wave 8 — Multilingual UI chrome (en / fr / es / de)

Translates the ~745 strings of UI chrome — buttons, labels, nav, empty states,
server error sentences — into French, Spanish and German. It deliberately does
**not** translate the ~180,000 characters of domain prose in `lib/advisor.js`,
`lib/detect.js`, `lib/hmr.js` and `lib/isup.js`: that text is hand-authored
diagnostic instruction executed against production SBCs, `advisor.js`'s own
header guarantees every word of it is deterministic and never machine-produced,
and a dropped negation there turns a caution into an instruction. It stays
English on purpose, in every language. `lib/hmr-generate.js` (Wave 9) joins
this list for the same reason: its questions, warnings, assumptions and
`explainRule()` intent text are generated instruction about a specific SBC
change, not UI chrome — only the surrounding buttons and labels on `/hmr` are
translated, exactly as with an analysed rule's correctness issues today. `public/privacy.html`'s notice is
excluded for the same reason at a smaller scale — a mistranslated legal
document is its own liability — and says so inline. Full inventory and
reasoning: `docs/i18n-plan.md`.

## Catalogue: keyed by the English source text, not a hand-written name

`locales/en.json` is the generated inventory — `hash -> {text, cat, where}` —
rebuilt by scanning every `public/*.html`, `public/*.js` and `server.js`'s
`error:` sentences. `locales/{fr,es,de}.json` are hand-maintained, keyed by
the **English text itself** (`"hiccup — join a team": "hiccup — rejoindre..."`)
because these are the only files a human edits, and a wall of hex is
unreviewable. `bin/i18n-build.js` applies the hash when it generates the
browser catalogues (`public/i18n/<lang>.js`, `window.HICCUP_I18N`), so the
safety property holds at every layer: **edit the English anywhere, and the key
it hashes to changes with it.** A stale translation cannot silently keep
showing under new English — the lookup just misses, and `_t()`'s fallback is
the argument you gave it, so the UI shows the new English instead. Rendering
blank is structurally impossible, not merely unlikely.

`public/i18n.js` is `require()`d by both the browser and `lib/i18n.js` /
`bin/i18n-*.js`, so there is exactly one hash implementation (FNV-1a, split
into two 32-bit halves for JS's 53-bit integer ceiling) and one whitespace-
normalisation rule. Two copies could drift by one rule and silently turn every
lookup into a fallback-to-English — which looks like "translation stopped
working" and nothing would report it. sha1 was the original plan
(`docs/i18n-plan.md` §2.1); it was dropped because the browser has no
*synchronous* sha1 (`crypto.subtle` is async and secure-context only) and
`_t()` must be synchronous. This is an addressing function, not a security
primitive, and `bin/i18n-extract.js` hard-fails on any collision across the
whole catalogue.

## Load order and the `_t()` fallback contract

Every page resolves the language in a tiny blocking `<script>` in `<head>`,
`document.write`-ing `/i18n/<lang>.js` before `/i18n.js` itself loads —
same FOUC-safe shape as `theme.js`'s inline picker, and for a stronger reason:
`_t()` and its catalogue must both exist before `app.js`'s first render, and
an async fetch would race it. `_t(en)` takes the English text as its own
argument and returns it unchanged on any miss, so a missing translation is
never a blank string or a thrown error — it is the current, correct English.
A one-shot `[data-i18n]` / `[data-i18n-attrs]` DOM pass runs on
`DOMContentLoaded`; `data-i18n` carries no key, the element's own English text
**is** the key, so a miss leaves the markup exactly as authored.

Inline `<script>` blocks in HTML files are outside this pipeline —
`scanHtml()` deliberately does not descend into `<script>`/`<style>` bodies —
so `admin-status.html` and `admin-feedback.html`'s dynamically-rendered field
labels stay English-only. Acceptable here: both pages are gated to
`config.adminEmails`, i.e. seen by nobody but the site operator.

Server error sentences reach the client with no `code` field
(`{error: '<English sentence>'}`), so rather than refactor every route to add
one, `scanServerErrors()` extracts every string literal that follows
`error:` in `server.js` and the client runs whatever sentence it receives
through `_t()`. Source-text keying makes this work with zero server changes.

## The nightly job records; it does not translate

`refreshIfDue()` (polled every 15 minutes, restart-safe on a day-stamp exactly
like `lib/feedback.js`'s digest and `lib/retention.js`'s sweep) re-scans the
tree and writes newly-missing strings to `data/i18n-missing.json`. It does
**not** call an LLM to fill them in. Translating unattended would mean
generated text landing in the repo with nobody reading it — the same argument
that keeps `advisor.js` out of scope applies in miniature to the chrome: a
wrong button label is cheap, a wrong confirmation dialog is not. Until a
string is translated by hand (`locales/<lang>.json`, then `npm run i18n`) the
UI shows English, which is correct and obvious rather than confidently wrong.
This is a deliberate narrower reading of "translate everything overnight" than
the original ask; revisit if hiccup ever gets more than one maintainer to
clear the backlog.

## Two bugs this wave's own live verification caught

Neither was a translation-content problem — both were found by actually
loading pages in the browser rather than trusting the diff:

- `public/admin-status.html`'s restart confirmation had a **literal newline
  inside a single-quoted JS string** (`confirm('...now?\n\nIn-flight...')`
  written with a real line break instead of `\n`). That is a hard syntax
  error, so the page's *entire* inline `<script>` failed to parse — not a
  cosmetic issue, the whole status page and restart button were dead. Predates
  this wave; unrelated to translation; only surfaced because the page was
  actually clicked through.
- `lib/hmr-generate.js`'s `findMethods()` matched `\bINVITE\b` but not the
  natural plural "outbound INVITEs" — engineers write it that way far more
  often than the bare method name. Fixed with a trailing `S?` (uppercase,
  since the input is upper-cased before matching — the obvious `s?` fix is
  silently wrong and was caught by re-running the new selftest rather than
  trusting the first patch). Covered by `test/selftest.js`'s `hmr-generate:`
  block, added alongside the fix since none existed.

---

# Wave 9 — Natural-language → HMR rule generator

`/hmr` gained a second, complementary flow above the existing paste-a-config
one: describe a rule ("delete the P-Asserted-Identity header on outbound
INVITEs") and hiccup drafts it, rather than requiring an existing config to
read from. `POST /api/hmr/generate` is a thin route wrapping
`lib/hmr-generate.js`'s `generateRule(description, opts)`.

## No guessing — ask, or say what was assumed

`generateRule()` never fabricates a rule from an ambiguous description. A
fixed `INTENTS` table (delete/replace/add/store — order matters, `replace` is
tested before `add` because "replace X with Y" contains "with" and would
otherwise read as an add) requires **both** a recognised action verb and a
named header before it will build anything; failing either, it returns
`ok:false` with `questions` naming exactly what is missing rather than a
confident wrong guess. Direction, message type and conditions are genuinely
optional — a description that omits them still produces a rule, but every
default taken is pushed onto `assumptions` for the caller to show, because an
unbound or over-broad rule is the single most common way a "correct" header
manipulation change is invisible in a trace.

## Value extraction: `.source` concatenation, not a hand-escaped string

Values ("set to X", "with Y") are read with a shared trailing-clause boundary:

```js
const BOUNDARY = /(?=\s+\b(?:on|when|if|for|unless|only|where)\b|[,.]|$)/i;
const m = text.match(new RegExp(/\b(?:with|to)\s+["']?([^"'\n,.]{1,120}?)["']?/.source + BOUNDARY.source, 'i'));
```

Built from two genuine regex *literals* joined via `.source`, not a hand-typed
string containing `\b`/`\s`. A string literal processes its own escapes before
the RegExp constructor ever sees it — `'\b'` becomes an actual backspace byte
and `'\s'` silently loses the backslash (unrecognised string escape) — so a
string-built version of this pattern compiles without error and then never
matches anything. `.source` concatenation is immune because the escapes are
never re-interpreted; this was a real bug during development, caught by the
adversarial test case "add a Privacy header set to id on outbound calls",
which used to capture the value as `"id on outbound calls"` instead of `"id"`.

## Reusing the analyse-flow renderer rather than building a second one

The generator's response — `{rule, explain: {intent, correctness}, drafts:
{oracle-acme, audiocodes, ribbon, generic}}` — is deliberately the same shape
`ingest()` builds per-rule from `/api/hmr/analyze`. `public/hmr.js`'s
`renderGenResult()` reshapes it into one `{rule, explanation, rendered}` entry
and hands it straight to the existing `ruleCard()`: intent, correctness
issues with citations, the vendor-translate picker and its copy button are
therefore pixel- and behaviour-identical for a generated rule and an analysed
one, and a future change to how a rule card renders (say, a new citation
style) applies to both without being written twice. `vendorLabel()` gained one
extra case — `'generic'` (the vendor a freshly generated, not-yet-vendor-
rendered rule is stamped with) reads as "not vendor-specific" rather than
being shown as if it were a real product name.

## What stays English — same boundary as Wave 8, applied to a new file

`lib/hmr-generate.js` was added after Wave 8's translation pass and is not in
`lib/i18n.js`'s scanned file list (`SERVER_FILES`, `public/*.html`,
`public/*.js`) — its `questions`, `warnings`, `assumptions` and the
`explainRule()` text they wrap are generated instruction about a specific
proposed SBC change, the same category as `advisor.js`'s findings, and stay
English regardless of UI language. Only the surrounding chrome — the
"Describe the rule you want" label, the Generate/Clear buttons, status line,
"hiccup needs to know more" heading — went through the translation catalogue
(18 new strings, `locales/{fr,es,de}.json`). The description label says so
explicitly ("in plain English") in every language, because the parser only
recognises English trigger words — a French description would silently fail
`INTENTS`' matching and surface as "hiccup needs to know more" with no
indication that the actual problem was the input language, so the UI has to
set that expectation up front rather than let it surprise someone.

---

# Wave 10 — Erase your data, distinct from deleting your account

`/settings` gains a third GDPR action alongside export and account deletion:
`DELETE /api/me/data {confirm:"ERASE"}` removes captures, projects and
library documents while leaving the account, login and (if on one) team
membership untouched. Until now the only self-serve erasure was full account
deletion — someone who wanted a clean slate without losing their login had no
way to get one. Implementation mirrors `handleMeDelete`'s established shape
exactly: same shared-library hazard (`resolveAccountUid(user.id) ===
user.id` gates every deletion, so one team member's erase cannot touch the
team's shared library), same iterate-and-delete-each pattern over
`store.deleteCapture` / `projects.deleteProject` / `kb.deleteDoc`, same
"best-effort, keep going on a partial failure" error handling.

The two actions sit right next to each other on the same page, both styled as
danger cards, so they use **different** confirm words — `ERASE` here,
`DELETE` for the account — on purpose: a mistyped confirmation must not
silently fall through into the other irreversible action. Verified end to end
against a disposable throwaway account (sign up, create a project, erase,
confirm the project is gone and `GET /api/me` still 200s, delete the test
account) rather than the real one — this is a real destructive endpoint and
the dev instance used for this wave's testing shares `data/` with the live
service.

The rest of `/settings` was reorganised around this: a new "Your privacy
rights" heading now groups export / erase / delete together, separately from
the "Privacy of your captures" preferences section above it (masking,
retention, sharing) — those are ongoing settings, not one-shot rights you
invoke, so keeping them apart from the actions was the point of "move the
GDPR stuff into its own subsection."

## Two more bugs this wave's live verification caught

- `public/settings.html`'s entire account-management script had been inline
  since it was first built, which means it was never covered by
  `lib/i18n.js`'s `scanHtml()` (deliberately skips `<script>` bodies — see
  Wave 8) or `scanJs()` (only scans `public/*.js` files). Every status
  message and account fact on this page — a page every signed-in user visits,
  not an admin-only one — had been silently English-only since Wave 8 shipped.
  Extracted to `public/settings.js`, matching every other page's convention,
  and its ~30 strings translated into fr/es/de. Building the extraction this
  way surfaced a second, sharper bug: writing `_t('foo ' + 'bar')` across two
  literals joined by `+` — instead of one literal — means the scanner only
  ever sees `'foo '` (it requires the literal to sit directly against `_t(`),
  so the catalogue holds a translation for `'foo'` alone while the runtime
  call still hashes the full `'foo bar'` string. The lookup can never hit;
  the string is quietly frozen in English forever, no matter how the
  catalogue is edited. All six such call sites in the new file were rewritten
  as single literals.
- `.set-confirm { display: flex; ... }` and the browser's default `[hidden] {
  display: none }` are equal specificity, and the page's own rule, being
  declared later, was winning — so both the erase-data and delete-account
  "type X to confirm" boxes were showing on page load instead of only after
  their button is clicked. Predates this wave (the delete-account box had the
  same bug); only surfaced because the new erase-data box was screenshotted
  immediately after being added and visibly wasn't hidden. Fixed with one
  `.set-confirm[hidden] { display: none; }` override.

---

# Wave 11 — Link to a vendor guide, instead of ingesting one

`/kb` gains a second way to add a guide: `POST /api/kb/link {url, title?,
vendor?, product?}` registers a link to a vendor's own hosted documentation.
This exists in place of the originally-planned "pre-ingest vendor SBC config
guides" feature, which stalled on a licensing question hiccup cannot answer
for itself — it holds no redistribution rights to any vendor's manuals, so a
stored, indexed copy (even one hiccup fetched and extracted text from itself,
never mind one shipped pre-loaded) raises exactly that question. A link
raises none of it: `lib/kb.js`'s `addLink()` stores the URL and the two tags
a user already types for an upload, and **nothing else** — no fetch, no
extracted text, no `chunks.json`, no index entry. It is a labelled bookmark
back to the vendor's site, not a copy of anything.

Reuses the existing per-document storage layout on purpose (same
`data/kb/<userId>/<docId>/`, same `listDocs`/`deleteDoc` lifecycle) so a link
and an ingested guide sit in the same table, are deleted the same way, and
required no new storage code — only `chunks: 0` and a `url` field
distinguish one from the other. `_cleanUrl()` requires `http(s)://`: the URL
is stored verbatim and later rendered as a real `<a href>` on the client, so
this is the one point standing between a `javascript:` URI typed into the
field and stored XSS the moment the person who added it — or anyone else
looking at their own library — clicks their own link. Verified against a
disposable throwaway account: added a link, confirmed it lists with
`chunks:0` and a `url`, confirmed `POST /api/kb/link {"url":"javascript:..."}`
is rejected with 422, confirmed a search for words in the linked page's title
returns nothing (proving it truly is not indexed), deleted it, deleted the
account.

Deliberately out of scope for this pass: surfacing a link as a citable
reference in advice cards the way an indexed document's chunks are. That
would need matching a rule or finding's detected vendor against a link's
vendor tag and is a meaningfully bigger feature than "let someone save a
link" — worth doing later, not implied by it.

---

# Wave 12 — `/privacy` was a 404 with no link pointing at it

Found doing an SEO health check, not building a feature: `public/privacy.html`
has existed since Wave 6/7's GDPR work, but was never added to `PUBLIC_PAGES`
(§ "The crawlable surface" above), so its clean URL — the one every other
page uses, and the one `LICENSE`'s "contact licensing@rfplex.ai" text and this
document both assume works — 404s. It was only ever reachable at the literal
`/privacy.html`, which nothing links to either. **No page in the app links to
it at all** — not the footer, not `/settings`' new privacy-rights section,
nowhere — so before this fix the notice was undiscoverable by URL guessing
alone, which fails GDPR Art. 12/13's "easily accessible" requirement on its
own terms regardless of the 404.

Fixed on both ends: `/privacy` added to `PUBLIC_PAGES` (so it 200s, and —
same mechanism as every other entry — is now in `sitemap.xml` automatically),
and a real `<a href="/privacy">` added to `index.html`'s footer and to
`/settings`' "Your privacy rights" section. The page has no `noindex` and was
left out of `robots.txt`'s disallow list on purpose: unlike `/app`/`/hmr`/
`/kb`/`/team`/`/settings`, it needs no session, and a privacy notice is more
GDPR-consistent findable than hidden — its own "draft, pending legal review"
banner is the appropriate caveat for a search visitor to see, not a reason to
keep it out of search entirely.

## Two more things found in the same pass, both outside the codebase

Cloudflare/DNS-level, not something a commit here can fix:

- Plain `http://hiccup.monster/` serves the full site over cleartext (a real
  200, `Server: cloudflare`) instead of redirecting to HTTPS. Cloudflare's
  "Always Use HTTPS" (SSL/TLS → Edge Certificates) is off for this zone.
- `https://www.hiccup.monster/` returns a Cloudflare 525 (SSL handshake
  failed to origin) — the tunnel's public-hostname list has the bare apex
  domain but not `www`, so Cloudflare has nothing to terminate against for
  that host.

Neither blocks anything today (nobody currently links to the `www` form or
plain `http`), but both are the kind of thing worth closing before they are
found by someone other than a self-audit.

---

# Wave 13 — Superuser management, and the adversarial review that rewrote it

`/admin/status` gains a "Users" table: every account, and a button to grant
or revoke site-admin ("superuser") status — the same `config.adminEmails`
allow-list `isSiteAdmin()` already gated every `/admin/*` route on. New
surface: `GET /api/admin/users`, `PATCH /api/admin/users/:id
{superuser:true|false}`, both `requireSiteAdmin`-gated; `lib/auth.js` gained
`findUserById()` and `listUsers()` (both reuse the existing `_publicUser()`
projection, so neither leaks `passwordHash`/`googleSub`).

The first version's grant/revoke logic lived inline in the HTTP handler and
looked correct — 12 manual HTTP tests passed, including the last-superuser
guard. All 12 exercised the same clean state: exactly one real admin, no
stale entries. **Granting admin rights is exactly the kind of change that
deserves adversarial review before shipping**, so before committing it went
to an independent agent briefed to find a way to break it. It found five real
bugs, all invisible on the happy path:

1. **Deleting an account never pruned it from `config.adminEmails`.**
   Promote someone → they exercise `DELETE /api/me` (their own GDPR erasure
   right) → the email is free → anyone re-registers that exact address →
   `isSiteAdmin()` matches the allow-list → instant site admin, no password
   guessing required. The only genuinely remote, unauthenticated finding —
   two ordinary in-app actions chained into a privilege-escalation path.
2. **The last-admin guard counted list *entries*, not live accounts.**
   `allow.length <= 1` passes even when one of those entries is a stale email
   with no account behind it (the shipped default seed, on a deployment where
   that account was never created, being the obvious real-world case) — so
   the guard could wave through removing the only admin who actually exists.
3. **A role-fallback admin locked themselves out by promoting someone else.**
   `isSiteAdmin()` falls back to `role:'admin'` ("whoever signed up first")
   only while `config.adminEmails` is empty; the first grant made the list
   non-empty with only the *target* in it. One click on "Make superuser"
   handed away the whole panel and locked the actor out, with no recovery
   short of a hand-edit.
4. **Revoke could report success while access was completely unchanged** —
   same empty-list root cause as #3 (nothing to remove from an empty list, so
   both branches were skipped and the handler returned `200 {ok:true}`), plus
   a duplicate-entry variant (`splice` only removes the *first* match) that
   the API itself cannot currently produce but a hand-edited `config.json`
   could.
5. **No rollback if the disk write failed.** `config.adminEmails` was mutated
   *before* `store.saveJson()` was even attempted — a failed save left the
   live authorization gate (every later `isSiteAdmin()` call reads that same
   object) out of sync with what a restart would actually load from disk, in
   either direction.

## The fix: pull the logic out where it can be tested at all

`server.js` cannot be unit tested — no `module.exports`, and it calls
`.listen()` at module scope. That is exactly why the buggy version's rules
never had a test written against them: there was nowhere to put one. The fix
extracts every rule above into `lib/adminlist.js` — `applyChange()` and
`pruneEmail()`, pure functions with no `config`/`res`/disk access — so
`test/selftest.js` can pin all five regressions down directly (9 new cases).
`handleAdminUserSet` is now a thin wrapper: normalize the request, call
`applyChange()`, and on success snapshot-then-swap `config.adminEmails` with
a rollback in the `catch` (closes #5). `handleMeDelete` now calls
`pruneEmail()` after a successful account deletion (closes #1) —
deliberately **never refusing**, even for the sole remaining admin's own
account: GDPR erasure is the account holder's right regardless of admin
status, and the alternative (refuse deletion) just re-creates the exact
reclaimable-phantom-slot bug this exists to close. `applyChange()`'s guard
now takes an `accountExists()` predicate and counts *live* entries (closes
#2), and grants while the list is empty seed the actor's own email alongside
the target (closes #3), while revokes while the list is empty are refused
outright with an explanatory error rather than silently no-op-ing (closes #4).
Also added: an Origin check matching `handleServerControl`'s existing
pattern (granting site-admin is at least as consequential as restarting the
process), and a `console.log` audit line — there was no record of who
changed anyone's admin status before this.

Re-verified end to end on an isolated `HICCUP_DATA_DIR` instance after the
rewrite, including the exact exploit chain from finding #1: promote a test
account → confirm real admin access via that account's own session → have it
delete itself → confirm its email is gone from `config.adminEmails` →
re-register the same email as a fresh account → confirm the new account gets
a 403, not the inherited access the first version would have granted.

## One finding NOT fixed here, on purpose

The review also flagged (PLAUSIBLE, not reproduced) that `lib/store.js`'s
`saveJson()` — the atomic-write helper *every* persisted file in this app
goes through, not just `config.json` — can, on the Windows
EEXIST/EPERM-then-retry path, `unlinkSync` the real target before the retry,
and if the retry also fails, the target is gone with nothing written in its
place. Real, and worth fixing, but it is foundational code every other
`saveJson()` caller in the app depends on — rewriting its failure handling
belongs in its own careful, dedicated pass with its own tests, not bundled
into an unrelated feature commit under review-driven time pressure.

---

# Wave 14 — Free vs. paid accounts: team participation is a paid feature

Adds `plan: 'free'|'paid'` to the user record (`lib/auth.js`) — a free
account cannot create or join a team; a paid account can be a team owner,
admin or member. This turned out to be a small addition on top of a lot that
already existed: the owner/admin/member role system, suspend, remove and
invite were all already fully built in `lib/teams.js` (see Wave 3) — the only
gap was that **anyone** could create or join a team regardless of plan.

## Where the gate lives, and why

`_isPaid(user)` and the two call sites live in `lib/teams.js`, not
`server.js` — `teams.js` already reads user records directly (`_userById`/
`_userByEmail`, used for `acceptInvite`'s identity verification), so this is
one more field on an existing read, not new coupling. `createTeam()` checks
it first, before name validation. `acceptInvite()` checks it **after**
resolving `userId` (all three branches — already-authenticated, existing
account + password, brand-new account) but **before** the invite token is
consumed or the membership is created.

That ordering is deliberate for branch 3 (a brand-new email): the account is
created either way — a real, working login — but is refused team membership
if not paid. The token is **not consumed** on refusal, so the identical
invite link works once the person subscribes and reopens it. The alternative
(refuse to create the account at all until paid) would mean a genuinely new
invitee has no way to even sign up to look at the product before paying,
which defeats the point of an invite.

## Granting 'paid' — no payment gateway, so it's a manual admin action

There is no billing integration (see Wave 15's payment page). `PATCH
/api/admin/users/:id` — the same endpoint Wave 13 built for granting
superuser — now also accepts `{plan: 'free'|'paid'}` as an independent
optional field, same shape as `PATCH /api/team/members/:userId` already
accepting `{role}` and `{suspended}` independently. The `/admin/status`
Users table gained a Plan column and a Set paid/Set free button next to the
existing superuser toggle. In practice: someone pays via Buy Me a Coffee,
the site admin matches the payment to an account by email in this table and
flips it.

## Existing tests, not new bugs

`test/selftest.js`'s wave-3 suite predates this feature and creates its test
users via a `mkUser()` helper that never set `plan`, so — correctly —
`createTeam`/`acceptInvite` started refusing them the moment the gate shipped
(25 cascading failures on the first run, all from that one root cause).
`mkUser()` now grants `plan:'paid'` immediately after creation: this suite is
about team ROLE mechanics, not the paid gate, so its fixtures being paid by
construction is correct — the gate itself gets its own dedicated tests. The
one test that could not just get a `setUserPlan` call and move on was branch
3's "brand-new email" case, since the whole point of that branch is an
account that does not exist until the call itself creates it; it is now two
tests — the first captures the invite token and asserts the refusal (account
created, not joined, token still valid), the second marks that same account
paid and reuses the **identical** captured token to prove nothing was wasted
by the refusal. Two more new tests cover the negative case directly: a fresh
free account is refused on both `createTeam` and `acceptInvite` (branch 1),
each confirming the invite survives the refusal and a same-token retry
succeeds once paid.

---

# Wave 15 — `/subscribe`, and a `plan`-dropping bug the page itself caught

`/subscribe`: two pricing cards (€20/mo, €200/yr — "two months free" framing)
linking out to `https://buymeacoffee.com/mcfadyen`, with numbered
instructions for the fully-manual match-a-payment-to-an-account flow Wave 14
built the admin side of. Deliberately not a checkout integration — hiccup's
own Buy Me a Coffee page (checked live) turned out to have no configured
Membership tiers, only the generic one-off/monthly-checkbox widget, so the
honest, working thing to ship is a plain link with clear instructions rather
than tier URLs that do not exist. The page explains this rather than hiding
it ("How this works, for now") — a solo-built tool with a manual upgrade step
for now is a fact about the product, not an embarrassment to smooth over.

If signed in, the page fetches `/api/me` and shows the account's current
plan — "already on the paid plan" or "currently on the free plan" — so nobody
pays twice or wonders why team creation still fails right after paying.
Best-effort only: the fetch is not required to succeed for the page to work,
since most of its traffic is signed-out visitors reached from the marketing
site before they have an account at all.

`team.html`'s "Create your team" form gained a one-line note with a link to
`/subscribe`, since that is exactly where a free user hits the paid wall
Wave 14 built.

## A real bug the personalisation caught immediately

First load showed Gavin's own (already-paid, per Wave 14) account as "on the
free plan." `server.js` turned out to have its own `sanitizeUser()` —
separate from `lib/auth.js`'s `_publicUser()`, used by `GET /api/me`, the
GDPR export, and the signup/login response — that predates the `plan` field
and never picked it up. Every client-facing user object in the app has been
silently missing `plan` since Wave 14 shipped; `/admin/status`'s Users table
was unaffected only because it reads `auth.listUsers()` directly rather than
going through this function. Fixed with the same default-to-`'free'` rule
`_publicUser()` uses. Caught by loading the page and looking, the same
lesson as every other live-verification catch this session: the diff looked
correct, and was not.

## `subscribe.html`'s own translation lessons

Two, both direct repeats of earlier mistakes in this file, worth naming so
they stop repeating:

- A `<li>` mixed prose with `<strong>€20</strong>` / `<strong>"Make this
  monthly"</strong>` fragments. `data-i18n` on a parent with mixed inline
  children extracts each direct text-node fragment separately (Wave 8) —
  "Enter", "and tick", "for the monthly plan, or" became four disconnected,
  context-free translation units instead of one sentence. Fixed by dropping
  the inline emphasis and writing it as one plain sentence; the amounts are
  already prominent on the pricing cards above.
- The page's own `<script>` (fetch `/api/me`, personalise the status line)
  was inline, which — same as `settings.html`'s inline script before Wave 10
  — is invisible to `scanHtml()`'s extraction on purpose (Wave 8) and would
  have left "You are already on the paid plan…" English-only on a page whose
  whole audience is signed-out and signed-in real users, not an admin. Moved
  to `subscribe.js` before it ever shipped translated.

`"Make this monthly"` stays in English inside every language's translation,
quoted, on purpose: it is the literal label on Buy Me a Coffee's own
checkbox, which is not translated by hiccup — translating hiccup's
*reference* to that label would describe a control the visitor cannot
actually find on the page they are about to land on.

# Wave 16 — the landing page actually sells the product

`index.html` shipped three feature cards (two-leg diff, retransmission
classifier, SIP↔H.323 correlation) and nothing else: no mention of the
advisor engine, no Diameter, no HMR, no config-guide KB, and no path from
"this looks useful" to a paid team account. Meanwhile `lib/diameter.js`,
`lib/hmr.js` and `lib/kb.js` are all real, shipped, tested features that the
front door never mentioned. Fixed by expanding the page rather than
replacing it — same hero, same auth card, same SIP-reference teaser and
footer, all still true and all still working.

**Verified before writing a word of marketing copy** (a claim on a landing
page is a claim, not vibes): grepped `lib/diameter.js` for its actual scope
— Rx/Gx/Cx/Sh AVP decode, cross-protocol correlation specifically via
AF-Charging-Identifier / the SIP `P-Charging-Vector` icid, not "full Diameter
support" — and read `lib/hmr.js`'s header comment for what the header-rule
explainer actually does (parses Oracle/Acme `sip-manipulation`, AudioCodes
`.ini` MessageManipulations, Ribbon SMM rule text; explains intent, checks
correctness, cites RFCs, matches configured rules against what a capture
actually shows). Both claims on the page now trace to code, not hope.

**New content**:
- Three new feature cards — automatic fault detection (the advisor rule
  engine, RFC-cited, severity-ranked), multi-protocol correlation (the old
  H.323 card's copy folded in with Diameter, both named precisely as above),
  header-rule explainer (HMR), your own config guides (`lib/kb.js`). Grid
  went from a fixed 3-column layout to `repeat(auto-fit, minmax(230px,
  1fr))` so six cards wrap 3×2 without a media-query rewrite.
- A "how it works" section: three numbered steps (upload → get a diagnosis →
  fix it or hand it off), deliberately *not* styled as cards — it is a
  sequence, and dressing a sequence up as a set of independent facts (like
  `.features`) would misrepresent it.
- An enterprise/teams promo card between the auth card and the SIP-reference
  teaser: who it's for, three bullets, and the €20/€200 price reused
  verbatim from `/subscribe`'s already-translated " / month" / " / year" /
  "See plans →" strings rather than re-authoring (and re-translating) the
  same numbers a second time. This card's job is "who this is for and why
  paid exists at all" — `/subscribe` still owns "which plan and how to pay".
  It does not duplicate `/subscribe`'s pricing cards.
- Hero sub-copy and the JSON-LD `featureList`/`applicationSubCategory`/
  descriptions updated to match — the structured data a crawler reads should
  claim the same things the page itself claims.

**What deliberately stayed out**: no mention that RFPlex.ai holds LLM/GPU
priority over hiccup's own shared Ollama instance (`lib/kb.js`'s "an
embedding model would compete with RFPlex for the GPU, which the LLM
contract forbids") — true, load-bearing, and entirely an operational detail
between two projects on the same box. A visitor evaluating hiccup has no
use for it and no way to act on it; it would only read as hiccup being
second-class to something else, which is not the pitch.

## Wave 16a — free-tier framing, the NL→HMR card, and an English-only feature

A follow-up pass on the same page:

- Dropped the `two-leg diff + delta view` and `retransmission classifier`
  cards. They were the two survivors of the pre-marketing page and the only
  two not on the brief's promote-list; they were also the most jargon-dense
  copy on the page ("100rel asymmetry", "session-timer conflicts", "UDP
  fragmentation"). Both capabilities still exist and still ship — they are
  simply not what the front door leads with. `how it works` step 2 still
  names the two-leg diff, so the capability is not invisible.
- Added a `describe it, get the config` card for `lib/hmr-generate.js`
  (`POST /api/hmr/generate`), which was shipped and routed but had never been
  mentioned on the public site.
- Made "free for individual users" a hero pill rather than a line of body
  copy, with a clarifying note that paid exists only for teams. The auth
  card's chip changed `free while in beta` → `free for individuals`: the beta
  framing implied the free tier expires, which undercuts the exact message
  the pill is there to deliver, and nothing in the code expires it.
- `offers` in the JSON-LD went from a single free Offer to an array of three
  (Individual 0, Team monthly 20, Team annual 200) so the structured data
  describes the tiers that now actually exist.
- Grid went back to a fixed `repeat(3, 1fr)` (plus a 2-col break at 900px).
  With five cards, `auto-fit` pulled four onto row one on wide viewports and
  left a single orphan; fixed 3 wraps to a deliberate-looking 3 + 2.

**The English-only catch.** The obvious copy for the new card was "describe
the change in plain language". That would have been a lie in three of the
four languages hiccup ships. `lib/hmr-generate.js`'s intent detection is
English regexes — `/\b(strip|remove|delete|drop|get rid of|take out)\b/`
(:232), `/\b(add|insert|set|stamp|put)\b/` (:261) — and its clarifying
questions are hardcoded English (:401). There is no locale awareness in the
module at all. A French visitor reading "décrivez en langage courant" would
type French and get questions back, every time.

So the source string says "plain **English**", and each translation says so
explicitly ("en anglais courant", "en inglés sencillo", "in einfachem
Englisch"). The quoted example stays untranslated for the same reason
`"Make this monthly"` does on `/subscribe` (Wave 15): it is literal text the
user types into a box, not prose about the product. Marketing copy is a
claim about behaviour — it gets checked against the module that implements
it, not against what would read best.

**Translation**: 22 new strings, all fr/es/de, zero fragmentation — checked
the missing-string list *before* translating this time (a script comparing
`locales/en.json`'s hash-keyed catalogue against each language's
text-keyed file), rather than discovering a split `<strong>` after the fact
as happened twice already in this file. All 22 came back as complete
sentences or short noun phrases, none as orphaned fragments. Verified live
on an isolated `HICCUP_DATA_DIR` instance in both English and French —
switching the language selector re-rendered all six cards, the three-step
flow and the enterprise card with no overflow, no layout break, and no
untranslated leftover text.

# Wave 17 — v0.3.0: the four things the audit said were worst

A 13-agent audit ranked what was outstanding; this wave clears the top four.

## 1. `lib/textlog.js` no longer swallows messages

The body loop broke only on `bytes >= cl`, so a `Content-Length` larger than
the body actually captured — routine in truncated `sipmsg.log` exports and
elided SDP — consumed the entire rest of the file as one body. Three valid
messages parsed as one, `warnings: []`. Silent, and against this document's
own "skip with a warning" contract.

The body now also stops at a `SEPARATOR` or an `isStartLine` — the module's
**existing** predicates, deliberately not a second notion of "a message starts
here" — and records `line N: declared Content-Length 9999 exceeds captured
body (308 bytes) — body truncated at the next message boundary`.

One deliberate exception: when `Content-Type` is `message/sipfrag` or
`multipart/*`, start lines do **not** bound the body. RFC 3420 has a REFER's
NOTIFY carry a literal `SIP/2.0 200 OK` as its whole body, so without this
every call-transfer trace — core to this product's domain — would shred into a
body-less NOTIFY plus a phantom message.

The two RFC 4475 start-line misses went with it. `REQ_LINE` now accepts RFC
3261's real `token` charset (so `RE%47IST%45R` matches) and any
`SIP/<digits>.<digits>` (so `SIP/7.0` is recognised); `STATUS_LINE` accepts a
1–10 digit code. Four brakes keep that from over-matching: the method must
start uppercase with no lowercase and no `:`; the Request-URI must contain a
`:` (a scheme), which is what kills the realistic false positive `RETRANSMIT
INVITE SIP/2.0` — a shape the *old* regex would have matched; both stay
anchored `^…$`; and every digit run is bounded. One deliberate narrowing: a
scheme-less Request-URI is no longer recognised. `sniffText`'s hand-copied
patterns are now built from the same sources, so the sniff can never tell
`analyze.js` "not SIP" about a file the parser would happily read.

**Measured:** `rfc4475-torture.txt` 10 → 19 messages, one warning. Shipped
fixtures unchanged (`sbc-log.txt` 14, `raw-messages.txt` 7, zero warnings).

Known follow-up, not done: `topVia()` still hardcodes `SIP/2.0`, so a
`SIP/7.0` message is now recognised but its Via is not parsed and `src`/`dst`
fall back to `unknown-a`/`unknown-b`. Pre-existing, but reachable more often
now.

## 2. Team exit, and recovering a team whose owner vanished

`handleMeDelete` called `removeMember(user.id, user.id)` under a comment
claiming "removing yourself is a leave". `removeMember` refuses a plain member
*and* refuses acting on yourself, so it **always threw**; a bare `catch {}`
swallowed it and the account was deleted anyway — leaving a member row
pointing at a user that no longer existed, still counting against
`MAX_TEAM_MEMBERS` and rendering as a raw hex id.

Worse, and found while fixing it: `solo` is `uid === user.id`, and a team's
`dataRootId` **is** the founding owner's user id. So an owner deleting their
account read as "solo" and fell into the capture-erase loop — **destroying the
whole team's shared library**. The shared-data hazard note in that function
protected ordinary members and never covered the owner. The ownership check
now runs *before* anything is erased, so the refusal is a clean 409 rather
than an account that survives with its team's captures already gone.

New in `lib/teams.js`:

- `leaveTeam(userId)` — the operation that never existed. An owner with other
  members must transfer first; a **sole** owner leaving dissolves the team
  (plus its pending invites, which would otherwise 500 on acceptance) rather
  than trapping the last person in a team they cannot leave.
- `getRecoveryState(userId)` / `claimOwnership(userId)` — a member can take
  over a team whose owner is **orphaned** (account gone: no wait) or
  **dormant** (no sign-in for `OWNER_DORMANT_DAYS`, 90).

Why 90 days, and why this is a smaller lever than it looks: every member of a
team already reads and writes the same shared data root via `accountUid()`, so
claiming ownership grants **management** rights — invite, suspend, remove,
transfer — and *no new data access*. The realistic abuse is therefore seizing a
team whose owner is merely quiet, which the window guards. Two further rules:
a **suspended** member can never claim (they would just un-suspend
themselves — that turns a moderation action into a takeover), and while any
active admin remains, only an admin may claim, so an ordinary member cannot go
over the heads of the people the owner actually delegated to. If no admin is
left, any active member may — otherwise a team whose only admin also vanished
stays stuck, which is the failure this exists to fix.

`dataRootId` is never touched, exactly as in `transferOwnership`, and a
still-existing old owner is demoted to **admin** rather than removed: someone
back from a long absence finds themselves demoted, not locked out.

Eligibility lives entirely in `getRecoveryState`, and the UI renders that
answer rather than re-deriving it, so the banner and the enforced rule cannot
drift apart. `/team` also finally grows the **Leave** and **Transfer
ownership** controls — the transfer API had existed since Wave 3 with nothing
in the UI able to call it, and two places in the app told users to "leave the
team" when no such control existed.

## 3. Rate limiting and security headers

Login is limited on **two** axes because either alone leaves a hole: per-email
(8 / 15 min) stops a focused attack on one known account from a botnet,
per-IP (30 / 15 min) stops a spray across many accounts from one host. Signup
is 5 / hour / IP. Checks use `peek` so a successful sign-in never spends the
budget — only failures are recorded. The 429 wording is **identical** whichever
limiter trips, since saying which one would tell an attacker they had found a
real account.

`clientIp()` prefers `CF-Connecting-IP`: the process binds `127.0.0.1` behind
a Cloudflare tunnel, so `remoteAddress` is always loopback and useless. That
header is trustworthy *here* precisely because no internet client can reach
the socket directly to forge it — an assumption that dies if this is ever
bound to a public interface, and which is written down at the function.

Security headers are set once at the request entry rather than in each
response helper, so an error path cannot miss them: `nosniff`,
`X-Frame-Options: DENY` (nothing here is ever legitimately framed, and
`/admin/status` hosts the superuser control and the restart button),
`Referrer-Policy`, HSTS (not preloaded — that is irreversible and the site
owner's call), and a `Permissions-Policy` denying camera/mic/geolocation.

**No CSP yet, deliberately rather than by omission:** `index.html`, the
workbench host page and `admin-status.html` all carry inline `<script>`, and
the landing page loads Google Identity Services. A CSP strict enough to be
worth having breaks all of them today, and one with `'unsafe-inline'` is
decoration. It needs the inline scripts lifted into files first.

**Not done: async scrypt.** `scryptSync` still blocks the event loop ~20ms per
attempt. Making it async forces `createUser` async, which forces
`acceptInvite` async, which forces its whole call chain async — a cross-cutting
refactor of the auth core, landing in the same release as the team-ownership
changes above. Rate limiting removes the *volume* that made the blocking
matter; doing both at once is how a subtle auth bug ships.

## 4. `server.js` is testable, and `test/http.js` exists

`server.listen()` at module scope with no `require.main` guard meant requiring
the file bound a port and armed three timers, so 43 API routes and 17 page
routes had **zero** coverage. That is not abstract: `/subscribe` 404'd in
production for four and a half hours because `public/` is served live from the
working tree while `server.js` only changes on restart, and nothing asserted
that a page in `PUBLIC_PAGES` resolves.

`start()` is now guarded and the module exports `{server, start, handle, …}`.
`test/http.js` spawns `server.js` as a **child process** — not an in-process
require, because a child is what production runs and it proves boot, config
load and route wiring — against a scratch `HICCUP_DATA_DIR` and port, then
asserts over real HTTP: every page route resolves, gated routes answer **401
not 404** (a 404 is indistinguishable from "not deployed"), security headers
are present, signup→`/api/me` carries `plan` (it was silently dropped once),
a free account cannot create a team, and the rate limiter trips with an
identical message for a real and an unknown address.

`npm test` now runs both suites. **112 selftest + 10 HTTP.**
