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
rendering helpers loaded by app.html), `logo.svg`.

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
