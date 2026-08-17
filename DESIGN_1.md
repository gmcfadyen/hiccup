# SIP Trace Analyser — Design Brief

Working notes for the build. Drop this in the repo root so it's in context every session.

## What this is

A web-based SIP trace / pcap reader aimed at an **SBC-curious** audience: engineers who
work around SBCs and want to understand what they're looking at, not just see a ladder
diagram. First user is me — build what makes me faster on real captures, not what a
hypothetical customer might want.

**Non-goals for v1:** multi-tenancy, ticketing integrations, fingerprint clustering,
billing, auth beyond the minimum. All of that is downstream and none of it is needed to
make the tool useful or to demo it.

## Positioning vs what exists

- `sngrep` — live terminal monitoring
- Wireshark — offline pcap, VoIP call flows, but the diff work is manual
- HOMER / heplify — scalable capture and storage, HEP-based
- VoIPmonitor, SIPFlow, SIP Workbench — capture + ladder diagrams
- Oracle Session Monitor — vendor-side, expensive
- SIPSymposium — closest competitor; browser-based, AI interpretation, claims
  multi-endpoint correlation

Gap worth aiming at: **two-leg SBC correlation with an explicit delta view**, plus
vendor-specific interpretation. Ingesting the SBC config alongside the trace is the
thing that would separate this from SIPSymposium.

## Core feature 1 — Two-leg correlation

Pair ingress and egress dialogs across the B2BUA. Heuristic, needs confidence scoring
and an explicit "ambiguous" state rather than a wrong guess.

Correlation signals, roughly in order of strength:

1. Vendor-inserted correlation headers (X-headers, `P-Charging-Vector` icid-value)
2. SDP `o=` session ID / version
3. Temporal proximity — egress INVITE follows ingress INVITE by low ms
4. To/From user parts that survive manipulation
5. Contact / Via rewrite patterns consistent with the SBC's topology hiding

Near-100% on single-call captures. Degrades on busy trunks with repeated numbers —
hence the confidence score. Do not silently pick the best match.

## Core feature 2 — The diff engine

Once legs are paired, emit a structured delta. This is the actual product; nobody enjoys
eyeballing two 200-line INVITEs side by side.

Categories to detect and surface:

- **Headers**: added / stripped / rewritten by the SBC
- **SDP**: codec list in vs out, forced transcoding, ptime mismatch
- **DTMF**: telephone-event payload type mismatch (101 vs 96 is perennial)
- **Reliability**: 100rel / PRACK asymmetry between legs
- **Session timers**: refresher direction, Min-SE vs Session-Expires conflicts
- **Early media**: 183+SDP vs 180, media before 200 OK
- **Transport**: UDP message >~1300 bytes → fragmentation risk
- **Topology**: private IPs leaking through topology hiding
- **T.38**: re-INVITE handling differences across legs

## Core feature 3 — Retransmission classifier

Detection is deterministic (same Via branch, CSeq, method, byte-identical payload, RFC
3261 timer intervals). Two jobs beyond detection:

**Collapse** — seven INVITEs become one row: `INVITE ×7, no response, abandoned at 32s
(Timer B)`. This alone makes ladders readable.

**Classify** — the pattern is diagnostic. Finite set:

| Pattern | Likely cause |
|---|---|
| INVITE ×7, no 100 Trying at all | Never arrived — ACL, firewall, source IP not whitelisted, dropped pre-classification |
| Retransmits then a late response | Far end slower than T1. Often blocking DNS (SRV/NAPTR) on egress, not congestion |
| Message >1300 bytes, no response | UDP fragmentation, fragments dropped upstream. Bloated SDP or History-Info |
| 200 OK retransmitting | ACK not landing — Contact or Record-Route unreachable after topology hiding |
| Retransmits clustered across many concurrent dialogs, same timestamp | Not the call, the box. Licence exhaustion, CPU, session-agent unreachable |

That last one needs an aggregate time-series view, not a per-call view. Distinguishing
"this call is broken" from "the SBC is melting" is a differentiator — most tools can't.

To separate slow-far-end from blocking-DNS: check whether the delay is consistent across
all calls or specific to a destination.

## Core feature 4 — IMS conformance checking

IMS is *specified* (3GPP 24.229), so this is conformance checking rather than guessing.
Public, stable corpus — unlike vendor parameter names which drift every release.

Recognise node roles from signalling alone:

- `Path` and `Service-Route` in REGISTER
- `P-Associated-URI`
- Third-party REGISTER to the AS
- `sip:orig` in the Route set
- `P-Charging-Vector` icid-value threading a session across nodes
- Preconditions: `a=curr` / `a=des` / `a=conf` through 183 / PRACK / UPDATE
- `P-Early-Media`

Flag violations directly: missing Service-Route in the 200 OK, `P-Access-Network-Info`
surviving in the wrong direction, preconditions requested but never confirmed.

**Hard part:** a single capture point sees the same INVITE loop through the S-CSCF three
or four times as the iFC chain fires. Correlating those passes into one session view is
what an engineer actually wants. Use Call-ID + Route set + orig/term markers.

**Stretch:** if the capture includes Diameter, tie an INVITE to its Rx AAR for the
dedicated bearer. Almost nobody does cross-protocol correlation well.

**Limit:** without the operator's iFC config you can describe what happened but not
whether it was intended. Gm leg is usually IPsec-protected, so you work from P-CSCF inward.

## Core feature 5 — Header manipulation IR + vendor renderers

Three vendors express the same idea in different dialects. The **intermediate
representation is the asset**; translation is then a rendering problem.

IR shape:

```
scope     → request|response, method
condition → element + comparison + match value
target    → header / element path (e.g. from.uri.user)
operation → add | delete | modify | store
value     → literal or expression
```

Renderers:

- **Oracle / Acme**: `sip-manipulation` → `header-rule` → `element-rule`; actions
  add/delete/manipulate/store; bound via `in-manipulationid` / `out-manipulationid` on
  session-agent, sip-interface or realm
- **AudioCodes**: Message Manipulations table — condition, action subject
  (`header.from.url.user`), action type, action value; grouped into a Manipulation Set,
  bound to IP Profile or IP Group
- **Ribbon**: SMM rules — criterion / token / operation; bound inbound or outbound on a
  Signaling Group

**Translates roughly** (concepts align, precedence and defaults don't): codec handling
(media-profile / codec-policy vs Coder Groups vs Media Lists), session timers, OPTIONS
keepalive.

**Does not translate at all** — do not promise whole-config migration:
- Topology model. Acme is realm-centric; AudioCodes is IP-Group-centric; Ribbon routes
  and manipulates numbers together in Transformation Tables
- HA, licensing, steering pools, TLS/SRTP profiles
- Vendor escape hatches — Acme SPL has no equivalent anywhere

Rule-level translation only. Output reviewable drafts, never applied config.

**Maintenance reality:** parameter names drift across SCX versions, AudioCodes 7.2→7.4,
Ribbon releases. Design for user-submitted corrections from day one — the audience will
spot errors faster than I can test for them.

## Architecture constraints

- **Privacy is structural, not optional.** Traces contain phone numbers, IPs, and Digest
  credentials. No enterprise uploads carrier captures to someone else's SaaS. Self-hosted
  with local inference is the requirement — same shape as RFPlex.
- Cloud-first competitors structurally can't follow into on-prem. That's the defensible
  position.
- TLS signalling means SBC-side or HEP capture, not a SPAN port. Assume the user supplies
  a decrypted or SBC-sourced capture.
- Consider a redaction pass on ingest regardless (numbers, Digest, credentials).

## Build order

1. pcap ingest + parse + basic ladder rendering
2. Two-leg correlation with confidence scoring
3. Diff view — this is where the value first becomes obvious
4. Retransmission collapse, then classification
5. Config ingest (Acme running-config, AudioCodes ini, Ribbon export) → attach findings
   to actual realms / IP Profiles / Signaling Groups
6. Header manipulation IR + three renderers
7. IMS conformance layer

Ship 1–4 publicly and free. That's the credential and the funnel.

## Open questions

- Config ingest roughly doubles diagnostic accuracy — worth pulling earlier than step 5?
- Free trace reader hosted publicly vs self-host-only from the start? Hosted is better for
  reach; conflicts with the privacy positioning. Possibly: hosted with aggressive
  client-side redaction and a documented self-host path.
- Do I need my own capture corpus for testing, and where does it come from?
