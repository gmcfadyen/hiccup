# Getting a trace hiccup can actually read

**Status: documentation only.** Nothing on this page is a hiccup feature. hiccup does not
decrypt anything — not TLS, not SRTP, not IPsec — and this document does not promise that
it ever will. These are suggestions for getting *plaintext signalling in front of the
tool*, written from the assumption in `DESIGN_1.md`: *"TLS signalling means SBC-side or
HEP capture, not a SPAN port. Assume the user supplies a decrypted or SBC-sourced
capture."*

If you have taken a SPAN of a TLS trunk and are wondering how to open it in hiccup: you
probably cannot, and the fix is almost always to capture somewhere else rather than to
attack the crypto. Section 1 is the answer most of the time.

---

## The short version

| What you have | Realistic path | Works? |
|---|---|---|
| SBC or softswitch you administer | Its own SIP message log / debug recording — already plaintext | **Yes, best path** |
| Endpoint or proxy you administer (Asterisk, FreeSWITCH, Kamailio) | Its SIP trace log | **Yes** |
| SPAN/TAP of SIP over TLS, client you control the build of | `SSLKEYLOGFILE` + Wireshark keylog, then export the decrypted stream as text | Sometimes |
| SPAN/TAP of SIP over TLS, appliances or hardware phones | — | **Usually not** |
| SPAN/TAP of TLS + the server's RSA private key | Only if the handshake used static RSA (not TLS 1.3, not ECDHE) | **Almost never** |
| SRTP with SDES keying | Decrypted signalling gives you the key from `a=crypto` | Yes, once you have the signalling |
| DTLS-SRTP (WebRTC) | Needs a keylog from an endpoint that writes one (browsers do) | Sometimes |
| ZRTP / MIKEY-RSA media | Passive decryption is not possible by design | **No** |
| IMS Gm leg (UE ↔ P-CSCF, IPsec) | Capture from the P-CSCF inward instead | Work around it |

---

## 1. The best path: capture where it is already plaintext

A B2BUA decrypts every message it processes. Its own logs are therefore
post-decryption, and they are the highest-value trace you can get: they show what the box
*believed* it received and sent, which is exactly what a two-leg diff needs. hiccup was
built around this: the `acme-log`, `sngrep` and `raw-sip` text ingests exist precisely so
that a log export drops straight in, with no pcap involved.

**Oracle / Acme Packet (SBC, SCX).** The one you want is `sipmsg.log` — SIP signalling as
sipd handled it, both legs, with `received from` / `sent to` framing. That is the format
hiccup's Acme parser was written against, including the case where both legs of one call
interleave in a single file. Enable SIP message logging (a per-process log level on
`sipd`; the exact ACLI wording moves between SCX releases, so check the Maintenance and
Troubleshooting guide for yours), reproduce the call, then pull the file off the box.
`packet-trace` / the on-box packet capture also exist, but note the distinction: a packet
capture of a TLS interface gives you ciphertext, whereas `sipmsg.log` gives you plaintext.
Prefer the log.

**AudioCodes.** Two useful sources. Syslog at a detailed debug level prints SIP messages
as the gateway processed them — plaintext, and close enough to a bare-SIP dump that
hiccup's text ingest handles it. Debug Recording (DR) streams internal traffic to a
Wireshark host and needs AudioCodes' DR dissector plugin to read; it includes decrypted
SIP, which is its main attraction. PacketSMART, where you have it, is a capture appliance
and gives you pcap from a point of your choosing. Names and menu locations differ between
7.2 and 7.4 — the concepts do not.

**Ribbon.** The SBC Core / SWe boxes have their own packet-capture facility and process
logs (the signalling front-end / signalling gateway debug logs) that record SIP as
handled, i.e. after TLS termination. Where a lawful-intercept or SIPREC feed already
exists for the trunk in question, that is also plaintext by construction — but see
section 5 before you go anywhere near an LI feed.

**SIPREC (RFC 7865 / 7866).** A session-recording feed carries the signalling metadata in
clear, and it is often already provisioned on the trunk you care about. Worth asking the
recording team before you build anything.

**HEP / Homer (captagent, heplify).** HEP taps sit *inside* the application, so what they
capture is what the application saw — decrypted. If your platform already ships HEP to a
Homer instance, that is a plaintext source you own. hiccup does not read HEP or connect
to Homer today; you would export the messages from Homer as text and use the `raw-sip`
ingest.

**Open-source proxies and PBXs**, all of which log plaintext SIP regardless of the
transport used on the wire:

- Asterisk: `pjsip set logger on` (or `sip set debug on` for `chan_sip`).
- FreeSWITCH: `sofia global siptrace on`.
- Kamailio / OpenSIPS: the `siptrace` module (to file, to a database, or as HEP).

Paste the resulting messages into a `.txt` and hiccup's bare-SIP ingest will take it;
addresses missing from the log are synthesised from the topmost `Via`, so the ladder still
has columns, and the analysis (correlation, diff, retransmission classification) works on
the messages themselves.

**A note on fidelity.** A log is not a wire capture. You lose exact on-wire byte sizes and
IP fragmentation, which are the evidence for hiccup's `udp-frag-risk` and
`udp-fragmentation` verdicts, and you usually lose the media entirely so there are no RTP
statistics. If your question is "why did this INVITE retransmit", a log is fine. If your
question is "is my 1450-byte INVITE being dropped by the path MTU", you need the pcap.

---

## 2. SIP over TLS

### The pre-master-secret log (the only route that generally works)

TLS session keys can be written out by the endpoint as they are negotiated, into a
"keylog" file in NSS format. Wireshark then reads that file and decrypts the capture.
This is the standard technique and it is well supported:

- Wireshark: *Preferences → Protocols → TLS → "(Pre)-Master-Secret log filename"*.
- tshark: `-o tls.keylog_file:C:\path\keys.txt`.

The catch is entirely on the endpoint side. **A TLS library does not write a keylog unless
the application asks it to.** `SSLKEYLOGFILE` is honoured by:

- Browsers (Chrome/Edge via BoringSSL, Firefox via NSS) — so WebRTC and browser softphones.
- `curl` built against OpenSSL or GnuTLS.
- Node.js (`--tls-keylog=<file>`, or the `keylog` event).
- Python 3.8+ (`SSLContext.keylog_filename`).
- Anything else whose build you control and can wire to `SSL_CTX_set_keylog_callback`.

It is **not** honoured by pjsip/pjsua, Asterisk, Kamailio, FreeSWITCH, commercial SBCs, or
hardware desk phones. If your TLS leg is between two appliances, there is no keylog to be
had and section 1 is your answer. This is the single most common dead end people hit.

Also worth knowing before you spend an afternoon on it: the capture must contain the
**full handshake** for the session you care about. A capture that starts mid-session, or
one where the session was resumed from a handshake you never captured, will not decrypt
even with correct keys. And a snaplen-clipped capture cannot be reassembled.

### Getting the decrypted SIP into hiccup

Wireshark can decrypt for display, but it cannot write a new capture in which the SIP is
plaintext. So you extract text:

- **GUI:** right-click a TLS packet → *Follow → TLS Stream*, set *Show data as: ASCII*,
  then *Save as…*. The result is concatenated plaintext SIP, which is exactly hiccup's
  `raw-sip` ingest format.
- **tshark:** `tshark -r in.pcapng -o tls.keylog_file:keys.txt -q -z follow,tls,ascii,0`
  (repeat per stream number).

Clean-up caveat, because it will silently corrupt your messages otherwise: the follow
output has a header block, `Node 0`/`Node 1` lines, and — in ASCII mode — the
server-to-client direction is **indented**. Strip the header, the node lines and the
leading indentation before feeding it in. hiccup will then synthesise src/dst from `Via`
(the follow output has no per-message addressing), so the ladder columns are inferred
rather than observed.

One route that does **not** work today: *File → Export PDUs to File* produces a pcapng
using Wireshark's Upper-PDU link type (252), and hiccup's pcap reader only handles link
types 0, 1, 101, 113, 228, 229 and 276. That export will be rejected. It is a plausible
thing for hiccup to support later (see section 6) — it is just not supported now.

### Handing over the server's private key: a dead end

The other thing people try is loading the SBC's RSA private key into Wireshark
(*Preferences → RSA Keys*). Be clear about what that can and cannot do:

- It only works for **static RSA key exchange** (`TLS_RSA_WITH_...`), where the client
  encrypts the pre-master secret to the server's public key. With forward secrecy —
  `(EC)DHE` — the private key only authenticates the handshake; it never touches the
  session keys, so it decrypts nothing.
- **TLS 1.3 removed static RSA key exchange entirely.** Every TLS 1.3 handshake is
  (EC)DHE. There is no key-file route, at all, for TLS 1.3.
- TLS 1.2 has allowed ECDHE for over a decade and it is the default nearly everywhere,
  including on every current SBC.

So: key-file decryption of modern SIP/TLS is generally impossible, and asking a customer
to hand over a production private key is a large ask that will not even pay off. Do not
build a plan around it. (The rare exception: old lab kit deliberately pinned to a
`TLS_RSA_*` cipher suite, with the whole handshake captured.)

---

## 3. SRTP

### SDES — the keys are in the signalling

With SDES (RFC 4568) the media keys travel in the SDP:

```
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:32
```

That base64 blob is the master key and salt, in the clear. Which means: **once you have
decrypted signalling, you have the media keys** — the two problems collapse into one, and
section 1 or section 2 solves both. It also means the reverse is a real finding in its own
right: SDES over a signalling leg that is not itself encrypted protects nothing, and
anyone with the trace has your media.

Decrypting the RTP itself is a separate tool problem. Wireshark's SRTP support has
historically been limited and varies by version and build, so check your own version's
release notes rather than a blog post. The dependable options are outside Wireshark:
libsrtp2's `rtp_decoder` test tool, or the small `srtp-decrypt` utility widely used in the
Homer/SIP community — both take the base64 key from `a=crypto` and a pcap, and hand you
decrypted RTP.

hiccup deliberately does not participate in any of this. Its media analyser identifies
SRTP streams (`RTP/SAVP`, `RTP/SAVPF`, or the presence of `a=crypto`), reports them as
`kind: 'srtp'`, and derives statistics **from packet headers only** — sequence numbers,
timestamps, SSRC, arrival times. Loss, jitter and gap detection all work on encrypted
media, because none of that lives in the payload. Payload-dependent things (DTMF events
from RFC 4733, codec confirmation) do not.

### DTLS-SRTP — the keylog again

With DTLS-SRTP (RFC 5764, the WebRTC default) the SRTP master keys are derived from the
DTLS handshake, so a passive observer with no keys gets nothing. The keys land in the same
`SSLKEYLOGFILE` that TLS uses, and Wireshark reads that file for DTLS too — so for
browser-based endpoints this is genuinely feasible, and for appliance-to-appliance
DTLS-SRTP it is not.

The consolation is that the most common WebRTC fault does not need decryption at all. Who
sent `ClientHello`, whether the handshake completed, which `use_srtp` profile was
negotiated, and whether the ICE connectivity checks ever succeeded are all visible in
plaintext — and that is what breaks. hiccup's STUN/ICE/DTLS analysis reports exactly those
things (handshake progression, `stalledAfter`, the negotiated SRTP profile, per-pair check
list outcomes) without any keying material, and one-way audio is usually diagnosed from
them.

### ZRTP and MIKEY

ZRTP negotiates keys directly between endpoints with nothing usable in the trace —
passive decryption is impossible by design, which is the entire point of it. MIKEY-RSA
needs the receiving endpoint's private key. Both are out of scope here; if you meet them,
go back to section 1 and capture at an endpoint that has the plaintext.

---

## 4. IMS: the Gm leg and why you start at the P-CSCF

On the 3GPP Gm interface (UE ↔ P-CSCF) the SIP signalling normally runs inside IPsec ESP,
with the security associations set up by the RFC 3329 security-agree exchange during
REGISTER and keyed from the AKA run — the integrity and cipher keys come out of the
ISIM/AUC, not out of the trace. A passive capture of Gm is therefore undecryptable in
practice. Wireshark *can* decrypt ESP if you populate its ESP SA table by hand, but that
needs someone to export the SAs, they are per-registration, and outside a lab with
known-key test USIMs nobody is going to give them to you.

So you work from the **P-CSCF inward**, which is what `DESIGN_1.md` says: the Mw legs
(P-CSCF ↔ I-CSCF ↔ S-CSCF), Mg/Mi/Mj toward the MGCF and BGCF, ISC toward the
application servers, Mb for media, and Rx toward the PCRF/PCF if you have Diameter in the
capture. Those legs are normally plaintext or at least capturable, and they are where the
interesting behaviour is anyway: iFC chains re-entering the S-CSCF, Service-Route and Path
handling, preconditions, `P-Charging-Vector` icid threading a session across nodes.

You lose less than you might think. The UE-side headers that matter —
`P-Access-Network-Info`, `P-Visited-Network-ID`, `P-Preferred-Identity`,
`sip.instance`/`+g.3gpp` feature tags — mostly survive into the network-side legs, which
is why hiccup's IMS detection is built on what those legs show. What you genuinely cannot
see from inside is the UE's own retransmission behaviour and its IPsec/SIP port
juggling; if that is the question, you need a client-side log from the UE, not a network
capture.

---

## 5. Authorisation, consent, and why hiccup redacts

**Get written authorisation before you capture, and again before you decrypt.** From the
network owner, and where you are a supplier, from the customer whose traffic it is. In
many jurisdictions intercepting the content of a communication without authority is a
criminal offence rather than a policy breach — France's Code pénal art. 226-15, the UK's
Investigatory Powers Act 2016, the US Wiretap Act (18 U.S.C. §2511) are the usual
examples. This document is not legal advice and the author is not a lawyer; if you are
being asked to decrypt someone else's calls, ask your legal team, in writing, first. If
the trace came from a lawful-intercept facility, it has its own authorisation regime and
none of the above is your call to make.

**Traces are personal data.** A SIP capture routinely contains E.164 numbers, SIP URIs,
display names, IP addresses, and — on the IMS side — IMSI/IMEI-derived identifiers and
access-network information. Under GDPR that is personal data whether or not you think of
the file as "just a pcap": purpose limitation, data minimisation and retention limits all
apply, and media captures may contain the content of the conversation itself.

This is why hiccup is shaped the way it is, and it is a deliberate design position rather
than a feature list:

- **Self-hosted, no egress.** The analysis runs on your machine; captures never leave the
  box. Inference is local (a shared Ollama), so even the chatbot does not ship your trace
  to a third party.
- **Digest credentials are redacted unconditionally on ingest.** The `response` and
  `cnonce` values and any `Authorization` / `Proxy-Authorization` credential parameters
  are replaced with `REDACTED` in both the stored raw text and the parsed headers, before
  anything is written to disk. The selftest asserts that a known Digest response value
  cannot be found anywhere in the stored analysis.
- **Number masking is available on request** (`redactNumbers`), middle-masking digits in
  URI user parts and display names.
- **Deletion is real.** `DELETE /api/captures/:id` removes the stored original bytes and
  the analysis together.

**Treat keylogs and exported SAs as secrets with a bigger blast radius than the trace.**
An `SSLKEYLOGFILE` from a host decrypts *everything* that host TLS'd during the capture
window — not only your SIP, but its logins, its API calls, its email. Scope it to a
dedicated test host and a short window, store it like a private key, and delete it when
the investigation closes. Never commit one. Never paste one into a chat window — including
hiccup's own "ask hiccup" drawer, which sends text to a local model but still handles it as
ordinary conversation text. And do not upload one to hiccup: there is no field for it, and
there should not be one until the ingest path in section 6 exists and has been thought
through properly.

---

## 6. What could become a hiccup feature later

Explicitly **not implemented**, no timeline, no commitment — recorded here so the ideas
are not lost, and so nobody mistakes this page for a feature list.

1. **A keylog-assisted TLS ingest path.** The obvious one. Accept a pcap plus an NSS-format
   keylog file, decrypt the TLS records, and feed the recovered SIP into the existing
   pipeline. It fits hiccup's model well: the keylog stays on your machine like the capture
   does, and it removes the manual follow-stream-and-clean-the-indentation dance in
   section 2. The realistic first cut shells out to `tshark` when one is installed and
   falls back to a clear "not available" message when it is not, rather than implementing
   TLS 1.2/1.3 record decryption in-process. Handling keys as a first-class secret —
   memory-only, never written to `data/`, never in a prompt — would be a precondition, not
   a follow-up.
2. **Reading Wireshark's Export-PDUs pcapng** (Upper-PDU link type 252). Small, contained,
   and it makes the manual TLS route in section 2 a two-click job instead of a text-cleaning
   exercise.
3. **SDES key harvesting for your own media.** hiccup already parses `a=crypto` while
   reading SDP. It could offer to use those keys to decrypt the matching SRTP streams *in
   the same capture* — payload-level statistics, DTMF events, codec confirmation. This one
   needs the section 5 conversation had properly first, and an explicit per-capture opt-in;
   silently decrypting media because the key happened to be in the file is not a default
   anybody should ship.
4. **HEP / Homer ingest.** Plaintext by construction, and it is where a lot of teams
   already keep their signalling. Either a HEP listener or an importer for Homer exports.
5. **SIPREC ingest**, for the same reason.
6. **Vendor log-format breadth.** AudioCodes syslog and Ribbon log dialects as
   first-class parsers alongside the existing Acme `sipmsg.log` support, since section 1
   says these are the traces people actually have.

If you have a plaintext-capture technique that works and is not listed here — especially a
vendor log format hiccup should parse — that is the most useful thing you could send back.
