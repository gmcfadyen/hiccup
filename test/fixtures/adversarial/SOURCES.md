# test/fixtures/adversarial/ — provenance

Real-world and standards-body "this should break a parser" captures, kept
apart from `make-fixtures.js`'s synthetic corpus (see `ARCHITECTURE.md`
`#Selftest`) because nobody here authored a ground-truth `expected.json` entry
for them — nothing built these scenarios from a known spec, so there's no
independently-known "correct diagnosis" to assert against. They're exercised
by the separate robustness pass in `test/adversarial.js`
(`npm run selftest:adversarial`), not the strict `expected.json` suite.

All fetched 2026-08-18, for local testing/development use only.

## rfc4475-torture.txt

18 messages copied byte-for-byte (only the RFC's own fixed 6-space artwork
indent is stripped — see the header comment in the file itself) from:

> RFC 4475, "Session Initiation Protocol (SIP) Torture Test Messages",
> R. Sparks et al., May 2006. https://www.rfc-editor.org/rfc/rfc4475.html

IETF RFCs are freely reproducible; this is a small excerpt (18 of the ~40
messages the RFC defines) used purely for local test fixtures.

Deliberately **not** included: messages the RFC itself reconstructs via
`<allOneLine>`/`<repeat count=N>` markup (`intmeth`, `longreq`, `unreason`,
`mpart01`, `scalar02`, `scalarlg`) — skipped rather than risk a transcription
error in the one place where byte-exactness is the entire point of the
fixture. Worth hand-adding later if wanted.

**What running this through hiccup already found.** `node test/adversarial.js`
reports only 10 of the 18 messages surfacing as `sip=10`, with **zero**
warnings. Root cause, traced through `lib/textlog.js`:

- `esc02`'s method token `RE%47IST%45R` (RFC §3.1.1.5) doesn't match
  `REQ_LINE` (`textlog.js:36`, method class is `[A-Z0-9_-]` — no `%`, even
  though `%` is a legal RFC 3261 `token` char) → silently invisible, not even
  counted as a candidate message.
- `badvers`'s `SIP/7.0` (§3.1.2.16) and `bigcode`'s 10-digit status code
  (§3.1.2.19) both fail `REQ_LINE` / `STATUS_LINE`'s hardcoded `SIP/2.0` /
  `\d{3}` (`textlog.js:36-37`) → also silently invisible.
- `clerr`'s `Content-Length: 9999` against a ~150-byte real body (§3.1.2.2)
  makes `consumeMessage`'s body-reading loop (`textlog.js:132-143`) consume
  every remaining line in the file as "body" — the loop has no bound besides
  running out of lines, so it silently swallows the next 8 messages whole
  (`ncl`, `quotbal`, `ltgtruri`, `lwsstart`, `badvers`, `mismatch02`,
  `bigcode`, `badbranch`) with no warning pushed anywhere on that path.

None of this crashes — `ARCHITECTURE.md`'s "never throw on malformed frames"
contract holds end to end — but the *silent* part (no `warnings` entry at all
for either case) looks like a gap against that same doc's "skip with a warning
string" promise for `raw-sip` mode specifically. Not fixed here; flagged as a
follow-up rather than folded into this fixture-adding pass.

## real-*.pcap / real-*.pcapng

Downloaded from `goffinet/sip_captures`, a small public GitHub repo of sample
SIP captures for learning/testing: https://github.com/goffinet/sip_captures

| File here | Upstream filename | What it actually shows (verified by parsing it through `lib/pcap.js`, not just going by the filename) |
|---|---|---|
| `real-sip-488-codec-negotiation-fail.pcapng` | `sip-488-Not-Acceptable-Here-codec-null.pcapng` | An INVITE answered `488 Not Acceptable Here` — a codec/SDP offer-answer failure. |
| `real-sip-register-wrong-password.pcapng` | `sip-register-wrong_password-401-403-401-403.pcapng` | REGISTER auth-failure loop: `401 Unauthorized` → retry → `403 Forbidden`, repeating. |
| `real-sip-register-wrong-user.pcapng` | `sip-register-wrong_user-401-403-404.pcapng` | REGISTER against an unknown user: `401` → `403` → `404`. |
| `real-sip-routing-error.pcapng` | `sip-routing-error-wireshark.pcapng` | Capture the uploader themselves labeled a SIP routing error (2 calls, 58 SIP messages). |
| `real-forensic-challenge-4.pcap` | `Forensic_challenge_4.pcap` | 3534 packets, some snaplen-truncated (declared length > captured length — real, not synthetic). Confirmed by inspection: `User-Agent: UNfriendly-scanner - for demo purposes` — this is [SIPVicious](https://github.com/EnableSecurity/sipvicious) (`svmap`/`svwar`), a well-known open-source SIP scanner — sending OPTIONS pings and REGISTER probes against an `Asterisk PBX 1.6.0.10-FONCORE-r40` at `172.25.105.40`, interleaved with a real X-Lite softphone registering normally. Real scanning/enumeration traffic against a real PBX, not a clean happy-path call. |

`node test/adversarial.js` ingests all five without a crash or a single
warning misfire — the truncated frames in the forensic-challenge capture
produce exactly the graceful "declared vs captured" warnings
`ARCHITECTURE.md` describes for that case, and nothing else.
