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

## real-*.pcap / real-*.pcapng — removed 2026-08-18

Five real captures (two REGISTER auth-failure loops, a codec-negotiation
failure, a routing error, and a SIPVicious scan against a live Asterisk PBX)
were briefly present here, downloaded from `goffinet/sip_captures`, a public
GitHub repo of sample SIP captures. Content review found nothing sensitive
(lab/test extensions, private IP ranges, standard software fingerprints —
no real personal data), but the source repo has **no LICENSE file**, so
redistribution rights were never established. Removed rather than kept on
an unclear license, since hiccup itself is a published, source-available
project. If equivalent coverage is wanted later, the better path is
synthetic fixtures built with `make-fixtures.js`'s own toolkit (a codec
478/488 rejection, an auth-retry loop, a SIPVicious-shaped scan pattern, a
routing error) — same diagnostic value, no provenance question.
