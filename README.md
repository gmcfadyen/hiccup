# hiccup

**see where the call went wrong** — a web-based SIP / H.323 trace analyser for the
SBC-curious: two-leg B2BUA correlation with an explicit delta view, a retransmission
classifier that tells you *why* the INVITE retransmitted, and a ladder that collapses
the noise. Free while in beta; accounts required.

## What it ingests

- `pcap` / `pcapng` (Wireshark captures — extension irrelevant, content is sniffed)
- SBC text log exports (Oracle/Acme `sipmsg.log` style, multiple legs interleaved)
- sngrep/sipgrep text output and bare concatenated SIP messages
- SIP over UDP and TCP; H.323 (Q.931/H.225 over TPKT) including SIP↔H.323 IWF pairing

## Quickstart

```
node server.js
```

Then open http://127.0.0.1:8400 — create the first account (it becomes admin).
Runtime config lives in `data/config.json` (port, Google client id, model preferences).

```
npm run selftest      # fixtures + end-to-end assertions
```

## The AI part

hiccup shares this machine's Ollama with RFPlex.ai and is deliberately the
**lower-priority tenant**: it uses whatever model RFPlex has loaded, never pulls or
evicts models, preserves RFPlex's VRAM pin, and yields when RFPlex is mid-job. Every
feature works with the LLM offline — the chatbot is garnish, the analysis is code.

Privacy is structural: self-hosted, local inference, Digest credentials redacted on
ingest, and your traces never leave the box.

## Layout

See `ARCHITECTURE.md` for module contracts and `DESIGN_1.md` for the product brief.

## Licence

hiccup is **source-available, not open source.** Please read this before you deploy it.

The code is published under the [Business Source License 1.1](LICENSE) (BSL 1.1).
You may read it, build it, modify it, self-host it and redistribute it — and you are
encouraged to, because a tool that ingests phone numbers, IP addressing and Digest
credentials should be auditable by the people whose data it touches. But BSL 1.1 is
**not** an OSI-approved open-source licence, and it restricts what you may use it *for*.

- **Free, no licence needed:** evaluation, development, testing, security audit, staff
  training (including running hiccup against your own captures to assess hiccup itself),
  teaching, academic research, personal study, hobbyist and home-lab use, and use by a
  registered charity.
- **Requires a commercial licence:** production use — troubleshooting, assuring,
  migrating or certifying a live service; any analysis performed as paid work, under a
  support contract or under an SLA; hosting hiccup for colleagues, customers or third
  parties; or embedding it in another product or managed service.

The [Additional Use Grant in `LICENSE`](LICENSE) is the authoritative wording; the
summary above is only a signpost. [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) explains
who needs a licence, what it costs and how to get one — email
**<licensing@rfplex.ai>**.

Each released version converts automatically to the **Apache License 2.0** four years
after publication (Change Date **2030-08-17** for version 0.1.0), after which that
version is fully permissive open source with no commercial restrictions.

hiccup is currently **free while in beta**. That is a pricing decision about the beta,
not a change to the licence above.

The name **hiccup** and its wordmark are trademarks and are *not* licensed with the
code — see [NOTICE](NOTICE). Fork freely; rename the fork.

Copyright (c) 2026 Gavin McFadyen.
