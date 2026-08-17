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
