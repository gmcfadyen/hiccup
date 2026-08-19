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
npm run selftest:adversarial   # RFC 4475 torture messages + real problem captures
                                # (robustness only -- see test/fixtures/adversarial/SOURCES.md)
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

## Runbook (hiccup.monster)

Installed as a Windows service named **`hiccup`** via `install-as-service.bat`
(NSSM, LocalSystem, auto-start), bound to `127.0.0.1:8400` and reached from the
internet through a Cloudflare tunnel. `data/` holds everything stateful.

**The one rule that matters when deploying:**

> Editing anything under `public/` is live the moment you save it.
> Editing `server.js` or `lib/**` does nothing until the service is restarted.

`PUBLIC_DIR` points at this working tree and static files are read per request,
so there is no build and no publish step for the front end — but Node caches
`require()`, so the back end is frozen at whatever was on disk when the process
booted. Ship a commit that touches both and the site runs **split-brain**: new
pages calling routes that do not exist yet. That has already happened once, and
it is how `/subscribe` 404'd for four hours while the landing page linking to it
was live.

Restart after any `server.js` / `lib/**` change, by either:

- clicking **restart server** on `/admin/status` (needs a site-admin session, no UAC), or
- an **elevated** PowerShell: `Restart-Service hiccup -Force`

Then confirm the deploy actually landed — `/api/status` reports uptime:

```
curl -s https://hiccup.monster/api/status
curl -s -o /dev/null -w '%{http_code}\n' https://hiccup.monster/subscribe
```

**Backups.** `backup-hiccup.ps1` mirrors the project to `F:\backups\hiccup`
with 30 dated snapshots, run daily at 03:30 by the *Hiccup Backup* scheduled
task. It deliberately keeps `.git` (commits here are often unpushed) and `data/`
(gitignored, so it exists nowhere else), and skips only `node_modules`.

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
