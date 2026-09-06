# groovable.ai

The landing page for **groovable** — a compute pool made of ordinary machines,
and an app builder that runs on it. Static: four files, no build step.

| file | purpose |
|---|---|
| `index.html` | the page |
| `site.css` | tokens + layout (dark default, light via system preference or the toggle) |
| `site.js` | the groove canvas and the theme toggle |
| `boot-theme.js` | applies a saved theme before first paint |
| `_headers` | Cloudflare Pages response headers (strict CSP; fonts from Google Fonts only) |

Paths are absolute (`/site.css`), so serve the directory from a web root rather
than opening `index.html` from disk. Locally: `python3 -m http.server 8765` in
this directory, then open http://127.0.0.1:8765/.

## Deploying to Cloudflare Pages

**Fastest (no git wiring): direct upload.**
1. Cloudflare dashboard → *Workers & Pages* → *Create* → *Pages* → *Upload assets*.
2. Project name `groovable`. Drag this `groovable/` folder in. Deploy.
3. *Custom domains* → *Set up a custom domain* → `groovable.ai`, then again for `www.groovable.ai`.

**Repeatable: connect the repo.**
1. *Workers & Pages* → *Create* → *Pages* → *Connect to Git* → this repository.
2. Production branch: `main`. Framework preset: *None*. Build command: *(empty)*.
   **Build output directory: `groovable`.**
3. Deploy, then add the custom domains as above. Every push to `main` that
   touches `groovable/` redeploys.

## DNS (Namecheap → Cloudflare)

Cloudflare Pages custom domains need the zone on Cloudflare DNS:
1. Cloudflare → *Add a domain* → `groovable.ai` → Free plan. Cloudflare shows two
   nameservers (e.g. `ada.ns.cloudflare.com` / `bob.ns.cloudflare.com`).
2. Namecheap → *Domain List* → *Manage* → *Nameservers* → *Custom DNS* → paste the two.
3. Wait for Cloudflare to report the zone active (minutes to a few hours), then add
   the custom domain to the Pages project. Cloudflare creates the CNAME itself.

## Notes

- `entriv.io`'s one-line description in `index.html` is a placeholder
  ("Another project from the studio.") — replace it with the real one.
- The pool table is illustrative and says so; keep that footnote until the pool exists.
- Social-card image (`og:image`) is deliberately absent; add one to `/brand/` when there is one.
