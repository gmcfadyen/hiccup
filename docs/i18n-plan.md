# hiccup — i18n design report (EN / FR / ES / DE)

**Status:** design only, nothing implemented.
**Date:** 2026-08-18.
**Scope:** four locales (en, fr, es, de), English-only development, a nightly job that
re-translates changed English strings.

Every number below was measured against the working tree by scanning string literals
(comment- and regex-aware) and HTML text nodes, not estimated. Where a figure is a
heuristic I say so.

---

## 1. String inventory

### Headline

| Category | Units | Characters | Words | Share of all text |
|---|---:|---:|---:|---:|
| (a) Static text in HTML | ~313 | ~9,550 | ~1,145 | 4% |
| (b) String literals in client JS | ~470 | ~16,120 | ~2,540 | 7% |
| (c) Server-generated strings | ~360 | ~15,080 | ~2,355 | 7% |
| (d) **Domain prose (advisor/detect/hmr/diff/...)** | **~2,050** | **~180,900** | **~30,000** | **82%** |
| **Total** | ~3,190 | ~221,650 | ~36,000 | 100% |

**The single most important number in this report: the UI chrome that users perceive as
"the app's language" is categories (a)+(b) — about 25,700 characters, ~3,700 words. The
domain corpus is seven times larger than everything else in the product combined.**

### (a) Static text in HTML — ~9,550 chars

Eight pages, all `<html lang="en">`. Measured text nodes (scripts/styles/comments stripped)
plus translatable attributes (`title`, `aria-label`, `placeholder`, `alt`):

| File | Text nodes | Chars | Attrs | Attr chars |
|---|---:|---:|---:|---:|
| `public/app.html` | 78 | 2,874 | 56 | 1,304 |
| `public/index.html` | 28 | 1,370 | 14 | 461 |
| `public/team.html` | 27 | 854 | 8 | 156 |
| `public/hmr.html` | 22 | 689 | 7 | 319 |
| `public/kb.html` | 21 | 609 | 9 | 249 |
| `public/accept-invite.html` | 7 | 158 | 2 | 49 |
| `public/admin-feedback.html` | 12 | 100 | 5 | 65 |
| `public/admin-status.html` | 12 | 77 | 5 | 65 |

Plus `public/site.webmanifest` (`name`, `description`, ~155 chars).

`public/index.html` is the only page with real marketing voice ("a big friendly monster
lives at hiccup.monster — its whole job is fixing yours"). At 226 words it should be
hand-translated, not machine-translated.

### (b) String literals in client JS — ~16,120 chars

| File | Prose units | Chars |
|---|---:|---:|
| `public/app.js` | 267 | 9,540 |
| `public/hmr.js` | 70 | 2,511 |
| `public/kb.js` | 33 | 1,231 |
| `public/feedback.js` | 32 | 930 |
| `public/team.js` | 30 | 794 |
| `public/accept-invite.js` | 23 | 766 |
| `public/ladder.js` | 7 | 208 |
| `public/theme.js` | 6 | 140 |

**Verified: there are zero `console.log/warn/error` calls in any client JS file.** So
essentially every prose literal in this category is user-facing — there is no diagnostic
noise to filter out. That makes extraction unusually clean here.

19% of `app.js` prose (by character) is assembled with `+` from runtime values
(`app.js:384` `'local model available (source: ' + x + ')'`, `app.js:561` `'Analysing ' + name + ' …'`).
Those need parameterised messages, not plain lookups — but there are only ~46 of them.

### (c) Server-generated strings — ~15,080 chars

`server.js` carries 140 prose units / 6,419 chars, of which only 23 lines are `console.*`;
the remainder is ~95 API error payloads (`error: '<English sentence>'`) that surface
directly in the UI. Supporting libs: `lib/kb.js` 2,509, `lib/pcap.js` 1,899 (parse
warnings), `lib/teams.js` 1,322, `lib/llm.js` 894, `lib/auth.js` 690, plus
`projects/mail/feedback/analyze/textlog/store` ≈ 1,350 combined.

Note the shape problem: server errors are sent as English *sentences*, not codes. There is
no `code` field to key a translation off. See Phase 2.

### (d) Domain prose — ~180,900 chars

This is the category that decides the feasibility of the whole feature.

| File | Prose units | Chars | % assembled from runtime values |
|---|---:|---:|---:|
| `lib/advisor.js` | 811 | 94,744 | 7% |
| `lib/detect.js` | 248 | 35,378 | **48%** |
| `lib/hmr.js` | 289 | 26,134 | **45%** |
| `lib/isup.js` | 335 | 10,232 | 17% |
| `lib/diff.js` | 62 | 4,242 | 11% |
| `lib/retrans.js`, `rtp.js`, `ice.js`, `diameter.js`, `dns.js`, `correlate.js`, `h323.js` | ~260 | ~10,200 | mixed |

**The brief named advisor.js and detect.js. Two others belong in the same category and
were not mentioned:**

- **`lib/hmr.js` — 26,134 chars.** `explainRule()` (line 1704) produces `intent`,
  `correctness` and `improvements` prose about header-manipulation rules. It is the same
  kind of dense, authored, technical English as advisor.js and it is fully user-facing on
  `/hmr`. Any advisor.js decision must cover it.
- **`lib/isup.js` — 10,232 chars.** These are almost all ITU-T Q.763 / Q.850 enumeration
  labels ('presentation restricted', 'user provided, verified and passed'). They are
  *normative spec terminology*, not authored prose. They have official FR/ES translations
  in the ITU-T recommendations that a general-purpose LLM will not reproduce. Treat as
  "do not machine-translate" regardless of what happens to advisor.js.

#### advisor.js field census (the useful breakdown)

26 rules (`RULES.push({ id: ... })`), 322 named prose field instances / 75,974 chars:

| Field | Instances | Chars | Interpolated | Longest |
|---|---:|---:|---:|---:|
| `steps` (86 arrays → 266 strings) | 266 | 28,729 | 5 | 604 |
| `mechanism` | 27 | 18,389 | **1** | 1,087 |
| `whyItMatters` | 27 | 10,213 | 8 | 805 |
| `summary` | 86 | 7,454 | **0** | 139 |
| `caution` | 45 | 5,148 | **0** | 163 |
| `whatsWrong` | 25 | 3,823 | **25 (all)** | 342 |
| `title` | 26 | 2,206 | **24** | 194 |

Plus, in the same file and **excluded from any translation**:

- **44 vendor config snippets / 7,974 chars** (`config: acme(...)`, `audiocodes(...)`,
  `ribbon(...)`) — literal device configuration.
- **64 backtick-delimited inline code spans** (`` `show sipd errors` ``, `` `SBCRemoteRepresentationMode` ``).
- **41 strings containing a literal vendor UI path or CLI verb** — e.g. `advisor.js:515`
  `'Setup > Signaling & Media > Core Entities > Proxy Sets: confirm the address '`. 25% of
  all `steps` strings contain one.
- ~180 `REFS` entries of RFC/ITU-T titles.

Two structural facts fall out of this and drive the architecture:

1. **`mechanism` + `whyItMatters` + `summary` + `caution` = 185 units / 41,204 chars that
   are essentially static** (9 interpolated out of 185). These are keyable 1:1 and are the
   only realistically translatable slice of advisor.js.
2. **`title` and `whatsWrong` are 92% and 100% runtime-assembled.** `advisor.js:469-475`
   is typical — method name, retransmission count, destination, leg count, an English
   pluralisation ternary and a nested `cls.detail` all concatenated. These cannot be
   extracted at all without first being rewritten as parameterised messages.

#### detect.js is structurally worse than advisor.js

35 detectors, but only **27 static `fallback` sentences (4,310 chars)** carry a stable key
(the detector's `key`, e.g. `'dtmf-rfc4733'`). The other ~31,000 characters live in **129
`return r('issue'|'on'|'partial', '<sentence>')` call sites** with no per-branch
identifier — see `detect.js:1038-1074`, where one detector emits five different sentences
depending on evidence. 48% of detect.js prose is interpolated. **Keying detect.js requires
inventing 129 branch ids first.** That is a refactor of the detector table, not a
translation task.

---

## 2. Recommended i18n architecture

Constraints this has to respect: zero runtime dependencies, no build step, vanilla
browser JS, static HTML served from `public/`, and a **frozen DOM id contract**
(`app.html:15-84`, 77 ids).

### Recommendation in one line

A **source-hash-keyed catalogue**, served as a plain `.js` file that assigns a global,
loaded by a blocking `<script>` in `<head>`, consumed by a `t()` function plus a
one-shot `[data-i18n]` DOM pass — with the English source text itself as the fallback, so
a missing translation is structurally incapable of rendering blank.

### 2.1 Keying and extraction

**Use the English source string as the key, addressed by a hash of it. Do not invent
dotted key names.**

```
locales/en.json     { "a1b2c3d4e5f6": { "text": "Sign out", "where": ["public/app.html:109"], "cat": "chrome" } }
locales/fr.json     { "a1b2c3d4e5f6": { "text": "Se déconnecter", "src": "a1b2c3d4e5f6", "engine": "...", "at": "...", "status": "mt" } }
```

Why source-hash rather than hand-written keys — this is the load-bearing argument:

- With hand keys (`topbar.logout`), editing the English text keeps the key, so the stale
  French translation keeps being served. The UI then shows **confidently wrong** text and
  nothing detects it.
- With a source hash, editing the English produces a **new key**, the lookup misses, and
  the UI falls back to the new English until the nightly job catches up. That is exactly
  the "trails English by at most a day" behaviour the owner asked for, and it is obtained
  for free rather than policed.
- It also removes the single largest cost of retrofitting i18n: naming ~800 keys.

Extractor: `bin/i18n-extract.js` — a comment/regex-aware literal scanner over
`public/*.html` (text nodes + a whitelist of attributes) and the marked call sites in
client JS, writing `locales/en.json`. `bin/` already exists (holds `nssm.exe`).

### 2.2 How a page picks up a locale

Mirror the existing theme mechanism exactly — it is already the house pattern and it is
FOUC-safe. `app.html:7` runs an inline `<script>` in `<head>` that reads
`localStorage['hiccup-theme']` before any CSS loads; `public/theme.js:13` owns the key.

Add, in the same `<head>` of all eight pages, before the stylesheet links:

```html
<script>(function(){try{var L=localStorage.getItem('hiccup-lang');
if(!/^(en|fr|es|de)$/.test(L||''))L=(navigator.language||'en').slice(0,2);
if(!/^(en|fr|es|de)$/.test(L))L='en';document.documentElement.lang=L;
document.write('<script src="/i18n/'+L+'.js"><\/script>');}catch(e){}})();</script>
```

(`document.write` here is deliberate — it gives a *blocking* load with no fetch/async race
and no build step. If that is distasteful, emit four `<link rel=preload>`-free static
`<script>` tags and let 404s be silent; the `document.write` version is simpler.)

Then `public/i18n.js` (loaded like `theme.js`) exposes `window.t` and runs the DOM pass.

**Serving the catalogue — a real gotcha.** `server.js:469-477` defines `STATIC_TYPES` with
`.html .css .js .svg .png .ico .webmanifest`. **`.json` is not whitelisted**, so
`fetch('/locales/fr.json')` returns 404 today (`serveStatic`, `server.js:524-549`, rejects
any extension outside that map). Two options:

- **Preferred:** ship the catalogue as `public/i18n/fr.js` containing
  `window.HICCUP_I18N={...}`. `.js` is already whitelisted, `Cache-Control: no-cache` is
  already set (`server.js:546`) so a nightly rewrite is picked up on next load, and
  **zero server changes are needed**.
- Alternative: add `'.json'` to `STATIC_TYPES`. One line, but it also exposes any other
  `.json` that ever lands in `public/`.

### 2.3 The trap the frozen contract creates

The id contract freezes *ids and their place in the tree*. Adding `data-i18n` attributes
and one new `#lang-select` element is additive and safe — Wave-5A already set that
precedent by adding `#command-palette-open` to the topbar (`app.html:100-104`).

But `app.html:75-83` documents something that breaks the naive approach:

> "For the life of one FRESH upload, app.js replaces the contents of `#filter-tree`,
> `#ladder-svg-host` and `#selection-list` ... Placeholder copy lives INSIDE each container
> so a renderer that clears the node removes it for free."

**A one-shot DOM translation pass is therefore not sufficient.** Anything `app.js` renders
after load — every empty state, every lamp tooltip, every advice card, the skeleton
placeholders — comes back in English. You need *both*:

1. a `[data-i18n]` DOM pass on `DOMContentLoaded` for the static markup, **and**
2. `t()` wrapped around every string at every render site in `app.js` (267 units),
   `hmr.js`, `kb.js`, `team.js`, `feedback.js`, `accept-invite.js`, `ladder.js`.

That second item is the actual labour of Phase 1 — roughly 470 call sites. The translating
is the cheap part.

Helpfully, `app.js:22-24` states that every piece of text goes in via `textContent` /
`createTextNode` and `innerHTML` is never used. So translated strings carry no XSS risk
and `t()` can be a pure string→string function with no escaping concerns.

### 2.4 Language chooser

A `<select id="lang-select">` in the topbar of each page next to the theme toggle
(`app.html:105`), wired in `i18n.js` the way `theme.js:53-56` wires `[data-theme-toggle]`:
write `localStorage['hiccup-lang']` and reload. A reload (rather than live re-render) is
the honest choice here — it costs nothing, guarantees every rendered surface is consistent,
and avoids auditing 470 call sites for re-render safety.

### 2.5 Degradation

`t(s)` returns `catalogue[hash(s)] ?? s`. The English source is the argument, so a miss
returns English by construction — **it is not possible for this design to render blank**.
For `[data-i18n]` elements, the English is already the element's own `textContent`; a miss
means the pass simply leaves the node untouched.

Missing-key reporting goes behind a `?i18ndebug` query flag, so the "zero console calls in
client JS" property is preserved in normal operation.

---

## 3. Change detection for the nightly job

**Yes, hash per string — and hash the *source text*, not a key name.** As argued in §2.1,
that choice is what makes staleness safe rather than silent.

Concretely:

- **Where the hashes live: in the locale files themselves.** No database, no sidecar. Key =
  first 12 hex of `sha1(normalised English source)` (trim, collapse internal whitespace),
  computed with node's built-in `crypto` — already required by `lib/kb.js`.
- Each target-locale entry stores `src` (the hash it was translated from), `at`, `engine`,
  and `status` (`mt` | `human` | `failed`).
- Nightly diff is a pure set operation:
  - `en` keys not in `fr` → **translate**.
  - keys in `fr` whose `src` ≠ their own key → **re-translate** (defensive; shouldn't occur).
  - keys in `fr` not in `en` → **prune** (the English string was edited or deleted; its
    translation is now unreachable anyway).
  - entries with `locked: true` or `status: "human"` → **never touched**, so a hand-corrected
    string is permanent. This matters a lot if advisor text is ever translated.
- Emit a one-line summary per locale (`fr: +12 new, -3 pruned, 0 failed`) so a drift is
  visible in `server.log`.

Nothing needs to compare timestamps or watch files — re-running the extractor and diffing
key sets is both simpler and exactly correct.

---

## 4. Translation engine assessment

### The plumbing is already right

`lib/llm.js` is a better starting point than most projects have. Its documented contract
(`llm.js:6-25`) already does everything a polite nightly job needs:

- **Never pulls a model, and never triggers a load of a different model while `/api/ps`
  shows a generation model loaded** (`llm.js:12-14`) — it cannot evict RFPlex's models.
- **Preserves RFPlex's pin**: passes `keep_alive:-1` when it detects RFPlex's
  `keep_alive:-1` pin, otherwise `5m` (`llm.js:15-18`).
- **Yields on RFPlex's GPU gate**: if RFPlex reports `accepting_jobs === false`, waits 3s
  and re-checks up to 10 times before proceeding (`llm.js:19-21`).
- Concurrency 1, FIFO, queue depth 8, 120s timeout, one retry (`llm.js:22-23`).

A nightly translator that goes through `askLlm()` (`llm.js:522`, exported at `llm.js:543`)
inherits all of that with no new policy. Midnight is also when RFPlex is least contended.
**No changes to the GPU-sharing arrangement are needed.**

Model: `llm.js:50` prefers `qwen3.5:9b` / `qwen3.5:2b`, but in practice it borrows whatever
RFPlex already has resident.

### Is a local ~9B model credible for this content?

**For UI chrome: yes.** Buttons, nav, empty states, form labels, error toasts. Short,
plain, low-stakes, and every string is reviewable by a human in bulk because there are only
~3,700 words. This is a solved problem.

**For advisor.js / detect.js / hmr.js prose: no, not without a domain-literate human
reviewer.** Concrete failure modes, all of which apply to strings that actually exist in
this tree:

- **`leg` / `call-leg`.** Renders as *jambe* (FR, anatomical) or *Bein* (DE). The correct
  senses are *branche d'appel* / *Anrufabschnitt*, and many practitioners keep the English.
  `leg` appears throughout `advisor.js` and is in the DOM contract's own vocabulary.
- **`trunk`.** The classic MT failure: *tronc* (tree trunk) / *Kofferraum* (car boot).
  Correct: *faisceau SIP* / German usually keeps "SIP-Trunk".
- **SIP header names used as bare capitalised words mid-sentence.** `advisor.js:858`
  reads "Record-Route set carries a private address"; `advisor.js:879` names `Contact`.
  `Contact`, `Via`, `Supported`, `Require`, `Allow` are ordinary English words *and*
  protocol identifiers. An LLM will translate them and silently destroy the instruction.
- **RFC and section numbers.** `mechanism` text is dense with them
  (`advisor.js:482-488`: "Timer A at T1 (500 ms)", "Timer B = 64×T1 = 32 s"). Models drop
  or alter digits, and a wrong timer value in a diagnostic is worse than no diagnostic.
- **Vendor UI paths.** `advisor.js:515` "Setup > Signaling & Media > Core Entities >
  Proxy Sets" is the literal English AudioCodes web UI. Translating it makes the step
  **unfollowable** — the menu it names does not exist in any other language.
- **ITU-T terminology.** `lib/isup.js`'s Q.763/Q.850 labels have official translations in
  the ITU recommendations; an LLM will produce plausible but non-normative alternatives.

### How to protect what must stay verbatim

The author has already done half this work: **64 inline code spans are bracketed in
backticks** and 44 config blocks are structurally separate. Formalise it:

1. **Mask-and-verify.** Before sending, replace every backtick span, every `RFC \d+`,
   every `Section [\d.]+`, every number-with-unit, and every glossary term with an opaque
   placeholder (`⟦7⟧`). After translation, **reject the result** if any placeholder is
   missing, duplicated, or reordered into nonsense. A rejected string keeps `status:
   "failed"` and falls back to English — which is safe, by §2.5.
2. **Exclude by category at extraction time**, never send at all: `config:` values, any
   `steps` string matching a vendor menu path, all of `lib/isup.js`, all `REFS` titles,
   licence/legal text (`LICENSE`, `NOTICE`, BUSL-1.1), and brand strings ("hiccup",
   "ask hiccup", "hiccup.monster", "Buy Me a Coffee").
3. **A ~120-term protected glossary**, passed in the prompt *and* enforced by post-check:
   SIP method names, header names, `100rel`, `PRACK`, `SDP`, `DTMF`, `telephone-event`,
   `Min-SE`, `Session-Expires`, `Timer A/B/F`, `T1/T2`, `B2BUA`, `SBC`, `UAC/UAS`, plus
   vendor product names.
4. **Cheap validators, not a back-translation pass.** Digit-set preserved; output length
   between 50% and 200% of source; a stopword check that the output is actually in the
   target language. Back-translation doubles GPU time on a shared card for modest gain —
   spend that budget on human review of the 45 `caution` strings instead.

---

## 5. Phased plan

| Phase | Scope | Rough effort | Delivers |
|---|---|---|---|
| **0** | Extractor + `i18n.js` + `<head>` snippet on 8 pages + `#lang-select` + `public/i18n/<lang>.js` serving | 0.5–1 day | Nothing visible. Everything still English. |
| **1** | **Chrome: HTML (313 strings) + client JS (~470 call sites), ~25,700 chars** | **2–3 days** | **~90% of perceived localisation** |
| **2** | Server user-facing messages (~95 API errors) | 0.5–1 day, +refactor | Localised errors |
| **3** | Nightly job (`bin/i18n-translate.js` + timer) | ~1 day | Translations trail English by ≤1 day |
| **4** | advisor.js static subset (185 units / 41,204 chars) | 3–5 days **+ human review per language** | Optional; needs a decision |
| **5** | detect.js `r()` branches + hmr.js | 5+ days of refactor *before* any translation | **Not recommended** |

### Phase 1 is where essentially all the value is

25,700 characters — 12% of the product's text — buys the entire perceived experience: nav,
buttons, empty states, upload flow, dialogs, the command palette, the shortcuts overlay,
error toasts. Note that the labour is the ~470 `t()` call sites, not the translating;
3,700 words × 3 languages is reviewable by one person in a day or two and cheap to have
checked by a native speaker.

### Phase 2 has a hidden refactor

`server.js` sends `error: '<English sentence>'` in ~95 places with no stable `code` field.
To translate client-side you must first add codes. Recommended (it also improves the API),
but it is a real change to a 2,389-line file, not a wrap-in-`t()` job. The alternative —
honouring `Accept-Language` and localising server-side — avoids the refactor but splits the
catalogue across client and server.

### Phase 3 should copy the existing scheduler, not invent one

`startFeedbackDigestTimer()` (`server.js:2350-2374`) polls every 15 minutes and asks a
`digestDue()` predicate (`server.js:1198`) rather than sleeping a day, and the comment at
`server.js:2343-2348` gives the reason explicitly: *this box reboots for Windows updates,
so a long `setInterval` drifts on every restart and can skip a period entirely.* That is
precisely the failure mode a `setInterval(24h)` midnight job would hit here. Model the
i18n timer on it, `unref()` the timer the same way (`server.js:2371`), and put the "has
tonight's run happened" decision in a predicate.

### Do NOT translate the advisor corpus in phase 1 — and possibly not at all

This is a deliberate recommendation, not a scoping shortcut. Five reasons:

1. **It contradicts a documented design contract.** `advisor.js:9-12`: *"DETERMINISTIC BY
   DESIGN. Every word of every Advice object comes from the hand-written rule/knowledge
   base below — never from an LLM."* Machine-translating it inverts that guarantee for
   three of the four locales. That is a product decision the owner must make consciously.
2. **The highest-value fields are the least extractable.** `title` (92% interpolated) and
   `whatsWrong` (100% interpolated) are the first thing a user reads and cannot be
   extracted at all without a parameterised-message refactor.
3. **Volume.** 94,744 chars in advisor.js alone, plus 35,378 in detect.js and 26,134 in
   hmr.js.
4. **Harm.** `steps` and `caution` are instructions executed against production SBCs (§6).
5. **Stored analyses freeze the language** (see §6, open question 1) — so this can only ever
   be a client-side render-time lookup, which further constrains it.

**If it is ever done, the tractable slice is well-defined and encouraging:** `mechanism`
(27), `whyItMatters` (27), `summary` (86), `caution` (45) — 185 units, 41,204 chars, only 9
interpolated. And the key already exists: every emitted Advice object carries
`ruleId: rule.id` (`advisor.js:3305`), so the client can look up
`advisor.<ruleId>.mechanism` **with no server change whatsoever**. The one wrinkle is that
some fields branch on a ternary (`advisor.js:476-481` yields two different `whyItMatters`
texts for the same rule), so those need a variant suffix — `advisor.<ruleId>.whyItMatters.0|1`.

detect.js and hmr.js do not have this property. detect.js's 129 `r()` branches carry no
identifier, so translating it means first inventing and maintaining 129 branch ids —
refactor risk with no functional payoff, against a file whose header calls the indicator
list a *"frozen contract"* (`detect.js:6-8`).

---

## 6. Risks and open questions for the owner

1. **Stored analyses are frozen in the language they were generated in.** `server.js:658`
   writes `analysis.json` with `advice` and `indicators` prose already baked in
   (`lib/analyze.js:267,271-272`). If domain text were ever translated server-side, a
   capture uploaded today would display in that language forever, and switching the UI
   language would not change it. **Any domain translation must therefore be a client-side
   render-time lookup keyed on `ruleId` / detector `key`, never a change to the generator.**
   This constrains phase 4 more than the translation quality does.

2. **Could a mistranslated instruction be actively harmful? Yes — concretely.** `steps`
   and `caution` are executable instructions against production SBCs. Two real examples
   from this tree: `advisor.js:527` *"Widening the Access List weakens the device's edge
   protection — scope any new entry to the peer's exact prefix"*; `advisor.js:543` *"An
   over-broad `ingressIpPrefix` accepts signalling from hosts you did not intend to
   trust."* A translation that drops a negation, or renders "scope" as "extend", converts a
   security caution into a security instruction. **Mitigation is cheap and specific: the 45
   `caution` strings total 5,148 characters. If advisor text is translated at all, make
   human review of `caution` mandatory — it is the highest harm-per-character text in the
   product and the cheapest possible place to spend a review budget.**

3. **Disclaimer — yes, but scope it.** A site-wide "machine-translated" banner is noise on
   a translated *button*. Recommendation: no disclaimer for phases 1–3 (chrome only), but
   if phase 4 ships, put a small "machine-translated · English is authoritative" chip on
   the advice drawer with a one-click "show English" toggle — which is nearly free given
   the English source is already the fallback value in the catalogue. Separately, keep
   `<html lang>` accurate regardless, for screen readers.

4. **The KB will degrade for non-English users, and there is no cheap fix.** `lib/kb.js`
   indexes *user-uploaded vendor documentation* — user data, and almost always English
   (Oracle/AudioCodes/Ribbon publish in English). Its BM25 retrieval uses an English
   stopword list and English token folding (`kb.js:22`, `kb.js:718`). A French-language
   query against English docs will retrieve badly. The obvious fix — embeddings — is
   explicitly ruled out by `kb.js:23`: *"an embedding model would compete with RFPlex for
   the GPU, which the LLM contract forbids."* **Decision needed: accept that KB search
   stays English-only and label it, or reopen the GPU contract.**

5. **Should "ask hiccup" answer in the UI language?** The chat layer paraphrases advice via
   the LLM. Making it answer in French is a one-line prompt change, but its answers would
   then be machine-generated French about English source material — the same accuracy risk
   as phase 4, though at least visibly a chatbot rather than authoritative product text.
   Owner's call.

6. **Number formatting.** `advisor.js:50-61` (`fmtS`/`fmtMs`) and `app.js:112-119`
   (`toFixed`) emit `.` as the decimal separator; FR/ES/DE use `,`. Low stakes, visible,
   and fixable with built-in `Intl.NumberFormat` at zero dependency cost. Worth doing in
   phase 1.

7. **Good news, verified: the test suite will not obstruct this.** `test/selftest.js`
   (1,220 lines) contains only 10 string-content assertions and **none of them assert on
   user-facing English prose** — they check ids, tags, cause codes, and the absence of
   leaked secrets (e.g. `selftest.js:273`, `:1098`, `:1132`). Translation work will not
   break the selftest, and the selftest will not catch translation regressions either. If
   you want a guard, add one check that `locales/*.js` parse and that every `en` key is a
   valid hash of its own `text`.

8. **Licence and legal text must be excluded.** `LICENSE` (BUSL-1.1),
   `LICENSE-COMMERCIAL.md`, `NOTICE`. Not currently surfaced in the UI, but if they ever
   are, they must stay English or be explicitly marked non-authoritative.

---

## Appendix — how the numbers were produced

Four throwaway scanners were run against the working tree (none written into the repo):

- a comment-, regex- and template-literal-aware JS string-literal scanner, with a "prose"
  filter (≥12 chars, contains whitespace, contains ≥3 consecutive letters, not a URL/MIME/selector);
- an expression-level pass that walks `+` chains, merges adjacent literals into one logical
  unit and flags any chain containing a non-literal operand (used for the "% assembled from
  runtime values" column);
- a brace/paren-aware field census keyed on `title:`, `whatsWrong:`, `whyItMatters:`,
  `mechanism:`, `summary:`, `caution:`, `fallback:`, `steps:`;
- an HTML scanner over text nodes (comments/`<script>`/`<style>` stripped) plus a
  translatable-attribute whitelist.

Counts are honest but approximate at the margins: the prose filter is a heuristic, so a
handful of internal identifiers may be counted as prose and a handful of very short UI
strings ("OK", "Close") missed. Character totals are reliable to roughly ±5%. The advisor
field census and the `ruleId` / `STATIC_TYPES` / scheduler / test-assertion findings were
each verified by reading the source directly.
