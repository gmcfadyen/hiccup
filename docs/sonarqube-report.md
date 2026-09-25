# SonarQube analysis — hiccup

Scanned with SonarQube 26.9.0 Community (local server) + sonar-scanner-cli 8.1.0 on commit `47a23a4`.
Scope: `server.js`, `lib/`, `bin/`, `public/` as sources, `test/` as tests; fixtures, brand assets and
knowledge-base content excluded (see `sonar-project.properties`).

## Summary

| Metric | Value |
|---|---|
| Lines of code | 36,421 |
| Files analysed | 97 |
| Quality gate | **OK** (Sonar way, clean-as-you-code compliant) |
| Bugs | 18 — reliability rating **D** |
| Vulnerabilities | 2 — security rating **B** |
| Security hotspots | 0 |
| Code smells | 1,474 — maintainability rating **A** |
| Technical debt | 13,652 min (~28 days) |
| Duplication | 3.6% |
| Comment density | 16.3% |
| Total cognitive complexity | 11,443 |

Severity split: 169 critical, 311 major, 1,014 minor.

The gate passes because the Sonar way gate only judges *new* code, and this is a first analysis with no
new-code period. The absolute numbers below are what actually matters here. (The clone is shallow, so Sonar
had no blame data and could not attribute code to authors or dates — it does not affect the findings.)

## Vulnerabilities (2)

- **`server.js:774`** (javascript:S5332, minor) — Using http protocol is insecure. Use https instead.
- **`server.js:2281`** (javascript:S4036, minor) — Make sure the "PATH" variable only contains fixed, unwriteable directories.

Both are low-impact and worth a look rather than a fix-now: the `http` URL and a `child_process` call that
inherits `PATH`.

## Bugs (18)

### Sort without a comparator — `javascript:S2871` (4, critical)

`.sort()` with no compare function coerces elements to strings. On numeric or mixed data this silently
produces the wrong order.

- `bin/i18n-build.js:23`
- `bin/traffic.js:55`
- `lib/feedback.js:243`
- `lib/rtp.js:1048`

### Logic bugs (4, major/minor)

- `lib/adminlist.js:95` (javascript:S7727) — Do not pass function `accountExists` directly to `.filter(…)`.
- `lib/advisor.js:2066` (javascript:S5842) — Rework this part of the regex to not match the empty string.
- `lib/analyze.js:302` (javascript:S6959) — Add an initial value to this "reduce()" call.
- `lib/analyze.js:302` (javascript:S6959) — Add an initial value to this "reduce()" call.

`lib/adminlist.js:95` is the notable one: passing a function straight to `.filter()` hands it the index and
array as extra arguments, which breaks if the callee has optional parameters.

### Accessibility (10, major)

`Web:InputWithoutLabelCheck` — inputs with no associated `<label>`:

- `public/app.html:127`
- `public/app.html:382`
- `public/app.html:401`
- `public/hmr.html:230`
- `public/index.html:546`
- `public/kb.html:184`
- `public/kb.html:223`
- `public/settings.html:102`
- `public/settings.html:145`
- `public/settings.html:155`

## Worth attention beyond the bug count

### Super-linear regexes — `javascript:S8786` (56 findings)

Regexes whose backtracking is super-linear in input length. This matters more than usual for hiccup: the
parsers in `lib/sip.js`, `lib/textlog.js`, `lib/hmr.js` and `lib/kb.js` run over attacker-influenced trace
and log data, so a pathological input is a plausible denial-of-service path rather than a theoretical one.

Concentration by file:

- `lib/hmr.js` — 23
- `server.js` — 7
- `lib/kb.js` — 6
- `lib/textlog.js` — 5
- `lib/hmr-sim.js` — 3
- `lib/sip.js` — 3
- `lib/advisor.js` — 2
- `lib/agent.js` — 1
- `lib/detect.js` — 1
- `lib/hmr-generate.js` — 1
- `lib/mail.js` — 1
- `lib/oidc.js` — 1
- `lib/stripe.js` — 1
- `lib/teams.js` — 1

### Cognitive complexity — `javascript:S3776` (159 findings)

159 functions exceed the threshold of 15; the project total is 11,443. Highest offenders sit in `lib/hmr.js`,
`server.js`, `lib/advisor.js` and `lib/detect.js` — the same four files that carry most of the issue count.

## Distribution

### Top rules

| Count | Rule | What it says |
|---|---|---|
| 392 | `javascript:S6582` | Prefer using an optional chain expression instead, as it's more concise and easi |
| 159 | `javascript:S3776` | Refactor this function to reduce its Cognitive Complexity from 23 to the 15 allo |
| 141 | `javascript:S4138` | Expected a `for-of` loop instead of a `for` loop with this simple iteration. |
| 100 | `javascript:S7765` | Use `.includes()`, rather than `.indexOf()`, when checking for existence. |
| 96 | `javascript:S3358` | Extract this nested ternary operation into an independent statement. |
| 95 | `javascript:S7778` | Do not call `Array#push()` multiple times. |
| 69 | `javascript:S7773` | Prefer `Number.parseInt` over `parseInt`. |
| 56 | `javascript:S8786` | Simplify this regular expression to reduce its runtime, as it has super-linear p |
| 48 | `javascript:S7772` | Prefer `node:fs` over `fs`. |
| 36 | `javascript:S6594` | Use the "RegExp.exec()" method instead. |
| 32 | `javascript:S6557` | Use 'String#startsWith' method instead. |
| 25 | `javascript:S7780` | `String.raw` should be used to avoid escaping `\`. |
| 24 | `Web:S6819` | Use <output> instead of the status role to ensure accessibility across all devic |
| 22 | `javascript:S6353` | Use concise character class syntax '\d' instead of '[0-9]'. |
| 15 | `javascript:S7755` | Prefer `.at(…)` over `[….length - index]`. |

### Top files

| Count | File |
|---|---|
| 331 | `lib/hmr.js` |
| 152 | `server.js` |
| 117 | `lib/advisor.js` |
| 111 | `lib/detect.js` |
| 59 | `lib/diff.js` |
| 48 | `lib/textlog.js` |
| 45 | `lib/kb.js` |
| 44 | `lib/agent.js` |
| 43 | `lib/hmr-sim.js` |
| 37 | `lib/correlate.js` |
| 37 | `lib/ice.js` |
| 32 | `lib/isup.js` |
| 31 | `lib/sip.js` |
| 29 | `lib/rtp.js` |
| 29 | `lib/teams.js` |

## False positives noted

- **`javascript:S2681` (12 findings)** — all twelve are spurious. They flag the codebase's one-line braced
  style, e.g. `if (isBot) { out.bot++; ...; continue; }` in `lib/metrics.js:110`. The braces are present and
  the rule is misreading the formatting. No action needed.

## Reproducing

```sh
docker run -d --name sonarqube -p 9000:9000 sonarqube:community
# wait for /api/system/status to report UP, then create a token in the UI
docker run --rm --network host \
  -e SONAR_HOST_URL=http://localhost:9000 -e SONAR_TOKEN="$SONAR_TOKEN" \
  -v "$PWD:/usr/src" sonarsource/sonar-scanner-cli
```

`sonar-project.properties` in the repo root carries the source/test/exclusion layout.
