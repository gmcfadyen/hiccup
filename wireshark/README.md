# hiccup ↔ Wireshark bridge

A small Lua plugin that adds two items to Wireshark's **Tools** menu:

```
Tools -> hiccup -> Analyse this capture in hiccup
Tools -> hiccup -> Settings...
```

The first uploads the capture you are looking at to a running hiccup and opens your
browser at the analysis. The second stores the hiccup base URL, your session cookie, and
whether to open the browser.

**It is a bridge, not a port.** Read [What it cannot do](#what-it-cannot-do) before you
form expectations — that section is the honest part of this file, and it is deliberately
longer than the install instructions.

---

## Install

Drop `hiccup.lua` into your **personal Lua plugins** folder. Wireshark tells you exactly
where that is: **Help → About Wireshark → Folders**, then the *Personal Lua Plugins* row —
double-click the path to open it. Use that in preference to the table below, which is only
the usual answer:

| OS | Personal Lua plugins folder |
|---|---|
| Windows | `%APPDATA%\Wireshark\plugins` |
| macOS | `~/.local/lib/wireshark/plugins` (older builds: `~/.config/wireshark/plugins`) |
| Linux | `~/.local/lib/wireshark/plugins` |

Create the folder if it does not exist. Then either restart Wireshark or use
**Analyze → Reload Lua Plugins** (`Ctrl+Shift+L`), which is faster and picks up edits.

The personal folder is the right one for three reasons: it needs no administrator rights,
it survives Wireshark upgrades, and the plugin can write its settings file next to itself.
A system-wide install (`C:\Program Files\Wireshark\plugins`, `/usr/lib/wireshark/plugins`)
also loads, but the settings file then falls back to your personal configuration folder.

Requirements: Wireshark with Lua enabled (the standard builds are; *Help → About* says so
under *Lua*), and `curl` — present by default on Windows 10+, macOS and virtually every
Linux. On Windows without curl the plugin falls back to PowerShell.

## Set it up

1. **Start hiccup**: `node server.js` in the hiccup folder. It listens on
   <http://127.0.0.1:8400> by default.
2. **Sign in** to hiccup in your browser and create an account if you have not.
3. **Copy the session cookie.** Uploads are authenticated, and the cookie is `HttpOnly`,
   so no script can read it for you — you copy it by hand, once every 30 days:
   - Chrome / Edge: `F12` → **Application** → Storage → **Cookies** →
     `http://127.0.0.1:8400` → the row `hiccup_session` → copy the **Value**.
   - Firefox: `F12` → **Storage** → **Cookies** → same row.
   - Safari: enable the Develop menu, then Web Inspector → **Storage** → Cookies.
4. **Paste it** into *Tools → hiccup → Settings…*. Each field takes blank to mean "leave
   this as it is", so you can set the cookie without retyping the URL. Typing `clear` in
   the cookie field forgets it.
5. Open a capture and run *Tools → hiccup → Analyse this capture in hiccup*.

Sessions are 30-day sliding, so step 3 is not a daily chore. If uploads start failing with
a 401, that is the cue to repeat it.

## Settings

Stored as plain `key = value` lines in `hiccup-settings.txt`, kept next to `hiccup.lua`
when that folder is writable, otherwise in your personal Wireshark configuration folder.
The Settings dialog reports the path it used.

| Key | Default | Meaning |
|---|---|---|
| `base_url` | `http://127.0.0.1:8400` | Where hiccup is. Scheme, host, port, optional path prefix. |
| `cookie` | *(empty)* | The `hiccup_session` value. **This is a credential.** |
| `open_browser` | `yes` | Open the analysis after a successful upload. |
| `max_mb` | `50` | Refuse to upload beyond this, mirroring hiccup's own `maxUploadMb`. |
| `timeout_sec` | `300` | Upload timeout. hiccup analyses synchronously, so allow for it. |

`max_mb` and `timeout_sec` are file-only — edit them by hand. If you raise hiccup's
`maxUploadMb` in its `data/config.json`, raise `max_mb` here to match, or the plugin will
stop the upload before it starts.

**That file contains a live session token.** Anyone who can read it can act as you in
hiccup. It is as sensitive as a saved password, and your plugins folder is probably not
where you would have chosen to keep one.

## What actually happens

1. **Which file?** Wireshark's Lua API has never exposed a dependable "what capture is
   open" call, so the plugin tries, in order:
   - a global filename accessor, on builds that have one (a forward-compatible probe —
     harmless where it is absent, which is most places);
   - a short-lived `Listener` + `retap_packets()` to count the loaded packets, which is the
     only honest way to distinguish *no capture loaded* from *cannot tell*;
   - Wireshark's own recent-files list as a **suggestion** — never used silently, because
     the most recently recorded file is usually but not certainly the open one;
   - a text-entry dialog, which is also the answer when everything else fails. Blank input
     accepts the suggestion shown in the field label.

   **Unsaved live captures** have no file to send, so type `export` in that dialog instead
   of a path: the plugin writes the loaded packets to a temporary file via the Lua `Dumper`
   and uploads that, deleting it afterwards. The same export runs automatically when no
   filename can be resolved at all.

2. **Upload.** Lua has no HTTP client, so this shells out: `curl` with
   `--data-binary @file`, an `X-Filename` header, and `Cookie: hiccup_session=…`, to
   `POST <base_url>/api/captures`. On Windows without curl, a temporary PowerShell script
   using `Invoke-WebRequest` does the same job (written to a file rather than fought
   through `cmd.exe` quoting). Response headers and body go to temp files, which are
   deleted immediately.

3. **Open.** On `200`, the reply's capture id becomes
   `<base_url>/app?capture=<id>` and `browser_open_url()` opens it.

The plugin never parses your capture and never sends anything anywhere except the bytes,
to the base URL you configured. hiccup stores the upload as
`data/captures/<userId>/<captureId>/original.bin` on whatever machine hiccup is running
on — which is your own, unless you pointed `base_url` somewhere else.

## What it cannot do

This is the section that matters, and none of it is a bug to be filed.

**A Wireshark plugin cannot embed hiccup's UI.** Lua's GUI surface in Wireshark is a menu
item, a plain text window, a simple field dialog, and a progress dialog. That is all.
There is no way to render hiccup's ladder, its two-column diff cards, its indicator lamps
or its chat drawer inside Wireshark, and no amount of Lua changes that. Hence a bridge:
Wireshark stays the capture tool, hiccup does the analysis, and the plugin is the doorway
between them.

**A Lua post-dissector cannot replicate the analysis.** This is the more interesting
limit. A dissector is handed one packet at a time and asked what it is. hiccup's actual
value is everything that is *not* per-packet:

- pairing an ingress dialog with its egress dialog across a B2BUA, using weighted signals
  (`P-Charging-Vector` icid, SDP `o=` session id, sub-second temporal proximity, surviving
  user parts, Via/Contact rewrite shape) and refusing to guess when two candidates are
  within 0.15 of each other;
- diffing the two INVITEs the SBC believed were the same call, by category, and explaining
  each delta;
- collapsing seven retransmissions into one row and classifying *why* they happened from
  the pattern and the timing;
- separating "this call is broken" from "the box is melting" by looking across all
  concurrent dialogs at once;
- correlating a SIP leg with an H.323 leg through an IWF.

Every one of those needs the whole capture in memory at once, a model of legs and calls,
and a place to show two things side by side. Wireshark's own *Telephony → VoIP Calls* is
written in C, not Lua, and even that does not pair B2BUA legs. So the bridge is not
laziness — it is the only integration that is actually worth having.

**Other honest limits:**

- **Filename resolution is best-effort**, for the reasons above. Expect the confirmation
  dialog rather than being surprised by it; blank input takes the suggestion.
- **Wireshark blocks while the upload runs.** hiccup analyses synchronously, so a large
  capture means a pause with no progress bar. Raise `timeout_sec` rather than assuming it
  has hung.
- **A console window may flash on Windows.** `os.execute` goes through `cmd.exe`; Lua
  cannot suppress that.
- **Paths containing a double quote are refused**, and on Windows so are paths containing
  `%` (`cmd.exe` would try to expand it). Copy the file somewhere plainer.
- **This is not a dissector.** It does not change how Wireshark decodes anything, adds no
  fields, and no filter expressions come from it.
- **Nothing here decrypts anything.** If the capture is TLS or SRTP, uploading it will not
  help — see `docs/DECRYPTION.md` in the hiccup repository for what does.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| No **hiccup** entry under Tools | The plugin did not load. Check it is in the *Personal Lua Plugins* folder from *Help → About → Folders*, then *Analyze → Reload Lua Plugins*. If Lua itself is disabled, *Help → About* will not list a Lua version. |
| "hiccup is not answering at …" | hiccup is not running, or `base_url` is wrong. Open the base URL in a browser: if that also fails, it is hiccup, not the plugin. `connection refused` in the message means nothing is listening on that port. |
| HTTP 401 | The session cookie is missing, stale, or was pasted with surrounding characters. Re-copy it (step 3) and paste it again. |
| HTTP 422 | hiccup parsed the file but found no SIP or H.323 signalling — usually the wrong interface, or a media-only capture. The message from hiccup is shown verbatim. |
| HTTP 413, or "over the 50 MB limit" | Raise `maxUploadMb` in hiccup's `data/config.json` **and** `max_mb` in the plugin settings, or cut the capture down first with *File → Export Specified Packets…*. |
| HTTP 501 | That hiccup server has no analysis engine deployed (`lib/analyze.js` missing). |
| "No capture is loaded" with a capture visibly open | The tap could not run — try after the capture has finished loading, or stop a live capture first. Worst case, save the file and give the path in the dialog. |
| Settings will not save | The plugin is in a read-only folder. Copy `hiccup.lua` to your personal plugins folder instead. |
| curl not found (non-Windows) | Install curl. The PowerShell fallback is Windows-only. |

## Verification status

Honest account of what has and has not been exercised, because there is no Wireshark on
the machine this was built on:

- **Syntax**: parses clean as Lua 5.1, 5.2 and 5.3 (Wireshark builds ship 5.1 through
  5.4; nothing version-specific is used — no `goto`, no integer division, no bitwise
  operators, and `os.execute`'s Lua 5.1-vs-5.2 return convention is handled explicitly).
  Pure ASCII, so no encoding surprises.
- **Logic**: the URL/cookie/filename sanitisers, HTTP status parsing, JSON field
  extraction, size formatting, settings loading, menu registration and both menu actions
  were run under a Lua VM with Wireshark's globals stubbed. Shell-injection attempts
  through the base URL and cookie are rejected; the oversize, unreadable-file,
  unsafe-path, 401, 413, 422, 501 and server-down paths each end in the intended dialog.
- **The curl command line** was run for real through `cmd.exe` against a stub endpoint: a
  capture filename containing a space arrived with the right method, URL, `X-Filename`,
  cookie, content type and byte count.
- **The generated PowerShell** was checked with PowerShell 5.1's own parser and embedded
  values are correctly single-quote-escaped.
- **Not yet exercised inside Wireshark**: the menu appearing where it should, the
  `Listener`/`retap_packets` packet count, and the `Dumper` export of an unsaved capture.
  Those three are the parts to try first, and the `Dumper` path in particular is defensive
  about the exact constructor signature because that has moved between releases. Every one
  of them degrades to the text-entry dialog rather than an error if it misbehaves.

## Licence

Part of hiccup, under the Business Source License 1.1 — source-available, **not** open
source; production use needs a commercial licence. See `LICENSE`,
`LICENSE-COMMERCIAL.md` and `NOTICE` in the hiccup repository.
