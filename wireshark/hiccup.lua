--
-- hiccup.lua -- a Wireshark bridge plugin for hiccup, the SIP/H.323 trace analyser.
--
-- Adds two items under Tools -> hiccup:
--   "Analyse this capture in hiccup"  -- upload the loaded capture, open the result
--   "Settings..."                     -- base URL, session cookie, browser behaviour
--
-- This is a BRIDGE, not a port. Wireshark cannot embed hiccup's UI, and a Lua
-- post-dissector cannot do hiccup's cross-leg correlation. All the plugin does is
-- get the bytes you are looking at into hiccup and open the browser at the result.
-- See README.md next to this file for install paths and the honest limitations.
--
-- Lua has no HTTP client, so the upload shells out: curl (Windows 10+ ships
-- curl.exe; macOS and Linux have it), with a PowerShell Invoke-WebRequest
-- fallback on Windows.
--
-- Nothing here throws into Wireshark: every external call is pcall'd or checked,
-- and every failure ends in a dialog that says what to do next.
--
-- Copyright (c) 2026 Gavin McFadyen. Part of hiccup; licensed under the Business
-- Source License 1.1 -- see LICENSE in the hiccup repository. Source-available,
-- not open source; production use needs a commercial licence.
--

local hiccup = {}

hiccup.plugin_version = "0.1.0"
hiccup.plugin_name = "hiccup bridge"

-- Defaults; overridden by the settings file (see settings_path()).
local DEFAULTS = {
  base_url = "http://127.0.0.1:8400",
  cookie = "",
  open_browser = "yes",
  max_mb = "50",          -- mirrors hiccup's data/config.json maxUploadMb
  timeout_sec = "300",
}

local SETTINGS_FILE = "hiccup-settings.txt"
local COOKIE_NAME = "hiccup_session"
local UPLOAD_PATH = "/api/captures"

-- ---------------------------------------------------------------------------
-- Small platform / filesystem helpers
-- ---------------------------------------------------------------------------

--- True when running on Windows (path separator in package.config is a backslash).
-- @return boolean
local function is_windows()
  return package.config:sub(1, 1) == "\\"
end

--- Directory separator for the host platform.
-- @return string
local function sep()
  if is_windows() then return "\\" end
  return "/"
end

--- Join a directory and a leaf name with the platform separator.
-- @param dir string|nil
-- @param name string
-- @return string
local function path_join(dir, name)
  if not dir or dir == "" then return name end
  local last = dir:sub(-1)
  if last == "/" or last == "\\" then return dir .. name end
  return dir .. sep() .. name
end

--- Basename of a path, tolerant of either separator.
-- @param p string|nil
-- @return string
local function basename(p)
  p = tostring(p or "")
  local b = p:match("([^/\\]+)$")
  return b or p
end

--- Read a whole file as a string, or nil when it cannot be opened.
-- @param p string
-- @return string|nil
local function read_file(p)
  if not p or p == "" then return nil end
  local f = io.open(p, "rb")
  if not f then return nil end
  local ok, data = pcall(function() return f:read("*a") end)
  f:close()
  if not ok then return nil end
  return data
end

--- Write a string to a file. Returns true on success.
-- @param p string
-- @param text string
-- @return boolean
local function write_file(p, text)
  if not p or p == "" then return false end
  local f = io.open(p, "wb")
  if not f then return false end
  local ok = pcall(function() f:write(text) end)
  f:close()
  return ok == true
end

--- Size of a file in bytes, or nil when unreadable.
-- @param p string
-- @return number|nil
local function file_size(p)
  local f = io.open(p, "rb")
  if not f then return nil end
  local ok, n = pcall(function() return f:seek("end") end)
  f:close()
  if not ok then return nil end
  return n
end

--- True when the path can be opened for reading.
-- @param p string|nil
-- @return boolean
local function file_exists(p)
  if not p or p == "" then return false end
  local f = io.open(p, "rb")
  if not f then return false end
  f:close()
  return true
end

--- Directory this script was loaded from, or nil if it cannot be determined.
-- @return string|nil
local function script_dir()
  local ok, info = pcall(debug.getinfo, 1, "S")
  if not ok or not info then return nil end
  local src = tostring(info.source or "")
  src = src:gsub("^@", "")
  local dir = src:match("^(.*)[/\\][^/\\]*$")
  if dir == "" then return nil end
  return dir
end

--- A writable temp directory.
-- @return string
local function temp_dir()
  local candidates = { os.getenv("TEMP"), os.getenv("TMP"), os.getenv("TMPDIR") }
  for i = 1, #candidates do
    local c = candidates[i]
    if c and c ~= "" then return c end
  end
  if is_windows() then return "." end
  return "/tmp"
end

local temp_counter = 0

--- A unique-ish temp file path (Lua has no mkstemp; os.tmpname is awkward on Windows).
-- @param suffix string
-- @return string
local function temp_path(suffix)
  temp_counter = temp_counter + 1
  local stamp = string.format("%d-%d-%d", os.time() or 0,
    math.floor((os.clock() or 0) * 1000), temp_counter)
  return path_join(temp_dir(), "hiccup-" .. stamp .. (suffix or ".tmp"))
end

--- Run a shell command. Normalises the Lua 5.1 vs 5.2+ os.execute return values.
-- @param cmd string
-- @return boolean ok, number code
local function run(cmd)
  local a, _, c = os.execute(cmd)
  if type(a) == "number" then return a == 0, a end
  if a == true then return true, tonumber(c) or 0 end
  return false, tonumber(c) or -1
end

-- ---------------------------------------------------------------------------
-- Dialogs (all optional -- degrade to print() if a build lacks the GUI classes)
-- ---------------------------------------------------------------------------

--- True when Wireshark's GUI (and therefore its dialogs) are available.
-- @return boolean
local function have_gui()
  if type(gui_enabled) ~= "function" then return false end
  local ok, enabled = pcall(gui_enabled)
  return ok and enabled == true
end

--- Show an informational window. Falls back to stdout.
-- @param title string
-- @param text string
local function info_dialog(title, text)
  local body = "hiccup\n" .. string.rep("-", 40) .. "\n" .. text .. "\n"
  if have_gui() and TextWindow then
    local ok, win = pcall(function() return TextWindow.new(title) end)
    if ok and win then
      local ok2 = pcall(function() win:set(body) end)
      if ok2 then return end
    end
  end
  print("[hiccup] " .. title .. ": " .. text)
end

--- Show an error. report_failure() renders a modal error box in the GUI.
-- @param text string
local function error_dialog(text)
  if type(report_failure) == "function" then
    local ok = pcall(report_failure, "hiccup: " .. text)
    if ok then return end
  end
  print("[hiccup] ERROR: " .. text)
end

--- Ask for one line of text. Wireshark's new_dialog() has no field prefill, so
--- current/suggested values are folded into the label -- blank input means keep.
-- @param title string
-- @param label string
-- @param on_ok function(string)
-- @return boolean true when the dialog was actually shown
local function ask(title, label, on_ok)
  if not have_gui() or type(new_dialog) ~= "function" then return false end
  local ok = pcall(new_dialog, title, function(value)
    local okc, err = pcall(on_ok, tostring(value or ""))
    if not okc then error_dialog("internal error: " .. tostring(err)) end
  end, label)
  return ok == true
end

-- ---------------------------------------------------------------------------
-- Settings
-- ---------------------------------------------------------------------------

--- Where the settings file lives: next to the plugin when that is writable
--- (the personal plugins folder normally is), else the personal config dir.
-- @return string path, string origin
local function settings_path()
  local dir = script_dir()
  if dir then
    local p = path_join(dir, SETTINGS_FILE)
    if file_exists(p) then return p, "plugin folder" end
  end
  local pers = nil
  if type(persconffile_path) == "function" then
    local ok, v = pcall(persconffile_path, SETTINGS_FILE)
    if ok and v and v ~= "" then pers = v end
  end
  if pers and file_exists(pers) then return pers, "personal config folder" end
  -- Nothing written yet: prefer next to the plugin, fall back to the config dir.
  if dir then return path_join(dir, SETTINGS_FILE), "plugin folder" end
  if pers then return pers, "personal config folder" end
  return path_join(temp_dir(), SETTINGS_FILE), "temp folder"
end

--- Trim leading/trailing whitespace.
-- @param s string|nil
-- @return string
local function trim(s)
  return (tostring(s or ""):gsub("^%s+", ""):gsub("%s+$", ""))
end

local settings_cache = nil

--- Load settings (cached). Malformed lines are ignored, never fatal.
-- @return table
local function load_settings()
  if settings_cache then return settings_cache end
  local cfg = {}
  for k, v in pairs(DEFAULTS) do cfg[k] = v end
  local text = read_file((settings_path()))
  if text then
    for line in tostring(text):gmatch("[^\r\n]+") do
      local l = trim(line)
      if l ~= "" and l:sub(1, 1) ~= "#" and l:sub(1, 1) ~= ";" then
        local k, v = l:match("^([%w_]+)%s*=%s*(.*)$")
        if k and DEFAULTS[k] ~= nil then cfg[k] = trim(v) end
      end
    end
  end
  settings_cache = cfg
  return cfg
end

--- Persist settings. Returns true, path on success; false, path on failure.
-- @param cfg table
-- @return boolean, string
local function save_settings(cfg)
  local p = settings_path()
  local lines = {
    "# hiccup Wireshark bridge settings.",
    "# Edit by hand, or via Tools -> hiccup -> Settings...",
    "# The session cookie is a credential: this file is as sensitive as a password.",
    "",
    "base_url = " .. tostring(cfg.base_url or DEFAULTS.base_url),
    "cookie = " .. tostring(cfg.cookie or ""),
    "open_browser = " .. tostring(cfg.open_browser or DEFAULTS.open_browser),
    "max_mb = " .. tostring(cfg.max_mb or DEFAULTS.max_mb),
    "timeout_sec = " .. tostring(cfg.timeout_sec or DEFAULTS.timeout_sec),
    "",
  }
  local ok = write_file(p, table.concat(lines, "\n"))
  if ok then settings_cache = cfg end
  return ok, p
end

-- ---------------------------------------------------------------------------
-- Sanitising -- everything below is interpolated into a shell command line
-- ---------------------------------------------------------------------------

--- Validate and normalise a base URL. Rejects anything with shell metacharacters.
-- @param s string|nil
-- @return string|nil
local function clean_base_url(s)
  local u = trim(s):gsub("%s+", "")
  u = u:gsub("/+$", "")
  local scheme, rest = u:match("^(https?://)(.+)$")
  if not scheme or not rest then return nil end
  if rest:find("[^%w%.%-_%[%]:/]") then return nil end
  return scheme .. rest
end

--- Reduce a pasted cookie to the bare hiccup_session token.
--- Accepts "abc123", "hiccup_session=abc123" or a whole Cookie header.
-- @param s string|nil
-- @return string
local function clean_cookie(s)
  local c = trim(s)
  local grabbed = c:match(COOKIE_NAME .. "=([^;%s]+)")
  if grabbed then c = grabbed end
  c = c:gsub("[^%w%-_%.=]", "")
  return c
end

--- Filename for the X-Filename header. The server strips paths itself, but keep
--- the header value tame so it cannot break out of the command line.
-- @param s string|nil
-- @return string
local function clean_filename(s)
  local n = basename(trim(s))
  n = n:gsub("[^%w%.%-_ ]", "_")
  n = trim(n)
  if n == "" then n = "wireshark-capture.pcapng" end
  if #n > 120 then n = n:sub(1, 120) end
  return n
end

--- Reject capture paths that cannot be safely quoted for the host shell.
-- @param p string
-- @return boolean ok, string|nil reason
local function path_is_shell_safe(p)
  if p:find('"', 1, true) then
    return false, 'the path contains a double quote'
  end
  if p:find("[%c]") then
    return false, "the path contains a control character"
  end
  if is_windows() then
    if p:find("%%") then
      return false, "the path contains a percent sign (cmd.exe would expand it)"
    end
  else
    if p:find("'", 1, true) then
      return false, "the path contains a single quote"
    end
  end
  return true, nil
end

--- Quote a string for the host shell.
-- @param s string
-- @return string
local function shell_quote(s)
  if is_windows() then return '"' .. s .. '"' end
  return "'" .. s .. "'"
end

--- Quote a string as a PowerShell single-quoted literal.
-- @param s string
-- @return string
local function ps_quote(s)
  return "'" .. tostring(s or ""):gsub("'", "''") .. "'"
end

-- ---------------------------------------------------------------------------
-- Which capture file are we looking at?
-- ---------------------------------------------------------------------------

-- Wireshark's Lua API has never exposed a dependable "what file is open" call.
-- Three routes are tried, cheapest first, and the last one just asks.
local state = { filename = nil, packets = 0 }

--- Route 1: some builds expose a global filename accessor. Harmless when absent.
-- @return string|nil
local function probe_api_filename()
  local ok, name = pcall(function()
    local f = rawget(_G, "get_filename")
    if type(f) == "function" then return f() end
    return nil
  end)
  if ok and type(name) == "string" and name ~= "" then return name end
  return nil
end

--- Route 2: Wireshark's recent-files list. This is a GUESS -- it is the last file
--- Wireshark recorded, which is usually but not certainly the open one, so it is
--- only ever offered as a suggestion in the confirm dialog, never uploaded blind.
-- @return string|nil
local function probe_recent_filename()
  if type(persconffile_path) ~= "function" then return nil end
  local names = { "recent_common", "recent" }
  local newest = nil
  for i = 1, #names do
    local ok, p = pcall(persconffile_path, names[i])
    if ok and p then
      local text = read_file(p)
      if text then
        -- "recent.capture_file: <path>", latest last per Wireshark's own comment.
        for value in tostring(text):gmatch("recent%.capture_file:%s*([^\r\n]+)") do
          local v = trim(value)
          if v ~= "" and file_exists(v) then newest = v end
        end
      end
    end
  end
  return newest
end

--- Run a short-lived tap over the loaded packets. Used to answer "is anything
--- loaded at all", and optionally to export those packets to `dest`.
--- Returns the packet count (0 when nothing is loaded) and an error string.
-- @param dest string|nil  when set, try to write the packets to this file
-- @return number packets, string|nil err
local function tap_packets(dest)
  if type(Listener) ~= "table" and type(Listener) ~= "userdata" then
    return 0, "this Wireshark build has no Lua Listener support"
  end
  if type(retap_packets) ~= "function" then
    return 0, "this Wireshark build cannot retap from Lua"
  end
  local okl, tap = pcall(function() return Listener.new() end)
  if not okl or not tap then return 0, "could not attach a Lua tap" end

  local count, dumper, dump_err = 0, nil, nil

  tap.packet = function()
    count = count + 1
    if dest and not dumper and not dump_err then
      -- Dumper.new_for_current() must be called while a packet is current; the
      -- exact signature has moved between releases, so try the plausible shapes.
      local ok, d = pcall(function() return Dumper.new_for_current(dest) end)
      if not ok or not d then
        ok, d = pcall(function() return Dumper.new(dest) end)
      end
      if ok and d then dumper = d else dump_err = "could not open a Dumper" end
    end
    if dumper then
      local ok = pcall(function() dumper:dump_current() end)
      if not ok then dump_err = "could not write an exported packet" end
    end
  end

  local okr, rerr = pcall(retap_packets)
  pcall(function() if dumper then dumper:flush() end end)
  pcall(function() if dumper then dumper:close() end end)
  pcall(function() tap:remove() end)

  if not okr then return count, "retap failed: " .. tostring(rerr) end
  return count, dump_err
end

-- ---------------------------------------------------------------------------
-- Upload
-- ---------------------------------------------------------------------------

--- Is curl on PATH?
-- @return boolean
local function have_curl()
  if is_windows() then
    return (run("curl.exe --version >nul 2>&1"))
  end
  return (run("command -v curl >/dev/null 2>&1"))
end

--- Last HTTP status code in a curl -D header dump.
-- @param head string|nil
-- @return number|nil
local function last_status(head)
  if not head then return nil end
  local code = nil
  for c in tostring(head):gmatch("HTTP/[%d%.]+%s+(%d%d%d)") do code = tonumber(c) end
  return code
end

--- Pull a JSON string value out of a small response body (no JSON parser here).
-- @param body string|nil
-- @param key string
-- @return string|nil
local function json_string(body, key)
  if not body then return nil end
  local v = tostring(body):match('"' .. key .. '"%s*:%s*"(.-)"')
  if not v then return nil end
  v = v:gsub("\\n", " "):gsub('\\"', '"'):gsub("\\\\", "\\")
  return v
end

--- POST the file with curl. Returns status, body, transport_error.
-- @param cfg table
-- @param path string
-- @param filename string
-- @return number|nil, string|nil, string|nil
local function post_with_curl(cfg, path, filename)
  local bodyf, headf = temp_path("-body.json"), temp_path("-head.txt")
  local exe = is_windows() and "curl.exe" or "curl"
  local parts = {
    exe,
    "-s -S",
    "--max-time " .. tostring(tonumber(cfg.timeout_sec) or 300),
    "-X POST",
    "-o " .. shell_quote(bodyf),
    "-D " .. shell_quote(headf),
    "-H " .. shell_quote("Content-Type: application/octet-stream"),
    "-H " .. shell_quote("X-Filename: " .. filename),
  }
  if cfg.cookie ~= "" then
    parts[#parts + 1] = "-H " .. shell_quote("Cookie: " .. COOKIE_NAME .. "=" .. cfg.cookie)
  end
  parts[#parts + 1] = "--data-binary " .. shell_quote("@" .. path)
  parts[#parts + 1] = shell_quote(cfg.base_url .. UPLOAD_PATH)

  -- No extra 'cmd /c' wrapper: os.execute() already goes through the shell, and
  -- nesting quotes inside cmd /c "..." is the classic way to break this.
  local _, code = run(table.concat(parts, " "))

  local head, body = read_file(headf), read_file(bodyf)
  os.remove(headf)
  os.remove(bodyf)
  local status = last_status(head)
  if not status then
    -- curl exit codes worth naming: 6 DNS, 7 connection refused, 28 timeout.
    local hint = "curl exit " .. tostring(code)
    if code == 7 then hint = "connection refused"
    elseif code == 6 then hint = "host not resolvable"
    elseif code == 28 then hint = "timed out"
    end
    return nil, body, hint
  end
  return status, body, nil
end

--- POST the file with PowerShell (Windows fallback when curl is missing).
--- The script is written to a temp .ps1 rather than fought through cmd quoting.
-- @param cfg table
-- @param path string
-- @param filename string
-- @return number|nil, string|nil, string|nil
local function post_with_powershell(cfg, path, filename)
  local bodyf, headf = temp_path("-body.json"), temp_path("-head.txt")
  local scriptf = temp_path(".ps1")
  local cookie_hdr = COOKIE_NAME .. "=" .. cfg.cookie
  local ps = table.concat({
    "$ErrorActionPreference = 'Stop'",
    "try { [Net.ServicePointManager]::SecurityProtocol = " ..
      "[Net.SecurityProtocolType]::Tls12 } catch { }",
    "$body = " .. ps_quote("") ,
    "$code = 0",
    "try {",
    "  $bytes = [System.IO.File]::ReadAllBytes(" .. ps_quote(path) .. ")",
    "  $h = @{ 'X-Filename' = " .. ps_quote(filename) .. " }",
    (cfg.cookie ~= "" and ("  $h['Cookie'] = " .. ps_quote(cookie_hdr)) or "  # no cookie set"),
    "  $r = Invoke-WebRequest -Uri " .. ps_quote(cfg.base_url .. UPLOAD_PATH) ..
      " -Method Post -Body $bytes -ContentType 'application/octet-stream'" ..
      " -Headers $h -UseBasicParsing -TimeoutSec " .. tostring(tonumber(cfg.timeout_sec) or 300),
    "  $code = [int]$r.StatusCode",
    "  $body = [string]$r.Content",
    "} catch {",
    "  $resp = $null",
    "  try { $resp = $_.Exception.Response } catch { }",
    "  if ($resp -ne $null) {",
    "    try { $code = [int]$resp.StatusCode } catch { }",
    "    try {",
    "      $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())",
    "      $body = $sr.ReadToEnd()",
    "      $sr.Close()",
    "    } catch { }",
    "  }",
    "}",
    "if ($code -ne 0) {",
    "  ('HTTP/1.1 ' + $code + ' X') | Out-File -FilePath " .. ps_quote(headf) ..
      " -Encoding ascii",
    "}",
    "$body | Out-File -FilePath " .. ps_quote(bodyf) .. " -Encoding ascii",
    "",
  }, "\r\n")

  if not write_file(scriptf, ps) then
    return nil, nil, "could not write a temporary PowerShell script"
  end
  run("powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " ..
    shell_quote(scriptf))

  local head, body = read_file(headf), read_file(bodyf)
  os.remove(headf)
  os.remove(bodyf)
  os.remove(scriptf)
  local status = last_status(head)
  if not status then return nil, body, "no HTTP response" end
  return status, body, nil
end

--- Human-readable size.
-- @param n number|nil
-- @return string
local function pretty_size(n)
  n = tonumber(n) or 0
  if n >= 1024 * 1024 then return string.format("%.1f MB", n / (1024 * 1024)) end
  if n >= 1024 then return string.format("%.1f kB", n / 1024) end
  -- string.format("%d") not tostring(): Lua 5.3+ renders 812 as "812.0".
  return string.format("%d bytes", n)
end

--- Upload one file to hiccup and report the outcome in a dialog.
-- @param path string    file to send
-- @param label string   what to call it in messages
-- @param temporary boolean  delete `path` afterwards
local function upload(path, label, temporary)
  local cfg = load_settings()
  local base = clean_base_url(cfg.base_url)
  if not base then
    error_dialog("the base URL in Settings is not usable: '" .. tostring(cfg.base_url) ..
      "'.\n\nIt should look like http://127.0.0.1:8400 -- scheme, host and port only.")
    return
  end
  cfg = {
    base_url = base,
    cookie = clean_cookie(cfg.cookie),
    open_browser = cfg.open_browser,
    max_mb = cfg.max_mb,
    timeout_sec = cfg.timeout_sec,
  }

  local safe, why = path_is_shell_safe(path)
  if not safe then
    error_dialog("cannot upload this file because " .. tostring(why) ..
      ".\n\n" .. path .. "\n\nCopy it somewhere with a plainer name and try again.")
    return
  end

  local size = file_size(path)
  if not size then
    error_dialog("cannot read the capture file:\n\n" .. path)
    return
  end
  if size == 0 then
    error_dialog("that file is empty:\n\n" .. path)
    return
  end
  local cap_mb = tonumber(cfg.max_mb) or 50
  if cap_mb > 0 and size > cap_mb * 1024 * 1024 then
    error_dialog(string.format(
      "that capture is %s, over the %d MB limit.\n\n" ..
      "hiccup's own cap is maxUploadMb in its data/config.json; the plugin's is " ..
      "max_mb in %s. Raise both, or cut the capture down in Wireshark first " ..
      "(File -> Export Specified Packets...).", pretty_size(size), cap_mb, (settings_path())))
    return
  end

  local filename = clean_filename(label)
  local status, body, transport

  if have_curl() then
    status, body, transport = post_with_curl(cfg, path, filename)
  elseif is_windows() then
    status, body, transport = post_with_powershell(cfg, path, filename)
  else
    error_dialog("curl was not found on PATH, and the PowerShell fallback is " ..
      "Windows-only.\n\nInstall curl (it is normally already there on macOS and " ..
      "Linux) and try again.")
    if temporary then os.remove(path) end
    return
  end

  if temporary then os.remove(path) end

  if not status then
    error_dialog("hiccup is not answering at " .. cfg.base_url .. " (" ..
      tostring(transport or "no response") .. ").\n\n" ..
      "Check that:\n" ..
      "  1. hiccup is running -- 'node server.js' in the hiccup folder.\n" ..
      "  2. the base URL in Tools -> hiccup -> Settings... is right (default " ..
      DEFAULTS.base_url .. ").\n" ..
      "  3. nothing local is blocking the port.\n\n" ..
      "Open " .. cfg.base_url .. " in a browser: if that fails too, it is hiccup, not the plugin.")
    return
  end

  if status == 200 or status == 201 then
    local id = json_string(body, "id")
    if not id then
      info_dialog("hiccup upload", "hiccup accepted the capture (HTTP " .. status ..
        ") but the reply did not contain a capture id.\n\nRaw reply:\n" ..
        tostring(body or "(empty)"))
      return
    end
    local url = cfg.base_url .. "/app?capture=" .. id
    local opened = false
    if tostring(cfg.open_browser):lower() ~= "no" and type(browser_open_url) == "function" then
      opened = pcall(browser_open_url, url)
    end
    info_dialog("hiccup upload", "Uploaded " .. filename .. " (" .. pretty_size(size) ..
      ") to hiccup.\n\nCapture id: " .. id .. "\n" .. url ..
      (opened and "\n\nOpened in your browser." or
        "\n\nOpen that URL to see the analysis.") ..
      "\n\n(If the app opens on the capture list rather than this capture, it is the " ..
      "newest entry in the sidebar.)")
    return
  end

  local msg = json_string(body, "error")

  if status == 401 then
    error_dialog("hiccup rejected the session (HTTP 401).\n\n" ..
      "Uploads need a signed-in session. Sign in at " .. cfg.base_url ..
      " in your browser, copy the value of the '" .. COOKIE_NAME ..
      "' cookie (DevTools -> Application/Storage -> Cookies), and paste it into " ..
      "Tools -> hiccup -> Settings...\n\nSessions last 30 days, so this is not a " ..
      "daily chore.")
  elseif status == 413 then
    error_dialog("hiccup refused the upload as too large (HTTP 413): " ..
      pretty_size(size) .. ".\n\n" .. (msg or "") ..
      "\n\nRaise maxUploadMb in hiccup's data/config.json, or export a subset of " ..
      "the packets from Wireshark first.")
  elseif status == 422 then
    error_dialog("hiccup could not make sense of that capture (HTTP 422):\n\n" ..
      (msg or "no detail given") ..
      "\n\nhiccup wants SIP or H.323 signalling. A capture with no signalling in " ..
      "it -- media only, or the wrong interface -- lands here.")
  elseif status == 501 then
    error_dialog("this hiccup server has no analysis engine deployed yet (HTTP 501)." ..
      "\n\n" .. (msg or "") .. "\n\nThe upload route needs lib/analyze.js present.")
  elseif status == 404 or status == 405 then
    error_dialog("nothing that looks like hiccup is at " .. cfg.base_url ..
      UPLOAD_PATH .. " (HTTP " .. status .. ").\n\nIs the base URL pointing at " ..
      "something else? Check Tools -> hiccup -> Settings...")
  else
    error_dialog("hiccup returned HTTP " .. status .. ".\n\n" ..
      (msg or tostring(body or "(no body)")))
  end
end

-- ---------------------------------------------------------------------------
-- Menu actions
-- ---------------------------------------------------------------------------

--- Ask for a path, then upload it.
--- Export whatever packets are loaded to a temp file and upload that. The only
--- route that works for an unsaved live capture, since there is no file to send.
-- @return boolean true when the upload was attempted
local function export_and_upload()
  local dest = temp_path(".pcapng")
  local written, derr = tap_packets(dest)
  if written and written > 0 and not derr and file_exists(dest) then
    upload(dest, "wireshark-export.pcapng", true)
    return true
  end
  os.remove(dest)
  return false
end

--- Ask which file to send. Blank takes the suggestion; "export" writes the
--- loaded packets out instead, which is what an unsaved capture needs.
-- @param suggestion string|nil
local function prompt_then_upload(suggestion)
  local label
  if suggestion then
    label = "Capture file (blank = " .. suggestion .. ", or type 'export')"
  else
    label = "Capture file path (or type 'export' to send the loaded packets)"
  end
  local shown = ask("hiccup: which capture?", label, function(value)
    local p = trim(value)
    if p:lower() == "export" then
      if not export_and_upload() then
        error_dialog("could not export the loaded packets.\n\n" ..
          "Save the capture (File -> Save As...) and give the path instead.")
      end
      return
    end
    if p == "" then p = suggestion or "" end
    p = p:gsub('^"(.*)"$', "%1")
    if p == "" then
      error_dialog("no path given, so nothing was uploaded.")
      return
    end
    if not file_exists(p) then
      error_dialog("cannot open that path:\n\n" .. p ..
        "\n\nUse the full path, and save an unsaved live capture first " ..
        "(File -> Save As...).")
      return
    end
    upload(p, basename(p), false)
  end)
  if not shown then
    error_dialog("could not work out which capture file is open, and this build " ..
      "cannot show a dialog to ask.\n\nSave the capture, then upload it from the " ..
      "hiccup web UI instead.")
  end
end

--- Tools -> hiccup -> Analyse this capture in hiccup
local function menu_analyse()
  if not have_gui() then
    error_dialog("this only works in the Wireshark GUI.")
    return
  end

  local ok, err = pcall(function()
    -- Route 1: the API, on builds that have it.
    local name = probe_api_filename()
    if name and file_exists(name) then
      state.filename = name
      upload(name, basename(name), false)
      return
    end

    -- How many packets are loaded? Also the only way to say "nothing is open".
    local count, tap_err = tap_packets(nil)
    state.packets = count or 0

    local guess = probe_recent_filename()

    if state.packets == 0 then
      -- Zero packets AND a tap error means we could not ask Wireshark, which is
      -- not the same as "nothing is loaded" -- do not claim it is. Just ask.
      if tap_err then
        prompt_then_upload(guess)
        return
      end
      if guess then
        info_dialog("hiccup", "Wireshark reports no packets loaded.\n\n" ..
          "If you meant the last file you had open, it was:\n  " .. guess ..
          "\n\nOpen a capture (or stop a running one) and try again -- or upload " ..
          "that file from the hiccup web UI at " ..
          tostring(clean_base_url(load_settings().base_url) or DEFAULTS.base_url) .. ".")
      else
        info_dialog("hiccup", "No capture is loaded.\n\n" ..
          "Open a capture file, or stop a live capture, then try " ..
          "Tools -> hiccup -> Analyse this capture in hiccup again.")
      end
      return
    end

    -- Route 2: confirm the recent-files guess. It is only ever a guess, so it
    -- is shown for confirmation rather than uploaded silently.
    if guess then
      prompt_then_upload(guess)
      return
    end

    -- Route 3: no name to be had anywhere, so export the loaded packets.
    if not export_and_upload() then prompt_then_upload(nil) end
  end)

  if not ok then
    error_dialog("something went wrong preparing the upload:\n\n" .. tostring(err) ..
      "\n\nSave the capture and upload it from the hiccup web UI instead.")
  end
end

--- Tools -> hiccup -> Settings...
local function menu_settings()
  if not have_gui() then
    error_dialog("settings can only be edited from the Wireshark GUI. Edit " ..
      (settings_path()) .. " by hand instead.")
    return
  end
  local cfg = load_settings()
  local path, origin = settings_path()
  local shown_cookie = (cfg.cookie ~= "" and
    ("set, ending " .. tostring(cfg.cookie):sub(-6)) or "not set")

  local ok = pcall(new_dialog, "hiccup settings", function(url, cookie, browser)
    local next_cfg = {
      base_url = cfg.base_url,
      cookie = cfg.cookie,
      open_browser = cfg.open_browser,
      max_mb = cfg.max_mb,
      timeout_sec = cfg.timeout_sec,
    }
    local u = trim(url)
    if u ~= "" then
      local cleaned = clean_base_url(u)
      if not cleaned then
        error_dialog("'" .. u .. "' is not a usable base URL. Nothing was saved.\n\n" ..
          "Expected something like http://127.0.0.1:8400 -- scheme, host, port.")
        return
      end
      next_cfg.base_url = cleaned
    end
    local c = trim(cookie)
    if c ~= "" then
      if c:lower() == "clear" or c == "-" then
        next_cfg.cookie = ""
      else
        local cleaned = clean_cookie(c)
        if cleaned == "" then
          error_dialog("that does not look like a session cookie value. Nothing was saved.")
          return
        end
        next_cfg.cookie = cleaned
      end
    end
    local b = trim(browser):lower()
    if b ~= "" then
      if b == "yes" or b == "y" or b == "true" then
        next_cfg.open_browser = "yes"
      elseif b == "no" or b == "n" or b == "false" then
        next_cfg.open_browser = "no"
      else
        error_dialog("answer the browser question with yes or no. Nothing was saved.")
        return
      end
    end

    local saved, where = save_settings(next_cfg)
    if not saved then
      error_dialog("could not write the settings file:\n\n" .. tostring(where) ..
        "\n\nIf the plugin lives in a read-only folder (a system-wide install), " ..
        "copy hiccup.lua into your personal plugins folder instead.")
      return
    end
    info_dialog("hiccup settings", "Saved to " .. tostring(where) .. "\n\n" ..
      "Base URL:      " .. next_cfg.base_url .. "\n" ..
      "Session cookie: " .. (next_cfg.cookie ~= "" and
        ("set, ending " .. next_cfg.cookie:sub(-6)) or "not set") .. "\n" ..
      "Open browser:  " .. next_cfg.open_browser .. "\n\n" ..
      "That file holds a live session token -- treat it like a password.")
  end,
    "Base URL (blank = keep " .. tostring(cfg.base_url) .. ")",
    "Session cookie " .. COOKIE_NAME .. " (blank = keep [" .. shown_cookie ..
      "], 'clear' = forget)",
    "Open browser after upload, yes/no (blank = keep " ..
      tostring(cfg.open_browser) .. ")")

  if not ok then
    info_dialog("hiccup settings", "This Wireshark build would not open the settings " ..
      "dialog.\n\nEdit the file by hand instead (" .. origin .. "):\n  " .. path ..
      "\n\nKeys: base_url, cookie, open_browser, max_mb, timeout_sec.")
  end
end

-- ---------------------------------------------------------------------------
-- Registration
-- ---------------------------------------------------------------------------

-- A "/" in the name makes Wireshark build the Tools -> hiccup submenu.
if type(register_menu) == "function" then
  local group = MENU_TOOLS_UNSORTED or 0
  pcall(register_menu, "hiccup/Analyse this capture in hiccup", menu_analyse, group)
  pcall(register_menu, "hiccup/Settings...", menu_settings, group)
end

hiccup.analyse = menu_analyse
hiccup.settings = menu_settings

return hiccup
