# backup-hiccup.ps1
# ---------------------------------------------------------------------------
# Daily versioned backup of the hiccup project to the secondary HDD.
#   - Mirrors the current state to <Dest>\latest\
#   - Snapshots a full copy to <Dest>\YYYY-MM-DD\ each run
#   - Prunes snapshots older than $KeepDays
#   - Logs to <Dest>\backup.log
#
# Run manually:  powershell -NoProfile -ExecutionPolicy Bypass -File backup-hiccup.ps1
# Scheduled:     task "Hiccup Backup", daily 03:30 (RFPlex Backup runs 03:00)
#
# WHY THIS EXISTS, and why it does NOT simply reuse backup-rfplex.ps1's
# exclusion list:
#
#   1. data\ is the point. It is gitignored, so it is in no commit and on no
#      remote: users.json, config.json (the adminEmails site-admin allow-list),
#      sessions.json, projects\, captures\, kb\. A disk failure without this
#      backup loses every hiccup account outright, with no recovery path.
#
#   2. .git is DELIBERATELY INCLUDED, unlike the RFPlex script which excludes
#      it. hiccup routinely carries commits that have never been pushed, so
#      .git is not a redundant copy of a remote here -- it is the only copy of
#      that history.
#
#   3. Only node_modules is excluded. It is 90 MB of the ~107 MB total and is
#      reproducible with `npm install`; everything else is ~17 MB, which makes
#      a 30-day snapshot history cost well under a gigabyte.
#
# Live-file safety: lib\store.js writes every JSON file atomically (write tmp,
# then rename), so robocopy always reads either the complete old version or the
# complete new one. There is no torn-read window to design around, which is why
# this can run against a live service without stopping it.
#
# ASCII ONLY, ON PURPOSE: Windows PowerShell 5.1 decodes a BOM-less .ps1 as
# ANSI, so a stray em-dash or box-drawing character can make the file fail to
# parse -- which is exactly how an earlier backup script on this machine
# silently never ran. Keep it to plain ASCII.

[CmdletBinding()]
param(
  [string]$Source   = 'C:\Users\gavin\Hiccup',
  [string]$Dest     = 'F:\backups\hiccup',
  [int]   $KeepDays = 30
)

$ErrorActionPreference = 'Stop'

function Log($msg, $color = 'Gray') {
  $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $line  = "[$stamp] $msg"
  Write-Host $line -ForegroundColor $color
  if ($script:logFile) { Add-Content -Path $script:logFile -Value $line -ErrorAction SilentlyContinue }
}

# -- Sanity checks ---------------------------------------------------------
if (-not (Test-Path $Source)) {
  Write-Error "Source folder not found: $Source"
  exit 1
}
$destRoot = Split-Path $Dest -Parent
if (-not (Test-Path $destRoot)) {
  Write-Error "Destination root not reachable: $destRoot. Is the backup drive mounted?"
  exit 2
}
New-Item -ItemType Directory -Path $Dest -Force | Out-Null
$script:logFile = Join-Path $Dest 'backup.log'

Log '== hiccup backup run starting ==' 'Cyan'
Log "source: $Source"
Log "dest:   $Dest"

# Warn loudly if the thing this backup exists to protect is missing.
if (-not (Test-Path (Join-Path $Source 'data'))) {
  Log 'WARNING: no data\ directory in source -- accounts/captures will not be in this backup' 'Yellow'
}

# -- 1. Mirror current state to "latest" -----------------------------------
$latest = Join-Path $Dest 'latest'
New-Item -ItemType Directory -Path $latest -Force | Out-Null

Log 'mirroring source -> latest/ ...'
# /MIR mirrors (creates + deletes to match source). Only node_modules is
# excluded; .git and data are intentionally kept (see header).
# /R:2 /W:5 = retry twice, 5s apart, so a momentarily locked sessions.json
# does not fail the run. /NP /NDL keep the log readable.
$roboArgs = @(
  $Source, $latest,
  '/MIR',
  '/XD', (Join-Path $Source 'node_modules'),
  # config.json can hold Stripe secrets. Excluded because /MIR plus 30 dated
  # snapshots would otherwise put a live secret key in ~31 plaintext copies on
  # the backup drive, and once it is in those snapshots the only remediation is
  # rotating the key at Stripe. Prefer the service environment for the secrets
  # (STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET); everything else in config.json
  # is non-secret and cheap to re-enter.
  '/XF', 'config.json',
  '/R:2', '/W:5',
  '/NP', '/NDL'
)
& robocopy @roboArgs | Out-Null
$exit = $LASTEXITCODE
# Robocopy: 0=no change, 1=copied, 2=extra, 3=copied+extra, 4-7=warnings, 8+=errors.
if ($exit -ge 8) {
  Log "robocopy reported errors (exit $exit)" 'Red'
  exit $exit
}
Log "mirror done (robocopy exit $exit - ok)" 'Green'

# -- 2. Dated snapshot -----------------------------------------------------
$today    = Get-Date -Format 'yyyy-MM-dd'
$snapshot = Join-Path $Dest $today
if (Test-Path $snapshot) {
  Log "snapshot for $today already exists - overwriting" 'Yellow'
  Remove-Item $snapshot -Recurse -Force
}
Log "snapshotting latest/ -> $today/ ..."
& robocopy $latest $snapshot /E /R:2 /W:5 /NP /NDL /NJH /NJS | Out-Null
$exit2 = $LASTEXITCODE
if ($exit2 -ge 8) {
  Log "snapshot copy failed (exit $exit2)" 'Red'
  exit $exit2
}
$snapSize = (Get-ChildItem $snapshot -Recurse -Force -ErrorAction SilentlyContinue |
             Measure-Object -Property Length -Sum).Sum
Log ("snapshot done - {0:N1} MB" -f ($snapSize / 1MB)) 'Green'

# -- 3. Prune old snapshots ------------------------------------------------
$cutoff = (Get-Date).AddDays(-$KeepDays).Date
$pruned = 0
Get-ChildItem $Dest -Directory | Where-Object {
  $_.Name -match '^\d{4}-\d{2}-\d{2}$' -and
  $_.Name -ne 'latest' -and
  [datetime]::ParseExact($_.Name, 'yyyy-MM-dd', $null) -lt $cutoff
} | ForEach-Object {
  Log "pruning $($_.Name) (older than $KeepDays days)"
  Remove-Item $_.FullName -Recurse -Force
  $pruned++
}
Log "pruned $pruned old snapshot(s)"

# -- 4. Summary ------------------------------------------------------------
$totalSize = (Get-ChildItem $Dest -Recurse -Force -ErrorAction SilentlyContinue |
              Measure-Object -Property Length -Sum).Sum
$freeBytes = (Get-PSDrive ($Dest.Substring(0,1))).Free
Log ("backup total: {0:N1} MB - destination free: {1:N1} GB" -f ($totalSize / 1MB), ($freeBytes / 1GB)) 'Cyan'
Log '== hiccup backup run done ==' 'Cyan'
