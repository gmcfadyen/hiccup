@echo off
REM Self-elevating script: install hiccup as a Windows service via NSSM.
REM - Auto-starts at boot (not at logon)
REM - Auto-restarts on crash
REM - Captures stdout/stderr to log files
REM - Survives user logoff
REM
REM Run by double-clicking. Accept the UAC prompt when it appears.

NET SESSION >nul 2>&1
IF %errorLevel% NEQ 0 (
    echo Requesting admin privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo === hiccup Windows Service Installer ===
echo Running as administrator.
echo.

set "HICCUP_DIR=C:\Users\gavin\Hiccup"
set "SERVER_JS=%HICCUP_DIR%\server.js"
set "LOG_DIR=%HICCUP_DIR%\data\logs"
set "NSSM=%HICCUP_DIR%\bin\nssm.exe"

REM ---- 1. Verify NSSM exists at the known fixed location -----------------
IF NOT EXIST "%NSSM%" (
    echo NSSM not found at %NSSM%
    echo Attempting to locate after winget install...
    for /f "delims=" %%I in ('dir /b /s "%LOCALAPPDATA%\Microsoft\WinGet\Packages\NSSM*\win64\nssm.exe" 2^>nul') do (
        copy "%%I" "%NSSM%" >nul
        goto :nssmfound
    )
    echo Installing NSSM via winget...
    winget install --id NSSM.NSSM --silent --accept-source-agreements --accept-package-agreements
    for /f "delims=" %%I in ('dir /b /s "%LOCALAPPDATA%\Microsoft\WinGet\Packages\NSSM*\win64\nssm.exe" 2^>nul') do (
        copy "%%I" "%NSSM%" >nul
        goto :nssmfound
    )
    echo ERROR: nssm.exe still not found. Manual install: https://nssm.cc/download
    pause
    exit /b 1
)
:nssmfound
echo NSSM:    %NSSM%

REM ---- 2. Locate node.exe -------------------------------------------------
for /f "delims=" %%I in ('where node') do (
    set "NODE_EXE=%%I"
    goto :foundnode
)
:foundnode
echo Node:    %NODE_EXE%
echo Server:  %SERVER_JS%
echo Logs:    %LOG_DIR%

if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

REM ---- 3. Stop and remove any existing hiccup service ---------------------
sc query hiccup >nul 2>&1
IF %errorLevel% EQU 0 (
    echo Stopping existing hiccup service...
    "%NSSM%" stop hiccup >nul 2>&1
    "%NSSM%" remove hiccup confirm >nul 2>&1
)

REM ---- 4. Install the new service ------------------------------------------
echo.
echo Installing hiccup service...
"%NSSM%" install hiccup "%NODE_EXE%" "%SERVER_JS%"
"%NSSM%" set hiccup AppDirectory "%HICCUP_DIR%"
"%NSSM%" set hiccup DisplayName "hiccup SIP Analyser"
"%NSSM%" set hiccup Description "hiccup - SIP/H.323 trace analyser - Node.js server on port 8400"
"%NSSM%" set hiccup Start SERVICE_AUTO_START
"%NSSM%" set hiccup AppEnvironmentExtra PORT=8400 NODE_ENV=production
"%NSSM%" set hiccup AppStdout "%LOG_DIR%\hiccup-out.log"
"%NSSM%" set hiccup AppStderr "%LOG_DIR%\hiccup-err.log"
"%NSSM%" set hiccup AppRotateFiles 1
"%NSSM%" set hiccup AppRotateOnline 1
"%NSSM%" set hiccup AppRotateBytes 10485760
"%NSSM%" set hiccup AppThrottle 5000
"%NSSM%" set hiccup AppExit Default Restart
"%NSSM%" set hiccup AppRestartDelay 2000

REM Service runs as LocalSystem by default, same as RFPlex's service --
REM hiccup's users.json/sessions.json are also stored as plain JSON (no
REM DPAPI), so there is no meaningful security difference between LocalSystem
REM and a per-user account here; matching the sibling app's proven setup.

REM ---- 5. Start the service ------------------------------------------------
echo.
echo Starting hiccup service...
"%NSSM%" start hiccup
timeout /t 5 /nobreak >nul
sc query hiccup | findstr STATE

REM ---- 6. Verify port 8400 is responding -----------------------------------
echo.
echo Verifying server responds on port 8400...
powershell -NoProfile -Command "try { $r = Invoke-WebRequest -Uri http://127.0.0.1:8400/api/status -UseBasicParsing -TimeoutSec 10; Write-Host ('OK: HTTP ' + $r.StatusCode + ' ' + $r.Content) } catch { Write-Host ('FAIL: ' + $_.Exception.Message) }"

echo.
echo === DONE ===
echo Service "hiccup" is now registered with auto-start at boot.
echo Logs:    %LOG_DIR%
echo Manage:  Services.msc, or "sc start hiccup" / "sc stop hiccup"
echo.
pause
