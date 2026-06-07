@echo off
REM =============================================================================
REM GUARDIAN — Relance infinie (Windows)
REM =============================================================================
REM Lance guardian.py sur BSC+ETH, redemarre automatiquement.
REM JAMAIS de git push (mode autonome offline).
REM Arret: Ctrl+C puis N a "Terminate batch job"
REM =============================================================================

cd /d "%~dp0"

set LOG_FILE=guardian_output.log
set RESTART_DELAY=10
set /a restart_count=0

echo ================================================================
echo   GUARDIAN — FOREVER MODE (BSC + ETH)
echo   Demarrage: %date% %time%
echo   Log: %LOG_FILE%
echo   Mode: NO PUSH
echo ================================================================

:loop
set /a restart_count+=1
echo.
echo [%time%] === LANCEMENT #%restart_count% ===

python guardian.py --chains ethereum,bsc 2>&1

echo [%time%] Guardian stopped (errorlevel=%errorlevel%)

REM Dump results to findings/scanned_contracts.md
echo [%time%] Dumping results to .md...
python dump_results.py "restart_%restart_count%" 2>&1

echo [%time%] Restart in %RESTART_DELAY%s...
ping -n %RESTART_DELAY% 127.0.0.1 >nul 2>&1
goto loop
