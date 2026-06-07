@echo off
REM =============================================================================
REM GUARDIAN — Relance infinie (Windows)
REM =============================================================================
REM Lance guardian.py sur BSC+ETH et le relance automatiquement.
REM Pour arrêter : Ctrl+C, puis répondre N à "Terminate batch job"
REM =============================================================================

cd /d "%~dp0"

set LOG_FILE=guardian_output.log
set RESTART_DELAY=10
set /a restart_count=0

echo ================================================================
echo   GUARDIAN — FOREVER MODE (BSC + ETH)
echo   Démarre: %date% %time%
echo   Log: %LOG_FILE%
echo   Redémarrage automatique si crash
echo ================================================================

:loop
set /a restart_count+=1
echo.
echo [%time%] LANCEMENT #%restart_count%
echo ----------------------------------------

python guardian.py --chains ethereum,bsc 2>&1

echo [%time%] Guardian arrete (errorlevel=%errorlevel%)

REM Quick commit of results
git add -A 2>nul
git commit -m "Auto: results after restart #%restart_count%" 2>nul
git push origin master 2>nul

echo [%time%] Redemarrage dans %RESTART_DELAY%s...
REM timeout not available on older Windows, fallback to ping
ping -n %RESTART_DELAY% 127.0.0.1 >nul 2>&1
goto loop
