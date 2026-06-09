@echo off
REM =============================================================================
REM run_guardian.bat - Lancer Guardian en arriere-plan (Windows)
REM =============================================================================
REM Usage:
REM   run_guardian.bat              # Demarrer
REM   run_guardian.bat --status     # Voir le statut
REM   run_guardian.bat --stop       # Arreter
REM =============================================================================

setlocal
cd /d "%~dp0"

if "%1"=="--status" goto status
if "%1"=="--stop" goto stop
if "%1"=="--report" goto report

:start
echo [GUARDIAN] Demarrage de l'usine de detection...
echo [GUARDIAN] Logs: guardian_output.log
echo [GUARDIAN] PID stocke dans guardian.pid
echo.

REM Kill any existing instance
if exist guardian.pid (
    set /p OLD_PID=<guardian.pid
    taskkill /F /PID %OLD_PID% 2>nul >nul
    timeout /t 1 /nobreak >nul
)

REM Start in background
start /B python guardian.py > guardian_output.log 2>&1

REM Save PID
set PID=!ERRORLEVEL!
if "%PID%"=="" set PID=%RANDOM%
powershell -Command "(Get-Process -Id $PID).Id" > guardian.pid 2>nul

echo [OK] Guardian demarre.
echo   Statut: %~dpnx0 --status
echo   Logs:   type guardian_output.log
goto end

:status
echo [GUARDIAN] Statut...
python guardian.py --status
if exist guardian.pid (
    set /p PID=<guardian.pid
    tasklist /FI "PID eq %PID%" 2>nul | findstr /I python >nul
    if not errorlevel 1 (
        echo [OK] Processus actif (PID: %PID%)
    ) else (
        echo [WARN] PID %PID% introuvable - gardien peut etre arrete
    )
) else (
    echo [INFO] Aucun PID enregistre
)
goto end

:stop
echo [GUARDIAN] Arret...
if exist guardian.pid (
    set /p PID=<guardian.pid
    taskkill /F /PID %PID% 2>nul >nul
    del guardian.pid 2>nul
    echo [OK] Processus %PID% termine
) else (
    echo [INFO] Aucun PID trouve
)
REM Backup kill all python guardian instances
taskkill /F /IM python.exe /FI "WINDOWTITLE eq guardian" 2>nul >nul

REM Nettoyage des Hardhat orphelins (ne touche PAS a Codebuff)
echo [GUARDIAN] Nettoyage des processus Hardhat orphelins...
call clean_hardhat.bat

echo [OK] Guardian arrete.
echo   Voir les logs: type guardian_output.log
goto end

:report
python guardian.py --report
goto end

:end
endlocal
