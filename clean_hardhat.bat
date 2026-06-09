@echo off
REM =============================================================================
REM clean_hardhat.bat - Tue SELECTIVEMENT les processus Hardhat
REM =============================================================================
REM Tue UNIQUEMENT les node.exe dont la ligne de commande contient "hardhat"
REM Ne touche PAS a Codebuff, VS Code, ou autres applis Node.js
REM =============================================================================
REM Usage:
REM   clean_hardhat.bat              # Nettoyer les processus Hardhat
REM   clean_hardhat.bat --loop       # Surveiller et nettoyer en continu
REM   clean_hardhat.bat --check      # Verifier sans tuer
REM =============================================================================

setlocal
cd /d "%~dp0"

if /I "%1"=="--check" goto check
if /I "%1"=="--loop" goto loop

:kill
echo [HARDHAT] Recherche des processus node.exe lies a Hardhat...

REM Methode 1: wmic avec filtre LIKE (selectif)
for /F "skip=2 tokens=2 delims=," %%i in ('wmic process where "name='node.exe' and CommandLine like '%%hardhat%%'" get ProcessId /format:csv 2^>nul') do (
    if not "%%i"=="" (
        echo [KILL] PID %%i
        taskkill /F /T /PID %%i 2>nul
    )
)


echo [HARDHAT] Nettoyage termine.
goto end

:check
echo [HARDHAT] Verification des processus node.exe lies a Hardhat...
echo.

REM Lister les processus Hardhat via wmic (sans tuer)
set FOUND=0
for /F "skip=2 tokens=2 delims=," %%i in ('wmic process where "name='node.exe' and CommandLine like '%%hardhat%%'" get ProcessId /format:csv 2^>nul') do (
    if not "%%i"=="" (
        set FOUND=1
        echo   [PID %%i]
    )
)

if "%FOUND%"=="0" (
    echo [OK] Aucun processus Hardhat en cours.
) else (
    echo.
    echo  ^>^> Utilisez clean_hardhat.bat pour les tuer.
)
goto end

:loop
echo [HARDHAT] Mode surveillance continue. Ctrl+C pour arreter.
echo.
:LoopKill
call :kill
timeout /t 10 /nobreak >nul
goto LoopKill

:end
endlocal
