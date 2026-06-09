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

REM Methode 2: PowerShell (complement si wmic echoue)
powershell -Command "
    $procs = Get-CimInstance Win32_Process -Filter """name='node.exe'""" | Where-Object { $_.CommandLine -match 'hardhat' };
    if ($procs) {
        Write-Host ('[KILL] ' + $procs.Count + ' processus Hardhat trouves');
        $procs | ForEach-Object { taskkill /F /T /PID $_.ProcessId 2>&1 | Out-Null };
    } else {
        Write-Host '[OK] Aucun processus Hardhat trouve';
    }
" 2>nul

echo [HARDHAT] Nettoyage termine.
goto end

:check
echo [HARDHAT] Verification des processus node.exe lies a Hardhat...
echo.
powershell -Command "
    $procs = Get-CimInstance Win32_Process -Filter """name='node.exe'""" | Where-Object { $_.CommandLine -match 'hardhat' };
    if ($procs) {
        Write-Host ('[!] ' + $procs.Count + ' processus Hardhat en cours:');
        $procs | ForEach-Object {
            $cmd = $_.CommandLine.Substring(0, [Math]::Min(120, $_.CommandLine.Length));
            Write-Host ('    PID ' + $_.ProcessId + ' -> ' + $cmd);
        };
    } else {
        Write-Host '[OK] Aucun processus Hardhat en cours.';
    }
" 2>nul
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
