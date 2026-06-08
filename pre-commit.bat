@echo off
REM Pre-commit hook for Windows: run Mythril pattern tests before every commit.
REM
REM To install: copy this file to .git\hooks\pre-commit (yes, no .bat extension in hooks)
REM   copy pre-commit.bat .git\hooks\pre-commit
REM
REM To bypass (emergency only):
REM   git commit --no-verify

echo.
echo === [pre-commit] Running Mythril pattern tests ===
python test_mythril_patterns.py
IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo !!! [pre-commit] TESTS FAILED (exit code %ERRORLEVEL%) !!!
    echo !!! Fix the issues or bypass with: git commit --no-verify  !!!
    echo.
    EXIT /B 1
)

echo === [pre-commit] All tests passed ===
echo.
EXIT /B 0
