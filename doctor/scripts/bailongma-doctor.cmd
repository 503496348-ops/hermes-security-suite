@echo off
rem Hermes Doctor wrapper for Windows (L-5: chained fallback py -3 / python3 / python / py)
setlocal
set "SCRIPT_DIR=%~dp0"
set "HERMES_DOCTOR=%SCRIPT_DIR%hermes_doctor.py"

where py >nul 2>&1
if not errorlevel 1 (
    py -3 "%HERMES_DOCTOR%" %*
    goto :eof
)

where python3 >nul 2>&1
if not errorlevel 1 (
    python3 "%HERMES_DOCTOR%" %*
    goto :eof
)

where python >nul 2>&1
if not errorlevel 1 (
    python "%HERMES_DOCTOR%" %*
    goto :eof
)

where py >nul 2>&1
if not errorlevel 1 (
    py "%HERMES_DOCTOR%" %*
    goto :eof
)

echo ERROR: no Python interpreter found (tried: py -3, python3, python, py) 1>&2
exit /b 127
