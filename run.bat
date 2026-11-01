@echo off
title Password Strength Analyzer & Cryptography Vault
echo ===================================================================
echo  Password Strength Analyzer & Cryptography Vault (Internship)
echo ===================================================================

:: Check if standard python command works
where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    set PY_CMD=python
    goto RUN_SERVER
)

:: Check if local Python 3.14 is installed in LocalAppData
if exist "%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe" (
    set "PY_CMD=%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe"
    goto RUN_SERVER
)

:: Check common python installation paths
if exist "C:\Python312\python.exe" (
    set "PY_CMD=C:\Python312\python.exe"
    goto RUN_SERVER
)

if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    set "PY_CMD=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    goto RUN_SERVER
)

echo [ERROR] Python not found in PATH or standard directories.
echo Please install Python 3.10+ or add Python to your PATH.
pause
exit /b 1

:RUN_SERVER
echo [*] Using Python: %PY_CMD%
echo [*] Installing dependencies (Flask)...
"%PY_CMD%" -m pip install -r requirements.txt --quiet
echo [*] Starting Flask web server...
echo [*] Open your browser and navigate to: http://127.0.0.1:5000
echo ===================================================================
"%PY_CMD%" app.py
pause

