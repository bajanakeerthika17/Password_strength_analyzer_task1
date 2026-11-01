@echo off
title Push Password Strength Analyzer to GitHub
echo ===================================================================
echo  Pushing code to GitHub: bajanakeerthika17/Password_strength_analyzer_task1
echo ===================================================================

:: Ensure MinGit is in PATH
set "PATH=%LOCALAPPDATA%\Programs\MinGit\cmd;%PATH%"

echo.
echo Choose authentication method:
echo [1] Push using GitHub Personal Access Token (Recommended)
echo [2] Standard git push (will prompt for credentials)
echo.
set /p choice="Enter choice (1 or 2): "

if "%choice%"=="1" (
    echo.
    echo Generate a token at: https://github.com/settings/tokens (select 'repo' scope)
    set /p token="Paste your GitHub Personal Access Token: "
    if not "%token%"=="" (
        git remote set-url origin https://%token%@github.com/bajanakeerthika17/Password_strength_analyzer_task1.git
        git push -u origin main
        git remote set-url origin https://github.com/bajanakeerthika17/Password_strength_analyzer_task1.git
    ) else (
        echo [ERROR] Token cannot be empty.
    )
) else (
    git push -u origin main
)

echo.
echo ===================================================================
pause

