@echo off
title Push Password Strength Analyzer to GitHub
echo ===================================================================
echo  Pushing code to GitHub
echo ===================================================================

:: Ensure MinGit is in PATH
set "PATH=%LOCALAPPDATA%\Programs\MinGit\cmd;%PATH%"

echo.
echo Select target repository:
echo [1] bajanakeerthika17/Password_strength_analyzer_task1
echo [2] sriharisha2006-hash/pass_analyzer
echo.
set /p repo_choice="Enter choice (1 or 2): "

set "REPO_URL=https://github.com/bajanakeerthika17/Password_strength_analyzer_task1.git"
set "REPO_NAME=bajanakeerthika17/Password_strength_analyzer_task1"
if "%repo_choice%"=="2" (
    set "REPO_URL=https://github.com/sriharisha2006-hash/pass_analyzer.git"
    set "REPO_NAME=sriharisha2006-hash/pass_analyzer"
)

echo.
echo Target: %REPO_NAME%
echo Choose authentication method:
echo [1] Push using GitHub Personal Access Token (PAT)
echo [2] Push using SSH (Requires SSH key or Deploy Key added)
echo.
set /p auth_choice="Enter choice (1 or 2): "

if "%auth_choice%"=="1" (
    echo.
    echo Enter a GitHub Personal Access Token with 'repo' scope:
    set /p token="Paste Token: "
    if not "%token%"=="" (
        git push https://%token%@github.com/%REPO_NAME%.git main
    ) else (
        echo [ERROR] Token cannot be empty.
    )
) else (
    git push git@github.com:%REPO_NAME%.git main
)

echo.
echo ===================================================================
pause
