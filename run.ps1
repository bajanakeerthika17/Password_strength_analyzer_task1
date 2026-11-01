# run.ps1 - PowerShell launcher for Password Strength Analyzer
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host " Password Strength Analyzer & Cryptography Vault Server" -ForegroundColor Green
Write-Host "===================================================================" -ForegroundColor Cyan

$pyCandidate = "python"
if (-not (Get-Command "python" -ErrorAction SilentlyContinue)) {
    $localPy = "$env:LOCALAPPDATA\Python\pythoncore-3.14-64\python.exe"
    if (Test-Path $localPy) {
        $pyCandidate = $localPy
    } else {
        Write-Error "Python executable not found. Please ensure Python is installed."
        exit 1
    }
}

Write-Host "[*] Using Python: $pyCandidate" -ForegroundColor Yellow
Write-Host "[*] Verifying requirements (Flask)..." -ForegroundColor Yellow
& $pyCandidate -m pip install -r requirements.txt --quiet
Write-Host "[*] Starting Flask web application on http://127.0.0.1:5000 ..." -ForegroundColor Green
& $pyCandidate app.py

