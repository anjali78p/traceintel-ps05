# TRACEINTEL one-command start (Windows PowerShell)
# Usage:  powershell -ExecutionPolicy Bypass -File .\start.ps1
Set-Location $PSScriptRoot
if (-not (Test-Path .\.venv\Scripts\python.exe)) {
    Write-Host "First run: creating virtual environment and installing packages..."
    python -m venv .venv
    & .\.venv\Scripts\python.exe -m pip install -r requirements.txt
}
Write-Host "Open http://127.0.0.1:8000/ui/  (Ctrl+C to stop)"
& .\.venv\Scripts\python.exe -m uvicorn traceintel.api:app --reload
