Param(
  [string]$Local,
  [switch]$Open,
  [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'

# Move to repo root (this script lives in scripts\)
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $here '..')

# Ensure virtual environment exists
if (!(Test-Path .\.venv\Scripts\python.exe)) {
  Write-Host "Creating virtual environment (.venv)..."
  try {
    python -m venv .venv
  } catch {
    py -3 -m venv .venv
  }
}

# Activate venv for this session
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force | Out-Null
. .\.venv\Scripts\Activate.ps1

# Install/upgrade dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# Make package importable (src layout)
$env:PYTHONPATH = 'src'

# Optional: prefill local interface via env
if ($Local) { $env:LOCAL_INTERFACE = $Local }

$webUrl = "http://127.0.0.1:8000"

# Auto-open browser unless explicitly disabled
if (-not $NoBrowser) {
  Start-Process $webUrl
}

Write-Host "Starting web UI on $webUrl ..."
python -m bacnet_extractor.webapp
