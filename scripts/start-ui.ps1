Param(
  [string]$Local
)

$ErrorActionPreference = 'Stop'

# Move to repo root
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

if ($Local) { $env:LOCAL_INTERFACE = $Local }

Write-Host "Launching desktop UI ..."
python -m bacnet_extractor.ui_app
