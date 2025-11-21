# Triton Edge Data Gateway

Thin web UI for extracting BACnet data.

## Prerequisites
- Python 3.10+ and pip
- PowerShell (for the helper script)
- Optional: copy `.env.example` to `.env` and fill in values

## Quick start
```powershell
cd C:\Projects\bacnet-extractor
.\scripts\start-web.ps1        # creates .venv, installs deps, runs the app
