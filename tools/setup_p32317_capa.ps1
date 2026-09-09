param([string]$CapaEnvDir = "", [string]$PythonLauncher = "py")
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
if (-not $CapaEnvDir) { $CapaEnvDir = Join-Path $ProjectRoot ".venv-capa" }
$CapaEnvDir = [System.IO.Path]::GetFullPath($CapaEnvDir)
& $PythonLauncher -3.12 -m venv $CapaEnvDir
if ($LASTEXITCODE -ne 0) { throw "Python 3.12 venv creation failed" }
$CapaPython = Join-Path $CapaEnvDir "Scripts\python.exe"
$Requirements = Join-Path $ProjectRoot "CAPEsolo\data\capa\requirements.txt"
& $CapaPython -m pip install -r $Requirements
if ($LASTEXITCODE -ne 0) { throw "capa dependency installation failed" }
& $CapaPython -m capa.main --version
if ($LASTEXITCODE -ne 0) { throw "capa preflight failed" }
$SettingsPath = Join-Path $ProjectRoot "CAPEsolo\data\capa\settings.json"
$Settings = Get-Content -Raw $SettingsPath | ConvertFrom-Json
$Settings.python = $CapaPython
$Settings.executable = ""
$Settings.enabled = $true
[System.IO.File]::WriteAllText($SettingsPath, ($Settings | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Configured capa 9.4.0: $CapaPython"
Write-Host "Run checks: & '$CapaPython' '$PSScriptRoot\p32317_selftest.py'"
