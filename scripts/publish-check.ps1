# Build and verify an installable artifact without uploading.
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$py = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }
Remove-Item -Recurse -Force dist, build -ErrorAction SilentlyContinue
& $py -m build
& $py -m twine check dist/*
$tmp = Join-Path $env:TEMP ("deniz-publish-" + [guid]::NewGuid().ToString("N"))
& $py -m venv $tmp
& "$tmp\Scripts\pip.exe" install --quiet (Get-ChildItem dist\*.whl | Select-Object -First 1).FullName
& "$tmp\Scripts\deniz.exe" version
& "$tmp\Scripts\python.exe" -c "import deniz.kit, deniz.mcp; print('import ok')"
Remove-Item -Recurse -Force $tmp
Write-Host "artifact ok; upload to TestPyPI first"
