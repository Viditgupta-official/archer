param([ValidateSet('debug','release')][string]$BuildProfile='release')
$ErrorActionPreference='Stop'
if (-not $env:ARCHER_API_TOKEN) { throw 'Set ARCHER_API_TOKEN in the service environment first.' }
$binary=Join-Path (Split-Path $PSScriptRoot -Parent) "target/$BuildProfile/archer-api.exe"
if (-not (Test-Path -LiteralPath $binary)) { throw "Build first: cargo build --locked --release --features api --bins" }
& $binary
exit $LASTEXITCODE
