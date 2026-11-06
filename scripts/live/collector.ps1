# P12 Live Hunt: keep the collector running until the finale.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\live\collector.ps1            # foreground
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\live\start-background.ps1     # detached
#
# Restarts the collector when it crashes (any exit code except 0 = asked to stop, 3 = already running).
# Stop it with:  .venv\Scripts\python.exe -m doppel.cli live stop
# Keep the laptop awake (Settings > Power: never sleep when plugged in), or the stream pauses with it.
param([int]$CtDailyCap = 20)

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $repo
$py = Join-Path $repo ".venv\Scripts\python.exe"
$log = Join-Path $repo "runs\live\live\supervisor.log"
New-Item -ItemType Directory -Force (Split-Path $log) | Out-Null

while ($true) {
    Add-Content -Path $log -Value "$(Get-Date -Format o) starting collector (cap $CtDailyCap)" -Encoding utf8
    & $py -m doppel.cli live run --quiet --ct-daily-cap $CtDailyCap
    $code = $LASTEXITCODE
    Add-Content -Path $log -Value "$(Get-Date -Format o) collector exited with $code" -Encoding utf8
    if ($code -eq 0 -or $code -eq 3) { break }
    Start-Sleep -Seconds 30
}
