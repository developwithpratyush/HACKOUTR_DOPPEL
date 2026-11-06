# Remove the "Doppel Live Hunt" scheduled task (after asking the running collector to stop cleanly).
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
& (Join-Path $repo ".venv\Scripts\python.exe") -m doppel.cli live stop
Unregister-ScheduledTask -TaskName "Doppel Live Hunt" -Confirm:$false -ErrorAction SilentlyContinue
"Scheduled task removed. The catch store and recordings stay in runs/live/."
