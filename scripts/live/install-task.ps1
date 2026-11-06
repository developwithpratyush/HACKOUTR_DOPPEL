# Run the P12 collector as a per-user Windows Scheduled Task ("Doppel Live Hunt"), so it keeps running whatever
# happens to terminals, editors or agent sessions, restarts after a crash, and starts again at every logon.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\live\install-task.ps1 [-CtDailyCap 20]
#   Remove:  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\live\uninstall-task.ps1
#   Pause until next logon:  .venv\Scripts\python.exe -m doppel.cli live stop
param([int]$CtDailyCap = 20)

$name = "Doppel Live Hunt"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script = Join-Path $PSScriptRoot "collector.ps1"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -WorkingDirectory $repo `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`" -CtDailyCap $CtDailyCap"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings -Force `
    -Description "Doppel P12 Live Hunt: judges the public Certificate Transparency stream (names only). Repo: $repo" | Out-Null
Start-ScheduledTask -TaskName $name
"Scheduled task '$name' installed and started. Status: .venv\Scripts\python.exe -m doppel.cli live status"
