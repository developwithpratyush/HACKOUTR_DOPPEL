# Start the P12 collector supervisor detached from this terminal (it keeps running after the terminal closes).
# Created through WMI, so it isn't a child of this shell and survives the shell's exit.
param([int]$CtDailyCap = 20)

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script = Join-Path $PSScriptRoot "collector.ps1"
$cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`" -CtDailyCap $CtDailyCap"
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd; CurrentDirectory = $repo }
if ($r.ReturnValue -eq 0) { "supervisor started, pid $($r.ProcessId). Status: .venv\Scripts\python.exe -m doppel.cli live status" }
else { "failed to start (WMI return value $($r.ReturnValue))"; exit 1 }
