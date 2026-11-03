param(
    [Parameter(Mandatory = $true)][string]$CredentialsPath,
    [string]$TaskName = 'Zeekr-Personal-Checkin',
    [string]$PythonExecutable = 'python.exe'
)
$ErrorActionPreference = 'Stop'
if ((Get-TimeZone).Id -ne 'China Standard Time') {
    throw 'This installer expects Beijing local time. Adjust the triggers explicitly for another timezone.'
}
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    throw 'A task with this name already exists. Inspect it before replacing it.'
}
$zeekrCredentialsFile = (Resolve-Path -LiteralPath $CredentialsPath).Path
$zeekrPythonFile = (Get-Command $PythonExecutable -ErrorAction Stop).Source
$zeekrRunnerFile = Join-Path $PSScriptRoot 'run-windows.ps1'
$zeekrWindowsPowerShell = Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
$zeekrActionArguments = '-NoProfile -NonInteractive -WindowStyle Hidden -File "' + $zeekrRunnerFile +
    '" -CredentialsPath "' + $zeekrCredentialsFile + '" -PythonExecutable "' + $zeekrPythonFile + '"'
$zeekrAction = New-ScheduledTaskAction -Execute $zeekrWindowsPowerShell `
    -Argument $zeekrActionArguments -WorkingDirectory $PSScriptRoot
$zeekrCurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$zeekrTriggers = @(
    (New-ScheduledTaskTrigger -Daily -At '08:10'),
    (New-ScheduledTaskTrigger -Daily -At '08:20'),
    (New-ScheduledTaskTrigger -AtLogOn -User $zeekrCurrentIdentity)
)
$zeekrPrincipal = New-ScheduledTaskPrincipal -UserId $zeekrCurrentIdentity `
    -LogonType Interactive -RunLevel Limited
$zeekrSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew `
    -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 10) `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
Register-ScheduledTask -TaskName $TaskName -Action $zeekrAction -Trigger $zeekrTriggers `
    -Principal $zeekrPrincipal -Settings $zeekrSettings `
    -Description 'Personal Zeekr sign-in and existing reward collection at 08:10 and 08:20 Beijing time, with logon catch-up.' |
    Select-Object TaskName, State
