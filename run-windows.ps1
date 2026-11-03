param(
    [Parameter(Mandatory = $true)][string]$CredentialsPath,
    [string]$PythonExecutable = 'python.exe'
)
$ErrorActionPreference = 'Stop'
$zeekrCredentialsFile = (Resolve-Path -LiteralPath $CredentialsPath).Path
$zeekrScriptFile = Join-Path $PSScriptRoot 'zeekr_checkin.py'
$zeekrLogDirectory = Join-Path (Split-Path -Parent $zeekrCredentialsFile) 'logs'
New-Item -ItemType Directory -Path $zeekrLogDirectory -Force | Out-Null
$zeekrRunStamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')
$zeekrOutputLog = Join-Path $zeekrLogDirectory ($zeekrRunStamp + '.stdout.log')
$zeekrErrorLog = Join-Path $zeekrLogDirectory ($zeekrRunStamp + '.stderr.log')
$zeekrReportFile = Join-Path $zeekrLogDirectory 'latest.json'
$zeekrArguments = @(
    '-X', 'utf8', ('"' + $zeekrScriptFile + '"'),
    '--credentials', ('"' + $zeekrCredentialsFile + '"'), '--claim',
    '--save-report', ('"' + $zeekrReportFile + '"')
)
$zeekrProcess = Start-Process -FilePath $PythonExecutable -ArgumentList $zeekrArguments `
    -WindowStyle Hidden -Wait -PassThru `
    -RedirectStandardOutput $zeekrOutputLog -RedirectStandardError $zeekrErrorLog
exit $zeekrProcess.ExitCode
