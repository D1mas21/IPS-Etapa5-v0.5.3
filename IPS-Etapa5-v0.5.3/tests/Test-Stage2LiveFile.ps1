#Requires -Version 4.0
# Checks the real Windows file identity, replacement and process-style restart.
# All reads and writes stay in a unique temporary directory; no Snort or firewall changes.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'modules\SnortReader.psm1') -Force
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ips-stage2-live-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$bridge=Join-Path $temp 'alert-live.log'
$archive=Join-Path $temp 'alert-live.old.log'
$utf8=New-Object Text.UTF8Encoding($false)
function New-TestAlert {
    param([string]$Port)
    $stamp=(Get-Date).ToString('MM/dd-HH:mm:ss.ffffff',[Globalization.CultureInfo]::InvariantCulture)
    return ('{0}  [**] [1:1000003:1] SOC DEKMA test [**] [Classification: Detection of a Network Scan] [Priority: 3] {{TCP}} 192.168.0.7:42000 -> 192.168.0.16:{1}' -f $stamp,$Port)
}
function Expect {
    param([bool]$Ok,[string]$Message)
    if (-not $Ok) { throw ('FAIL: '+$Message) }
    Write-Host ('PASS: '+$Message)
}
try {
    [IO.File]::WriteAllText($bridge,((New-TestAlert '80')+"`n"),$utf8)
    $reader=New-IPSSnortReader -StartAt End
    $first=Get-IPSSnortChunk -Path $bridge -State $reader
    Expect ($first.Signals.Count -eq 1 -and $first.Signals[0].event -eq 'READER_READY' -and
        $first.Signals[0].bytes -gt 0 -and $first.Lines.Count -eq 0) 'StartAt End skips historical line'
    $oldKey=$reader.Key

    [IO.File]::AppendAllText($bridge,((New-TestAlert '445')+"`n"),$utf8)
    $fresh=Get-IPSSnortChunk -Path $bridge -State $reader
    Expect ($fresh.Lines.Count -eq 1 -and
        (ConvertFrom-IPSSnortAlert $fresh.Lines[0].Text (Get-Date)).DestinationPort -eq 445) 'Fresh alert delivered once'
    Expect ((Get-IPSSnortChunk -Path $bridge -State $reader).Lines.Count -eq 0) 'Poll does not replay alert'

    $restarted=New-IPSSnortReader -StartAt End
    $start=Get-IPSSnortChunk -Path $bridge -State $restarted
    Expect ($start.Signals[0].event -eq 'READER_READY' -and $start.Lines.Count -eq 0 -and
        $start.Signals[0].bytes -gt 0) 'New reader skips lines from earlier process'
    [IO.File]::AppendAllText($bridge,((New-TestAlert '135')+"`n"),$utf8)
    $afterRestart=Get-IPSSnortChunk -Path $bridge -State $restarted
    Expect ($afterRestart.Lines.Count -eq 1 -and
        (ConvertFrom-IPSSnortAlert $afterRestart.Lines[0].Text (Get-Date)).DestinationPort -eq 135) 'New reader receives subsequent alert'

    Move-Item -LiteralPath $bridge -Destination $archive
    [IO.File]::WriteAllText($bridge,((New-TestAlert '139')+"`n"),$utf8)
    $rotated=Get-IPSSnortChunk -Path $bridge -State $restarted
    Expect ($restarted.Key -ne $oldKey -and @($rotated.Signals | Where-Object {$_.event -eq 'SOURCE_ROTATED'}).Count -eq 1 -and
        $rotated.Lines.Count -eq 1 -and
        (ConvertFrom-IPSSnortAlert $rotated.Lines[0].Text (Get-Date)).DestinationPort -eq 139) 'Win32 file identity detects replacement and reads new file'
    Expect ((Get-IPSSnortChunk -Path $bridge -State $restarted).Lines.Count -eq 0) 'Replacement not replayed'
    Write-Host 'RESULT: live file continuity passed; no production files or firewall touched.'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
