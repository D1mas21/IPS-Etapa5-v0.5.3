#Requires -Version 4.0
# End-to-end Audit test for delayed, stale and future Snort alerts.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$env:OS='Windows_NT';$env:COMPUTERNAME='SIMULATED'
function global:Get-NetIPAddress { [CmdletBinding()]param($AddressFamily);[pscustomobject]@{InterfaceAlias='Ethernet 2';InterfaceIndex=6;IPAddress='192.168.0.16';PrefixLength=24;AddressState='Preferred'} }
function global:Get-NetRoute { [CmdletBinding()]param($AddressFamily,$DestinationPrefix);[pscustomobject]@{NextHop='192.168.0.1'} }
function global:Get-DnsClientServerAddress { [CmdletBinding()]param($AddressFamily);[pscustomobject]@{ServerAddresses=@('192.168.0.1')} }
function global:Get-NetFirewallProfile { [CmdletBinding()]param($PolicyStore);[pscustomobject]@{Name='Domain';Enabled=$true;DefaultInboundAction='Block';DefaultOutboundAction='Allow'} }

$root=Split-Path -Parent $PSScriptRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ips-stage5-latency-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$path=Join-Path $temp 'alert-live.log';$logdir=Join-Path $temp 'events'

function Stamp {param([DateTime]$Value) $Value.ToString('MM/dd-HH:mm:ss.ffffff',[Globalization.CultureInfo]::InvariantCulture)}
function TcpLine {param([string]$Timestamp,[int]$SourcePort,[int]$DestinationPort)
    '{0}  [**] [1:1000003:1] SOC DEKMA latency test [**] [Classification: Detection of a Network Scan] [Priority: 3] {{TCP}} 192.168.0.7:{1} -> 192.168.0.16:{2}' -f $Timestamp,$SourcePort,$DestinationPort
}

$delayed=Stamp ((Get-Date).AddSeconds(-12))
$stale=Stamp ((Get-Date).AddSeconds(-45))
# Use a wide margin so slow PowerShell 4 startup cannot turn this fixture
# into an ON_TIME alert before the watcher evaluates it.
$future=Stamp ((Get-Date).AddSeconds(60))
$lines=@(
    (TcpLine $delayed 41001 80),
    (TcpLine $delayed 41002 445),
    (TcpLine $delayed 41003 3389),
    (TcpLine $stale 41004 22),
    (TcpLine $future 41005 53)
)

try{
    [IO.File]::WriteAllText($path,(($lines -join "`n")+"`n"),(New-Object Text.UTF8Encoding($false)))
    $provider={param($stream)'SIMULATED-VOLUME:LATENCY1'}
    & (Join-Path $root 'IPS-watch.ps1') -RunMode Watch -BridgePath $path -EventLogDirectory $logdir -StartAt Beginning -MaxPolls 1 -FileKeyProvider $provider
    if($LASTEXITCODE -ne 0){throw 'Stage5 latency watcher exited with error.'}
    $files=@(Get-ChildItem -LiteralPath $logdir -Filter 'ips.*.log')
    if($files.Count -ne 1){throw 'Expected exactly one Stage5 event log.'}
    $events=@(Get-Content $files[0].FullName|ForEach-Object{ConvertFrom-Json -InputObject $_})
    $observed=@($events|Where-Object{$_.event -eq 'ALERT_OBSERVED'})
    $delayedObserved=@($observed|Where-Object{$_.delivery_status -eq 'DELAYED' -and $_.delivery_delayed})
    if($observed.Count -ne 3){throw "Expected exactly 3 accepted alerts, got $($observed.Count)."}
    if($delayedObserved.Count -ne 3){throw "Expected 3 delayed accepted alerts, got $($delayedObserved.Count)."}
    if(@($events|Where-Object{$_.event -eq 'POLICY_TRACKING'}).Count -ne 2){throw 'Expected two POLICY_TRACKING events.'}
    if(@($events|Where-Object{$_.event -eq 'WOULD_BLOCK'}).Count -ne 1){throw 'Expected one WOULD_BLOCK event.'}
    if(@($events|Where-Object{$_.event -eq 'BLOCK_SIMULATED'}).Count -ne 1){throw 'Expected one BLOCK_SIMULATED event.'}
    $staleEvents=@($events|Where-Object{$_.event -eq 'ALERT_REJECTED' -and $_.decision -eq 'STALE'})
    $futureEvents=@($events|Where-Object{$_.event -eq 'ALERT_REJECTED' -and $_.decision -eq 'FUTURE'})
    if($staleEvents.Count -ne 1 -or $futureEvents.Count -ne 1){throw 'Expected one STALE and one FUTURE rejection.'}
    $stopped=@($events|Where-Object{$_.event -eq 'WATCH_STOPPED'})[0]
    if($stopped.accepted_total -ne 3 -or $stopped.delayed_total -ne 3 -or
       $stopped.stale_rejected_total -ne 1 -or $stopped.future_rejected_total -ne 1){
        throw 'WATCH_STOPPED latency counters mismatch.'
    }
    Write-Host 'RESULT: Stage5 latency integration passed; delayed alerts correlated; stale/future rejected; Audit only.'
}finally{
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
