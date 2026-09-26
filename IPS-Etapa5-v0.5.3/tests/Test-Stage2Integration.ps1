#Requires -Version 4.0
# End-to-end audit test using a temporary bridge and simulated Windows inventory.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$env:OS='Windows_NT';$env:COMPUTERNAME='SIMULATED'
function global:Get-NetIPAddress {
    [CmdletBinding()]param($AddressFamily)
    [pscustomobject]@{InterfaceAlias='Ethernet 2';InterfaceIndex=6;IPAddress='192.168.0.16';PrefixLength=24;AddressState='Preferred'}
}
function global:Get-NetRoute { [CmdletBinding()]param($AddressFamily,$DestinationPrefix);[pscustomobject]@{NextHop='192.168.0.1'} }
function global:Get-DnsClientServerAddress { [CmdletBinding()]param($AddressFamily);[pscustomobject]@{ServerAddresses=@('192.168.0.1')} }
function global:Get-NetFirewallProfile {
    [CmdletBinding()]param($PolicyStore)
    [pscustomobject]@{Name='Domain';Enabled=$true;DefaultInboundAction='Block';DefaultOutboundAction='Allow'}
}
$root=Split-Path -Parent $PSScriptRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ips-stage2-integration-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$path=Join-Path $temp 'alert-live.log'
$logdir=Join-Path $temp 'events'
$stamp=(Get-Date).ToString('MM/dd-HH:mm:ss.ffffff',[Globalization.CultureInfo]::InvariantCulture)
$template='{0}  [**] [1:{1}:2] SOC DEKMA test [**] [Classification: Detection of a Network Scan] [Priority: 3] {{TCP}} {2}:41211 -> 192.168.0.16:445'
$lines=@(
    ($template -f $stamp,1000703,'192.168.0.7'),
    ($template -f $stamp,1000703,'192.168.0.3'),
    ($template -f $stamp,1000703,'192.168.0.7'),
    ('{0}  [**] [1:453:8] PROTOCOL-ICMP Timestamp Request [**] [Classification: Misc activity] [Priority: 3] {{ICMP}} 192.168.0.7 -> 192.168.0.16' -f $stamp),
    ('{0}  [**] [129:15:1] Reset outside window [**] [Classification: Potentially Bad Traffic] [Priority: 2] {{TCP}} 2603:1056:2000:0038:0000:0000:0000:0002:443 -> 2800:0320:c2a6:cb00:eddd:cfd2:2a21:06f7:51385' -f $stamp)
)
try {
    [IO.File]::WriteAllText($path,(($lines -join "`n")+"`n"),(New-Object Text.UTF8Encoding($false)))
    $provider={ param($stream) 'SIMULATED-VOLUME:FILE1' }
    & (Join-Path $root 'IPS-watch.ps1') -RunMode Watch -BridgePath $path -EventLogDirectory $logdir -StartAt Beginning -MaxPolls 1 -FileKeyProvider $provider
    if ($LASTEXITCODE -ne 0) { throw 'Stage2 watcher exited with error.' }
    $files=@(Get-ChildItem -LiteralPath $logdir -Filter 'ips.*.log')
    if($files.Count -ne 1) { throw 'Expected exactly one event log.' }
    $events=@(Get-Content $files[0].FullName | ForEach-Object {ConvertFrom-Json -InputObject $_})
    foreach($name in @('WATCH_STARTED','READER_READY','ALERT_OBSERVED','ALERT_PROTECTED','ALERT_DUPLICATE','ALERT_OTHER_SIGNATURE','ALERT_UNSUPPORTED_IPV6','WATCH_STOPPED')) {
        if(@($events | Where-Object {$_.event -eq $name}).Count -ne 1) { throw ('Missing or repeated event: ' + $name) }
    }
    if(@($events | Where-Object {$_.firewall_modified}).Count -ne 0) { throw 'Firewall status incorrectly changed.' }
    $observed=@($events | Where-Object {$_.event -eq 'ALERT_OBSERVED'})[0]
    if($observed.snort_sid -ne 1000703 -or $observed.src_ip -ne '192.168.0.7' -or $observed.decision -ne 'SUBJECT_TO_POLICY') {
        throw 'Normalized fields mismatch.'
    }
    Write-Host 'RESULT: Stage2 integration passed (8 required event types; observer only; no firewall actions).'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
