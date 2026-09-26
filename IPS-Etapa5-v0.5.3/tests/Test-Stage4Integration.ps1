#Requires -Version 4.0
# End-to-end stage 4 Audit test using a temporary bridge and simulated inventory.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$env:OS='Windows_NT';$env:COMPUTERNAME='SIMULATED'
function global:Get-NetIPAddress { [CmdletBinding()]param($AddressFamily);[pscustomobject]@{InterfaceAlias='Ethernet 2';InterfaceIndex=6;IPAddress='192.168.0.16';PrefixLength=24;AddressState='Preferred'} }
function global:Get-NetRoute { [CmdletBinding()]param($AddressFamily,$DestinationPrefix);[pscustomobject]@{NextHop='192.168.0.1'} }
function global:Get-DnsClientServerAddress { [CmdletBinding()]param($AddressFamily);[pscustomobject]@{ServerAddresses=@('192.168.0.1')} }
function global:Get-NetFirewallProfile { [CmdletBinding()]param($PolicyStore);[pscustomobject]@{Name='Domain';Enabled=$true;DefaultInboundAction='Block';DefaultOutboundAction='Allow'} }
$root=Split-Path -Parent $PSScriptRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ips-stage4-integration-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$path=Join-Path $temp 'alert-live.log';$logdir=Join-Path $temp 'events'
$stamp=(Get-Date).ToString('MM/dd-HH:mm:ss.ffffff',[Globalization.CultureInfo]::InvariantCulture)
function TcpLine { param([int]$Sid,[int]$Rev,[string]$Source,[int]$SourcePort,[int]$DestinationPort)
    '{0}  [**] [1:{1}:{2}] SOC DEKMA test [**] [Classification: Detection of a Network Scan] [Priority: 3] {{TCP}} {3}:{4} -> 192.168.0.16:{5}' -f $stamp,$Sid,$Rev,$Source,$SourcePort,$DestinationPort
}
$first=TcpLine 1000003 1 '192.168.0.7' 41211 80
$lines=@(
    $first,
    (TcpLine 1000003 1 '192.168.0.3' 41220 445),
    $first,
    (TcpLine 1000003 1 '192.168.0.7' 41212 445),
    (TcpLine 1000003 1 '192.168.0.7' 41213 3389),
    (TcpLine 1000504 1 '192.168.0.7' 42000 137),
    ('{0}  [**] [1:453:8] PROTOCOL-ICMP Timestamp Request [**] [Classification: Misc activity] [Priority: 3] {{ICMP}} 192.168.0.7 -> 192.168.0.16' -f $stamp),
    ('{0}  [**] [129:15:1] Reset outside window [**] [Classification: Potentially Bad Traffic] [Priority: 2] {{TCP}} 2603:1056:2000:0038:0000:0000:0000:0002:443 -> 2800:0320:c2a6:cb00:eddd:cfd2:2a21:06f7:51385' -f $stamp)
)
try {
    [IO.File]::WriteAllText($path,(($lines -join "`n")+"`n"),(New-Object Text.UTF8Encoding($false)))
    $provider={param($stream)'SIMULATED-VOLUME:FILE1'}
    & (Join-Path $root 'IPS-watch.ps1') -RunMode Watch -BridgePath $path -EventLogDirectory $logdir -StartAt Beginning -MaxPolls 1 -FileKeyProvider $provider
    if($LASTEXITCODE -ne 0){throw 'Stage4 watcher exited with error.'}
    $files=@(Get-ChildItem -LiteralPath $logdir -Filter 'ips.*.log')
    if($files.Count -ne 1){throw 'Expected exactly one stage4 event log.'}
    $events=@(Get-Content $files[0].FullName | ForEach-Object {ConvertFrom-Json -InputObject $_})
    $expected=@{
        WATCH_STARTED=1;READER_READY=1;ALERT_OBSERVED=4;ALERT_PROTECTED=1;ALERT_DUPLICATE=1
        ALERT_OTHER_SIGNATURE=1;ALERT_UNSUPPORTED_IPV6=1;POLICY_TRACKING=2;WOULD_BLOCK=1
        BLOCK_REQUEST=1;BLOCK_SIMULATED=1
        ALERT_NO_POLICY=1;WATCH_STOPPED=1
    }
    foreach($name in $expected.Keys){
        $actual=@($events|Where-Object {$_.event -eq $name}).Count
        if($actual -ne $expected[$name]){throw "Event $name expected $($expected[$name]), got $actual."}
    }
    if(@($events|Where-Object {$_.firewall_modified}).Count -ne 0){throw 'Firewall status incorrectly changed.'}
    $would=@($events|Where-Object {$_.event -eq 'WOULD_BLOCK'})[0]
    if($would.policy_id -ne 'tcp_syn_open_scan' -or $would.src_ip -ne '192.168.0.7' -or
        $would.observed_count -ne 3 -or $would.distinct_ports -ne 3 -or $would.decision -ne 'WOULD_BLOCK') { throw 'WOULD_BLOCK fields mismatch.' }
    if(@($events|Where-Object {$_.event -eq 'WOULD_BLOCK' -and $_.src_ip -eq '192.168.0.3'}).Count -ne 0){throw 'Protected source reached WOULD_BLOCK.'}
    $simulated=@($events|Where-Object {$_.event -eq 'BLOCK_SIMULATED'})[0]
    if($simulated.src_ip -ne '192.168.0.7' -or $simulated.dst_ip -ne '192.168.0.16' -or
        $simulated.actuator_result -ne 'SIMULATED' -or $simulated.rule_name -ne 'SOC-DEKMA-IPS-V4-C0A80007-C0A80010'){
        throw 'BLOCK_SIMULATED fields mismatch.'
    }
    Write-Host 'RESULT: Stage4 integration passed; block request simulated; protected host excluded; no firewall actions.'
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
