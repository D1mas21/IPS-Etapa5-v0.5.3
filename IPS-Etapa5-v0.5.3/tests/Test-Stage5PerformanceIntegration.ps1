#Requires -Version 4.0
# End-to-end Audit validation of performance telemetry. No real firewall actions.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$env:OS='Windows_NT';$env:COMPUTERNAME='SIMULATED'
function global:Get-NetIPAddress { [CmdletBinding()]param($AddressFamily);[pscustomobject]@{InterfaceAlias='Ethernet 2';InterfaceIndex=6;IPAddress='192.168.0.16';PrefixLength=24;AddressState='Preferred'} }
function global:Get-NetRoute { [CmdletBinding()]param($AddressFamily,$DestinationPrefix);[pscustomobject]@{NextHop='192.168.0.1'} }
function global:Get-DnsClientServerAddress { [CmdletBinding()]param($AddressFamily);[pscustomobject]@{ServerAddresses=@('192.168.0.1')} }
function global:Get-NetFirewallProfile { [CmdletBinding()]param($PolicyStore);[pscustomobject]@{Name='Domain';Enabled=$true;DefaultInboundAction='Block';DefaultOutboundAction='Allow'} }

$root=Split-Path -Parent $PSScriptRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ips-stage5-performance-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$path=Join-Path $temp 'alert-live.log';$logdir=Join-Path $temp 'events'
$stamp=(Get-Date).ToString('MM/dd-HH:mm:ss.ffffff',[Globalization.CultureInfo]::InvariantCulture)
$line='{0}  [**] [1:1000003:1] SOC DEKMA performance test [**] [Classification: Detection of a Network Scan] [Priority: 3] {{TCP}} 192.168.0.7:41001 -> 192.168.0.16:80' -f $stamp

try{
    [IO.File]::WriteAllText($path,($line+"`n"),(New-Object Text.UTF8Encoding($false)))
    $provider={param($stream)'SIMULATED-VOLUME:PERFORMANCE1'}
    & (Join-Path $root 'IPS-watch.ps1') -RunMode Watch -BridgePath $path -EventLogDirectory $logdir -StartAt Beginning -MaxPolls 1 -FileKeyProvider $provider
    if($LASTEXITCODE -ne 0){throw 'Performance watcher exited with error.'}
    $files=@(Get-ChildItem -LiteralPath $logdir -Filter 'ips.*.log')
    if($files.Count -ne 1){throw 'Expected exactly one performance event log.'}
    $events=@(Get-Content $files[0].FullName|ForEach-Object{ConvertFrom-Json -InputObject $_})
    $samples=@($events|Where-Object{$_.event -eq 'PERFORMANCE_SAMPLE'})
    if($samples.Count -ne 1){throw "Expected one PERFORMANCE_SAMPLE, got $($samples.Count)."}
    $sample=$samples[0]
    foreach($name in @('bridge_delivery_ms','decision_ms','log_mutex_wait_ms','log_file_write_ms','console_write_ms','policy_engine_ms','actuator_ms','actuator_pipeline_ms','unattributed_ms','total_processing_ms','slow_processing','primary_delay','primary_delay_ms')){
        if($sample.PSObject.Properties.Name -cnotcontains $name){throw "Missing performance field: $name"}
    }
    foreach($name in @('decision_ms','log_mutex_wait_ms','log_file_write_ms','console_write_ms','policy_engine_ms','actuator_ms','actuator_pipeline_ms','unattributed_ms','total_processing_ms','primary_delay_ms')){
        if([double]$sample.$name -lt 0){throw "Negative performance field: $name"}
    }
    if($sample.snort_sid -ne 1000003 -or $sample.src_ip -ne '192.168.0.7'){throw 'Performance alert identity mismatch.'}
    if(@($events|Where-Object{$_.firewall_modified}).Count -ne 0){throw 'Performance test modified firewall status.'}
    Write-Host 'RESULT: Stage5 performance integration passed; component timings emitted; Audit only.'
}finally{
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
