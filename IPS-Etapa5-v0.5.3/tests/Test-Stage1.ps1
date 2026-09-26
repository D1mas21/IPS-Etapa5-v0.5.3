#Requires -Version 4.0
# Offline tests: no firewall, scheduled task or live network commands.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'modules/Configuration.psm1') -Force
Import-Module (Join-Path $root 'modules/IPv4.psm1') -Force
$template = [IO.File]::ReadAllText((Join-Path $root 'config/ips-config.json'))
$script:passed = 0
function Check {
    param([string]$Name, [scriptblock]$Test)
    & $Test
    $script:passed++
    Write-Host ('PASS ' + $Name)
}
function Assert {
    param([bool]$Condition, [string]$Message='Assertion failed')
    if (-not $Condition) { throw $Message }
}
function MustThrow {
    param([scriptblock]$Action)
    $thrown = $false
    try { & $Action | Out-Null } catch { $thrown = $true }
    Assert $thrown 'Expected rejection did not occur.'
}
function FreshConfig { ConvertFrom-Json -InputObject $template }
function FreshInventory {
    [pscustomobject]@{
        ComputerName = 'SIMULATED'; PowerShellVersion = '4.0'
        LocalAddresses = @(
            [pscustomobject]@{InterfaceAlias='Ethernet 2';InterfaceIndex=6;IPAddress='192.168.0.16';PrefixLength=24;AddressState='Preferred'},
            [pscustomobject]@{InterfaceAlias='Loopback';InterfaceIndex=1;IPAddress='127.0.0.1';PrefixLength=8;AddressState='Preferred'}
        )
        Gateways = @('192.168.0.1'); DnsServers = @('192.168.0.1')
        FirewallProfiles = @([pscustomobject]@{Name='Domain';Enabled=$true})
        Modules = @([pscustomobject]@{Name='NetSecurity';Version='2.0'},[pscustomobject]@{Name='ScheduledTasks';Version='1.0'})
    }
}
function DenyEntry {
    param([string]$Network)
    [pscustomobject]@{network=$Network;reason='Test fixture';expires_at=$null}
}
$inventory = FreshInventory
$config = Import-IPSConfiguration (Join-Path $root 'config/ips-config.json')
$resolved = Resolve-IPSConfiguration $config $inventory
Check 'User configuration accepted with matching inventory' { Assert $resolved.Valid }
foreach ($ip in @('192.168.0.16','192.168.0.1','192.168.0.3','192.168.0.15','201.222.77.13','192.168.0.4')) {
    Check ('Protected ' + $ip) { Assert ((Test-IPSAddress $ip $resolved).Decision -eq 'PROTECTED') }
}
Check 'Kali is subject to policy, never implicitly blocked' { Assert ((Test-IPSAddress '192.168.0.7' $resolved).Decision -eq 'SUBJECT_TO_POLICY') }
foreach ($ip in @('192.168.0.0','192.168.0.255','224.0.0.1','255.255.255.255','0.0.0.0','169.254.1.1')) {
    Check ('Excluded ' + $ip) { Assert ((Test-IPSAddress $ip $resolved).Decision -eq 'EXCLUDED') }
}
foreach ($ip in @('192.168.0.999','192.168.00.7','127.1','0xC0A80007','::1',' 192.168.0.7','192.168.0.7;Write-Host x')) {
    Check ('Invalid address ' + $ip) { Assert ((Test-IPSAddress $ip $resolved).Decision -eq 'INVALID_ADDRESS') }
}
Check 'Full IPv4 range arithmetic' {
    $range=Get-IPSNetworkRange '0.0.0.0/0'
    Assert ($range.Start -eq 0 -and $range.End -eq 4294967295)
}
Check 'CIDR /31 and /32 boundaries' {
    $a=Get-IPSNetworkRange '192.168.0.6/31'; $b=Get-IPSNetworkRange '192.168.0.7/32'
    Assert ($a.End -eq $b.End -and (Test-IPSRangeOverlap $a $b))
}
Check 'CIDR host bits rejected' { MustThrow { Get-IPSNetworkRange '192.168.0.7/24' } }
Check 'CIDR prefix 33 rejected' { MustThrow { Get-IPSNetworkRange '192.168.0.0/33' } }
Check 'Integer conversion high IPv4' { Assert ((ConvertFrom-IPSIPv4Number (ConvertTo-IPSIPv4Number '201.222.77.13')) -eq '201.222.77.13') }
Check 'Allowlist and denylist same IP rejected' {
    $c=FreshConfig; $c.denylist=@(DenyEntry '192.168.0.4')
    $r=Resolve-IPSConfiguration $c $inventory
    Assert (-not $r.Valid)
    Assert ((Test-IPSAddress '192.168.0.4' $r).Decision -eq 'PROTECTED')
}
Check 'Denylist subnet containing protected hosts rejected' {
    $c=FreshConfig; $c.denylist=@(DenyEntry '192.168.0.0/24')
    Assert (-not (Resolve-IPSConfiguration $c $inventory).Valid)
}
Check 'Denylist /0 rejected through protected range intersections' {
    $c=FreshConfig; $c.denylist=@(DenyEntry '0.0.0.0/0')
    Assert (-not (Resolve-IPSConfiguration $c $inventory).Valid)
}
Check 'Manual deny entry recognized but not executed' {
    $c=FreshConfig; $c.denylist=@(DenyEntry '192.168.0.7')
    $r=Resolve-IPSConfiguration $c $inventory
    Assert $r.Valid
    Assert ((Test-IPSAddress '192.168.0.7' $r).Decision -eq 'DENYLIST_MATCH')
}
Check 'Nested allow/deny overlap rejected' {
    $c=FreshConfig; $c.allowlist=@([pscustomobject]@{network='10.8.0.0/24';reason='test'})
    $c.denylist=@(DenyEntry '10.8.0.128/25')
    Assert (-not (Resolve-IPSConfiguration $c $inventory).Valid)
}
Check 'Overlapping deny entries rejected' {
    $c=FreshConfig; $c.denylist=@((DenyEntry '10.8.0.0/24'),(DenyEntry '10.8.0.8'))
    Assert (-not (Resolve-IPSConfiguration $c $inventory).Valid)
}
Check 'Wrong server rejected' {
    $c=FreshConfig; $c.protected_server='192.168.0.99'
    Assert (-not (Resolve-IPSConfiguration $c $inventory).Valid)
}
Check 'Server tentative state rejected' {
    $v=FreshInventory; $v.LocalAddresses[0].AddressState='Tentative'
    Assert (-not (Resolve-IPSConfiguration $config $v).Valid)
}
Check 'Wrong gateway rejected' {
    $v=FreshInventory; $v.Gateways=@('192.168.0.254')
    Assert (-not (Resolve-IPSConfiguration $config $v).Valid)
}
Check 'Additional gateway protected automatically' {
    $v=FreshInventory; $v.Gateways+= '192.168.0.254'
    $r=Resolve-IPSConfiguration $config $v
    Assert ((Test-IPSAddress '192.168.0.254' $r).Decision -eq 'PROTECTED')
}
Check 'Additional local IP protected automatically' {
    $v=FreshInventory
    $v.LocalAddresses+= [pscustomobject]@{InterfaceAlias='Extra';InterfaceIndex=9;IPAddress='10.9.0.5';PrefixLength=24;AddressState='Preferred'}
    $r=Resolve-IPSConfiguration $config $v
    Assert ((Test-IPSAddress '10.9.0.5' $r).Decision -eq 'PROTECTED')
}
Check 'Unprotected DNS reported, not silently whitelisted' {
    $v=FreshInventory; $v.DnsServers=@('8.8.8.8')
    $r=Resolve-IPSConfiguration $config $v
    Assert (@($r.Warnings | Where-Object {$_ -like '*DNS*8.8.8.8*'}).Count -eq 1)
}
Check 'Expired deny entry rejected' {
    $c=FreshConfig; $c.denylist=@(DenyEntry '192.168.0.7'); $c.denylist[0].expires_at='2000-01-01T00:00:00Z'
    MustThrow { Resolve-IPSConfiguration $c $inventory }
}
Check 'Future deny expiry accepted' {
    $c=FreshConfig; $c.denylist=@(DenyEntry '192.168.0.7')
    $c.denylist[0].expires_at=[DateTime]::UtcNow.AddDays(1).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    Assert (Resolve-IPSConfiguration $c $inventory).Valid
}
Check 'Invalid date rejected' {
    $c=FreshConfig; $c.denylist=@(DenyEntry '192.168.0.7'); $c.denylist[0].expires_at='2099-02-31T00:00:00Z'
    MustThrow { Resolve-IPSConfiguration $c $inventory }
}
Check 'Enforce accepted by stage 5 configuration' {
    $c=FreshConfig; $c.operation.mode='Enforce'
    $enforceResolved=Resolve-IPSConfiguration $c $inventory
    Assert $enforceResolved.Valid
}
Check 'Boolean cannot substitute integer' {
    $c=FreshConfig; $c.operation.block_seconds=$true
    MustThrow { Resolve-IPSConfiguration $c $inventory }
}
Check 'Latency thresholds accepted' {
    $c=FreshConfig
    Assert ($c.operation.delay_warning_seconds -eq 10)
    Assert ($c.operation.max_event_age_seconds -eq 30)
    Assert (Resolve-IPSConfiguration $c $inventory).Valid
}
Check 'Warning threshold must precede maximum age' {
    $c=FreshConfig; $c.operation.delay_warning_seconds=30
    MustThrow { Resolve-IPSConfiguration $c $inventory }
}
Check 'Boolean cannot substitute latency threshold' {
    $c=FreshConfig; $c.operation.delay_warning_seconds=$true
    MustThrow { Resolve-IPSConfiguration $c $inventory }
}
Check 'Singleton list must remain JSON array' {
    $c=FreshConfig; $c.allowlist=$c.allowlist[0]
    MustThrow { Resolve-IPSConfiguration $c $inventory }
}
Check 'CIDR /32 duplicate recognized' {
    $c=FreshConfig; $c.allowlist+= [pscustomobject]@{network='192.168.0.4/32';reason='dup'}
    MustThrow { Resolve-IPSConfiguration $c $inventory }
}
Check 'Unknown option rejected' {
    $c=FreshConfig; $c | Add-Member -NotePropertyName typo -NotePropertyValue $true
    MustThrow { Resolve-IPSConfiguration $c $inventory }
}
Check 'Duplicate JSON key rejected' {
    $path=Join-Path ([IO.Path]::GetTempPath()) ('dekma-test-'+[guid]::NewGuid().ToString('N')+'.json')
    try {
        [IO.File]::WriteAllText($path,$template.Replace('"schema_version": 1,','"schema_version": 1, "schema_version": 1,'))
        MustThrow { Import-IPSConfiguration $path }
    } finally { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path } }
}
Write-Host ('RESULT: {0} tests passed. Inventory simulated; no Windows API execution.' -f $script:passed)
