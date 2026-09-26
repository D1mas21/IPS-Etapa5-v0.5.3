#Requires -Version 4.0
# Unit tests for the Stage 4 actuator. All firewall operations are simulated.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'modules\Configuration.psm1') -Force
Import-Module (Join-Path $root 'modules\FirewallActuator.psm1') -Force
$script:passed=0
function Assert {param([bool]$Condition,[string]$Message='Assertion failed');if(-not $Condition){throw $Message}}
function Check {param([string]$Name,[scriptblock]$Test);& $Test;$script:passed++;Write-Host ('PASS '+$Name)}
function MustThrow {param([scriptblock]$Action);$thrown=$false;try{& $Action|Out-Null}catch{$thrown=$true};Assert $thrown 'Expected rejection did not occur.'}
function New-Resolved {
    $config=Import-IPSConfiguration (Join-Path $root 'config\ips-config.json')
    $inventory=[pscustomobject]@{
        ComputerName='SIMULATED';PowerShellVersion='4.0'
        LocalAddresses=@([pscustomobject]@{InterfaceAlias='Ethernet 2';InterfaceIndex=6;IPAddress='192.168.0.16';PrefixLength=24;AddressState='Preferred'})
        Gateways=@('192.168.0.1');DnsServers=@('192.168.0.1')
        FirewallProfiles=@([pscustomobject]@{Name='Domain';Enabled=$true})
        Modules=@([pscustomobject]@{Name='NetSecurity';Version='2.0'},[pscustomobject]@{Name='ScheduledTasks';Version='1.0'})
    }
    Resolve-IPSConfiguration $config $inventory
}
function New-FakeAdapter {
    param([switch]$BadVerification)
    $global:IPSStage4FakeRules=@{}
    $global:IPSStage4BadVerification=[bool]$BadVerification
    [pscustomobject]@{
        Kind='Simulated'
        GetRule={param([string]$Name);if($global:IPSStage4FakeRules.ContainsKey($Name)){@($global:IPSStage4FakeRules[$Name])}else{@()}}
        CreateRule={param([string]$Name,[string]$Source,[string]$Destination)
            if($global:IPSStage4FakeRules.ContainsKey($Name)){throw 'duplicate fake rule'}
            $global:IPSStage4FakeRules[$Name]=[pscustomobject]@{Name=$Name;Source=$Source;Destination=$Destination}
            $global:IPSStage4FakeRules[$Name]
        }
        RemoveRule={param([string]$Name);if(-not $global:IPSStage4FakeRules.ContainsKey($Name)){throw 'missing fake rule'};$global:IPSStage4FakeRules.Remove($Name)}
        GetAddressFilter={param($Rule)
            if($global:IPSStage4BadVerification){[pscustomobject]@{RemoteAddress=@('10.0.0.99');LocalAddress=@($Rule.Destination)}}
            else{[pscustomobject]@{RemoteAddress=@($Rule.Source);LocalAddress=@($Rule.Destination)}}
        }
    }
}
function New-TestActuator {
    param([string]$Mode='Enforce',[int]$Maximum=256,[switch]$BadVerification)
    $adapter=New-FakeAdapter -BadVerification:$BadVerification
    $state=Join-Path $script:temp ([Guid]::NewGuid().ToString('N')+'.json')
    New-IPSFirewallActuator -Mode $Mode -StatePath $state -Resolved $script:resolved -MaxActiveBlocks $Maximum -Adapter $adapter
}
$script:temp=Join-Path ([IO.Path]::GetTempPath()) ('ips-stage4-unit-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $script:temp
try{
    $script:resolved=New-Resolved
    Check 'Audit simulates without rule or state file' {
        $a=New-TestActuator -Mode Audit
        $r=Invoke-IPSBlockRequest $a '192.168.0.7' '192.168.0.16' 'tcp_syn_open_scan' 300 ([DateTime]'2026-09-24T12:00:00Z')
        Assert ($r.Result -eq 'SIMULATED' -and -not $r.FirewallModified)
        Assert ($r.ExpiresUtc -is [DateTime] -and
            $r.ExpiresUtc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'") -eq '2026-09-24T12:05:00Z')
        Assert ($global:IPSStage4FakeRules.Count -eq 0 -and -not (Test-Path $a.StatePath))
    }
    Check 'Protected source refused' {
        $a=New-TestActuator
        $r=Invoke-IPSBlockRequest $a '192.168.0.3' '192.168.0.16' 'tcp_syn_open_scan' 300
        Assert ($r.Result -eq 'REFUSED' -and $global:IPSStage4FakeRules.Count -eq 0)
    }
    Check 'Wrong destination refused' {
        $a=New-TestActuator
        $r=Invoke-IPSBlockRequest $a '192.168.0.7' '192.168.0.99' 'tcp_syn_open_scan' 300
        Assert ($r.Result -eq 'REFUSED' -and $global:IPSStage4FakeRules.Count -eq 0)
    }
    Check 'Enforce creates verified inbound block and persistent state' {
        $a=New-TestActuator;$now=[DateTime]'2026-09-24T12:00:00Z'
        $r=Invoke-IPSBlockRequest $a '192.168.0.7' '192.168.0.16' 'tcp_syn_open_scan' 300 $now
        Assert ($r.Result -eq 'CREATED' -and $r.FirewallModified)
        Assert ($global:IPSStage4FakeRules.Count -eq 1 -and (Test-Path $a.StatePath))
        $saved=ConvertFrom-Json ([IO.File]::ReadAllText($a.StatePath))
        Assert (@($saved.records).Count -eq 1 -and $saved.records[0].source -eq '192.168.0.7')
    }
    Check 'Repeated request refreshes without duplicate rule' {
        $a=New-TestActuator;$first=[DateTime]'2026-09-24T12:00:00Z'
        $null=Invoke-IPSBlockRequest $a '192.168.0.7' '192.168.0.16' 'tcp_syn_open_scan' 300 $first
        $r=Invoke-IPSBlockRequest $a '192.168.0.7' '192.168.0.16' 'tcp_syn_open_scan' 600 $first.AddSeconds(10)
        Assert ($r.Result -eq 'REFRESHED' -and -not $r.FirewallModified -and $global:IPSStage4FakeRules.Count -eq 1) `
            ('Refresh incorrecto: result={0}; reason={1}; rules={2}' -f $r.Result,$r.Reason,$global:IPSStage4FakeRules.Count)
        Assert ($a.State.records[0].block_seconds -eq 600) ('block_seconds esperado=600; actual='+$a.State.records[0].block_seconds)
        Assert (@(Get-ChildItem -LiteralPath $script:temp -Filter '*.bak' -ErrorAction SilentlyContinue).Count -eq 0) 'Quedo un respaldo temporal .bak.'
    }
    Check 'Untracked homonymous rule is conflict and untouched' {
        $a=New-TestActuator;$name=Get-IPSRuleName $a.RulePrefix '192.168.0.7' '192.168.0.16'
        $global:IPSStage4FakeRules[$name]=[pscustomobject]@{Name=$name;Source='192.168.0.7';Destination='192.168.0.16'}
        $r=Invoke-IPSBlockRequest $a '192.168.0.7' '192.168.0.16' 'tcp_syn_open_scan' 300
        Assert ($r.Result -eq 'CONFLICT' -and $global:IPSStage4FakeRules.Count -eq 1)
    }
    Check 'Maximum active blocks enforced' {
        $a=New-TestActuator -Maximum 1
        $null=Invoke-IPSBlockRequest $a '192.168.0.7' '192.168.0.16' 'tcp_syn_open_scan' 300
        $r=Invoke-IPSBlockRequest $a '192.168.0.8' '192.168.0.16' 'tcp_syn_open_scan' 300
        Assert ($r.Result -eq 'LIMIT' -and $global:IPSStage4FakeRules.Count -eq 1)
    }
    Check 'Expired managed rule removed exactly' {
        $a=New-TestActuator;$now=[DateTime]'2026-09-24T12:00:00Z'
        $null=Invoke-IPSBlockRequest $a '192.168.0.7' '192.168.0.16' 'tcp_syn_open_scan' 15 $now
        $r=@(Invoke-IPSExpiredCleanup $a $now.AddSeconds(16))
        Assert ($r.Count -eq 1 -and $r[0].Result -eq 'REMOVED' -and $r[0].FirewallModified)
        Assert ($global:IPSStage4FakeRules.Count -eq 0 -and @($a.State.records).Count -eq 0)
    }
    Check 'Manual unblock removes only managed exact rule' {
        $a=New-TestActuator
        $null=Invoke-IPSBlockRequest $a '192.168.0.7' '192.168.0.16' 'tcp_syn_open_scan' 300
        $r=Remove-IPSManagedBlock $a '192.168.0.7' '192.168.0.16'
        Assert ($r.Result -eq 'REMOVED' -and $r.FirewallModified -and $global:IPSStage4FakeRules.Count -eq 0)
    }
    Check 'Failed post-create verification rolls rule back' {
        $a=New-TestActuator -BadVerification
        $r=Invoke-IPSBlockRequest $a '192.168.0.7' '192.168.0.16' 'tcp_syn_open_scan' 300
        Assert ($r.Result -eq 'ERROR' -and -not $r.FirewallModified)
        Assert ($global:IPSStage4FakeRules.Count -eq 0 -and @($a.State.records).Count -eq 0)
    }
    Check 'Corrupt state fails closed before adapter mutation' {
        $adapter=New-FakeAdapter;$path=Join-Path $script:temp 'corrupt.json'
        [IO.File]::WriteAllText($path,'{"schema_version":1,"records":"bad"}')
        MustThrow {New-IPSFirewallActuator -Mode Enforce -StatePath $path -Resolved $script:resolved -Adapter $adapter}
        Assert ($global:IPSStage4FakeRules.Count -eq 0)
    }
    Write-Host ('RESULT: {0} Stage4 actuator tests passed; simulated firewall only.' -f $script:passed)
}finally{Remove-Item -LiteralPath $script:temp -Recurse -Force -ErrorAction SilentlyContinue}
