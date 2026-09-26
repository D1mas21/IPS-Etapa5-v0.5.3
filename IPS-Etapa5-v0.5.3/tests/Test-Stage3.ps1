#Requires -Version 4.0
# Policy engine tests only. No network, Snort or firewall dependency.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'modules\PolicyEngine.psm1') -Force
$script:passed=0
function Check {param([bool]$Ok,[string]$Name);if(-not $Ok){throw ('FAIL '+$Name)};$script:passed++;Write-Host ('PASS '+$Name)}
function Alert {param([int]$Sid,[int]$Rev=2,[Nullable[int]]$Port=445);[pscustomobject]@{Gid=1;Sid=$Sid;Rev=$Rev;DestinationPort=$Port}}
$config=Import-IPSPolicyConfiguration (Join-Path $root 'config\ips-policies.json')
Check ($config.policies.Count -eq 10) 'Ten conservative policies loaded'
$engine=New-IPSPolicyEngine $config
$t=[DateTime]::UtcNow
$r=@(Add-IPSPolicyAlert $engine (Alert 1000003 1 80) '192.168.0.7' $t)
Check ($r[0].Result -eq 'TRACKING' -and $r[0].ObservedCount -eq 1) 'SYN first alert tracked'
$r=@(Add-IPSPolicyAlert $engine (Alert 1000003 1 445) '192.168.0.7' ($t.AddSeconds(1)))
Check ($r[0].Result -eq 'TRACKING' -and $r[0].DistinctPorts -eq 2) 'SYN second port tracked'
$r=@(Add-IPSPolicyAlert $engine (Alert 1000003 1 3389) '192.168.0.7' ($t.AddSeconds(2)))
Check ($r[0].Result -eq 'WOULD_BLOCK' -and $r[0].ObservedCount -eq 3 -and $r[0].ProposedBlockSeconds -eq 300) 'SYN threshold proposes block'
$r=@(Add-IPSPolicyAlert $engine (Alert 1000003 1 80) '192.168.0.7' ($t.AddSeconds(3)))
Check ($r[0].Result -eq 'COOLDOWN' -and $r[0].CooldownRemainingSeconds -gt 0) 'Repeated decision enters cooldown'
$null=Add-IPSPolicyAlert $engine (Alert 1000003 1 80) '192.168.0.8' $t
$r=@(Add-IPSPolicyAlert $engine (Alert 1000003 1 445) '192.168.0.8' ($t.AddSeconds(11)))
Check ($r[0].Result -eq 'TRACKING' -and $r[0].ObservedCount -eq 1) 'Expired events removed from window'
$null=Add-IPSPolicyAlert $engine (Alert 1000301 2 $null) '192.168.0.9' $t
$null=Add-IPSPolicyAlert $engine (Alert 1000302 2 $null) '192.168.0.9' ($t.AddSeconds(1))
$r=@(Add-IPSPolicyAlert $engine (Alert 1000303 2 $null) '192.168.0.9' ($t.AddSeconds(2)))
Check ($r[0].Result -eq 'WOULD_BLOCK' -and $r[0].DistinctSids -eq 3) 'OS fingerprint requires three distinct SIDs'
$r=@(Add-IPSPolicyAlert $engine (Alert 1000402 2 80) '192.168.0.10' $t)
Check ($r[0].Result -eq 'WOULD_BLOCK') 'Specific service payload proposes block once'
$r=@(Add-IPSPolicyAlert $engine (Alert 1000703 1 80) '192.168.0.11' $t)
Check ($r[0].Result -eq 'NO_POLICY') 'Debug SID has no blocking policy'
$r=@(Add-IPSPolicyAlert $engine (Alert 1000003 2 80) '192.168.0.12' $t)
Check ($r[0].Result -eq 'NO_POLICY') 'Unapproved revision has no policy'
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ips-policy-'+[Guid]::NewGuid().ToString('N')+'.json')
try {
    $raw=[IO.File]::ReadAllText((Join-Path $root 'config\ips-policies.json'))
    $duplicate=$raw.Replace('"schema_version": 1,','"schema_version": 1, "schema_version": 1,')
    Check ([regex]::Matches($duplicate,'"schema_version"\s*:').Count -eq 2) 'Duplicate-key test fixture created'
    [IO.File]::WriteAllText($temp,$duplicate)
    $thrown=$false;try{$null=Import-IPSPolicyConfiguration $temp}catch{$thrown=$true}
    Check $thrown 'Duplicate JSON key rejected'
} finally {if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Force}}
Write-Host ('RESULT: {0} Stage3 policy tests passed; Audit only.' -f $script:passed)
