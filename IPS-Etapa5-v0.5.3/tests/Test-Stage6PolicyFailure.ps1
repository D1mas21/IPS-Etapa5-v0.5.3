#Requires -Version 4.0
# SOC DEKMA IPS v0.5.4-dev1
# Adversarial test: a failed actuator decision must never start cooldown.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'modules\PolicyEngine.psm1') -Force

$script:passed=0
function Assert {
    param([bool]$Condition,[string]$Message='Assertion failed')
    if(-not $Condition){throw $Message}
}
function Check {
    param([string]$Name,[scriptblock]$Test)
    & $Test
    $script:passed++
    Write-Host ('PASS '+$Name)
}
function Alert {
    param([int]$Sid,[int]$Rev=1,[Nullable[int]]$Port=80)
    [pscustomobject]@{Gid=1;Sid=$Sid;Rev=$Rev;DestinationPort=$Port}
}

$config=Import-IPSPolicyConfiguration (Join-Path $root 'config\ips-policies.json')
$engine=New-IPSPolicyEngine $config
$t=[DateTime]'2026-09-27T12:00:00Z'
$src='192.168.0.160'

Check 'Threshold creates pending proposal, not cooldown' {
    $null=Add-IPSPolicyAlert $engine (Alert 1000003 1 80) $src $t
    $null=Add-IPSPolicyAlert $engine (Alert 1000003 1 445) $src ($t.AddSeconds(1))
    $r=@(Add-IPSPolicyAlert $engine (Alert 1000003 1 3389) $src ($t.AddSeconds(2)))
    Assert ($r.Count -eq 1)
    Assert ($r[0].Result -eq 'WOULD_BLOCK')
    Assert (-not [string]::IsNullOrWhiteSpace($r[0].ProposalId))
    Assert ($engine.Cooldowns.Count -eq 0)
    Assert ($engine.PendingDecisions.Count -eq 1)
}

$proposal=@($engine.PendingDecisions.Values)[0].ProposalId

Check 'While actuator outcome is pending, duplicate proposal is suppressed' {
    $r=@(Add-IPSPolicyAlert $engine (Alert 1000003 1 443) $src ($t.AddSeconds(3)))
    Assert ($r[0].Result -eq 'PENDING')
    Assert ($r[0].ProposalId -eq $proposal)
    Assert ($engine.Cooldowns.Count -eq 0)
}

Check 'Abort preserves tracking and does not create cooldown' {
    $r=Cancel-IPSPolicyBlock -Engine $engine -ProposalId $proposal
    Assert ($r.Result -eq 'ABORTED')
    Assert ($r.TrackingPreserved)
    Assert ($engine.PendingDecisions.Count -eq 0)
    Assert ($engine.Cooldowns.Count -eq 0)
}

Check 'After failure, next matching alert can propose again immediately' {
    $r=@(Add-IPSPolicyAlert $engine (Alert 1000003 1 8443) $src ($t.AddSeconds(4)))
    Assert ($r[0].Result -eq 'WOULD_BLOCK')
    Assert ($r[0].ProposalId -ne $proposal)
    $script:secondProposal=$r[0].ProposalId
}

Check 'Only confirmed actuator outcome starts cooldown' {
    $r=Confirm-IPSPolicyBlock -Engine $engine -ProposalId $script:secondProposal -NowUtc ($t.AddSeconds(4))
    Assert ($r.Result -eq 'COMMITTED')
    Assert ($r.CooldownSeconds -eq 60)
    Assert ($engine.PendingDecisions.Count -eq 0)
    Assert ($engine.Cooldowns.Count -eq 1)
    $next=@(Add-IPSPolicyAlert $engine (Alert 1000003 1 80) $src ($t.AddSeconds(5)))
    Assert ($next[0].Result -eq 'COOLDOWN')
}

Write-Host ('RESULT: {0} v0.5.4 transactional cooldown adversarial tests passed.' -f $script:passed)
