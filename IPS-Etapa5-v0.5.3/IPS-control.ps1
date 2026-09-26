#Requires -Version 4.0
<# Administrative recovery utility. It only manages exact rules recorded by this package. #>
[CmdletBinding()]
param(
    [ValidateSet('Status','CleanupExpired','Unblock')][string]$Action='Status',
    [string]$Address,
    [switch]$ConfirmRemoval,
    [string]$ConfigPath,
    [string]$StatePath,
    [string]$EventLogDirectory
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$scriptFile=$MyInvocation.MyCommand.Path
if([string]::IsNullOrWhiteSpace($scriptFile)){throw 'No se pudo resolver la ruta de IPS-control.ps1.'}
$scriptRoot=Split-Path -Parent $scriptFile
if([string]::IsNullOrWhiteSpace($ConfigPath)){$ConfigPath=Join-Path $scriptRoot 'config\ips-config.json'}
if([string]::IsNullOrWhiteSpace($StatePath)){$StatePath=Join-Path $scriptRoot 'state\firewall-blocks.json'}
if([string]::IsNullOrWhiteSpace($EventLogDirectory)){$EventLogDirectory=Join-Path $scriptRoot 'events'}
$script:controlMode='Unknown'
function Write-ControlEvent {param([string]$Event,$Result)
    Write-IPSOperationalEvent -Directory $EventLogDirectory -Component 'dekma_ips_control' -Mode $script:controlMode -Name $Event -Fields @{
        firewall_modified=$Result.FirewallModified;result=$Result.Result;reason=$Result.Reason;rule_name=$Result.RuleName
        src_ip=$Result.Source;dst_ip=$Result.Destination
    }
}
try{
    Import-Module (Join-Path $scriptRoot 'modules\Configuration.psm1') -Force
    Import-Module (Join-Path $scriptRoot 'modules\FirewallActuator.psm1') -Force
    Import-Module (Join-Path $scriptRoot 'modules\Operational.psm1') -Force
    $config=Import-IPSConfiguration $ConfigPath;$inventory=Get-IPSInventory
    $script:controlMode=[string]$config.operation.mode
    $resolved=Resolve-IPSConfiguration $config $inventory
    if(-not $resolved.Valid){throw ('Configuracion invalida: '+($resolved.Errors -join '; '))}
    if($Action -eq 'Status'){
        $status=Invoke-IPSWithMutex -Name (Get-IPSStateMutexName) -TimeoutMilliseconds 30000 -ScriptBlock {
            $actuator=New-IPSFirewallActuator -Mode Enforce -StatePath $StatePath -Resolved $resolved -MaxActiveBlocks $config.operation.max_active_blocks
            [pscustomobject]@{Count=@($actuator.State.records).Count;Records=@($actuator.State.records)}
        }
        Write-IPSOperationalEvent -Directory $EventLogDirectory -Component 'dekma_ips_control' -Mode $script:controlMode -Name 'STATUS' -Fields @{
            managed_blocks=$status.Count;records=$status.Records
        }
        exit 0
    }
    if(-not $ConfirmRemoval){throw "$Action requiere -ConfirmRemoval."}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=New-Object Security.Principal.WindowsPrincipal($identity)
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'La operacion requiere PowerShell como administrador.'}
    if($Action -eq 'CleanupExpired'){
        $results=@(Invoke-IPSWithMutex -Name (Get-IPSStateMutexName) -TimeoutMilliseconds 30000 -ScriptBlock {
            $actuator=New-IPSFirewallActuator -Mode Enforce -StatePath $StatePath -Resolved $resolved -MaxActiveBlocks $config.operation.max_active_blocks
            @(Invoke-IPSExpiredCleanup $actuator ([DateTime]::UtcNow))
        })
        if($results.Count -eq 0){Write-IPSOperationalEvent -Directory $EventLogDirectory -Component 'dekma_ips_control' -Mode $script:controlMode -Name 'NOTHING_EXPIRED' -Fields @{reason='No existen bloqueos administrados vencidos.'}}
        foreach($result in $results){Write-ControlEvent 'CLEANUP_RESULT' $result}
        exit 0
    }
    if([string]::IsNullOrWhiteSpace($Address)){throw 'Unblock requiere -Address con un host IPv4 exacto.'}
    $result=Invoke-IPSWithMutex -Name (Get-IPSStateMutexName) -TimeoutMilliseconds 30000 -ScriptBlock {
        $actuator=New-IPSFirewallActuator -Mode Enforce -StatePath $StatePath -Resolved $resolved -MaxActiveBlocks $config.operation.max_active_blocks
        Remove-IPSManagedBlock -Actuator $actuator -Source $Address -Destination $config.protected_server
    }
    Write-ControlEvent 'UNBLOCK_RESULT' $result
    if($result.Result -eq 'ERROR' -or $result.Result -eq 'CONFLICT'){exit 2}
    exit 0
}catch{
    try{Write-IPSOperationalEvent -Directory $EventLogDirectory -Component 'dekma_ips_control' -Mode $script:controlMode -Name 'CONTROL_ERROR' -Fields @{reason=$_.Exception.Message}}
    catch{Write-Warning ('CONTROL_ERROR sin log: '+$_.Exception.Message)}
    Write-Error ('IPS-control: '+$_.Exception.Message);exit 1
}
