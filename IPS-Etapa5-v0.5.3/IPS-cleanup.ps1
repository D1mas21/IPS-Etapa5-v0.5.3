#Requires -Version 4.0
<# Limpieza independiente de bloqueos vencidos administrados por SOC DEKMA IPS. #>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string]$StatePath,
    [string]$EventLogDirectory,
    [switch]$ConfirmRemoval
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$scriptFile=$MyInvocation.MyCommand.Path
if([string]::IsNullOrWhiteSpace($scriptFile)){throw 'No se pudo resolver la ruta de IPS-cleanup.ps1.'}
$scriptRoot=Split-Path -Parent $scriptFile
if([string]::IsNullOrWhiteSpace($ConfigPath)){$ConfigPath=Join-Path $scriptRoot 'config\ips-config.json'}
if([string]::IsNullOrWhiteSpace($StatePath)){$StatePath=Join-Path $scriptRoot 'state\firewall-blocks.json'}
if([string]::IsNullOrWhiteSpace($EventLogDirectory)){$EventLogDirectory=Join-Path $scriptRoot 'events'}

Import-Module (Join-Path $scriptRoot 'modules\Configuration.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $scriptRoot 'modules\FirewallActuator.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $scriptRoot 'modules\Operational.psm1') -Force -ErrorAction Stop

function Write-CleanupEvent {
    param([string]$Name,[hashtable]$Fields=@{})
    Write-IPSOperationalEvent -Directory $EventLogDirectory -Component 'dekma_ips_cleanup' -Mode 'Enforce' -Name $Name -Fields $Fields
}

try{
    if(-not $ConfirmRemoval){throw 'La limpieza independiente requiere -ConfirmRemoval.'}
    if($env:OS -ne 'Windows_NT'){throw 'La limpieza real requiere Windows.'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($identity)
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'La limpieza requiere PowerShell como administrador.'}
    foreach($commandName in @('Get-NetFirewallRule','Remove-NetFirewallRule','Get-NetFirewallAddressFilter')){
        if($null -eq (Get-Command $commandName -ErrorAction SilentlyContinue)){throw "$commandName no esta disponible."}
    }
    $config=Import-IPSConfiguration -Path $ConfigPath
    $inventory=Get-IPSInventory
    $resolved=Resolve-IPSConfiguration -Configuration $config -Inventory $inventory
    if(-not $resolved.Valid){throw ('Configuracion invalida: '+($resolved.Errors -join '; '))}
    $results=@(Invoke-IPSWithMutex -Name (Get-IPSStateMutexName) -TimeoutMilliseconds 30000 -ScriptBlock {
        $actuator=New-IPSFirewallActuator -Mode Enforce -StatePath $StatePath -Resolved $resolved -MaxActiveBlocks ([int]$config.operation.max_active_blocks)
        @(Invoke-IPSExpiredCleanup -Actuator $actuator -NowUtc ([DateTime]::UtcNow))
    })
    if($results.Count -eq 0){
        Write-CleanupEvent 'CLEANUP_NOTHING_EXPIRED' @{reason='No existen bloqueos administrados vencidos.'}
    }else{
        foreach($result in $results){
            $event=$(if($result.Result -eq 'REMOVED'){'BLOCK_EXPIRED_REMOVED'}elseif($result.Result -eq 'STATE_STALE'){'BLOCK_STATE_STALE'}elseif($result.Result -eq 'CONFLICT'){'BLOCK_CONFLICT'}else{'BLOCK_ERROR'})
            Write-CleanupEvent $event @{src_ip=$result.Source;dst_ip=$result.Destination;rule_name=$result.RuleName;actuator_result=$result.Result;reason=$result.Reason;firewall_modified=$result.FirewallModified}
        }
    }
    exit 0
}catch{
    try{Write-CleanupEvent 'CLEANUP_ERROR' @{reason=$_.Exception.Message}}catch{Write-Warning ('CLEANUP_ERROR sin log: '+$_.Exception.Message)}
    Write-Error ('IPS-cleanup: '+$_.Exception.Message)
    exit 1
}
