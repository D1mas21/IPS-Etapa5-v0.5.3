#Requires -Version 4.0
<#
ETAPA 1 - Validador de configuracion. Ejecuta una vez y termina.
No lee alertas, no modifica firewall, no registra tareas ni bloquea IPs.
Compatible con sintaxis Windows PowerShell 4.0. Prueba real requerida en Windows.
Exit codes: 0=validado, 1=error/inventario, 2=conflicto de configuracion.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string[]]$TestAddress = @(),
    [string]$ReportPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$exitCode = 1
$scriptFile=$MyInvocation.MyCommand.Path
if([string]::IsNullOrWhiteSpace($scriptFile)){throw 'No se pudo resolver la ruta de IPS-validate.ps1.'}
$scriptRoot=Split-Path -Parent $scriptFile
if([string]::IsNullOrWhiteSpace($ConfigPath)){$ConfigPath=Join-Path $scriptRoot 'config\ips-config.json'}

try {
    Import-Module (Join-Path $scriptRoot 'modules\Configuration.psm1') -Force -ErrorAction Stop
    $config = Import-IPSConfiguration -Path $ConfigPath
    $inventory = Get-IPSInventory
    $resolved = Resolve-IPSConfiguration -Configuration $config -Inventory $inventory
    $checks = @(foreach ($address in $TestAddress) { Test-IPSAddress -Address $address -Resolved $resolved })
    $warnings = @($resolved.Warnings)
    if (-not (Test-Path -LiteralPath $config.snort.alert_path -PathType Leaf)) {
        $warnings += 'El puente Snort no existe ahora. No impide validar configuracion; sera necesario para ejecutar Watch.'
    }

    Write-Host 'SOC DEKMA IPS - ETAPA 1 / VALIDACION'
    Write-Host ('Equipo: {0} | PowerShell: {1} | Modo: {2}' -f $inventory.ComputerName,$inventory.PowerShellVersion,$config.operation.mode)
    Write-Host ('Servidor: {0} | Gateway detectado: {1}' -f $config.protected_server,($inventory.Gateways -join ', '))
    Write-Host ('Puente configurado: {0}' -f $config.snort.alert_path)
    Write-Host ('Entradas de lista negra: {0}' -f $resolved.Denylist.Count)
    $resolved.Protections | Select-Object Network,Reason,Origin | Format-Table -AutoSize -Wrap | Out-Host
    Write-Host 'Direcciones/rangos excluidos adicionales:'
    $resolved.Exclusions | Select-Object Network,Reason | Format-Table -AutoSize -Wrap | Out-Host
    Write-Host 'Perfiles de firewall (solo lectura):'
    $inventory.FirewallProfiles | Format-Table -AutoSize | Out-Host
    if ($checks.Count -gt 0) { $checks | Format-Table -AutoSize -Wrap | Out-Host }
    foreach ($warning in $warnings) { Write-Warning $warning }
    foreach ($failure in $resolved.Errors) { Write-Host ('ERROR: ' + $failure) -ForegroundColor Red }

    $exitCode = 2
    if ($resolved.Valid) { $exitCode = 0 }
    if ($ReportPath) {
        # Explicit optional diagnostic snapshot, not the future Wazuh event stream.
        # Do not overwrite existing files, scripts or logs through ReportPath.
        $report = [ordered]@{
            schema_version = 1
            component = 'dekma_ips_stage1'
            timestamp = [DateTime]::UtcNow.ToString('o')
            event = 'configuration_validation'
            valid = $resolved.Valid
            firewall_modified = $false
            inventory = $inventory
            configuration = $config
            protections = @($resolved.Protections | Select-Object Network,Reason,Origin)
            excluded = @($resolved.Exclusions | Select-Object Network,Reason,Origin)
            address_checks = $checks
            errors = @($resolved.Errors)
            warnings = $warnings
        }
        $fullReportPath = [IO.Path]::GetFullPath($ReportPath)
        $json = ConvertTo-Json -InputObject $report -Depth 12
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json)
        $stream = $null
        try {
            $stream = [IO.File]::Open($fullReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
            $stream.Write($bytes,0,$bytes.Length)
            $stream.Flush()
        } finally { if ($null -ne $stream) { $stream.Dispose() } }
        Write-Host ('Informe: ' + $fullReportPath)
    }
    if ($resolved.Valid) { Write-Host 'CONFIG_VALID - configuracion de etapa 1 valida. Ningun bloqueo ejecutado.' -ForegroundColor Green }
    else { Write-Host 'CONFIG_INVALID - revisar errores. Ningun bloqueo ejecutado.' -ForegroundColor Red }
} catch {
    Write-Error ('VALIDATION_FAILED: ' + $_.Exception.Message) -ErrorAction Continue
    $exitCode = 1
}
exit $exitCode
