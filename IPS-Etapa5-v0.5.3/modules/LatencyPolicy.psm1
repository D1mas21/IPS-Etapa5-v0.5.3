#Requires -Version 4.0
Set-StrictMode -Version 2.0

function Test-IPSEventAge {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][double]$AgeSeconds,
        [ValidateRange(1,59)][int]$WarningSeconds,
        [ValidateRange(1,60)][int]$MaximumSeconds,
        [ValidateRange(0,10)][double]$FutureToleranceSeconds=2
    )
    if($WarningSeconds -ge $MaximumSeconds){throw 'WarningSeconds debe ser menor que MaximumSeconds.'}
    if([double]::IsNaN($AgeSeconds) -or [double]::IsInfinity($AgeSeconds)){
        throw 'AgeSeconds debe ser un numero finito.'
    }
    if($AgeSeconds -lt (-1 * $FutureToleranceSeconds)){
        return [pscustomobject]@{Result='FUTURE';Accept=$false;Delayed=$false;Reason='Fecha de alerta posterior a la tolerancia permitida.'}
    }
    if($AgeSeconds -gt $MaximumSeconds){
        return [pscustomobject]@{Result='STALE';Accept=$false;Delayed=$true;Reason='Alerta mas antigua que max_event_age_seconds.'}
    }
    if($AgeSeconds -gt $WarningSeconds){
        return [pscustomobject]@{Result='DELAYED';Accept=$true;Delayed=$true;Reason='Alerta aceptada con retraso superior al umbral de advertencia.'}
    }
    return [pscustomobject]@{Result='ON_TIME';Accept=$true;Delayed=$false;Reason='Alerta recibida dentro del umbral normal.'}
}

Export-ModuleMember -Function Test-IPSEventAge
