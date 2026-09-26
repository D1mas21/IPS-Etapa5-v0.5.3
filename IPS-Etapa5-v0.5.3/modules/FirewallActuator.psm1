#Requires -Version 4.0
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'IPv4.psm1') -Force -ErrorAction Stop

function New-IPSActuatorResult {
    param([string]$Result,[string]$Reason,[string]$RuleName,[string]$Source,[string]$Destination,
          [bool]$FirewallModified=$false,[Nullable[DateTime]]$ExpiresUtc=$null)
    [pscustomobject]@{
        Result=$Result;Reason=$Reason;RuleName=$RuleName;Source=$Source;Destination=$Destination
        FirewallModified=$FirewallModified
        # Windows PowerShell 4 unwraps Nullable[DateTime] arguments. Casting
        # works for both the unwrapped DateTime and a nullable value.
        ExpiresUtc=$(if($null -eq $ExpiresUtc){$null}else{[DateTime]$ExpiresUtc})
    }
}

function Get-IPSRuleName {
    param([string]$Prefix,[string]$Source,[string]$Destination)
    [uint64]$src=ConvertTo-IPSIPv4Number $Source
    [uint64]$dst=ConvertTo-IPSIPv4Number $Destination
    return ('{0}-{1:X8}-{2:X8}' -f $Prefix,$src,$dst)
}

function New-IPSRealFirewallAdapter {
    [CmdletBinding()]param()
    if($env:OS -ne 'Windows_NT'){throw 'El adaptador real de firewall requiere Windows.'}
    [pscustomobject]@{
        Kind='WindowsNetSecurity'
        GetRule={param([string]$Name) @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $Name -ErrorAction SilentlyContinue)}
        CreateRule={param([string]$Name,[string]$Source,[string]$Destination)
            New-NetFirewallRule -PolicyStore PersistentStore -Name $Name -DisplayName $Name `
                -Group 'SOC DEKMA IPS' -Enabled True -Profile Any -Direction Inbound -Action Block `
                -RemoteAddress $Source -LocalAddress $Destination -ErrorAction Stop
        }
        RemoveRule={param([string]$Name) Remove-NetFirewallRule -PolicyStore PersistentStore -Name $Name -ErrorAction Stop}
        GetAddressFilter={param($Rule) @($Rule | Get-NetFirewallAddressFilter -ErrorAction Stop)}
    }
}

function Assert-IPSStateRecord {
    param($Record,[string]$Prefix)
    $required=@('rule_name','source','destination','created_utc','expires_utc','policy_id','block_seconds')
    if($null -eq $Record -or $Record -isnot [pscustomobject]){throw 'Registro de estado invalido.'}
    $actual=@($Record.PSObject.Properties|ForEach-Object{$_.Name})
    foreach($key in $required){if($actual -cnotcontains $key){throw "Falta state.$key."}}
    foreach($key in $actual){if($required -cnotcontains $key){throw "Campo de estado no admitido: $key."}}
    $null=ConvertTo-IPSIPv4Number ([string]$Record.source)
    $null=ConvertTo-IPSIPv4Number ([string]$Record.destination)
    $expected=Get-IPSRuleName $Prefix ([string]$Record.source) ([string]$Record.destination)
    if([string]$Record.rule_name -cne $expected){throw "Nombre de regla de estado no coincide: $($Record.rule_name)."}
    if($Record.policy_id -isnot [string] -or [string]::IsNullOrWhiteSpace($Record.policy_id) -or $Record.policy_id -cnotmatch '^[a-z][a-z0-9_]{2,63}$'){
        throw 'policy_id invalido en estado.'
    }
    if(($Record.block_seconds -isnot [int] -and $Record.block_seconds -isnot [long]) -or $Record.block_seconds -lt 15 -or $Record.block_seconds -gt 86400){
        throw 'block_seconds invalido en estado.'
    }
    foreach($field in @('created_utc','expires_utc')){
        if($Record.$field -isnot [string] -or $Record.$field -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$'){
            throw "$field invalido en estado."
        }
        $parsed=[DateTime]::MinValue
        if(-not [DateTime]::TryParseExact($Record.$field,"yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
            [Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal),[ref]$parsed)){
            throw "$field no contiene una fecha valida."
        }
    }
}

function Read-IPSActuatorState {
    param([string]$Path,[string]$Prefix)
    if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){
        return [pscustomobject]@{schema_version=1;records=@()}
    }
    $file=Get-Item -LiteralPath $Path -ErrorAction Stop
    if($file.Length -gt 1048576){throw 'El estado del firewall supera 1 MiB.'}
    $text=[IO.File]::ReadAllText($file.FullName,[Text.Encoding]::UTF8)
    try{$state=ConvertFrom-Json -InputObject $text -ErrorAction Stop}catch{throw "Estado de firewall corrupto: $($_.Exception.Message)"}
    if($null -eq $state -or $state -isnot [pscustomobject]){throw 'Estado de firewall invalido.'}
    $keys=@($state.PSObject.Properties|ForEach-Object{$_.Name})
    if($keys.Count -ne 2 -or $keys -cnotcontains 'schema_version' -or $keys -cnotcontains 'records'){throw 'Esquema de estado no admitido.'}
    if($state.schema_version -ne 1){throw 'Version de estado no admitida.'}
    if($state.records -isnot [array]){throw 'state.records debe ser un arreglo JSON.'}
    $seen=@{}
    foreach($record in $state.records){
        Assert-IPSStateRecord $record $Prefix
        if($seen.ContainsKey($record.rule_name)){throw "Regla duplicada en estado: $($record.rule_name)."}
        $seen[$record.rule_name]=$true
    }
    return $state
}

function Write-IPSActuatorState {
    param([string]$Path,$State)
    $directory=Split-Path -Parent $Path
    if(-not (Test-Path -LiteralPath $directory -PathType Container)){$null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop}
    $temp=Join-Path $directory ('.firewall-blocks.'+[Guid]::NewGuid().ToString('N')+'.tmp')
    $backup=Join-Path $directory ('.firewall-blocks.'+[Guid]::NewGuid().ToString('N')+'.bak')
    try{
        $json=ConvertTo-Json -InputObject $State -Depth 6
        [IO.File]::WriteAllText($temp,$json,(New-Object Text.UTF8Encoding($false)))
        if(Test-Path -LiteralPath $Path -PathType Leaf){[IO.File]::Replace($temp,$Path,$backup)}
        else{[IO.File]::Move($temp,$Path)}
    }finally{
        if(Test-Path -LiteralPath $temp -PathType Leaf){Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue}
        if(Test-Path -LiteralPath $backup -PathType Leaf){Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue}
    }
}

function Test-IPSFirewallRuleBinding {
    param($Adapter,$Rule,[string]$Source,[string]$Destination)
    try{$filters=@(& $Adapter.GetAddressFilter $Rule)}catch{return $false}
    foreach($filter in $filters){
        $remote=@($filter.RemoteAddress|ForEach-Object{[string]$_})
        $local=@($filter.LocalAddress|ForEach-Object{[string]$_})
        $sourceExact=($remote -contains $Source -or $remote -contains ($Source+'/32'))
        $destinationExact=($local -contains $Destination -or $local -contains ($Destination+'/32'))
        if($sourceExact -and $destinationExact){return $true}
    }
    return $false
}

function New-IPSFirewallActuator {
    [CmdletBinding()]
    param([ValidateSet('Audit','Enforce')][string]$Mode='Audit',
          [Parameter(Mandatory=$true)][string]$StatePath,
          [Parameter(Mandatory=$true)]$Resolved,
          [ValidateRange(1,4096)][int]$MaxActiveBlocks=256,
          [string]$RulePrefix='SOC-DEKMA-IPS-V4',$Adapter)
    if($RulePrefix -cnotmatch '^[A-Z0-9-]{8,32}$'){throw 'RulePrefix invalido.'}
    $full=[IO.Path]::GetFullPath($StatePath)
    if($null -eq $Adapter){$Adapter=New-IPSRealFirewallAdapter}
    $state=$(if($Mode -eq 'Enforce'){Read-IPSActuatorState $full $RulePrefix}else{[pscustomobject]@{schema_version=1;records=@()}})
    [pscustomobject]@{Mode=$Mode;StatePath=$full;Resolved=$Resolved;MaxActiveBlocks=$MaxActiveBlocks;RulePrefix=$RulePrefix;Adapter=$Adapter;State=$state}
}

function Invoke-IPSBlockRequest {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Actuator,[Parameter(Mandatory=$true)][string]$Source,
          [Parameter(Mandatory=$true)][string]$Destination,[Parameter(Mandatory=$true)][string]$PolicyId,
          [ValidateRange(15,86400)][int]$BlockSeconds,[DateTime]$NowUtc=([DateTime]::UtcNow))
    $NowUtc=$NowUtc.ToUniversalTime()
    $ruleName=Get-IPSRuleName $Actuator.RulePrefix $Source $Destination
    if($Destination -ne $Actuator.Resolved.Configuration.protected_server){
        return New-IPSActuatorResult 'REFUSED' 'Destino distinto al servidor protegido.' $ruleName $Source $Destination
    }
    $eligibility=Test-IPSAddress -Address $Source -Resolved $Actuator.Resolved
    if($eligibility.Decision -ne 'SUBJECT_TO_POLICY' -and $eligibility.Decision -ne 'DENYLIST_MATCH'){
        return New-IPSActuatorResult 'REFUSED' ('Origen no elegible: '+$eligibility.Decision+'; '+$eligibility.Reason) $ruleName $Source $Destination
    }
    $expires=$NowUtc.AddSeconds($BlockSeconds)
    if($Actuator.Mode -eq 'Audit'){
        return New-IPSActuatorResult 'SIMULATED' 'Audit: solicitud validada; firewall sin cambios.' $ruleName $Source $Destination $false $expires
    }
    $records=@($Actuator.State.records)
    $existing=@($records|Where-Object{$_.rule_name -eq $ruleName})
    $rules=@(& $Actuator.Adapter.GetRule $ruleName)
    if($existing.Count -eq 0 -and $rules.Count -gt 0){
        return New-IPSActuatorResult 'CONFLICT' 'Existe una regla homonima sin estado administrado; no se modifica.' $ruleName $Source $Destination
    }
    if($existing.Count -gt 0){
        if($rules.Count -ne 1 -or -not (Test-IPSFirewallRuleBinding $Actuator.Adapter $rules[0] $Source $Destination)){
            return New-IPSActuatorResult 'CONFLICT' 'Estado y regla de firewall no coinciden; no se modifica.' $ruleName $Source $Destination
        }
        $oldExpiry=$existing[0].expires_utc;$oldPolicy=$existing[0].policy_id;$oldSeconds=$existing[0].block_seconds
        $existing[0].expires_utc=$expires.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'")
        $existing[0].policy_id=$PolicyId;$existing[0].block_seconds=$BlockSeconds
        try{Write-IPSActuatorState $Actuator.StatePath $Actuator.State}catch{
            $existing[0].expires_utc=$oldExpiry;$existing[0].policy_id=$oldPolicy;$existing[0].block_seconds=$oldSeconds
            return New-IPSActuatorResult 'ERROR' ('No se pudo guardar la renovacion: '+$_.Exception.Message) $ruleName $Source $Destination
        }
        return New-IPSActuatorResult 'REFRESHED' 'Bloqueo administrado renovado.' $ruleName $Source $Destination $false $expires
    }
    if($records.Count -ge $Actuator.MaxActiveBlocks){
        return New-IPSActuatorResult 'LIMIT' 'Se alcanzo max_active_blocks; no se crea regla.' $ruleName $Source $Destination
    }
    $created=$false
    try{
        $null=& $Actuator.Adapter.CreateRule $ruleName $Source $Destination;$created=$true
        $rules=@(& $Actuator.Adapter.GetRule $ruleName)
        if($rules.Count -ne 1 -or -not (Test-IPSFirewallRuleBinding $Actuator.Adapter $rules[0] $Source $Destination)){
            throw 'La verificacion posterior de la regla fallo.'
        }
        $record=[pscustomobject][ordered]@{
            rule_name=$ruleName;source=$Source;destination=$Destination
            created_utc=$NowUtc.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'")
            expires_utc=$expires.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'")
            policy_id=$PolicyId;block_seconds=$BlockSeconds
        }
        $Actuator.State.records=@($records+$record)
        Write-IPSActuatorState $Actuator.StatePath $Actuator.State
        return New-IPSActuatorResult 'CREATED' 'Regla entrante creada y verificada.' $ruleName $Source $Destination $true $expires
    }catch{
        $failure=$_.Exception.Message
        $rollbackFailed=$false
        if($created){try{$null=& $Actuator.Adapter.RemoveRule $ruleName}catch{$rollbackFailed=$true;$failure+='; rollback fallo: '+$_.Exception.Message}}
        $Actuator.State.records=@($records)
        return New-IPSActuatorResult 'ERROR' ('Creacion revertida: '+$failure) $ruleName $Source $Destination $rollbackFailed
    }
}

function Invoke-IPSExpiredCleanup {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Actuator,[DateTime]$NowUtc=([DateTime]::UtcNow))
    $NowUtc=$NowUtc.ToUniversalTime()
    if($Actuator.Mode -ne 'Enforce'){return @()}
    $results=New-Object System.Collections.ArrayList;$kept=New-Object System.Collections.ArrayList;$changed=$false
    foreach($record in @($Actuator.State.records)){
        $expiry=[DateTime]::ParseExact($record.expires_utc,"yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal).ToUniversalTime()
        if($expiry -gt $NowUtc){$null=$kept.Add($record);continue}
        $rules=@(& $Actuator.Adapter.GetRule $record.rule_name)
        if($rules.Count -eq 0){
            $changed=$true;$null=$results.Add((New-IPSActuatorResult 'STATE_STALE' 'Regla ausente; estado vencido retirado.' $record.rule_name $record.source $record.destination))
            continue
        }
        if($rules.Count -ne 1 -or -not (Test-IPSFirewallRuleBinding $Actuator.Adapter $rules[0] $record.source $record.destination)){
            $null=$kept.Add($record);$null=$results.Add((New-IPSActuatorResult 'CONFLICT' 'Regla vencida no coincide; no se elimina.' $record.rule_name $record.source $record.destination));continue
        }
        try{
            $null=& $Actuator.Adapter.RemoveRule $record.rule_name
            $remaining=@(& $Actuator.Adapter.GetRule $record.rule_name)
            if($remaining.Count -ne 0){throw 'La regla continua presente tras Remove.'}
            $changed=$true;$null=$results.Add((New-IPSActuatorResult 'REMOVED' 'Bloqueo vencido eliminado.' $record.rule_name $record.source $record.destination $true))
        }catch{$null=$kept.Add($record);$null=$results.Add((New-IPSActuatorResult 'ERROR' ('No se pudo eliminar: '+$_.Exception.Message) $record.rule_name $record.source $record.destination))}
    }
    if($changed){
        $old=@($Actuator.State.records);$Actuator.State.records=@($kept.ToArray())
        try{Write-IPSActuatorState $Actuator.StatePath $Actuator.State}catch{$Actuator.State.records=$old;throw}
    }
    return @($results.ToArray())
}

function Remove-IPSManagedBlock {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Actuator,[Parameter(Mandatory=$true)][string]$Source,
          [Parameter(Mandatory=$true)][string]$Destination)
    if($Actuator.Mode -ne 'Enforce'){return New-IPSActuatorResult 'REFUSED' 'El desbloqueo requiere Enforce.' '' $Source $Destination}
    $ruleName=Get-IPSRuleName $Actuator.RulePrefix $Source $Destination
    $records=@($Actuator.State.records);$match=@($records|Where-Object{$_.rule_name -eq $ruleName})
    if($match.Count -eq 0){return New-IPSActuatorResult 'NOT_FOUND' 'No existe bloqueo administrado para la IP.' $ruleName $Source $Destination}
    $rules=@(& $Actuator.Adapter.GetRule $ruleName)
    if($rules.Count -gt 1 -or ($rules.Count -eq 1 -and -not (Test-IPSFirewallRuleBinding $Actuator.Adapter $rules[0] $Source $Destination))){
        return New-IPSActuatorResult 'CONFLICT' 'La regla no coincide; no se elimina.' $ruleName $Source $Destination
    }
    $removed=$false
    try{
        if($rules.Count -eq 1){$null=& $Actuator.Adapter.RemoveRule $ruleName}
        $removed=($rules.Count -eq 1)
        $Actuator.State.records=@($records|Where-Object{$_.rule_name -ne $ruleName})
        Write-IPSActuatorState $Actuator.StatePath $Actuator.State
        return New-IPSActuatorResult 'REMOVED' 'Bloqueo administrado eliminado manualmente.' $ruleName $Source $Destination $removed
    }catch{
        $Actuator.State.records=@($records)
        return New-IPSActuatorResult 'ERROR' ('Desbloqueo fallo: '+$_.Exception.Message) $ruleName $Source $Destination $removed
    }
}

Export-ModuleMember -Function New-IPSRealFirewallAdapter,New-IPSFirewallActuator,Invoke-IPSBlockRequest,Invoke-IPSExpiredCleanup,Remove-IPSManagedBlock,Get-IPSRuleName
