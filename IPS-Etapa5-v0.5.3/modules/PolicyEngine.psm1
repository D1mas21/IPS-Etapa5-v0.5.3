#Requires -Version 4.0
Set-StrictMode -Version 2.0

function Assert-IPSPolicyObject {
    param($Object,[string[]]$Keys,[string]$Context)
    if ($null -eq $Object -or $Object -isnot [pscustomobject]) { throw "$Context debe ser un objeto JSON." }
    $actual=@($Object.PSObject.Properties | ForEach-Object {$_.Name})
    foreach($key in $Keys) { if($actual -cnotcontains $key) { throw "Falta '$Context.$key'." } }
    foreach($key in $actual) { if($Keys -cnotcontains $key) { throw "Campo no admitido: '$Context.$key'." } }
}

function Assert-IPSPolicyInteger {
    param($Value,[int]$Minimum,[int]$Maximum,[string]$Context)
    if(($Value -isnot [int] -and $Value -isnot [long]) -or $Value -lt $Minimum -or $Value -gt $Maximum) {
        throw "$Context debe ser entero entre $Minimum y $Maximum."
    }
}

function Import-IPSPolicyConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)
    $file=Get-Item -LiteralPath $Path -ErrorAction Stop
    if($file.PSIsContainer -or $file.Length -gt 1048576) { throw 'Se requiere un archivo de politicas JSON de hasta 1 MiB.' }
    $text=[IO.File]::ReadAllText($file.FullName,[Text.Encoding]::UTF8)
    try { $config=ConvertFrom-Json -InputObject $text -ErrorAction Stop }
    catch { throw "JSON de politicas invalido: $($_.Exception.Message)" }
    # Windows PowerShell 4 treats some top-level one-element JSON arrays
    # differently. Decode each property name through an object wrapper so
    # duplicate detection also works with escaped and case-variant keys.
    $tokens=[regex]::Matches($text,'"(?:\\.|[^"\\])*"|[{}\[\]:,]')
    $objects=New-Object System.Collections.Stack
    for($i=0;$i -lt $tokens.Count;$i++) {
        $token=$tokens[$i].Value
        if($token -eq '{') { $objects.Push(@{});continue }
        if($token -eq '}') { $null=$objects.Pop();continue }
        if($token.StartsWith('"') -and ($i+1) -lt $tokens.Count -and $tokens[$i+1].Value -eq ':') {
            $decoded=ConvertFrom-Json -InputObject ('{"property":'+$token+'}') -ErrorAction Stop
            $key=[string]$decoded.property
            $keys=$objects.Peek()
            if($keys.ContainsKey($key)) { throw "Clave JSON duplicada en politicas: '$key'." }
            $keys[$key]=$true
        }
    }
    Assert-IPSPolicyObject $config @('schema_version','state_limits','policies') 'policies'
    Assert-IPSPolicyInteger $config.schema_version 1 1 'policies.schema_version'
    Assert-IPSPolicyObject $config.state_limits @('max_tracking_keys','max_events_per_key') 'state_limits'
    Assert-IPSPolicyInteger $config.state_limits.max_tracking_keys 1 65536 'state_limits.max_tracking_keys'
    Assert-IPSPolicyInteger $config.state_limits.max_events_per_key 1 1024 'state_limits.max_events_per_key'
    if($config.policies -isnot [array] -or $config.policies.Count -eq 0 -or $config.policies.Count -gt 256) {
        throw 'policies debe ser un arreglo JSON de 1 a 256 entradas.'
    }
    $ids=@{}
    foreach($policy in $config.policies) {
        Assert-IPSPolicyObject $policy @('id','enabled','description','signatures','threshold','cooldown_seconds','proposed_block_seconds') 'policy'
        if($policy.id -isnot [string] -or $policy.id -cnotmatch '^[a-z][a-z0-9_]{2,63}$') { throw "ID de politica invalido: '$($policy.id)'." }
        if($ids.ContainsKey($policy.id)) { throw "ID de politica duplicado: '$($policy.id)'." }
        $ids[$policy.id]=$true
        if($policy.enabled -isnot [bool]) { throw "policy.enabled debe ser booleano en '$($policy.id)'." }
        if($policy.description -isnot [string] -or [string]::IsNullOrWhiteSpace($policy.description) -or
            $policy.description.Length -gt 256 -or $policy.description -match '[\r\n\x00]') { throw "Descripcion invalida en '$($policy.id)'." }
        if($policy.signatures -isnot [array] -or $policy.signatures.Count -eq 0 -or $policy.signatures.Count -gt 128) {
            throw "signatures debe contener de 1 a 128 entradas en '$($policy.id)'."
        }
        $signatures=@{};$uniqueSids=@{}
        foreach($signature in $policy.signatures) {
            Assert-IPSPolicyObject $signature @('gid','sid','revisions') ('policy.'+$policy.id+'.signature')
            Assert-IPSPolicyInteger $signature.gid 1 2147483647 ('policy.'+$policy.id+'.gid')
            Assert-IPSPolicyInteger $signature.sid 1 2147483647 ('policy.'+$policy.id+'.sid')
            $uniqueSids[[string]$signature.sid]=$true
            if($signature.revisions -isnot [array] -or $signature.revisions.Count -eq 0 -or $signature.revisions.Count -gt 32) {
                throw "revisions debe ser un arreglo no vacio en '$($policy.id)'."
            }
            foreach($revision in $signature.revisions) {
                Assert-IPSPolicyInteger $revision 1 65535 ('policy.'+$policy.id+'.revision')
                $signatureKey='{0}:{1}:{2}' -f $signature.gid,$signature.sid,$revision
                if($signatures.ContainsKey($signatureKey)) { throw "Firma duplicada $signatureKey en '$($policy.id)'." }
                $signatures[$signatureKey]=$true
            }
        }
        Assert-IPSPolicyObject $policy.threshold @('count','window_seconds','distinct_ports','distinct_sids') ('policy.'+$policy.id+'.threshold')
        Assert-IPSPolicyInteger $policy.threshold.count 1 10000 ('policy.'+$policy.id+'.threshold.count')
        Assert-IPSPolicyInteger $policy.threshold.window_seconds 1 3600 ('policy.'+$policy.id+'.threshold.window_seconds')
        Assert-IPSPolicyInteger $policy.threshold.distinct_ports 0 65535 ('policy.'+$policy.id+'.threshold.distinct_ports')
        Assert-IPSPolicyInteger $policy.threshold.distinct_sids 0 128 ('policy.'+$policy.id+'.threshold.distinct_sids')
        if($policy.threshold.distinct_ports -gt $policy.threshold.count) { throw "distinct_ports supera count en '$($policy.id)'." }
        if($policy.threshold.distinct_sids -gt $policy.threshold.count) { throw "distinct_sids supera count en '$($policy.id)'." }
        if($policy.threshold.distinct_sids -gt $uniqueSids.Count) { throw "distinct_sids supera los SID disponibles en '$($policy.id)'." }
        if($policy.threshold.count -gt $config.state_limits.max_events_per_key) { throw "count supera max_events_per_key en '$($policy.id)'." }
        Assert-IPSPolicyInteger $policy.cooldown_seconds 0 86400 ('policy.'+$policy.id+'.cooldown_seconds')
        Assert-IPSPolicyInteger $policy.proposed_block_seconds 15 86400 ('policy.'+$policy.id+'.proposed_block_seconds')
    }
    return $config
}

function New-IPSPolicyEngine {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Configuration)
    $index=@{}
    foreach($policy in $Configuration.policies) {
        if(-not $policy.enabled) { continue }
        foreach($signature in $policy.signatures) {
            foreach($revision in $signature.revisions) {
                $key='{0}:{1}:{2}' -f $signature.gid,$signature.sid,$revision
                if(-not $index.ContainsKey($key)) { $index[$key]=New-Object System.Collections.ArrayList }
                $null=$index[$key].Add($policy)
            }
        }
    }
    [pscustomobject]@{
        Configuration=$Configuration
        Index=$index
        Tracking=@{}
        Cooldowns=@{}
    }
}

function Remove-IPSExpiredPolicyState {
    param($Engine,[DateTime]$NowUtc)
    foreach($key in @($Engine.Cooldowns.Keys)) {
        if($Engine.Cooldowns[$key] -le $NowUtc) { $Engine.Cooldowns.Remove($key) }
    }
    foreach($key in @($Engine.Tracking.Keys)) {
        $state=$Engine.Tracking[$key]
        $cutoff=$NowUtc.AddSeconds(-[int]$state.Policy.threshold.window_seconds)
        $kept=New-Object System.Collections.ArrayList
        foreach($item in $state.Events) { if($item.TimeUtc -ge $cutoff) { $null=$kept.Add($item) } }
        $state.Events=$kept
        if($state.Events.Count -eq 0) { $Engine.Tracking.Remove($key) }
    }
}

function New-IPSPolicyResult {
    param([string]$Result,[string]$Reason,$Policy,[int]$Count,[int]$DistinctPorts,[int]$DistinctSids,[int]$CooldownRemaining=0)
    [pscustomobject]@{
        Result=$Result;Reason=$Reason
        PolicyId=$(if($null -eq $Policy){$null}else{$Policy.id})
        ObservedCount=$Count
        RequiredCount=$(if($null -eq $Policy){0}else{[int]$Policy.threshold.count})
        DistinctPorts=$DistinctPorts
        RequiredDistinctPorts=$(if($null -eq $Policy){0}else{[int]$Policy.threshold.distinct_ports})
        DistinctSids=$DistinctSids
        RequiredDistinctSids=$(if($null -eq $Policy){0}else{[int]$Policy.threshold.distinct_sids})
        WindowSeconds=$(if($null -eq $Policy){0}else{[int]$Policy.threshold.window_seconds})
        ProposedBlockSeconds=$(if($null -eq $Policy){0}else{[int]$Policy.proposed_block_seconds})
        CooldownRemainingSeconds=$CooldownRemaining
    }
}

function Add-IPSPolicyAlert {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Engine,[Parameter(Mandatory=$true)]$Alert,
          [Parameter(Mandatory=$true)][string]$Source,[DateTime]$NowUtc=([DateTime]::UtcNow))
    Remove-IPSExpiredPolicyState $Engine $NowUtc
    $signatureKey='{0}:{1}:{2}' -f $Alert.Gid,$Alert.Sid,$Alert.Rev
    if(-not $Engine.Index.ContainsKey($signatureKey)) {
        return (New-IPSPolicyResult 'NO_POLICY' 'La firma y revision no tienen una politica Audit habilitada.' $null 0 0 0)
    }
    $results=New-Object System.Collections.ArrayList
    foreach($policy in $Engine.Index[$signatureKey]) {
        $trackingKey=$policy.id+'|'+$Source
        if($Engine.Cooldowns.ContainsKey($trackingKey)) {
            $remaining=[int][Math]::Ceiling(($Engine.Cooldowns[$trackingKey]-$NowUtc).TotalSeconds)
            $null=$results.Add((New-IPSPolicyResult 'COOLDOWN' 'La politica ya propuso un bloqueo recientemente.' $policy 0 0 0 $remaining))
            continue
        }
        if(-not $Engine.Tracking.ContainsKey($trackingKey)) {
            if($Engine.Tracking.Count -ge [int]$Engine.Configuration.state_limits.max_tracking_keys) {
                $null=$results.Add((New-IPSPolicyResult 'STATE_LIMIT' 'Limite de claves de seguimiento alcanzado; no se toma decision.' $policy 0 0 0))
                continue
            }
            $Engine.Tracking[$trackingKey]=[pscustomobject]@{Policy=$policy;Events=(New-Object System.Collections.ArrayList)}
        }
        $state=$Engine.Tracking[$trackingKey]
        $port=$(if($null -eq $Alert.DestinationPort){-1}else{[int]$Alert.DestinationPort})
        $null=$state.Events.Add([pscustomobject]@{TimeUtc=$NowUtc;Port=$port;Sid=[int]$Alert.Sid})
        while($state.Events.Count -gt [int]$Engine.Configuration.state_limits.max_events_per_key) { $state.Events.RemoveAt(0) }
        $ports=@($state.Events | Where-Object {$_.Port -ge 0} | ForEach-Object {$_.Port} | Sort-Object -Unique)
        $sids=@($state.Events | ForEach-Object {$_.Sid} | Sort-Object -Unique)
        $count=$state.Events.Count
        $met=($count -ge [int]$policy.threshold.count)
        if([int]$policy.threshold.distinct_ports -gt 0) { $met=$met -and ($ports.Count -ge [int]$policy.threshold.distinct_ports) }
        if([int]$policy.threshold.distinct_sids -gt 0) { $met=$met -and ($sids.Count -ge [int]$policy.threshold.distinct_sids) }
        if($met) {
            $null=$results.Add((New-IPSPolicyResult 'WOULD_BLOCK' 'Umbral de politica satisfecho; solicitud disponible para el actuador.' $policy $count $ports.Count $sids.Count))
            $Engine.Tracking.Remove($trackingKey)
            if([int]$policy.cooldown_seconds -gt 0) { $Engine.Cooldowns[$trackingKey]=$NowUtc.AddSeconds([int]$policy.cooldown_seconds) }
        } else {
            $null=$results.Add((New-IPSPolicyResult 'TRACKING' 'Alerta acumulada; el umbral aun no se cumple.' $policy $count $ports.Count $sids.Count))
        }
    }
    return @($results.ToArray())
}

Export-ModuleMember -Function Import-IPSPolicyConfiguration,New-IPSPolicyEngine,Add-IPSPolicyAlert
