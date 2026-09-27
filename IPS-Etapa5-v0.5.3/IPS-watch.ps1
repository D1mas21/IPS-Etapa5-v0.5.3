#Requires -Version 4.0
<#
SOC DEKMA IPS - etapa 5, operacion concurrente y limpieza independiente.
-RunMode Validate conserva el validador de etapa 1.
-RunMode Watch observa SOLO eventos nuevos y registra JSONL.
Audit simula; Enforce requiere configuracion y -EnableEnforcement explicito.
Requiere Windows PowerShell 4.0 y ejecucion en el servidor protegido.
#>
[CmdletBinding()]
param(
    [ValidateSet('Validate','Watch')][string]$RunMode='Validate',
    [string]$ConfigPath,
    [string]$PolicyPath,
    [string[]]$TestAddress=@(),
    [string]$ReportPath,
    [string]$BridgePath,
    [string]$EventLogDirectory,
    [string]$StatePath,
    [switch]$EnableEnforcement,
    [ValidateRange(0,1000000)][int]$MaxPolls=0,
    [ValidateSet('End','Beginning')][string]$StartAt='End',
    [scriptblock]$FileKeyProvider
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$scriptFile=$MyInvocation.MyCommand.Path
if([string]::IsNullOrWhiteSpace($scriptFile)){throw 'No se pudo resolver la ruta de IPS-watch.ps1.'}
$scriptRoot=Split-Path -Parent $scriptFile
if([string]::IsNullOrWhiteSpace($ConfigPath)){$ConfigPath=Join-Path $scriptRoot 'config\ips-config.json'}
if([string]::IsNullOrWhiteSpace($PolicyPath)){$PolicyPath=Join-Path $scriptRoot 'config\ips-policies.json'}
if([string]::IsNullOrWhiteSpace($EventLogDirectory)){$EventLogDirectory=Join-Path $scriptRoot 'events'}
if([string]::IsNullOrWhiteSpace($StatePath)){$StatePath=Join-Path $scriptRoot 'state\firewall-blocks.json'}

if ($RunMode -eq 'Validate') {
    if ($BridgePath -or $MaxPolls -or $StartAt -ne 'End' -or $null -ne $FileKeyProvider -or $EnableEnforcement) {
        Write-Error 'BridgePath, MaxPolls, StartAt, FileKeyProvider y EnableEnforcement solo aplican a -RunMode Watch.'
        exit 1
    }
    & (Join-Path $scriptRoot 'IPS-validate.ps1') -ConfigPath $ConfigPath -TestAddress $TestAddress -ReportPath $ReportPath
    if($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    try {
        Import-Module (Join-Path $scriptRoot 'modules\PolicyEngine.psm1') -Force -ErrorAction Stop
        $validatedPolicies=Import-IPSPolicyConfiguration -Path $PolicyPath
        $policyCount=@($validatedPolicies.policies).Count
        $enabledPolicyCount=@($validatedPolicies.policies | Where-Object {$_.enabled}).Count
        Write-Host ('POLICY_CONFIG_VALID - {0} politicas; {1} habilitadas; ningun bloqueo ejecutado.' -f $policyCount,$enabledPolicyCount)
        exit 0
    } catch {
        Write-Error ('Politicas invalidas: '+$_.Exception.Message)
        exit 1
    }
}
if ($ReportPath -or $TestAddress.Count -gt 0) {
    Write-Error 'TestAddress y ReportPath solo aplican a -RunMode Validate.'
    exit 1
}

$exitCode=1
$mutex=$null
$held=$false
$stoppedLogged=$false
$runtimeMode='Audit'
$script:latencyCounters=[ordered]@{accepted=0;delayed=0;stale_rejected=0;future_rejected=0}

function Write-IPSJsonEvent {
    param([string]$Name, [hashtable]$Fields=@{}, [switch]$PassThru)
    Write-IPSOperationalEvent -Directory $EventLogDirectory -Component 'dekma_ips' `
        -Mode $script:runtimeMode -Name $Name -Fields $Fields -PassThru:$PassThru
}

function Invoke-IPSActuatorLocked {
    param([scriptblock]$Action)
    Invoke-IPSWithMutex -Name (Get-IPSStateMutexName) -TimeoutMilliseconds 30000 -ScriptBlock {
        # Se reconstruye desde disco dentro del mutex para evitar estado obsoleto
        # cuando IPS-control o IPS-cleanup trabajaron en otro proceso.
        $script:actuator=New-IPSFirewallActuator -Mode $script:runtimeMode -StatePath $StatePath -Resolved $resolved `
            -MaxActiveBlocks ([int]$config.operation.max_active_blocks)
        & $Action $script:actuator
    }
}

function Write-IPSActuatorOutcome {
    param($Outcome,[string]$PolicyId,[int]$BlockSeconds,[switch]$PassThru)
    $name='BLOCK_ERROR'
    if($Outcome.Result -eq 'SIMULATED'){$name='BLOCK_SIMULATED'}
    elseif($Outcome.Result -eq 'CREATED'){$name='BLOCK_CREATED'}
    elseif($Outcome.Result -eq 'REFRESHED'){$name='BLOCK_REFRESHED'}
    elseif($Outcome.Result -eq 'REFUSED'){$name='BLOCK_REFUSED'}
    elseif($Outcome.Result -eq 'LIMIT'){$name='BLOCK_LIMIT'}
    elseif($Outcome.Result -eq 'CONFLICT'){$name='BLOCK_CONFLICT'}
    Write-IPSJsonEvent $name @{
        policy_id=$PolicyId;src_ip=$Outcome.Source;dst_ip=$Outcome.Destination
        rule_name=$Outcome.RuleName;block_seconds=$BlockSeconds
        expires_utc=$(if($null -eq $Outcome.ExpiresUtc){$null}else{$Outcome.ExpiresUtc.ToString('o')})
        actuator_result=$Outcome.Result;reason=$Outcome.Reason
        firewall_modified=$Outcome.FirewallModified
    } -PassThru:$PassThru
}

function Submit-IPSBlockRequest {
    param([string]$Source,[string]$Destination,[string]$PolicyId,[int]$BlockSeconds,[string]$ProposalId=$null)
    $submitWatch=[Diagnostics.Stopwatch]::StartNew()
    $requestWrite=Write-IPSJsonEvent 'BLOCK_REQUEST' @{
        policy_id=$PolicyId;proposal_id=$ProposalId;src_ip=$Source;dst_ip=$Destination;block_seconds=$BlockSeconds
        reason='Solicitud enviada al actuador despues de WOULD_BLOCK.'
    } -PassThru
    $actuatorWatch=[Diagnostics.Stopwatch]::StartNew()
    $outcome=Invoke-IPSActuatorLocked {
        param($lockedActuator)
        Invoke-IPSBlockRequest -Actuator $lockedActuator -Source $Source -Destination $Destination `
            -PolicyId $PolicyId -BlockSeconds $BlockSeconds -NowUtc ([DateTime]::UtcNow)
    }
    $actuatorWatch.Stop()
    $outcomeWrite=Write-IPSActuatorOutcome $outcome $PolicyId $BlockSeconds -PassThru
    $submitWatch.Stop()
    [pscustomobject]@{
        ActuatorMilliseconds=[Math]::Round($actuatorWatch.Elapsed.TotalMilliseconds,3)
        MutexWaitMilliseconds=[Math]::Round(($requestWrite.MutexWaitMilliseconds+$outcomeWrite.MutexWaitMilliseconds),3)
        FileWriteMilliseconds=[Math]::Round(($requestWrite.FileWriteMilliseconds+$outcomeWrite.FileWriteMilliseconds),3)
        ConsoleWriteMilliseconds=[Math]::Round(($requestWrite.ConsoleWriteMilliseconds+$outcomeWrite.ConsoleWriteMilliseconds),3)
        TotalMilliseconds=[Math]::Round($submitWatch.Elapsed.TotalMilliseconds,3)
        Result=$outcome.Result
        Outcome=$outcome
    }
}

try {
    Import-Module (Join-Path $scriptRoot 'modules\Configuration.psm1') -Force -ErrorAction Stop
    Import-Module (Join-Path $scriptRoot 'modules\SnortReader.psm1') -Force -ErrorAction Stop
    Import-Module (Join-Path $scriptRoot 'modules\PolicyEngine.psm1') -Force -ErrorAction Stop
    Import-Module (Join-Path $scriptRoot 'modules\FirewallActuator.psm1') -Force -ErrorAction Stop
    Import-Module (Join-Path $scriptRoot 'modules\Operational.psm1') -Force -ErrorAction Stop
    Import-Module (Join-Path $scriptRoot 'modules\LatencyPolicy.psm1') -Force -ErrorAction Stop
    $config=Import-IPSConfiguration -Path $ConfigPath
    $inventory=Get-IPSInventory
    $resolved=Resolve-IPSConfiguration -Configuration $config -Inventory $inventory
    if (-not $resolved.Valid) { throw ('Configuracion invalida: ' + ($resolved.Errors -join '; ')) }
    $policyConfig=Import-IPSPolicyConfiguration -Path $PolicyPath
    $policyEngine=New-IPSPolicyEngine -Configuration $policyConfig
    $script:runtimeMode=[string]$config.operation.mode
    if($script:runtimeMode -eq 'Enforce'){
        if(-not $EnableEnforcement){throw 'Enforce requiere el parametro explicito -EnableEnforcement.'}
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
        $principal=New-Object Security.Principal.WindowsPrincipal($identity)
        if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Enforce requiere PowerShell como administrador.'}
        foreach($commandName in @('Get-NetFirewallRule','New-NetFirewallRule','Remove-NetFirewallRule','Get-NetFirewallAddressFilter')){
            if($null -eq (Get-Command $commandName -ErrorAction SilentlyContinue)){throw "$commandName no esta disponible."}
        }
    } elseif($EnableEnforcement){throw 'EnableEnforcement no se admite mientras operation.mode=Audit.'}
    $alertPath=$config.snort.alert_path
    if ($BridgePath) {
        $alertPath=[IO.Path]::GetFullPath($BridgePath)
        if (-not [IO.Path]::IsPathRooted($alertPath)) { throw 'BridgePath debe ser ruta absoluta.' }
    }
    $eventDir=[IO.Path]::GetFullPath($EventLogDirectory)
    if (-not (Test-Path -LiteralPath $eventDir -PathType Container)) {
        $null=New-Item -ItemType Directory -Path $eventDir -ErrorAction Stop
    }
    $mutex=New-Object Threading.Mutex -ArgumentList $false,'Global\SOC-DEKMA-IPS-WATCH-5'
    try { $held=$mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $held=$true }
    if (-not $held) { throw 'Ya existe otra instancia IPS etapa 5. Detengala antes de iniciar otra.' }

    if($script:runtimeMode -eq 'Enforce'){
        $startupCleanup=@(Invoke-IPSActuatorLocked {param($lockedActuator) @(Invoke-IPSExpiredCleanup -Actuator $lockedActuator -NowUtc ([DateTime]::UtcNow))})
        foreach($cleanup in $startupCleanup){
            $cleanupEvent=$(if($cleanup.Result -eq 'REMOVED'){'BLOCK_EXPIRED_REMOVED'}elseif($cleanup.Result -eq 'STATE_STALE'){'BLOCK_STATE_STALE'}elseif($cleanup.Result -eq 'CONFLICT'){'BLOCK_CONFLICT'}else{'BLOCK_ERROR'})
            Write-IPSJsonEvent $cleanupEvent @{src_ip=$cleanup.Source;dst_ip=$cleanup.Destination;rule_name=$cleanup.RuleName;actuator_result=$cleanup.Result;reason=$cleanup.Reason;firewall_modified=$cleanup.FirewallModified}
        }
    }

    $reader=New-IPSSnortReader -StartAt $StartAt -FileKeyProvider $FileKeyProvider
    Write-IPSJsonEvent 'WATCH_STARTED' @{source_path=$alertPath;event_log_directory=$eventDir;start_at=$StartAt;protected_server=$config.protected_server;policy_path=([IO.Path]::GetFullPath($PolicyPath));state_path=([IO.Path]::GetFullPath($StatePath));enabled_policies=@($policyConfig.policies | Where-Object {$_.enabled}).Count;enforcement_confirmed=[bool]$EnableEnforcement;delay_warning_seconds=[int]$config.operation.delay_warning_seconds;max_event_age_seconds=[int]$config.operation.max_event_age_seconds;performance_telemetry=$true;slow_processing_threshold_ms=1000}
    $poll=0
    $nextCleanupUtc=[DateTime]::UtcNow.AddSeconds(5)
    while ($true) {
        $chunk=Get-IPSSnortChunk -Path $alertPath -State $reader
        foreach ($signal in $chunk.Signals) {
            Write-IPSJsonEvent $signal.event @{reason=$signal.reason;bytes=$signal.bytes}
        }
        foreach ($line in $chunk.Lines) {
            $processingWatch=[Diagnostics.Stopwatch]::StartNew()
            [double]$logMutexWaitMs=0;[double]$logFileWriteMs=0;[double]$consoleWriteMs=0
            [double]$policyEngineMs=0;[double]$actuatorMs=0;[double]$actuatorTotalMs=0
            $now=Get-Date
            $alert=ConvertFrom-IPSSnortAlert -Line $line.Text -Now $now
            if (-not $alert.Valid) {
                $rejectedEvent='ALERT_REJECTED'
                if ($alert.Reason -eq 'UNSUPPORTED_IPV6') { $rejectedEvent='ALERT_UNSUPPORTED_IPV6' }
                Write-IPSJsonEvent $rejectedEvent @{reason=$alert.Reason;line_length=$line.Text.Length}
                continue
            }
            $base=@{
                snort_gid=$alert.Gid;snort_sid=$alert.Sid;snort_rev=$alert.Rev
                snort_timestamp=$alert.TimestampLocal.ToString('o')
                src_ip=$alert.Source;src_port=$alert.SourcePort
                dst_ip=$alert.Destination;dst_port=$alert.DestinationPort
                protocol=$alert.Protocol;snort_priority=$alert.Priority
                snort_classification=$alert.Classification
                snort_message=$alert.Message
                age_seconds=[Math]::Round($alert.AgeSeconds,3)
            }
            $latency=Test-IPSEventAge -AgeSeconds $alert.AgeSeconds `
                -WarningSeconds ([int]$config.operation.delay_warning_seconds) `
                -MaximumSeconds ([int]$config.operation.max_event_age_seconds)
            $base['delivery_status']=$latency.Result
            $base['delivery_delayed']=[bool]$latency.Delayed
            $base['delay_warning_seconds']=[int]$config.operation.delay_warning_seconds
            $base['max_event_age_seconds']=[int]$config.operation.max_event_age_seconds
            $event='ALERT_OBSERVED';$decision='SUBJECT_TO_POLICY';$reason='Alerta elegible para el motor de politicas Audit.'
            if (-not $latency.Accept) {
                $event='ALERT_REJECTED'
                if($latency.Result -eq 'STALE'){
                    $decision='STALE';$script:latencyCounters['stale_rejected']++
                }else{
                    $decision='FUTURE';$script:latencyCounters['future_rejected']++
                }
                $reason=$latency.Reason
                $base['stale_rejected_total']=$script:latencyCounters.stale_rejected
                $base['future_rejected_total']=$script:latencyCounters.future_rejected
            } elseif (Test-IPSSnortDuplicate -State $reader -Line $line.Text) {
                $event='ALERT_DUPLICATE';$decision='DUPLICATE';$reason='Misma linea repetida dentro de la ventana de 30 s.'
            } elseif ($alert.Destination -ne $config.protected_server) {
                $event='ALERT_OUTSIDE_TARGET';$decision='OUTSIDE_TARGET';$reason='Destino distinto al servidor protegido.'
            } elseif ($alert.Gid -ne 1 -or $alert.Sid -lt 1000000 -or $alert.Sid -ge 2000000) {
                $event='ALERT_OTHER_SIGNATURE';$decision='UNSUPPORTED_SIGNATURE';$reason='No es un SID SOC DEKMA habilitado para respuesta.'
            } else {
                $ipDecision=Test-IPSAddress -Address $alert.Source -Resolved $resolved
                $decision=$ipDecision.Decision
                $reason=$ipDecision.Reason
                if ($decision -eq 'PROTECTED' -or $decision -eq 'EXCLUDED') { $event='ALERT_PROTECTED' }
            }
            if($latency.Accept){
                $script:latencyCounters['accepted']++
                if($latency.Delayed){$script:latencyCounters['delayed']++}
            }
            $base['decision']=$decision;$base['reason']=$reason
            $base['accepted_total']=$script:latencyCounters.accepted
            $base['delayed_total']=$script:latencyCounters.delayed
            $decisionMs=[Math]::Round($processingWatch.Elapsed.TotalMilliseconds,3)
            $eventWrite=Write-IPSJsonEvent $event $base -PassThru
            $logMutexWaitMs+=$eventWrite.MutexWaitMilliseconds
            $logFileWriteMs+=$eventWrite.FileWriteMilliseconds
            $consoleWriteMs+=$eventWrite.ConsoleWriteMilliseconds
            if($event -eq 'ALERT_OBSERVED' -and $decision -eq 'DENYLIST_MATCH') {
                $wouldWrite=Write-IPSJsonEvent 'WOULD_BLOCK' @{
                    policy_id='manual_denylist';src_ip=$alert.Source;dst_ip=$alert.Destination
                    trigger_gid=$alert.Gid;trigger_sid=$alert.Sid;trigger_rev=$alert.Rev
                    observed_count=1;required_count=1;distinct_ports=0;required_distinct_ports=0
                    distinct_sids=1;required_distinct_sids=1;window_seconds=0
                    proposed_block_seconds=[int]$config.operation.block_seconds
                    cooldown_remaining_seconds=0;decision='WOULD_BLOCK'
                    reason='Coincidencia con lista negra; solicitud disponible para el actuador.'
                } -PassThru
                $logMutexWaitMs+=$wouldWrite.MutexWaitMilliseconds
                $logFileWriteMs+=$wouldWrite.FileWriteMilliseconds
                $consoleWriteMs+=$wouldWrite.ConsoleWriteMilliseconds
                $actuation=Submit-IPSBlockRequest $alert.Source $alert.Destination 'manual_denylist' ([int]$config.operation.block_seconds)
                $actuatorMs+=$actuation.ActuatorMilliseconds;$actuatorTotalMs+=$actuation.TotalMilliseconds
                $logMutexWaitMs+=$actuation.MutexWaitMilliseconds;$logFileWriteMs+=$actuation.FileWriteMilliseconds;$consoleWriteMs+=$actuation.ConsoleWriteMilliseconds
            } elseif($event -eq 'ALERT_OBSERVED' -and $decision -eq 'SUBJECT_TO_POLICY') {
                $policyWatch=[Diagnostics.Stopwatch]::StartNew()
                $policyResults=@(Add-IPSPolicyAlert -Engine $policyEngine -Alert $alert -Source $alert.Source -NowUtc ([DateTime]::UtcNow))
                $policyWatch.Stop();$policyEngineMs=[Math]::Round($policyWatch.Elapsed.TotalMilliseconds,3)
                foreach($policyResult in $policyResults) {
                    $policyEvent='POLICY_TRACKING'
                    if($policyResult.Result -eq 'WOULD_BLOCK') { $policyEvent='WOULD_BLOCK' }
                    elseif($policyResult.Result -eq 'NO_POLICY') { $policyEvent='ALERT_NO_POLICY' }
                    elseif($policyResult.Result -eq 'COOLDOWN') { $policyEvent='POLICY_COOLDOWN' }
                    elseif($policyResult.Result -eq 'PENDING') { $policyEvent='POLICY_PENDING' }
                    elseif($policyResult.Result -eq 'STATE_LIMIT') { $policyEvent='POLICY_STATE_LIMIT' }
                    $policyWrite=Write-IPSJsonEvent $policyEvent @{
                        policy_id=$policyResult.PolicyId;proposal_id=$policyResult.ProposalId;src_ip=$alert.Source;dst_ip=$alert.Destination
                        trigger_gid=$alert.Gid;trigger_sid=$alert.Sid;trigger_rev=$alert.Rev
                        observed_count=$policyResult.ObservedCount;required_count=$policyResult.RequiredCount
                        distinct_ports=$policyResult.DistinctPorts;required_distinct_ports=$policyResult.RequiredDistinctPorts
                        distinct_sids=$policyResult.DistinctSids;required_distinct_sids=$policyResult.RequiredDistinctSids
                        window_seconds=$policyResult.WindowSeconds;proposed_block_seconds=$policyResult.ProposedBlockSeconds
                        cooldown_remaining_seconds=$policyResult.CooldownRemainingSeconds
                        decision=$policyResult.Result;reason=$policyResult.Reason
                    } -PassThru
                    $logMutexWaitMs+=$policyWrite.MutexWaitMilliseconds
                    $logFileWriteMs+=$policyWrite.FileWriteMilliseconds
                    $consoleWriteMs+=$policyWrite.ConsoleWriteMilliseconds
                    if($policyResult.Result -eq 'WOULD_BLOCK'){
                        $actuation=Submit-IPSBlockRequest $alert.Source $alert.Destination $policyResult.PolicyId ([int]$policyResult.ProposedBlockSeconds) $policyResult.ProposalId
                        $actuatorMs+=$actuation.ActuatorMilliseconds;$actuatorTotalMs+=$actuation.TotalMilliseconds
                        $logMutexWaitMs+=$actuation.MutexWaitMilliseconds;$logFileWriteMs+=$actuation.FileWriteMilliseconds;$consoleWriteMs+=$actuation.ConsoleWriteMilliseconds
                        if(@('SIMULATED','CREATED','REFRESHED') -contains $actuation.Result){
                            $transaction=Confirm-IPSPolicyBlock -Engine $policyEngine -ProposalId $policyResult.ProposalId -NowUtc ([DateTime]::UtcNow)
                            Write-IPSJsonEvent 'BLOCK_COMMITTED' @{
                                policy_id=$transaction.PolicyId;proposal_id=$transaction.ProposalId;src_ip=$transaction.Source
                                dst_ip=$alert.Destination;actuator_result=$actuation.Result
                                cooldown_seconds=$transaction.CooldownSeconds
                                reason='El actuador confirmo la solicitud; se inicia cooldown.'
                            }
                        } else {
                            $transaction=Cancel-IPSPolicyBlock -Engine $policyEngine -ProposalId $policyResult.ProposalId
                            Write-IPSJsonEvent 'BLOCK_ABORTED' @{
                                policy_id=$transaction.PolicyId;proposal_id=$transaction.ProposalId;src_ip=$transaction.Source
                                dst_ip=$alert.Destination;actuator_result=$actuation.Result
                                tracking_preserved=$transaction.TrackingPreserved
                                reason='El actuador no confirmo el bloqueo; no se inicia cooldown.'
                            }
                        }
                    }
                }
            }
            $processingWatch.Stop()
            $totalProcessingMs=[Math]::Round($processingWatch.Elapsed.TotalMilliseconds,3)
            $knownMs=$decisionMs+$logMutexWaitMs+$logFileWriteMs+$consoleWriteMs+$policyEngineMs+$actuatorMs
            $unattributedMs=[Math]::Round([Math]::Max(0,($totalProcessingMs-$knownMs)),3)
            $components=[ordered]@{
                decision=$decisionMs;log_mutex_wait=$logMutexWaitMs;log_file_write=$logFileWriteMs
                console_write=$consoleWriteMs;policy_engine=$policyEngineMs;actuator=$actuatorMs;unattributed=$unattributedMs
            }
            $primaryDelay='decision';$primaryDelayMs=[double]$components.decision
            foreach($componentName in $components.Keys){
                if([double]$components[$componentName] -gt $primaryDelayMs){$primaryDelay=$componentName;$primaryDelayMs=[double]$components[$componentName]}
            }
            Write-IPSJsonEvent 'PERFORMANCE_SAMPLE' @{
                snort_gid=$alert.Gid;snort_sid=$alert.Sid;snort_rev=$alert.Rev;src_ip=$alert.Source;dst_ip=$alert.Destination;dst_port=$alert.DestinationPort
                alert_event=$event;alert_decision=$decision;delivery_status=$latency.Result;bridge_delivery_ms=[Math]::Round(($alert.AgeSeconds*1000),3)
                decision_ms=$decisionMs;log_mutex_wait_ms=[Math]::Round($logMutexWaitMs,3);log_file_write_ms=[Math]::Round($logFileWriteMs,3)
                console_write_ms=[Math]::Round($consoleWriteMs,3);policy_engine_ms=[Math]::Round($policyEngineMs,3)
                actuator_ms=[Math]::Round($actuatorMs,3);actuator_pipeline_ms=[Math]::Round($actuatorTotalMs,3)
                unattributed_ms=$unattributedMs;total_processing_ms=$totalProcessingMs
                slow_processing=($totalProcessingMs -ge 1000);slow_processing_threshold_ms=1000
                primary_delay=$primaryDelay;primary_delay_ms=[Math]::Round($primaryDelayMs,3)
            }
        }
        if($script:runtimeMode -eq 'Enforce' -and [DateTime]::UtcNow -ge $nextCleanupUtc){
            try{
                $periodicCleanup=@(Invoke-IPSActuatorLocked {param($lockedActuator) @(Invoke-IPSExpiredCleanup -Actuator $lockedActuator -NowUtc ([DateTime]::UtcNow))})
                foreach($cleanup in $periodicCleanup){
                    $cleanupEvent=$(if($cleanup.Result -eq 'REMOVED'){'BLOCK_EXPIRED_REMOVED'}elseif($cleanup.Result -eq 'STATE_STALE'){'BLOCK_STATE_STALE'}elseif($cleanup.Result -eq 'CONFLICT'){'BLOCK_CONFLICT'}else{'BLOCK_ERROR'})
                    Write-IPSJsonEvent $cleanupEvent @{src_ip=$cleanup.Source;dst_ip=$cleanup.Destination;rule_name=$cleanup.RuleName;actuator_result=$cleanup.Result;reason=$cleanup.Reason;firewall_modified=$cleanup.FirewallModified}
                }
            }catch{Write-IPSJsonEvent 'CLEANUP_ERROR' @{reason=$_.Exception.Message}}
            $nextCleanupUtc=[DateTime]::UtcNow.AddSeconds(5)
        }
        $poll++
        if ($MaxPolls -gt 0 -and $poll -ge $MaxPolls) { break }
        Start-Sleep -Milliseconds $config.operation.poll_milliseconds
    }
    Write-IPSJsonEvent 'WATCH_STOPPED' @{reason='MaxPolls completado';polls=$poll;accepted_total=$script:latencyCounters.accepted;delayed_total=$script:latencyCounters.delayed;stale_rejected_total=$script:latencyCounters.stale_rejected;future_rejected_total=$script:latencyCounters.future_rejected}
    $stoppedLogged=$true
    $exitCode=0
} catch {
    try { Write-IPSJsonEvent 'WATCH_ERROR' @{reason=$_.Exception.Message} }
    catch { Write-Warning ('WATCH_ERROR (sin log): ' + $_.Exception.Message) }
    Write-Error ('IPS etapa 5: ' + $_.Exception.Message) -ErrorAction Continue
} finally {
    if (-not $stoppedLogged) {
        try { Write-IPSJsonEvent 'WATCH_STOPPED' @{reason='Proceso detenido o error';accepted_total=$script:latencyCounters.accepted;delayed_total=$script:latencyCounters.delayed;stale_rejected_total=$script:latencyCounters.stale_rejected;future_rejected_total=$script:latencyCounters.future_rejected} }
        catch { Write-Warning ('No se pudo registrar WATCH_STOPPED: ' + $_.Exception.Message) }
    }
    if ($held) { $mutex.ReleaseMutex() }
    if ($null -ne $mutex) { $mutex.Dispose() }
}
exit $exitCode
