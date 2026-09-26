#Requires -Version 4.0
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$root=Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$module=Join-Path $root 'modules\Operational.psm1'
Import-Module $module -Force
Import-Module (Join-Path $root 'modules\LatencyPolicy.psm1') -Force

function Check {param([bool]$Condition,[string]$Message) if(-not $Condition){throw $Message};Write-Host ('PASS '+$Message)}

$temp=Join-Path ([IO.Path]::GetTempPath()) ('ips-stage5-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
try{
    $fixedUtc=[DateTime]::Parse('2026-09-26T13:00:00Z').ToUniversalTime()
    $fixedLocal=[DateTime]::Parse('2026-09-26T09:00:00')
    $one=Write-IPSOperationalEvent -Directory $temp -Component 'test' -Mode 'Audit' -Name 'TEST_ONE' `
        -Fields @{value=1} -NowUtc $fixedUtc -LocalDate $fixedLocal -PassThru
    Check ((Split-Path -Leaf $one.Path) -eq 'ips.2026-09-26.log') 'Daily filename is ips.YYYY-MM-DD.log'
    Check (Test-Path -LiteralPath $one.Path -PathType Leaf) 'Daily log created'
    $parsed=ConvertFrom-Json -InputObject $one.Line
    Check ($parsed.event -eq 'TEST_ONE' -and $parsed.schema_version -eq 1) 'JSON event schema preserved'
    Check ($one.PSObject.Properties.Name -ccontains 'MutexWaitMilliseconds') 'Log mutex wait metric returned'
    Check ($one.PSObject.Properties.Name -ccontains 'FileWriteMilliseconds') 'Log file write metric returned'
    Check ($one.PSObject.Properties.Name -ccontains 'ConsoleWriteMilliseconds') 'Console write metric returned'
    Check ($one.MutexWaitMilliseconds -ge 0 -and $one.FileWriteMilliseconds -ge 0 -and $one.ConsoleWriteMilliseconds -ge 0 -and $one.TotalWriteMilliseconds -ge 0) 'Operational timing metrics are nonnegative'
    $bytes=[IO.File]::ReadAllBytes($one.Path)
    Check (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)) 'Log is UTF8 without BOM'

    $handle=Enter-IPSNamedMutex -Name ('Global\SOC-DEKMA-IPS-TEST-'+[Guid]::NewGuid().ToString('N')) -TimeoutMilliseconds 1000
    Check ($handle.Acquired) 'Named mutex acquired'
    Exit-IPSNamedMutex $handle
    Check (-not $handle.Acquired) 'Named mutex released'

    $concurrent=Join-Path $temp 'concurrent'
    $jobs=@()
    foreach($worker in 1..2){
        $jobs+=Start-Job -ArgumentList $module,$concurrent,$worker -ScriptBlock {
            param($modulePath,$directory,$id)
            Import-Module $modulePath -Force
            foreach($index in 1..20){
                Write-IPSOperationalEvent -Directory $directory -Component ('worker_'+$id) -Mode 'Audit' `
                    -Name 'CONCURRENT_WRITE' -Fields @{worker=$id;sequence=$index}
            }
        }
    }
    $null=Wait-Job -Job $jobs -Timeout 60
    $failed=@($jobs|Where-Object{$_.State -ne 'Completed'})
    Check ($failed.Count -eq 0) 'Concurrent writers completed'
    $null=@($jobs|Receive-Job)
    $files=@(Get-ChildItem -LiteralPath $concurrent -Filter 'ips.*.log')
    Check ($files.Count -eq 1) 'Concurrent writers share one daily file'
    $lines=@(Get-Content -LiteralPath $files[0].FullName)
    Check ($lines.Count -eq 40) 'Concurrent writes are not lost'
    foreach($line in $lines){$null=ConvertFrom-Json -InputObject $line}
    Check ($true) 'Every concurrent line is valid JSON'
    Check (@(Get-ChildItem -LiteralPath $temp -Recurse -Filter 'ips-stage4.*.jsonl').Count -eq 0) 'Legacy stage4 log name not generated'

    $watch=[IO.File]::ReadAllText((Join-Path $root 'IPS-watch.ps1'))
    $control=[IO.File]::ReadAllText((Join-Path $root 'IPS-control.ps1'))
    $cleanup=[IO.File]::ReadAllText((Join-Path $root 'IPS-cleanup.ps1'))
    Check ($watch.Contains('Get-IPSStateMutexName') -and $control.Contains('Get-IPSStateMutexName') -and $cleanup.Contains('Get-IPSStateMutexName')) 'Watch, control and cleanup use shared state mutex'
    Check ($cleanup.Contains("[switch]`$ConfirmRemoval") -and $cleanup.Contains("if(-not `$ConfirmRemoval)")) 'Independent cleanup requires explicit confirmation'
    $age=Test-IPSEventAge -AgeSeconds 9.9 -WarningSeconds 10 -MaximumSeconds 30
    Check ($age.Result -eq 'ON_TIME' -and $age.Accept -and -not $age.Delayed) 'Age 9.9 seconds accepted on time'
    $age=Test-IPSEventAge -AgeSeconds 10.2 -WarningSeconds 10 -MaximumSeconds 30
    Check ($age.Result -eq 'DELAYED' -and $age.Accept -and $age.Delayed) 'Age 10.2 seconds accepted and marked delayed'
    $age=Test-IPSEventAge -AgeSeconds 29.9 -WarningSeconds 10 -MaximumSeconds 30
    Check ($age.Result -eq 'DELAYED' -and $age.Accept -and $age.Delayed) 'Age 29.9 seconds accepted and marked delayed'
    $age=Test-IPSEventAge -AgeSeconds 30.1 -WarningSeconds 10 -MaximumSeconds 30
    Check ($age.Result -eq 'STALE' -and -not $age.Accept) 'Age over 30 seconds rejected as stale'
    $age=Test-IPSEventAge -AgeSeconds -2.1 -WarningSeconds 10 -MaximumSeconds 30
    Check ($age.Result -eq 'FUTURE' -and -not $age.Accept) 'Future timestamp beyond tolerance rejected'
    Write-Host 'RESULT: 22 Stage5 operational, latency and timing tests passed; no firewall actions.'
}finally{
    if($null -ne $jobs){$jobs|Remove-Job -Force -ErrorAction SilentlyContinue}
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
