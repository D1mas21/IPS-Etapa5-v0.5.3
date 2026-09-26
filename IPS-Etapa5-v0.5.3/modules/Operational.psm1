#Requires -Version 4.0
Set-StrictMode -Version 2.0

$script:DefaultStateMutex='Global\SOC-DEKMA-IPS-STATE-5'
$script:DefaultLogMutex='Global\SOC-DEKMA-IPS-LOG-5'

function Enter-IPSNamedMutex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [ValidateRange(0,300000)][int]$TimeoutMilliseconds=30000
    )
    if([string]::IsNullOrWhiteSpace($Name)){throw 'El nombre del mutex no puede estar vacio.'}
    $mutex=New-Object Threading.Mutex -ArgumentList $false,$Name
    $acquired=$false
    try{
        try{$acquired=$mutex.WaitOne($TimeoutMilliseconds)}
        catch [Threading.AbandonedMutexException]{$acquired=$true}
        if(-not $acquired){throw "Tiempo agotado esperando mutex: $Name"}
        return [pscustomobject]@{Name=$Name;Mutex=$mutex;Acquired=$true}
    }catch{
        $mutex.Dispose()
        throw
    }
}

function Exit-IPSNamedMutex {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Handle)
    if($null -eq $Handle){return}
    try{
        if($Handle.Acquired){$Handle.Mutex.ReleaseMutex();$Handle.Acquired=$false}
    }finally{
        if($null -ne $Handle.Mutex){$Handle.Mutex.Dispose()}
    }
}

function Invoke-IPSWithMutex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [ValidateRange(0,300000)][int]$TimeoutMilliseconds=30000
    )
    $handle=$null
    try{
        $handle=Enter-IPSNamedMutex -Name $Name -TimeoutMilliseconds $TimeoutMilliseconds
        & $ScriptBlock
    }finally{
        if($null -ne $handle){Exit-IPSNamedMutex -Handle $handle}
    }
}

function Write-IPSOperationalEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Directory,
        [Parameter(Mandatory=$true)][string]$Component,
        [Parameter(Mandatory=$true)][string]$Mode,
        [Parameter(Mandatory=$true)][string]$Name,
        [hashtable]$Fields=@{},
        [DateTime]$NowUtc=([DateTime]::UtcNow),
        [DateTime]$LocalDate=(Get-Date),
        [string]$MutexName=$script:DefaultLogMutex,
        [switch]$PassThru
    )
    $full=[IO.Path]::GetFullPath($Directory)
    if(-not (Test-Path -LiteralPath $full -PathType Container)){
        $null=New-Item -ItemType Directory -Path $full -Force -ErrorAction Stop
    }
    $day=$LocalDate.ToString('yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture)
    $path=Join-Path $full ('ips.{0}.log' -f $day)
    $record=[ordered]@{
        schema_version=1
        timestamp=$NowUtc.ToUniversalTime().ToString('o')
        component=$Component
        mode=$Mode
        event=$Name
        firewall_modified=$false
    }
    foreach($key in $Fields.Keys){$record[$key]=$Fields[$key]}
    $line=ConvertTo-Json -InputObject $record -Depth 6 -Compress
    $totalWatch=[Diagnostics.Stopwatch]::StartNew()
    $waitWatch=[Diagnostics.Stopwatch]::StartNew()
    $handle=$null
    try{
        $handle=Enter-IPSNamedMutex -Name $MutexName -TimeoutMilliseconds 30000
        $waitWatch.Stop()
        $writeWatch=[Diagnostics.Stopwatch]::StartNew()
        $encoding=New-Object Text.UTF8Encoding($false)
        $stream=[IO.File]::Open($path,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
        try{
            $writer=New-Object IO.StreamWriter($stream,$encoding)
            try{$writer.WriteLine($line);$writer.Flush()}finally{$writer.Dispose()}
        }finally{
            if($null -ne $stream){$stream.Dispose()}
        }
        $writeWatch.Stop()
    }finally{
        if($waitWatch.IsRunning){$waitWatch.Stop()}
        if($null -ne $handle){Exit-IPSNamedMutex -Handle $handle}
    }
    $consoleWatch=[Diagnostics.Stopwatch]::StartNew()
    Write-Host $line
    $consoleWatch.Stop();$totalWatch.Stop()
    if($PassThru){
        [pscustomobject]@{
            Path=$path;Line=$line;Record=[pscustomobject]$record
            MutexWaitMilliseconds=[Math]::Round($waitWatch.Elapsed.TotalMilliseconds,3)
            FileWriteMilliseconds=[Math]::Round($writeWatch.Elapsed.TotalMilliseconds,3)
            ConsoleWriteMilliseconds=[Math]::Round($consoleWatch.Elapsed.TotalMilliseconds,3)
            TotalWriteMilliseconds=[Math]::Round($totalWatch.Elapsed.TotalMilliseconds,3)
        }
    }
}

function Get-IPSStateMutexName {return $script:DefaultStateMutex}
function Get-IPSLogMutexName {return $script:DefaultLogMutex}

Export-ModuleMember -Function Enter-IPSNamedMutex,Exit-IPSNamedMutex,Invoke-IPSWithMutex,Write-IPSOperationalEvent,Get-IPSStateMutexName,Get-IPSLogMutexName
