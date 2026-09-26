#Requires -Version 4.0
Set-StrictMode -Version 2.0

function New-IPSSnortReader {
    [CmdletBinding()]
    param([ValidateSet('End','Beginning')][string]$StartAt='End',
          [ValidateRange(1024,1048576)][int]$MaxLineBytes=16384,
          [scriptblock]$FileKeyProvider)
    [pscustomobject]@{
        Started=$false; Missing=$false; Key=''; Offset=[long]0
        Pending=(New-Object IO.MemoryStream)
        Dropping=$false
        StartAt=$StartAt
        MaxLineBytes=$MaxLineBytes
        FileKeyProvider=$FileKeyProvider
        Seen=@{}
    }
}

function Initialize-IPSFileIdentity {
    if ('DEKMA.Stage2FileIdentityV1' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace DEKMA {
 public static class Stage2FileIdentityV1 {
  [StructLayout(LayoutKind.Sequential)]
  private struct Info {
   public uint Attributes;
   public System.Runtime.InteropServices.ComTypes.FILETIME Creation;
   public System.Runtime.InteropServices.ComTypes.FILETIME Access;
   public System.Runtime.InteropServices.ComTypes.FILETIME Write;
   public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
  }
  [DllImport("kernel32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
  public static string GetKey(SafeFileHandle handle) {
   Info info;
   if (!GetFileInformationByHandle(handle, out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
   return info.Volume.ToString("X8") + ":" + info.IndexHigh.ToString("X8") + info.IndexLow.ToString("X8");
  }
 }
}
'@
}

function Get-IPSFileKey {
    param([IO.FileStream]$Stream, [scriptblock]$Provider)
    if ($null -ne $Provider) { return [string](& $Provider $Stream) }
    if ($env:OS -ne 'Windows_NT') {
        # Local test adapter only; production identity always uses the open Win32 handle.
        return [string]([IO.File]::GetCreationTimeUtc($Stream.Name).Ticks)
    }
    Initialize-IPSFileIdentity
    return [DEKMA.Stage2FileIdentityV1]::GetKey($Stream.SafeFileHandle)
}

function New-IPSSourceEvent {
    param([string]$Event,[string]$Reason,[long]$Bytes)
    [pscustomobject]@{event=$Event;reason=$Reason;bytes=$Bytes}
}

function Add-IPSReadBytes {
    param($State,[byte[]]$Buffer,[int]$Count,[string]$FileKey,
          [long]$BaseOffset,[System.Collections.ArrayList]$Lines,
          [System.Collections.ArrayList]$Signals)
    $encoding = New-Object Text.UTF8Encoding($false,$true)
    for ($i=0; $i -lt $Count; $i++) {
        [byte]$one = $Buffer[$i]
        if ($one -eq 10) {
            if ($State.Dropping) {
                $State.Dropping = $false
                $State.Pending.SetLength(0)
                $null = $Signals.Add((New-IPSSourceEvent 'LINE_TOO_LONG' 'Linea descartada por longitud' 0))
                continue
            }
            $bytes = $State.Pending.ToArray()
            $State.Pending.SetLength(0)
            if ($bytes.Length -gt 0 -and $bytes[$bytes.Length-1] -eq 13) {
                [Array]::Resize([ref]$bytes,$bytes.Length-1)
            }
            if ($bytes.Length -eq 0) { continue }
            try { $line = $encoding.GetString($bytes) }
            catch {
                $null = $Signals.Add((New-IPSSourceEvent 'INVALID_UTF8' 'Linea descartada por codificacion invalida' $bytes.Length))
                continue
            }
            $null = $Lines.Add([pscustomobject]@{
                Text=$line;Key=$FileKey;Offset=[long]($BaseOffset+$i+1)
            })
        } elseif (-not $State.Dropping) {
            if ($State.Pending.Length -ge $State.MaxLineBytes) {
                $State.Dropping=$true
                $State.Pending.SetLength(0)
            } else { $State.Pending.WriteByte($one) }
        }
    }
}

function Get-IPSSnortChunk {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path,
          [Parameter(Mandatory=$true)]$State,
          [ValidateRange(1024,1048576)][int]$MaxBytesPerPoll=262144)
    $lines = New-Object System.Collections.ArrayList
    $signals = New-Object System.Collections.ArrayList
    $stream = $null
    try {
        # Open directly: File.Exists before Open introduces a rotation race.
        $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,
            ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $key = Get-IPSFileKey $stream $State.FileKeyProvider
        if ([string]::IsNullOrEmpty($key)) { throw 'No se pudo identificar el archivo abierto.' }
        if (-not $State.Started) {
            $State.Started=$true; $State.Missing=$false; $State.Key=$key
            $State.Offset=[long]0
            if ($State.StartAt -eq 'End') { $State.Offset=$stream.Length }
            $null=$signals.Add((New-IPSSourceEvent 'READER_READY' ('key={0}; skipped_bytes={1}; path={2}' -f $key,$State.Offset,$Path) $State.Offset))
        } elseif ($State.Key -ne $key -or $stream.Length -lt $State.Offset) {
            $pending=[long]$State.Pending.Length
            if ($State.Dropping) { $pending=$State.MaxLineBytes }
            if ($pending -gt 0) {
                $null=$signals.Add((New-IPSSourceEvent 'SOURCE_GAP' 'Linea pendiente perdida por rotacion/truncamiento; puede haber datos sin leer' $pending))
            }
            $reason='replaced'
            if ($State.Key -eq $key) { $reason='truncated' }
            $State.Key=$key; $State.Offset=[long]0; $State.Pending.SetLength(0);$State.Dropping=$false
            $null=$signals.Add((New-IPSSourceEvent 'SOURCE_ROTATED' $reason 0))
        } elseif ($State.Missing) {
            $null=$signals.Add((New-IPSSourceEvent 'SOURCE_RESTORED' ('key=' + $key) 0))
        }
        $State.Missing=$false
        $null=$stream.Seek($State.Offset,[IO.SeekOrigin]::Begin)
        $buffer=New-Object byte[] 65536
        [int]$budget=$MaxBytesPerPoll
        while ($budget -gt 0) {
            [int]$wanted=[Math]::Min($buffer.Length,$budget)
            $read=$stream.Read($buffer,0,$wanted)
            if ($read -eq 0) { break }
            $base=$State.Offset
            Add-IPSReadBytes $State $buffer $read $key $base $lines $signals
            $State.Offset += $read
            $budget -= $read
        }
    } catch [IO.FileNotFoundException] {
        if (-not $State.Missing) {
            $State.Missing=$true
            $null=$signals.Add((New-IPSSourceEvent 'SOURCE_MISSING' 'Puente ausente; no se pueden confirmar alertas durante la ausencia' 0))
        }
    } catch [IO.DirectoryNotFoundException] {
        if (-not $State.Missing) {
            $State.Missing=$true
            $null=$signals.Add((New-IPSSourceEvent 'SOURCE_MISSING' 'Directorio del puente ausente' 0))
        }
    } finally { if ($null -ne $stream) { $stream.Dispose() } }
    [pscustomobject]@{Signals=@($signals.ToArray());Lines=@($lines.ToArray())}
}

function Test-IPSIPv6Endpoint {
    param([string]$Value)
    $address=$null
    if ([Net.IPAddress]::TryParse($Value,[ref]$address) -and
        $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { return $true }
    # Snort alert_fast writes unbracketed IPv6 addresses followed by :port.
    $lastColon=$Value.LastIndexOf(':')
    if ($lastColon -lt 0) { return $false }
    $port=0
    if (-not [int]::TryParse($Value.Substring($lastColon+1),[ref]$port) -or
        $port -lt 0 -or $port -gt 65535) { return $false }
    return ([Net.IPAddress]::TryParse($Value.Substring(0,$lastColon),[ref]$address) -and
        $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6)
}

function ConvertFrom-IPSSnortAlert {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Line,[DateTime]$Now=(Get-Date))
    $pattern='^(?<stamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d{6})\s+\[\*\*\]\s+\[(?<gid>\d+):(?<sid>\d+):(?<rev>\d+)\]\s+(?<message>.*?)\s+\[\*\*\](?:\s+\[Classification:\s*(?<classification>[^\]]+)\])?\s+\[Priority:\s*(?<priority>\d+)\]\s+\{(?<protocol>[A-Za-z0-9:]+)\}\s+(?<src>\d{1,3}(?:\.\d{1,3}){3})(?::(?<srcport>\d{1,5}))?\s+->\s+(?<dst>\d{1,3}(?:\.\d{1,3}){3})(?::(?<dstport>\d{1,5}))?\s*$'
    $m=[regex]::Match($Line,$pattern)
    if (-not $m.Success) {
        # Classify only a well-formed Snort header with two valid IPv6 endpoints.
        # IPv6 is outside this stage's IPv4 protection policy; it never authorizes a block.
        $ipv6Pattern='^\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d{6}\s+\[\*\*\]\s+\[(?<gid>\d+):(?<sid>\d+):(?<rev>\d+)\]\s+.*?\s+\[\*\*\](?:\s+\[Classification:\s*[^\]]+\])?\s+\[Priority:\s*\d+\]\s+\{[A-Za-z0-9:]+\}\s+(?<src>\S+)\s+->\s+(?<dst>\S+)\s*$'
        $v6=[regex]::Match($Line,$ipv6Pattern)
        if ($v6.Success -and (Test-IPSIPv6Endpoint $v6.Groups['src'].Value) -and
            (Test-IPSIPv6Endpoint $v6.Groups['dst'].Value)) {
            return [pscustomobject]@{Valid=$false;Reason='UNSUPPORTED_IPV6'}
        }
        return [pscustomobject]@{Valid=$false;Reason='INVALID_FORMAT'}
    }
    $validIp='^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$'
    foreach ($group in @('src','dst')) {
        $address=$m.Groups[$group].Value
        if ($address -cnotmatch $validIp) { return [pscustomobject]@{Valid=$false;Reason='INVALID_IP'} }
        foreach ($part in $address.Split('.')) {
            if ([int]$part -gt 255) { return [pscustomobject]@{Valid=$false;Reason='INVALID_IP'} }
        }
    }
    foreach ($group in @('srcport','dstport')) {
        if ($m.Groups[$group].Success -and [int]$m.Groups[$group].Value -gt 65535) {
            return [pscustomobject]@{Valid=$false;Reason='INVALID_PORT'}
        }
    }
    foreach ($group in @('gid','sid','rev','priority')) {
        $number=0
        if (-not [int]::TryParse($m.Groups[$group].Value,[ref]$number)) {
            return [pscustomobject]@{Valid=$false;Reason='INVALID_NUMBER'}
        }
    }
    $best=$null
    foreach ($year in @(($Now.Year-1),$Now.Year,($Now.Year+1))) {
        $date=[DateTime]::MinValue
        $dateString='{0}/{1}' -f $year,$m.Groups['stamp'].Value
        $ok=[DateTime]::TryParseExact($dateString,'yyyy/MM/dd-HH:mm:ss.ffffff',
            [Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$date)
        if ($ok -and ($null -eq $best -or [Math]::Abs(($Now-$date).TotalSeconds) -lt [Math]::Abs(($Now-$best).TotalSeconds))) {
            $best=$date
        }
    }
    if ($null -eq $best) { return [pscustomobject]@{Valid=$false;Reason='INVALID_TIMESTAMP'} }
    $srcport=$null; $dstport=$null
    if ($m.Groups['srcport'].Success) { $srcport=[int]$m.Groups['srcport'].Value }
    if ($m.Groups['dstport'].Success) { $dstport=[int]$m.Groups['dstport'].Value }
    [pscustomobject]@{
        Valid=$true;Reason='PARSED'
        TimestampLocal=$best; AgeSeconds=($Now-$best).TotalSeconds
        Gid=[int]$m.Groups['gid'].Value; Sid=[int]$m.Groups['sid'].Value
        Rev=[int]$m.Groups['rev'].Value; Message=$m.Groups['message'].Value
        Classification=$m.Groups['classification'].Value
        Priority=[int]$m.Groups['priority'].Value; Protocol=$m.Groups['protocol'].Value
        Source=$m.Groups['src'].Value; SourcePort=$srcport
        Destination=$m.Groups['dst'].Value; DestinationPort=$dstport
    }
}

function Test-IPSSnortDuplicate {
    param($State,[string]$Line,[DateTime]$NowUtc=([DateTime]::UtcNow),[int]$WindowSeconds=30)
    $cutoff=$NowUtc.AddSeconds(-$WindowSeconds)
    foreach ($hash in @($State.Seen.Keys)) {
        if ($State.Seen[$hash] -lt $cutoff) { $State.Seen.Remove($hash) }
    }
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $bytes=[Text.Encoding]::UTF8.GetBytes($Line); $digest=[Convert]::ToBase64String($sha.ComputeHash($bytes)) }
    finally { $sha.Dispose() }
    if ($State.Seen.ContainsKey($digest)) { return $true }
    $State.Seen[$digest]=$NowUtc
    return $false
}

Export-ModuleMember -Function New-IPSSnortReader, Get-IPSSnortChunk, ConvertFrom-IPSSnortAlert, Test-IPSSnortDuplicate
