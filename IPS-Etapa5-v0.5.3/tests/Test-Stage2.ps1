#Requires -Version 4.0
# Offline file stream / parser tests, no Snort/Windows Firewall dependency.
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'modules\SnortReader.psm1') -Force
$script:passed=0
function Expect { param([bool]$Pass,[string]$Message);if(-not $Pass){throw $Message};$script:passed++;Write-Host ('PASS '+$Message) }
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ips-stage2-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$bridge=Join-Path $temp 'alert-live.log'
$script:key='A'
$keyProvider={ param($stream) $script:key }
$stamp=(Get-Date).ToString('MM/dd-HH:mm:ss.ffffff',[Globalization.CultureInfo]::InvariantCulture)
$tcp='{0}  [**] [1:1000003:1] SOC DEKMA - Nmap probable TCP SYN scan sobre puerto abierto [**] [Classification: Detection of a Network Scan] [Priority: 3] {{TCP}} 192.168.0.7:41849 -> 192.168.0.16:80' -f $stamp
$icmp='{0}  [**] [1:1001501:2] SOC DEKMA - ICMP Timestamp probe - Nmap-like [**] [Classification: Detection of a Network Scan] [Priority: 3] {{ICMP}} 192.168.0.7 -> 192.168.0.16' -f $stamp
$nbstat='{0}  [**] [1:1000504:1] DEBUG NMAP -sU - NetBIOS NBSTAT wildcard probe [**] [Priority: 0] {{UDP}} 192.168.0.7:34433 -> 192.168.0.16:137' -f $stamp
try {
    $reader=New-IPSSnortReader -FileKeyProvider $keyProvider
    $r=Get-IPSSnortChunk -Path $bridge -State $reader
    Expect ($r.Signals.Count -eq 1 -and $r.Signals[0].event -eq 'SOURCE_MISSING') 'Missing bridge reported once'
    $r=Get-IPSSnortChunk -Path $bridge -State $reader
    Expect ($r.Signals.Count -eq 0) 'Missing bridge not spammed'
    [IO.File]::WriteAllText($bridge,($tcp+"`n"),(New-Object Text.UTF8Encoding($false)))
    $r=Get-IPSSnortChunk -Path $bridge -State $reader
    Expect ($r.Lines.Count -eq 0 -and $r.Signals[0].event -eq 'READER_READY' -and $r.Signals[0].bytes -gt 0) 'First open skips existing lines'
    [IO.File]::AppendAllText($bridge,$icmp.Substring(0,30))
    $r=Get-IPSSnortChunk -Path $bridge -State $reader
    Expect ($r.Lines.Count -eq 0 -and $reader.Pending.Length -eq 30) 'Incomplete line held pending'
    [IO.File]::AppendAllText($bridge,$icmp.Substring(30)+"`r`n"+$nbstat+"`n")
    $r=Get-IPSSnortChunk -Path $bridge -State $reader
    Expect ($r.Lines.Count -eq 2 -and $r.Lines[0].Text -eq $icmp -and $r.Lines[1].Text -eq $nbstat) 'Split line, CRLF and two alerts reassembled'
    $r=Get-IPSSnortChunk -Path $bridge -State $reader
    Expect ($r.Lines.Count -eq 0) 'Polling same offset does not replay'
    $p=ConvertFrom-IPSSnortAlert $tcp (Get-Date)
    Expect ($p.Valid -and $p.Sid -eq 1000003 -and $p.SourcePort -eq 41849 -and $p.DestinationPort -eq 80) 'TCP probe fields'
    $p=ConvertFrom-IPSSnortAlert $icmp (Get-Date)
    Expect ($p.Valid -and $p.Sid -eq 1001501 -and $null -eq $p.SourcePort -and $null -eq $p.DestinationPort) 'ICMP without ports'
    $p=ConvertFrom-IPSSnortAlert $nbstat (Get-Date)
    Expect ($p.Valid -and $p.Priority -eq 0 -and $p.Classification -eq '') 'NBSTAT without classification'
    Expect (-not (Test-IPSSnortDuplicate -State $reader -Line $tcp)) 'First payload accepted'
    Expect (Test-IPSSnortDuplicate -State $reader -Line $tcp) 'Identical payload deduplicated'
    Expect (-not (Test-IPSSnortDuplicate -State $reader -Line $icmp)) 'Different SID never deduplicated'
    $bad=$tcp.Replace('192.168.0.7:41849','192.168.0.999:41849')
    Expect ((ConvertFrom-IPSSnortAlert $bad (Get-Date)).Reason -eq 'INVALID_IP') 'Malformed IPv4 rejected'
    $bad=$tcp.Replace(':80',':65536')
    Expect ((ConvertFrom-IPSSnortAlert $bad (Get-Date)).Reason -eq 'INVALID_PORT') 'Port range enforced'
    Expect ((ConvertFrom-IPSSnortAlert 'garbage' (Get-Date)).Reason -eq 'INVALID_FORMAT') 'Malformed alert rejected'
    $ipv6='{0}  [**] [129:15:1] Reset outside window [**] [Classification: Potentially Bad Traffic] [Priority: 2] {{TCP}} 2603:1056:2000:0038:0000:0000:0000:0002:443 -> 2800:0320:c2a6:cb00:eddd:cfd2:2a21:06f7:51385' -f $stamp
    Expect ((ConvertFrom-IPSSnortAlert $ipv6 (Get-Date)).Reason -eq 'UNSUPPORTED_IPV6') 'IPv6 Snort alert classified as unsupported'
    Expect ((ConvertFrom-IPSSnortAlert ($ipv6.Replace('2603:1056:2000:0038:0000:0000:0000:0002:443','not-an-ip')) (Get-Date)).Reason -eq 'INVALID_FORMAT') 'Malformed endpoint not classified as IPv6'
    $bad=$tcp.Replace($stamp,'02/30-19:01:01.000000')
    Expect ((ConvertFrom-IPSSnortAlert $bad (Get-Date)).Reason -eq 'INVALID_TIMESTAMP') 'Invalid calendar date rejected'
    # Truncation while a line is pending: emit gap then parse new file from offset 0.
    [IO.File]::AppendAllText($bridge,'PARTIAL')
    $null=Get-IPSSnortChunk -Path $bridge -State $reader
    $script:key='B'
    [IO.File]::WriteAllText($bridge,($tcp+"`n"),(New-Object Text.UTF8Encoding($false)))
    $r=Get-IPSSnortChunk -Path $bridge -State $reader
    Expect ($r.Signals.Count -eq 2 -and $r.Signals[0].event -eq 'SOURCE_GAP' -and $r.Signals[1].event -eq 'SOURCE_ROTATED' -and $r.Lines.Count -eq 1) 'Replacement signals lost partial line and reads new file'
    $script:key='B'
    [IO.File]::WriteAllText($bridge,'x')
    $r=Get-IPSSnortChunk -Path $bridge -State $reader
    Expect ($r.Signals.Count -eq 1 -and $r.Signals[0].reason -eq 'truncated') 'Same-key truncation detected when length decreases'
    $small=New-IPSSnortReader -StartAt Beginning -MaxLineBytes 1024 -FileKeyProvider $keyProvider
    [IO.File]::WriteAllText($bridge,('z'*1200)+"`n"+$tcp+"`n")
    $r=Get-IPSSnortChunk -Path $bridge -State $small
    Expect ($r.Signals[1].event -eq 'LINE_TOO_LONG' -and $r.Lines.Count -eq 1) 'Oversized line discarded without losing following alert'
    $badbytes=[byte[]](0xC3,0x28,0x0A)
    [IO.File]::WriteAllBytes($bridge,$badbytes)
    $utf8=New-IPSSnortReader -StartAt Beginning -FileKeyProvider $keyProvider
    $r=Get-IPSSnortChunk -Path $bridge -State $utf8
    Expect ($r.Signals[1].event -eq 'INVALID_UTF8' -and $r.Lines.Count -eq 0) 'Invalid UTF8 diagnosed, never interpreted'
    # New file identity even with same final byte count must trigger rotation.
    $script:key='C'
    [IO.File]::WriteAllText($bridge,'ABCD'+"`n")
    $r=Get-IPSSnortChunk -Path $bridge -State $small
    Expect ($r.Signals[0].event -eq 'SOURCE_ROTATED' -and $r.Lines[0].Text -eq 'ABCD') 'New identity triggers rotation'
    Write-Host ('RESULT: {0} Stage2 tests passed.' -f $script:passed)
} finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
