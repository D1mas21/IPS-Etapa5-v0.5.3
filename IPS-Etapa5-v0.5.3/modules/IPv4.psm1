#Requires -Version 4.0
Set-StrictMode -Version 2.0

# Canonical dotted decimal only: no DNS, abbreviated, hexadecimal or octal IPs.
function ConvertTo-IPSIPv4Number {
    param([Parameter(Mandatory=$true)][string]$Address)
    if ($Address -cnotmatch '^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$') {
        throw "IPv4 invalida o no canonica: '$Address'."
    }
    [uint64]$value = 0
    foreach ($part in $Address.Split('.')) {
        $octet = [int]$part
        if ($octet -gt 255) { throw "Octeto IPv4 fuera de rango: '$Address'." }
        $value = ($value * 256) + $octet
    }
    return $value
}

function Get-IPSNetworkRange {
    param([Parameter(Mandatory=$true)][string]$Network)
    $parts = $Network.Split('/')
    if ($parts.Count -gt 2) { throw "CIDR invalido: '$Network'." }
    $number = ConvertTo-IPSIPv4Number $parts[0]
    $prefix = 32
    if ($parts.Count -eq 2) {
        if ($parts[1] -cnotmatch '^(0|[1-9]|[12][0-9]|3[0-2])$') {
            throw "Prefijo CIDR fuera de rango: '$Network'."
        }
        $prefix = [int]$parts[1]
    }
    [uint64]$size = [math]::Pow(2, (32 - $prefix))
    [uint64]$start = [math]::Floor($number / [double]$size) * $size
    if ($number -ne $start) {
        throw "CIDR con bits de host: '$Network'. Escriba la direccion de red, no una IP de host."
    }
    [pscustomobject]@{
        Network = '{0}/{1}' -f $parts[0], $prefix
        Prefix = $prefix
        Start = $start
        End = $start + $size - 1
    }
}

function Test-IPSRangeOverlap {
    param($First, $Second)
    return ($First.Start -le $Second.End -and $Second.Start -le $First.End)
}

function ConvertFrom-IPSIPv4Number {
    param([Parameter(Mandatory=$true)][uint64]$Value)
    if ($Value -gt 4294967295) { throw 'Numero IPv4 fuera de rango.' }
    return '{0}.{1}.{2}.{3}' -f ([math]::Floor($Value / 16777216)),
        ([math]::Floor($Value / 65536) % 256),
        ([math]::Floor($Value / 256) % 256), ($Value % 256)
}

Export-ModuleMember -Function ConvertTo-IPSIPv4Number, Get-IPSNetworkRange, Test-IPSRangeOverlap, ConvertFrom-IPSIPv4Number
