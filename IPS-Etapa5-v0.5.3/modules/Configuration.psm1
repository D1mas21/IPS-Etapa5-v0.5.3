#Requires -Version 4.0
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'IPv4.psm1') -Force -ErrorAction Stop

function Assert-IPSObject {
    param($Object, [string[]]$Keys, [string]$Context)
    if ($null -eq $Object -or $Object -isnot [pscustomobject]) {
        throw "$Context debe ser un objeto JSON."
    }
    $actual = @($Object.PSObject.Properties | ForEach-Object { $_.Name })
    foreach ($key in $Keys) {
        if ($actual -cnotcontains $key) { throw "Falta '$Context.$key'." }
    }
    foreach ($key in $actual) {
        if ($Keys -cnotcontains $key) { throw "Campo no admitido: '$Context.$key'." }
    }
}

function Assert-IPSInteger {
    param($Value, [int]$Minimum, [int]$Maximum, [string]$Context)
    if (($Value -isnot [int] -and $Value -isnot [long]) -or $Value -lt $Minimum -or $Value -gt $Maximum) {
        throw "$Context debe ser entero entre $Minimum y $Maximum."
    }
}

function Assert-IPSString {
    param($Value, [string]$Context)
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)) {
        throw "$Context debe ser texto no vacio."
    }
}

function Get-IPSExcludedRanges {
    # Eligibility exclusions, not a claim that every unlisted IP is public.
    foreach ($network in @('0.0.0.0/8','127.0.0.0/8','169.254.0.0/16','224.0.0.0/4','240.0.0.0/4')) {
        Get-IPSNetworkRange $network
    }
}

function Assert-IPSHost {
    param($Address, [string]$Context)
    Assert-IPSString $Address $Context
    $null = ConvertTo-IPSIPv4Number $Address
    $range = Get-IPSNetworkRange $Address
    foreach ($special in @(Get-IPSExcludedRanges)) {
        if (Test-IPSRangeOverlap $range $special) { throw "$Context no es un host IPv4 elegible: '$Address'." }
    }
}

function Assert-IPSConfiguration {
    param($Configuration)
    Assert-IPSObject $Configuration @('schema_version','protected_server','trusted_hosts','allowlist','denylist','operation','snort') 'config'
    Assert-IPSInteger $Configuration.schema_version 1 1 'schema_version'
    Assert-IPSHost $Configuration.protected_server 'protected_server'
    Assert-IPSObject $Configuration.trusted_hosts @('gateway','administrator','soc_wazuh','public_ip') 'trusted_hosts'
    foreach ($p in $Configuration.trusted_hosts.PSObject.Properties) { Assert-IPSHost $p.Value ('trusted_hosts.' + $p.Name) }
    foreach ($listName in @('allowlist','denylist')) {
        if ($Configuration.$listName -isnot [array]) { throw "$listName debe ser un arreglo JSON, incluso si esta vacio: []." }
        if ($Configuration.$listName.Count -gt 1024) { throw "$listName supera el limite de 1024 entradas." }
        $seen = @{}
        foreach ($entry in $Configuration.$listName) {
            $keys = @('network','reason')
            if ($listName -eq 'denylist') { $keys += 'expires_at' }
            Assert-IPSObject $entry $keys $listName
            Assert-IPSString $entry.network ($listName + '.network')
            Assert-IPSString $entry.reason ($listName + '.reason')
            if ($entry.reason.Length -gt 256 -or $entry.reason -match '[\r\n\x00]') { throw "Motivo invalido en $listName." }
            $range = Get-IPSNetworkRange $entry.network
            if ($seen.ContainsKey($range.Network)) { throw "Entrada duplicada en ${listName}: $($range.Network)." }
            $seen[$range.Network] = $true
            if ($listName -eq 'denylist' -and $null -ne $entry.expires_at) {
                if ($entry.expires_at -isnot [string] -or $entry.expires_at -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') {
                    throw 'denylist.expires_at debe ser UTC yyyy-MM-ddTHH:mm:ssZ o null para permanente explicito.'
                }
                $expiry = [DateTime]::MinValue
                $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
                if (-not [DateTime]::TryParseExact($entry.expires_at, "yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$expiry)) {
                    throw 'Fecha invalida en denylist.expires_at.'
                }
                if ($expiry -le [DateTime]::UtcNow) { throw "Entrada de lista negra vencida: $($entry.network). Retirela de la configuracion." }
            }
        }
    }
    Assert-IPSObject $Configuration.operation @('mode','block_seconds','max_active_blocks','poll_milliseconds','delay_warning_seconds','max_event_age_seconds') 'operation'
    if ($Configuration.operation.mode -cne 'Audit' -and $Configuration.operation.mode -cne 'Enforce') { throw 'operation.mode debe ser Audit o Enforce.' }
    Assert-IPSInteger $Configuration.operation.block_seconds 15 86400 'block_seconds'
    Assert-IPSInteger $Configuration.operation.max_active_blocks 1 4096 'max_active_blocks'
    Assert-IPSInteger $Configuration.operation.poll_milliseconds 100 2000 'poll_milliseconds'
    Assert-IPSInteger $Configuration.operation.delay_warning_seconds 1 59 'delay_warning_seconds'
    Assert-IPSInteger $Configuration.operation.max_event_age_seconds 1 60 'max_event_age_seconds'
    if([int]$Configuration.operation.delay_warning_seconds -ge [int]$Configuration.operation.max_event_age_seconds){
        throw 'delay_warning_seconds debe ser menor que max_event_age_seconds.'
    }
    Assert-IPSObject $Configuration.snort @('alert_path','daily_log_directory') 'snort'
    foreach ($p in $Configuration.snort.PSObject.Properties) {
        Assert-IPSString $p.Value ('snort.' + $p.Name)
        if ($p.Value -notmatch '^[A-Za-z]:\\' -or $p.Value -match '[\x00-\x1f*?<>"|]' -or $p.Value.Substring(2).Contains(':')) {
            throw "snort.$($p.Name) debe ser una ruta local absoluta de Windows sin comodines."
        }
    }
}

function Import-IPSConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -gt 1048576) { throw 'Se requiere un archivo JSON de hasta 1 MiB.' }
    # Data only; never dot-source config or execute strings from the configuration.
    $text = [IO.File]::ReadAllText($file.FullName, [Text.Encoding]::UTF8)
    try { $config = ConvertFrom-Json -InputObject $text -ErrorAction Stop }
    catch { throw "JSON invalido: $($_.Exception.Message)" }
    # Decode through an object wrapper. Windows PowerShell 4 can preserve a
    # one-element JSON array as one array object, which hid duplicate keys in v0.4.0.
    $tokens = [regex]::Matches($text, '"(?:\\.|[^"\\])*"|[{}\[\]:,]')
    $objects = New-Object System.Collections.Stack
    for ($i=0; $i -lt $tokens.Count; $i++) {
        $token = $tokens[$i].Value
        if ($token -eq '{') { $objects.Push(@{}); continue }
        if ($token -eq '}') { $null = $objects.Pop(); continue }
        if ($token.StartsWith('"') -and ($i+1) -lt $tokens.Count -and $tokens[$i+1].Value -eq ':') {
            $decoded=ConvertFrom-Json -InputObject ('{"property":'+$token+'}') -ErrorAction Stop
            $key=[string]$decoded.property
            $keys = $objects.Peek()
            if ($keys.ContainsKey($key)) { throw "Clave JSON duplicada: '$key'." }
            $keys[$key] = $true
        }
    }
    Assert-IPSConfiguration $config
    return $config
}

function Get-IPSInventory {
    [CmdletBinding()]
    param()
    if ($env:OS -ne 'Windows_NT') { throw 'El inventario real requiere Windows. Las pruebas unitarias usan inventarios simulados.' }
    $local = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Select-Object InterfaceAlias, InterfaceIndex, IPAddress, PrefixLength, AddressState)
    $gateways = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
        Where-Object { $_.NextHop -ne '0.0.0.0' } | Select-Object -ExpandProperty NextHop -Unique)
    $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
        ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique)
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
    $modules = @(Get-Module -ListAvailable -Name NetSecurity,ScheduledTasks |
        Select-Object Name, @{Name='Version';Expression={$_.Version.ToString()}})
    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        LocalAddresses = $local
        Gateways = $gateways
        DnsServers = $dns
        FirewallProfiles = $profiles
        Modules = $modules
    }
}

function New-IPSProtection {
    param([string]$Network, [string]$Reason, [string]$Origin)
    [pscustomobject]@{ Network=$Network; Reason=$Reason; Origin=$Origin; Range=(Get-IPSNetworkRange $Network) }
}

function Resolve-IPSConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Configuration, [Parameter(Mandatory=$true)]$Inventory)
    Assert-IPSConfiguration $Configuration
    $errors = @(); $warnings = @(); $protections = @(); $excluded = @(); $deny = @()
    $protections += New-IPSProtection $Configuration.protected_server 'Servidor protegido' 'config'
    foreach ($p in $Configuration.trusted_hosts.PSObject.Properties) {
        $protections += New-IPSProtection $p.Value $p.Name 'config'
    }
    foreach ($entry in $Configuration.allowlist) { $protections += New-IPSProtection $entry.network $entry.reason 'allowlist' }
    foreach ($entry in $Inventory.LocalAddresses) {
        $protections += New-IPSProtection $entry.IPAddress ('IP local: ' + $entry.InterfaceAlias) 'discovery'
        # Protect subnet network/broadcast endpoints, never the whole local LAN.
        Assert-IPSInteger ([int]$entry.PrefixLength) 0 32 'inventory.PrefixLength'
        if ([int]$entry.PrefixLength -le 30) {
            [uint64]$value = ConvertTo-IPSIPv4Number $entry.IPAddress
            [uint64]$size = [math]::Pow(2, (32 - [int]$entry.PrefixLength))
            [uint64]$start = [math]::Floor($value / [double]$size) * $size
            $excluded += New-IPSProtection (ConvertFrom-IPSIPv4Number $start) 'Direccion de red local' 'discovery'
            $excluded += New-IPSProtection (ConvertFrom-IPSIPv4Number ($start + $size - 1)) 'Broadcast local' 'discovery'
        }
    }
    foreach ($gateway in $Inventory.Gateways) { $protections += New-IPSProtection $gateway 'Gateway detectado' 'discovery' }
    foreach ($range in @(Get-IPSExcludedRanges)) { $excluded += New-IPSProtection $range.Network 'Rango excluido de bloqueo' 'built_in' }

    $serverLocal = @($Inventory.LocalAddresses | Where-Object {
        $_.IPAddress -eq $Configuration.protected_server -and [string]$_.AddressState -eq 'Preferred'
    })
    if ($serverLocal.Count -eq 0) { $errors += 'El servidor protegido no es una IP local Preferred de este equipo.' }
    if (@($Inventory.Gateways) -notcontains $Configuration.trusted_hosts.gateway) {
        $errors += 'El gateway configurado no coincide con ninguna ruta IPv4 por defecto detectada.'
    }
    # Reject allowlist ranges that include addresses not eligible for blocking.
    # Local IPs may themselves be loopback; only manual allowlist entries are checked here.
    foreach ($entry in $Configuration.allowlist) {
        $range = Get-IPSNetworkRange $entry.network
        foreach ($special in @(Get-IPSExcludedRanges)) {
            if (Test-IPSRangeOverlap $range $special) { $errors += "Lista blanca $($entry.network) intersecta rango excluido $($special.Network)." }
        }
    }
    foreach ($entry in $Configuration.denylist) {
        $range = Get-IPSNetworkRange $entry.network
        $deny += [pscustomobject]@{Network=$entry.network;Reason=$entry.reason;ExpiresAt=$entry.expires_at;Range=$range}
        foreach ($protected in @($protections) + @($excluded)) {
            if (Test-IPSRangeOverlap $range $protected.Range) {
                $errors += "CONFLICTO: lista negra $($entry.network) intersecta $($protected.Network) [$($protected.Reason)]."
            }
        }
    }
    for ($i=0; $i -lt $deny.Count; $i++) {
        for ($j=$i+1; $j -lt $deny.Count; $j++) {
            if (Test-IPSRangeOverlap $deny[$i].Range $deny[$j].Range) {
                $errors += "Listas negras superpuestas: $($deny[$i].Network) y $($deny[$j].Network). Use entradas sin solapamiento."
            }
        }
    }
    foreach ($dns in $Inventory.DnsServers) {
        $number = ConvertTo-IPSIPv4Number $dns
        $matched = @($protections | Where-Object { $number -ge $_.Range.Start -and $number -le $_.Range.End })
        if ($matched.Count -eq 0) { $warnings += "DNS no incluido en protecciones: $dns. Revise si debe agregarse a allowlist." }
    }
    foreach ($moduleName in @('NetSecurity','ScheduledTasks')) {
        if (@($Inventory.Modules | Where-Object { $_.Name -eq $moduleName }).Count -eq 0) {
            $warnings += "Modulo requerido por la solucion IPS no disponible: $moduleName."
        }
    }
    if (@($Inventory.FirewallProfiles).Count -eq 0) { $warnings += 'No se encontraron perfiles de firewall.' }
    foreach ($profile in $Inventory.FirewallProfiles) {
        if ([string]$profile.Enabled -ne 'True') { $warnings += "Perfil de firewall desactivado: $($profile.Name)." }
    }
    if($Configuration.operation.mode -eq 'Audit'){$warnings += 'Etapa 5 en Audit: el actuador simula solicitudes y no modifica Windows Firewall.'}
    else{$warnings += 'Etapa 5 en Enforce: Watch exigira -EnableEnforcement antes de modificar Windows Firewall.'}
    [pscustomobject]@{
        Valid = ($errors.Count -eq 0)
        Errors = @($errors)
        Warnings = @($warnings)
        Protections = @($protections)
        Exclusions = @($excluded)
        Denylist = @($deny)
        Configuration = $Configuration
    }
}

function Test-IPSAddress {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Address, [Parameter(Mandatory=$true)]$Resolved)
    try { $number = ConvertTo-IPSIPv4Number $Address }
    catch { return [pscustomobject]@{Address=$Address;Decision='INVALID_ADDRESS';Reason=$_.Exception.Message} }
    $protected = @($Resolved.Protections | Where-Object { $number -ge $_.Range.Start -and $number -le $_.Range.End })
    if ($protected.Count -gt 0) {
        return [pscustomobject]@{Address=$Address;Decision='PROTECTED';Reason=(@($protected | ForEach-Object {$_.Reason}) -join '; ')}
    }
    $excluded = @($Resolved.Exclusions | Where-Object { $number -ge $_.Range.Start -and $number -le $_.Range.End })
    if ($excluded.Count -gt 0) {
        return [pscustomobject]@{Address=$Address;Decision='EXCLUDED';Reason=(@($excluded | ForEach-Object {$_.Reason}) -join '; ')}
    }
    if (-not $Resolved.Valid) {
        return [pscustomobject]@{Address=$Address;Decision='CONFIG_INVALID';Reason='Resolver errores antes de evaluar decisiones.'}
    }
    $denied = @($Resolved.Denylist | Where-Object { $number -ge $_.Range.Start -and $number -le $_.Range.End })
    if ($denied.Count -gt 0) {
        return [pscustomobject]@{Address=$Address;Decision='DENYLIST_MATCH';Reason='Coincidencia con lista negra configurada.'}
    }
    [pscustomobject]@{Address=$Address;Decision='SUBJECT_TO_POLICY';Reason='Sin exclusion ni lista negra; necesita una alerta y politica validada.'}
}

Export-ModuleMember -Function Import-IPSConfiguration, Get-IPSInventory, Resolve-IPSConfiguration, Test-IPSAddress
