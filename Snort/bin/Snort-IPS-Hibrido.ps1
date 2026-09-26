# ==============================================================================
# SENSOR IPS HIBRIDO (SNORT + FIREWALL) - VERSION ULTRA COMPATIBLE V4
# ==============================================================================

$SnortLogPath         = "C:\Snort\log\alert.ids" 
$BlockRuleGroup       = "Snort-Blocked-IPs"
$BlockDurationMinutes = 1   # Tiempo de baneo temporal (5 minutos para pruebas)

# LISTA BLANCA: IPs protegidas
$Whitelist = @(
    "127.0.0.1",
    "0.0.0.0",
    "192.168.0.1",   # Router / Gateway
    "192.168.0.16"   # Tu IP local de Windows Server
)

# Inicializacion explicita en el ambito del SCRIPT
$script:ActiveBlocks = @{}

Write-Host "[*] Iniciando IPS Hibrido V4 (Snort + Windows Defender)..." -ForegroundColor Cyan
Write-Host "[*] IPs protegidas por Whitelist: $($Whitelist -join ', ')" -ForegroundColor Yellow
Write-Host "[*] Monitoreando activamente en: $SnortLogPath" -ForegroundColor Gray

# Funcion de Bloqueo
function Block-IPAddress ($IP) {
    if ($Whitelist -contains $IP) {
        Write-Host "[W] Intento de bloqueo ignorado: $IP esta en la LISTA BLANCA." -ForegroundColor Yellow
        return
    }

    $RuleName = "Snort-Block-$IP"
    $Exists = Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue
    
    if (-not $Exists) {
        $ExpireAt = (Get-Date).AddMinutes($BlockDurationMinutes)
        Write-Host "[!] BLOQUEANDO IP ATACANTE: $IP hasta las $($ExpireAt.ToString('HH:mm:ss'))" -ForegroundColor Red
        
        # Guardamos en $null para evitar el error de renderizado de consola Win32 0x1F
        $null = New-NetFirewallRule -DisplayName $RuleName `
                            -Name $RuleName `
                            -Group $BlockRuleGroup `
                            -Direction Inbound `
                            -Action Block `
                            -RemoteAddress $IP `
                            -Description "Bloqueo automatico por IPS Hibrido - Expira: $ExpireAt" `
                            -Enabled True

        # Guardar en el hash global de forma explicita
        $script:ActiveBlocks[$IP] = $ExpireAt
    }
}

# Funcion de Desbloqueo
function Cleanup-ExpiredBlocks {
    $Now = Get-Date
    $IPsToRemove = @()

    # Copiar las llaves a un array estatico para evitar errores de modificacion de coleccion en caliente
    $CurrentKeys = @($script:ActiveBlocks.Keys)

    foreach ($IP in $CurrentKeys) {
        $ExpireTime = [datetime]$script:ActiveBlocks[$IP]
        if ($Now -ge $ExpireTime) {
            $IPsToRemove += $IP
        }
    }

    foreach ($IP in $IPsToRemove) {
        Write-Host "[*] Desbloqueando IP $IP (Tiempo de baneo expirado)" -ForegroundColor Green
        $null = Remove-NetFirewallRule -Name "Snort-Block-$IP" -ErrorAction SilentlyContinue
        $script:ActiveBlocks.Remove($IP)
        Write-Host ">>> Esperando alertas de Snort (Modo Real-Time Activo)..." -ForegroundColor Gray
    }
}

# Limpiar bloqueos huerfanos al iniciar
$null = Remove-NetFirewallRule -Group $BlockRuleGroup -ErrorAction SilentlyContinue

# ==============================================================================
# BUCLE DE LECTURA DE LOGS EN TIEMPO REAL (SIN BUFFERING)
# ==============================================================================
Write-Host ">>> Esperando alertas de Snort (Modo Real-Time Activo)..." -ForegroundColor Gray

# Esperar a que Snort cree el archivo si no existe
while (-not (Test-Path $SnortLogPath)) {
    Start-Sleep -Seconds 1
}

# Abrir el archivo en modo de lectura compartida sin bloquear la escritura de Snort
$FileStream = New-Object System.IO.FileStream($SnortLogPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
$Reader     = New-Object System.IO.StreamReader($FileStream)

# Posicionarse directamente al final del archivo (analizar solo alertas nuevas)
$null = $Reader.BaseStream.Seek(0, [System.IO.SeekOrigin]::End)

$LastCleanup = Get-Date

try {
    while ($true) {
        # 1. Limpieza periodica cada 5 segundos
        if ((Get-Date) -ge $LastCleanup.AddSeconds(5)) {
            Cleanup-ExpiredBlocks
            $LastCleanup = Get-Date
        }

        # 2. Intentar leer una linea nueva del log de Snort
        $Line = $Reader.ReadLine()
        if ($Line -ne $null) {
            
            # Filtrar por SID (Solo procesa tus reglas personalizadas 1002001 - 1002036)
            if ($Line -match '\[\d+:(\d+):\d+\]') {
                $SID = [int]$Matches[1]
                if ($SID -lt 1002001 -or $SID -gt 1002036) {
                    continue # Ignorar alertas ajenas al laboratorio
                }
            } else {
                continue
            }

            # Extraer la IP de origen
            if ($Line -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?\s*->') {
                $AttackerIP = $Matches[1]

                # Si ya esta bloqueado, renovamos el baneo
                if ($script:ActiveBlocks.ContainsKey($AttackerIP)) {
                    $script:ActiveBlocks[$AttackerIP] = (Get-Date).AddMinutes($BlockDurationMinutes)
                    continue
                }

                Block-IPAddress -IP $AttackerIP
            }
        } else {
            # SOLUCION AL CACHE DE .NET: Forzar al StreamReader a sincronizar con el disco duro
            $Reader.DiscardBufferedData()
            Start-Sleep -Milliseconds 100
        }
    }
}
finally {
    # Asegurar el cierre correcto de archivos y limpieza al detener el script
    $Reader.Close()
    $FileStream.Close()
    $null = Remove-NetFirewallRule -Group $BlockRuleGroup -ErrorAction SilentlyContinue
    Write-Host "`n[!] Script finalizado. Todas las reglas del laboratorio han sido removidas." -ForegroundColor Yellow
}