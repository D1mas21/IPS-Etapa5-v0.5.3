# C:\Snort\watch-ps4-v5.ps1
#
# SOC DEKMA - Snort 2.9.20
# Windows Server 2012 R2
# Windows PowerShell 4.0
#
# V5: agrega limpieza del archivo puente de alertas (alert-live.log).
#
# CONTEXTO (viene de V4):
#   Snort no puede escribir sus alertas via stdout capturado por un pipe
#   de PowerShell sin sufrir "full buffering" (ver comentarios de V4).
#   La solucion es que Snort escriba con su propio plugin de archivo
#   (output alert_fast: alert-live.log) y que el script haga polling
#   sincronico sobre ese archivo. ESO SIGUE IGUAL EN V5.
#
#   Consecuencia inevitable: mientras Snort corre, "alert-live.log" va a
#   contener temporalmente los mismos eventos que ya se escribieron en
#   snort.<fecha>.log. No hay forma de eliminar ese archivo puente por
#   completo sin volver al esquema roto de V3 (captura de stdout).
#
# QUE CAMBIA EN V5:
#   Se evito truncar "alert-live.log" en caliente mientras Snort lo tiene
#   abierto (truncar con un handle externo mientras el proceso escribe
#   tiene una ventana de carrera en la que se podria perder una alerta
#   escrita justo en ese instante -> inaceptable para una herramienta de
#   deteccion).
#
#   En cambio, en el mismo momento en que rota el log diario (cambio de
#   fecha), el script fuerza un REINICIO CONTROLADO de Snort: se drena
#   todo lo que haya quedado en el archivo puente, se detiene Snort de
#   forma prolija, se borra "alert-live.log", y se vuelve a arrancar
#   limpio. Es el mismo mecanismo ya probado que se usa para recuperarse
#   de un crash, asi que no agrega riesgo nuevo de perder alertas.
#
#   Resultado: "alert-live.log" nunca acumula mas que el dia en curso,
#   y se limpia solo, todos los dias, sin intervencion manual.
#
# IMPORTANTE:
#   Esto significa que, durante el dia, "alert-live.log" SI va a tener
#   contenido (es el origen tecnico de los datos). Lo que ya no va a
#   pasar es que crezca sin limite ni quede como un archivo permanente
#   con todo el historico duplicado.

$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# Configuracion
# ---------------------------------------------------------------------------

$snortExe        = "C:\Snort\bin\snort.exe"
$baseConfig      = "C:\Snort\etc\snort.conf"
$runtimeConfig   = "C:\Snort\etc\snort-runtime.conf"
$snortLogDir     = "C:\Snort\log"
$oldSpoolPath    = "C:\Snort\log\snort-spool.log"
$interfaceId     = "6"
$alertLiveName   = "alert-live.log"
$alertLivePath   = Join-Path $snortLogDir $alertLiveName

$script:currentDate    = ""
$script:logStream      = $null
$script:logWriter      = $null
$script:snortProcess   = $null

# ---------------------------------------------------------------------------
# Validaciones
# ---------------------------------------------------------------------------

if ($PSVersionTable.PSVersion.Major -lt 4) {
    Write-Error "Este script requiere Windows PowerShell 4.0 o superior."
    exit 1
}

if (-not (Test-Path $snortExe -PathType Leaf)) {
    Write-Error "No se encontro Snort: $snortExe"
    exit 1
}

if (-not (Test-Path $baseConfig -PathType Leaf)) {
    Write-Error "No se encontro snort.conf: $baseConfig"
    exit 1
}

if (-not (Test-Path $snortLogDir -PathType Container)) {
    New-Item -Path $snortLogDir -ItemType Directory -Force | Out-Null
}

$existingSnort = @(Get-Process -Name "snort" -ErrorAction SilentlyContinue)

if ($existingSnort.Count -gt 0) {
    Write-Error "Ya existe un proceso Snort. Detengalo antes de ejecutar este script."
    exit 1
}

# ---------------------------------------------------------------------------
# Preparar runtime: forzar alert_fast a archivo conocido
# ---------------------------------------------------------------------------

$alertFastPattern    = '(?m)^[ \t]*output[ \t]+alert_fast[ \t]*:.*$'
$binaryOutputPattern = '(?m)^[ \t]*output[ \t]+(alert_unified2|log_unified2|log_tcpdump)[ \t]*:'
$alertLiveDirective  = "output alert_fast: $alertLiveName"

function New-RuntimeConfig {

    $content = [System.IO.File]::ReadAllText($baseConfig)

    if ([System.Text.RegularExpressions.Regex]::IsMatch(
        $content,
        $binaryOutputPattern
    )) {
        throw "Comente alert_unified2, log_unified2 y log_tcpdump en snort.conf."
    }

    if ([System.Text.RegularExpressions.Regex]::IsMatch($content, $alertFastPattern)) {
        $content = [System.Text.RegularExpressions.Regex]::Replace(
            $content,
            $alertFastPattern,
            $alertLiveDirective
        )
    }
    else {
        $content += "`r`n$alertLiveDirective`r`n"
    }

    [System.IO.File]::WriteAllText(
        $runtimeConfig,
        $content,
        [System.Text.Encoding]::ASCII
    )
}

# ---------------------------------------------------------------------------
# Archivo diario (log consolidado que arma el watcher)
# ---------------------------------------------------------------------------

function Close-DailyLog {

    if ($null -ne $script:logWriter) {
        try { $script:logWriter.Flush() } catch {}
        try { $script:logWriter.Dispose() } catch {}
        $script:logWriter = $null
    }

    if ($null -ne $script:logStream) {
        try { $script:logStream.Dispose() } catch {}
        $script:logStream = $null
    }
}

function Open-DailyLog {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Date
    )

    Close-DailyLog

    $logPath = Join-Path $snortLogDir ("snort.{0}.log" -f $Date)

    $utf8 = New-Object System.Text.UTF8Encoding($false)

    $script:logStream = New-Object System.IO.FileStream(
        $logPath,
        [System.IO.FileMode]::Append,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::ReadWrite
    )

    $script:logWriter = New-Object System.IO.StreamWriter(
        $script:logStream,
        $utf8
    )

    $script:logWriter.AutoFlush = $true
    $script:currentDate = $Date

    Write-Host ("Log activo: {0}" -f $logPath)
}

# ---------------------------------------------------------------------------
# Manejo de procesos Snort
# ---------------------------------------------------------------------------

function Stop-Snort {

    $processes = @(Get-Process -Name "snort" -ErrorAction SilentlyContinue)

    foreach ($process in $processes) {
        try {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
        catch {}
    }
}

function Wait-ForAlertFile {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [int]$TimeoutSeconds = 15
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while (-not (Test-Path $Path -PathType Leaf)) {

        if ((Get-Date) -gt $deadline) {
            return $false
        }

        Start-Sleep -Milliseconds 200
    }

    return $true
}

# ---------------------------------------------------------------------------
# Inicio
# ---------------------------------------------------------------------------

try {

    if (Test-Path $oldSpoolPath -PathType Leaf) {
        Remove-Item -Path $oldSpoolPath -Force -ErrorAction SilentlyContinue
    }

    New-RuntimeConfig

    $today = Get-Date -Format "yyyy-MM-dd"
    Open-DailyLog -Date $today

    Write-Host ""
    Write-Host "SOC DEKMA - Snort Watch PS4 V5"
    Write-Host ("PowerShell       : {0}" -f $PSVersionTable.PSVersion)
    Write-Host ("Interfaz         : {0}" -f $interfaceId)
    Write-Host ("Runtime          : {0}" -f $runtimeConfig)
    Write-Host ("Alertas (puente) : {0}" -f $alertLivePath)
    Write-Host "Packet logging   : -N"
    Write-Host "Checksum         : -k none"
    Write-Host ("Log              : C:\Snort\log\snort.{0}.log" -f $today)
    Write-Host ""
    Write-Host "Presione Ctrl+C para detener."
    Write-Host ""

    while ($true) {

        Write-Host ("Iniciando Snort: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))

        if (Test-Path $alertLivePath -PathType Leaf) {
            Remove-Item -Path $alertLivePath -Force -ErrorAction SilentlyContinue
        }

        $snortArgs = @(
            "-q",
            "-i", $interfaceId,
            "-c", $runtimeConfig,
            "-l", $snortLogDir,
            "-N",
            "-k", "none"
        )

        $script:snortProcess = Start-Process `
            -FilePath $snortExe `
            -ArgumentList $snortArgs `
            -NoNewWindow `
            -PassThru

        if (-not (Wait-ForAlertFile -Path $alertLivePath -TimeoutSeconds 15)) {

            Write-Warning ("El archivo de alertas no aparecio: {0}" -f $alertLivePath)
            Write-Warning "Revise que 'output alert_fast' se haya aplicado bien en el runtime config."

            if (-not $script:snortProcess.HasExited) {
                Stop-Process -Id $script:snortProcess.Id -Force -ErrorAction SilentlyContinue
            }

            Start-Sleep -Seconds 2
            Stop-Snort
            continue
        }

        $alertStream = New-Object System.IO.FileStream(
            $alertLivePath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite
        )

        $alertReader = New-Object System.IO.StreamReader($alertStream)

        $restartForRotation = $false

        try {

            # ============================================================
            # BLOQUE CRITICO
            #
            # Polling sincronico sobre el archivo puente. Sin ReadLineAsync,
            # sin 2>&1, sin depender del stdout de Snort.
            # ============================================================

            while ((-not $script:snortProcess.HasExited) -and (-not $restartForRotation)) {

                $line = $alertReader.ReadLine()

                if ($null -eq $line) {
                    Start-Sleep -Milliseconds 300
                    continue
                }

                if ([string]::IsNullOrWhiteSpace($line)) {
                    continue
                }

                $newDate = Get-Date -Format "yyyy-MM-dd"

                if ($newDate -ne $script:currentDate) {

                    Open-DailyLog -Date $newDate
                    Write-Host ("Cambio diario. Nuevo log: C:\Snort\log\snort.{0}.log" -f $newDate)

                    # Cambio de dia: pedimos un reinicio controlado de Snort
                    # para que el archivo puente se limpie (ver encabezado).
                    $restartForRotation = $true
                }

                # No se imprime la alerta a la terminal: en produccion solo
                # debe quedar registrada en el log diario.
                if ($null -ne $script:logWriter) {
                    $script:logWriter.WriteLine($line)
                }
            }

            # Drenaje final: cualquier linea que haya quedado escrita en el
            # archivo puente justo antes de cerrar (por rotacion de dia o
            # porque Snort termino/crasheo).
            while ($true) {

                $line = $alertReader.ReadLine()

                if ($null -eq $line) {
                    break
                }

                if ([string]::IsNullOrWhiteSpace($line)) {
                    continue
                }

                if ($null -ne $script:logWriter) {
                    $script:logWriter.WriteLine($line)
                }
            }
        }
        finally {
            try { $alertReader.Dispose() } catch {}
            try { $alertStream.Dispose() } catch {}
        }

        if ($restartForRotation) {

            Write-Host "Rotacion diaria: reiniciando Snort para limpiar el archivo puente de alertas."

            if (-not $script:snortProcess.HasExited) {
                Stop-Process -Id $script:snortProcess.Id -Force -ErrorAction SilentlyContinue
            }

            Start-Sleep -Seconds 2
            Stop-Snort
            continue
        }

        $exitCode = -1

        if ($null -ne $script:snortProcess -and $script:snortProcess.HasExited) {
            $exitCode = $script:snortProcess.ExitCode
        }

        Write-Warning ("Snort termino. Codigo de salida: {0}" -f $exitCode)
        Write-Warning "Reinicio automatico en 2 segundos."

        Start-Sleep -Seconds 2

        Stop-Snort
    }
}
catch {
    Write-Error ("watch-ps4-v5: {0}" -f $_.Exception.Message)
}
finally {

    if ($null -ne $script:snortProcess -and -not $script:snortProcess.HasExited) {
        try {
            Stop-Process -Id $script:snortProcess.Id -Force -ErrorAction SilentlyContinue
        }
        catch {}
    }

    Stop-Snort
    Close-DailyLog

    Write-Host "Snort Watch finalizado."
}
