# Validacion de SOC DEKMA IPS Etapa 5 v0.5.3

Realice estas pruebas en Windows Server 2012 R2 desde PowerShell como administrador. Mantenga `operation.mode` en `Audit` durante toda esta validacion.

## 1. Verificar configuracion

```powershell
cd C:\Snort\IPS-Etapa5-v0.5.3
powershell.exe -NoProfile -File .\IPS-watch.ps1 -RunMode Validate
```

Resultado esperado: `CONFIG_VALID` y `POLICY_CONFIG_VALID`.

## 2. Ejecutar la regresion completa

```powershell
powershell.exe -NoProfile -File .\tests\Test-Stage1.ps1
powershell.exe -NoProfile -File .\tests\Test-Stage2.ps1
powershell.exe -NoProfile -File .\tests\Test-Stage2Integration.ps1
powershell.exe -NoProfile -File .\tests\Test-Stage2LiveFile.ps1
powershell.exe -NoProfile -File .\tests\Test-Stage3.ps1
powershell.exe -NoProfile -File .\tests\Test-Stage4.ps1
powershell.exe -NoProfile -File .\tests\Test-Stage4Integration.ps1
powershell.exe -NoProfile -File .\tests\Test-Stage5.ps1
powershell.exe -NoProfile -File .\tests\Test-Stage5LatencyIntegration.ps1
powershell.exe -NoProfile -File .\tests\Test-Stage5PerformanceIntegration.ps1
```

Ninguna de estas pruebas debe crear reglas reales. Envie la salida completa si aparece un `FAIL`, `Assertion failed` o texto rojo.

## 3. Confirmar umbrales de latencia

```powershell
Select-String -Path .\config\ips-config.json -Pattern `
    'delay_warning_seconds', `
    'max_event_age_seconds'
```

Resultado esperado: 10 segundos para advertencia y 30 segundos como maximo.

## 4. Comprobar el nuevo log diario

Inicie Watch en Audit:

```powershell
powershell.exe -NoProfile -File .\IPS-watch.ps1 -RunMode Watch
```

Genere desde Kali un escaneo controlado y compruebe en otra consola:

```powershell
Get-ChildItem .\events\ips.*.log
Get-Content .\events\ips.$((Get-Date).ToString('yyyy-MM-dd')).log -Tail 10
```

Debe existir exactamente el formato `ips.YYYY-MM-DD.log`. Cada linea debe ser un JSON completo.

## 5. Comprobar control concurrente

Con Watch todavia activo, ejecute:

```powershell
.\IPS-control.ps1 -Action Status
```

Debe terminar sin error de acceso al estado. El evento `STATUS` debe aparecer en el mismo log diario.

## 6. Comprobar limpieza independiente sin vencimientos

La limpieza es una operacion real y exige confirmacion, aunque no haya bloqueos:

```powershell
.\IPS-cleanup.ps1 -ConfirmRemoval
```

Resultado esperado cuando no hay bloqueos vencidos: evento `CLEANUP_NOTHING_EXPIRED`. No debe crear ni eliminar una regla.

## 7. Prueba Nmap de calibracion

Con Watch en Audit, ejecute desde Kali:

```bash
sudo nmap -sS -Pn -n -p 22,53,80,445 --max-retries 0 --reason 192.168.0.16
```

Luego, en Windows:

```powershell
$log = "C:\Snort\IPS-Etapa5-v0.5.3\events\ips.$((Get-Date).ToString('yyyy-MM-dd')).log"

Select-String -Path $log -Pattern `
    '"snort_sid":1000003', `
    '"event":"POLICY_TRACKING"', `
    '"event":"WOULD_BLOCK"', `
    '"event":"BLOCK_SIMULATED"', `
    '"event":"PERFORMANCE_SAMPLE"', `
    '"delivery_status":"DELAYED"', `
    '"decision":"STALE"'
```

El escaneo normal debe alcanzar `WOULD_BLOCK` y `BLOCK_SIMULATED`. Una alerta entre 10 y 30 segundos puede estar marcada `DELAYED`, pero no debe ser rechazada. Los lotes superiores a 30 segundos deben continuar como `STALE`.

## 8. Mostrar la medicion de tiempo

Despues del escaneo, convierta solamente las muestras de rendimiento a una tabla:

```powershell
$samples = Get-Content $log | ForEach-Object { ConvertFrom-Json -InputObject $_ } |
    Where-Object { $_.event -eq 'PERFORMANCE_SAMPLE' }

$samples | Select-Object timestamp,src_ip,dst_port,delivery_status, `
    bridge_delivery_ms,decision_ms,log_mutex_wait_ms,log_file_write_ms, `
    console_write_ms,policy_engine_ms,actuator_ms,actuator_pipeline_ms, `
    unattributed_ms,total_processing_ms,slow_processing,primary_delay,primary_delay_ms |
    Format-Table -AutoSize
```

Para ver primero las alertas mas lentas:

```powershell
$samples | Sort-Object total_processing_ms -Descending |
    Select-Object -First 10 timestamp,src_ip,dst_port,total_processing_ms, `
        primary_delay,primary_delay_ms,log_mutex_wait_ms,console_write_ms, `
        policy_engine_ms,actuator_ms |
    Format-Table -AutoSize
```

Interpretacion principal:

- `primary_delay=log_mutex_wait`: contencion entre procesos que escriben el log.
- `primary_delay=log_file_write`: almacenamiento o antivirus ralentizando el archivo.
- `primary_delay=console_write`: consola PowerShell bloqueada o demasiado lenta.
- `primary_delay=policy_engine`: evaluacion de politica lenta.
- `primary_delay=actuator`: mutex de estado, estado persistente o Windows Firewall.
- `primary_delay=unattributed`: demora fuera de los bloques instrumentados.

## 9. Evidencias que debe devolver

- Salida de `IPS-watch.ps1 -RunMode Validate`.
- Resultados finales de los diez scripts de pruebas.
- Nombre obtenido con `Get-ChildItem .\events\ips.*.log`.
- Ultimas lineas que contengan `STATUS` y `CLEANUP_NOTHING_EXPIRED`.
- Eventos del escaneo que muestren edad, estado de entrega y resultado de politica.
- Las dos tablas de `PERFORMANCE_SAMPLE`.

No cambie a Enforce en esta ronda. La prueba de expiracion real se definira despues de aprobar estas comprobaciones.
