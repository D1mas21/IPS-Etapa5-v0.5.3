# SOC DEKMA IPS - Etapa 5 v0.5.3

Esta version conserva las etapas 1 a 4 validadas y agrega el primer bloque de robustecimiento operativo:

- Log diario definitivo `events\ips.YYYY-MM-DD.log` en JSON Lines UTF-8 sin BOM.
- Escritura serializada entre Watch, Control y Cleanup mediante un mutex de log.
- Mutex de estado compartido para coordinar cambios de firewall y `firewall-blocks.json`.
- Limpieza independiente mediante `IPS-cleanup.ps1`.
- Recarga del estado desde disco dentro del mutex antes de cada operacion del actuador.
- Mutex separado para impedir dos instancias simultaneas de Watch.

## Revision v0.5.1: calibracion de latencia

Las mediciones reales mostraron una entrega habitual cercana a 10 segundos y lotes anormales de 105 a 191 segundos. La configuracion ahora distingue ambos casos:

- `delay_warning_seconds`: 10.
- `max_event_age_seconds`: 30.
- Hasta 10 segundos: `delivery_status=ON_TIME`.
- Mas de 10 y hasta 30 segundos: la alerta se acepta con `delivery_status=DELAYED`.
- Mas de 30 segundos: se rechaza con `decision=STALE`.
- Mas de 2 segundos en el futuro: se rechaza con `decision=FUTURE`.

Cada alerta conserva `age_seconds` e incorpora `delivery_delayed`, los dos umbrales y contadores acumulados. `WATCH_STOPPED` resume alertas aceptadas, retrasadas, antiguas y futuras.

## Revision v0.5.2: correccion de validacion

Esta revision no modifica la logica operativa validada con Nmap. Corrige exclusivamente la bateria y el empaquetado:

- Restaura `tests\Test-Stage2Integration.ps1` y lo adapta al log diario `ips.YYYY-MM-DD.log`.
- La alerta futura de la integracion usa un margen de 60 segundos para evitar que el tiempo de arranque de PowerShell 4 la convierta en `ON_TIME`.
- La comprobacion de alertas retrasadas filtra explicitamente `delivery_status=DELAYED`.
- La integracion exige una alerta `STALE`, una `FUTURE`, tres alertas retrasadas aceptadas y los contadores finales exactos.

## Revision v0.5.3: telemetria de tiempo

Esta revision mantiene `Audit` y no cambia umbrales ni decisiones. Agrega un evento `PERFORMANCE_SAMPLE` por alerta valida con:

- `bridge_delivery_ms`: antiguedad de la alerta al recibirla.
- `decision_ms`: parseo, validacion y decision inicial.
- `log_mutex_wait_ms`: espera acumulada del mutex de log.
- `log_file_write_ms`: escritura y flush al log diario.
- `console_write_ms`: tiempo consumido por la salida de PowerShell.
- `policy_engine_ms`: evaluacion del motor de politicas.
- `actuator_ms`: mutex de estado y actuador.
- `actuator_pipeline_ms`: solicitud, actuador y eventos asociados.
- `unattributed_ms`: tiempo restante no explicado por los componentes anteriores.
- `total_processing_ms`, `slow_processing`, `primary_delay` y `primary_delay_ms`.

Una muestra se marca lenta cuando `total_processing_ms` es igual o superior a 1000 ms. El evento permite distinguir contencion del mutex, lentitud de disco, consola, politica o actuador antes de habilitar `Enforce`.

## Arquitectura de concurrencia

Se utilizan tres responsabilidades independientes:

1. `Global\SOC-DEKMA-IPS-WATCH-5`: permanece adquirido durante toda la ejecucion de Watch e impide otro Watch.
2. `Global\SOC-DEKMA-IPS-STATE-5`: se adquiere solo mientras se lee o modifica el estado y Windows Firewall.
3. `Global\SOC-DEKMA-IPS-LOG-5`: se adquiere durante la escritura de una sola linea JSON.

Watch no mantiene el mutex de estado permanentemente. Por ello `IPS-control.ps1` e `IPS-cleanup.ps1` pueden operar mientras Watch se encuentra activo, sin escribir simultaneamente el archivo de estado.

## Barreras de seguridad conservadas

- `Audit` nunca modifica Windows Firewall.
- `Enforce` requiere `operation.mode=Enforce` y `-EnableEnforcement`.
- La IP se vuelve a evaluar antes del bloqueo.
- El destino solo puede ser el servidor protegido.
- Las reglas ajenas o inconsistentes se consideran conflicto y no se eliminan.
- La limpieza independiente exige administrador y `-ConfirmRemoval`.

## Validacion segura

Ejecutar inicialmente con la configuracion en `Audit`:

```powershell
powershell.exe -NoProfile -File .\IPS-watch.ps1 -RunMode Validate
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

Las pruebas Stage4 usan firewall simulado o modo Audit. `Test-Stage5.ps1` valida nombre diario, JSON, UTF-8, mutex, escrituras concurrentes y los limites 9.9, 10.2, 29.9, 30.1 y -2.1 segundos. `Test-Stage5LatencyIntegration.ps1` comprueba que tres alertas retrasadas alcancen `WOULD_BLOCK` y `BLOCK_SIMULATED`, mientras una antigua y una futura se rechazan. Ninguna toca Windows Firewall.

## Limpieza independiente

Prueba manual, desde PowerShell como administrador:

```powershell
.\IPS-cleanup.ps1 -ConfirmRemoval
```

El script solo examina reglas registradas en `state\firewall-blocks.json`. Puede emitir:

- `CLEANUP_NOTHING_EXPIRED`
- `BLOCK_EXPIRED_REMOVED`
- `BLOCK_STATE_STALE`
- `BLOCK_CONFLICT`
- `BLOCK_ERROR`
- `CLEANUP_ERROR`

No se instala todavia una tarea programada. La instalacion automatica, reinicio ante fallo, heartbeat y retencion de logs forman el siguiente bloque de la Etapa 5.

## Control administrativo

```powershell
.\IPS-control.ps1 -Action Status
.\IPS-control.ps1 -Action CleanupExpired -ConfirmRemoval
.\IPS-control.ps1 -Action Unblock -Address 192.168.0.7 -ConfirmRemoval
```

Las acciones de control tambien se registran en el log diario compartido.

## Estado de la configuracion entregada

`config\ips-config.json` permanece en `Audit`. No cambie a Enforce hasta completar todas las pruebas en Windows Server 2012 R2 y revisar los eventos generados.
