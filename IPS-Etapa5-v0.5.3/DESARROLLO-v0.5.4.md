# SOC DEKMA IPS v0.5.4-dev1 - Adversarial Hardening

Rama de desarrollo: `v0.5.4-dev1-adversarial-hardening`

## Objetivo de dev1

Eliminar la ventana lógica en la que el motor de políticas iniciaba cooldown antes de conocer el resultado real del actuador.

## Cambios implementados

- La configuración de desarrollo por defecto vuelve a `Audit`.
- Se conserva `config\ips-config.enforce.test.json` para pruebas reales controladas.
- `PolicyEngine.psm1` incorpora `PendingDecisions`.
- Un umbral satisfecho genera una propuesta con `ProposalId`.
- Mientras la propuesta está pendiente se devuelve `PENDING` y no se crea otra propuesta para la misma política/origen.
- `Confirm-IPSPolicyBlock` elimina tracking e inicia cooldown.
- `Cancel-IPSPolicyBlock` elimina solamente la propuesta y conserva tracking.
- `IPS-watch.ps1` confirma solo resultados `SIMULATED`, `CREATED` y `REFRESHED`.
- `ERROR`, `LIMIT`, `CONFLICT` y `REFUSED` abortan la propuesta y no inician cooldown.
- Nuevos eventos operativos: `POLICY_PENDING`, `BLOCK_COMMITTED` y `BLOCK_ABORTED`.

## Validación requerida en Windows Server 2012 R2

Ejecutar primero en Audit:

```powershell
powershell.exe -NoProfile -File .\IPS-watch.ps1 -RunMode Validate
powershell.exe -NoProfile -File .\tests\Test-Stage3.ps1
powershell.exe -NoProfile -File .\tests\Test-Stage6PolicyFailure.ps1
powershell.exe -NoProfile -File .\tests\Test-Stage4.ps1
powershell.exe -NoProfile -File .\tests\Test-Stage4Integration.ps1
powershell.exe -NoProfile -File .\tests\Test-Stage5LatencyIntegration.ps1
powershell.exe -NoProfile -File .\tests\Test-Stage5PerformanceIntegration.ps1
```

Después debe ejecutarse la regresión completa de v0.5.3 antes de avanzar a dev2.

## Criterio de aceptación

Un resultado del actuador distinto de `SIMULATED`, `CREATED` o `REFRESHED` no debe crear cooldown y debe conservar suficiente estado para permitir una nueva propuesta.
