# Matriz inicial de politicas

| Politica | SID autorizados | Condicion | Propuesta |
|---|---|---|---|
| `tcp_syn_open_scan` | 1000003 rev. 1 | 3 alertas, 2 puertos, 10 s | 300 s |
| `tcp_connect_scan` | 1000116 rev. 2 | 3 alertas, 2 puertos, 15 s | 300 s |
| `os_fingerprint_sequence` | 1000301-1000310 rev. 2 | 3 alertas y 3 SID, 15 s | 600 s |
| `service_version_fingerprint` | 1000401-1000403 rev. 2 | 1 alerta especifica | 600 s |
| `udp_scan_confirmed` | 1000503, 1000506, 1000507 rev. 2 | 1 alerta confirmada | 300 s |
| `tcp_flag_scan_confirmed` | 1000603, 1000702, 1000802, 1000902, 1001002, 1001102 rev. 2 | 1 alerta agregada | 300 s |
| `ip_protocol_recon` | 1001201, 1001202 rev. 2 | 2 alertas y 2 SID, 15 s | 600 s |
| `sctp_scan_confirmed` | 1001302 rev. 2; 1001402 rev. 1 | 1 alerta agregada | 300 s |
| `icmp_timestamp_recon` | 1001501 rev. 2 | 2 alertas, 5 s | 300 s |
| `smb_version_recon` | 1001701 rev. 2 | 3 alertas, 10 s | 600 s |

En `Audit`, las duraciones solo se simulan. En `Enforce`, una decision `WOULD_BLOCK` valida solicita al actuador una regla entrante temporal contra el origen y con destino exclusivo al servidor protegido. Los SID no enumerados quedan sin politica de respuesta aunque el lector los registre.
