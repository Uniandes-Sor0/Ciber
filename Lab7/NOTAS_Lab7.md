# Lab 7 — Seguridad Perimetral (pfSense + Wazuh) — Progreso

## Escenario
Borraron **todas** las reglas del firewall pfSense → zonas aisladas, servicios caídos.
Tareas: (1) reconstruir reglas con **mínimo privilegio**; (2) instalar **agentes Wazuh** en los servidores **FTP y HTTP** para que reporten al Wazuh Manager.

## Topología (confirmada en pfSense — Status→Interfaces + Aliases)
| Interfaz | Subred | IP pfSense | Zona |
|---|---|---|---|
| WAN | 10.10.20.0/24 | 10.10.20.63 | Exterior; NAT SSH 22 / RDP 3389 → Kali |
| LAN | 192.123.99.0/24 | .99.1 | **GESTIÓN** (Kali `kali-123` .128) |
| OPT1 | 192.123.10.0/24 | .10.1 | **DMZ** — Web .10.10, FTP .10.20, Mail .10.30 |
| OPT2 | 192.123.20.0/24 | .20.1 | **INTERNA** — BD .20.10; Wazuh Mgr .20.40, nodo .41, Dashboard .42 |
| OPT3 | 192.123.30.0/24 | .30.1 | **OTHER** (clientes) |
| OPT4 | 192.123.40.0/24 | .40.1 | Troncal de VLANs |
| VLAN41_SERV | 192.123.41.0/24 | .41.1 | **HIDDEN-SERVICE** |
| VLAN42_LEGACY | 192.123.42.0/24 | .42.1 | **HIDDEN-LEGACY** |

**Aliases pfSense:** `DB`=.20.10 · `DMZ`=10.0/24 · `INTERNAL`=20.0/24 · `OTHER`=30.0/24 · `KALI`=.99.128 · `MASCARA_KALI`=99.0/24 · `FIREWALL`=10.10.20.63 · `WAZUH_MANAGER`=.20.40 · `WAZUH_DASHBOARD`=.20.42 · `WAZUH_NODES`=.20.40/.41/.42.

> Observación para el informe: el enunciado dice "SIEM en el segmento de gestión", pero en el entorno real Wazuh está en **INTERNA (192.123.20.x)**, no en gestión (99.x).

## Fase 1 — Diagnóstico ✅ (HECHO)
- **Reglas internas vacías:** LAN solo tiene la *Anti-Lockout* (443/80 al pfSense, regla de sistema); OPT1–OPT4 y las VLANs: "No rules currently defined" → todo bloqueado.
- **WAN conserva reglas a propósito** (gestión): OpenVPN 1194, NAT SSH/RDP → KALI, syslog 514 → WAZUH_NODES, block bogons. **No tocar.**
- **nmap -sn:** 0 hosts up. **ping al gateway .99.1 = 100% packet loss** (solo 443/80 permitido por anti-lockout) → **aislamiento total confirmado**.

## Fase 2 — Diseño de reglas (mínimo privilegio) — PROPUESTA
Regla en la interfaz de **origen** (stateful: la respuesta se permite sola). ✅ = dependencia segura; ❓ = pendiente de confirmar.

### OPT1 / DMZ (origen: servidores DMZ)
| Origen | Destino | Puerto | Justificación |
|---|---|---|---|
| ✅ WEB .10.10 | DB .20.10 | TCP 3306❓ | App web → base de datos |
| ✅ WEB .10.10, FTP .10.20 | WAZUH_MANAGER .20.40 | TCP 1514-1515 | Agentes Wazuh → SIEM (tarea nueva) |

### OPT3 / OTHER (origen: usuarios)
| Origen | Destino | Puerto | Justificación |
|---|---|---|---|
| ❓ OTHER | WEB .10.10 | TCP 80,443 | Acceso web |
| ❓ OTHER | MAIL .10.30 | TCP 25/587/143/993 | Correo |
| ❓ OTHER | FTP .10.20 | TCP 21 + pasivos | FTP |

### LAN / GESTIÓN (origen: Kali/admin)
| Origen | Destino | Puerto | Justificación |
|---|---|---|---|
| ✅ MASCARA_KALI | WAZUH_DASHBOARD .20.42 | TCP 443 | Ver panel SIEM |
| ❓ KALI | servidores | TCP 22 | Administración (acotar) |

### INTERNAL / VLANs HIDDEN
- INTERNAL: sin reglas entrantes nuevas (respuestas stateful).
- VLAN41/42 HIDDEN: pendiente de qué alojan.

## Pendiente de confirmar (5 datos)
1. IPs reales de web/ftp/mail (¿.10.10 / .10.20 / .10.30 como en Lab 1?)
2. Motor y puerto de BD (MySQL 3306 / PostgreSQL 5432 / otro)
3. Zona de los clientes (¿OTHER 30.x? ¿también HIDDEN?)
4. Protocolos de correo necesarios
5. Qué alojan VLAN41_SERV y VLAN42_LEGACY y si participan en flujos

## Acceso y puente de evidencias
- **Kali SSH/RDP = `10.10.20.63`** (NO `172.24.101.18:8000`, que da TCP cerrado). Requiere la VPN del lab (la PC obtiene `10.10.8.x`).
- Alias PC: `ssh kali7` → `10.10.20.63:22`, user `proyecto`, llave `~/.ssh/lab4_kali`.
- Evidencias: en Kali `~/lab7/{diagnostico,reglas,wazuh,verificacion}` → `scp -r kali7:"lab7/*" <repo>/Lab7/evidencias/`.

## Capturas tomadas
1) `ip -br a`/`ip route` (topología) · 2) Interfaces pfSense · 2b) IPs de interfaces · 3) Reglas vacías · 4) nmap/ping (aislamiento).
