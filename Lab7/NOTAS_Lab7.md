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

## Fase 2 — Reconstrucción de reglas ⏳ (LAN ✅ aplicado 05/11 · faltan DMZ, OTHER, INTERNA, VLANs)

### Bloque LAN — APLICADO Y VERIFICADO (05/11)
Las 6 reglas (LAN-1…LAN-5) están activas y el verificador pasa en verde: ping a las 4 zonas,
SSH a web/ftp/db, API Wazuh 55000. Los 3 controles de mínimo privilegio (Kali→MySQL,
Kali→php-fpm, Kali→web 80) siguen **bloqueados**, como debe ser.
Evidencia: `evidencias/verificacion/fase2_lan.txt`.

**Incidente didáctico para el informe (*shadowing* de reglas):** al crearlas con el botón
`Add ↑`, LAN-5 (deny-all) quedó **encima** de las demás. pfSense evalúa de arriba abajo con
*first match wins*, así que bloqueaba todo y las 5 reglas de paso nunca se evaluaban. Se detectó
porque el panel de Wazuh pasó de `Connection refused` a `Connection timed out` sin tocar LAN-1.
Se arregló arrastrando LAN-5 al final. Responde directo a la pregunta 1 de reflexión.

**Hallazgo abierto:** el **Wazuh Dashboard no escucha en 192.123.20.42:443** (da *refused*: el
paquete cruza el firewall, no hay servicio). El **Manager sí responde en 55000**, así que la pila
está viva y es solo el puerto/servicio del panel. Hay que encontrar el puerto real (¿5601?) —
requiere una regla temporal `KALI → WAZUH_NODES` para inventariar, o mirarlo desde el manager.



**Matriz completa y pasos de la GUI: [`FASE2_reglas.md`](FASE2_reglas.md).** Resumen:

| Interfaz | Reglas de paso | Idea |
|---|---|---|
| LAN (gestión) | Kali → Dashboard 443, Manager 55000, servidores 22, ICMP echo a todo | poder ver y verificar |
| OPT1 DMZ | WEB→DB 3306 · agentes→Manager 1514/1515 · DNS .10.1:53 · agentes→**!internas** 80/443 | servicio + Fase 3 sin pivote |
| OPT3 OTHER | →WEB 80 · →MAIL 143/465/587 · →FTP 21 + pasivo 50000-50100 | usuarios, sin tocar la BD |
| OPT2 INTERNA | ninguna (solo respuestas por estado) | zona de datos, deny total |
| OPT4 / VLAN41 / VLAN42 | ninguna | deny hasta inventariar |
| WAN | **no tocar** | gestión intacta |

Cada interfaz cierra con un **block + log** explícito: no cambia el filtrado pero deja rastro, y
el syslog 514 ya va a `WAZUH_NODES` → el SIEM también ve lo denegado.

### Los 5 pendientes: RESUELTOS (fuente: `Lab1/evidencias/nmap/` + `WazuhAlpine.pdf`)
1. **IPs/puertos reales:** web `192.123.10.10` **solo 80** (nginx 1.26.3, Alpine; 9000 = php-fpm, no se abre) · ftp `192.123.10.20` **21** (vsftpd 3.0.3) · mail `192.123.10.30` **25/143/465/587** (Postfix+Dovecot) · todos con 22.
2. **BD:** MySQL 8.0.46 en `192.123.20.10` → **3306/TCP**.
3. **Clientes:** zona OTHER `192.123.30.0/24` (.10, .11 y .20 vivos). Las VLAN HIDDEN no participan en ningún flujo conocido.
4. **Correo:** a los clientes solo IMAP 143 + submission 587/465. **El 25 NO se abre a clientes** (es transporte servidor-a-servidor).
5. **VLAN41_SERV / VLAN42_LEGACY: RESUELTO con el entregable del Lab 6** (`Lab6/Lab6_entrega 2.zip`). HIDDEN = `192.123.40.0/24` con 4 hosts: gateway `.40.1` (Unbound DNS + nginx) y tres web `.40.4`, `.40.189`, `.40.231` (nginx 1.31.3, solo puerto 80, contenido idéntico, 3 CVE sin parchear). Las VLAN 41/42 las crearon **ellas** en el Lab 6 sobre `vtnet5`, con los hosts aún **sin migrar** (siguen en 40.x sin etiquetar). **Hallazgo nuevo (verificado hoy en la VM):** el borrado del practicante se llevó también la regla de la pestaña **OpenVPN** → `tun0` levanta y la ruta existe, pero ningún host de HIDDEN responde y el `curl` devuelve cuerpo vacío en vez del `f24c1e10…` del Lab 6. Restaurar esa regla y las de VLAN41/42 es parte de la Fase 2 (ver `FASE2_reglas.md` §2.5). Revisión del diseño del Lab 6: `Lab6/REVISION_diseno.md`.

### Hallazgo que condiciona la Fase 3
El web es **Alpine + musl**: el agente Wazuh 4.12 hay que **compilarlo** (`apk add`, `git clone`,
`make deps`) → necesita **salida a Internet**. De ahí la regla DMZ-4 con destino **negado**
(`not REDES_INTERNAS`): sale a Internet pero no puede pivotar hacia dentro. Alternativa sin
salida: bajar fuentes y dependencias por `scp` desde Kali.

### Línea base antes de aplicar (evidencia)
`~/lab7/verificacion/antes_fase2.txt` (29/10): ping al gateway .99.1 **100% loss**; los 8 flujos
(web 80, ftp 21, mail 25/587, db 3306, wazuh 1514/1515, dashboard 443) **todos en timeout**;
en pfSense solo responden 443/80 (anti-lockout) y el 22 del firewall está cerrado → la
configuración se hace **por la GUI**, no por CLI.

## Acceso y puente de evidencias
- **Kali SSH/RDP = `10.10.20.63`** (NO `172.24.101.18:8000`, que da TCP cerrado). Requiere la VPN del lab (la PC obtiene `10.10.8.x`).
- Alias PC: `ssh kali7` → `10.10.20.63:22`, user `proyecto`, llave `~/.ssh/lab4_kali`.
- Evidencias: en Kali `~/lab7/{diagnostico,reglas,wazuh,verificacion}` → `scp -r kali7:"lab7/*" <repo>/Lab7/evidencias/`.

## Capturas tomadas
1) `ip -br a`/`ip route` (topología) · 2) Interfaces pfSense · 2b) IPs de interfaces · 3) Reglas vacías · 4) nmap/ping (aislamiento).
