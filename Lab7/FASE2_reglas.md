# Lab 7 — Fase 2: Reconstrucción de reglas de firewall (pfSense)

Política: **deny por defecto**, permitir solo el flujo mínimo documentado. Cada regla se crea en
la **interfaz de origen** (pfSense filtra el tráfico que *entra* por la interfaz) y es **stateful**:
la respuesta vuelve sola, no hace falta la regla inversa.

## 0. Datos confirmados (origen de la verdad)

IPs y puertos tomados del escaneo del Lab 1 (`Lab1/evidencias/nmap/`), no de suposiciones:

| Servicio | IP | Puertos abiertos reales | Software |
|---|---|---|---|
| Web (portal académico) | 192.123.10.10 | 22, **80**, 9000 | nginx 1.26.3 (Alpine) |
| FTP | 192.123.10.20 | 22, **21** | vsftpd 3.0.3 |
| Mail | 192.123.10.30 | **25, 143, 465, 587** | Postfix + Dovecot |
| Base de datos | 192.123.20.10 | 22, **3306** | MySQL 8.0.46 |
| Wazuh Manager | 192.123.20.40 | 1514, 1515, 55000 | Wazuh 4.12 |
| Wazuh Dashboard | 192.123.20.42 | 443 | — |
| Clientes (OTHER) | 192.123.30.10/.11/.20 | 22 (y .20: 25/80/8080) | puestos de usuario |

Notas:
- El web **no tiene 443**: hoy el portal es HTTP plano. La regla se escribe para 80 y se deja
  preparada para 443 (recomendación de mejora en el informe).
- El **9000/tcp** del web es php-fpm: no debe salir de la máquina, no se abre en el firewall.
- El agente Wazuh necesita **1515/TCP** (registro) y **1514/TCP** (conexión persistente); el
  **55000/TCP** (API) solo es el plan B de registro — ver `WazuhAlpine.pdf`.
- El web es **Alpine + musl**: para compilar el agente necesita **salida a Internet**
  (`apk add`, `git clone`, `make deps`). Eso obliga a una regla de salida acotada (ver DMZ-4).

## 1. Aliases a crear (Firewall → Aliases)

Ya existen: `DB`, `DMZ`, `INTERNAL`, `OTHER`, `KALI`, `MASCARA_KALI`, `FIREWALL`,
`WAZUH_MANAGER`, `WAZUH_DASHBOARD`, `WAZUH_NODES`. Faltan:

| Alias | Tipo | Valor | Para qué |
|---|---|---|---|
| `WEB` | Host | 192.123.10.10 | servidor web |
| `FTP_SRV` | Host | 192.123.10.20 | servidor FTP |
| `MAIL` | Host | 192.123.10.30 | servidor de correo |
| `SRV_DMZ` | Host | 192.123.10.10, .20, .30 | administración SSH |
| `AGENTES_WAZUH` | Host | 192.123.10.10, 192.123.10.20 | los 2 servidores a monitorear |
| `REDES_INTERNAS` | Network | 192.123.10.0/24, 192.123.20.0/24, 192.123.30.0/24, 192.123.40.0/24, 192.123.41.0/24, 192.123.42.0/24, 192.123.99.0/24 | usado **negado** para "solo Internet" |
| `P_WAZUH_AGENT` | Port | 1514, 1515 | agente → manager |
| `P_MAIL_CLIENTE` | Port | 143, 465, 587 | buzón y envío autenticado |

## 2. Matriz de reglas

### 2.1 LAN / GESTIÓN — `vtnet4` (192.123.99.0/24) · origen: Kali

> La *Anti-Lockout* del sistema va de primera y **no se toca**.

| # | Acción | Proto | Origen | Destino | Puerto | Descripción |
|---|---|---|---|---|---|---|
| LAN-1 | pass | TCP | `KALI` | `WAZUH_DASHBOARD` | 443 | Panel del SIEM |
| LAN-2 | pass | TCP | `KALI` | `WAZUH_MANAGER` | 55000 | API Wazuh (registro alterno de agentes) |
| LAN-3 | pass | TCP | `KALI` | `SRV_DMZ`, `DB` | 22 | Administración SSH de los servidores |
| LAN-4 | pass | ICMP (echo request) | `KALI` | `REDES_INTERNAS` | — | Diagnóstico/verificación (Fase 4) |
| LAN-5 | **block + log** | any | any | any | any | Deny-all explícito **con log** |

- LAN-4 es solo *echo request* y solo desde el host de gestión: permite `ping`/`traceroute` para
  la validación sin abrir nada más.
- LAN-5 no cambia el comportamiento (ya hay deny implícito) pero **deja registro**, y las reglas
  WAN ya reenvían syslog 514 a `WAZUH_NODES` → el SIEM ve también lo denegado.

**Temporal (quitar al cerrar el lab):** para inventariar las VLAN HIDDEN, una regla
`pass TCP KALI → 192.123.41.0/24, 192.123.42.0/24 : any` con descripción
`TEMPORAL - inventario VLAN HIDDEN (eliminar)`. Si el escaneo no muestra nada que participe
en un flujo de negocio, se borra y esas VLAN quedan en deny total.

### 2.2 OPT1 / DMZ — `vtnet1` (192.123.10.0/24) · origen: servidores DMZ

| # | Acción | Proto | Origen | Destino | Puerto | Descripción |
|---|---|---|---|---|---|---|
| DMZ-1 | pass | TCP | `WEB` | `DB` | 3306 | Portal académico → MySQL (**única** vía a la BD) |
| DMZ-2 | pass | TCP | `AGENTES_WAZUH` | `WAZUH_MANAGER` | `P_WAZUH_AGENT` | Agentes Wazuh → SIEM (1515 registro, 1514 eventos) |
| DMZ-3 | pass | TCP/UDP | `AGENTES_WAZUH` | 192.123.10.1 | 53 | DNS contra el resolver de pfSense |
| DMZ-4 | pass | TCP | `AGENTES_WAZUH` | **!** `REDES_INTERNAS` | 80, 443 | Descarga de paquetes/fuentes para compilar el agente (Fase 3) |
| DMZ-5 | pass | TCP | `MAIL` | **!** `REDES_INTERNAS` | 25 | Correo saliente a Internet *(solo si el escenario lo requiere)* |
| DMZ-6 | **block + log** | any | any | any | any | Deny-all explícito con log |

- **DMZ-1 es la regla clave de confidencialidad:** la BD solo acepta a la aplicación web.
  Ni los clientes ni el resto de la DMZ llegan al 3306 → se mantiene la separación DMZ/INTERNA.
- **DMZ-4 usa el destino negado** (`Destination: not REDES_INTERNAS`): la DMZ sale a Internet
  pero **no puede pivotar** hacia INTERNA, OTHER, gestión ni las VLAN. Es la diferencia entre
  "dar Internet" y "abrir la DMZ hacia dentro".
- DMZ-4 solo se justifica mientras se compila el agente (Alpine/musl). Si se prefiere cero salida,
  la alternativa es bajar el tarball y las dependencias con `scp` desde Kali y luego borrar la regla.
- Requiere NAT de salida activo: comprobar **Firewall → NAT → Outbound** en modo automático.

### 2.3 OPT3 / OTHER — `vtnet3` (192.123.30.0/24) · origen: clientes

| # | Acción | Proto | Origen | Destino | Puerto | Descripción |
|---|---|---|---|---|---|---|
| OTH-1 | pass | TCP | `OTHER` | `WEB` | 80 (443 a futuro) | Portal académico |
| OTH-2 | pass | TCP | `OTHER` | `MAIL` | `P_MAIL_CLIENTE` | Correo: IMAP 143, submission 587/465 |
| OTH-3 | pass | TCP | `OTHER` | `FTP_SRV` | 21 | Canal de control FTP |
| OTH-4 | pass | TCP | `OTHER` | `FTP_SRV` | 50000–50100 | Canal de datos FTP **pasivo** |
| OTH-5 | **block + log** | any | any | any | any | Deny-all explícito con log |

- **No se abre el 25 a los clientes:** el 25 es transporte entre servidores de correo; el cliente
  envía por *submission* autenticado (587/465). Es un ejemplo directo de mínimo privilegio.
- **No hay regla OTHER → DB.** El acceso a datos pasa siempre por la aplicación web.
- OTH-4 exige fijar el rango pasivo en el servidor (`/etc/vsftpd.conf`):
  `pasv_enable=YES`, `pasv_min_port=50000`, `pasv_max_port=50100`, y reiniciar vsftpd.
  Sin eso vsftpd negocia un puerto aleatorio y el `ls`/transferencia se queda colgado
  aunque el 21 sí conecte (síntoma típico: login OK, directorio vacío).

### 2.4 OPT2 / INTERNA — `vtnet2` (192.123.20.0/24)

**Sin reglas de paso** + `block + log` explícito. La BD y los nodos Wazuh no inician conexiones
hacia otras zonas: todo su tráfico legítimo es *respuesta* a sesiones ya permitidas (stateful).
Es la zona más protegida porque guarda los datos personales y financieros del caso Aura University.

*Opcional y justificable:* `pass TCP WAZUH_NODES → ! REDES_INTERNAS : 443` si se quiere que el
manager actualice reglas/CTI desde Internet.

### 2.5 OPT4 / HIDDEN y VLAN41_SERV / VLAN42_LEGACY — **restaurar lo del Lab 6**

Ya no hace falta inventariar: el **Lab 6** mapeó este segmento y construyó aquí la VPN y las VLAN.
El borrado del practicante también se llevó **la regla de la pestaña OpenVPN**, así que hoy el
trabajo del Lab 6 está inoperante (verificado 29/10: `tun0` arriba y la ruta a `192.123.40.0/24`
presente, pero `.40.1/.4/.189/.231` no responden ni a ICMP ni a TCP 80, y el `curl` devuelve
cuerpo vacío en vez del `f24c1e10…` documentado en el Lab 6).

Qué hay en HIDDEN (`192.123.40.0/24`, según `Lab6/`):

| Host | Rol | Puertos | Nota |
|---|---|---|---|
| 192.123.40.1 | gateway pfSense | 53 (Unbound), 80, 443 | resolver DNS de la zona |
| 192.123.40.4 | web | 80 | nginx 1.31.3, → VLAN 41 |
| 192.123.40.189 | web | 80 | nginx 1.31.3, → VLAN 41 |
| 192.123.40.231 | web | 80 | nginx 1.31.3, → VLAN 42 (legacy) |

Los tres sirven contenido idéntico y **nginx 1.31.3 arrastra 3 CVE** (corregidos en 1.31.7 / 1.30.6).

**Pestaña OpenVPN** (restaurar la regla del Lab 6, es la que da acceso al analista):

| # | Acción | Proto | Origen | Destino | Puerto | Descripción |
|---|---|---|---|---|---|---|
| VPN-1 | pass | any | 10.8.0.0/24 | `HIDDEN_NETS` | any | Analista por túnel → solo HIDDEN |

Crear el alias `HIDDEN_NETS` = `192.123.40.0/24, 192.123.41.0/24, 192.123.42.0/24` (el Lab 6 lo
dejó propuesto en su Tabla 12: hoy la regla solo cubría `.40.0/24` y al migrar los hosts se rompía).

**VLAN41_SERV** y **VLAN42_LEGACY** (restaurar, corrigiendo el fallo del Lab 6):

| Interfaz | # | Acción | Origen | Destino | Puerto | Descripción |
|---|---|---|---|---|---|---|
| VLAN41 | 1 | block | VLAN41 net | VLAN42 net | any | Servicios no inicia hacia legacy |
| VLAN41 | 2 | pass TCP/UDP | VLAN41 net | **This Firewall** | 53 | DNS |
| VLAN41 | 3 | pass TCP | VLAN41 net | **!** `REDES_INTERNAS` | 80, 443 | Salida controlada a Internet |
| VLAN41 | 4 | **block + log** | any | any | any | Deny-all explícito |
| VLAN42 | 1 | block | VLAN42 net | VLAN41 net | any | Legacy aislado de servicios |
| VLAN42 | 2 | pass TCP/UDP | VLAN42 net | **This Firewall** | 53 | Solo DNS |
| VLAN42 | 3 | **block + log** | any | any | any | Deny-all explícito |

> **Corrección al diseño del Lab 6:** su regla VLAN41 nº2 era `Permitir TCP/UDP → Cualquiera`,
> un *allow any* de salida que dejaba a la zona de servicios alcanzar DMZ, INTERNA (la BD) y
> gestión. Ellos mismos lo listan como riesgo R3. Aquí se sustituye por DNS + salida a Internet
> con destino negado, que es lo que la zona realmente necesita.

> **Ojo con el destino "Firewall":** debe ser **This Firewall (self)**, no el alias `FIREWALL`
> (= `10.10.20.63`, la IP de WAN). El cliente resuelve contra su gateway (`192.123.41.1` /
> `192.123.42.1`), así que con el alias la regla no hace match y el DNS falla.

**OPT4** (red nativa `192.123.40.0/24`, donde los hosts siguen sin etiquetar): sin reglas de paso
+ `block + log`. El acceso legítimo entra por la VPN (VPN-1). Mientras los hosts no migren a las
VLAN, las reglas de VLAN41/42 no filtran nada real — es deuda del Lab 6, no un error nuestro,
pero hay que decirlo en el informe en vez de dar la contención por hecha.

### 2.6 WAN — **no tocar**

Conserva: OpenVPN 1194, NAT SSH 22 / RDP 3389 → `KALI`, syslog 514 → `WAZUH_NODES`,
block bogons. Son las reglas de gestión que el practicante no borró.

## 3. Orden de aplicación (y por qué)

1. **LAN primero.** Sin LAN-1/3/4 no hay forma de ver el panel ni de verificar nada.
2. **DMZ** (DMZ-1 a DMZ-4) → habilita BD y la Fase 3 (agentes).
3. **OTHER** → restituye el servicio a los usuarios.
4. **Deny-all con log** en cada interfaz, al final de cada lista.
5. Verificar después de **cada** bloque, no al final.

En cada cambio: **Save** y luego **Apply Changes** (la barra azul arriba).

## 4. Verificación (lo que se corre desde Kali)

```bash
# gestión
ping -c2 192.123.10.10 && ping -c2 192.123.20.10
curl -k -I https://192.123.20.42        # dashboard
# debe FALLAR (comprueba el mínimo privilegio)
nc -zvw2 192.123.20.10 3306             # Kali NO debe entrar a la BD
nc -zvw2 192.123.10.10 9000             # php-fpm cerrado
```

Desde el web (`192.123.10.10`): `nc -zvw2 192.123.20.10 3306` → **abierto**;
`nc -zvw2 192.123.30.10 22` → **cerrado** (no pivota).
Desde un cliente OTHER: `curl -I http://192.123.10.10`, `nc -zvw2 192.123.10.30 587`,
`nc -zvw2 192.123.10.30 25` → este último **debe fallar**.

## 5. Capturas para el informe

- 📸 **F2-1** Firewall → Aliases, con los aliases nuevos creados.
- 📸 **F2-2** Firewall → Rules → **LAN** con las reglas LAN-1…LAN-5 aplicadas.
- 📸 **F2-3** Firewall → Rules → **OPT1/DMZ** (se ve el `!` del destino negado en DMZ-4).
- 📸 **F2-4** Firewall → Rules → **OPT3/OTHER**.
- 📸 **F2-5** Firewall → Rules → **OPT2/INTERNA** (solo deny-all con log).
- 📸 **F2-6** Status → System Logs → Firewall, mostrando *pass* de los flujos buenos y *block*
  de un intento denegado (p. ej. el `nc` a 3306 desde Kali). Es la evidencia de mínimo privilegio.
- 📸 **F2-7** Salidas de `ping`/`curl`/`nc` antes vs. después (`~/lab7/verificacion/`).
