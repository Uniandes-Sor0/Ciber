# Lab 7 — Fase 3: Agentes Wazuh en DMZ (web + ftp)

Objetivo: instalar el **agente Wazuh 4.12** en el **web `192.123.10.10`** y en el **ftp
`192.123.10.20`** para que reporten al **Manager `192.123.20.40`** y aparezcan `active` en el
dashboard. Vale 25 % (web) + 10 % (ftp) de la nota.

---

## ✅ ESTADO FINAL (06/11/2026) — FASE 3 COMPLETA

**Los dos agentes quedaron `connected` reportando al Manager `192.123.20.40`:**

| Agente | Host | Método | Versión | Evidencia de conexión |
|---|---|---|---|---|
| web | 192.123.10.10 (Alpine/musl) | **compilado desde fuente** | 4.12.0 | log `Connected to the server ([192.123.20.40]:1514/tcp)` |
| ftp | 192.123.10.20 (Debian 11)   | **paquete .deb** (id agente 005) | 4.12.0-1 | `agentd.state` → `status='connected'` + `last_ack` del Manager |

Acceso de sistema a la DMZ (confirmado): **web y ftp = usuario `root`** (clave en el archivo de
credenciales fuera del repo `Downloads/Lab7_credenciales_DMZ.txt`; **NO** es `alice`, que es usuario
de la app web). Las reglas de Fase 2 DMZ-1..5 quedaron aplicadas en pfSense.

### Troubleshooting real (todo esto va al informe)
1. **DNS de la DMZ roto → se arregló en pfSense.** Las cajas son contenedores Docker; `apk`/`apt`
   no resolvían (`SERVFAIL` desde `192.123.10.1`). Causa: el DNS Resolver (Unbound) de pfSense no
   resolvía externo. **Fix:** Services → DNS Resolver → **Enable Forwarding Mode** + DNS `1.1.1.1`
   en System→General. En cada contenedor: `echo "nameserver 192.123.10.1" > /etc/resolv.conf`.
   La salida a Internet (NAT, `nc 1.1.1.1 443`=open) sí funcionaba; era solo resolución de nombres.
2. **web (Alpine):** compilación según `WazuhAlpine.pdf` sin incidentes graves. Único tropiezo: el
   shim `musl_compat.c` necesita `'\\'` (doble barra) en `glob_pattern_p` — copiar/pegar del PDF
   mete una sola barra y rompe el `.o`. Los scripts `Lab7/scripts/{alpine_headers.sh,musl_compat.c}`
   ya traen la versión correcta. Resultado: `nm -D libwazuhext.so` con `getcontext/setcontext/
   makecontext` = `T`, y "Done building agent".
3. **ftp (Debian 11, contenedor sin systemd):**
   - `systemctl` no sirve (no hay systemd en el contenedor) → arranque con `/var/ossec/bin/wazuh-control start`.
   - `apt` roto: `bullseye-security` da **404** en `python3`/`libsqlite3` (snapshot del mirror
     purgado). `curl`/`gpg` tampoco estaban.
   - **Solución:** repo Wazuh con `deb [trusted=yes]` (salta la firma GPG, sin `curl`/`gpg`);
     instalar la versión **4.12.0-1** fija (`apt-get install wazuh-agent=4.12.0-1`) — la `stable`
     ya va por 4.14.10, que depende de `python3` (el que da 404) y además no empata con el Manager 4.12.
   - El `.deb` 4.12 igual arrastra `lsb-release`→`python3`. Como el agente **no** necesita
     `lsb-release` para correr: `dpkg -i` (desempaca) + **stub de `/usr/bin/lsb_release`** +
     `WAZUH_MANAGER="192.123.20.40" dpkg --configure --force-depends wazuh-agent` (crea el usuario
     `wazuh` y escribe el `<address>` del Manager). Auto-enrolló solo en 1515 (llave `005`).
4. **Pendiente lado-Manager (no bloquea la nota, pero anotarlo):** el **dashboard** no escucha en
   `192.123.20.42` (443 y 5601 cerrados) y la **API 55000** rechaza todas las credenciales del lab
   (las del dashboard y los usuarios API por defecto; detalle fuera del repo). Sin SSH al Manager no podemos levantarlos
   → la verificación se hizo **agent-side** (logs + `agentd.state`). Pedir al monitor el dashboard
   o la clave de la API para la captura del panel con ambos agentes `active`.

---

## 0. Estado y lo que cambió al tener credenciales de DMZ

Confirmado hoy (06/11) desde Kali con las reglas de Fase 2 (bloque LAN) ya aplicadas:

| Host | SSH 22 | Sistema (banner) | Camino del agente |
|---|---|---|---|
| web `192.123.10.10` | ✅ abierto · `OpenSSH_9.9` | **Alpine + musl** (nginx 1.26.3) | **compilar** (guía `WazuhAlpine.pdf`) |
| ftp `192.123.10.20` | ✅ abierto · `OpenSSH_8.4p1 Debian-5+deb11u7` | **Debian 11 (glibc)** | **paquete .deb oficial** (mucho más simple) |
| db `192.123.20.10` | — | `OpenSSH_9.2p1 Debian-2+deb12u10` | no es parte de Fase 3 |

> **Hallazgo que simplifica el 10 %:** el ftp **no es Alpine**, es Debian 11. No hay que compilar
> nada ahí: se instala el `.deb` oficial de Wazuh. Toda la gimnasia musl de `WazuhAlpine.pdf`
> aplica **solo al web**.

**Bloqueantes que siguen abiertos (hay que resolverlos antes o durante):**
1. **1514/1515 del Manager están CERRADOS desde Kali** (solo responde 55000). Eso es correcto por
   diseño (esos puertos son para los agentes de la DMZ, no para gestión), **pero** la regla
   **DMZ-2** (`AGENTES_WAZUH → WAZUH_MANAGER : 1514,1515`) todavía **no está aplicada**. Sin ella
   el registro (Paso 9) y la conexión (Paso 10) fallan con *timeout*. → aplicar DMZ-2 primero.
2. **Salida a Internet de la DMZ (DMZ-4)** tampoco está aplicada. El web la necesita para
   `apk add`, `git clone` y `make deps`. Alternativa sin Internet: subir todo por `scp` desde Kali.
3. El **dashboard no escucha en `.20.42:443`** (cruza el firewall, nada atiende). No bloquea la
   Fase 3 (el agente habla con el **Manager**, no con el dashboard), pero sí la evidencia visual.
   Para ver los agentes `active` hay que levantar/encontrar el puerto real del panel.

## 1. Orden recomendado

1. **Aplicar en pfSense el bloque DMZ** de Fase 2 (al menos DMZ-2 y DMZ-4). Ver `FASE2_reglas.md` §2.2.
2. **ftp Debian (fácil, 10 %)** — instalar el `.deb`, registrar, verificar. Calienta el flujo
   completo contra el Manager con la caja sencilla.
3. **web Alpine (difícil, 25 %)** — compilar siguiendo `WazuhAlpine.pdf` con los scripts de
   `Lab7/scripts/`.
4. Verificar ambos `active` en el Manager y capturar.

## 2. ftp `192.123.10.20` (Debian 11) — agente por paquete

Desde Kali: `ssh USUARIO@192.123.10.20` (credenciales de DMZ). Luego, **como root** (`sudo -i`):

```bash
# repo oficial de Wazuh
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
  chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update

# instalar el agente apuntando al Manager
WAZUH_MANAGER="192.123.20.40" apt-get install -y wazuh-agent

# arrancar
systemctl daemon-reload
systemctl enable --now wazuh-agent
systemctl status wazuh-agent --no-pager | head -15
tail -20 /var/ossec/logs/ossec.log
```

> Si la DMZ **no** tiene salida a Internet (DMZ-4 sin aplicar), bajar el `.deb` en Kali
> (`wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.12.0-1_amd64.deb`),
> subirlo con `scp` al ftp y:
> `WAZUH_MANAGER="192.123.20.40" dpkg -i wazuh-agent_4.12.0-1_amd64.deb`.

📸 **CAPTURA** — `systemctl status wazuh-agent` en el ftp mostrando `active (running)`, y las
últimas líneas de `ossec.log` con `Connected to the server`.

## 3. web `192.123.10.10` (Alpine + musl) — agente compilado

Scripts preparados en `Lab7/scripts/` para evitar el copy-paste del PDF (que trae comillas
tipográficas que rompen los heredocs en silencio — la propia guía lo advierte):

- `alpine_headers.sh` — Paso 2: crea las 5 cabeceras de compatibilidad y las valida.
- `musl_compat.c` — Paso 5.3: el shim glibc→musl ya con comillas correctas.

Subirlos desde la PC (o desde Kali) al web:

```bash
# desde la PC, con el puente de Kali:
scp Lab7/scripts/alpine_headers.sh Lab7/scripts/musl_compat.c kali7:/tmp/
# desde Kali:
scp /tmp/alpine_headers.sh /tmp/musl_compat.c USUARIO@192.123.10.10:/tmp/
```

En el web, **como root**:

```bash
# Paso 1 - paquetes de desarrollo
apk update && apk add --no-cache \
  build-base cmake git curl unzip tar automake autoconf libtool pkgconfig \
  linux-headers musl-dev bsd-compat-headers gettext-dev \
  clang llvm zlib-dev elfutils-dev

# Paso 2 - clonar Wazuh y crear cabeceras (usar el script, NO pegar del PDF)
rm -rf /root/wazuh
git clone --depth 1 --branch v4.12.0 https://github.com/wazuh/wazuh.git /root/wazuh
sh /tmp/alpine_headers.sh      # crea /usr/include/linux/*.h y valida

# Paso 3 - dependencias externas (fuente, para musl)
cd /root/wazuh/src
make deps TARGET=agent EXTERNAL_SRC_ONLY=yes
# Paso 3.1 - excepcion libbpf-bootstrap: usar el PRECOMPILADO
rm -rf /root/wazuh/src/external/libbpf-bootstrap
make deps TARGET=agent

# Paso 4 - parche OpenSSL (bug strerror_r en musl)
sed -i 's/#elif defined(_GNU_SOURCE)/#elif defined(_GNU_SOURCE) \&\& defined(__GLIBC__)/' \
  /root/wazuh/src/external/openssl/crypto/o_str.c

# Paso 5.1 - libexecinfo (backtrace)
git clone https://github.com/ronchaine/libexecinfo.git /root/libexecinfo
cd /root/libexecinfo && make && \
  cp execinfo.h /usr/include/ && cp libexecinfo.a /usr/lib/ && \
  cp libexecinfo.so.1 /usr/lib/ && ln -sf /usr/lib/libexecinfo.so.1 /usr/lib/libexecinfo.so

# Paso 5.2 - libucontext (getcontext/setcontext/makecontext)
git clone https://github.com/kaniini/libucontext.git /root/libucontext
cd /root/libucontext && make ARCH=x86_64 && make ARCH=x86_64 DESTDIR=/usr install
# si quedaron en /usr/usr/* moverlos:
[ -d /usr/usr ] && { cp -a /usr/usr/lib/. /usr/lib/; cp -a /usr/usr/include/. /usr/include/; rm -rf /usr/usr; }

# Paso 5.3 - shim de compatibilidad (usar el .c preparado)
mkdir -p /root/wazuh/src/external/musl_compat
cp /tmp/musl_compat.c /root/wazuh/src/external/musl_compat/musl_compat.c
gcc -c -fPIC /root/wazuh/src/external/musl_compat/musl_compat.c \
  -o /root/wazuh/src/external/musl_compat/musl_compat.o

# Paso 6 - inyectar el shim en el Makefile (en OSSEC_LIBS, que es la variable real)
cd /root/wazuh/src
git checkout Makefile
cat << 'EOF' >> Makefile
# Inyeccion de compatibilidad musl
OSSEC_LIBS += /root/wazuh/src/external/musl_compat/musl_compat.o /usr/lib/libucontext.a /usr/lib/libexecinfo.a
EOF
rm -f libwazuhext.so
make TARGET=agent CFLAGS="-D_GNU_SOURCE -I/usr/include -include /usr/include/linux/bpf_insn.h -Wno-error=incompatible-pointer-types" libwazuhext.so
nm -D libwazuhext.so | grep -E 'getcontext|setcontext|makecontext'   # deben salir como 'T'

# Paso 7 - compilacion completa del agente (CMAKE_OPTS para los sub-builds)
make TARGET=agent \
  CFLAGS="-D_GNU_SOURCE -I/usr/include -include /usr/include/linux/bpf_insn.h -Wno-error=incompatible-pointer-types" \
  CMAKE_OPTS='-DCMAKE_EXE_LINKER_FLAGS="/root/wazuh/src/external/musl_compat/musl_compat.o -Wl,--whole-archive /usr/lib/libexecinfo.a /usr/lib/libucontext.a -Wl,--no-whole-archive" -DCMAKE_SHARED_LINKER_FLAGS="/root/wazuh/src/external/musl_compat/musl_compat.o -Wl,--whole-archive /usr/lib/libexecinfo.a /usr/lib/libucontext.a -Wl,--no-whole-archive"'

# Paso 8 - instalar (elegir 'agent', destino /var/ossec por defecto)
cd /root/wazuh && ./install.sh

# Paso 9 - registrar contra el Manager
/var/ossec/bin/agent-auth -m 192.123.20.40
# si falla: apk add --no-cache netcat-openbsd && nc -zv 192.123.20.40 1515
#   timeout -> falta la regla DMZ-2 en pfSense; refused -> wazuh-authd caido en el manager
#   plan B por API (puerto 55000) en WazuhAlpine.pdf seccion 6.3

# Paso 10 - arrancar. Antes aplicar el fix de BusyBox ps (seccion 6.4), si no el
#   agente queda 'never connected':
sed -i 's/ps -p \$j > \/dev\/null 2>&1/kill -0 $j > \/dev\/null 2>\&1/' /var/ossec/bin/wazuh-control
sed -i 's/ps -p \${pid} > \/dev\/null 2>&1/kill -0 ${pid} > \/dev\/null 2>\&1/' /var/ossec/bin/wazuh-control
/var/ossec/bin/wazuh-control stop
rm -f /var/ossec/var/run/*.pid
/var/ossec/bin/wazuh-control start
ps aux | grep wazuh
tail -50 /var/ossec/logs/ossec.log
```

📸 **CAPTURA** — (a) `nm -D libwazuhext.so | grep ...context` con las `T`; (b) la salida final del
Paso 7 (agente compilado); (c) `ps aux | grep wazuh` con los 5-6 demonios arriba; (d) el agente
`active` en el Manager/dashboard.

## 4. Puntos de atención (van al informe)

- **ftp Debian ≠ web Alpine:** documentar que por eso el ftp es trivial (paquete) y el web exige
  recompilar — es un hallazgo de reconocimiento, no un descuido.
- **DMZ-2 y DMZ-4** son la precondición de red de toda esta fase: sin ellas el agente compila pero
  nunca conecta. Enlaza con el diseño de mínimo privilegio de la Fase 2.
- **Fix del `ps` de BusyBox (Paso 6.4):** aplicarlo *antes* del primer arranque en el web, no
  después del síntoma `never connected`.
- Verificación recomendada antes de compilar: `nc -zv 192.123.20.40 1515` desde el web, para no
  perder 30 min compilando y descubrir al final que el firewall bloquea.
