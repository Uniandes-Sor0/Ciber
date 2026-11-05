# Revisión del diseño — Lab 6 (segmento HIDDEN, VPN y VLANs)

Revisado: `Lab6_entrega 2.zip` → `Lab6Ciber.pdf`, los `.nmap` de `lab6/` y los tres diagramas.
Autoras: Mariana Cediel, Valeria Martínez (Grupo 3).

## Veredicto corto

El diseño es sólido y está bien sustentado en evidencia. Tiene **un fallo de fondo** (la regla
"permitir hacia cualquiera" de la VLAN 41), **dos imprecisiones técnicas** que un evaluador puede
picar, y **una afirmación en presente de algo que todavía no surte efecto**. Nada de eso exige
rehacer el laboratorio; son correcciones de redacción y una regla.

## Lo que está bien

- **Los criterios de división están justificados con datos propios**, no inventados: uptime
  (39 días sin reiniciar vs. 7.6 y 20.4) como señal de falta de parcheo. Que los tres servidores
  sirvan contenido idéntico (mismo md5, mismo ETag) es lo que permite mover `.231` sin cortar
  servicio — ese razonamiento es el punto más fuerte del informe.
- **La VLAN 42 está bien contenida:** bloqueo explícito hacia VLAN 41 *y* solo DNS. Y el orden de
  reglas es correcto (el `block` antes del `permit`), que es donde la gente se equivoca en pfSense.
- **La VPN está bien montada y, sobre todo, bien verificada:** autenticación mutua con CA interna,
  TLS 1.3, AES-256-GCM, sin redirigir el gateway, y la restricción al segmento comprobada con
  **pruebas negativas** (`192.123.41.1` y `.42.1` al 100% de pérdida). Demostrar lo que *no* pasa
  vale más que demostrar lo que sí.
- **La Tabla 12 es honesta** sobre lo implementado vs. lo propuesto. Eso juega a favor.

## Fallos a corregir

### 1. La regla `VLAN41_SERV → Cualquiera` rompe el mínimo privilegio *(el importante)*

La Tabla 10 lista como regla de diseño: `Permitir TCP y UDP · VLAN41_SERV (red) → Cualquiera`.
Eso es un **allow-any de salida**: la zona de servicios puede iniciar tráfico hacia la DMZ, hacia
INTERNA (donde vive la base de datos con los datos personales del caso) y hacia la red de gestión.

Choca de frente con la frase del resumen, "VLAN 41 y 42 **aisladas entre sí**": lo están entre
ellas, pero la 41 queda abierta hacia *todo lo demás*. Ustedes lo detectan y lo ponen como riesgo
residual **R3**, pero sigue figurando en la tabla de reglas como si fuera el diseño querido.

**Cambio concreto:** sustituir esa regla por lo que la zona realmente necesita —
DNS (53) contra el firewall y, si hace falta salir, 80/443 con **destino negado** sobre un alias de
las redes internas. Así sale a Internet pero no puede pivotar hacia dentro. En el informe, bajarlo
de "riesgo residual" a "corregido", que puntúa más.

### 2. "Firewall" como destino de la regla DNS es ambiguo — y puede no funcionar

La Tabla 10 pone destino `Firewall, puerto 53`. En pfSense hay que usar **`This Firewall (self)`**.
Si se usó el alias existente `FIREWALL`, ese alias vale `10.10.20.63`, que es **la IP de WAN**:
el cliente de la VLAN 42 resuelve contra su gateway (`192.123.42.1`), así que la regla no haría
match y el DNS fallaría pese a estar "permitido". Vale la pena mirar la Figura 40 y confirmar
cuál de los dos está puesto.

### 3. La sección 4.6 habla en presente de una contención que aún no existe

"Un equipo comprometido en la zona heredada **no puede** iniciar comunicación con los servicios".
Hoy no es cierto: los tres hosts siguen en `192.123.40.0/24` **sin etiquetar** (lo dice la propia
Tabla 12), así que las reglas de VLAN41/42 no se aplican a ningún host real, y OPT4 —donde el
tráfico sí pasa— no fue auditada (sección 1.3). Las VLAN son, por ahora, cascarones correctos
pero vacíos.

**Cambio:** pasar 4.6 a condicional ("una vez migrados los hosts, un equipo comprometido…").
Es un cambio de dos palabras que evita que el evaluador lo lea como una afirmación falsa.

### 4. "Libre entre pares" no es una política, es una consecuencia de la capa 2

La Tabla 11 presenta "VLAN 41 → VLAN 41: Libre entre pares" como si fuera una decisión. El tráfico
entre `.40.4` y `.40.189` **no cruza pfSense**, así que el firewall no puede ni permitirlo ni
negarlo. Si de verdad se quiere controlar, hace falta aislamiento de puertos en el switch o
firewall de host. Conviene decirlo así: es un límite del diseño, no una elección.

### 5. Un riesgo que falta en la Tabla 13

Los tres servidores son **réplicas idénticas** del mismo sitio y la misma versión vulnerable.
Repartirlas entre dos VLAN **no reduce la superficie de ataque, solo la distribuye**: si `.231`
es explotable, `.4` y `.189` lo son igual. La mitigación real es parchear y retirar réplicas
(su R1), no segmentar. Decirlo explícitamente se adelanta a la pregunta obvia del evaluador:
"¿y qué ganaron separando máquinas que son iguales?". La respuesta buena existe —contención del
daño y gobierno del ciclo de vida—, pero hay que escribirla.

## Hallazgo nuevo (verificado hoy en la VM, 29/10)

**El borrado de reglas del Lab 7 también se llevó la regla de la pestaña OpenVPN**, así que todo
lo que construyeron en el Lab 6 está hoy inoperante:

```
tun0 10.8.0.2/24 arriba · ruta 192.123.40.0/24 via 10.8.0.1 presente
192.123.40.1    ping: X   tcp80: X
192.123.40.4    ping: X   tcp80: X
192.123.40.189  ping: X   tcp80: X
192.123.40.231  ping: X   tcp80: X
curl http://192.123.40.4/ → md5 d41d8cd98f00b204e9800998ecf8427e  (cuerpo vacío)
```

Ese `d41d8cd9…` es el md5 de la cadena vacía — es decir, no llegó nada, frente al
`f24c1e10effb95ac89026cc9decd7713` que documenta el Lab 6. El túnel levanta porque la regla de
WAN (UDP 1194) sí sobrevivió; lo que falta es la regla de la **interfaz OpenVPN**.

Evidencia: `Lab7/evidencias/diagnostico/estado_lab6_tras_borrado.txt`.

Restaurar esa regla —y las de VLAN41/42, ya corregidas según el punto 1— forma parte de la
Fase 2 del Lab 7: ver `Lab7/FASE2_reglas.md` §2.5. Es un buen gancho para el informe del Lab 7:
el incidente no solo tumbó los servicios productivos, también borró el control perimetral
construido en el laboratorio anterior.

## Nota aparte

`Lab6/LabCS_6.pdf` **no es el enunciado de este laboratorio**: es el Lab 6 de *Tecnología e
Infraestructura de Cómputo (ISIS 1311)*, sobre concurrencia en Java. El enunciado de Ciberseguridad
no está en la carpeta.
