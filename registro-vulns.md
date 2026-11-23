# Registro de Vulnerabilidades Priorizado · Gadir Logística, S.L. (Partes 3 y 4)

- **Alcance analizado (`scope.txt`):** `172.17.0.0/24` (9 equipos vivos documentados en `inventario.md`).
- **Fechas de análisis:** 10 – 20 de noviembre de 2026 (contraste final de métricas con fuentes oficiales: 23 de noviembre de 2026).
- **Metodología de caracterización y priorización:** Cruce de versiones y configuraciones reales con bases públicas de vulnerabilidades (NVD/CVE, CWE, MITRE ATT&CK), puntuación de severidad técnica (**CVSS**), probabilidad de explotación en los próximos 30 días (**EPSS**), catálogo de explotación activa de **CISA (KEV)** y contexto operativo de negocio.
- **Fuentes consultadas:**
  * NVD API 2.0 — `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>` (CVSS, CWE oficiales).
  * FIRST EPSS API — `https://api.first.org/data/v1/epss?cve=<CVE>&date=2026-11-20` (probabilidad y percentil a 20-11-2026).
  * CISA KEV — `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (catálogo `2026.11.20`, publicado el 20-11-2026; fecha de inclusión y uso en ransomware).
  * MITRE ATT&CK y CWE; boletín de OX Security sobre `CVE-2026-123158` (05-11-2026).
- **Fecha de consulta y contraste de los datos:** **23 de noviembre de 2026** (los valores EPSS corresponden al dato publicado el 20-11-2026). Los CWE propios se indican explícitamente como mapeo analítico cuando difieren del CWE oficial de NVD.
- **Restricción de compromiso:** **No se ha explotado ni probado intrusivamente ninguna vulnerabilidad.** Todas las entradas representan riesgos potenciales verificados de forma pasiva/no intrusiva, detallando explícitamente sus limitaciones.

---

## 1. Matriz de priorización del riesgo (Orden de actuación recomendado)

La priorización no se basa únicamente en la puntuación CVSS aislada, sino en la combinación de **explotabilidad real (CISA KEV + EPSS)**, **grado de certeza de la evidencia en red** e **impacto operativo en Gadir Logística**:

| Prioridad | ID | Título del hallazgo | Equipo / Servicio | CVE / CWE | CVSS | EPSS (20-11-2026) | ¿En CISA KEV? | Plazo recomendado |
| :---: | :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **1** | `VULN-01` | Ejecución remota de código (RCE) por deserialización en Apache ActiveMQ | `172.17.0.5` (`61616/tcp` OpenWire) | `CVE-2023-46604` (`CWE-502`) | **10.0** v3.1 (Crítica) | **99,992 %** | **Sí** (02-11-2023, *Ransomware: Known*) | **Inmediato (< 24 h)** |
| **2** | `VULN-02` | Lectura arbitraria de archivos vía Jenkins CLI | `172.17.0.6` (`8080/tcp` Jenkins `2.441`) | `CVE-2024-23897` (`CWE-22`/`CWE-27`) | **9.8** v3.1 (Crítica) | **99,999 %** | **Sí** (19-08-2024, *Ransomware: Known*) | **Inmediato (< 24-48 h)** |
| **3** | `VULN-03` | Lectura/inclusión de archivos vía conector AJP (*Ghostcat*) en Tomcat | `172.17.0.4` (`8009/tcp` AJP + `8080/tcp`) | `CVE-2020-1938` (NVD-CWE-Other) | **9.8** v3.1 (Crítica) | **99,27 %** | **Sí** (03-03-2022, *Ransomware: Unknown*) | **Inmediato (< 48 h)** |
| **4** | `VULN-04` | Exposición de hashes de autenticación RAKP en gestión fuera de banda IPMI 2.0 | `172.17.0.10` (`623/udp` `asf-rmcp`) | `CVE-2013-4786` (`CWE-255`) | **7.5** v3.0 (Alta) | **98,385 %** | No | **Urgente (< 72 h)** |
| **5** | `VULN-05` | Exposición anónima de información vía `access.txt`, enumeración de cuentas y política débil en Samba | `172.17.0.8` (`139, 445/tcp`, `myshare`) | `CWE-284`, `CWE-522`/`CWE-200`, `CWE-521` | **7.5** *(Est.)* (Alta) | N/A *(Config.)* | N/A | **Urgente (< 72 h)** |
| **6** | `VULN-06` | Posible puerta trasera en binario heredado `vsftpd 2.3.4` | `172.17.0.3` (`21/tcp` FTP) | `CVE-2011-2523` (`CWE-78` / `CWE-506`*) | **9.8** *(Cond.)* | **96,184 %** | No | **Corto plazo (1 semana)** |
| **7** | `VULN-07` | Enumeración de usuarios locales válidos en `OpenSSH 7.7` | `172.17.0.7` (`22/tcp` SSH) | `CVE-2018-15473` (`CWE-362` / `CWE-204`*) | **5.3** v3.1 (Media) | **98,675 %** | No | **Medio plazo (2-4 semanas)** |

\* Cuando una fila muestra dos CWE, el primero es el oficial de NVD y el segundo el mapeo analítico propio.

### Servicios con versión revisados sin CVE incorporado al registro

Se han contrastado también los servicios con banner identificado para los que **no se ha encontrado un CVE aplicable con la evidencia disponible**, y por eso no generan ficha: `OpenSSH 10.3p1 Debian 5` (`.1`), `OpenSSH 7.9p1 Debian 10+deb10u4` (`.4`), `OpenSSH 9.2p1 Debian 2+deb12u2/2+deb12u10` (`.6`, `.9`), `OpenSSH 9.6p1 Ubuntu 3ubuntu13.5` (`.8`), `Apache httpd 2.4.58/2.4.59/2.4.68`, `Jetty 9.4.39/10.0.18`, `Samba smbd 4`, `SimpleHTTPServer 0.6 (Python 3.11.2)`, `MQTT`, `AMQP` y `tcpwrapped` (`.5:39383`). En los paquetes Debian/Ubuntu las revisiones del mantenedor (*backports*) pueden corregir fallos sin cambiar el número de versión del banner, por lo que su inclusión sin más sería un falso positivo (ver §4).

### Justificación del orden de prioridad
1. **`VULN-01`, `VULN-02` y `VULN-03` encabezan la tabla (Prioridades 1 a 3):** Los tres fallos afectan a versiones exactas confirmadas en red (`ActiveMQ 5.15.15`, `Jenkins 2.441` y `Tomcat 9.0.30` con puerto `8009` abierto), poseen puntuaciones **CVSS críticas (9.8–10.0)**, probabilidades **EPSS superiores al 99 %** (99,992 %, 99,999 % y 99,27 %) y figuran en **CISA KEV** con explotación masiva documentada. KEV registra uso conocido en campañas de ransomware para ActiveMQ y Jenkins; para Ghostcat consta como *Unknown*.
2. **`VULN-04` (IPMI `623/udp`, Prioridad 4) y `VULN-05` (Samba `172.17.0.8`, Prioridad 5) superan a `VULN-06` (`vsftpd`, Prioridad 6):** Aunque `CVE-2011-2523` tiene un CVSS teórico de `9.8` y un EPSS del `96,184 %`, se trata de una puerta trasera condicional cuya presencia en el binario compilado no puede confirmarse sin auditoría interna. Por el contrario, `VULN-04` y `VULN-05` son **exposiciones verificadas al 100 %** en red interna: el servicio IPMI otorga control físico/hardware sobre el servidor por debajo del SO, y el servidor Samba entrega sin contraseña la lista de usuarios reales (`administrador`, `satriani7`, etc.) y un token JWT **caducado en 2024** que aun así revela correo, rol y configuración criptográfica. El orden responde, por tanto, a certeza e impacto operativo, no solo a CVSS o EPSS.

---

## 2. Fichas técnicas detalladas de vulnerabilidades

### `VULN-01` · Ejecución remota de código por deserialización en Apache ActiveMQ (`CVE-2023-46604`)

* **Prioridad:** `1 · Crítica`
* **Equipo y servicio:** `172.17.0.5` — Puerto `61616/tcp` (`Apache ActiveMQ OpenWire transport 5.15.15`), junto con `1883/tcp` (MQTT), `5672/tcp` (AMQP), `8161/tcp` (Jetty 9.4.39) y `61613/tcp` (STOMP).
* **Identificadores:** `CVE-2023-46604` | **CWE:** `CWE-502` (*Deserialization of Untrusted Data*) | **MITRE ATT&CK:** `T1190` (*Exploit Public-Facing Application*), `T1059` (*Command and Scripting Interpreter*).
* **Métricas de riesgo:**
  * **CVSS v3.1 (NVD):** `10.0 (Crítica)` — Vector oficial: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H` (el impacto de confidencialidad es **Bajo**, no Alto; la puntuación sigue siendo 10.0 por el cambio de alcance)
  * **EPSS:** `99,992 %` (percentil 99,986 %; dato de 20-11-2026, FIRST API)
  * **CISA KEV:** **Sí** (incluida el `2023-11-02`; `knownRansomwareCampaignUse: Known`).
* **Descripción técnica:** Las versiones de Apache ActiveMQ anteriores a `5.15.16` permiten a un atacante remoto que alcance el puerto OpenWire (`61616/tcp`) manipular los tipos de clases serializadas en las tramas de excepción para forzar al servidor a cargar un archivo XML remoto mediante `org.springframework.context.support.ClassPathXmlApplicationContext`, ejecutando comandos arbitrarios en el sistema sin autenticación.
* **Evidencias observadas en la red:**
  * Banner `ActiveMQ OpenWire transport 5.15.15` en `61616/tcp`.
  * Traza de excepción Java (`org.apache.activemq.transport.stomp.ProtocolException`) expuesta en `61613/tcp`.
  * Suscripción anónima permitida a tópicos internos en `1883/tcp` (`ActiveMQ/Advisory/MasterBroker`).
* **Limitaciones y verificación pendiente:** No se han enviado paquetes OpenWire maliciosos ni URLs de contexto XML en cumplimiento de las reglas de compromiso. Queda pendiente verificar en el servidor la versión exacta del paquete instalado y comprobar si existen filtros de red sobre `61616/tcp`.
* **Remediación recomendada:** Actualizar Apache ActiveMQ a una versión parcheada (`>= 5.15.16`, `5.16.7`, `5.17.6` o `5.18.3+`), restringir por cortafuegos el acceso a los puertos `61616`, `61613`, `5672`, `1883` y `8161` únicamente a los servidores de aplicaciones autorizados, y deshabilitar los protocolos de mensajería que no se utilicen.

---

### `VULN-02` · Lectura arbitraria de archivos a través de Jenkins CLI (`CVE-2024-23897`)

* **Prioridad:** `2 · Crítica`
* **Equipo y servicio:** `172.17.0.6` — Puerto `8080/tcp` (`Jenkins 2.441` sobre `Jetty 10.0.18`).
* **Identificadores:** `CVE-2024-23897` | **CWE:** `CWE-22` (*Path Traversal*) y `CWE-27` (*Path Traversal: 'dir/../../filename'*), ambos en NVD; KEV registra `CWE-27` | **MITRE ATT&CK:** `T1190` (*Exploit Public-Facing Application*), `T1005` (*Data from Local System*).
* **Métricas de riesgo:**
  * **CVSS v3.1:** `9.8 (Crítica)` — Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  * **EPSS:** `99,999 %` (percentil 99,995 %; dato de 20-11-2026, FIRST API)
  * **CISA KEV:** **Sí** (incluida el `2024-08-19`; `knownRansomwareCampaignUse: Known`).
* **Descripción técnica:** Jenkins `2.441` utiliza el analizador de argumentos `args4j` en su interfaz de línea de comandos (CLI), que expande automáticamente el prefijo `@ruta_archivo` sustituyéndolo por el contenido del fichero local del servidor. Un atacante sin credenciales puede invocar comandos CLI (`help`, `connect-node`, etc.) para leer secretos de Jenkins (`master.key`, `hudson.util.Secret`, `credentials.xml`) y comprometer todo el servidor de integración continua y sus credenciales desplegadas.
* **Evidencias observadas en la red:**
  * Cabeceras HTTP `X-Jenkins: 2.441` y `X-Hudson: 1.395` obtenidas mediante `curl -i -s http://172.17.0.6:8080/`.
  * Confirmación de funcionalidad de compilación en `/robots.txt` (`# we don't want robots to click "build" links`).
* **Limitaciones y verificación pendiente:** No se ha realizado ninguna petición al endpoint `/cli` ni se ha intentado leer ficheros internos. Queda por verificar si la interfaz CLI está habilitada en la configuración del servidor.
* **Remediación recomendada:** Actualizar Jenkins inmediatamente a la versión `2.442` o superior (o rama LTS `>= 2.426.3`), deshabilitar explícitamente el acceso CLI sobre HTTP/WebSocket si no es imprescindible y segmentar el acceso al puerto `8080/tcp`.

---

### `VULN-03` · Lectura e inclusión de archivos en Apache Tomcat vía AJP *Ghostcat* (`CVE-2020-1938`)

* **Prioridad:** `3 · Crítica`
* **Equipo y servicio:** `172.17.0.4` — Puertos `8009/tcp` (`Apache Jserv Protocol v1.3`) y `8080/tcp` (`Apache Tomcat 9.0.30`).
* **Identificadores:** `CVE-2020-1938` (*Ghostcat*) | **CWE:** `NVD-CWE-Other` en NVD (la KEV no registra CWE); `CWE-285` (*Improper Authorization*) / `CWE-98` como mapeo analítico propio | **MITRE ATT&CK:** `T1190` (*Exploit Public-Facing Application*), `T1083` (*File and Directory Discovery*).
* **Métricas de riesgo:**
  * **CVSS v3.1:** `9.8 (Crítica)` — Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  * **EPSS:** `99,27 %` (percentil 99,938 %; dato de 20-11-2026, FIRST API)
  * **CISA KEV:** **Sí** (incluida el `2022-03-03`; `knownRansomwareCampaignUse: Unknown`).
* **Descripción técnica:** En Apache Tomcat `9.0.30`, el conector binario AJP (`8009/tcp`) acepta conexiones sin secreto de autenticación por defecto. Un atacante con acceso al puerto `8009/tcp` puede manipular atributos de la petición AJP para leer cualquier archivo dentro del directorio `webapps` (incluyendo `WEB-INF/web.xml`, código JSP o ficheros de configuración con contraseñas de bases de datos) o incluir archivos arbitrarios como JSP si existe capacidad de subida.
* **Evidencias observadas en la red:**
  * Banner `Apache Tomcat/9.0.30` en `8080/tcp` con página de bienvenida por defecto intacta.
  * Puerto `8009/tcp` abierto y respondiendo al protocolo `ajp13` en toda la red `172.17.0.0/24`.
* **Limitaciones y verificación pendiente:** No se han enviado paquetes AJP manipulados para leer `WEB-INF/web.xml` ni se ha enumerado el contenido de aplicaciones desplegadas.
* **Remediación recomendada:** Actualizar Apache Tomcat a una versión mantenida (`>= 9.0.31`, preferiblemente rama `9.0.9x` o `10.1.x`). Si el conector AJP (`8009/tcp`) no se utiliza detrás de un proxy inverso Apache, **comentarlo y deshabilitarlo** en `conf/server.xml`; si es necesario, vincularlo a `127.0.0.1` y configurar un `secret` robusto (`secretRequired="true"`).

---

### `VULN-04` · Exposición de credenciales mediante fallo de diseño RAKP en IPMI 2.0 (`CVE-2013-4786`)

* **Prioridad:** `4 · Alta`
* **Equipo y servicio:** `172.17.0.10` — Puerto `623/udp` (`asf-rmcp` / IPMI 2.0), contextualizado por `80/tcp`.
* **Identificadores:** `CVE-2013-4786` | **CWE:** `CWE-255` (*Credentials Management*, oficial en NVD); `CWE-287` (*Improper Authentication*) / `CWE-326` como mapeo analítico propio | **MITRE ATT&CK:** `T1110.002` (*Password Cracking*), `T1552` (*Unsecured Credentials*).
* **Métricas de riesgo:**
  * **CVSS v3.0 (NVD):** `7.5 (Alta)` — Vector oficial: `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
  * **EPSS:** `98,385 %` (percentil 99,920 %; dato de 20-11-2026, FIRST API)
  * **CISA KEV:** No.
* **Descripción técnica:** Durante el establecimiento de sesión RMCP+ (mensaje `RAKP 2`) en IPMI 2.0, el controlador BMC envía al cliente el resumen criptográfico HMAC-SHA1/MD5 con sal de la contraseña del usuario solicitado antes de autenticar al solicitante. Esto permite capturar el hash por red y someterlo a descifrado fuera de línea sin límite de intentos, obteniendo acceso privilegiado de administración hardware (encendido/apagado, consola serie SOL y montaje remoto de medios).
* **Evidencias observadas en la red:**
  * Puerto `623/udp` confirmado en estado `open` (`asf-rmcp`) mediante escaneo UDP dirigido (`nmap -sU -p 623 -sV`).
  * Página en `http://172.17.0.10:80/` (*«CTG · IPMI bajo exposición»*) confirmando la exposición de una interfaz de gestión fuera de banda en la red general.
* **Limitaciones y verificación pendiente:** No se han iniciado sesiones RAKP para extraer hashes ni se han probado usuarios por defecto (`ADMIN`). Queda por auditar localmente si el BMC admite Cipher Suite 0.
* **Remediación recomendada:** Aislar inmediatamente la interfaz IPMI (`623/udp`) en una **VLAN de gestión dedicada** inaccesible desde la red de oficinas o servidores generales, deshabilitar IPMI sobre LAN si no es imprescindible, actualizar el firmware del BMC y establecer contraseñas robustas y únicas.

---

### `VULN-05` · Exposición anónima de token JWT (`access.txt`), enumeración de usuarios y política débil en Samba

* **Prioridad:** `5 · Alta`
* **Equipo y servicio:** `172.17.0.8` (`SAMBASERVER`) — Puertos `139/tcp`, `445/tcp` y `137/udp` (`Samba 4`, recurso compartido `myshare`).
* **Identificadores:** Hallazgo de configuración y diseño inseguro (`CWE-284` *Improper Access Control*, `CWE-200` *Exposure of Sensitive Information to an Unauthorized Actor*, `CWE-522` *Insufficiently Protected Credentials*, `CWE-521` *Weak Password Requirements*) | **MITRE ATT&CK:** `T1135`, `T1087.001`, `T1552.001`.
* **Métricas de riesgo:**
  * **CVSS v3.1 (estimación interna):** `7.5 (Alta)` — Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
  * **EPSS / CISA KEV:** No aplica (deficiencia de configuración y control de acceso, no es un CVE de binario).
* **Descripción técnica:** La configuración de Samba permite sesiones nulas anónimas (`''`/`''`) que exponen vía RPC/RID cycling el nombre de dominio `ESEEMEB.DL`, la lista completa de usuarios locales (`administrador`, `satriani7`, `usuario1`, `usuario2`, `usuario3`, `ubuntu`) y una política de contraseñas sin complejidad mínima, longitud mínima de 5 caracteres y sin bloqueo de cuenta. Además, el recurso compartido público `myshare` expone sin autenticación el archivo `access.txt` con un token JWT (`RS256`) que revela el correo `satriani7@eseemeb.dl`, el rol `user` y una clave **pública** RSA en el campo `jwk` del payload. El token está **caducado desde el 05-10-2024** (`exp: 1728163973`), por lo que constituye una fuga de información y un riesgo de Ingeniería Social / *phishing* dirigido, **no una credencial vigente**. No hay evidencia de verificación de firma defectuosa (`CWE-347`), por lo que ese CWE se ha descartado.
* **Evidencias observadas en la red:**
  * Enumeración completa con `enum4linux -a 172.17.0.8`.
  * Lectura directa del JWT mediante `smbclient //172.17.0.8/myshare -N -c "get access.txt -"`; payload decodificado con `iat: 1728160373` y `exp: 1728163973` (validez de una hora el 05-10-2024).
* **Limitaciones y verificación pendiente:** No se ha probado el token JWT ni las cuentas enumeradas contra los portales web de `172.17.0.8:80` o `172.17.0.9/login.html` ni contra los recursos privados `backup24` y `home`. El JWT está expirado, por lo que tampoco se puede usar para validar el sistema de autenticación; conviene comprobar internamente si se han emitido otros tokens con el mismo esquema y si la clave pública incrustada pertenece a una infraestructura real.
* **Remediación recomendada:** Deshabilitar el acceso anónimo (`guest ok = no`) en `myshare` y bloquear las sesiones nulas RPC (`restrict anonymous = 2` en `smb.conf`), eliminar `access.txt` de carpetas públicas, rotar/invalidar el token expuesto y revisar el esquema de emisión (la clave del `jwk` es pública, no hay clave privada que revocar), exigir firma SMB obligatoria (`server signing = mandatory`) y endurecer la política de contraseñas (mínimo 12–14 caracteres, complejidad y bloqueo tras intentos fallidos).

---

### `VULN-06` · Posible puerta trasera en el binario heredado `vsftpd 2.3.4` (`CVE-2011-2523`)

* **Prioridad:** `6 · Alta / Media condicional`
* **Equipo y servicio:** `172.17.0.3` — Puerto `21/tcp` (`vsftpd 2.3.4`).
* **Identificadores:** `CVE-2011-2523` | **CWE:** `CWE-78` (*OS Command Injection*, oficial en NVD); `CWE-506` (*Embedded Malicious Code*) / `CWE-912` como mapeo analítico propio del caso de puerta trasera | **MITRE ATT&CK:** `T1195.002` (*Compromise Software Supply Chain*), `T1059.004`.
* **Métricas de riesgo:**
  * **CVSS v3.1:** `9.8 (Crítica)` *(condicional a que el binario proceda del paquete comprometido)* — Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  * **EPSS:** `96,184 %` (percentil 99,879 %; dato de 20-11-2026, FIRST API)
  * **CISA KEV:** No.
* **Descripción técnica:** La distribución fuente de `vsftpd 2.3.4` distribuida entre el 30 de junio y el 3 de julio de 2011 fue alterada para abrir una shell remota sin autenticación en el puerto `6200/tcp` al recibir un nombre de usuario finalizado en `:)`.
* **Evidencias observadas en la red:** Banner `vsftpd 2.3.4` activo en `172.17.0.3:21/tcp` sobre un sistema Ubuntu moderno.
* **Limitaciones y verificación pendiente:** En respeto a la prohibición de activar puertas traseras o ejecutar exploits, **no se ha comprobado** si el binario instalado corresponde a la versión comprometida de 2011 o a una compilación limpia. Se requiere verificar localmente el hash SHA-256 de `/usr/sbin/vsftpd` o sustituir el servicio.
* **Remediación recomendada:** Desinstalar inmediatamente esta versión heredada de 2011, migrar la transferencia de archivos a **SFTP** sobre SSH o instalar el paquete oficial mantenido de `vsftpd` desde los repositorios de Ubuntu.

---

### `VULN-07` · Enumeración de cuentas de usuario válidas en `OpenSSH 7.7` (`CVE-2018-15473`)

* **Prioridad:** `7 · Media`
* **Equipo y servicio:** `172.17.0.7` — Puerto `22/tcp` (`OpenSSH 7.7`).
* **Identificadores:** `CVE-2018-15473` | **CWE:** `CWE-362` (*Concurrent Execution using Shared Resource with Improper Synchronization*, oficial en NVD); `CWE-204` (*Observable Response Discrepancy*) como mapeo analítico propio | **MITRE ATT&CK:** `T1087.001` (*Account Discovery: Local Account*).
* **Métricas de riesgo:**
  * **CVSS v3.1:** `5.3 (Media)` — Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
  * **EPSS:** `98,675 %` (percentil 99,925 %; dato de 20-11-2026, FIRST API)
  * **CISA KEV:** No.
* **Descripción técnica:** `OpenSSH <= 7.7` presenta una diferencia observable en el manejo de paquetes malformados de autenticación por clave pública (`SSH2_MSG_USERAUTH_REQUEST`) que permite distinguir si un nombre de usuario existe en el sistema antes de completar la autenticación.
* **Evidencias observadas en la red:** Banner `OpenSSH 7.7 (protocol 2.0)` sin sufijo de distribución en `172.17.0.7:22/tcp`.
* **Limitaciones y verificación pendiente:** No se han enviado paquetes de autenticación malformados ni diccionarios de usuarios.
* **Remediación recomendada:** Actualizar OpenSSH a una versión actual soportada (`>= 9.x`), deshabilitar la autenticación por contraseña (`PasswordAuthentication no`) y restringir el acceso al puerto `22/tcp` mediante reglas de cortafuegos.

---

## 3. Evaluación de alerta externa reciente: `CVE-2026-123158` («sshole»)

Ante la consulta urgente de Gerencia sobre la vulnerabilidad mediática **`CVE-2026-123158` (*sshole*)** (CVSS v3.1 **8.1 Alta**, vector `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`, CWE-394) se realizó el contraste técnico completo frente a los 9 equipos vivos del inventario. El boletín de OX Security se publicó el `2026-11-05`; **la inclusión en CISA KEV es el `2026-11-09`** (`knownRansomwareCampaignUse: Unknown`). **EPSS: 95,538 %** (percentil 99,871 %, dato de 20-11-2026). Fuentes: boletín OX, NVD API, FIRST EPSS API y catálogo KEV `2026.11.20`, consultados el 23-11-2026:

* **Condición técnica del fallo:** `CVE-2026-123158` permite eludir la autenticación SSH mediante contraseñas de entre `257` y `1 024` bytes **exclusivamente en sistemas Linux compilados contra `musl libc` y sin PAM** (como **Alpine Linux**, OpenWrt o sistemas embebidos), donde `crypt()` devuelve `*` ante entradas sobredimensionadas y coincide con el marcador `*` de cuentas sin contraseña en `/etc/shadow`.
* **Impacto real en Gadir Logística (`172.17.0.0/24`):**
  * **No vulnerables (8 de 9 equipos):** Tres equipos (`172.17.0.3`, `172.17.0.5`, `172.17.0.10`) no ejecutan SSH y cinco servidores (`172.17.0.1`, `172.17.0.4`, `172.17.0.6`, `172.17.0.8`, `172.17.0.9`) funcionan sobre **Debian y Ubuntu** (`glibc` + PAM), inmunes por arquitectura a este fallo.
  * **Verificación puntual recomendada (1 de 9 equipos):** El servidor `172.17.0.7` expone `OpenSSH 7.7` sin etiqueta de distribución en el banner. Como limitación inherente a una auditoría externa no intrusiva, no puede confirmarse desde red si corre sobre `glibc` o `musl`, por lo que se recomienda comprobar localmente `/etc/os-release` y asegurar `PasswordAuthentication no`.

---

## 4. Falsos positivos descartados

Se han filtrado y descartado del registro:
1. **Parches retroportados (*backported*) de Debian/Ubuntu:** Servicios como `OpenSSH 9.2p1 Debian 2+deb12u2` (`172.17.0.6`), `OpenSSH 9.6p1 Ubuntu 3ubuntu13.5` (`172.17.0.8`), `OpenSSH 9.2p1 Debian 2+deb12u10` (`172.17.0.9`) y los servidores web `Apache 2.4.58/2.4.59/2.4.68` con páginas estáticas por defecto incorporan las correcciones de seguridad mediante revisiones de paquete del mantenedor de la distribución (como el parche de *regreSSHion* `CVE-2024-6387`).
2. **Banners genéricos sin versión menor:** `Samba smbd 4` (`172.17.0.8`) sobre Ubuntu moderno no es vulnerable a fallos históricos de ramas antiguas como *SambaCry* (`CVE-2017-7494`).
3. **Observaciones menores de endurecimiento:** Certificado TLS autofirmado caducado (`CN=example.com`) en `172.17.0.5:443` y método `TRACE` habilitado en `172.17.0.5:61614`, recomendados como mejora general pero sin impacto crítico aislado.