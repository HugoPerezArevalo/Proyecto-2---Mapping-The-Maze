# Inventario de Red · Gadir Logística, S.L. (Partes 1 y 2)

- **Alcance autorizado (`scope.txt`):** `172.17.0.0/24`
- **Fechas de ejecución:** 10, 18 y 20 de noviembre de 2026
- **Metodología:** Descubrimiento ARP/Ping (`nmap -sn -PR`), escaneo completo TCP (`-p-`), escaneo UDP (`--top-ports 50` y dirigido `-p 623`), detección de versiones/scripts seguros (`-sV -sC --script="default and not (intrusive or exploit or dos or brute or malware)" -T3`), enumeración SMB anónima (`enum4linux -a`, `smbclient -N`) e inspección HTTP sin credenciales (`curl -i -s`).
- **Resultado global:** 256 direcciones IP analizadas; **9 equipos vivos** detectados dentro del rango autorizado.

---

## 1. Resumen de equipos vivos y superficie descubierta

| IP | Hostname / NetBIOS | SO / Plataforma detectada | Puertos TCP abiertos | Puertos UDP abiertos / relevantes | Servicios y versiones principales |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `172.17.0.1` | — *(Gateway)* | Linux | `22/tcp` | Ninguno (50 cerrados) | `OpenSSH 10.3p1 Debian 5` |
| `172.17.0.3` | — | Linux (Ubuntu) | `21/tcp`, `80/tcp` | Ninguno confirmado *(30 open\|filtered)* | `vsftpd 2.3.4`, `Apache httpd 2.4.58 ((Ubuntu))` |
| `172.17.0.4` | — | Linux (Debian 10) | `22/tcp`, `8009/tcp`, `8080/tcp` | Ninguno confirmado *(30 open\|filtered)* | `OpenSSH 7.9p1 Debian 10+deb10u4`, `Apache Jserv (AJP v1.3)`, `Apache Tomcat 9.0.30` |
| `172.17.0.5` | — | Linux (Debian) | `80/tcp`, `443/tcp`, `1883/tcp`, `5672/tcp`, `8161/tcp`, `39383/tcp`, `61613/tcp`, `61614/tcp`, `61616/tcp` | Ninguno confirmado *(30 open\|filtered)* | `Apache httpd 2.4.59 ((Debian))`, `MQTT`, `AMQP`, `Jetty 9.4.39.v20210325`, `Apache ActiveMQ 5.15.15` (STOMP / OpenWire) |
| `172.17.0.6` | — | Linux (Debian 12) | `22/tcp`, `8080/tcp` | Ninguno confirmado *(30 open\|filtered)* | `OpenSSH 9.2p1 Debian 2+deb12u2`, `Jetty 10.0.18` (`Jenkins 2.441`) |
| `172.17.0.7` | — | Linux | `22/tcp` | Ninguno confirmado *(30 open\|filtered)* | `OpenSSH 7.7` |
| `172.17.0.8` | `SAMBASERVER` (Dominio/Grupo `ESEEMEB.DL` / `DL`) | Linux (Ubuntu) | `22/tcp`, `80/tcp`, `139/tcp`, `445/tcp` | `137/udp` (open), `138/udp` (open\|filtered) | `OpenSSH 9.6p1 Ubuntu 3ubuntu13.5`, `Apache httpd 2.4.58 ((Ubuntu))`, `Samba smbd 4`, `Samba nmbd netbios-ns` |
| `172.17.0.9` | — | Linux (Debian 12) | `22/tcp`, `80/tcp` | Ninguno confirmado *(30 open\|filtered)* | `OpenSSH 9.2p1 Debian 2+deb12u10`, `Apache httpd 2.4.68 ((Debian))` |
| `172.17.0.10` | — | Linux (Python) | `80/tcp` | **`623/udp` (open)** | `SimpleHTTPServer 0.6 (Python 3.11.2)` (Web IPMI), **`asf-rmcp` (IPMI / RMCP+)** |

---

## 2. Detalle técnico por equipo vivo (Mapeo TCP/UDP)

### `172.17.0.1` (Puerta de enlace / Host anfitrión)
* **Sistema operativo:** Linux (`cpe:/o:linux:linux_kernel`).
* **Puertos TCP:** `22/tcp` (`open`) — `OpenSSH 10.3p1 Debian 5 (protocol 2.0)`. Los 65 534 puertos restantes figuran como `filtered` sin respuesta.
* **Puertos UDP:** Los 50 puertos principales analizados responden `closed` (`port-unreach`).

### `172.17.0.3` (Servidor FTP y Web)
* **MAC:** `EA:14:64:C9:8A:8C` | **Sistema operativo:** Unix / Ubuntu Linux.
* **Puertos TCP:**
  * `21/tcp` (`open`): **FTP** — `vsftpd 2.3.4`.
  * `80/tcp` (`open`): **HTTP** — `Apache httpd 2.4.58 ((Ubuntu))`.
* **Puertos UDP:** 20 puertos cerrados y 30 en estado `open|filtered` (sin respuesta).

### `172.17.0.4` (Servidor de aplicaciones Java / Tomcat)
* **MAC:** `A2:74:43:48:E8:D2` | **Sistema operativo:** Linux (Debian 10).
* **Puertos TCP:**
  * `22/tcp` (`open`): **SSH** — `OpenSSH 7.9p1 Debian 10+deb10u4 (protocol 2.0)`.
  * `8009/tcp` (`open`): **AJP13** — `Apache Jserv (Protocol v1.3)` (métodos soportados: `GET`, `HEAD`, `POST`, `OPTIONS`).
  * `8080/tcp` (`open`): **HTTP** — `Apache Tomcat 9.0.30`.
* **Puertos UDP:** 20 puertos cerrados y 30 en estado `open|filtered`.

### `172.17.0.5` (Servidor Web y Broker de Mensajería ActiveMQ)
* **MAC:** `8A:02:25:29:44:1F` | **Sistema operativo:** Linux (Debian).
* **Puertos TCP:**
  * `80/tcp` (`open`): **HTTP** — `Apache httpd 2.4.59 ((Debian))`.
  * `443/tcp` (`open`): **HTTPS** — `Apache httpd 2.4.59 ((Debian))`.
  * `1883/tcp` (`open`): **MQTT** — Broker con tópicos `ActiveMQ/Advisory/MasterBroker` y `ActiveMQ/Advisory/Consumer/Topic/#`.
  * `5672/tcp` (`open`): **AMQP** — Servicio de mensajería AMQP.
  * `8161/tcp` (`open`): **HTTP** — `Jetty 9.4.39.v20210325` (consola administrativa `ActiveMQRealm`).
  * `39383/tcp` (`open`): Servicio `tcpwrapped`.
  * `61613/tcp` (`open`): **STOMP** — `Apache ActiveMQ`.
  * `61614/tcp` (`open`): **HTTP** — `Jetty 9.4.39.v20210325` (método HTTP `TRACE` habilitado).
  * `61616/tcp` (`open`): **ApacheMQ** — `ActiveMQ OpenWire transport 5.15.15`.
* **Puertos UDP:** 20 puertos cerrados y 30 en estado `open|filtered`.

### `172.17.0.6` (Servidor CI/CD Jenkins sobre Jetty)
* **MAC:** `0E:21:92:C5:FD:87` | **Sistema operativo:** Linux (Debian 12).
* **Puertos TCP:**
  * `22/tcp` (`open`): **SSH** — `OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)`.
  * `8080/tcp` (`open`): **HTTP** — `Jetty 10.0.18` sirviendo **`Jenkins 2.441`** (cabeceras `X-Jenkins: 2.441`, `X-Hudson: 1.395`).
* **Puertos UDP:** 20 puertos cerrados y 30 en estado `open|filtered`.

### `172.17.0.7` (Servidor SSH)
* **MAC:** `1A:80:06:85:79:92` | **Sistema operativo:** Linux.
* **Puertos TCP:** `22/tcp` (`open`) — `OpenSSH 7.7 (protocol 2.0)`.
* **Puertos UDP:** 20 puertos cerrados y 30 en estado `open|filtered`.

### `172.17.0.8` (Servidor de archivos Samba y Portal Web)
* **MAC:** `0A:92:62:99:E3:35` | **Nombre NetBIOS:** `SAMBASERVER` | **Dominio / Grupo de trabajo:** `ESEEMEB.DL` (`DL`) | **OS:** Ubuntu Linux.
* **Puertos TCP:**
  * `22/tcp` (`open`): **SSH** — `OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)`.
  * `80/tcp` (`open`): **HTTP** — `Apache httpd 2.4.58 ((Ubuntu))`.
  * `139/tcp` (`open`): **NetBIOS-SSN** — `Samba smbd 4`.
  * `445/tcp` (`open`): **Microsoft-DS / SMB** — `Samba smbd 4` (SMB 3.1.1 con firma de mensajes habilitada pero no obligatoria).
* **Puertos UDP:**
  * `137/udp` (`open`): **NetBIOS-NS** — `Samba nmbd netbios-ns (workgroup: DL)`.
  * `138/udp` (`open|filtered`): **NetBIOS-DGM**.

### `172.17.0.9` (Servidor Web Debian)
* **MAC:** `4E:A1:35:14:E8:C3` | **Sistema operativo:** Linux (Debian 12).
* **Puertos TCP:**
  * `22/tcp` (`open`): **SSH** — `OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)`.
  * `80/tcp` (`open`): **HTTP** — `Apache httpd 2.4.68 ((Debian))`.
* **Puertos UDP:** 20 puertos cerrados y 30 en estado `open|filtered`.

### `172.17.0.10` (Interfaz de Gestión Fuera de Banda IPMI y Web Informativa)
* **MAC:** `BA:ED:39:93:D1:03` | **Sistema operativo:** Linux.
* **Puertos TCP:** `80/tcp` (`open`) — `SimpleHTTPServer 0.6 (Python 3.11.2)`.
* **Puertos UDP:** **`623/udp` (`open`)** — **`asf-rmcp`** (servicio IPMI / RMCP+ confirmado mediante escaneo UDP dirigido tras identificar su referencia en la web del puerto 80).

---

## 3. Auditoría y correcciones al inventario del cliente (`inventario-cliente.csv`)

El inventario entregado por Gadir Logística, S.L. (elaborado por el antiguo informático, Juanma, con revisiones entre 2017 y 2020) está **completamente obsoleto** y presenta errores críticos de direccionamiento, sistemas operativos y servicios. En la red real no existe ningún servidor Windows ni impresora en red.

### 3.1. Qué SOBRA (Equipos fantasma o fuera de alcance en el CSV del cliente)

| Equipo en CSV | IP registrada | Qué decía el cliente | Estado real y corrección |
| :--- | :--- | :--- | :--- |
| `FTP-ALMACEN` | `172.17.0.2` | Windows XP SP3 · FileZilla Server 0.9.41 (`21/tcp`) | **Sobra (Inexistente):** La IP `172.17.0.2` no responde. El servicio FTP real de la red corre en `172.17.0.3` bajo Linux (`vsftpd 2.3.4`). |
| `SRV-PORTAL01` *(BD)* | `172.17.0.11` | Windows Server 2008 · SQL Server 2008 R2 SP1 (`1433/tcp`) | **Sobra (Inexistente):** No hay ningún host activo en `172.17.0.11` ni ningún servicio SQL Server expuesto. |
| `srv-mensajeria` | `172.17.0.20` | Windows Server 2003 · MSMQ 3.0 (`1801/tcp`) | **Sobra (Inexistente):** La IP `172.17.0.20` no está viva. La mensajería real se ejecuta sobre Apache ActiveMQ en `172.17.0.5`. |
| `IMPRESORA-MUELLE` | `172.17.0.30` | HP LaserJet P2055 (`9100/tcp`) | **Sobra (Inexistente):** No existe ningún dispositivo ni puerto JetDirect `9100/tcp` activo en `172.17.0.30`. |
| `NAS-OFICINA` | `172.17.0.50` | Synology DSM 5.2 · Carpetas compartidas (`445/tcp`) | **Sobra (Inexistente):** La IP `172.17.0.50` no responde. El almacenamiento compartido real es el servidor Samba `172.17.0.8`. |
| `srv-backup` | `172.17.0.100` | Debian 7 · OpenSSH 5.5 (`22/tcp`) | **Sobra (Inexistente):** Host apagado/eliminado (el propio inventario indicaba *«Creo que ya no funciona»*). |
| `consola sala tecnica` | `172.17.0.254` | HP iLO 2 fw 2.05 (`443/tcp`) | **Sobra (Inexistente en esta red):** No hay ningún equipo en `172.17.0.254`. La consola de gestión real responde en `172.17.0.10` (`623/udp` IPMI). |
| `PC-PRUEBAS` | `172.17.1.6` | Ubuntu 12.04 · Puertos `3000, 5000, 9090` | **Sobra / Fuera de alcance:** La dirección `172.17.1.6` pertenece a otra subred (`/24` distinta a `172.17.0.0/24`), por lo que queda fuera de scope. Probablemente fue una errata tipográfica del técnico al anotar `172.17.0.6`. |

### 3.2. Qué FALTA (Equipos activos reales no documentados en el CSV)

1. **`172.17.0.1` (Gateway / Host Linux):** Puerta de enlace con `OpenSSH 10.3p1` (`22/tcp`).
2. **`172.17.0.3` (Servidor FTP y Web Ubuntu):** `vsftpd 2.3.4` (`21/tcp`) y `Apache httpd 2.4.58` (`80/tcp`).
3. **`172.17.0.4` (Servidor Java / Tomcat):** `OpenSSH 7.9p1` (`22/tcp`), `Apache Jserv AJP v1.3` (`8009/tcp`) y `Apache Tomcat 9.0.30` (`8080/tcp`).
4. **`172.17.0.5` (Broker de Mensajería ActiveMQ y Web):** `Apache httpd 2.4.59` (`80, 443/tcp`), `MQTT` (`1883/tcp`), `AMQP` (`5672/tcp`), `Jetty 9.4.39` (`8161, 61614/tcp`) y `Apache ActiveMQ 5.15.15` (`61613, 61616/tcp`). Reemplaza en función al desaparecido `srv-mensajeria`.
5. **`172.17.0.6` (Servidor CI/CD Jenkins):** `OpenSSH 9.2p1` (`22/tcp`) y `Jenkins 2.441` sobre `Jetty 10.0.18` (`8080/tcp`).
6. **`172.17.0.7` (Servidor SSH):** `OpenSSH 7.7` (`22/tcp`).
7. **`172.17.0.8` (`SAMBASERVER`):** `OpenSSH 9.6p1` (`22/tcp`), `Apache httpd 2.4.58` (`80/tcp`) y `Samba smbd/nmbd 4` (`139, 445/tcp` y `137, 138/udp`). Sustituye al antiguo `NAS-OFICINA`.

### 3.3. Qué ESTÁ MAL (IPs coincidentes con datos erróneos)

* **`172.17.0.9`:** El cliente lo listaba como `TPV-RECEPCION` (Windows 7 con RDP `3389/tcp`). En realidad es un servidor **Debian 12** con `OpenSSH 9.2p1` (`22/tcp`) y `Apache httpd 2.4.68` (`80/tcp`) alojando un portal web en desarrollo.
* **`172.17.0.10`:** El cliente lo listaba como `SRV-PORTAL01` (Windows Server 2008 R2 con IIS 7.5 en `80/443`). En realidad es un equipo Linux con **`SimpleHTTPServer 0.6 (Python 3.11.2)`** en `80/tcp` (sin `443/tcp`) y el servicio de gestión fuera de banda **IPMI (`623/udp`, `asf-rmcp`)**.

---

## 4. Enumeración sin autenticación por servicio (Parte 2)

### `172.17.0.8` (`SAMBASERVER` · Samba 4 + Web Apache)
* **Servicio SMB/NetBIOS (`139/445/tcp`, `137/udp`):**
  * **Sesión nula anónima:** Permitida (`Username: ''`, `Password: ''`), revelando el nombre de dominio/workgroup **`ESEEMEB.DL`** (`DL`) y la información de servidor `EseEmeB Samba Server`.
  * **Recursos compartidos descubiertos:**
    * `myshare` (*Carpeta compartida sin restricciones*): Acceso y listado anónimo permitidos (`Mapping: OK`, `Listing: OK`). Contiene el archivo **`access.txt`** (956 bytes).
    * `backup24` (*Privado*): Acceso denegado (`Mapping: DENIED`).
    * `home` (*Produccion*): Acceso denegado (`Mapping: DENIED`).
  * **Análisis del archivo expuesto `access.txt`:** Contiene un **token JWT** (`alg: RS256`, `typ: JWT`) cuya carga útil decodificada expone:
    * Identidad: `"email": "satriani7@eseemeb.dl"`, `"role": "user"`.
    * Validez temporal: Emitido el `2024-10-05 20:32:53 UTC` (`iat: 1728160373`) y expirado el `2024-10-05 21:32:53 UTC` (`exp: 1728163973`).
    * Configuración criptográfica: Incluye una clave pública RSA embebida directamente en el payload bajo el parámetro `"jwk"` (`kty: RSA`, `e: 65537`).
  * **Política de contraseñas del dominio (`SAMBASERVER`):** Longitud mínima de **5 caracteres**, complejidad deshabilitada (`Password Complexity: Disabled`), sin historial de contraseñas y sin umbral de bloqueo tras intentos fallidos (`Account Lockout Threshold: None`).
* **Servicio Web HTTP (`80/tcp`):**
  * Muestra un formulario de inicio de sesión (*«Iniciar Sesión»*, título `Login`) construido con TailwindCSS que solicita `email` y `password` mediante `POST` a la propia raíz. No existe `/robots.txt` (`404 Not Found`).

### `172.17.0.10` (Web Python + IPMI `623/udp`)
* **Servicio Web HTTP (`80/tcp` — `SimpleHTTP/0.6 Python/3.11.2`):**
  * Sirve una página técnica titulada *«CTG · IPMI bajo exposición»* (`Last-Modified: Fri, 25 Sep 2026 12:17:06 GMT`) que documenta la arquitectura de un controlador BMC (Baseboard Management Controller), la consola Serial Over LAN (SOL), el uso del puerto **`UDP 623`** (RMCP/RMCP+) y la referencia histórica a **CVE-2013-4786** (autenticación RAKP en IPMI 2.0). No dispone de `/robots.txt` (`404 Not Found`).
* **Servicio IPMI (`623/udp` — `asf-rmcp`):**
  * Tras detectar la referencia al puerto en la web, el escaneo UDP dirigido confirmó que `623/udp` está **abierto** y responde a sondas `ipmi-rmcp` con huella binaria activa.

### `172.17.0.6` (Jenkins `2.441` sobre Jetty `10.0.18`)
* **Servicio Web HTTP (`8080/tcp`):**
  * Aunque Nmap identificó únicamente `Jetty 10.0.18`, la inspección de cabeceras HTTP confirmó que la aplicación subyacente es **`Jenkins 2.441`** (`X-Jenkins: 2.441`, `X-Hudson: 1.395`).
  * La raíz `/` devuelve `HTTP/1.1 403 Forbidden` (*«Authentication required»*) y redirige mediante meta-refresh y JavaScript a `/login?from=%2F`.
  * El archivo `/robots.txt` devuelve `HTTP/1.1 200 OK` con el comentario `# we don't want robots to click "build" links` y la directiva `Disallow: /`.

### `172.17.0.5` (Apache + Broker ActiveMQ `5.15.15` + Jetty `9.4.39`)
* **Web HTTP (`80/tcp`) y HTTPS (`443/tcp`):**
  * El puerto `80/tcp` muestra la página por defecto de instalación de Debian (`Apache/2.4.59`).
  * El puerto `443/tcp` usa un certificado TLS autofirmado emitido para `CN=example.com` (caducado el `2025-04-17`) y aloja una plantilla web de restaurante (*«DockerLabs | Plantilla gratuita Bootstrap 4.3.x»*) con el correo de contacto genérico `info@dockerlabs.lab` y un marcador sin configurar en la API de Google Maps (`key=YOUR_API_KEY`).
* **Mensajería MQTT (`1883/tcp`) y STOMP (`61613/tcp`):**
  * El broker MQTT permite suscripción anónima a tópicos de aviso (`ActiveMQ/Advisory/MasterBroker`, `ActiveMQ/Advisory/Consumer/Topic/#`).
  * El puerto STOMP `61613/tcp` devuelve trazas completas de excepciones Java (`org.apache.activemq.transport.stomp.ProtocolException`) con rutas internas de clases al recibir comandos no reconocidos.
* **Consolas Jetty (`8161/tcp` y `61614/tcp`):**
  * `8161/tcp` expone la consola web de ActiveMQ protegida por autenticación HTTP Basic (`401 Unauthorized`, `WWW-Authenticate: basic realm="ActiveMQRealm"`).
  * `61614/tcp` responde `HTTP/1.1 200 OK` vacío y tiene habilitado el método HTTP `TRACE`.

### `172.17.0.4` (Apache Tomcat `9.0.30` + AJP13)
* **Servicio Web HTTP (`8080/tcp`):**
  * Expone la página de bienvenida por defecto de **`Apache Tomcat/9.0.30`** sin modificar, revelando rutas administrativas estándar (`/manager/status`, `/manager/html`, `/host-manager/html`), documentación (`/docs/`, `/examples/`) y rutas de configuración interna (`$CATALINA_HOME/conf/tomcat-users.xml`). No existe `/robots.txt` (`404 Not Found`).
* **Conector AJP (`8009/tcp`):**
  * Escucha el protocolo binario `AJP v1.3` admitiendo los métodos `GET`, `HEAD`, `POST` y `OPTIONS`.

### `172.17.0.3` y `172.17.0.9` (Servicios Web Apache y FTP)
* **`172.17.0.3` (`80/tcp`):** Sirve la página de instalación por defecto de Ubuntu (`Apache2 Ubuntu Default Page: It works`).
* **`172.17.0.9` (`80/tcp`):** Aloja un sitio en construcción (*«Under Development»*, título `test page`) con enlace a `/login.html`, donde se expone un formulario `POST` hacia `login.php` con campos `username` y `password`.

---

## 5. Cuentas de usuario y correos descubiertos

| Cuenta / Identificador | Tipo | Equipo / Servicio de origen | Evidencia y observaciones |
| :--- | :--- | :--- | :--- |
| `administrador` | Usuario local / Samba (RID `1004` / `0x3ec`) | `172.17.0.8` (`SAMBASERVER`) | Enumerado vía RPC y RID cycling en `enum4linux` (`S-1-5-21-...-1004`). Cuenta con perfil administrativo. |
| `satriani7` / `satriani7@eseemeb.dl` | Usuario local / Correo corporativo (RID `1003` / `0x3eb`) | `172.17.0.8` (`SAMBASERVER` + `myshare/access.txt`) | Usuario enumerado en Samba (`S-1-5-21-...-1003`) y confirmado con correo y rol `user` dentro del token JWT de `access.txt`. |
| `usuario1` | Usuario local / Samba (RID `1000` / `0x3e8`) | `172.17.0.8` (`SAMBASERVER`) | Enumerado vía RPC y RID cycling (`S-1-5-21-...-1000`). |
| `usuario2` | Usuario local / Samba (RID `1001` / `0x3e9`) | `172.17.0.8` (`SAMBASERVER`) | Enumerado vía RPC y RID cycling (`S-1-5-21-...-1001`). |
| `usuario3` | Usuario local / Samba (RID `1002` / `0x3ea`) | `172.17.0.8` (`SAMBASERVER`) | Enumerado vía RPC y RID cycling (`S-1-5-21-...-1002`). |
| `ubuntu` | Usuario local Unix (UID `1000`) | `172.17.0.8` (`SAMBASERVER`) | Enumerado mediante RID cycling sobre el SID Unix `S-1-22-1-1000`. |
| `nobody` | Usuario de sistema (RID `501`) | `172.17.0.8` (`SAMBASERVER`) | Cuenta estándar sin privilegios (`S-1-5-21-...-501`). |
| `info@dockerlabs.lab` | Correo **genérico de plantilla (NO cuenta real)** | `172.17.0.5` (`443/tcp`) | Marcador de contacto incluido en la plantilla HTML Bootstrap; no identifica a ningún usuario del cliente y no debe contabilizarse como cuenta. |

---

> **Nota sobre el JWT de `access.txt`:** el token expone correo, rol y una clave **pública** RSA (`jwk`), pero está **caducado desde el 05-10-2024** (`exp: 1728163973`). Se interpreta como fuga de información útil para *phishing* dirigido, no como credencial vigente; no se ha probado contra ningún portal.

---

## 6. Limitaciones encontradas durante la enumeración sin credenciales

En cumplimiento estricto de las reglas de compromiso (prohibición de probar contraseñas por defecto, lanzar fuerza bruta o ejecutar exploits), la enumeración se detuvo ante los siguientes controles de acceso:

1. **Recursos compartidos restringidos en Samba (`172.17.0.8`):** Los recursos `backup24` (*Privado*) y `home` (*Produccion*) rechazan el acceso anónimo (`NT_STATUS_ACCESS_DENIED`), impidiendo listar su contenido sin credenciales válidas.
2. **Paneles web protegidos por autenticación:**
   * **Jenkins (`172.17.0.6:8080`):** Devuelve `HTTP 403 Forbidden` y exige inicio de sesión en `/login` para visualizar trabajos, nodos o plugins instalados.
   * **Consola ActiveMQ (`172.17.0.5:8161`):** Protegida mediante HTTP Basic (`401 Unauthorized`, `ActiveMQRealm`).
   * **Tomcat Manager (`172.17.0.4:8080/manager/html`):** Requiere credenciales definidas en `tomcat-users.xml`.
   * **Portales de login (`172.17.0.8/` y `172.17.0.9/login.html`):** Formularios de autenticación funcionales cuya validación requiere credenciales reales.
3. **Servicio FTP con directorio inaccesible (`172.17.0.3:21`):** Aunque `vsftpd 2.3.4` responde al saludo inicial, el acceso anónimo falla con el error de servidor `500 OOPS: cannot change directory:/var/ftp`, impidiendo enumerar archivos por FTP.
4. **Hosts exclusivamente con SSH (`172.17.0.1` y `172.17.0.7`):** Al exponer únicamente `OpenSSH` en `22/tcp`, solo es posible obtener el banner de versión y las claves públicas del host sin interactuar con la autenticación.
5. **Puertos UDP filtrados (`open|filtered`):** En 8 de los 9 equipos, 30 puertos UDP no devuelven respuesta ICMP `port-unreachable`, lo que impide distinguir desde red si están filtrados por cortafuegos o si un servicio UDP silencioso ignora paquetes malformados (salvo el puerto `623/udp` en `.10` y `137/udp` en `.8`, que sí respondieron).