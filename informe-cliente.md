# Informe Ejecutivo de Evaluación de Seguridad y Exposición de Red
## Gadir Logística, S.L.

- **Cliente:** Gerencia — Gadir Logística, S.L.
- **Alcance evaluado:** Red interna `172.17.0.0/24` (evaluación no intrusiva sin credenciales).
- **Periodo de ejecución:** 10 – 20 de noviembre de 2026 (contraste de fuentes de vulnerabilidades: 23 de noviembre de 2026).
- **Elaborado por:** Hugo Pérez — Equipo de Auditoría de Seguridad.

---

## 1. Resumen Ejecutivo

Tras realizar un reconocimiento completo y seguro de la red interna de **Gadir Logística, S.L.** (`172.17.0.0/24`), hemos detectado **9 servidores y equipos activos** que sostienen actualmente la operativa de comunicaciones, archivos, aplicaciones y gestión técnica.

La conclusión principal para Dirección se resume en tres puntos clave:

1. **Situación frente a la alerta de prensa «sshole» (`CVE-2026-123158`):** **Su empresa no está afectada de forma general por este fallo.** Dicha vulnerabilidad solo compromete a sistemas Linux minimalistas muy concretos (como Alpine Linux), mientras que sus servidores principales operan sobre Debian y Ubuntu, inmunes a este problema. Únicamente recomendamos una comprobación preventiva rápida en uno de los equipos (`172.17.0.7`).
2. **Riesgos reales urgentes detectados en su red:** Aunque «sshole» no representa una amenaza directa, **sí hemos identificado 3 fallos críticos, 3 fallos altos (uno de ellos condicional) y 1 medio** en servicios internos desactualizados o accesibles sin restricciones dentro de la red (mensajería interna, servidor de automatización Jenkins, servidor de aplicaciones Tomcat, consola de gestión hardware IPMI y carpetas compartidas). Los tres fallos críticos **sí están siendo aprovechados activamente por ciberdelincuentes**, con uso en campañas de ransomware confirmado para ActiveMQ y Jenkins.
3. **Desactualización total del inventario heredado:** El listado de equipos facilitado inicialmente (`inventario-cliente.csv`, elaborado hasta 2020) **no refleja la infraestructura real**: incluye 8 equipos que ya no existen o pertenecen a otra red, omite 7 servidores reales que hoy están en funcionamiento y asigna sistemas operativos erróneos a los restantes.

> **Nivel de riesgo global actual:** **ALTO / CRÍTICO** — Requiere actuaciones correctivas inmediatas (en las próximas 24 a 72 horas) para evitar que un incidente interno o un equipo infectado en la oficina derive en el secuestro de datos o la parada operativa de la empresa.

---

## 2. Alcance, Metodología y Límites del Trabajo

Para garantizar la continuidad total de las operaciones logísticas sin provocar caídas ni bloqueos:
* **Alcance:** Se analizaron las 256 direcciones de la red `172.17.0.0/24` autorizadas por Gerencia. Quedó excluida la dirección `172.17.1.6` que figuraba en su antiguo listado por pertenecer a una red distinta fuera del alcance autorizado.
* **Metodología no intrusiva:** Se identificaron los equipos activos, los servicios publicados y la información visible de forma anónima, contrastando las versiones detectadas con los catálogos oficiales de vulnerabilidades (NVD, EPSS y CISA). **Fuentes y fecha de consulta:** NVD API 2.0, FIRST EPSS API (dato de 20-11-2026) y catálogo CISA KEV `2026.11.20`, contrastados el **23-11-2026**; boletín de OX Security sobre `CVE-2026-123158` (05-11-2026).
* **Limitaciones:** En cumplimiento estricto de las reglas acordadas, **no se han probado contraseñas, no se ha forzado el acceso a carpetas o paneles protegidos y no se ha ejecutado ningún ataque de prueba**. En consecuencia, las vulnerabilidades descritas indican exposición confirmada por versión o configuración y requieren verificación interna por parte de su soporte técnico durante la aplicación de los parches.

---

## 3. Estado Real de la Infraestructura frente al Inventario Heredado

Contar con un inventario fiable es un requisito básico tanto para el mantenimiento diario como ante cualquier auditoría o póliza de ciberseguro. A continuación se resume la fotografía real de sus **9 equipos activos** frente al listado anterior:

| Dirección IP | Qué constaba en el inventario antiguo | Qué existe realmente en la red hoy | Función actual |
| :--- | :--- | :--- | :--- |
| `172.17.0.1` | No figuraba | Equipo Linux (Puerta de enlace) | Enrutamiento y acceso remoto SSH |
| `172.17.0.3` | No figuraba | Servidor Linux (Ubuntu) con FTP antiguo (`vsftpd 2.3.4`) y Web | Transferencia de archivos y servidor web |
| `172.17.0.4` | No figuraba | Servidor Linux (Debian 10) con **Apache Tomcat 9.0.30** | Servidor de aplicaciones internas Java |
| `172.17.0.5` | No figuraba *(figuraba un Windows en `.20`)* | Servidor Linux (Debian) con **Apache ActiveMQ 5.15.15** y Web | Cola de mensajería e intercambio de datos |
| `172.17.0.6` | No figuraba | Servidor Linux (Debian 12) con **Jenkins 2.441** | Plataforma de automatización y despliegues |
| `172.17.0.7` | No figuraba | Servidor Linux con acceso remoto SSH (`OpenSSH 7.7`) | Servidor interno administrado por SSH |
| `172.17.0.8` | No figuraba *(figuraba un NAS en `.50`)* | Servidor Linux (`SAMBASERVER`) con carpetas compartidas y Web | Almacenamiento de archivos y portal de acceso |
| `172.17.0.9` | `TPV-RECEPCION` (Windows 7) | Servidor Linux (Debian 12) con portal web en pruebas | Web interna en desarrollo (`/login.html`) |
| `172.17.0.10` | `SRV-PORTAL01` (Windows Server 2008) | Equipo Linux con interfaz de gestión hardware **IPMI (`623/udp`)** | Consola de control remoto de servidor (sala técnica) |

*(Nota: Los equipos antiguos `172.17.0.2`, `.11`, `.20`, `.30`, `.50`, `.100` y `.254` ya no están activos en esta red y deben darse de baja del inventario oficial).*

---

## 4. Hallazgos Principales Priorizados por Impacto de Negocio

Ordenamos los problemas detectados de **mayor a menor urgencia** atendiendo al daño que podrían causar a Gadir Logística y a la facilidad con la que los atacantes los aprovechan actualmente:

| Prioridad | Riesgo | Equipo afectado | Qué ocurre en lenguaje sencillo | Impacto para el negocio |
| :---: | :---: | :--- | :--- | :--- |
| **1** | **CRÍTICO** | `172.17.0.5` *(Mensajería ActiveMQ)* | El programa que gestiona las colas de mensajes internos tiene un fallo crítico (`CVE-2023-46604`) que permite a un atacante tomar el control total del servidor sin contraseña. | **Parada operativa total** o entrada de **ransomware** (secuestro de sistemas) desde cualquier equipo infectado de la red. |
| **2** | **CRÍTICO** | `172.17.0.6` *(Automatización Jenkins)* | La herramienta de automatización (`Jenkins 2.441`) permite leer archivos internos del servidor sin iniciar sesión (`CVE-2024-23897`), exponiendo claves y contraseñas guardadas. | **Robo de credenciales internas** y compromiso de otros servidores conectados. |
| **3** | **CRÍTICO** | `172.17.0.4` *(Aplicaciones Tomcat)* | El servidor de aplicaciones (`Tomcat 9.0.30`) mantiene abierto un puerto interno (`8009`) sin contraseña que permite leer archivos de configuración de las aplicaciones (`CVE-2020-1938`). | **Filtración de datos sensibles** y contraseñas de bases de datos internas. |
| **4** | **ALTO** | `172.17.0.10` *(Consola técnica IPMI)* | La interfaz de control remoto del hardware (`623/udp`) está accesible desde toda la red interna y usa un protocolo antiguo (`CVE-2013-4786`) que permite capturar y descifrar su contraseña. | **Control físico remoto del servidor** (apagado forzoso, reinicio o acceso a la consola de arranque por debajo del sistema operativo). |
| **5** | **ALTO** | `172.17.0.8` *(Servidor de archivos)* | El servidor de archivos permite consultar sin contraseña la lista de usuarios reales (`administrador`, `satriani7`, etc.), tiene una carpeta pública con un pase de acceso (`access.txt`) y admite contraseñas muy débiles (5 caracteres, sin bloqueo). | **Suplantación de identidad** y acceso no autorizado a carpetas privadas de producción o copias de seguridad. |
| **6** | **ALTO / MEDIO** | `172.17.0.3` *(Servidor FTP antiguo)* | Ejecuta una versión de transferencia de archivos del año 2011 (`vsftpd 2.3.4`) conocida históricamente por haber sufrido una puerta trasera (`CVE-2011-2523`). | Posible **acceso oculto sin contraseña** si el programa instalado procede de la versión alterada. |
| **7** | **MEDIO** | `172.17.0.7` *(Servidor SSH)* | Ejecuta una versión antigua de acceso remoto (`OpenSSH 7.7`) que permite averiguar qué nombres de usuario existen en el equipo (`CVE-2018-15473`). | Facilita el trabajo previo a un atacante que intente adivinar contraseñas. |

---

## 5. Hoja de Ruta y Plan de Acción Recomendado

Proponemos ejecutar las mejoras en **tres fases escalonadas** para reducir el riesgo crítico en menos de 72 horas sin interrumpir la actividad diaria:

### Fase 1 · Actuaciones Inmediatas (Primeras 24 – 72 horas)
1. **Actualizar los tres servicios críticos:**
   * Actualizar **Apache ActiveMQ** (`172.17.0.5`) a una versión segura (`>= 5.18.3` o `5.15.16+`).
   * Actualizar **Jenkins** (`172.17.0.6`) a la versión `2.442` o superior y deshabilitar su interfaz de comandos remota (CLI) si no se utiliza.
   * Actualizar **Apache Tomcat** (`172.17.0.4`) y **cerrar el puerto `8009`** en su archivo de configuración (`server.xml`) si no es estrictamente necesario.
2. **Aislar la consola de gestión técnica (`172.17.0.10`):**
   * Configurar el cortafuegos o la red para que el puerto `623/udp` (IPMI) **solo sea accesible desde el puesto del técnico de mantenimiento** y nunca desde los ordenadores de oficina o almacén.
3. **Cerrar el acceso anónimo en el servidor de archivos (`172.17.0.8`):**
   * Eliminar el archivo `access.txt` de la carpeta compartida pública `myshare` y desactivar el acceso sin usuario/contraseña en Samba.

### Fase 2 · Corto Plazo (Primera semana)
4. **Endurecer contraseñas y accesos en `172.17.0.8`:**
   * Cambiar las contraseñas de las cuentas detectadas (`administrador`, `satriani7`, `usuario1-3`) exigiendo al menos **12 caracteres** con combinación de letras, números y símbolos, y activar el bloqueo temporal tras varios intentos fallidos.
5. **Retirar el servicio FTP obsoleto (`172.17.0.3`):**
   * Desinstalar `vsftpd 2.3.4` (de 2011) y sustituirlo por transferencia cifrada **SFTP** o por una versión moderna y oficial del sistema.
6. **Verificación preventiva en `172.17.0.7` (por la alerta «sshole»):**
   * Comprobar localmente qué sistema operativo tiene instalado y confirmar que el acceso remoto SSH solo admite llaves criptográficas (desactivando el acceso por contraseña).

### Fase 3 · Medio Plazo (2 a 4 semanas)
7. **Segmentación de red y actualización del inventario:**
   * Separar la red en zonas diferenciadas (puestos de oficina, servidores de aplicaciones y gestión técnica) mediante reglas de cortafuegos.
   * Actualizar el paquete OpenSSH en `172.17.0.7` y dar por oficial el nuevo inventario de activos entregado con este informe.

---

## 6. Respuesta Oficial sobre la Alerta «sshole» (`CVE-2026-123158`) para Gerencia y Aseguradora

Ante la consulta recibida sobre el fallo publicado en prensa bajo el nombre **«sshole» (`CVE-2026-123158`)** en el servicio de acceso remoto OpenSSH, dejamos constancia técnica de lo siguiente:

* **Diagnóstico:** La vulnerabilidad `CVE-2026-123158` (boletín publicado el 5 de noviembre de 2026, **incluida en CISA KEV el 9 de noviembre de 2026**, CVSS v3.1 **8.1 Alta**, **EPSS 95,5 %** a 20-11-2026, sin uso en ransomware registrado —`Unknown`—) solo afecta a sistemas Linux minimalistas que utilizan una librería interna específica llamada `musl libc` sin módulos PAM (principalmente **Alpine Linux**). Requiere además contraseñas de 257 a 1 024 bytes, inicio de sesión por contraseña habilitado y una cuenta con el campo de contraseña `*`. Fuentes: NVD, FIRST EPSS API, CISA KEV `2026.11.20` y OX Security; consultadas el 23-11-2026.
* **Situación en Gadir Logística:**
  * **3 de los 9 equipos activos** (`172.17.0.3`, `172.17.0.5` y `172.17.0.10`) **no tienen el servicio SSH habilitado**.
  * **5 de los 9 equipos activos** (`172.17.0.1`, `172.17.0.4`, `172.17.0.6`, `172.17.0.8` y `172.17.0.9`) operan sobre **Debian y Ubuntu**, distribuciones que emplean una arquitectura distinta (`glibc` con PAM) y que **no son vulnerables a este fallo**.
  * **1 equipo (`172.17.0.7`)** ejecuta `OpenSSH 7.7` sin especificar su distribución en la respuesta de red; se ha incluido en la **Fase 2** del plan de acción su verificación interna y el bloqueo de acceso por contraseña como medida preventiva.
* **Conclusión:** Gadir Logística **no sufre exposición crítica derivada de `CVE-2026-123158`**, siendo prioritario concentrar los recursos técnicos en los 6 hallazgos críticos y altos (3 críticos y 3 altos, uno de ellos condicional) detallados en la Sección 4 de este informe.